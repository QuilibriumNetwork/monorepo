//! Log requests from peers this node's operator allowlists, served on the
//! authenticated peer listener.
//!
//! An allowlisted peer submits a [`LogRequest`] signed by its network key:
//! a window of at most 24 h, optional shard filters and a fresh sntrup761
//! key of that request alone. The node queues it in memory. Listing a peer
//! in `diagnostics.logRequests.allowedPeers` is consent to send it this
//! node's redacted logs, so a node that writes log files approves the
//! request itself: one at a time, off the async runtime, it exports the
//! window from its log files with `node log export`'s redaction, seals the
//! bundle to the request's key ([`bundle`]) and writes the token map to its
//! config directory's `.diagnostics/token-maps`. An export over
//! `maxBundleBytes`, or one that fails, denies the request with its reason.
//!
//! A node that writes no log files asks its operator instead, in a warning
//! repeated hourly, to review the request with `qclient node diagnostics
//! pending|approve|deny`. That approval runs `node log export` in the
//! operator's qclient, with its preview, and uploads the sealed bundle here
//! over [`DiagnosticsOperatorService`], which only this node's own identity
//! reaches: whoever holds this node's network key acts as its operator
//! there; it also lists requests and denies them, withdrawing an approved
//! bundle. The node keeps the sealed bundle in its diagnostics spool until
//! the request expires and serves it only to the requester. A request
//! whose bundle the requester fetched holds no place in the queue: its
//! bundle stays fetchable until it expires or a new request needs the place.
//!
//! A caller without a handshake identity, one not allowlisted, a node that
//! has not enabled requests, a request whose key is not the caller's or whose
//! signature does not verify all get the health report's PERMISSION_DENIED.
//! An allowlisted peer's other refusals are a [`LogRequestRefusal`], and
//! another peer's request is NOT_FOUND like an unknown one.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use prost::Message as _;
use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use quil_config::LogRequestsConfig;
use quil_p2p::PeerId;
use quil_types::crypto::Signer as _;
use quil_types::proto::diagnostics::diagnostics_log_service_client::DiagnosticsLogServiceClient;
use quil_types::proto::diagnostics::diagnostics_log_service_server::{DiagnosticsLogService, DiagnosticsLogServiceServer};
use quil_types::proto::diagnostics::diagnostics_operator_service_client::DiagnosticsOperatorServiceClient;
use quil_types::proto::diagnostics::diagnostics_operator_service_server::{
    DiagnosticsOperatorService, DiagnosticsOperatorServiceServer,
};
use quil_types::proto::diagnostics::{
    DenyLogRequestRequest, DenyLogRequestResponse, FetchLogBundleRequest, GetLogRequestStatusRequest,
    ListLogRequestsRequest, ListLogRequestsResponse, LogBundleChunk, LogRequest, LogRequestDenial, LogRequestRefusal,
    LogRequestStatus, LogRequestStatusResponse, PendingLogRequest, SignedLogRequest, SubmitLogRequestResponse,
    UploadLogBundleChunk, UploadLogBundleResponse,
};

use crate::diagnostics_service::{parse_allowed, peer_tail, DENIED, REFUSAL_SUMMARY_INTERVAL};
use crate::log_export::redact::format_rfc3339_utc;
use crate::peer_auth_middleware::AuthenticatedPeer;

pub mod bundle;

pub use bundle::AutoApproval;

/// The signature domain of a [`LogRequest`].
pub const DOMAIN: &[u8] = b"quil/diagnostics/log-request/v1";
const ID_TAG: &[u8] = b"quil/diagnostics/log-request-id/v1";
/// The request layout this build signs and accepts.
pub const REQUEST_SCHEMA: u32 = 1;
pub const ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 16;
/// The longest window a peer may ask for, as `node log export` allows.
pub const MAX_WINDOW_SECS: u64 = 24 * 3600;
pub const MAX_FILTERS: usize = 16;
/// The lengths of a full public shard filter, as prover joins and filter
/// operations bound them: a 32-byte application address and up to 32
/// bytes of shard path. Export selection matches a filter against log lines
/// before redaction, so a shorter one could probe redacted text.
pub const SHARD_FILTER_BYTES: std::ops::RangeInclusive<usize> = 32..=64;
/// How far a request's issue time may be from this node's clock.
pub const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
/// Nonces of queued requests remembered, at most; a request is refused once
/// that many are remembered within [`NONCE_HORIZON_MS`].
pub const NONCE_CACHE: usize = 1024;
/// How long a queued request's nonce is remembered: a request issued up to
/// the skew ahead of this node's clock stays fresh until twice the skew
/// after it was queued; a minute more covers tick granularity.
pub const NONCE_HORIZON_MS: u64 = 2 * MAX_CLOCK_SKEW_MS + 60_000;
/// How often a waiting request is logged again.
pub const REMINDER_INTERVAL_MS: u64 = 3600 * 1000;
/// Finished requests (denied, expired) whose status a requester can still read.
pub const FINISHED_KEPT: usize = 64;
/// Bundle bytes per upload message and per fetch message.
pub const UPLOAD_CHUNK_BYTES: usize = 32 * 1024;
pub const FETCH_CHUNK_BYTES: usize = 256 * 1024;
/// The largest message the peer service decodes: a signed request with 16
/// filters of 128 bytes is about 5 KiB.
pub const MAX_PEER_MESSAGE_BYTES: usize = 8 * 1024;
/// The largest message the operator service decodes: one upload chunk.
pub const MAX_OPERATOR_MESSAGE_BYTES: usize = UPLOAD_CHUNK_BYTES + 1024;
/// The largest answer either service encodes.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DAY_MS: u64 = 24 * 3600 * 1000;

/// How long an upload of `bytes` may take: a minute plus 64 KiB/s. The
/// operator's qclient waits this long for the node's answer, and the node
/// abandons an upload still running a minute after it.
pub fn upload_timeout(bytes: u64) -> Duration {
    Duration::from_secs(60 + bytes / (64 * 1024))
}

/// How long a unary call may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How long this node's own export of a request may run; past this it
/// denies the request as failed and stops the export.
pub const AUTO_EXPORT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How often the automatic approval looks for requests it was not woken for.
const AUTO_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// A request's ID: the first 16 bytes of a tagged SHA-256 of its bytes, so
/// the same request resubmitted keeps its ID.
pub fn request_id(request: &[u8]) -> [u8; ID_LEN] {
    let digest = Sha256::new().chain_update(ID_TAG).chain_update(request).finalize();
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&digest[..ID_LEN]);
    id
}

/// The first 8 hex digits of `id`, as logs and qclient show it.
pub fn short_id(id: &[u8]) -> String {
    hex::encode(&id[..id.len().min(4)])
}

/// Sign `request` with the Falcon network key `falcon_signing_key`; the
/// request's `requester_public_key` must be that key's.
pub fn sign_request(request: &LogRequest, falcon_signing_key: &[u8]) -> anyhow::Result<SignedLogRequest> {
    let public = quil_crypto::falcon_public_from_signing_key(falcon_signing_key)
        .ok_or_else(|| anyhow::anyhow!("the network key is not a Falcon signing key"))?;
    anyhow::ensure!(public == request.requester_public_key, "the request names another requester key");
    let bytes = request.encode_to_vec();
    let signature = quil_crypto::FalconSigner::from_bytes(falcon_signing_key, &public)
        .sign_with_domain(&bytes, DOMAIN)
        .map_err(|e| anyhow::anyhow!("sign the log request: {e}"))?;
    Ok(SignedLogRequest { request: bytes, signature })
}

/// Why a caller was refused, as the refusal summary counts it. The first
/// five get the same PERMISSION_DENIED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Refused {
    NoIdentity,
    NotAllowed,
    KeyMismatch,
    BadSignature,
    NotOperator,
    Request(LogRequestRefusal),
}

impl Refused {
    fn label(self) -> &'static str {
        match self {
            Refused::NoIdentity => "no_identity",
            Refused::NotAllowed => "not_allowed",
            Refused::KeyMismatch => "key_mismatch",
            Refused::BadSignature => "bad_signature",
            Refused::NotOperator => "not_operator",
            Refused::Request(refusal) => match refusal {
                LogRequestRefusal::None => "none",
                LogRequestRefusal::Malformed => "malformed",
                LogRequestRefusal::WrongTarget => "wrong_target",
                LogRequestRefusal::Stale => "stale",
                LogRequestRefusal::Replayed => "replayed",
                LogRequestRefusal::WindowTooLong => "window_too_long",
                LogRequestRefusal::TooManyFilters => "too_many_filters",
                LogRequestRefusal::OverBudget => "over_budget",
                LogRequestRefusal::QueueFull => "queue_full",
                LogRequestRefusal::FilterLength => "filter_length",
                LogRequestRefusal::TooManyPending => "too_many_pending",
            },
        }
    }

    /// A refusal of an allowlisted peer: a request this node was set up to
    /// take and did not.
    fn of_allowlisted(self) -> bool {
        !matches!(self, Refused::NoIdentity | Refused::NotAllowed | Refused::NotOperator)
    }
}

/// Refusals since the last summary line, logged at once for the first and
/// then at most every [`REFUSAL_SUMMARY_INTERVAL`].
#[derive(Debug, Default)]
struct RefusalSummary {
    logged_ms: Option<u64>,
    since_ms: Option<u64>,
    counts: BTreeMap<Refused, u64>,
    requesters: HashSet<PeerId>,
    /// The budget of the latest allowlisted requester whose request was
    /// refused, as [`Budget::summary`] states it.
    latest_budget: Option<String>,
}

impl RefusalSummary {
    fn note(&mut self, refused: Refused, caller: Option<&PeerId>, now_ms: u64) {
        let since = *self.since_ms.get_or_insert(now_ms);
        *self.counts.entry(refused).or_default() += 1;
        if let Some(caller) = caller.filter(|_| self.requesters.len() < NONCE_CACHE) {
            self.requesters.insert(*caller);
        }
        let interval = REFUSAL_SUMMARY_INTERVAL.as_millis() as u64;
        if self.logged_ms.is_some_and(|at| now_ms.saturating_sub(at) < interval) {
            return;
        }
        self.logged_ms = Some(now_ms);
        self.since_ms = None;
        let counts = std::mem::take(&mut self.counts);
        let requesters = std::mem::take(&mut self.requesters).len();
        let refused: u64 = counts.values().sum();
        let reasons = counts.iter().map(|(r, n)| format!("{}:{n}", r.label())).collect::<Vec<_>>().join(",");
        let window_secs = now_ms.saturating_sub(since) / 1000;
        let latest_budget = self.latest_budget.take();
        if counts.keys().any(|r| r.of_allowlisted()) {
            warn!(refused, requesters, %reasons, window_secs,
                latest_budget = latest_budget.as_ref().map(tracing::field::display), scope = "allowlisted peers",
                action = "over_budget and queue_full count requests beyond diagnostics.logRequests.requestsPerDay \
                    and maxPending (review the queue with 'qclient node diagnostics pending'); stale means a \
                    clock is off; key_mismatch, bad_signature and malformed mean a broken or incompatible requester",
                "diagnostics log requests refused");
        } else {
            info!(refused, requesters, %reasons, window_secs, scope = "remote peers",
                action = "expected unless you meant to take these peers' requests; to take one's, add its peer ID \
                    to diagnostics.logRequests.allowedPeers and restart",
                "diagnostics log requests refused");
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    requester: PeerId,
    request: LogRequest,
    status: LogRequestStatus,
    received_ms: u64,
    expires_ms: u64,
    reminded_ms: u64,
    bundle_bytes: u64,
    bundle_sha256: Vec<u8>,
    /// The upload in progress: its token and when the node gives it up.
    upload: Option<Upload>,
    /// This node's automatic approval took it: it is not taken again.
    attempted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Upload {
    token: u64,
    deadline_ms: u64,
    /// This node's own export, rather than its operator's upload.
    automatic: bool,
}

#[derive(Debug, Default)]
struct State {
    /// Pending, ready and served requests.
    entries: BTreeMap<[u8; ID_LEN], Entry>,
    /// Denied and expired requests, oldest first.
    finished: VecDeque<Finished>,
    /// Nonces of queued requests: request ID and when it was queued.
    nonces: HashMap<(PeerId, Vec<u8>), ([u8; ID_LEN], u64)>,
    /// When each peer's requests in the last 24 h were queued.
    queued: HashMap<PeerId, VecDeque<u64>>,
    /// The token of the next upload.
    uploads: u64,
    /// This node's own export, from when it is taken until its blocking
    /// task ends, even after its request was denied or timed out: no other
    /// export or upload starts meanwhile.
    export: Option<RunningExport>,
    refusals: RefusalSummary,
}

/// This node's export of a request and the flag that stops it.
#[derive(Debug, Clone)]
struct RunningExport {
    id: [u8; ID_LEN],
    token: u64,
    cancel: Arc<AtomicBool>,
}

/// What builds an automatic approval's bundle: [`bundle::build_automatic`],
/// or a stand-in in tests.
#[derive(Clone, Copy)]
struct Exporter(fn(&AutoApproval, &bundle::AutoRequest, usize, i64, &AtomicBool) -> anyhow::Result<bundle::AutoBundle>);

impl std::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Exporter")
    }
}

fn build_automatic(
    auto: &AutoApproval,
    request: &bundle::AutoRequest,
    max: usize,
    now_secs: i64,
    cancel: &AtomicBool,
) -> anyhow::Result<bundle::AutoBundle> {
    bundle::build_automatic(auto, request, max, now_secs, cancel, None)
}

/// A denied or expired request, as its requester can still read it.
#[derive(Debug, Clone, Copy)]
struct Finished {
    id: [u8; ID_LEN],
    requester: PeerId,
    status: LogRequestStatus,
    denial: LogRequestDenial,
}

/// What [`LogRequests::tick`] did, for tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tick {
    pub expired: usize,
    pub reminded: usize,
    pub abandoned: usize,
}

/// A requester's budget of `requestsPerDay` in the last 24 h, as its
/// next submission is checked against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    /// Requests it may still make: none means its next is over budget.
    remaining: u32,
    per_day: u32,
    /// When its oldest counted request ages out, freeing one request.
    next_ms: Option<u64>,
}

impl Budget {
    /// Report the budget in a submit answer.
    fn fill(self, response: &mut SubmitLogRequestResponse) {
        response.requests_remaining = Some(self.remaining);
        response.requests_per_day = Some(self.per_day);
        response.next_request_unix_ms = self.next_ms;
    }

    /// The budget of `requester`, as the refusal summary logs it.
    fn summary(self, requester: &str) -> String {
        let mut text = format!("{requester}: {} of {} requests left in 24 h", self.remaining, self.per_day);
        if let Some(next_ms) = self.next_ms.filter(|_| self.remaining == 0) {
            let secs = i64::try_from(next_ms.saturating_add(999) / 1000).unwrap_or(i64::MAX);
            text.push_str(&format!(", next at {}", format_rfc3339_utc(secs)));
        }
        text
    }
}

/// The queue of log requests: admission, approval (this node's own or its
/// operator's), denial and the spool of sealed bundles.
#[derive(Debug)]
pub struct LogRequests {
    enabled: bool,
    /// Empty while disabled.
    allowed: HashSet<PeerId>,
    own: PeerId,
    limits: LogRequestsConfig,
    spool: PathBuf,
    /// Where this node approves requests itself from; `None` leaves them
    /// to its operator.
    auto: Option<AutoApproval>,
    /// Wakes the automatic approval when a request is queued or an export
    /// ends.
    wake: tokio::sync::Notify,
    /// [`AUTO_EXPORT_TIMEOUT`] and [`AUTO_POLL_INTERVAL`], shorter or
    /// longer in tests.
    auto_timeout: Duration,
    auto_poll: Duration,
    exporter: Exporter,
    state: Mutex<State>,
}

fn mkdir_private(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

impl LogRequests {
    /// The queue of `config` for the node `own`, with sealed bundles in
    /// `spool`, whose requests wait for its operator.
    pub fn new(config: &LogRequestsConfig, own: PeerId, spool: PathBuf) -> Self {
        Self::with_approval(config, own, spool, None)
    }

    /// The queue of `config` for the node `own`, with sealed bundles in
    /// `spool`. With `auto` the node approves requests itself from its log
    /// files ([`Self::run_automatic_approval`]); without, they wait for its
    /// operator. Bundles left from an earlier run are deleted: their requests
    /// were in memory only.
    pub fn with_approval(config: &LogRequestsConfig, own: PeerId, spool: PathBuf, auto: Option<AutoApproval>) -> Self {
        let limits = config.clamped();
        let (allowed, invalid) = parse_allowed(&limits.allowed_peers);
        if !invalid.is_empty() {
            warn!(indices = ?invalid, scope = "this node",
                action = "replace them with base58 peer IDs, as `qclient node info` prints them, and restart",
                "diagnostics.logRequests.allowedPeers entries are not peer IDs; ignored");
        }
        let removed = Self::clear_spool(&spool);
        if removed > 0 {
            info!(removed, "diagnostics log bundles of an earlier run deleted");
        }
        let serves = if allowed.is_empty() { "this node only" } else { "this node and the allowlisted peers" };
        if limits.enabled && auto.is_some() {
            info!(log_peers = allowed.len(), requests_per_day = limits.requests_per_day,
                max_pending = limits.max_pending, ttl_secs = limits.ttl_secs,
                max_bundle_bytes = limits.max_bundle_bytes, approval = "automatic", serves,
                "diagnostics log requests enabled: requests from diagnostics.logRequests.allowedPeers are now approved \
                 automatically; this node exports, redacts and seals each requested window itself, without its operator");
        } else if limits.enabled {
            info!(log_peers = allowed.len(), requests_per_day = limits.requests_per_day,
                max_pending = limits.max_pending, ttl_secs = limits.ttl_secs,
                max_bundle_bytes = limits.max_bundle_bytes, approval = "manual", serves,
                "diagnostics log requests enabled: this node writes no log files, so each request waits for \
                 'qclient node diagnostics approve', which exports from the journal");
        } else if !limits.allowed_peers.is_empty() {
            info!(allowed_peers = limits.allowed_peers.len(),
                "diagnostics.logRequests.allowedPeers is ignored until diagnostics.logRequests.enabled is set");
        }
        Self {
            enabled: limits.enabled,
            allowed: if limits.enabled { allowed } else { HashSet::new() },
            own,
            auto: if limits.enabled { auto } else { None },
            limits,
            spool,
            wake: tokio::sync::Notify::new(),
            auto_timeout: AUTO_EXPORT_TIMEOUT,
            auto_poll: AUTO_POLL_INTERVAL,
            exporter: Exporter(build_automatic),
            state: Mutex::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether this node approves requests itself.
    pub fn automatic(&self) -> bool {
        self.auto.is_some()
    }

    fn clear_spool(spool: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(spool) else { return 0 };
        entries
            .flatten()
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".sealed") || name.ends_with(".partial")
            })
            .filter(|entry| std::fs::remove_file(entry.path()).is_ok())
            .count()
    }

    fn bundle_path(&self, id: &[u8; ID_LEN]) -> PathBuf {
        self.spool.join(format!("{}.sealed", hex::encode(id)))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ttl_ms(&self) -> u64 {
        self.limits.ttl_secs * 1000
    }

    /// Requests one peer may have waiting or ready at once: half of
    /// `maxPending`, at least one, so no peer fills the queue.
    fn per_requester(&self) -> usize {
        (self.limits.max_pending as usize / 2).max(1)
    }

    /// `caller`'s budget of requests in the last 24 h. Read it after
    /// [`Self::sweep`], which drops the requests older than that.
    fn budget(&self, state: &State, caller: &PeerId) -> Budget {
        let times = state.queued.get(caller);
        let used = u32::try_from(times.map_or(0, VecDeque::len)).unwrap_or(u32::MAX);
        Budget {
            remaining: self.limits.requests_per_day.saturating_sub(used),
            per_day: self.limits.requests_per_day,
            next_ms: times.and_then(VecDeque::front).map(|at| at.saturating_add(DAY_MS)),
        }
    }

    /// Whether `entry` holds a place in the queue: it waits for a decision
    /// or a fetch. A fetched (served) bundle holds none.
    fn holds_place(entry: &Entry) -> bool {
        entry.status != LogRequestStatus::Served
    }

    /// Make room for a new request: while the queue keeps `maxPending`
    /// requests, end the oldest fetched one and delete its bundle, so the
    /// queue and the spool stay within `maxPending` requests. Its requester
    /// sees it expired.
    fn make_room(&self, state: &mut State) {
        while state.entries.len() >= self.limits.max_pending as usize {
            let Some((id, requester, bytes)) = state
                .entries
                .iter()
                .filter(|(_, entry)| !Self::holds_place(entry))
                .min_by_key(|(_, entry)| entry.received_ms)
                .map(|(id, entry)| (*id, peer_tail(&entry.requester), entry.bundle_bytes))
            else {
                return;
            };
            self.finish(state, id, LogRequestStatus::Expired, LogRequestDenial::Operator);
            info!(request = %short_id(&id), %requester, bytes,
                "diagnostics log bundle deleted: its requester fetched it and a new request needs its place");
        }
    }

    /// Admit a requester: a handshake identity, requests enabled, and this
    /// node or an allowlisted peer.
    fn requester(&self, state: &mut State, caller: Option<&PeerId>, now_ms: u64) -> Result<PeerId, Status> {
        let refused = match caller {
            None => Refused::NoIdentity,
            Some(_) if !self.enabled => {
                debug!("diagnostics log request refused: diagnostics.logRequests is not enabled");
                return Err(Status::permission_denied(DENIED));
            }
            Some(caller) if *caller == self.own || self.allowed.contains(caller) => return Ok(*caller),
            Some(_) => Refused::NotAllowed,
        };
        state.refusals.note(refused, caller, now_ms);
        Err(Status::permission_denied(DENIED))
    }

    /// Admit this node's own identity, which only its operator's qclient holds.
    fn operator(&self, caller: Option<&PeerId>, now_ms: u64) -> Result<(), Status> {
        if caller == Some(&self.own) {
            return Ok(());
        }
        let refused = if caller.is_none() { Refused::NoIdentity } else { Refused::NotOperator };
        if self.enabled {
            self.state().refusals.note(refused, caller, now_ms);
        } else {
            debug!(reason = refused.label(), "diagnostics operator call refused: not this node's identity");
        }
        Err(Status::permission_denied(DENIED))
    }

    /// End request `id`, stopping this node's export of it.
    fn finish(&self, state: &mut State, id: [u8; ID_LEN], status: LogRequestStatus, denial: LogRequestDenial) {
        if let Some(export) = state.export.as_ref().filter(|export| export.id == id) {
            export.cancel.store(true, Ordering::Relaxed);
        }
        if let Some(entry) = state.entries.remove(&id) {
            if entry.bundle_bytes > 0 || entry.upload.is_some() {
                let _ = std::fs::remove_file(self.bundle_path(&id));
            }
            state.finished.push_back(Finished { id, requester: entry.requester, status, denial });
            while state.finished.len() > FINISHED_KEPT {
                state.finished.pop_front();
            }
        }
    }

    /// Expire requests past their time, give up stalled uploads, and remind
    /// the operator of waiting ones, at most hourly.
    fn sweep(&self, state: &mut State, now_ms: u64) -> Tick {
        let mut tick = Tick::default();
        for (id, entry) in state.entries.iter_mut() {
            if entry.upload.is_some_and(|upload| !upload.automatic && now_ms >= upload.deadline_ms) {
                entry.upload = None;
                let _ = std::fs::remove_file(self.bundle_path(id));
                warn!(request = %short_id(id), requester = %peer_tail(&entry.requester), scope = "this node",
                    action = "the operator's qclient stopped uploading; approve the request again",
                    "diagnostics log bundle upload abandoned");
                tick.abandoned += 1;
            }
        }
        let expired: Vec<([u8; ID_LEN], &'static str)> = state
            .entries
            .iter()
            .filter(|(_, entry)| now_ms >= entry.expires_ms && entry.upload.is_none())
            .map(|(id, entry)| (*id, status_name(entry.status)))
            .collect();
        for (id, was) in expired {
            let requester = peer_tail(&state.entries[&id].requester);
            self.finish(state, id, LogRequestStatus::Expired, LogRequestDenial::Operator);
            info!(request = %short_id(&id), %requester, was, "diagnostics log request expired");
            tick.expired += 1;
        }
        for (id, entry) in state.entries.iter_mut().filter(|_| self.auto.is_none()) {
            if entry.status == LogRequestStatus::Pending && now_ms.saturating_sub(entry.reminded_ms) >= REMINDER_INTERVAL_MS {
                entry.reminded_ms = now_ms;
                log_awaiting(id, entry, now_ms);
                tick.reminded += 1;
            }
        }
        state.nonces.retain(|_, (_, at)| now_ms.saturating_sub(*at) <= NONCE_HORIZON_MS);
        state.queued.retain(|_, times| {
            while times.front().is_some_and(|at| now_ms.saturating_sub(*at) >= DAY_MS) {
                times.pop_front();
            }
            !times.is_empty()
        });
        tick
    }

    /// Expire and remind; the node calls this every minute.
    pub fn tick(&self, now_ms: u64) -> Tick {
        let mut state = self.state();
        self.sweep(&mut state, now_ms)
    }

    /// The status `caller` sees of request `id`: none of another peer's.
    fn lookup(state: &State, caller: &PeerId, id: &[u8; ID_LEN]) -> Option<Seen> {
        if let Some(entry) = state.entries.get(id).filter(|entry| entry.requester == *caller) {
            return Some(Seen {
                status: entry.status,
                bundle_bytes: entry.bundle_bytes,
                expires_ms: entry.expires_ms,
                denial: LogRequestDenial::Operator,
            });
        }
        state.finished.iter().rev().find(|f| f.id == *id && f.requester == *caller).map(|f| Seen {
            status: f.status,
            bundle_bytes: 0,
            expires_ms: 0,
            denial: f.denial,
        })
    }

    /// Queue a signed request from `caller`, or refuse it.
    pub fn submit(&self, caller: Option<&PeerId>, signed: &SignedLogRequest, now_ms: u64) -> Result<SubmitLogRequestResponse, Status> {
        let mut state = self.state();
        let caller = self.requester(&mut state, caller, now_ms)?;
        self.sweep(&mut state, now_ms);
        let id = request_id(&signed.request);
        let refuse = |state: &mut State, refusal: LogRequestRefusal| -> Result<SubmitLogRequestResponse, Status> {
            let budget = self.budget(state, &caller);
            state.refusals.latest_budget = Some(budget.summary(&peer_tail(&caller)));
            state.refusals.note(Refused::Request(refusal), Some(&caller), now_ms);
            let mut response = SubmitLogRequestResponse { request_id: id.to_vec(), ..Default::default() };
            response.set_status(LogRequestStatus::Refused);
            response.set_refusal(refusal);
            budget.fill(&mut response);
            Ok(response)
        };
        let Ok(request) = LogRequest::decode(signed.request.as_slice()) else {
            return refuse(&mut state, LogRequestRefusal::Malformed);
        };
        // The key must be the caller's, so a request an allowlisted peer
        // signed is refused over another peer's channel.
        if quil_p2p::peer_id_from_falcon_pubkey(&request.requester_public_key) != caller.to_bytes() {
            state.refusals.note(Refused::KeyMismatch, Some(&caller), now_ms);
            return Err(Status::permission_denied(DENIED));
        }
        if !quil_crypto::falcon_verify(&request.requester_public_key, &signed.signature, &signed.request, DOMAIN) {
            state.refusals.note(Refused::BadSignature, Some(&caller), now_ms);
            return Err(Status::permission_denied(DENIED));
        }
        if let Some(seen) = Self::lookup(&state, &caller, &id) {
            let mut response = SubmitLogRequestResponse {
                request_id: id.to_vec(),
                expires_unix_ms: seen.expires_ms,
                automatic: self.automatic(),
                ..Default::default()
            };
            response.set_status(seen.status);
            self.budget(&state, &caller).fill(&mut response);
            return Ok(response);
        }
        let malformed = request.schema != REQUEST_SCHEMA
            || request.nonce.len() != NONCE_LEN
            || request.recipient_kem_public_key.len() != quil_crypto::SNTRUP761_PUBLIC_KEY_LEN
            || request.since_unix >= request.until_unix
            || i64::try_from(request.until_unix).is_err();
        let pending_here =
            state.entries.values().filter(|entry| entry.requester == caller && Self::holds_place(entry)).count();
        let pending = state.entries.values().filter(|entry| Self::holds_place(entry)).count();
        let refusal = if malformed {
            LogRequestRefusal::Malformed
        } else if request.target_peer_id != self.own.to_bytes() {
            LogRequestRefusal::WrongTarget
        } else if request.issued_unix_ms.abs_diff(now_ms) > MAX_CLOCK_SKEW_MS
            || request.until_unix > (now_ms + MAX_CLOCK_SKEW_MS) / 1000
        {
            LogRequestRefusal::Stale
        } else if request.filters.iter().any(|f| !SHARD_FILTER_BYTES.contains(&f.len())) {
            LogRequestRefusal::FilterLength
        } else if request.until_unix - request.since_unix > MAX_WINDOW_SECS {
            LogRequestRefusal::WindowTooLong
        } else if request.filters.len() > MAX_FILTERS {
            LogRequestRefusal::TooManyFilters
        } else if state.nonces.contains_key(&(caller, request.nonce.clone())) {
            LogRequestRefusal::Replayed
        } else if self.budget(&state, &caller).remaining == 0 {
            LogRequestRefusal::OverBudget
        } else if pending_here >= self.per_requester() {
            LogRequestRefusal::TooManyPending
        } else if pending >= self.limits.max_pending as usize || state.nonces.len() >= NONCE_CACHE {
            LogRequestRefusal::QueueFull
        } else {
            LogRequestRefusal::None
        };
        if refusal != LogRequestRefusal::None {
            return refuse(&mut state, refusal);
        }
        self.make_room(&mut state);
        state.nonces.insert((caller, request.nonce.clone()), (id, now_ms));
        state.queued.entry(caller).or_default().push_back(now_ms);
        let entry = Entry {
            requester: caller,
            request,
            status: LogRequestStatus::Pending,
            received_ms: now_ms,
            expires_ms: now_ms + self.ttl_ms(),
            reminded_ms: now_ms,
            bundle_bytes: 0,
            bundle_sha256: Vec::new(),
            upload: None,
            attempted: false,
        };
        if self.automatic() {
            self.wake.notify_one();
        } else {
            log_awaiting(&id, &entry, now_ms);
        }
        let expires_unix_ms = entry.expires_ms;
        state.entries.insert(id, entry);
        let mut response =
            SubmitLogRequestResponse { request_id: id.to_vec(), expires_unix_ms, automatic: self.automatic(), ..Default::default() };
        response.set_status(LogRequestStatus::Pending);
        self.budget(&state, &caller).fill(&mut response);
        Ok(response)
    }

    /// The status of `caller`'s request `id`.
    pub fn status(&self, caller: Option<&PeerId>, id: &[u8], now_ms: u64) -> Result<LogRequestStatusResponse, Status> {
        let mut state = self.state();
        let caller = self.requester(&mut state, caller, now_ms)?;
        self.sweep(&mut state, now_ms);
        let id = parse_id(id)?;
        let seen = Self::lookup(&state, &caller, &id).ok_or_else(not_found)?;
        let mut response = LogRequestStatusResponse {
            request_id: id.to_vec(),
            bundle_bytes: seen.bundle_bytes,
            expires_unix_ms: seen.expires_ms,
            ..Default::default()
        };
        response.set_status(seen.status);
        response.set_denial(seen.denial);
        Ok(response)
    }

    /// The spool file, size and digest of `caller`'s approved request `id`.
    fn bundle(&self, caller: Option<&PeerId>, id: &[u8], now_ms: u64) -> Result<([u8; ID_LEN], PathBuf, u64, Vec<u8>), Status> {
        let mut state = self.state();
        let caller = self.requester(&mut state, caller, now_ms)?;
        self.sweep(&mut state, now_ms);
        let id = parse_id(id)?;
        let status = Self::lookup(&state, &caller, &id).ok_or_else(not_found)?.status;
        if !matches!(status, LogRequestStatus::Ready | LogRequestStatus::Served) {
            return Err(Status::failed_precondition(format!("the log request is {}", status_name(status))));
        }
        let entry = &state.entries[&id];
        Ok((id, self.bundle_path(&id), entry.bundle_bytes, entry.bundle_sha256.clone()))
    }

    /// A fetch of `id` sent its last byte.
    fn served(&self, id: &[u8; ID_LEN]) {
        let mut state = self.state();
        if let Some(entry) = state.entries.get_mut(id) {
            if entry.status == LogRequestStatus::Ready {
                entry.status = LogRequestStatus::Served;
                info!(request = %short_id(id), requester = %peer_tail(&entry.requester), bytes = entry.bundle_bytes,
                    "diagnostics log bundle served");
            }
        }
    }

    /// Every request, for this node's operator.
    pub fn list(&self, caller: Option<&PeerId>, now_ms: u64) -> Result<ListLogRequestsResponse, Status> {
        self.operator(caller, now_ms)?;
        let mut state = self.state();
        self.sweep(&mut state, now_ms);
        let requests = state
            .entries
            .iter()
            .map(|(id, entry)| {
                let mut pending = PendingLogRequest {
                    request_id: id.to_vec(),
                    requester_peer_id: entry.requester.to_bytes(),
                    received_unix_ms: entry.received_ms,
                    expires_unix_ms: entry.expires_ms,
                    since_unix: entry.request.since_unix,
                    until_unix: entry.request.until_unix,
                    filters: entry.request.filters.clone(),
                    recipient_kem_public_key: entry.request.recipient_kem_public_key.clone(),
                    bundle_bytes: entry.bundle_bytes,
                    ..Default::default()
                };
                pending.set_status(entry.status);
                pending
            })
            .collect();
        Ok(ListLogRequestsResponse { requests, max_bundle_bytes: self.limits.max_bundle_bytes, automatic: self.automatic() })
    }

    /// Deny a request, for this node's operator: a pending one (even while
    /// its upload runs, which then is dropped), or withdraw an approved
    /// bundle, fetched or not, deleting it.
    pub fn deny(&self, caller: Option<&PeerId>, id: &[u8], now_ms: u64) -> Result<DenyLogRequestResponse, Status> {
        self.operator(caller, now_ms)?;
        let mut state = self.state();
        self.sweep(&mut state, now_ms);
        let id = parse_id(id)?;
        let entry = state.entries.get(&id).ok_or_else(not_found)?;
        let (requester, was) = (peer_tail(&entry.requester), status_name(entry.status));
        let withdrawn = entry.status != LogRequestStatus::Pending;
        let bytes = entry.bundle_bytes;
        self.finish(&mut state, id, LogRequestStatus::Denied, LogRequestDenial::Operator);
        if withdrawn {
            info!(request = %short_id(&id), %requester, was, bytes, "diagnostics log bundle withdrawn");
        } else {
            info!(request = %short_id(&id), %requester, "diagnostics log request denied");
        }
        let mut response = DenyLogRequestResponse::default();
        response.set_status(LogRequestStatus::Denied);
        Ok(response)
    }

    /// Start the upload of the bundle of pending request `id`; its token.
    fn begin_upload(&self, id: &[u8], total_bytes: u64, now_ms: u64) -> Result<([u8; ID_LEN], u64), Status> {
        let mut state = self.state();
        self.sweep(&mut state, now_ms);
        let id = parse_id(id)?;
        if state.export.is_some() || state.entries.values().any(|entry| entry.upload.is_some()) {
            return Err(Status::resource_exhausted("another log bundle upload or this node's own export is running"));
        }
        state.uploads += 1;
        let token = state.uploads;
        let entry = state.entries.get_mut(&id).ok_or_else(not_found)?;
        if entry.status != LogRequestStatus::Pending {
            return Err(Status::failed_precondition(format!("the log request is {}", status_name(entry.status))));
        }
        if total_bytes == 0 || total_bytes > self.limits.max_bundle_bytes {
            return Err(Status::invalid_argument(format!(
                "a sealed bundle of {total_bytes} bytes; this node accepts 1 to {} (diagnostics.logRequests.maxBundleBytes)",
                self.limits.max_bundle_bytes
            )));
        }
        let deadline_ms = now_ms + upload_timeout(total_bytes).as_millis() as u64 + 60_000;
        entry.upload = Some(Upload { token, deadline_ms, automatic: false });
        Ok((id, token))
    }

    /// Give up the upload `token` of `id`, if it still runs: its handler
    /// ended without storing it.
    fn abandon_upload(&self, id: &[u8; ID_LEN], token: u64) {
        let mut state = self.state();
        if let Some(entry) = state.entries.get_mut(id).filter(|entry| entry.upload.is_some_and(|u| u.token == token)) {
            entry.upload = None;
            let _ = std::fs::remove_file(self.bundle_path(id));
        }
    }

    /// Store the bundle of upload `token` of `id`, or abandon the upload;
    /// `automatic` describes this node's own approval for its log line.
    fn finish_upload(
        &self,
        id: &[u8; ID_LEN],
        token: u64,
        bundle: Result<(Vec<u8>, Vec<u8>), Status>,
        now_ms: u64,
        automatic: Option<&Approved<'_>>,
    ) -> Result<UploadLogBundleResponse, Status> {
        let stored = bundle.and_then(|(data, sha256)| {
            mkdir_private(&self.spool)
                .and_then(|()| write_private(&self.bundle_path(id), &data))
                .map_err(|error| {
                    // An automatic approval logs its own failure.
                    if automatic.is_none() {
                        warn!(request = %short_id(id), %error, scope = "this node",
                            action = "check that the node can write its config directory's .diagnostics/log-bundles",
                            "diagnostics log bundle not stored");
                    }
                    Status::internal(format!("the node could not store the bundle in .diagnostics/log-bundles: {error}"))
                })
                .map(|()| (data.len() as u64, sha256))
        });
        let mut state = self.state();
        let Some(entry) = state.entries.get_mut(id).filter(|entry| entry.upload.is_some_and(|u| u.token == token)) else {
            // Denied, expired or given up meanwhile.
            let _ = std::fs::remove_file(self.bundle_path(id));
            return Err(Status::failed_precondition("the log request was denied, expired or gave up this upload"));
        };
        entry.upload = None;
        let (bytes, sha256) = match stored {
            Ok(stored) => stored,
            Err(status) => {
                let _ = std::fs::remove_file(self.bundle_path(id));
                return Err(status);
            }
        };
        entry.status = LogRequestStatus::Ready;
        entry.bundle_bytes = bytes;
        entry.bundle_sha256 = sha256;
        entry.expires_ms = now_ms + self.ttl_ms();
        match automatic {
            Some(approved) => info!(request = %short_id(id), requester = %peer_tail(&entry.requester),
                window = %window_text(&entry.request), filters = entry.request.filters.len(), lines = approved.lines,
                bytes, duration_ms = approved.duration_ms, token_map = %approved.token_map,
                expires_in_secs = self.limits.ttl_secs, scope = "this node",
                "diagnostics log request approved automatically: its requester is in diagnostics.logRequests.allowedPeers"),
            None => info!(request = %short_id(id), requester = %peer_tail(&entry.requester), bytes,
                expires_in_secs = self.limits.ttl_secs, "diagnostics log request approved"),
        }
        let mut response = UploadLogBundleResponse { expires_unix_ms: entry.expires_ms, ..Default::default() };
        response.set_status(LogRequestStatus::Ready);
        Ok(response)
    }
}

/// What `caller` sees of a request.
#[derive(Debug, Clone, Copy)]
struct Seen {
    status: LogRequestStatus,
    bundle_bytes: u64,
    expires_ms: u64,
    denial: LogRequestDenial,
}

/// This node's own approval of a request, for its log line.
struct Approved<'a> {
    lines: u64,
    duration_ms: u64,
    /// The token map, from the node's working directory when under it.
    token_map: &'a str,
}

/// A request the automatic approval took, the token of its export and the
/// flag that stops it.
#[derive(Debug, Clone)]
struct AutoJob {
    id: [u8; ID_LEN],
    token: u64,
    cancel: Arc<AtomicBool>,
    request: bundle::AutoRequest,
}

/// Ends this node's export when its blocking task ends, however it ends,
/// and wakes the approval for the next request.
struct ExportDone {
    queue: Arc<LogRequests>,
    token: u64,
}

impl Drop for ExportDone {
    fn drop(&mut self) {
        self.queue.export_done(self.token);
    }
}

/// Stops an export whose approval was dropped before it ended (node
/// shutdown), unless disarmed.
struct StopOnDrop(Option<Arc<AtomicBool>>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

impl LogRequests {
    /// Take the oldest pending request no approval took yet, unless an
    /// export or an upload runs: one export at a time, each request once.
    fn take_auto_job(&self, now_ms: u64) -> Option<AutoJob> {
        let mut state = self.state();
        self.sweep(&mut state, now_ms);
        if state.export.is_some() || state.entries.values().any(|entry| entry.upload.is_some()) {
            return None;
        }
        let id = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.status == LogRequestStatus::Pending && !entry.attempted)
            .min_by_key(|(_, entry)| entry.received_ms)
            .map(|(id, _)| *id)?;
        state.uploads += 1;
        let token = state.uploads;
        let cancel = Arc::new(AtomicBool::new(false));
        state.export = Some(RunningExport { id, token, cancel: cancel.clone() });
        let entry = state.entries.get_mut(&id)?;
        entry.attempted = true;
        // The export's own timeout ends it, not the upload deadline.
        entry.upload = Some(Upload { token, deadline_ms: u64::MAX, automatic: true });
        let request = bundle::AutoRequest {
            id: id.to_vec(),
            requester: peer_tail(&entry.requester),
            since_unix: entry.request.since_unix,
            until_unix: entry.request.until_unix,
            filters: entry.request.filters.clone(),
            recipient_kem_public_key: entry.request.recipient_kem_public_key.clone(),
        };
        Some(AutoJob { id, token, cancel, request })
    }

    /// The export of `token` ended: let the next one start.
    fn export_done(&self, token: u64) {
        let mut state = self.state();
        if state.export.as_ref().is_some_and(|export| export.token == token) {
            state.export = None;
        }
        drop(state);
        self.wake.notify_one();
    }

    /// Deny the request of export `token` of `id` as failed for `reason`, if
    /// it still waits for that export.
    fn abort_auto(&self, id: [u8; ID_LEN], token: u64, reason: &str, duration_ms: u64) {
        let mut state = self.state();
        let Some(entry) = state.entries.get(&id).filter(|entry| {
            entry.status == LogRequestStatus::Pending && entry.upload.is_some_and(|upload| upload.token == token)
        }) else {
            return;
        };
        let (requester, window, filters) = (peer_tail(&entry.requester), window_text(&entry.request), entry.request.filters.len());
        self.finish(&mut state, id, LogRequestStatus::Denied, LogRequestDenial::ExportFailed);
        warn!(request = %short_id(&id), %requester, %window, filters, denial = denial_name(LogRequestDenial::ExportFailed),
            reason, duration_ms, scope = "this node",
            action = "check the node's disk and its log directory; the requester sees it denied as failed and can ask again",
            "diagnostics log request automatic approval failed; request denied");
    }

    /// Store the bundle of automatic approval `job`, or deny its request with
    /// the reason it failed; drop it when the request was denied or expired
    /// meanwhile.
    fn settle_auto(&self, job: &AutoJob, built: anyhow::Result<bundle::AutoBundle>, duration_ms: u64, now_ms: u64) {
        let failure = match built {
            Ok(built) => {
                let token_map = node_relative(&built.token_map);
                let approved = Approved { lines: built.lines_kept, duration_ms, token_map: &token_map };
                match self.finish_upload(&job.id, job.token, Ok((built.sealed, built.sha256)), now_ms, Some(&approved)) {
                    Ok(_) => return,
                    Err(status) => {
                        let _ = std::fs::remove_file(&built.token_map);
                        anyhow::anyhow!("{}", status.message())
                    }
                }
            }
            Err(error) => error,
        };
        let denial =
            if bundle::is_too_large(&failure) { LogRequestDenial::TooLarge } else { LogRequestDenial::ExportFailed };
        let mut state = self.state();
        let Some(entry) = state.entries.get(&job.id).filter(|entry| {
            entry.status == LogRequestStatus::Pending && entry.upload.is_none_or(|upload| upload.token == job.token)
        }) else {
            info!(request = %short_id(&job.id), requester = %job.request.requester, duration_ms,
                "diagnostics log request automatic export dropped: the request was denied, expired or timed out meanwhile");
            return;
        };
        let window = window_text(&entry.request);
        let filters = entry.request.filters.len();
        self.finish(&mut state, job.id, LogRequestStatus::Denied, denial);
        let action = if denial == LogRequestDenial::TooLarge {
            "the requester sees it denied as too large and can ask for a shorter window or fewer shard filters; \
             to send more, raise diagnostics.logRequests.maxBundleBytes and restart"
        } else {
            "check that the node can read its log directory and write its config directory's .diagnostics; \
             the requester sees it denied as failed and can ask again"
        };
        warn!(request = %short_id(&job.id), requester = %job.request.requester, %window, filters,
            denial = denial_name(denial), reason = %format!("{failure:#}"), duration_ms, scope = "this node", action,
            "diagnostics log request automatic approval failed; request denied");
    }

    /// Approve the oldest waiting request from this node's log files;
    /// whether there was one. The export, the seal and every file write run
    /// on a blocking task, which stops when the request is denied, its
    /// export runs over [`AUTO_EXPORT_TIMEOUT`], or this future is dropped.
    pub async fn approve_next(self: &Arc<Self>) -> bool {
        let Some(auto) = self.auto.clone() else { return false };
        let started = now_ms();
        let Some(job) = self.take_auto_job(started) else { return false };
        let (id, token, cancel) = (job.id, job.token, job.cancel.clone());
        let mut stop = StopOnDrop(Some(cancel.clone()));
        let (queue, exporter) = (self.clone(), self.exporter);
        let max = usize::try_from(self.limits.max_bundle_bytes).unwrap_or(usize::MAX);
        let export = tokio::task::spawn_blocking(move || {
            let _done = ExportDone { queue: queue.clone(), token };
            let built = (exporter.0)(&auto, &job.request, max, (now_ms() / 1000) as i64, &job.cancel);
            let done = now_ms();
            queue.settle_auto(&job, built, done.saturating_sub(started), done);
        });
        match tokio::time::timeout(self.auto_timeout, export).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => self.abort_auto(id, token, &format!("the export task ended: {error}"), now_ms().saturating_sub(started)),
            Err(_) => {
                cancel.store(true, Ordering::Relaxed);
                let reason = format!("the export ran over {} s", self.auto_timeout.as_secs());
                self.abort_auto(id, token, &reason, now_ms().saturating_sub(started));
            }
        }
        stop.0 = None;
        true
    }

    /// Approve requests as they are queued, one at a time; runs until
    /// dropped, which stops a running export. Does nothing on a node whose
    /// operator approves.
    pub async fn run_automatic_approval(self: &Arc<Self>) {
        if !self.automatic() {
            return;
        }
        loop {
            while self.approve_next().await {}
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(self.auto_poll) => {}
            }
        }
    }
}

/// `path` from the node's working directory when under it, as its operator
/// finds it from the node directory.
fn node_relative(path: &Path) -> String {
    let relative = std::env::current_dir().ok().and_then(|cwd| path.strip_prefix(cwd).ok().map(Path::to_path_buf));
    relative.as_deref().unwrap_or(path).display().to_string()
}

/// A request's window, as logs show it.
fn window_text(request: &LogRequest) -> String {
    let utc = |secs: u64| format_rfc3339_utc(i64::try_from(secs).unwrap_or(i64::MAX));
    format!("{}..{}", utc(request.since_unix), utc(request.until_unix))
}

/// The name of `denial` as logs show it.
pub fn denial_name(denial: LogRequestDenial) -> &'static str {
    match denial {
        LogRequestDenial::Operator => "operator",
        LogRequestDenial::TooLarge => "too_large",
        LogRequestDenial::ExportFailed => "export_failed",
    }
}

fn log_awaiting(id: &[u8; ID_LEN], entry: &Entry, now_ms: u64) {
    let id = short_id(id);
    warn!(request = %id, requester = %peer_tail(&entry.requester),
        since_unix = entry.request.since_unix, until_unix = entry.request.until_unix,
        filters = entry.request.filters.len(), pending_secs = now_ms.saturating_sub(entry.received_ms) / 1000,
        expires_in_secs = entry.expires_ms.saturating_sub(now_ms) / 1000, scope = "this node",
        action = %format!("review with 'qclient node diagnostics pending'; approve with 'qclient node diagnostics \
            approve {id}' (it shows a redacted preview first) or deny with 'qclient node diagnostics deny {id}'"),
        "diagnostics log request awaiting approval");
}

/// The name of `status` as qclient and logs show it.
pub fn status_name(status: LogRequestStatus) -> &'static str {
    match status {
        LogRequestStatus::Unspecified => "unknown",
        LogRequestStatus::Pending => "pending",
        LogRequestStatus::Ready => "ready",
        LogRequestStatus::Denied => "denied",
        LogRequestStatus::Expired => "expired",
        LogRequestStatus::Served => "served",
        LogRequestStatus::Refused => "refused",
    }
}

fn not_found() -> Status {
    Status::not_found("no such log request")
}

fn parse_id(id: &[u8]) -> Result<[u8; ID_LEN], Status> {
    id.try_into().map_err(|_| Status::invalid_argument("a log request ID is 16 bytes"))
}

fn caller<T>(request: &Request<T>) -> Option<PeerId> {
    // Fail closed: only the handshake identity admits a caller.
    request.extensions().get::<AuthenticatedPeer>().map(|auth| auth.peer_id)
}

fn now_ms() -> u64 {
    quil_engine::worker_execution::now_ms()
}

/// Both log request services, over one queue.
#[derive(Debug, Clone)]
pub struct LogRequestServer {
    requests: Arc<LogRequests>,
}

impl LogRequestServer {
    pub fn new(requests: Arc<LogRequests>) -> Self {
        Self { requests }
    }

    /// The service for requesting peers, bounded to their small messages.
    pub fn peer_service(&self) -> DiagnosticsLogServiceServer<Self> {
        DiagnosticsLogServiceServer::new(self.clone())
            .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RESPONSE_BYTES)
    }

    /// The service for this node's operator.
    pub fn operator_service(&self) -> DiagnosticsOperatorServiceServer<Self> {
        DiagnosticsOperatorServiceServer::new(self.clone())
            .max_decoding_message_size(MAX_OPERATOR_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RESPONSE_BYTES)
    }
}

type ChunkStream = Pin<Box<dyn futures::Stream<Item = Result<LogBundleChunk, Status>> + Send + 'static>>;

fn read_chunk(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _};
    let mut file = std::fs::File::open(path)?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut data = vec![0u8; len];
    file.read_exact(&mut data)?;
    Ok(data)
}

#[tonic::async_trait]
impl DiagnosticsLogService for LogRequestServer {
    async fn submit_log_request(&self, request: Request<SignedLogRequest>) -> Result<Response<SubmitLogRequestResponse>, Status> {
        let caller = caller(&request);
        self.requests.submit(caller.as_ref(), request.get_ref(), now_ms()).map(Response::new)
    }

    async fn get_log_request_status(&self, request: Request<GetLogRequestStatusRequest>) -> Result<Response<LogRequestStatusResponse>, Status> {
        let caller = caller(&request);
        self.requests.status(caller.as_ref(), &request.get_ref().request_id, now_ms()).map(Response::new)
    }

    type FetchLogBundleStream = ChunkStream;

    async fn fetch_log_bundle(&self, request: Request<FetchLogBundleRequest>) -> Result<Response<ChunkStream>, Status> {
        let caller = caller(&request);
        let (id, path, total, sha256) = self.requests.bundle(caller.as_ref(), &request.get_ref().request_id, now_ms())?;
        let start = request.get_ref().offset;
        if start > total {
            return Err(Status::out_of_range(format!("the bundle has {total} bytes")));
        }
        let requests = self.requests.clone();
        let stream = async_stream::try_stream! {
            let mut offset = start;
            loop {
                let len = (total - offset).min(FETCH_CHUNK_BYTES as u64) as usize;
                let path = path.clone();
                let data = tokio::task::spawn_blocking(move || read_chunk(&path, offset, len))
                    .await
                    .map_err(|_| Status::unavailable("bundle read interrupted"))?
                    .map_err(|_| Status::unavailable("the bundle is no longer available"))?;
                let chunk = LogBundleChunk { total_bytes: total, offset, data, sha256: sha256.clone() };
                offset += len as u64;
                yield chunk;
                if offset >= total {
                    requests.served(&id);
                    break;
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tonic::async_trait]
impl DiagnosticsOperatorService for LogRequestServer {
    async fn list_log_requests(&self, request: Request<ListLogRequestsRequest>) -> Result<Response<ListLogRequestsResponse>, Status> {
        let caller = caller(&request);
        self.requests.list(caller.as_ref(), now_ms()).map(Response::new)
    }

    async fn deny_log_request(&self, request: Request<DenyLogRequestRequest>) -> Result<Response<DenyLogRequestResponse>, Status> {
        let caller = caller(&request);
        self.requests.deny(caller.as_ref(), &request.get_ref().request_id, now_ms()).map(Response::new)
    }

    async fn upload_log_bundle(&self, request: Request<Streaming<UploadLogBundleChunk>>) -> Result<Response<UploadLogBundleResponse>, Status> {
        // The identity is checked before any chunk is read.
        let caller = caller(&request);
        self.receive_upload(caller.as_ref(), request.into_inner()).await.map(Response::new)
    }
}

/// Gives up its upload when dropped before it is disarmed: on an error, or
/// when the operator's qclient goes away and the handler future is dropped.
struct UploadGuard {
    requests: Arc<LogRequests>,
    id: [u8; ID_LEN],
    token: u64,
    armed: bool,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if self.armed {
            self.requests.abandon_upload(&self.id, self.token);
        }
    }
}

impl LogRequestServer {
    /// Receive an operator's upload from `chunks` and store it.
    async fn receive_upload<S>(&self, caller: Option<&PeerId>, mut chunks: S) -> Result<UploadLogBundleResponse, Status>
    where
        S: futures::Stream<Item = Result<UploadLogBundleChunk, Status>> + Unpin,
    {
        use futures::StreamExt as _;
        self.requests.operator(caller, now_ms())?;
        let first = chunks.next().await.transpose()?.ok_or_else(|| Status::invalid_argument("an empty upload"))?;
        let (id, token) = self.requests.begin_upload(&first.request_id, first.total_bytes, now_ms())?;
        let mut guard = UploadGuard { requests: self.requests.clone(), id, token, armed: true };
        let received: Result<(Vec<u8>, Vec<u8>), Status> = async {
            let total = first.total_bytes as usize;
            let mut data = Vec::with_capacity(total);
            data.extend_from_slice(&first.data);
            while data.len() < total {
                let chunk = chunks.next().await.transpose()?.ok_or_else(|| Status::invalid_argument("the upload ended early"))?;
                if data.len() + chunk.data.len() > total {
                    return Err(Status::invalid_argument("the upload is longer than announced"));
                }
                data.extend_from_slice(&chunk.data);
            }
            if data.len() != total || chunks.next().await.transpose()?.is_some() {
                return Err(Status::invalid_argument("the upload is longer than announced"));
            }
            let sha256 = Sha256::digest(&data).to_vec();
            if sha256 != first.sha256 {
                return Err(Status::invalid_argument("the upload does not match its SHA-256"));
            }
            Ok((data, sha256))
        }
        .await;
        let requests = self.requests.clone();
        let stored = tokio::task::spawn_blocking(move || requests.finish_upload(&id, token, received, now_ms(), None))
            .await
            .map_err(|_| Status::internal("the bundle store was interrupted"))?;
        // finish_upload settled the upload either way.
        guard.armed = false;
        stored
    }
}

/// The PQNoise channel to the peer listener at `addr`, as the holder of
/// `falcon_signing_key`, refusing an endpoint that does not prove `expected`.
pub async fn peer_channel(
    addr: &str,
    falcon_signing_key: &[u8],
    expected: PeerId,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))?
        .connect_timeout(Duration::from_secs(15))
        .tcp_nodelay(true);
    let connector = crate::QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).with_expected_peer(expected);
    Ok(endpoint.connect_with_connector(connector).await?)
}

/// `message` as a request that gives up after `timeout`: [`CALL_TIMEOUT`]
/// for a unary call, [`upload_timeout`] for an upload. The channel itself
/// has no deadline, so a large bundle's transfer is not cut off.
pub fn timed<T>(message: T, timeout: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

/// A client of a target's log request service.
pub type LogPeerClient = DiagnosticsLogServiceClient<Channel>;
/// A client of this node's operator service.
pub type OperatorClient = DiagnosticsOperatorServiceClient<Channel>;

/// A client of a target's log request service.
pub async fn connect_log_peer(
    addr: &str,
    falcon_signing_key: &[u8],
    target: PeerId,
) -> Result<LogPeerClient, Box<dyn std::error::Error + Send + Sync>> {
    let channel = peer_channel(addr, falcon_signing_key, target).await?;
    Ok(DiagnosticsLogServiceClient::new(channel).max_decoding_message_size(MAX_RESPONSE_BYTES))
}

/// A client of this node's operator service, dialing with its own key.
pub async fn connect_operator(
    addr: &str,
    falcon_signing_key: &[u8],
) -> Result<OperatorClient, Box<dyn std::error::Error + Send + Sync>> {
    let own = quil_p2p::Keypair::falcon_from_bytes(falcon_signing_key)?.public().to_peer_id();
    let channel = peer_channel(addr, falcon_signing_key, own).await?;
    Ok(DiagnosticsOperatorServiceClient::new(channel)
        .max_decoding_message_size(MAX_RESPONSE_BYTES)
        .max_encoding_message_size(MAX_OPERATOR_MESSAGE_BYTES))
}

/// Parse a peer ID from its bytes, for rendering.
pub fn peer_from_bytes(bytes: &[u8]) -> Option<PeerId> {
    PeerId::from_bytes(bytes).ok()
}

/// Parse a base58 peer ID.
pub fn parse_peer(text: &str) -> Option<PeerId> {
    PeerId::from_str(text.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    struct Key {
        signing: Vec<u8>,
        public: Vec<u8>,
        peer: PeerId,
    }

    fn key() -> Key {
        let signing = quil_p2p::generate_falcon_signing_key();
        let public = quil_crypto::falcon_public_from_signing_key(&signing).unwrap();
        let peer = quil_p2p::Keypair::falcon_from_bytes(&signing).unwrap().public().to_peer_id();
        Key { signing, public, peer }
    }

    fn config(enabled: bool, allowed: &[&Key]) -> LogRequestsConfig {
        LogRequestsConfig {
            enabled,
            allowed_peers: allowed.iter().map(|key| key.peer.to_base58()).collect(),
            ..Default::default()
        }
    }

    fn request(from: &Key, target: &PeerId, nonce: u8) -> LogRequest {
        LogRequest {
            schema: REQUEST_SCHEMA,
            target_peer_id: target.to_bytes(),
            requester_public_key: from.public.clone(),
            issued_unix_ms: NOW,
            nonce: vec![nonce; NONCE_LEN],
            since_unix: NOW / 1000 - 6 * 3600,
            until_unix: NOW / 1000,
            filters: vec![vec![0xa1; 32], vec![0xb2; 32]],
            recipient_kem_public_key: vec![7; quil_crypto::SNTRUP761_PUBLIC_KEY_LEN],
        }
    }

    fn signed(from: &Key, request: &LogRequest) -> SignedLogRequest {
        sign_request(request, &from.signing).unwrap()
    }

    fn queue(config: &LogRequestsConfig, own: &Key) -> (LogRequests, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (LogRequests::new(config, own.peer, dir.path().join("log-bundles")), dir)
    }

    fn refusal(response: Result<SubmitLogRequestResponse, Status>) -> LogRequestRefusal {
        let response = response.unwrap();
        assert_eq!(response.status(), LogRequestStatus::Refused, "{response:?}");
        response.refusal()
    }

    fn denied(result: Result<impl std::fmt::Debug, Status>) {
        let status = result.unwrap_err();
        assert_eq!((status.code(), status.message()), (tonic::Code::PermissionDenied, DENIED));
    }

    #[test]
    fn the_request_id_is_stable_and_the_signature_binds_the_domain() {
        let (from, target) = (key(), key());
        let request = request(&from, &target.peer, 1);
        let one = signed(&from, &request);
        assert_eq!(request_id(&one.request), request_id(&signed(&from, &request).request));
        assert_ne!(request_id(&one.request), request_id(&signed(&from, &self::request(&from, &target.peer, 2)).request));
        assert!(quil_crypto::falcon_verify(&from.public, &one.signature, &one.request, DOMAIN));
        assert!(!quil_crypto::falcon_verify(&from.public, &one.signature, &one.request, b"quil/other"));
        assert_eq!(quil_p2p::peer_id_from_falcon_pubkey(&from.public), from.peer.to_bytes());
        assert!(sign_request(&request, &target.signing).is_err(), "only the named key signs");
        assert_eq!(short_id(&[0xab, 0xcd, 0xef, 0x01, 0x23]), "abcdef01");
    }

    /// Disabled, unlisted, unidentified, a key that is not the caller's and
    /// a bad signature all get the same PERMISSION_DENIED.
    #[test]
    fn callers_not_admitted_are_refused_alike() {
        let (own, listed, other, unlisted) = (key(), key(), key(), key());
        let (enabled, _a) = queue(&config(true, &[&listed, &other]), &own);
        let (disabled, _b) = queue(&config(false, &[&listed]), &own);
        let good = signed(&listed, &request(&listed, &own.peer, 1));
        denied(disabled.submit(Some(&listed.peer), &good, NOW));
        denied(enabled.submit(None, &good, NOW));
        denied(enabled.submit(Some(&unlisted.peer), &signed(&unlisted, &request(&unlisted, &own.peer, 1)), NOW));
        denied(enabled.submit(Some(&other.peer), &good, NOW));
        let mut forged = good.clone();
        forged.signature[40] ^= 1;
        denied(enabled.submit(Some(&listed.peer), &forged, NOW));
        let mut swapped = request(&listed, &own.peer, 1);
        swapped.since_unix -= 1;
        denied(enabled.submit(Some(&listed.peer), &SignedLogRequest { request: swapped.encode_to_vec(), signature: good.signature.clone() }, NOW));
        for result in [disabled.status(Some(&listed.peer), &[0; 16], NOW).map(|_| ()), enabled.status(Some(&unlisted.peer), &[0; 16], NOW).map(|_| ())] {
            denied(result);
        }
        assert!(enabled.state().entries.is_empty());
        let queued = enabled.submit(Some(&listed.peer), &good, NOW).unwrap();
        assert_eq!((queued.status(), queued.refusal()), (LogRequestStatus::Pending, LogRequestRefusal::None));
        assert_eq!(queued.request_id, request_id(&good.request).to_vec());
        assert_eq!(queued.expires_unix_ms, NOW + 86_400_000);
        let own_request = signed(&own, &request(&own, &own.peer, 9));
        assert_eq!(enabled.submit(Some(&own.peer), &own_request, NOW).unwrap().status(), LogRequestStatus::Pending, "this node itself");
    }

    #[test]
    fn an_allowlisted_peers_bad_requests_are_refused_by_reason() {
        let (own, listed, elsewhere) = (key(), key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let submit = |request: &LogRequest| queue.submit(Some(&listed.peer), &signed(&listed, request), NOW);
        let base = request(&listed, &own.peer, 1);
        assert_eq!(refusal(submit(&request(&listed, &elsewhere.peer, 1))), LogRequestRefusal::WrongTarget);
        for issued in [NOW - MAX_CLOCK_SKEW_MS - 1, NOW + MAX_CLOCK_SKEW_MS + 1] {
            assert_eq!(refusal(submit(&LogRequest { issued_unix_ms: issued, ..base.clone() })), LogRequestRefusal::Stale);
        }
        assert_eq!(refusal(submit(&LogRequest { since_unix: base.until_unix - MAX_WINDOW_SECS - 1, ..base.clone() })),
            LogRequestRefusal::WindowTooLong);
        assert_eq!(refusal(submit(&LogRequest { filters: vec![vec![1; 32]; MAX_FILTERS + 1], ..base.clone() })),
            LogRequestRefusal::TooManyFilters);
        for malformed in [
            LogRequest { since_unix: base.until_unix, ..base.clone() },
            LogRequest { since_unix: base.until_unix + 1, ..base.clone() },
            LogRequest { since_unix: 1 << 63, until_unix: u64::MAX, ..base.clone() },
            LogRequest { recipient_kem_public_key: vec![7; 32], ..base.clone() },
            LogRequest { nonce: vec![1; 8], ..base.clone() },
            LogRequest { schema: 2, ..base.clone() },
        ] {
            assert_eq!(refusal(submit(&malformed)), LogRequestRefusal::Malformed, "{malformed:?}");
        }
        let undecodable = SignedLogRequest { request: vec![0xff; 64], signature: Vec::new() };
        assert_eq!(refusal(queue.submit(Some(&listed.peer), &undecodable, NOW)), LogRequestRefusal::Malformed);
        assert!(queue.state().entries.is_empty(), "refused requests are not queued");
        assert_eq!(submit(&LogRequest { since_unix: base.until_unix - MAX_WINDOW_SECS, filters: vec![vec![1; 32]; MAX_FILTERS], ..base.clone() })
            .unwrap().status(), LogRequestStatus::Pending, "the bounds themselves pass");
    }

    #[test]
    fn a_replayed_nonce_is_refused_and_a_resubmission_keeps_its_id() {
        let (own, listed) = (key(), key());
        let mut limits = config(true, &[&listed]);
        limits.requests_per_day = 2;
        let (queue, _dir) = queue(&limits, &own);
        let first = signed(&listed, &request(&listed, &own.peer, 1));
        let queued = queue.submit(Some(&listed.peer), &first, NOW).unwrap();
        let again = queue.submit(Some(&listed.peer), &first, NOW + 1_000).unwrap();
        assert_eq!((again.request_id.clone(), again.status()), (queued.request_id, LogRequestStatus::Pending));
        let same_nonce = LogRequest { until_unix: NOW / 1000 - 60, ..request(&listed, &own.peer, 1) };
        assert_eq!(refusal(queue.submit(Some(&listed.peer), &signed(&listed, &same_nonce), NOW)), LogRequestRefusal::Replayed);
        assert_eq!(queue.state().queued[&listed.peer].len(), 1, "a resubmission is not charged");
        assert_eq!(queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 2)), NOW).unwrap().status(),
            LogRequestStatus::Pending);
    }

    #[test]
    fn requests_beyond_the_daily_budget_or_the_queue_are_refused() {
        let (own, a, b, c) = (key(), key(), key(), key());
        let mut limits = config(true, &[&a, &b, &c]);
        (limits.requests_per_day, limits.max_pending) = (2, 4);
        let (queue, _dir) = queue(&limits, &own);
        let submit = |from: &Key, nonce: u8, at: u64| {
            queue.submit(Some(&from.peer), &signed(from, &LogRequest { issued_unix_ms: at, ..request(from, &own.peer, nonce) }), at)
        };
        for nonce in 1..=2 {
            assert_eq!(submit(&a, nonce, NOW).unwrap().status(), LogRequestStatus::Pending);
            assert_eq!(submit(&b, nonce, NOW).unwrap().status(), LogRequestStatus::Pending);
        }
        assert_eq!(refusal(submit(&a, 3, NOW)), LogRequestRefusal::OverBudget);
        assert_eq!(refusal(submit(&c, 1, NOW)), LogRequestRefusal::QueueFull);
        let id = |nonce| request_id(&signed(&a, &request(&a, &own.peer, nonce)).request);
        queue.deny(Some(&own.peer), &id(1), NOW).unwrap();
        assert_eq!(submit(&c, 1, NOW).unwrap().status(), LogRequestStatus::Pending, "a decision frees a place");
        let next_day = NOW + DAY_MS;
        queue.tick(next_day);
        assert_eq!(submit(&a, 4, next_day).unwrap().status(), LogRequestStatus::Pending, "the budget renews after 24 h");
    }

    /// Every answer to a submission, queued or refused, reports the
    /// requester's budget as the next submission is checked against it:
    /// none left means over budget until the oldest counted request ages
    /// out, at exactly the time reported.
    #[test]
    fn every_answer_reports_the_requesters_budget() {
        let (own, a, b, c) = (key(), key(), key(), key());
        let mut limits = config(true, &[&a, &b, &c]);
        (limits.requests_per_day, limits.max_pending) = (2, 8);
        let (queue, _dir) = queue(&limits, &own);
        let submit = |from: &Key, nonce: u8, at: u64| {
            let request = LogRequest { issued_unix_ms: at, ..request(from, &own.peer, nonce) };
            queue.submit(Some(&from.peer), &signed(from, &request), at).unwrap()
        };
        let budget = |response: &SubmitLogRequestResponse| {
            (response.status(), response.refusal(), response.requests_remaining, response.requests_per_day, response.next_request_unix_ms)
        };
        let (pending, refused) = (LogRequestStatus::Pending, LogRequestStatus::Refused);
        let (none, over) = (LogRequestRefusal::None, LogRequestRefusal::OverBudget);
        let first_frees = NOW + DAY_MS;
        assert_eq!(budget(&submit(&a, 1, NOW)), (pending, none, Some(1), Some(2), Some(first_frees)));
        assert_eq!(budget(&submit(&a, 2, NOW + 1_000)), (pending, none, Some(0), Some(2), Some(first_frees)));
        assert_eq!(budget(&submit(&a, 3, NOW + 2_000)), (refused, over, Some(0), Some(2), Some(first_frees)));
        let resubmitted = queue.submit(Some(&a.peer), &signed(&a, &request(&a, &own.peer, 1)), NOW + 3_000).unwrap();
        assert_eq!(budget(&resubmitted), (pending, none, Some(0), Some(2), Some(first_frees)),
            "a resubmission reports the budget too");
        assert_eq!(budget(&submit(&a, 4, first_frees - 1)), (refused, over, Some(0), Some(2), Some(first_frees)),
            "still over budget a millisecond before");
        assert_eq!(budget(&submit(&a, 4, first_frees)), (pending, none, Some(0), Some(2), Some(NOW + 1_000 + DAY_MS)),
            "the reported time frees one request");
        let later = NOW + 3 * DAY_MS;
        let wrong_target = LogRequest { issued_unix_ms: later, ..request(&a, &a.peer, 5) };
        let answer = queue.submit(Some(&a.peer), &signed(&a, &wrong_target), later).unwrap();
        assert_eq!(budget(&answer), (refused, LogRequestRefusal::WrongTarget, Some(2), Some(2), None),
            "the whole budget renews once every counted request is older than 24 h");

        (limits.requests_per_day, limits.max_pending) = (8, 2);
        let (small, _dir) = self::queue(&limits, &own);
        let submit = |from: &Key, nonce: u8| small.submit(Some(&from.peer), &signed(from, &request(from, &own.peer, nonce)), NOW).unwrap();
        assert_eq!(budget(&submit(&a, 1)), (pending, none, Some(7), Some(8), Some(NOW + DAY_MS)));
        assert_eq!(budget(&submit(&a, 2)), (refused, LogRequestRefusal::TooManyPending, Some(7), Some(8), Some(NOW + DAY_MS)),
            "a refusal is not charged");
        assert_eq!(budget(&submit(&b, 1)), (pending, none, Some(7), Some(8), Some(NOW + DAY_MS)));
        assert_eq!(budget(&submit(&c, 1)), (refused, LogRequestRefusal::QueueFull, Some(8), Some(8), None),
            "no time while no request is counted");
    }

    #[test]
    fn the_refusal_summary_states_the_latest_budget() {
        let full = Budget { remaining: 0, per_day: 2, next_ms: Some(NOW + DAY_MS - 1) };
        assert_eq!(full.summary("…Ab12cd"), "…Ab12cd: 0 of 2 requests left in 24 h, next at 2027-01-16T08:00:00Z");
        assert_eq!(Budget { remaining: 1, ..full }.summary("…Ab12cd"), "…Ab12cd: 1 of 2 requests left in 24 h");
        assert!(Budget { next_ms: Some(u64::MAX), ..full }.summary("…Ab12cd").ends_with('Z'), "no overflow");
    }

    /// A peer holds at most half of maxPending (at least one), so no peer
    /// fills the queue for the others.
    #[test]
    fn a_peer_holds_at_most_half_the_queue() {
        let (own, a, b) = (key(), key(), key());
        let mut limits = config(true, &[&a, &b]);
        (limits.requests_per_day, limits.max_pending) = (8, 4);
        let (queue, _dir) = queue(&limits, &own);
        let submit = |from: &Key, nonce: u8| queue.submit(Some(&from.peer), &signed(from, &request(from, &own.peer, nonce)), NOW);
        assert_eq!(submit(&a, 1).unwrap().status(), LogRequestStatus::Pending);
        assert_eq!(submit(&a, 2).unwrap().status(), LogRequestStatus::Pending);
        assert_eq!(refusal(submit(&a, 3)), LogRequestRefusal::TooManyPending);
        assert_eq!(submit(&b, 1).unwrap().status(), LogRequestStatus::Pending, "the other peer still has room");
        queue.deny(Some(&own.peer), &request_id(&signed(&a, &request(&a, &own.peer, 1)).request), NOW).unwrap();
        assert_eq!(submit(&a, 3).unwrap().status(), LogRequestStatus::Pending);
        limits.max_pending = 1;
        let (small, _dir) = self::queue(&limits, &own);
        assert_eq!(small.per_requester(), 1, "at least one");
    }

    /// A request whose bundle its requester fetched holds no place in the
    /// queue: a pending or an approved, unfetched one still does. The
    /// fetched bundle stays fetchable until a new request needs its place.
    #[test]
    fn a_fetched_request_frees_its_place_in_the_queue() {
        let (own, a, b, c) = (key(), key(), key(), key());
        let mut limits = config(true, &[&a, &b, &c]);
        (limits.requests_per_day, limits.max_pending) = (8, 4);
        let (queue, dir) = queue(&limits, &own);
        let submit = |from: &Key, nonce: u8| queue.submit(Some(&from.peer), &signed(from, &request(from, &own.peer, nonce)), NOW);
        let id = |from: &Key, nonce: u8| -> [u8; ID_LEN] { request_id(&signed(from, &request(from, &own.peer, nonce)).request) };
        for nonce in 1..=2 {
            assert_eq!(submit(&a, nonce).unwrap().status(), LogRequestStatus::Pending);
        }
        let fetched = id(&a, 2);
        let (_, token) = queue.begin_upload(&fetched, 5, NOW).unwrap();
        queue.finish_upload(&fetched, token, Ok((b"seal!".to_vec(), vec![9; 32])), NOW, None).unwrap();
        assert_eq!(refusal(submit(&a, 3)), LogRequestRefusal::TooManyPending, "a pending and an approved request hold the share");
        queue.served(&fetched);
        assert_eq!(submit(&a, 3).unwrap().status(), LogRequestStatus::Pending, "the fetched one no longer does");
        assert!(queue.bundle(Some(&a.peer), &fetched, NOW).is_ok(), "it stays fetchable");
        assert_eq!(refusal(submit(&a, 4)), LogRequestRefusal::TooManyPending, "the two pending ones hold the share");
        assert_eq!(submit(&b, 1).unwrap().status(), LogRequestStatus::Pending);
        let path = dir.path().join("log-bundles").join(format!("{}.sealed", hex::encode(fetched)));
        assert!(path.exists());
        assert_eq!(submit(&b, 2).unwrap().status(), LogRequestStatus::Pending, "a fetched request gives up its place");
        assert!(!path.exists(), "its bundle is deleted");
        assert_eq!(queue.status(Some(&a.peer), &fetched, NOW).unwrap().status(), LogRequestStatus::Expired);
        assert_eq!(queue.bundle(Some(&a.peer), &fetched, NOW).unwrap_err().code(), tonic::Code::FailedPrecondition);
        assert_eq!(refusal(submit(&c, 1)), LogRequestRefusal::QueueFull, "unfetched requests hold every place");
        assert_eq!(queue.list(Some(&own.peer), NOW).unwrap().requests.len(), limits.max_pending as usize);
    }

    /// Only full shard filters (32 to 64 bytes) are taken: a shorter one
    /// would match unredacted text, since selection runs before redaction.
    #[test]
    fn only_full_shard_filters_are_taken() {
        let (own, listed) = (key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let submit = |filters: Vec<Vec<u8>>, nonce: u8| {
            queue.submit(Some(&listed.peer), &signed(&listed, &LogRequest { filters, ..request(&listed, &own.peer, nonce) }), NOW)
        };
        for (n, len) in [0usize, 1, 4, 31, 65, 128].into_iter().enumerate() {
            assert_eq!(refusal(submit(vec![vec![0xa1; 32], vec![0x0a; len]], n as u8)), LogRequestRefusal::FilterLength, "{len} bytes");
        }
        assert!(queue.state().entries.is_empty());
        for (n, len) in [32usize, 33, 64].into_iter().enumerate() {
            assert_eq!(submit(vec![vec![0x0a; len]], 10 + n as u8).unwrap().status(), LogRequestStatus::Pending, "{len} bytes");
            queue.deny(Some(&own.peer), &request_id(&signed(&listed, &LogRequest { filters: vec![vec![0x0a; len]], ..request(&listed, &own.peer, 10 + n as u8) }).request), NOW).unwrap();
        }
        assert_eq!(*SHARD_FILTER_BYTES.start(), quil_execution::global_intrinsic::verify::MIN_FILTER_LEN);
        assert_eq!(*SHARD_FILTER_BYTES.end(), quil_execution::global_intrinsic::MAX_PROVER_FILTER_LEN as usize);
    }

    /// A window ending ahead of this node's clock beyond the skew, or with
    /// times no signed clock holds, is refused.
    #[test]
    fn a_window_must_lie_within_this_nodes_clock() {
        let (own, listed) = (key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let submit = |request: LogRequest| queue.submit(Some(&listed.peer), &signed(&listed, &request), NOW);
        let base = request(&listed, &own.peer, 1);
        let ahead = (NOW + MAX_CLOCK_SKEW_MS) / 1000;
        assert_eq!(refusal(submit(LogRequest { until_unix: ahead + 1, since_unix: ahead - 60, ..base.clone() })), LogRequestRefusal::Stale);
        assert_eq!(refusal(submit(LogRequest { since_unix: i64::MAX as u64 - 10, until_unix: i64::MAX as u64 + 1, ..base.clone() })),
            LogRequestRefusal::Malformed);
        assert_eq!(submit(LogRequest { until_unix: ahead, since_unix: ahead - 60, ..base }).unwrap().status(), LogRequestStatus::Pending);
    }

    /// A nonce is remembered as long as a request carrying it can be fresh:
    /// issued a skew ahead, it is still fresh twice the skew after queueing.
    #[test]
    fn a_nonce_is_remembered_while_its_request_can_be_fresh() {
        let (own, listed) = (key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let issued = NOW + MAX_CLOCK_SKEW_MS;
        let first = LogRequest { issued_unix_ms: issued, ..request(&listed, &own.peer, 1) };
        assert_eq!(queue.submit(Some(&listed.peer), &signed(&listed, &first), NOW).unwrap().status(), LogRequestStatus::Pending);
        let later = NOW + 2 * MAX_CLOCK_SKEW_MS;
        queue.tick(later);
        let replay = LogRequest { until_unix: first.until_unix - 1, ..first.clone() };
        assert_eq!(refusal(queue.submit(Some(&listed.peer), &signed(&listed, &replay), later)), LogRequestRefusal::Replayed);
        queue.tick(later + NONCE_HORIZON_MS);
        assert!(queue.state().nonces.is_empty(), "forgotten once no request with it can be fresh");
    }

    #[test]
    fn only_this_nodes_own_identity_reaches_the_operator_methods() {
        let (own, listed) = (key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let good = signed(&listed, &request(&listed, &own.peer, 1));
        let id = queue.submit(Some(&listed.peer), &good, NOW).unwrap().request_id;
        for caller in [None, Some(&listed.peer)] {
            denied(queue.list(caller, NOW));
            denied(queue.deny(caller, &id, NOW));
            denied(queue.operator(caller, NOW));
        }
        let list = queue.list(Some(&own.peer), NOW).unwrap();
        assert_eq!(list.max_bundle_bytes, 32 * 1024 * 1024);
        assert_eq!(list.requests.len(), 1);
        let pending = &list.requests[0];
        assert_eq!((pending.request_id.clone(), pending.requester_peer_id.clone(), pending.status()),
            (id.clone(), listed.peer.to_bytes(), LogRequestStatus::Pending));
        assert_eq!((pending.filters.len(), pending.recipient_kem_public_key.len()), (2, quil_crypto::SNTRUP761_PUBLIC_KEY_LEN));
        assert_eq!(queue.deny(Some(&own.peer), &id, NOW).unwrap().status(), LogRequestStatus::Denied);
        assert_eq!(queue.status(Some(&listed.peer), &id, NOW).unwrap().status(), LogRequestStatus::Denied);
        assert_eq!(queue.deny(Some(&own.peer), &id, NOW).unwrap_err().code(), tonic::Code::NotFound);
        let disabled = LogRequests::new(&config(false, &[]), own.peer, PathBuf::from("/nonexistent"));
        assert!(disabled.list(Some(&own.peer), NOW).unwrap().requests.is_empty(), "the operator lists even while disabled");
    }

    #[test]
    fn a_bundle_is_kept_for_its_requester_until_it_expires() {
        let (own, listed, other) = (key(), key(), key());
        let (queue, dir) = queue(&config(true, &[&listed, &other]), &own);
        let good = signed(&listed, &request(&listed, &own.peer, 1));
        let id: [u8; ID_LEN] = queue.submit(Some(&listed.peer), &good, NOW).unwrap().request_id.try_into().unwrap();
        assert_eq!(queue.bundle(Some(&listed.peer), &id, NOW).unwrap_err().code(), tonic::Code::FailedPrecondition);
        assert_eq!(queue.begin_upload(&id, 64 * 1024 * 1024, NOW).unwrap_err().code(), tonic::Code::InvalidArgument, "over maxBundleBytes");
        let (_, token) = queue.begin_upload(&id, 5, NOW).unwrap();
        assert_eq!(queue.begin_upload(&id, 5, NOW).unwrap_err().code(), tonic::Code::ResourceExhausted, "one upload at a time");
        assert_eq!(queue.finish_upload(&id, token + 1, Ok((b"x".to_vec(), vec![1; 32])), NOW, None).unwrap_err().code(),
            tonic::Code::FailedPrecondition, "another upload's token");
        let ready = queue.finish_upload(&id, token, Ok((b"seal!".to_vec(), vec![9; 32])), NOW + 1_000, None).unwrap();
        assert_eq!((ready.status(), ready.expires_unix_ms), (LogRequestStatus::Ready, NOW + 1_000 + 86_400_000));
        let path = dir.path().join("log-bundles").join(format!("{}.sealed", hex::encode(id)));
        assert_eq!(std::fs::read(&path).unwrap(), b"seal!");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        for result in [queue.status(Some(&other.peer), &id, NOW).map(|_| ()), queue.bundle(Some(&other.peer), &id, NOW).map(|_| ())] {
            assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound, "another peer's request is unknown to it");
        }
        let (_, served_path, bytes, sha) = queue.bundle(Some(&listed.peer), &id, NOW + 2_000).unwrap();
        assert_eq!((served_path, bytes, sha), (path.clone(), 5, vec![9; 32]));
        queue.served(&id);
        assert_eq!(queue.status(Some(&listed.peer), &id, NOW).unwrap().status(), LogRequestStatus::Served);
        assert!(queue.bundle(Some(&listed.peer), &id, NOW + 3_000).is_ok(), "fetchable again until it expires");
        assert_eq!(queue.tick(NOW + 1_000 + 86_400_000 - 1), Tick::default());
        assert_eq!(queue.tick(NOW + 1_000 + 86_400_000).expired, 1);
        assert!(!path.exists(), "an expired bundle is deleted");
        assert_eq!(queue.status(Some(&listed.peer), &id, NOW).unwrap().status(), LogRequestStatus::Expired);
        assert_eq!(queue.bundle(Some(&listed.peer), &id, NOW).unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn a_waiting_request_is_reminded_hourly_and_expires_unapproved() {
        let (own, listed) = (key(), key());
        let (queue, dir) = queue(&config(true, &[&listed]), &own);
        let id = queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 1)), NOW).unwrap().request_id;
        assert_eq!(queue.tick(NOW + REMINDER_INTERVAL_MS - 1), Tick::default());
        assert_eq!(queue.tick(NOW + REMINDER_INTERVAL_MS), Tick { reminded: 1, ..Tick::default() });
        assert_eq!(queue.tick(NOW + REMINDER_INTERVAL_MS + 60_000), Tick::default());
        assert_eq!(queue.tick(NOW + DAY_MS), Tick { expired: 1, ..Tick::default() });
        assert_eq!(queue.status(Some(&listed.peer), &id, NOW + DAY_MS).unwrap().status(), LogRequestStatus::Expired);
        assert_eq!(queue.begin_upload(&id, 5, NOW + DAY_MS).unwrap_err().code(), tonic::Code::NotFound);
        let spool = dir.path().join("log-bundles");
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::write(spool.join("old.sealed"), b"x").unwrap();
        std::fs::write(spool.join("keep.txt"), b"x").unwrap();
        let _restarted = LogRequests::new(&config(true, &[&listed]), own.peer, spool.clone());
        assert!(!spool.join("old.sealed").exists() && spool.join("keep.txt").exists(), "a restart drops earlier bundles");
    }

    /// An upload holds its request past expiry only until its deadline;
    /// then the node gives it up and the request expires.
    #[test]
    fn an_upload_holds_its_request_only_until_its_deadline() {
        let (own, listed) = (key(), key());
        let (queue, _dir) = queue(&config(true, &[&listed]), &own);
        let id: [u8; ID_LEN] = queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 1)), NOW)
            .unwrap().request_id.try_into().unwrap();
        let started = NOW + DAY_MS - 1_000;
        let (_, token) = queue.begin_upload(&id, 32 * 1024 * 1024, started).unwrap();
        let deadline = started + upload_timeout(32 * 1024 * 1024).as_millis() as u64 + 60_000;
        assert_eq!(queue.tick(deadline - 1).expired, 0, "the upload in progress holds the request");
        assert_eq!(queue.tick(deadline), Tick { expired: 1, abandoned: 1, ..Tick::default() });
        assert_eq!(queue.finish_upload(&id, token, Ok((b"late".to_vec(), vec![1; 32])), deadline, None).unwrap_err().code(),
            tonic::Code::FailedPrecondition, "a late upload is not stored");
        assert_eq!(queue.status(Some(&listed.peer), &id, deadline).unwrap().status(), LogRequestStatus::Expired);
    }

    /// A max-size bundle has time at 64 KiB/s, both in the operator's
    /// qclient and in the node's deadline.
    #[test]
    fn a_max_size_upload_has_time() {
        let max = *quil_config::LOG_BUNDLE_BYTES.end();
        assert!(upload_timeout(max) >= Duration::from_secs(max / (64 * 1024)), "{:?}", upload_timeout(max));
        assert_eq!(upload_timeout(0), Duration::from_secs(60));
    }

    /// An upload whose handler is dropped mid-stream (its qclient went
    /// away) frees its request: it can be approved again, denied, or let
    /// expire.
    #[tokio::test]
    async fn a_dropped_upload_does_not_wedge_the_queue() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(LogRequests::new(&config(true, &[&listed]), own.peer, dir.path().join("log-bundles")));
        let server = LogRequestServer::new(queue.clone());
        let now = now_ms();
        let request = LogRequest { issued_unix_ms: now, since_unix: now / 1000 - 3600, until_unix: now / 1000, ..self::request(&listed, &own.peer, 1) };
        let id = queue.submit(Some(&listed.peer), &signed(&listed, &request), now).unwrap().request_id;
        let first = UploadLogBundleChunk { request_id: id.clone(), total_bytes: 10, sha256: vec![0; 32], data: vec![1; 4] };
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<UploadLogBundleChunk, Status>>();
        tx.unbounded_send(Ok(first.clone())).unwrap();
        let mut upload = Box::pin(server.receive_upload(Some(&own.peer), rx));
        assert!(futures::poll!(upload.as_mut()).is_pending(), "waiting for the rest of the bundle");
        assert!(queue.state().entries.values().all(|entry| entry.upload.is_some()));
        drop(upload);
        assert!(queue.state().entries.values().all(|entry| entry.upload.is_none()), "the dropped upload is given up");
        let (again, token) = queue.begin_upload(&id, 10, now).unwrap();
        queue.abandon_upload(&again, token);
        assert_eq!(queue.deny(Some(&own.peer), &id, now).unwrap().status(), LogRequestStatus::Denied);
        let other = LogRequest { nonce: vec![2; NONCE_LEN], ..request };
        let other_id = queue.submit(Some(&listed.peer), &signed(&listed, &other), now).unwrap().request_id;
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<UploadLogBundleChunk, Status>>();
        tx.unbounded_send(Ok(UploadLogBundleChunk { request_id: other_id.clone(), ..first })).unwrap();
        let mut upload = Box::pin(server.receive_upload(Some(&own.peer), rx));
        assert!(futures::poll!(upload.as_mut()).is_pending());
        drop(upload);
        assert_eq!(queue.tick(now + DAY_MS).expired, 1, "and expires on time");
        drop(tx);
    }

    /// The operator can withdraw an approved bundle, fetched or not: it is
    /// deleted, its place freed, and the requester sees it denied.
    #[test]
    fn deny_withdraws_an_approved_bundle() {
        let (own, listed) = (key(), key());
        let mut limits = config(true, &[&listed]);
        limits.max_pending = 1;
        let (queue, dir) = queue(&limits, &own);
        let id: [u8; ID_LEN] = queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 1)), NOW)
            .unwrap().request_id.try_into().unwrap();
        let (_, token) = queue.begin_upload(&id, 5, NOW).unwrap();
        queue.finish_upload(&id, token, Ok((b"seal!".to_vec(), vec![9; 32])), NOW, None).unwrap();
        let path = dir.path().join("log-bundles").join(format!("{}.sealed", hex::encode(id)));
        assert!(path.exists());
        assert_eq!(refusal(queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 2)), NOW)),
            LogRequestRefusal::TooManyPending);
        queue.served(&id);
        assert_eq!(queue.deny(Some(&own.peer), &id, NOW).unwrap().status(), LogRequestStatus::Denied);
        assert!(!path.exists(), "the withdrawn bundle is deleted");
        assert_eq!(queue.status(Some(&listed.peer), &id, NOW).unwrap().status(), LogRequestStatus::Denied);
        assert_eq!(queue.bundle(Some(&listed.peer), &id, NOW).unwrap_err().code(), tonic::Code::FailedPrecondition);
        assert_eq!(queue.submit(Some(&listed.peer), &signed(&listed, &request(&listed, &own.peer, 2)), NOW).unwrap().status(),
            LogRequestStatus::Pending, "its place is free");
    }

    /// Over the real transport: the requester submits, this node's operator
    /// uploads a bundle sealed to the request's key, and only the requester
    /// fetches and opens it; another allowlisted peer and the operator
    /// methods from it are refused.
    #[tokio::test]
    async fn a_sealed_bundle_reaches_only_its_requester_over_the_peer_listener() {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        let (own, listed, other) = (key(), key(), key());
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(LogRequests::new(&config(true, &[&listed, &other]), own.peer, dir.path().join("log-bundles")));
        let server = LogRequestServer::new(queue.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let server_key = own.signing.clone();
        let accept = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (tx, key) = (tx.clone(), server_key.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = crate::pqnoise_channel::pq_server_handshake(tcp, &key).await {
                        let _ = tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let intercept = crate::peer_auth_middleware::peer_auth_interceptor;
        let serve = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(tonic::service::interceptor::InterceptedService::new(server.peer_service(), intercept))
                .add_service(tonic::service::interceptor::InterceptedService::new(server.operator_service(), intercept))
                .serve_with_incoming(UnboundedReceiverStream::new(rx)),
        );

        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let now = now_ms();
        let request = LogRequest {
            issued_unix_ms: now,
            since_unix: now / 1000 - 3600,
            until_unix: now / 1000,
            recipient_kem_public_key: kem.public.clone(),
            ..self::request(&listed, &own.peer, 1)
        };
        let mut requester = connect_log_peer(&addr, &listed.signing, own.peer).await.unwrap();
        let submitted = requester.submit_log_request(signed(&listed, &request)).await.unwrap().into_inner();
        assert_eq!(submitted.status(), LogRequestStatus::Pending);
        let id = submitted.request_id.clone();

        assert!(connect_operator(&addr, &listed.signing).await.is_err(), "a peer's key does not prove this node's identity");
        let channel = peer_channel(&addr, &listed.signing, own.peer).await.unwrap();
        let mut stranger_ops = DiagnosticsOperatorServiceClient::new(channel);
        for status in [
            stranger_ops.list_log_requests(ListLogRequestsRequest {}).await.unwrap_err(),
            stranger_ops.deny_log_request(DenyLogRequestRequest { request_id: id.clone() }).await.unwrap_err(),
            stranger_ops
                .upload_log_bundle(futures::stream::iter(vec![UploadLogBundleChunk { request_id: id.clone(), total_bytes: 1, sha256: Vec::new(), data: vec![1] }]))
                .await
                .unwrap_err(),
        ] {
            assert_eq!((status.code(), status.message()), (tonic::Code::PermissionDenied, DENIED));
        }
        let mut operator = connect_operator(&addr, &own.signing).await.unwrap();
        let listed_requests = operator.list_log_requests(ListLogRequestsRequest {}).await.unwrap().into_inner();
        let pending = &listed_requests.requests[0];
        let plaintext: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let sealed = quil_crypto::seal::seal(&plaintext, &pending.recipient_kem_public_key, &pending.request_id).unwrap();
        let sha256 = Sha256::digest(&sealed).to_vec();
        let chunks: Vec<UploadLogBundleChunk> = sealed
            .chunks(UPLOAD_CHUNK_BYTES)
            .enumerate()
            .map(|(n, data)| UploadLogBundleChunk {
                request_id: if n == 0 { id.clone() } else { Vec::new() },
                total_bytes: if n == 0 { sealed.len() as u64 } else { 0 },
                sha256: if n == 0 { sha256.clone() } else { Vec::new() },
                data: data.to_vec(),
            })
            .collect();
        let uploaded = operator.upload_log_bundle(futures::stream::iter(chunks)).await.unwrap().into_inner();
        assert_eq!(uploaded.status(), LogRequestStatus::Ready);

        let mut nosy = connect_log_peer(&addr, &other.signing, own.peer).await.unwrap();
        let fetch = FetchLogBundleRequest { request_id: id.clone(), offset: 0 };
        assert_eq!(nosy.get_log_request_status(GetLogRequestStatusRequest { request_id: id.clone() }).await.unwrap_err().code(), tonic::Code::NotFound);
        assert_eq!(nosy.fetch_log_bundle(fetch.clone()).await.unwrap_err().code(), tonic::Code::NotFound);

        let mut stream = requester.fetch_log_bundle(fetch).await.unwrap().into_inner();
        let mut fetched = Vec::new();
        let mut messages = 0;
        while let Some(chunk) = stream.message().await.unwrap() {
            assert_eq!((chunk.offset, chunk.total_bytes, chunk.sha256.as_slice()), (fetched.len() as u64, sealed.len() as u64, sha256.as_slice()));
            fetched.extend_from_slice(&chunk.data);
            messages += 1;
        }
        assert_eq!(messages, sealed.len().div_ceil(FETCH_CHUNK_BYTES));
        assert_eq!(fetched, sealed);
        assert_eq!(quil_crypto::seal::open(&fetched, &kem.secret, &id).unwrap(), plaintext);
        let status = requester.get_log_request_status(GetLogRequestStatusRequest { request_id: id.clone() }).await.unwrap().into_inner();
        assert_eq!((status.status(), status.bundle_bytes), (LogRequestStatus::Served, sealed.len() as u64));
        let resumed: Vec<LogBundleChunk> = {
            let mut stream = requester.fetch_log_bundle(FetchLogBundleRequest { request_id: id.clone(), offset: 300_000 }).await.unwrap().into_inner();
            let mut out = Vec::new();
            while let Some(chunk) = stream.message().await.unwrap() {
                out.push(chunk);
            }
            out
        };
        assert_eq!(resumed.iter().flat_map(|c| c.data.clone()).collect::<Vec<u8>>(), sealed[300_000..]);
        accept.abort();
        serve.abort();
    }

    /// A node that writes `lines` to its log directory and approves its
    /// allowlisted peers' requests itself, at `dir`.
    fn automatic_queue(config: &LogRequestsConfig, own: &Key, dir: &Path, lines: &str) -> Arc<LogRequests> {
        Arc::new(automatic_requests(config, own, dir, lines))
    }

    fn automatic_requests(config: &LogRequestsConfig, own: &Key, dir: &Path, lines: &str) -> LogRequests {
        let log_dir = dir.join(".log");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("master.log"), lines).unwrap();
        let auto = AutoApproval { log_dir, token_maps: dir.join(".diagnostics").join("token-maps") };
        LogRequests::with_approval(config, own.peer, dir.join(".diagnostics").join("log-bundles"), Some(auto))
    }

    /// A node log line `ago_secs` before `now_ms`.
    fn log_line(now_ms: u64, ago_secs: u64, level: &str, message: &str, fields: &str) -> String {
        let at = format_rfc3339_utc((now_ms / 1000 - ago_secs) as i64);
        format!("{at}\t{level}\tquil_node/src/main.rs:7\t{message}\t{fields}\n")
    }

    /// A request for the hour before `now_ms`, sealed to `kem`.
    fn fresh(from: &Key, target: &PeerId, nonce: u8, now_ms: u64, kem: &[u8]) -> LogRequest {
        LogRequest {
            issued_unix_ms: now_ms,
            since_unix: now_ms / 1000 - 3600,
            until_unix: now_ms / 1000,
            filters: Vec::new(),
            recipient_kem_public_key: kem.to_vec(),
            ..request(from, target, nonce)
        }
    }

    fn submit_fresh(queue: &LogRequests, from: &Key, own: &Key, nonce: u8, kem: &[u8]) -> SubmitLogRequestResponse {
        let now = now_ms();
        queue.submit(Some(&from.peer), &signed(from, &fresh(from, &own.peer, nonce, now, kem)), now).unwrap()
    }

    fn token_maps(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir.join(".diagnostics").join("token-maps")) else { return Vec::new() };
        entries.flatten().map(|entry| entry.path()).collect()
    }

    /// An allowlisted peer's request is approved by this node itself: the
    /// window is exported with `node log export`'s redaction, sealed to the
    /// request's key alone, and its token map kept owner-only beside the
    /// node's config; the requester sees it approved and opens it.
    #[tokio::test]
    async fn this_node_approves_an_allowlisted_peers_request_itself() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let lines = [
            log_line(now, 7200, "info", "before the window", "{}"),
            log_line(now, 1800, "info", "dialing 192.0.2.10:8340", r#"{"coreId":0}"#),
            log_line(now, 60, "warn", "archive slow", r#"{"coreId":0}"#),
        ]
        .concat();
        let queue = automatic_queue(&config(true, &[&listed]), &own, dir.path(), &lines);
        assert!(queue.automatic());
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let submitted = submit_fresh(&queue, &listed, &own, 1, &kem.public);
        assert_eq!((submitted.status(), submitted.automatic), (LogRequestStatus::Pending, true));
        let id: [u8; ID_LEN] = submitted.request_id.clone().try_into().unwrap();
        assert!(queue.list(Some(&own.peer), now).unwrap().automatic);

        assert!(queue.approve_next().await, "the queued request is exported");
        assert!(!queue.approve_next().await, "each request once");
        let status = queue.status(Some(&listed.peer), &id, now_ms()).unwrap();
        assert_eq!(status.status(), LogRequestStatus::Ready);
        let (_, path, bytes, sha256) = queue.bundle(Some(&listed.peer), &id, now_ms()).unwrap();
        let sealed = std::fs::read(&path).unwrap();
        assert_eq!((sealed.len() as u64, Sha256::digest(&sealed).to_vec()), (bytes, sha256));
        assert_eq!(status.bundle_bytes, bytes);
        let files = bundle::unpack_bundle(&quil_crypto::seal::open(&sealed, &kem.secret, &id).unwrap()).unwrap();
        let mut log = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(files[0].as_slice()), &mut log).unwrap();
        assert_eq!(log.lines().count(), 2, "the window's lines, every level: {log}");
        assert!(!log.contains("192.0.2.10") && log.contains("ip4#") && log.contains("archive slow"), "{log}");
        let manifest: serde_json::Value = serde_json::from_slice(&files[1]).unwrap();
        assert_eq!(manifest["request"]["approval"], "automatic");
        assert_eq!(manifest["request"]["id"], hex::encode(id));
        assert_eq!(manifest["tool"], "quil-node automatic log request approval");
        assert!(quil_crypto::seal::open(&sealed, &quil_crypto::Sntrup761KeyPair::generate().secret, &id).is_err());

        let maps = token_maps(dir.path());
        assert_eq!(maps.len(), 1);
        let name = maps[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(&format!("log-request-{}-", short_id(&id))) && name.ends_with(".map.txt"), "{name}");
        assert!(std::fs::read_to_string(&maps[0]).unwrap().contains("192.0.2.10"), "the map holds the original");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&maps[0]).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(maps[0].parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    /// Requests from a peer not listed are refused before anything is
    /// exported, and a node without log files leaves requests to its
    /// operator.
    #[tokio::test]
    async fn only_allowlisted_peers_requests_are_exported() {
        let (own, listed, unlisted) = (key(), key(), key());
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let queue = automatic_queue(&config(true, &[&listed]), &own, dir.path(), &log_line(now, 60, "info", "x", "{}"));
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        denied(queue.submit(Some(&unlisted.peer), &signed(&unlisted, &fresh(&unlisted, &own.peer, 1, now, &kem.public)), now));
        assert!(!queue.approve_next().await, "nothing to export");
        assert!(token_maps(dir.path()).is_empty() && queue.state().entries.is_empty());
        let disabled = automatic_queue(&config(false, &[&listed]), &own, dir.path(), "");
        assert!(!disabled.automatic(), "disabled requests are never exported");
        denied(disabled.submit(Some(&listed.peer), &signed(&listed, &fresh(&listed, &own.peer, 1, now, &kem.public)), now));

        let (manual, _dir) = self::queue(&config(true, &[&listed]), &own);
        let manual = Arc::new(manual);
        assert!(!manual.automatic());
        let submitted = submit_fresh(&manual, &listed, &own, 1, &kem.public);
        assert_eq!((submitted.status(), submitted.automatic), (LogRequestStatus::Pending, false));
        assert!(!manual.approve_next().await, "it waits for the operator");
        assert!(!manual.list(Some(&own.peer), now).unwrap().automatic);
    }

    /// The daily budget and the queue's places still bound automatically
    /// approved requests: a ready bundle holds its place until it is
    /// fetched, expires or is withdrawn.
    #[tokio::test]
    async fn the_limits_bound_automatic_approval() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let mut limits = config(true, &[&listed]);
        (limits.requests_per_day, limits.max_pending) = (3, 4);
        let now = now_ms();
        let queue = automatic_queue(&limits, &own, dir.path(), &log_line(now, 60, "info", "x", "{}"));
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        for nonce in 1..=2 {
            assert_eq!(submit_fresh(&queue, &listed, &own, nonce, &kem.public).status(), LogRequestStatus::Pending);
            assert!(queue.approve_next().await);
        }
        let ready = queue.list(Some(&own.peer), now_ms()).unwrap().requests;
        assert!(ready.iter().all(|request| request.status() == LogRequestStatus::Ready), "{ready:?}");
        assert_eq!(submit_fresh(&queue, &listed, &own, 3, &kem.public).refusal(), LogRequestRefusal::TooManyPending);
        queue.deny(Some(&own.peer), &ready[0].request_id, now_ms()).unwrap();
        assert_eq!(submit_fresh(&queue, &listed, &own, 3, &kem.public).status(), LogRequestStatus::Pending);
        assert_eq!(submit_fresh(&queue, &listed, &own, 4, &kem.public).refusal(), LogRequestRefusal::OverBudget);
    }

    /// An export over maxBundleBytes denies its request as too large and
    /// keeps nothing; one that fails denies it as failed. Either frees the
    /// requester's place at once.
    #[tokio::test]
    async fn a_failed_automatic_approval_denies_the_request_with_its_reason() {
        use rand::RngCore as _;
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let mut noise = vec![0u8; 1024];
        let lines: String = (0..400)
            .map(|n| {
                rand::thread_rng().fill_bytes(&mut noise);
                log_line(now, 600 + n, "info", "noise", &format!("{{\"data\":\"{}\"}}", hex::encode(&noise)))
            })
            .collect();
        let mut limits = config(true, &[&listed]);
        limits.max_bundle_bytes = *quil_config::LOG_BUNDLE_BYTES.start();
        (limits.requests_per_day, limits.max_pending) = (4, 2);
        let queue = automatic_queue(&limits, &own, dir.path(), &lines);
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let id = submit_fresh(&queue, &listed, &own, 1, &kem.public).request_id;
        assert!(queue.approve_next().await);
        let status = queue.status(Some(&listed.peer), &id, now_ms()).unwrap();
        assert_eq!((status.status(), status.denial()), (LogRequestStatus::Denied, LogRequestDenial::TooLarge));
        assert!(token_maps(dir.path()).is_empty(), "no token map of a bundle not kept");
        assert!(queue.state().entries.is_empty(), "its place is free");
        assert!(std::fs::read_dir(dir.path().join(".diagnostics").join("log-bundles")).map_or(true, |mut d| d.next().is_none()));

        std::fs::remove_dir_all(dir.path().join(".log")).unwrap();
        let id = submit_fresh(&queue, &listed, &own, 2, &kem.public).request_id;
        assert!(queue.approve_next().await);
        let status = queue.status(Some(&listed.peer), &id, now_ms()).unwrap();
        assert_eq!((status.status(), status.denial()), (LogRequestStatus::Denied, LogRequestDenial::ExportFailed));
        assert!(queue.state().entries.is_empty());
        assert_eq!(submit_fresh(&queue, &listed, &own, 3, &kem.public).status(), LogRequestStatus::Pending, "it can ask again");
    }

    /// The operator can deny an automatically approved bundle, fetched or
    /// not, and a request denied or expired during its export is not
    /// approved by it: its bundle and token map are dropped.
    #[tokio::test]
    async fn deny_withdraws_an_automatic_approval() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let queue = automatic_queue(&config(true, &[&listed]), &own, dir.path(), &log_line(now, 60, "info", "x", "{}"));
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        for fetched in [false, true] {
            let id = submit_fresh(&queue, &listed, &own, 1 + fetched as u8, &kem.public).request_id;
            assert!(queue.approve_next().await);
            let (id, path, _, _) = queue.bundle(Some(&listed.peer), &id, now_ms()).unwrap();
            if fetched {
                queue.served(&id);
            }
            assert!(path.exists());
            assert_eq!(queue.deny(Some(&own.peer), &id, now_ms()).unwrap().status(), LogRequestStatus::Denied);
            assert!(!path.exists(), "the withdrawn bundle is deleted");
            let status = queue.status(Some(&listed.peer), &id, now_ms()).unwrap();
            assert_eq!((status.status(), status.denial()), (LogRequestStatus::Denied, LogRequestDenial::Operator));
        }

        let id: [u8; ID_LEN] = submit_fresh(&queue, &listed, &own, 3, &kem.public).request_id.try_into().unwrap();
        let job = queue.take_auto_job(now_ms()).unwrap();
        assert_eq!(job.id, id);
        assert!(queue.take_auto_job(now_ms()).is_none(), "one export at a time");
        assert_eq!(queue.begin_upload(&id, 5, now_ms()).unwrap_err().code(), tonic::Code::ResourceExhausted);
        assert!(!job.cancel.load(Ordering::Relaxed));
        queue.deny(Some(&own.peer), &id, now_ms()).unwrap();
        assert!(job.cancel.load(Ordering::Relaxed), "deny stops the export");
        let auto = queue.auto.clone().unwrap();
        let built = bundle::build_automatic(&auto, &job.request, 1 << 20, (now_ms() / 1000) as i64, &AtomicBool::new(false), None).unwrap();
        let map = built.token_map.clone();
        queue.settle_auto(&job, Ok(built), 1, now_ms());
        assert!(!map.exists(), "the late export's token map is dropped");
        assert!(!queue.bundle_path(&id).exists());
        assert_eq!(queue.status(Some(&listed.peer), &id, now_ms()).unwrap().denial(), LogRequestDenial::Operator);
        assert!(queue.take_auto_job(now_ms()).is_none(), "until the export's task ends");
        queue.export_done(job.token);
        submit_fresh(&queue, &listed, &own, 4, &kem.public);
        assert!(queue.take_auto_job(now_ms()).is_some(), "then the next one starts");
    }

    /// Opened by a test to let a stand-in export end once cancelled.
    static GATE: AtomicBool = AtomicBool::new(false);

    /// An export that runs until it is cancelled and [`GATE`] is open.
    fn stalled_export(
        _: &AutoApproval,
        _: &bundle::AutoRequest,
        _: usize,
        _: i64,
        cancel: &AtomicBool,
    ) -> anyhow::Result<bundle::AutoBundle> {
        let start = std::time::Instant::now();
        while !(cancel.load(Ordering::Relaxed) && GATE.load(Ordering::Relaxed)) && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(crate::log_export::Cancelled.into())
    }

    async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let waited = tokio::time::timeout(Duration::from_secs(10), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        assert!(waited.await.is_ok(), "{what}");
    }

    /// An export over its time denies its request as failed and is
    /// stopped; until its task ends, no other export or upload starts.
    /// Dropping the approval (shutdown) stops its export too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_export_over_its_time_is_denied_and_stopped() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let mut requests = automatic_requests(&config(true, &[&listed]), &own, dir.path(), "");
        (requests.auto_timeout, requests.exporter) = (Duration::from_millis(200), Exporter(stalled_export));
        let queue = Arc::new(requests);
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let id = submit_fresh(&queue, &listed, &own, 1, &kem.public).request_id;
        assert!(queue.approve_next().await);
        let status = queue.status(Some(&listed.peer), &id, now_ms()).unwrap();
        assert_eq!((status.status(), status.denial()), (LogRequestStatus::Denied, LogRequestDenial::ExportFailed));
        let cancel = queue.state().export.as_ref().map(|export| export.cancel.clone()).expect("still running");
        assert!(cancel.load(Ordering::Relaxed), "the timeout stops it");
        let next: [u8; ID_LEN] = submit_fresh(&queue, &listed, &own, 2, &kem.public).request_id.try_into().unwrap();
        assert!(!queue.approve_next().await, "no second export while the first runs");
        assert_eq!(queue.begin_upload(&next, 5, now_ms()).unwrap_err().code(), tonic::Code::ResourceExhausted);
        GATE.store(true, Ordering::Relaxed);
        wait_for("the stopped export ends", || queue.state().export.is_none()).await;

        let mut requests = automatic_requests(&config(true, &[&listed]), &own, dir.path(), "");
        (requests.auto_timeout, requests.exporter) = (Duration::from_secs(3600), Exporter(stalled_export));
        let queue = Arc::new(requests);
        submit_fresh(&queue, &listed, &own, 1, &kem.public);
        let approval = tokio::spawn({
            let queue = queue.clone();
            async move { queue.approve_next().await }
        });
        wait_for("the export starts", || queue.state().export.is_some()).await;
        approval.abort();
        let _ = approval.await;
        wait_for("a dropped approval stops its export", || queue.state().export.is_none()).await;
    }

    /// The automatic approval wakes for a queued request rather than
    /// waiting for its poll, here an hour.
    #[tokio::test]
    async fn the_automatic_approval_wakes_for_a_queued_request() {
        let (own, listed) = (key(), key());
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let mut requests = automatic_requests(&config(true, &[&listed]), &own, dir.path(), &log_line(now, 60, "info", "x", "{}"));
        requests.auto_poll = Duration::from_secs(3600);
        let queue = Arc::new(requests);
        let runner = tokio::spawn({
            let queue = queue.clone();
            async move { queue.run_automatic_approval().await }
        });
        // Let it find nothing and park.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let id = submit_fresh(&queue, &listed, &own, 1, &quil_crypto::Sntrup761KeyPair::generate().public).request_id;
        wait_for("approved well before the hour's poll", || {
            queue.status(Some(&listed.peer), &id, now_ms()).unwrap().status() != LogRequestStatus::Pending
        })
        .await;
        assert_eq!(queue.status(Some(&listed.peer), &id, now_ms()).unwrap().status(), LogRequestStatus::Ready);
        runner.abort();
    }
}
