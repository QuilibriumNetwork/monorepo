//! The opt-in health report, served on the authenticated peer listener.
//!
//! A node serves [`HealthReport`] to itself and to the peers its operator
//! lists in `diagnostics.healthReport`, identified by the peer ID their
//! PQNoise handshake proved ([`AuthenticatedPeer`]). A request without that
//! identity, from a peer not on the list, or to a node that has not enabled
//! the report gets one and the same PERMISSION_DENIED, so a refusal reveals
//! nothing about the configuration. The report carries no strings: the
//! engine's state, blocker and recovery texts become enums, and archive
//! addresses and error texts are left out.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use prost::Message as _;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use quil_config::HealthReportConfig;
use quil_p2p::PeerId;
use quil_types::proto::diagnostics::diagnostics_service_client::DiagnosticsServiceClient;
use quil_types::proto::diagnostics::diagnostics_service_server::{DiagnosticsService, DiagnosticsServiceServer};
use quil_types::proto::diagnostics::{
    Blocker, FailureCount, GetHealthReportRequest, HealthReport, Phase, RecoveryFailure, RecoveryPhase, WorkerHealth,
};
use quil_types::consensus::JoinWait;
use quil_types::proto::node::{GlobalAppFrameHead, WorkerExecution};

use crate::node_service::WorkerEntry;
use crate::peer_auth_middleware::AuthenticatedPeer;

/// The report layout this build serves.
pub const SCHEMA: u32 = 1;
/// Bounds of one report: workers beyond them are counted, not sent.
pub const MAX_WORKERS: usize = 256;
pub const MAX_REPORT_BYTES: usize = 32 * 1024;
/// A filter longer than any shard filter is not reported.
pub const MAX_FILTER_BYTES: usize = 128;
/// Requests are empty: anything larger is refused before it is decoded.
pub const MAX_REQUEST_BYTES: usize = 1024;
/// The one answer to a caller who is not served.
pub const DENIED: &str = "diagnostics unavailable";
/// How often refused requests are summarized in the log.
pub const REFUSAL_SUMMARY_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// An observation older than this, at the time of the report, is stale
/// (the threshold of the local worker view).
pub const STALE_AFTER_MS: u64 = 30_000;

const PHASES: [(&str, Phase); 11] = [
    ("starting", Phase::Starting),
    ("waiting", Phase::Waiting),
    ("syncing", Phase::Syncing),
    ("serving", Phase::Serving),
    ("closing", Phase::Closing),
    ("handoff", Phase::Handoff),
    ("blocked", Phase::Blocked),
    ("stopped", Phase::Stopped),
    ("running", Phase::Running),
    ("unknown", Phase::Unknown),
    // Not an engine state: the master's registry view of a joining worker.
    ("joining", Phase::Joining),
];

const BLOCKERS: [(&str, Blocker); 14] = [
    ("waiting for transport", Blocker::WaitingForTransport),
    ("restarting consensus host", Blocker::RestartingConsensusHost),
    ("engine exited", Blocker::EngineExited),
    ("awaiting successor", Blocker::AwaitingSuccessor),
    ("staging shard data", Blocker::StagingShardData),
    ("awaiting closing certificate", Blocker::AwaitingClosingCertificate),
    ("awaiting allocation activation", Blocker::AwaitingAllocationActivation),
    ("checkpoint mismatch", Blocker::CheckpointMismatch),
    ("state unavailable", Blocker::StateUnavailable),
    ("committee admission unavailable", Blocker::CommitteeAdmissionUnavailable),
    ("consensus startup unavailable", Blocker::ConsensusStartupUnavailable),
    ("session identity unavailable", Blocker::SessionIdentityUnavailable),
    ("session state unavailable", Blocker::SessionStateUnavailable),
    ("storage writes stopped", Blocker::StorageWriteFailed),
];

const RECOVERY_PHASES: [(&str, RecoveryPhase); 6] = [
    ("idle", RecoveryPhase::Idle),
    ("waiting_for_permit", RecoveryPhase::WaitingForPermit),
    ("replaying_frames", RecoveryPhase::ReplayingFrames),
    ("fetching_checkpoint", RecoveryPhase::FetchingCheckpoint),
    ("installing_leaves", RecoveryPhase::InstallingLeaves),
    ("installing_checkpoint", RecoveryPhase::InstallingCheckpoint),
];

const FAILURES: [(&str, RecoveryFailure); 6] = [
    ("no_archive_known", RecoveryFailure::NoArchiveKnown),
    ("connect", RecoveryFailure::Connect),
    ("archive_request", RecoveryFailure::ArchiveRequest),
    ("archive_state", RecoveryFailure::ArchiveState),
    ("replay_mismatch", RecoveryFailure::ReplayMismatch),
    ("other", RecoveryFailure::Other),
];

fn lookup<T: Copy + PartialEq>(table: &[(&'static str, T)], text: &str) -> Option<T> {
    table.iter().find(|(name, _)| *name == text).map(|(_, value)| *value)
}

fn name<T: Copy + PartialEq>(table: &[(&'static str, T)], value: T) -> Option<&'static str> {
    table.iter().find(|(_, v)| *v == value).map(|(name, _)| *name)
}

/// The phase of a worker record's `state` and `blocker`.
pub fn phase(state: &str, blocker: &str) -> Phase {
    // Older workers recorded this expected lifecycle wait as a blocker.
    if state == "blocked" && blocker == "awaiting successor" {
        return Phase::Handoff;
    }
    if state.is_empty() {
        return Phase::Unspecified;
    }
    lookup(&PHASES, state).unwrap_or(Phase::Unrecognized)
}

/// The engine's name of `phase`, as the worker view shows it.
pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Unspecified => "unobserved",
        Phase::Unrecognized => "unrecognized",
        phase => name(&PHASES, phase).unwrap_or("unrecognized"),
    }
}

pub fn blocker(text: &str) -> Blocker {
    if text.is_empty() {
        return Blocker::None;
    }
    lookup(&BLOCKERS, text).unwrap_or(Blocker::Unrecognized)
}

/// The engine's text of `blocker`; empty for none.
pub fn blocker_text(blocker: Blocker) -> &'static str {
    match blocker {
        Blocker::None => "",
        Blocker::Unrecognized => "unrecognized",
        blocker => name(&BLOCKERS, blocker).unwrap_or("unrecognized"),
    }
}

pub fn recovery_phase(text: &str) -> RecoveryPhase {
    if text.is_empty() {
        return RecoveryPhase::Starting;
    }
    lookup(&RECOVERY_PHASES, text).unwrap_or(RecoveryPhase::Unrecognized)
}

pub fn recovery_phase_name(phase: RecoveryPhase) -> &'static str {
    match phase {
        RecoveryPhase::None => "none",
        RecoveryPhase::Starting => "starting",
        RecoveryPhase::Unrecognized => "unrecognized",
        phase => name(&RECOVERY_PHASES, phase).unwrap_or("unrecognized"),
    }
}

/// The failure of an engine class
/// ([`quil_engine::worker_execution::FAILURE_CLASSES`]).
pub fn recovery_failure(class: &str) -> RecoveryFailure {
    lookup(&FAILURES, class).unwrap_or(RecoveryFailure::Other)
}

pub fn recovery_failure_name(failure: RecoveryFailure) -> &'static str {
    match failure {
        RecoveryFailure::None => "none",
        failure => name(&FAILURES, failure).unwrap_or("other"),
    }
}

/// `peer` as operators see it in logs: the last six characters of its ID.
pub fn peer_tail(peer: &PeerId) -> String {
    let id = peer.to_base58();
    format!("…{}", &id[id.len().saturating_sub(6)..])
}

/// One worker of the master's worker view, with the committed GLOBAL head
/// of its shard's session and what its allocation's join waits for.
///
/// A joining or activating allocation reads as [`Phase::Joining`] whether
/// its worker runs no engine (an unconfirmed join binds the filter without
/// consensus) or runs one that cannot start before activation, so an
/// expected wait does not read as unobserved or blocked; the blocker and
/// recovery columns still carry what the engine reports.
pub fn worker_health(
    entry: &WorkerEntry,
    head: Option<&GlobalAppFrameHead>,
    join_wait: Option<JoinWait>,
) -> WorkerHealth {
    let mut worker = WorkerHealth {
        core_id: entry.core_id,
        filter: entry.filter.clone(),
        allocated: entry.allocated,
        committee_head_frame: head.map(|head| head.frame),
        committed_generation: head.map(|head| head.generation),
        ..Default::default()
    };
    if let Some(execution) = &entry.execution {
        observe(&mut worker, execution);
    }
    if let Some(wait) = join_wait {
        if let JoinWait::Confirmation { epoch } = wait {
            worker.join_confirm_epoch = Some(epoch);
        }
        worker.activation_frame = Some(wait.activation_frame());
        if matches!(worker.phase(), Phase::Unspecified | Phase::Starting | Phase::Waiting | Phase::Blocked
            | Phase::Unknown | Phase::Running)
        {
            worker.set_phase(Phase::Joining);
        }
    }
    worker
}

fn observe(worker: &mut WorkerHealth, execution: &WorkerExecution) {
    worker.set_phase(phase(&execution.state, &execution.blocker));
    worker.set_blocker(blocker(&execution.blocker));
    worker.observed_unix_ms = execution.observed_unix_ms;
    worker.awaited_frame = execution.awaited_frame;
    worker.materialized_frame = execution.materialized_frame;
    worker.last_advance_unix_ms = execution.last_advance_unix_ms;
    if let Some(recovery) = &execution.recovery {
        worker.set_recovery_phase(recovery_phase(&recovery.phase));
        worker.recovery_phase_since_unix_ms = recovery.phase_since_unix_ms;
        worker.recovery_attempts = recovery.attempts;
        worker.recovery_consecutive_failures = recovery.consecutive_failures;
        let mut failures: BTreeMap<i32, u32> = BTreeMap::new();
        for (class, count) in &recovery.failures_by_class {
            let total = failures.entry(recovery_failure(class) as i32).or_default();
            *total = total.saturating_add(*count);
        }
        worker.recovery_failures =
            failures.into_iter().map(|(class, count)| FailureCount { class, count }).collect();
        if recovery.last_error_unix_ms > 0 {
            let class = quil_engine::worker_execution::failure_class(&recovery.last_error);
            worker.set_last_failure(recovery_failure(class));
            worker.last_failure_unix_ms = recovery.last_error_unix_ms;
        }
        worker.last_success_unix_ms = recovery.last_outcome_unix_ms;
        worker.longest_permit_wait_ms = recovery.longest_permit_wait_ms.max(recovery.permit_wait_ms);
    }
    if let Some(seal) = &execution.seal {
        worker.seal_generation = Some(seal.generation);
        worker.seal_recorded_unix_ms = seal.recorded_unix_ms;
    }
}

/// What a report is built from, read from the master on each request.
#[derive(Debug, Clone, Default)]
pub struct HealthInputs {
    pub workers: Vec<WorkerEntry>,
    /// Committed GLOBAL session heads, by shard filter.
    pub committee_heads: HashMap<Vec<u8>, GlobalAppFrameHead>,
    pub global_head_frame: u64,
    /// What this prover's joining or activating allocations wait for, by
    /// shard filter, in this node's prover registry.
    pub join_waits: HashMap<Vec<u8>, JoinWait>,
    /// This node's master store refuses writes after a failed write.
    pub master_store_write_failed: bool,
}

/// The report of `inputs` at `now_ms`: allocated workers first, by core,
/// within [`MAX_WORKERS`] and [`MAX_REPORT_BYTES`].
pub fn build_report(inputs: &HealthInputs, build_fingerprint: &[u8], now_ms: u64) -> HealthReport {
    let mut report = HealthReport {
        schema: SCHEMA,
        version: quil_config::VERSION.to_vec(),
        patch: quil_config::PATCH_NUMBER.into(),
        subpatch: quil_config::SUBPATCH.parse().unwrap_or(0),
        build_fingerprint: build_fingerprint.to_vec(),
        global_head_frame: inputs.global_head_frame,
        generated_unix_ms: now_ms,
        master_store_write_failed: inputs.master_store_write_failed,
        ..Default::default()
    };
    let mut entries: Vec<&WorkerEntry> = inputs.workers.iter().collect();
    entries.sort_by_key(|entry| (!entry.allocated, entry.core_id));
    // Room for the omitted-worker count (a tag and a varint).
    let mut bytes = report.encoded_len() + 1 + 5;
    let mut omitted = 0u32;
    for entry in entries {
        if report.workers.len() >= MAX_WORKERS || entry.filter.len() > MAX_FILTER_BYTES {
            omitted += 1;
            continue;
        }
        let head = (!entry.filter.is_empty()).then(|| inputs.committee_heads.get(&entry.filter)).flatten();
        let join_wait = (!entry.filter.is_empty()).then(|| inputs.join_waits.get(&entry.filter).copied()).flatten();
        let worker = worker_health(entry, head, join_wait);
        let len = worker.encoded_len();
        let framed = 1 + prost::length_delimiter_len(len) + len;
        if bytes + framed > MAX_REPORT_BYTES {
            omitted += 1;
            continue;
        }
        bytes += framed;
        report.workers.push(worker);
    }
    report.omitted_workers = omitted;
    report
}

/// Why a request was not served, as the refusal summary counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Refusal {
    /// The request reached the service without a handshake identity.
    NoIdentity,
    Disabled,
    NotAllowed,
    /// An allowlisted peer asked again within the interval.
    RateLimited,
}

impl Refusal {
    pub fn label(self) -> &'static str {
        match self {
            Refusal::NoIdentity => "no_identity",
            Refusal::Disabled => "disabled",
            Refusal::NotAllowed => "not_allowed",
            Refusal::RateLimited => "rate_limited",
        }
    }
}

/// Who was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// This node itself (its operator's qclient holds the node key).
    Own,
    Peer(PeerId),
}

/// Refused requests since the last summary line.
#[derive(Debug, Default)]
struct RefusalSummary {
    logged: Option<Instant>,
    since: Option<Instant>,
    counts: BTreeMap<Refusal, u64>,
    requesters: HashSet<PeerId>,
}

/// Distinct refused requesters counted per summary, at most.
const MAX_COUNTED_REQUESTERS: usize = 1024;

/// One summary line of refused requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalLog {
    pub refused: u64,
    /// Distinct identified requesters (at most 1024).
    pub requesters: usize,
    /// `reason:count` pairs.
    pub reasons: String,
    /// Refusals of allowlisted peers asking again within the interval.
    pub rate_limited: u64,
    /// From the first refusal it counts to the last.
    pub window_secs: u64,
}

impl RefusalLog {
    /// Refusing an unlisted peer is the gate working; refusing an
    /// allowlisted one is a report this node was set up to serve and did
    /// not.
    pub fn level(&self) -> tracing::Level {
        if self.rate_limited > 0 { tracing::Level::WARN } else { tracing::Level::INFO }
    }
}

impl RefusalSummary {
    /// Count a refusal at `now`; the summary to log, at once for the first
    /// and then at most every [`REFUSAL_SUMMARY_INTERVAL`].
    fn note(&mut self, refusal: Refusal, caller: Option<&PeerId>, now: Instant) -> Option<RefusalLog> {
        let since = *self.since.get_or_insert(now);
        *self.counts.entry(refusal).or_default() += 1;
        if let Some(caller) = caller.filter(|_| self.requesters.len() < MAX_COUNTED_REQUESTERS) {
            self.requesters.insert(*caller);
        }
        if self.logged.is_some_and(|at| now.saturating_duration_since(at) < REFUSAL_SUMMARY_INTERVAL) {
            return None;
        }
        self.logged = Some(now);
        self.since = None;
        let counts = std::mem::take(&mut self.counts);
        Some(RefusalLog {
            refused: counts.values().sum(),
            requesters: std::mem::take(&mut self.requesters).len(),
            rate_limited: counts.get(&Refusal::RateLimited).copied().unwrap_or(0),
            reasons: counts.iter().map(|(r, n)| format!("{}:{n}", r.label())).collect::<Vec<_>>().join(","),
            window_secs: now.saturating_duration_since(since).as_secs(),
        })
    }
}

/// Who is served: this node, and while enabled the allowlisted peers, each
/// at most once per interval.
#[derive(Debug)]
pub struct Admission {
    enabled: bool,
    /// Empty while disabled, so every other caller takes the same lookup.
    allowed: HashSet<PeerId>,
    own: PeerId,
    min_interval: Duration,
    served: Mutex<HashMap<PeerId, Instant>>,
    refusals: Mutex<RefusalSummary>,
}

/// The peer IDs of `entries`, and the indices of the entries that are not
/// one.
pub fn parse_allowed(entries: &[String]) -> (HashSet<PeerId>, Vec<usize>) {
    let mut invalid = Vec::new();
    let peers = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let peer = PeerId::from_str(entry.trim()).ok();
            if peer.is_none() {
                invalid.push(index);
            }
            peer
        })
        .collect();
    (peers, invalid)
}

impl Admission {
    /// The admission of `config` for the node `own`, logging what it serves.
    pub fn new(config: &HealthReportConfig, own: PeerId) -> Self {
        let (allowed, invalid) = parse_allowed(&config.allowed_peers);
        if !invalid.is_empty() {
            warn!(indices = ?invalid, scope = "this node",
                action = "replace them with base58 peer IDs, as `qclient node info` prints them, and restart",
                "diagnostics.healthReport.allowedPeers entries are not peer IDs; ignored");
        }
        let min_interval_secs = config.min_interval_secs.clamp(
            *quil_config::HEALTH_REPORT_INTERVAL_SECS.start(),
            *quil_config::HEALTH_REPORT_INTERVAL_SECS.end(),
        );
        if config.enabled {
            info!(health_peers = allowed.len(), min_interval_secs,
                serves = if allowed.is_empty() { "this node only" } else { "this node and the allowlisted peers" },
                "diagnostics enabled");
        } else if !config.allowed_peers.is_empty() {
            info!(allowed_peers = config.allowed_peers.len(),
                "diagnostics.healthReport.allowedPeers is ignored until diagnostics.healthReport.enabled is set");
        }
        Self {
            enabled: config.enabled,
            allowed: if config.enabled { allowed } else { HashSet::new() },
            own,
            min_interval: Duration::from_secs(min_interval_secs),
            served: Mutex::default(),
            refusals: Mutex::default(),
        }
    }

    /// Count a refusal for the summary of an enabled node.
    fn note(&self, refusal: Refusal, caller: Option<&PeerId>, now: Instant) -> Option<RefusalLog> {
        self.refusals.lock().unwrap_or_else(PoisonError::into_inner).note(refusal, caller, now)
    }

    /// Give back the interval `requester` was charged at `at`, for a report
    /// that could not be built.
    pub fn refund(&self, requester: Requester, at: Instant) {
        let Requester::Peer(peer) = requester else { return };
        let mut served = self.served.lock().unwrap_or_else(PoisonError::into_inner);
        if served.get(&peer) == Some(&at) {
            served.remove(&peer);
        }
    }

    fn check(&self, caller: Option<&PeerId>, now: Instant) -> Result<Requester, Refusal> {
        let caller = caller.ok_or(Refusal::NoIdentity)?;
        if *caller == self.own {
            return Ok(Requester::Own);
        }
        if !self.allowed.contains(caller) {
            return Err(if self.enabled { Refusal::NotAllowed } else { Refusal::Disabled });
        }
        let mut served = self.served.lock().unwrap_or_else(PoisonError::into_inner);
        if served.get(caller).is_some_and(|at| now.saturating_duration_since(*at) < self.min_interval) {
            return Err(Refusal::RateLimited);
        }
        served.insert(*caller, now);
        Ok(Requester::Peer(*caller))
    }

    /// Admit `caller` at `now`, or the status to answer with; refusals are
    /// summarized in the log.
    pub fn admit(&self, caller: Option<&PeerId>, now: Instant) -> Result<Requester, Status> {
        let refusal = match self.check(caller, now) {
            Ok(requester) => return Ok(requester),
            Err(refusal) => refusal,
        };
        // Every node serves itself, so a node that never enabled the report
        // still answers probes: nothing there for its operator to act on.
        if !self.enabled {
            debug!(reason = refusal.label(), "diagnostics request refused: the health report is disabled");
        } else if let Some(log) = self.note(refusal, caller, now) {
            if log.level() == tracing::Level::WARN {
                warn!(refused = log.refused, requesters = log.requesters, reasons = %log.reasons,
                    window_secs = log.window_secs, scope = "allowlisted peers",
                    action = "allowlisted peers asked again within diagnostics.healthReport.minIntervalSecs; \
                        ask their operators to ask less often, or lower minIntervalSecs and restart",
                    "diagnostics requests refused");
            } else {
                info!(refused = log.refused, requesters = log.requesters, reasons = %log.reasons,
                    window_secs = log.window_secs, scope = "remote peers",
                    action = "expected unless you meant to serve these peers; to serve one, add its peer ID \
                        to diagnostics.healthReport.allowedPeers and restart",
                    "diagnostics requests refused");
            }
        }
        Err(match refusal {
            Refusal::RateLimited => Status::resource_exhausted(format!(
                "a health report was served to this peer less than {}s ago",
                self.min_interval.as_secs()
            )),
            _ => Status::permission_denied(DENIED),
        })
    }
}

/// Reads the master's state for one report; it may block briefly.
pub type HealthSource = Arc<dyn Fn() -> HealthInputs + Send + Sync>;

pub struct DiagnosticsServer {
    admission: Arc<Admission>,
    source: HealthSource,
    build_fingerprint: Vec<u8>,
}

impl DiagnosticsServer {
    pub fn new(admission: Arc<Admission>, source: HealthSource, build_fingerprint: Vec<u8>) -> Self {
        Self { admission, source, build_fingerprint }
    }

    /// The tonic service, bounded to empty requests.
    pub fn into_service(self) -> DiagnosticsServiceServer<Self> {
        DiagnosticsServiceServer::new(self)
            .max_decoding_message_size(MAX_REQUEST_BYTES)
            .max_encoding_message_size(2 * MAX_REPORT_BYTES)
    }
}

#[tonic::async_trait]
impl DiagnosticsService for DiagnosticsServer {
    async fn get_health_report(
        &self,
        request: Request<GetHealthReportRequest>,
    ) -> Result<Response<HealthReport>, Status> {
        // Fail closed: only the handshake identity admits a caller.
        let caller = request.extensions().get::<AuthenticatedPeer>().map(|auth| auth.peer_id);
        let admitted = Instant::now();
        let requester = self.admission.admit(caller.as_ref(), admitted)?;
        let source = self.source.clone();
        let inputs = match tokio::task::spawn_blocking(move || source()).await {
            Ok(inputs) => inputs,
            Err(error) => {
                // The requester may ask again at once: nothing was served.
                self.admission.refund(requester, admitted);
                warn!(%error, scope = "this node", action = "report it with this line",
                    "diagnostics health report could not be built");
                return Err(Status::unavailable("health report unavailable"));
            }
        };
        let report = build_report(&inputs, &self.build_fingerprint, quil_engine::worker_execution::now_ms());
        let requester = match requester {
            Requester::Own => "self".to_string(),
            Requester::Peer(peer) => peer_tail(&peer),
        };
        info!(%requester, workers = report.workers.len(), omitted_workers = report.omitted_workers,
            bytes = report.encoded_len(), "diagnostics health report served");
        Ok(Response::new(report))
    }
}

/// Dial the peer listener at `addr` as the holder of `falcon_signing_key`,
/// refusing an endpoint that does not prove the identity `expected`.
pub async fn connect_peer(
    addr: &str,
    falcon_signing_key: &[u8],
    expected: PeerId,
) -> Result<DiagnosticsServiceClient<Channel>, Box<dyn std::error::Error + Send + Sync>> {
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))?
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);
    let connector = crate::QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).with_expected_peer(expected);
    let channel = endpoint.connect_with_connector(connector).await?;
    Ok(DiagnosticsServiceClient::new(channel).max_decoding_message_size(2 * MAX_REPORT_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_engine::worker_execution::{BLOCKERS as ENGINE_BLOCKERS, FAILURE_CLASSES, RECOVERY_PHASES as ENGINE_RECOVERY_PHASES, STATES};
    use quil_types::proto::node::{SessionSeal, ShardRecovery};

    fn peer() -> PeerId {
        quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key()).unwrap().public().to_peer_id()
    }

    fn config(enabled: bool, allowed: &[PeerId]) -> HealthReportConfig {
        HealthReportConfig {
            enabled,
            allowed_peers: allowed.iter().map(|peer| peer.to_base58()).collect(),
            min_interval_secs: 60,
        }
    }

    fn entry(core_id: u32, filter: &[u8], execution: Option<WorkerExecution>) -> WorkerEntry {
        WorkerEntry {
            core_id,
            filter: filter.to_vec(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            allocated: !filter.is_empty(),
            execution,
        }
    }

    fn server(admission: Admission) -> DiagnosticsServer {
        let source: HealthSource = Arc::new(|| HealthInputs {
            workers: vec![entry(1, &[7; 32], None)],
            committee_heads: HashMap::new(),
            global_head_frame: 9,
            join_waits: HashMap::new(),
            ..Default::default()
        });
        DiagnosticsServer::new(Arc::new(admission), source, vec![0xab; 32])
    }

    fn request(caller: Option<PeerId>) -> Request<GetHealthReportRequest> {
        let mut request = Request::new(GetHealthReportRequest {});
        if let Some(peer_id) = caller {
            request.extensions_mut().insert(AuthenticatedPeer { peer_id, falcon_public_key: Vec::new() });
        }
        request
    }

    /// No identity, an unlisted peer and a node that has not enabled the
    /// report give the same answer; this node and listed peers are served.
    #[tokio::test]
    async fn only_this_node_and_listed_peers_are_served_and_refusals_are_alike() {
        let (own, listed, other) = (peer(), peer(), peer());
        let enabled = server(Admission::new(&config(true, &[listed]), own));
        let disabled = server(Admission::new(&config(false, &[listed]), own));
        let mut refusals = Vec::new();
        for (service, caller) in [(&enabled, None), (&enabled, Some(other)), (&disabled, Some(listed)), (&disabled, None)] {
            refusals.push(service.get_health_report(request(caller)).await.unwrap_err());
        }
        for status in &refusals {
            assert_eq!((status.code(), status.message()), (tonic::Code::PermissionDenied, DENIED));
        }
        let served = enabled.get_health_report(request(Some(listed))).await.unwrap().into_inner();
        assert_eq!((served.schema, served.global_head_frame, served.workers.len()), (SCHEMA, 9, 1));
        assert_eq!(served.build_fingerprint, vec![0xab; 32]);
        assert_eq!(served.version, quil_config::VERSION.to_vec());
        for service in [&enabled, &disabled] {
            for _ in 0..3 {
                assert!(service.get_health_report(request(Some(own))).await.is_ok(), "this node is always served");
            }
        }
    }

    #[test]
    fn a_listed_peer_is_served_once_per_interval() {
        let (own, listed, other) = (peer(), peer(), peer());
        let admission = Admission::new(&config(true, &[listed, other]), own);
        let start = Instant::now();
        assert_eq!(admission.admit(Some(&listed), start).unwrap(), Requester::Peer(listed));
        let again = admission.admit(Some(&listed), start + Duration::from_secs(59)).unwrap_err();
        assert_eq!(again.code(), tonic::Code::ResourceExhausted);
        assert!(admission.admit(Some(&other), start + Duration::from_secs(59)).is_ok(), "each peer has its own interval");
        assert!(admission.admit(Some(&listed), start + Duration::from_secs(60)).is_ok());
        assert_eq!(admission.check(Some(&own), start), Ok(Requester::Own));
        assert_eq!(admission.check(None, start), Err(Refusal::NoIdentity));
        assert_eq!(admission.check(Some(&peer()), start), Err(Refusal::NotAllowed));
        let disabled = Admission::new(&config(false, &[listed]), own);
        assert_eq!(disabled.check(Some(&listed), start), Err(Refusal::Disabled));
    }

    /// A report that fails to build does not use up the requester's
    /// interval; a served one does.
    #[tokio::test]
    async fn only_a_served_report_charges_the_interval() {
        let (own, listed) = (peer(), peer());
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let failing = fail.clone();
        let source: HealthSource = Arc::new(move || {
            assert!(!failing.swap(false, std::sync::atomic::Ordering::SeqCst), "the master's state is unreadable");
            HealthInputs::default()
        });
        let service = DiagnosticsServer::new(Arc::new(Admission::new(&config(true, &[listed]), own)), source, Vec::new());
        let failed = service.get_health_report(request(Some(listed))).await.unwrap_err();
        assert_eq!(failed.code(), tonic::Code::Unavailable);
        assert!(service.get_health_report(request(Some(listed))).await.is_ok(), "the failure was refunded");
        let again = service.get_health_report(request(Some(listed))).await.unwrap_err();
        assert_eq!(again.code(), tonic::Code::ResourceExhausted);
    }

    /// A node that has not enabled the report counts no refusals for its
    /// operator; an enabled one warns only about allowlisted peers it
    /// refused.
    #[test]
    fn only_refused_allowlisted_peers_are_warned_about() {
        let (own, listed, other) = (peer(), peer(), peer());
        let start = Instant::now();
        let disabled = Admission::new(&config(false, &[listed]), own);
        for caller in [None, Some(&listed), Some(&other)] {
            assert!(disabled.admit(caller, start).is_err());
        }
        assert!(disabled.refusals.lock().unwrap().logged.is_none(), "nothing summarized while disabled");
        let enabled = Admission::new(&config(true, &[listed]), own);
        let unlisted = enabled.note(Refusal::NotAllowed, Some(&other), start).unwrap();
        assert_eq!(unlisted.level(), tracing::Level::INFO);
        enabled.note(Refusal::NoIdentity, None, start + Duration::from_secs(1));
        enabled.note(Refusal::RateLimited, Some(&listed), start + Duration::from_secs(2));
        let mixed = enabled.note(Refusal::NotAllowed, Some(&other), start + REFUSAL_SUMMARY_INTERVAL).unwrap();
        assert_eq!((mixed.rate_limited, mixed.level()), (1, tracing::Level::WARN));
    }

    #[test]
    fn entries_that_are_not_peer_ids_are_dropped_by_index() {
        let (a, b) = (peer(), peer());
        let entries = vec![a.to_base58(), "not-a-peer".into(), format!(" {} ", b.to_base58()), String::new()];
        let (peers, invalid) = parse_allowed(&entries);
        assert_eq!(peers, HashSet::from([a, b]));
        assert_eq!(invalid, [1, 3]);
    }

    /// The first refusal is logged at once, later ones in one summary per
    /// interval with counts by reason and distinct requesters.
    #[test]
    fn refusals_are_summarized_at_a_bounded_rate() {
        let (a, b, c) = (peer(), peer(), peer());
        let start = Instant::now();
        let mut summary = RefusalSummary::default();
        assert_eq!(summary.note(Refusal::NotAllowed, Some(&a), start),
            Some(RefusalLog { refused: 1, requesters: 1, reasons: "not_allowed:1".into(), rate_limited: 0, window_secs: 0 }));
        let mut logged = 0;
        for (n, peer) in [&a, &b, &a, &c, &b].into_iter().enumerate() {
            let at = start + Duration::from_secs(60 * (n as u64 + 1));
            logged += usize::from(summary.note(Refusal::NotAllowed, Some(peer), at).is_some());
        }
        assert_eq!(logged, 0);
        assert_eq!(summary.note(Refusal::RateLimited, Some(&a), start + Duration::from_secs(400)), None);
        assert_eq!(summary.note(Refusal::NoIdentity, None, start + Duration::from_secs(500)), None);
        assert_eq!(summary.note(Refusal::RateLimited, Some(&a), start + Duration::from_secs(600)),
            Some(RefusalLog { refused: 8, requesters: 3,
                reasons: "no_identity:1,not_allowed:5,rate_limited:2".into(), rate_limited: 2, window_secs: 540 }));
        assert_eq!(summary.note(Refusal::Disabled, Some(&b), start + Duration::from_secs(601)), None);
    }

    /// Every phase, reason, recovery phase and failure class the engine
    /// writes has its own value, and its text round-trips.
    #[test]
    fn every_engine_literal_maps_to_its_own_value() {
        let phases: HashSet<Phase> = STATES.iter().map(|state| phase(state, "")).collect();
        assert_eq!(phases.len(), STATES.len());
        for state in STATES {
            assert!(!matches!(phase(state, ""), Phase::Unrecognized | Phase::Unspecified), "{state}");
            assert_eq!(phase_name(phase(state, "")), state);
        }
        assert_eq!(phase("running", ""), Phase::Running, "older workers");
        assert_eq!(phase("blocked", "awaiting successor"), Phase::Handoff, "older workers");
        assert_eq!((phase("", ""), phase("dancing", "")), (Phase::Unspecified, Phase::Unrecognized));

        let blockers: HashSet<Blocker> = ENGINE_BLOCKERS.iter().map(|text| blocker(text)).collect();
        assert_eq!(blockers.len(), ENGINE_BLOCKERS.len());
        for text in ENGINE_BLOCKERS {
            assert!(!matches!(blocker(text), Blocker::Unrecognized | Blocker::None), "{text}");
            assert_eq!(blocker_text(blocker(text)), text);
        }
        assert_eq!((blocker(""), blocker("disk full at 192.0.2.1")), (Blocker::None, Blocker::Unrecognized));

        let recovery: HashSet<RecoveryPhase> = ENGINE_RECOVERY_PHASES.iter().map(|text| recovery_phase(text)).collect();
        assert_eq!(recovery.len(), ENGINE_RECOVERY_PHASES.len());
        for text in ENGINE_RECOVERY_PHASES {
            assert!(!matches!(recovery_phase(text), RecoveryPhase::Unrecognized | RecoveryPhase::Starting), "{text}");
            assert_eq!(recovery_phase_name(recovery_phase(text)), text);
        }
        assert_eq!(recovery_phase("teleporting"), RecoveryPhase::Unrecognized);

        let failures: HashSet<RecoveryFailure> = FAILURE_CLASSES.iter().map(|class| recovery_failure(class)).collect();
        assert_eq!(failures.len(), FAILURE_CLASSES.len());
        for class in FAILURE_CLASSES {
            assert_ne!(recovery_failure(class), RecoveryFailure::None, "{class}");
            assert_eq!(recovery_failure_name(recovery_failure(class)), class);
        }
    }

    /// A worker whose own store refuses writes reads as blocked by it, and a
    /// master store that does is reported.
    #[test]
    fn a_failed_store_write_is_reported() {
        let latched = WorkerExecution {
            state: "blocked".into(),
            blocker: quil_engine::worker_execution::STORAGE_WRITE_FAILED.into(),
            observed_unix_ms: 2_000,
            ..Default::default()
        };
        let inputs = HealthInputs { workers: vec![entry(2, &[2; 32], Some(latched))], ..Default::default() };
        let report = build_report(&inputs, &[], 3_000);
        assert_eq!((report.workers[0].phase(), report.workers[0].blocker()), (Phase::Blocked, Blocker::StorageWriteFailed));
        assert!(!report.master_store_write_failed);
        let inputs = HealthInputs { master_store_write_failed: true, ..inputs };
        assert!(build_report(&inputs, &[], 3_000).master_store_write_failed);
    }

    fn noisy_execution() -> WorkerExecution {
        WorkerExecution {
            state: "blocked".into(),
            blocker: "state unavailable".into(),
            materialized_frame: Some(1_180),
            last_advance_unix_ms: 1_000,
            observed_unix_ms: 2_000,
            recovery: Some(ShardRecovery {
                phase: "installing_leaves".into(),
                phase_since_unix_ms: 1_500,
                source: "192.0.2.7:8340".into(),
                last_error: "archive connect: /home/operator/.config refused by 192.0.2.8".into(),
                last_error_unix_ms: 1_900,
                last_outcome: "replayed to frame 1180 from 192.0.2.9:8340".into(),
                last_outcome_unix_ms: 1_200,
                attempts: 5,
                consecutive_failures: 2,
                permit_wait_ms: 4_000,
                longest_permit_wait_ms: 95_000,
                failures_by_class: HashMap::from([("connect".into(), 2), ("archive_state".into(), 1), ("someday".into(), 1)]),
                ..Default::default()
            }),
            seal: Some(SessionSeal { generation: 6, drain: "partial via 192.0.2.10".into(), recorded_unix_ms: 1_700, ..Default::default() }),
            awaited_frame: None,
            ..Default::default()
        }
    }

    #[test]
    fn a_worker_reports_its_observations_without_their_texts() {
        let head = GlobalAppFrameHead { frame: 1_204, global_frame: 90_000, generation: 7 };
        let worker = worker_health(&entry(3, &[5; 32], Some(noisy_execution())), Some(&head), None);
        assert_eq!((worker.phase(), worker.blocker()), (Phase::Blocked, Blocker::StateUnavailable));
        assert_eq!((worker.materialized_frame, worker.committee_head_frame, worker.committed_generation),
            (Some(1_180), Some(1_204), Some(7)));
        assert_eq!((worker.recovery_phase(), worker.recovery_attempts, worker.recovery_consecutive_failures),
            (RecoveryPhase::InstallingLeaves, 5, 2));
        assert_eq!(worker.recovery_failures, [
            FailureCount { class: RecoveryFailure::Connect as i32, count: 2 },
            FailureCount { class: RecoveryFailure::ArchiveState as i32, count: 1 },
            FailureCount { class: RecoveryFailure::Other as i32, count: 1 },
        ]);
        assert_eq!((worker.last_failure(), worker.last_failure_unix_ms, worker.last_success_unix_ms),
            (RecoveryFailure::Connect, 1_900, 1_200));
        assert_eq!(worker.longest_permit_wait_ms, 95_000);
        assert_eq!((worker.seal_generation, worker.seal_recorded_unix_ms), (Some(6), 1_700));

        let inputs = HealthInputs {
            workers: vec![entry(3, &[5; 32], Some(noisy_execution()))],
            committee_heads: HashMap::from([(vec![5; 32], head)]),
            global_head_frame: 90_001,
            join_waits: HashMap::new(),
            ..Default::default()
        };
        let encoded = build_report(&inputs, &[1; 32], 3_000).encode_to_vec();
        for secret in ["192.0.2", "/home", "operator", "refused", "replayed", "partial", "state unavailable"] {
            assert!(!encoded.windows(secret.len()).any(|w| w == secret.as_bytes()), "{secret} leaked");
        }
    }

    /// A worker whose allocation joins reads as joining, with the epoch its
    /// confirm is due in or the frame it activates at, whether it runs no
    /// engine or one refused before activation; a serving engine keeps its
    /// phase, and the engine's blocker and recovery stay in the report.
    #[test]
    fn a_joining_allocation_reads_as_joining_with_what_it_awaits() {
        let blocked = WorkerExecution {
            state: "blocked".into(),
            blocker: "consensus startup unavailable".into(),
            observed_unix_ms: 2_000,
            recovery: Some(ShardRecovery { phase: "idle".into(), attempts: 3, consecutive_failures: 3, ..Default::default() }),
            ..Default::default()
        };
        let unconfirmed = worker_health(&entry(1, &[1; 32], None), None, Some(JoinWait::Confirmation { epoch: 1276 }));
        assert_eq!((unconfirmed.phase(), unconfirmed.join_confirm_epoch, unconfirmed.activation_frame),
            (Phase::Joining, Some(1276), Some(1277 * 720)));
        let activating = worker_health(&entry(2, &[2; 32], Some(blocked)), None, Some(JoinWait::Activation { frame: 918_720 }));
        assert_eq!((activating.phase(), activating.blocker(), activating.join_confirm_epoch, activating.activation_frame),
            (Phase::Joining, Blocker::ConsensusStartupUnavailable, None, Some(918_720)));
        assert_eq!((activating.recovery_attempts, activating.recovery_consecutive_failures), (3, 3));
        let serving = WorkerExecution { state: "serving".into(), observed_unix_ms: 2_000, ..Default::default() };
        let serving = worker_health(&entry(3, &[3; 32], Some(serving)), None, Some(JoinWait::Activation { frame: 918_720 }));
        assert_eq!(serving.phase(), Phase::Serving);
        let seat = WorkerExecution { state: "waiting".into(), blocker: "committee admission unavailable".into(),
            observed_unix_ms: 2_000, awaited_frame: Some(919_440), ..Default::default() };
        let seat = worker_health(&entry(6, &[6; 32], Some(seat)), None, None);
        assert_eq!((seat.phase(), seat.blocker(), seat.awaited_frame),
            (Phase::Waiting, Blocker::CommitteeAdmissionUnavailable, Some(919_440)));
        let unknown = worker_health(&entry(4, &[4; 32], None), None, None);
        assert_eq!((unknown.phase(), unknown.activation_frame), (Phase::Unspecified, None));

        let inputs = HealthInputs {
            workers: vec![entry(1, &[1; 32], None), entry(5, &[], None)],
            join_waits: HashMap::from([(vec![1; 32], JoinWait::Confirmation { epoch: 1276 }), (Vec::new(), JoinWait::Activation { frame: 1 })]),
            ..Default::default()
        };
        let phases: Vec<(u32, Phase)> = build_report(&inputs, &[], 0).workers.iter().map(|w| (w.core_id, w.phase())).collect();
        assert_eq!(phases, [(1, Phase::Joining), (5, Phase::Unspecified)], "an idle worker has no join");
        assert_eq!(phase_name(Phase::Joining), "joining");
    }

    #[test]
    fn allocated_workers_come_first_with_their_shards_committee_head() {
        let head = |frame| GlobalAppFrameHead { frame, global_frame: 1, generation: frame / 100 };
        let inputs = HealthInputs {
            workers: vec![entry(4, &[], None), entry(2, &[2; 32], None), entry(1, &[], None), entry(3, &[3; 32], None)],
            committee_heads: HashMap::from([(vec![2; 32], head(200)), (vec![3; 32], head(300)), (Vec::new(), head(9))]),
            global_head_frame: 5,
            join_waits: HashMap::new(),
            ..Default::default()
        };
        let report = build_report(&inputs, &[], 0);
        let order: Vec<(u32, Option<u64>, Option<u64>)> =
            report.workers.iter().map(|w| (w.core_id, w.committee_head_frame, w.committed_generation)).collect();
        assert_eq!(order, [(2, Some(200), Some(2)), (3, Some(300), Some(3)), (1, None, None), (4, None, None)]);
        assert_eq!(report.omitted_workers, 0);
    }

    #[test]
    fn a_report_is_bounded_in_workers_and_bytes() {
        let many = |execution: Option<WorkerExecution>| HealthInputs {
            workers: (0..300).map(|core| entry(core, &[core as u8; 32], execution.clone())).collect(),
            committee_heads: (0..300u32).map(|core| (vec![core as u8; 32],
                GlobalAppFrameHead { frame: u64::MAX, global_frame: u64::MAX, generation: u64::MAX })).collect(),
            global_head_frame: u64::MAX,
            join_waits: HashMap::new(),
            ..Default::default()
        };
        let light = build_report(&many(None), &[0xff; 32], u64::MAX);
        assert_eq!((light.workers.len(), light.omitted_workers), (MAX_WORKERS, 44));
        let mut heavy = noisy_execution();
        let recovery = heavy.recovery.as_mut().unwrap();
        recovery.failures_by_class = FAILURE_CLASSES.iter().map(|class| (class.to_string(), u32::MAX)).collect();
        (recovery.attempts, recovery.consecutive_failures) = (u32::MAX, u32::MAX);
        for at in [&mut recovery.last_error_unix_ms, &mut recovery.last_outcome_unix_ms, &mut recovery.phase_since_unix_ms] {
            *at = u64::MAX;
        }
        let heavy = build_report(&many(Some(heavy)), &[0xff; 32], u64::MAX);
        assert!(heavy.encoded_len() <= MAX_REPORT_BYTES, "{}", heavy.encoded_len());
        assert!(heavy.workers.len() < MAX_WORKERS);
        assert_eq!(heavy.workers.len() + heavy.omitted_workers as usize, 300);
        let long = HealthInputs { workers: vec![entry(1, &[1; MAX_FILTER_BYTES + 1], None)], ..Default::default() };
        assert_eq!(build_report(&long, &[], 0).omitted_workers, 1);
    }

    /// Over the real transport: the listener's handshake identity admits a
    /// listed peer, an unlisted one is refused, and a client pinned to
    /// another identity never sends its request.
    #[tokio::test]
    async fn the_handshake_identity_is_what_admits_a_peer() {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        let (server_key, listed_key, other_key) = (
            quil_p2p::generate_falcon_signing_key(),
            quil_p2p::generate_falcon_signing_key(),
            quil_p2p::generate_falcon_signing_key(),
        );
        let id = |key: &[u8]| quil_p2p::Keypair::falcon_from_bytes(key).unwrap().public().to_peer_id();
        let (server_id, listed) = (id(&server_key), id(&listed_key));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
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
        let service = tonic::service::interceptor::InterceptedService::new(
            server(Admission::new(&config(true, &[listed]), server_id)).into_service(),
            crate::peer_auth_middleware::peer_auth_interceptor,
        );
        let serve = tokio::spawn(
            tonic::transport::Server::builder().add_service(service).serve_with_incoming(UnboundedReceiverStream::new(rx)),
        );

        let mut client = connect_peer(&addr, &listed_key, server_id).await.unwrap();
        let report = client.get_health_report(GetHealthReportRequest {}).await.unwrap().into_inner();
        assert_eq!(report.workers.len(), 1);
        let mut client = connect_peer(&addr, &other_key, server_id).await.unwrap();
        let refused = client.get_health_report(GetHealthReportRequest {}).await.unwrap_err();
        assert_eq!((refused.code(), refused.message()), (tonic::Code::PermissionDenied, DENIED));
        let pinned = connect_peer(&addr, &listed_key, listed).await;
        assert!(pinned.is_err(), "an endpoint answering with another identity is refused");
        accept.abort();
        serve.abort();
    }
}
