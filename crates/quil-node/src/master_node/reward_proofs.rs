//! The node's GLOBAL submissions for its app-shard workers: certified shard
//! frame headers (the reward proofs GLOBAL credits a shard's provers from),
//! committee-handoff submissions and presence reports, each sent as a
//! one-request bundle through the prover-message transport (gRPC to the
//! archives).
//!
//! Thread workers hand them over in process; standalone workers through
//! `GlobalService.SubmitWorkerProverMessage` on their own master. Before the
//! latter existed a standalone worker's finalized frames were never submitted,
//! so a shard staffed only by standalone workers was never credited.

use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
use quil_execution::global_intrinsic::handoff::{
    presence::PresenceReport, presence_report_frame, TYPE_COMMITTEE_HANDOFF, TYPE_PRESENCE_REPORT,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// What a worker may submit to GLOBAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerSubmission {
    /// A certified shard frame header: a reward proof.
    FrameHeader,
    /// A committee-handoff submission (a closing seal).
    CommitteeHandoff,
    /// A stalled session's notarize votes, as evidence of its members' presence.
    PresenceReport,
}

impl WorkerSubmission {
    /// Whether the own-operation tracker follows it to a GLOBAL frame
    /// (`quil_engine::own_prover_ops`): a presence report. Only the master
    /// sees GLOBAL frames, so it registers the reports it publishes for its
    /// thread and standalone workers alike ([`track_worker_request`]).
    pub(crate) fn tracked(self) -> bool {
        self == Self::PresenceReport
    }

    /// Whether this node publishes it now: a presence report only while the
    /// presence report frame is set, so a node with reports off (mainnet,
    /// and by default) publishes none, whatever a worker sends.
    pub(crate) fn active(self) -> bool {
        self != Self::PresenceReport || presence_report_frame() != u64::MAX
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::FrameHeader => "reward_proof",
            Self::CommitteeHandoff => "committee_handoff",
            Self::PresenceReport => "presence_report",
        }
    }
}

/// The kind and full shard filter of a worker's request, for its log lines;
/// a committee-handoff submission names no filter.
pub(crate) fn describe_request(request: &[u8]) -> (&'static str, String) {
    match worker_submission(request) {
        Some(WorkerSubmission::FrameHeader) => (
            "reward_proof",
            FrameHeader::from_canonical_bytes(request)
                .map(|h| hex::encode(h.address))
                .unwrap_or_default(),
        ),
        Some(WorkerSubmission::PresenceReport) => (
            "presence_report",
            PresenceReport::from_canonical_bytes(request)
                .map(|r| hex::encode(r.filter))
                .unwrap_or_default(),
        ),
        Some(kind) => (kind.name(), String::new()),
        None => ("other", String::new()),
    }
}

/// Seconds since the Unix epoch of the last "not tracked" warning.
static UNTRACKED_WARNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const UNTRACKED_WARN_SECS: u64 = 600;

/// Register a worker's request this node is about to publish, at GLOBAL
/// frame `frame`, with the own-operation tracker if it follows its kind;
/// true if registered. Registering first lets an inclusion seen before the
/// publication completes resolve it. Without a frame it is not tracked,
/// and a warning says so at most every ten minutes.
pub(crate) fn track_worker_request(request: &[u8], frame: Option<u64>) -> bool {
    if !worker_submission(request).is_some_and(WorkerSubmission::tracked) {
        return false;
    }
    let Some(frame) = frame else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let last = UNTRACKED_WARNED.load(std::sync::atomic::Ordering::Relaxed);
        if now >= last.saturating_add(UNTRACKED_WARN_SECS)
            && UNTRACKED_WARNED
                .compare_exchange(
                    last,
                    now,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            let (kind, filter) = describe_request(request);
            tracing::warn!(kind, filter = %filter, scope = "local", action = "check",
                "worker submission published without inclusion tracking: this node's latest GLOBAL frame could not \
                 be read; check its clock store (repeated at most every ten minutes)");
        }
        return false;
    };
    quil_engine::own_prover_ops::tracker().submitted(request, frame);
    true
}

/// The publication of a worker's request failed or was held back: withdraw
/// it from the tracker if [`track_worker_request`] registered it, and let a
/// presence report's reporter in this process give back its budget.
pub(crate) fn unpublished(request: &[u8], tracked: bool) {
    if tracked {
        quil_engine::own_prover_ops::tracker().withdraw(request);
    }
    quil_engine::presence_reports::publication_failed(request);
}

/// The kind of a worker's canonical GLOBAL request, by its type prefix.
pub(crate) fn worker_submission(request: &[u8]) -> Option<WorkerSubmission> {
    let prefix = u32::from_be_bytes(request.get(..4)?.try_into().ok()?);
    match prefix {
        TYPE_FRAME_HEADER => Some(WorkerSubmission::FrameHeader),
        TYPE_COMMITTEE_HANDOFF => Some(WorkerSubmission::CommitteeHandoff),
        TYPE_PRESENCE_REPORT => Some(WorkerSubmission::PresenceReport),
        _ => None,
    }
}

/// Log a certified shard frame header going out as a reward proof.
pub(crate) fn log_reward_proof(core_id: u32, worker: &'static str, header: &[u8]) {
    if let Ok(h) = FrameHeader::from_canonical_bytes(header) {
        tracing::info!(
            core_id,
            worker,
            filter = %hex::encode(&h.address),
            frame = h.frame_number,
            rank = h.rank,
            prover = %hex::encode(&h.prover),
            "submitting reward proof to GLOBAL_PROVER"
        );
    }
}

/// One canonical request as a bundle for the prover-message transport.
pub(crate) fn prover_bundle(request: Vec<u8>) -> Result<Vec<u8>, String> {
    let request = CanonicalMessageRequest::wrap(request).map_err(|e| e.to_string())?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    CanonicalMessageBundle {
        requests: vec![Some(request)],
        timestamp,
    }
    .to_canonical_bytes()
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_frame_headers_handoff_submissions_and_presence_reports_are_worker_submissions() {
        let header = FrameHeader {
            address: vec![7; 32],
            frame_number: 9,
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        assert_eq!(
            worker_submission(&header),
            Some(WorkerSubmission::FrameHeader)
        );
        let mut handoff = TYPE_COMMITTEE_HANDOFF.to_be_bytes().to_vec();
        handoff.extend_from_slice(b"seal");
        assert_eq!(
            worker_submission(&handoff),
            Some(WorkerSubmission::CommitteeHandoff)
        );
        let mut presence = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
        presence.extend_from_slice(b"report");
        assert_eq!(
            worker_submission(&presence),
            Some(WorkerSubmission::PresenceReport)
        );
        assert!(
            WorkerSubmission::PresenceReport.tracked(),
            "its inclusion is logged for a standalone worker too"
        );
        // Reports are relayed only while the presence report frame is set.
        quil_execution::global_intrinsic::handoff::set_presence_report_frame_for_thread(Some(
            u64::MAX,
        ));
        assert!(!WorkerSubmission::PresenceReport.active());
        assert!(
            WorkerSubmission::FrameHeader.active() && WorkerSubmission::CommitteeHandoff.active()
        );
        quil_execution::global_intrinsic::handoff::set_presence_report_frame_for_thread(Some(0));
        assert!(WorkerSubmission::PresenceReport.active());
        quil_execution::global_intrinsic::handoff::set_presence_report_frame_for_thread(Some(
            u64::MAX,
        ));
        assert!(
            !WorkerSubmission::FrameHeader.tracked()
                && !WorkerSubmission::CommitteeHandoff.tracked()
        );
        let mut join = quil_execution::global_intrinsic::TYPE_PROVER_JOIN
            .to_be_bytes()
            .to_vec();
        join.extend_from_slice(b"join");
        assert_eq!(
            worker_submission(&join),
            None,
            "a worker submits no lifecycle ops"
        );
        assert_eq!(worker_submission(&[0x03]), None);

        let bundle =
            CanonicalMessageBundle::from_canonical_bytes(&prover_bundle(header.clone()).unwrap())
                .unwrap();
        let requests: Vec<_> = bundle.requests.into_iter().flatten().collect();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].inner_type_prefix, TYPE_FRAME_HEADER);
        assert_eq!(requests[0].inner_bytes, header);
    }
}
