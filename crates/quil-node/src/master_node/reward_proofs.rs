//! The node's GLOBAL submissions for its app-shard workers: certified shard
//! frame headers (the reward proofs GLOBAL credits a shard's provers from) and
//! committee-handoff submissions, each sent as a one-request bundle through
//! the prover-message transport (gRPC to the archives).
//!
//! Thread workers hand them over in process; standalone workers through
//! `GlobalService.SubmitWorkerProverMessage` on their own master. Before the
//! latter existed a standalone worker's finalized frames were never submitted,
//! so a shard staffed only by standalone workers was never credited.

use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
use quil_execution::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// What a worker may submit to GLOBAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerSubmission {
    /// A certified shard frame header: a reward proof.
    FrameHeader,
    /// A committee-handoff submission (a closing seal).
    CommitteeHandoff,
}

/// The kind of a worker's canonical GLOBAL request, by its type prefix.
pub(crate) fn worker_submission(request: &[u8]) -> Option<WorkerSubmission> {
    let prefix = u32::from_be_bytes(request.get(..4)?.try_into().ok()?);
    match prefix {
        TYPE_FRAME_HEADER => Some(WorkerSubmission::FrameHeader),
        TYPE_COMMITTEE_HANDOFF => Some(WorkerSubmission::CommitteeHandoff),
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
    CanonicalMessageBundle { requests: vec![Some(request)], timestamp }
        .to_canonical_bytes()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_frame_headers_and_handoff_submissions_are_worker_submissions() {
        let header = FrameHeader { address: vec![7; 32], frame_number: 9, ..Default::default() }
            .to_canonical_bytes()
            .unwrap();
        assert_eq!(worker_submission(&header), Some(WorkerSubmission::FrameHeader));
        let mut handoff = TYPE_COMMITTEE_HANDOFF.to_be_bytes().to_vec();
        handoff.extend_from_slice(b"seal");
        assert_eq!(worker_submission(&handoff), Some(WorkerSubmission::CommitteeHandoff));
        let mut join = quil_execution::global_intrinsic::TYPE_PROVER_JOIN.to_be_bytes().to_vec();
        join.extend_from_slice(b"join");
        assert_eq!(worker_submission(&join), None, "a worker submits no lifecycle ops");
        assert_eq!(worker_submission(&[0x03]), None);

        let bundle = CanonicalMessageBundle::from_canonical_bytes(&prover_bundle(header.clone()).unwrap()).unwrap();
        let requests: Vec<_> = bundle.requests.into_iter().flatten().collect();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].inner_type_prefix, TYPE_FRAME_HEADER);
        assert_eq!(requests[0].inner_bytes, header);
    }
}
