//! Whether this node's own prover operations reach a GLOBAL frame. A join,
//! confirm, reject or leave the archives drop before inclusion and one they
//! include but refuse at execution look the same to a regular node: neither
//! changes its registry, and it does not execute GLOBAL frames itself. A
//! worker's presence report is tracked the same way: the master registers the
//! reports it publishes for its thread and standalone workers, before
//! publishing them, and withdraws one whose publication fails. Each published
//! operation is matched against the authenticated frames this node receives,
//! and one line says which frame included it, or that none of the frames
//! received within `INCLUSION_WINDOW_FRAMES` did.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use quil_execution::global_intrinsic::handoff::{presence::PresenceReport, TYPE_PRESENCE_REPORT};
use quil_execution::global_intrinsic::prover_filter_ops::{ProverLeave, TYPE_PROVER_LEAVE};
use quil_execution::global_intrinsic::prover_join::{ProverJoin, TYPE_PROVER_JOIN};
use quil_execution::global_intrinsic::prover_ops::{
    ProverConfirm, ProverReject, TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT, TYPE_PROVER_SENIORITY_MERGE,
    TYPE_SHARD_MERGE, TYPE_SHARD_SPLIT,
};
use quil_execution::canonical_cursor::{read_lp, read_u32, read_u64};
use quil_execution::message_envelope::CanonicalMessageBundle;
use quil_types::error::Result;
use tracing::info;

/// GLOBAL frames after its submission frame by which an operation not yet
/// seen is reported as not included.
pub const INCLUSION_WINDOW_FRAMES: u64 = 30;
/// Bound on tracked operations; a node publishes a few per epoch.
const MAX_TRACKED: usize = 64;
/// Bound on tracked presence reports, kept apart from the lifecycle
/// operations so a burst of reports (each up to about 45 KB) never evicts a
/// join or confirm, and their memory stays bounded.
const MAX_TRACKED_PRESENCE: usize = 8;
/// Filters named per line; longer lists (an epoch reconfirm) give the count.
const MAX_LOGGED_FILTERS: usize = 4;

struct Submitted {
    kind: &'static str,
    filters: Vec<Vec<u8>>,
    frame: u64,
    last_observed: u64,
    observed: u64,
}

#[derive(Default)]
pub struct OwnProverOps(Mutex<HashMap<Vec<u8>, Submitted>>);

/// The process-wide tracker the prover pipeline and the GLOBAL frame
/// receiver share.
pub fn tracker() -> &'static OwnProverOps {
    static TRACKER: OnceLock<OwnProverOps> = OnceLock::new();
    TRACKER.get_or_init(OwnProverOps::default)
}

const PRESENCE_REPORT: &str = "presence_report";

/// An op's kind and the filters it names. An op that does not decode has its
/// filters read without the decoders' limits, as far as its bytes go, so the
/// line refusing to publish it (`prover_pipeline::refuse_undecodable`) still
/// counts its seats. No such op is tracked: the pipeline refuses it before
/// publication, and the requests workers send through the master are frame
/// headers, handoffs and presence reports.
pub(crate) fn describe(inner: &[u8]) -> (&'static str, Vec<Vec<u8>>) {
    let Some(prefix) = inner.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])) else {
        return ("unknown", Vec::new());
    };
    let or_lenient = |kind, decoded: Result<Vec<Vec<u8>>>| match decoded {
        Ok(filters) => (kind, filters),
        Err(_) => (kind, lenient_filters(prefix, inner)),
    };
    match prefix {
        TYPE_PROVER_JOIN => or_lenient("join", ProverJoin::from_canonical_bytes(inner).map(|op| op.filters)),
        TYPE_PROVER_CONFIRM => or_lenient("confirm", ProverConfirm::from_canonical_bytes(inner)
            .map(|op| if op.filters.is_empty() { vec![op.filter] } else { op.filters })),
        TYPE_PROVER_REJECT => or_lenient("reject", ProverReject::from_canonical_bytes(inner)
            .map(|op| if op.filters.is_empty() { vec![op.filter] } else { op.filters })),
        TYPE_PROVER_LEAVE => or_lenient("leave", ProverLeave::from_canonical_bytes(inner).map(|op| op.filters)),
        TYPE_PRESENCE_REPORT => (PRESENCE_REPORT,
            PresenceReport::from_canonical_bytes(inner).map(|report| vec![report.filter]).unwrap_or_default()),
        TYPE_PROVER_SENIORITY_MERGE => ("seniority_merge", Vec::new()),
        TYPE_SHARD_SPLIT => ("shard_split", Vec::new()),
        TYPE_SHARD_MERGE => ("shard_merge", Vec::new()),
        _ => ("other", Vec::new()),
    }
}

/// The filters a join, leave, confirm or reject names, read without the
/// decoders' limits: as many as its bytes hold.
fn lenient_filters(prefix: u32, inner: &[u8]) -> Vec<Vec<u8>> {
    let mut filters = Vec::new();
    let mut cursor = 4;
    let _ = (|| -> Result<()> {
        if matches!(prefix, TYPE_PROVER_CONFIRM | TYPE_PROVER_REJECT) {
            // The deprecated single filter, the frame number, the signature.
            read_lp(inner, &mut cursor)?;
            read_u64(inner, &mut cursor)?;
            read_lp(inner, &mut cursor)?;
        }
        for _ in 0..read_u32(inner, &mut cursor)? {
            filters.push(read_lp(inner, &mut cursor)?);
        }
        Ok(())
    })();
    filters
}

fn filter_list(filters: &[Vec<u8>]) -> String {
    filters.iter().take(MAX_LOGGED_FILTERS).map(hex::encode).collect::<Vec<_>>().join(",")
}

impl OwnProverOps {
    /// Record an operation published at `frame` (the node's latest frame).
    pub fn submitted(&self, inner: &[u8], frame: u64) {
        let Ok(mut ops) = self.0.lock() else { return };
        let (kind, filters) = describe(inner);
        // Each class evicts only its own oldest entry.
        let presence = |op: &Submitted| op.kind == PRESENCE_REPORT;
        let (cap, same) = if kind == PRESENCE_REPORT { (MAX_TRACKED_PRESENCE, true) } else { (MAX_TRACKED, false) };
        if ops.values().filter(|op| presence(op) == same).count() >= cap {
            let oldest = ops.iter().filter(|(_, op)| presence(op) == same).min_by_key(|(_, op)| op.frame);
            if let Some(oldest) = oldest.map(|(key, _)| key.clone()) {
                ops.remove(&oldest);
            }
        }
        ops.insert(inner.to_vec(), Submitted { kind, filters, frame, last_observed: frame, observed: 0 });
    }

    /// Stop tracking an operation whose publication failed.
    pub fn withdraw(&self, inner: &[u8]) {
        if let Ok(mut ops) = self.0.lock() {
            ops.remove(inner);
        }
    }

    /// Match an authenticated GLOBAL frame's bundles.
    pub fn observe_frame(&self, frame_number: u64, bundles: &[quil_types::proto::global::MessageBundle]) {
        if self.0.lock().map_or(true, |ops| ops.is_empty()) {
            return;
        }
        let requests: Vec<Vec<u8>> = bundles
            .iter()
            .filter_map(|bundle| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle).ok())
            .filter_map(|bytes| CanonicalMessageBundle::from_canonical_bytes(&bytes).ok())
            .flat_map(|bundle| bundle.requests.into_iter().flatten().map(|request| request.inner_bytes))
            .collect();
        self.observe_requests(frame_number, &requests);
    }

    fn observe_requests(&self, frame_number: u64, requests: &[Vec<u8>]) {
        let Ok(mut ops) = self.0.lock() else { return };
        for request in requests {
            if let Some(op) = ops.remove(request) {
                info!(
                    kind = op.kind,
                    filter_count = op.filters.len(),
                    filters = %filter_list(&op.filters),
                    submitted_frame = op.frame,
                    included_frame = frame_number,
                    "own prover operation included in a GLOBAL frame"
                );
            }
        }
        ops.retain(|_, op| {
            if frame_number > op.last_observed {
                op.last_observed = frame_number;
                op.observed += 1;
            }
            if frame_number < op.frame + INCLUSION_WINDOW_FRAMES {
                return true;
            }
            info!(
                kind = op.kind,
                filter_count = op.filters.len(),
                filters = %filter_list(&op.filters),
                submitted_frame = op.frame,
                frames_received = op.observed,
                window_frames = INCLUSION_WINDOW_FRAMES,
                "own prover operation not included in the GLOBAL frames this node received"
            );
            false
        });
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.0.lock().map_or(0, |ops| ops.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each op kind has its own name, so the per-kind refusal warning of one
    /// does not hide another's.
    #[test]
    fn shard_splits_and_merges_are_named_apart() {
        use quil_execution::global_intrinsic::prover_ops::{ShardMerge, ShardSplit};
        let split = ShardSplit::default().to_canonical_bytes().unwrap();
        let merge = ShardMerge::default().to_canonical_bytes().unwrap();
        assert_eq!(describe(&split).0, "shard_split");
        assert_eq!(describe(&merge).0, "shard_merge");
        assert_eq!(describe(b"\xff\xff\xff\xff").0, "other");
    }

    #[test]
    fn an_included_operation_stops_being_tracked() {
        let ops = OwnProverOps::default();
        ops.submitted(b"join-a", 100);
        ops.submitted(b"join-b", 100);
        ops.observe_requests(101, &[b"other".to_vec(), b"join-a".to_vec()]);
        assert_eq!(ops.tracked(), 1, "only the included operation is resolved");
        ops.observe_requests(100 + INCLUSION_WINDOW_FRAMES - 1, &[]);
        assert_eq!(ops.tracked(), 1, "still inside its window");
        ops.observe_requests(100 + INCLUSION_WINDOW_FRAMES, &[]);
        assert_eq!(ops.tracked(), 0, "reported as not included once its window has passed");
    }

    /// Gossip and the archive poller can both deliver a frame; it counts
    /// once towards the frames received, in either order.
    #[test]
    fn a_frame_delivered_twice_counts_once() {
        let ops = OwnProverOps::default();
        ops.submitted(b"join", 100);
        for frame in [102, 101, 102, 103, 103] {
            ops.observe_requests(frame, &[]);
        }
        let observed = ops.0.lock().unwrap().get(b"join".as_slice()).map(|op| op.observed);
        assert_eq!(observed, Some(2), "frames 102 and 103; 101 arrived after 102");
        ops.observe_requests(101, &[b"join".to_vec()]);
        assert_eq!(ops.tracked(), 0, "a late copy of an earlier frame still resolves it");
    }

    #[test]
    fn a_presence_report_is_tracked_under_its_filter() {
        use quil_execution::global_intrinsic::{
            frame_header::FrameHeader,
            handoff::presence::{NotarizeVote, PresenceProposal},
        };
        let report = PresenceReport {
            session: [2; 32],
            filter: vec![0x21; 32],
            proposals: vec![PresenceProposal {
                header: FrameHeader { address: vec![0x21; 32], frame_number: 9, rank: 6, ..Default::default() },
                epoch: 3, view: 6, parent: 5, payload: [5; 32],
                votes: vec![NotarizeVote { signer: 1, signature: vec![7; quil_crypto::FALCON_SIGNATURE_LEN] }],
            }],
            nullifies: Vec::new(),
        };
        assert_eq!(describe(&report.to_canonical_bytes().unwrap()), ("presence_report", vec![vec![0x21; 32]]));
    }

    /// Presence reports have their own bound: a burst of them never evicts
    /// a lifecycle operation.
    #[test]
    fn presence_reports_never_evict_lifecycle_operations() {
        let ops = OwnProverOps::default();
        let mut join = TYPE_PROVER_JOIN.to_be_bytes().to_vec();
        join.push(1);
        ops.submitted(&join, 10);
        for n in 0..(2 * MAX_TRACKED_PRESENCE as u32) {
            let mut report = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
            report.extend_from_slice(&n.to_be_bytes());
            ops.submitted(&report, 11 + n as u64);
        }
        assert_eq!(ops.tracked(), 1 + MAX_TRACKED_PRESENCE);
        assert!(ops.0.lock().unwrap().contains_key(&join), "the join is still tracked");
    }

    #[test]
    fn a_withdrawn_operation_is_no_longer_tracked() {
        let ops = OwnProverOps::default();
        let mut report = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
        report.push(1);
        ops.submitted(&report, 10);
        ops.withdraw(&report);
        assert_eq!(ops.tracked(), 0);
    }

    #[test]
    fn tracking_stays_bounded() {
        let ops = OwnProverOps::default();
        for i in 0..(MAX_TRACKED as u64 + 5) {
            ops.submitted(&i.to_be_bytes(), i);
        }
        assert_eq!(ops.tracked(), MAX_TRACKED);
    }

    /// An op over the decoders' limits (a renewal of 103 seats in one
    /// confirm) is still described by the filters it names, which the line
    /// refusing to publish it counts.
    #[test]
    fn an_undecodable_op_is_described_by_the_filters_it_names() {
        use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
        let filters: Vec<Vec<u8>> = (0..103u8).map(|i| vec![i; 32]).collect();
        let confirm = ProverConfirm {
            frame_number: 9,
            public_key_signature_bls48581: Some(AddressedSignature { signature: vec![1; 666], address: vec![2; 32] }),
            filters: filters.clone(),
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(ProverConfirm::from_canonical_bytes(&confirm).is_err(), "over the decoder's limit");
        assert_eq!(describe(&confirm), ("confirm", filters.clone()));
        let reject = ProverReject { filters: filters.clone(), ..Default::default() }.to_canonical_bytes().unwrap();
        assert_eq!(describe(&reject), ("reject", filters.clone()));
        let leave = ProverLeave { filters: filters.clone(), ..Default::default() }.to_canonical_bytes().unwrap();
        assert_eq!(describe(&leave), ("leave", filters.clone()));
        let join = ProverJoin { filters: filters.clone(), ..Default::default() }.to_canonical_bytes().unwrap();
        assert_eq!(describe(&join), ("join", filters));
        let mut truncated = TYPE_PROVER_LEAVE.to_be_bytes().to_vec();
        truncated.extend_from_slice(&u32::MAX.to_be_bytes());
        truncated.extend_from_slice(&[0, 0, 0, 1, 7, 0, 0]);
        assert_eq!(describe(&truncated), ("leave", vec![vec![7]]), "as far as its bytes go");
    }

    #[test]
    fn a_seniority_merge_is_named() {
        let merge = quil_execution::global_intrinsic::prover_ops::ProverSeniorityMerge { frame_number: 9, ..Default::default() };
        assert_eq!(describe(&merge.to_canonical_bytes().unwrap()), ("seniority_merge", Vec::new()));
    }
}
