//! Whether this node's own prover operations reach a GLOBAL frame. A join,
//! confirm, reject or leave the archives drop before inclusion and one they
//! include but refuse at execution look the same to a regular node: neither
//! changes its registry, and it does not execute GLOBAL frames itself. Each
//! published operation is matched against the authenticated frames this node
//! receives, and one line says which frame included it, or that none of the
//! frames received within `INCLUSION_WINDOW_FRAMES` did.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use quil_execution::global_intrinsic::prover_filter_ops::{ProverLeave, TYPE_PROVER_LEAVE};
use quil_execution::global_intrinsic::prover_join::{ProverJoin, TYPE_PROVER_JOIN};
use quil_execution::global_intrinsic::prover_ops::{
    ProverConfirm, ProverReject, TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT,
};
use quil_execution::message_envelope::CanonicalMessageBundle;
use tracing::info;

/// GLOBAL frames after its submission frame by which an operation not yet
/// seen is reported as not included.
pub const INCLUSION_WINDOW_FRAMES: u64 = 30;
/// Bound on tracked operations; a node publishes a few per epoch.
const MAX_TRACKED: usize = 64;
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

fn describe(inner: &[u8]) -> (&'static str, Vec<Vec<u8>>) {
    let Some(prefix) = inner.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])) else {
        return ("unknown", Vec::new());
    };
    match prefix {
        TYPE_PROVER_JOIN => ("join", ProverJoin::from_canonical_bytes(inner).map(|op| op.filters).unwrap_or_default()),
        TYPE_PROVER_CONFIRM => ("confirm", ProverConfirm::from_canonical_bytes(inner)
            .map(|op| if op.filters.is_empty() { vec![op.filter] } else { op.filters }).unwrap_or_default()),
        TYPE_PROVER_REJECT => ("reject", ProverReject::from_canonical_bytes(inner)
            .map(|op| if op.filters.is_empty() { vec![op.filter] } else { op.filters }).unwrap_or_default()),
        TYPE_PROVER_LEAVE => ("leave", ProverLeave::from_canonical_bytes(inner).map(|op| op.filters).unwrap_or_default()),
        _ => ("other", Vec::new()),
    }
}

fn filter_list(filters: &[Vec<u8>]) -> String {
    filters.iter().take(MAX_LOGGED_FILTERS).map(hex::encode).collect::<Vec<_>>().join(",")
}

impl OwnProverOps {
    /// Record an operation published at `frame` (the node's latest frame).
    pub fn submitted(&self, inner: &[u8], frame: u64) {
        let Ok(mut ops) = self.0.lock() else { return };
        if ops.len() >= MAX_TRACKED {
            if let Some(oldest) = ops.iter().min_by_key(|(_, op)| op.frame).map(|(key, _)| key.clone()) {
                ops.remove(&oldest);
            }
        }
        let (kind, filters) = describe(inner);
        ops.insert(inner.to_vec(), Submitted { kind, filters, frame, last_observed: frame, observed: 0 });
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
    fn tracking_stays_bounded() {
        let ops = OwnProverOps::default();
        for i in 0..(MAX_TRACKED as u64 + 5) {
            ops.submitted(&i.to_be_bytes(), i);
        }
        assert_eq!(ops.tracked(), MAX_TRACKED);
    }
}
