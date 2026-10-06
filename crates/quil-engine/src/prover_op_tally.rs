//! Prover lifecycle work each executed GLOBAL frame carries, counted in
//! filters by op and outcome. A new shard drew leaves off several healthy
//! shards on every regular node; this measures such a wave from the chain's
//! side. Leader-side refusals, which never reach a frame, are in the leader's
//! "dropped protocol-invalid messages" breakdown.
use quil_execution::global_engine::{peek_global_message_kind, MessageKindGlobal};
use quil_execution::global_intrinsic::{ProverConfirm, ProverJoin, ProverLeave, ProverReject};
use quil_execution::message_envelope::CanonicalMessageBundle;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProverOpTally {
    /// Op, filters applied, filters refused; in first-seen order.
    ops: Vec<(MessageKindGlobal, u64, u64)>,
}

impl ProverOpTally {
    /// Count the prover lifecycle ops in one canonical bundle. A bundle
    /// executes or fails as a whole.
    pub(crate) fn record(&mut self, bundle: &[u8], applied: bool) {
        let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(bundle) else {
            return;
        };
        for request in bundle.requests.iter().flatten() {
            let Some((kind, filters)) = prover_op_filters(&request.inner_bytes) else {
                continue;
            };
            let index = match self.ops.iter().position(|(op, _, _)| *op == kind) {
                Some(index) => index,
                None => {
                    self.ops.push((kind, 0, 0));
                    self.ops.len() - 1
                }
            };
            let (_, done, refused) = &mut self.ops[index];
            *if applied { done } else { refused } += filters;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(crate) fn log(&self, frame: u64) {
        if self.is_empty() {
            return;
        }
        let count = |kind: MessageKindGlobal| {
            self.ops
                .iter()
                .find(|(op, _, _)| *op == kind)
                .map_or((0, 0), |(_, done, refused)| (*done, *refused))
        };
        let (joins, joins_refused) = count(MessageKindGlobal::ProverJoin);
        let (leaves, leaves_refused) = count(MessageKindGlobal::ProverLeave);
        let (confirms, confirms_refused) = count(MessageKindGlobal::ProverConfirm);
        let (rejects, rejects_refused) = count(MessageKindGlobal::ProverReject);
        let (kicks, kicks_refused) = count(MessageKindGlobal::ProverKick);
        tracing::info!(
            frame,
            joins,
            joins_refused,
            leaves,
            leaves_refused,
            confirms,
            confirms_refused,
            rejects,
            rejects_refused,
            kicks,
            kicks_refused,
            "GLOBAL prover lifecycle filters",
        );
    }
}

/// A prover lifecycle op and the filters it names; a kick names one.
fn prover_op_filters(inner: &[u8]) -> Option<(MessageKindGlobal, u64)> {
    let kind = peek_global_message_kind(inner).ok()?;
    let filters = match kind {
        MessageKindGlobal::ProverJoin => ProverJoin::from_canonical_bytes(inner).ok()?.filters.len(),
        MessageKindGlobal::ProverLeave => ProverLeave::from_canonical_bytes(inner).ok()?.filters.len(),
        MessageKindGlobal::ProverConfirm => ProverConfirm::from_canonical_bytes(inner).ok()?.filters.len(),
        MessageKindGlobal::ProverReject => ProverReject::from_canonical_bytes(inner).ok()?.filters.len(),
        MessageKindGlobal::ProverKick => 1,
        _ => return None,
    };
    Some((kind, filters as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::message_envelope::CanonicalMessageRequest;

    fn bundle(ops: &[Vec<u8>]) -> Vec<u8> {
        CanonicalMessageBundle {
            requests: ops
                .iter()
                .map(|inner| {
                    Some(CanonicalMessageRequest {
                        inner_type_prefix: u32::from_be_bytes(inner[..4].try_into().unwrap()),
                        inner_bytes: inner.clone(),
                    })
                })
                .collect(),
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn prover_ops_are_counted_in_filters_by_outcome() {
        let leave = |n: u8| {
            ProverLeave { filters: (0..n).map(|i| vec![i; 32]).collect(), ..Default::default() }
                .to_canonical_bytes()
                .unwrap()
        };
        let confirm = ProverConfirm { filters: vec![vec![7; 32]], ..Default::default() }
            .to_canonical_bytes()
            .unwrap();
        let mut tally = ProverOpTally::default();
        assert!(tally.is_empty());
        tally.record(&bundle(&[leave(3)]), true);
        tally.record(&bundle(&[leave(2), confirm.clone()]), false);
        tally.record(&bundle(&[confirm]), true);
        tally.record(b"not a bundle", true);
        assert_eq!(
            tally.ops,
            vec![(MessageKindGlobal::ProverLeave, 3, 2), (MessageKindGlobal::ProverConfirm, 1, 1)],
        );
    }
}
