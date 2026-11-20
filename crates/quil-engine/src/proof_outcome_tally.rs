//! Storage epoch proofs each materialized GLOBAL frame carries, counted by
//! outcome. A full proposal can carry many proofs while its frame records
//! few changed seat parts; this tells proofs that seat from those GLOBAL
//! executes to no effect (applied in this frame already) and from those it
//! refuses, by reason, with the proposal bytes each took.
use quil_execution::global_intrinsic::persistent_storage::capacity_message;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    refusal_kind, RefusalKind, StorageEpochProof,
};
use quil_types::proto::global::{message_request::Request, MessageBundle};

/// How one bundle's execution ended.
pub(crate) enum Outcome<'a> {
    /// It executed, changing this many seat parts (a seal or a settlement
    /// each).
    Executed { seat_parts: usize },
    /// It was refused, for this reason.
    Refused(&'a str),
}

/// Proofs, the seat parts they cover (a seal or a settlement each) and
/// their bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Count {
    proofs: u64,
    parts: u64,
    bytes: u64,
}

impl Count {
    fn add(&mut self, other: Count) {
        self.proofs += other.proofs;
        self.parts += other.parts;
        self.bytes += other.bytes;
    }
}

/// The longest refusal kept as the latest other reason.
const REASON_CHARS: usize = 160;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProofOutcomeTally {
    /// Executed and changed seat parts.
    seated: Count,
    /// Seat parts those changed.
    seat_parts: u64,
    /// Executed and changed nothing: applied in this frame already.
    no_effect: Count,
    duplicate: Count,
    late: Count,
    early: Count,
    invalid: Count,
    other: Count,
    other_reason: String,
    /// Persistent-sector capacity messages, which share the type.
    capacity: Count,
}

impl ProofOutcomeTally {
    /// Count the storage epoch proofs in one bundle of the frame. A bundle
    /// executes or fails as a whole. Reads the frame's own bundle: only a
    /// storage epoch proof is decoded, nothing else is copied.
    pub(crate) fn record(&mut self, bundle: &MessageBundle, outcome: Outcome<'_>) {
        let (mut proofs, mut capacity) = (Count::default(), Count::default());
        for request in &bundle.requests {
            let Some(Request::StorageEpochProof(bytes)) = &request.request else {
                continue;
            };
            let Ok(proof) = StorageEpochProof::from_canonical_bytes(bytes) else {
                continue;
            };
            let count = Count {
                proofs: 1,
                parts: proof
                    .seats
                    .iter()
                    .map(|seat| u64::from(seat.seals) + u64::from(seat.settles))
                    .sum(),
                bytes: bytes.len() as u64,
            };
            if capacity_message(&proof) {
                capacity.add(count);
            } else {
                proofs.add(count);
            }
        }
        self.capacity.add(capacity);
        if proofs.proofs == 0 {
            return;
        }
        match outcome {
            Outcome::Executed { seat_parts: 0 } => self.no_effect.add(proofs),
            Outcome::Executed { seat_parts } => {
                self.seated.add(proofs);
                self.seat_parts += seat_parts as u64;
            }
            Outcome::Refused(reason) => match refusal_kind(reason) {
                RefusalKind::Duplicate => self.duplicate.add(proofs),
                RefusalKind::Late => self.late.add(proofs),
                RefusalKind::Early => self.early.add(proofs),
                RefusalKind::Invalid => self.invalid.add(proofs),
                RefusalKind::Other => {
                    self.other.add(proofs);
                    self.other_reason.clear();
                    self.other_reason.extend(reason.chars().take(REASON_CHARS));
                }
            },
        }
    }

    /// Proofs that changed no seat: executed to no effect or refused.
    fn unseated(&self) -> Count {
        let mut all = Count::default();
        for count in [
            self.no_effect,
            self.duplicate,
            self.late,
            self.early,
            self.invalid,
            self.other,
        ] {
            all.add(count);
        }
        all
    }

    fn carried(&self) -> Count {
        let mut all = self.unseated();
        all.add(self.seated);
        all
    }

    /// Whether the frame carried no storage epoch proof at all.
    fn is_empty(&self) -> bool {
        self.carried().proofs == 0 && self.capacity.proofs == 0
    }

    /// One line per frame that carried storage epoch proofs.
    pub(crate) fn log(&self, frame: u64) {
        if self.is_empty() {
            return;
        }
        let carried = self.carried();
        tracing::info!(
            frame,
            epoch = quil_types::consensus::epoch_for_frame(frame),
            proofs = carried.proofs,
            parts = carried.parts,
            bytes = carried.bytes,
            unseated_bytes = self.unseated().bytes,
            seated = self.seated.proofs,
            seated_bytes = self.seated.bytes,
            seat_parts = self.seat_parts,
            no_effect = self.no_effect.proofs,
            no_effect_parts = self.no_effect.parts,
            no_effect_bytes = self.no_effect.bytes,
            duplicate = self.duplicate.proofs,
            duplicate_bytes = self.duplicate.bytes,
            late = self.late.proofs,
            late_bytes = self.late.bytes,
            early = self.early.proofs,
            early_bytes = self.early.bytes,
            invalid = self.invalid.proofs,
            invalid_bytes = self.invalid.bytes,
            other = self.other.proofs,
            other_bytes = self.other.bytes,
            other_reason = %self.other_reason,
            capacity = self.capacity.proofs,
            capacity_bytes = self.capacity.bytes,
            "storage epoch proofs in this GLOBAL frame by outcome: seated changed seat_parts; \
             no_effect was applied in this frame already; duplicate, late, early, invalid and \
             other were refused (other_reason: the latest); unseated_bytes took proposal room \
             and changed no seat",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::global_intrinsic::storage_epoch_proof::{
        SeatProof, REFUSED_DUPLICATE, REFUSED_EARLY, REFUSED_INVALID, REFUSED_LATE,
    };
    use quil_types::proto::global::MessageRequest;
    use sha3::{Digest, Sha3_256};

    fn proof_with(filter: impl Fn(u8) -> Vec<u8>, parts: u8, len: usize) -> Vec<u8> {
        StorageEpochProof {
            member: [1; 32],
            seats: (0..parts)
                .map(|i| SeatProof {
                    shard_filter: filter(i),
                    epoch: 1533,
                    settles: true,
                    ..Default::default()
                })
                .collect(),
            proof: vec![0; len],
        }
        .to_canonical_bytes()
    }

    fn proof(parts: u8, len: usize) -> Vec<u8> {
        proof_with(|i| vec![i; 35], parts, len)
    }

    /// A persistent-sector capacity message: one seat on the capacity
    /// filter.
    fn capacity(len: usize) -> Vec<u8> {
        proof_with(
            |_| Sha3_256::digest(b"quil/persistent-sector-capacity/v1").to_vec(),
            1,
            len,
        )
    }

    fn bundle(requests: &[Request]) -> MessageBundle {
        MessageBundle {
            requests: requests
                .iter()
                .map(|request| MessageRequest {
                    request: Some(request.clone()),
                    timestamp: 0,
                })
                .collect(),
            timestamp: 0,
        }
    }

    fn sep(bytes: &[u8]) -> Request {
        Request::StorageEpochProof(bytes.to_vec())
    }

    fn count(proofs: u64, parts: u64, bytes: usize) -> Count {
        Count {
            proofs,
            parts,
            bytes: bytes as u64,
        }
    }

    #[test]
    fn storage_epoch_proofs_are_counted_by_outcome() {
        let (two, one, cap) = (proof(2, 1000), proof(1, 500), capacity(300));
        assert!(capacity_message(
            &StorageEpochProof::from_canonical_bytes(&cap).unwrap()
        ));
        let other_op = Request::PresenceReport(vec![9; 700]);
        let mut tally = ProofOutcomeTally::default();
        assert!(tally.is_empty());
        // A proof beside another request and a capacity message: only the
        // proof is a seat proof.
        tally.record(
            &bundle(&[sep(&two), other_op.clone(), sep(&cap)]),
            Outcome::Executed { seat_parts: 3 },
        );
        tally.record(&bundle(&[sep(&one)]), Outcome::Executed { seat_parts: 0 });
        tally.record(
            &bundle(&[sep(&one), sep(&two)]),
            Outcome::Refused(&format!(
                "storage epoch proof: the seat's registration for epoch 1535 is sealed: \
                 {REFUSED_DUPLICATE}, sealed at frame 1105600"
            )),
        );
        tally.record(
            &bundle(&[sep(&one)]),
            Outcome::Refused(&format!(
                "storage epoch proof: epoch 1533 settles in frames [1104773, 1105493): \
                 {REFUSED_LATE}, frames past the deadline: 4"
            )),
        );
        tally.record(
            &bundle(&[sep(&one)]),
            Outcome::Refused(&format!(
                "storage epoch proof: epoch 1533 settles in frames [1104773, 1105493): \
                 {REFUSED_EARLY}"
            )),
        );
        tally.record(
            &bundle(&[sep(&two)]),
            Outcome::Refused(&format!(
                "storage epoch proof: {REFUSED_INVALID}: a bad opening"
            )),
        );
        tally.record(
            &bundle(&[sep(&one)]),
            Outcome::Refused(&format!("invalid fee cost: {}", "x".repeat(400))),
        );
        // No decodable storage epoch proof in it: nothing counted.
        tally.record(&bundle(&[other_op]), Outcome::Executed { seat_parts: 0 });
        tally.record(
            &bundle(&[sep(b"not a proof")]),
            Outcome::Refused("undecodable"),
        );

        assert_eq!(tally.seated, count(1, 2, two.len()), "seated count");
        assert_eq!(tally.seat_parts, 3);
        assert_eq!(tally.no_effect, count(1, 1, one.len()), "no_effect count");
        assert_eq!(
            tally.duplicate,
            count(2, 3, one.len() + two.len()),
            "duplicate count"
        );
        assert_eq!(tally.late, count(1, 1, one.len()));
        assert_eq!(tally.early, count(1, 1, one.len()));
        assert_eq!(tally.invalid, count(1, 2, two.len()));
        assert_eq!(tally.other, count(1, 1, one.len()));
        assert_eq!(tally.other_reason.chars().count(), REASON_CHARS);
        assert!(tally.other_reason.starts_with("invalid fee cost: xxx"));
        assert_eq!(tally.capacity, count(1, 1, cap.len()));
        assert_eq!(tally.unseated(), count(7, 9, 5 * one.len() + 2 * two.len()));
        assert_eq!(tally.carried(), count(8, 11, 5 * one.len() + 3 * two.len()));
        assert!(!tally.is_empty());
    }

    /// A seat that seals and settles is two seat parts, as GLOBAL counts the
    /// parts it changes.
    #[test]
    fn a_seat_that_seals_and_settles_is_two_parts() {
        let both = StorageEpochProof {
            member: [1; 32],
            seats: vec![SeatProof {
                shard_filter: vec![7; 35],
                epoch: 1533,
                seals: true,
                settles: true,
                ..Default::default()
            }],
            proof: vec![0; 200],
        }
        .to_canonical_bytes();
        let mut tally = ProofOutcomeTally::default();
        tally.record(&bundle(&[sep(&both)]), Outcome::Executed { seat_parts: 2 });
        assert_eq!(
            tally.seated,
            count(1, 2, both.len()),
            "parts_not_seat_parts"
        );
        assert_eq!(tally.seat_parts, 2);
    }

    /// Another operation's rejection, in a bundle that carries a proof, is
    /// not read as the proof failing to verify.
    #[test]
    fn another_operations_rejection_is_not_an_invalid_proof() {
        let one = proof(1, 500);
        let reason = "ProverLeaveConfirm rejected: shard 0a would land at 3 active provers";
        let mut tally = ProofOutcomeTally::default();
        tally.record(
            &bundle(&[sep(&one), Request::PresenceReport(vec![9; 10])]),
            Outcome::Refused(reason),
        );
        assert_eq!(tally.invalid, Count::default(), "rejection_read_as_invalid");
        assert_eq!(tally.other, count(1, 1, one.len()));
        assert_eq!(tally.other_reason, reason);
    }
}
