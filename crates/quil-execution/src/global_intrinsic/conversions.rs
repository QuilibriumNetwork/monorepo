//! Conversions between prost-generated global proto types and the
//! canonical-bytes types in this module. Same pattern as
//! `hypergraph_intrinsic/conversions.rs`.

use quil_types::proto::global as pb;
use quil_types::proto::keys as keys_pb;

use super::addressed_signature::AddressedSignature;
use super::prover_filter_ops::{ProverLeave, ProverPause, ProverResume};
use super::prover_join::ProverJoin;
use super::prover_ops::{
    ProverConfirm, ProverReject,
    ProverUpdate,
};
use super::seniority_merge::SeniorityMerge;
use super::frame_header::FrameHeader;
use super::sig_with_pop::SignatureWithPop;
use crate::hypergraph_intrinsic::canonical::{
    AggregateSignature as CanonicalAggregateSignature, Bls48581G2PublicKey,
};

// =====================================================================
// AddressedSignature ↔ Bls48581AddressedSignature
// =====================================================================

pub fn addressed_sig_from_proto(
    pb: &keys_pb::Bls48581AddressedSignature,
) -> AddressedSignature {
    AddressedSignature {
        signature: pb.signature.clone(),
        address: pb.address.clone(),
    }
}

pub fn addressed_sig_to_proto(
    s: &AddressedSignature,
) -> keys_pb::Bls48581AddressedSignature {
    keys_pb::Bls48581AddressedSignature {
        signature: s.signature.clone(),
        address: s.address.clone(),
    }
}

// =====================================================================
// SignatureWithPop ↔ Bls48581SignatureWithProofOfPossession
// =====================================================================

pub fn sig_with_pop_from_proto(
    pb: &keys_pb::Bls48581SignatureWithProofOfPossession,
) -> SignatureWithPop {
    SignatureWithPop {
        signature: pb.signature.clone(),
        public_key: pb.public_key.as_ref().map(|pk| pk.key_value.clone()),
        pop_signature: pb.pop_signature.clone(),
    }
}

pub fn sig_with_pop_to_proto(
    s: &SignatureWithPop,
) -> keys_pb::Bls48581SignatureWithProofOfPossession {
    keys_pb::Bls48581SignatureWithProofOfPossession {
        signature: s.signature.clone(),
        public_key: s.public_key.as_ref().map(|kv| keys_pb::Bls48581g2PublicKey {
            key_value: kv.clone(),
        }),
        pop_signature: s.pop_signature.clone(),
    }
}

// =====================================================================
// SeniorityMerge ↔ proto::SeniorityMerge
// =====================================================================

pub fn seniority_merge_from_proto(pb: &pb::SeniorityMerge) -> SeniorityMerge {
    SeniorityMerge {
        signature: pb.signature.clone(),
        key_type: pb.key_type,
        prover_public_key: pb.prover_public_key.clone(),
    }
}

pub fn seniority_merge_to_proto(s: &SeniorityMerge) -> pb::SeniorityMerge {
    pb::SeniorityMerge {
        signature: s.signature.clone(),
        key_type: s.key_type,
        prover_public_key: s.prover_public_key.clone(),
    }
}

// =====================================================================
// ProverJoin ↔ proto::ProverJoin
// =====================================================================

pub fn prover_join_from_proto(pb: &pb::ProverJoin) -> ProverJoin {
    ProverJoin {
        filters: pb.filters.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(sig_with_pop_from_proto),
        delegate_address: pb.delegate_address.clone(),
        merge_targets: pb
            .merge_targets
            .iter()
            .map(seniority_merge_from_proto)
            .collect(),
        proof: pb.proof.clone(),
    }
}

pub fn prover_join_to_proto(j: &ProverJoin) -> pb::ProverJoin {
    pb::ProverJoin {
        filters: j.filters.clone(),
        frame_number: j.frame_number,
        public_key_signature_bls48581: j
            .public_key_signature_bls48581
            .as_ref()
            .map(sig_with_pop_to_proto),
        delegate_address: j.delegate_address.clone(),
        merge_targets: j
            .merge_targets
            .iter()
            .map(seniority_merge_to_proto)
            .collect(),
        proof: j.proof.clone(),
    }
}

// =====================================================================
// ProverLeave/Pause/Resume ↔ proto variants
// =====================================================================

pub fn prover_leave_from_proto(pb: &pb::ProverLeave) -> ProverLeave {
    ProverLeave {
        filters: pb.filters.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn prover_leave_to_proto(l: &ProverLeave) -> pb::ProverLeave {
    pb::ProverLeave {
        filters: l.filters.clone(),
        frame_number: l.frame_number,
        public_key_signature_bls48581: l
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

pub fn prover_pause_from_proto(pb: &pb::ProverPause) -> ProverPause {
    ProverPause {
        filter: pb.filter.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn prover_pause_to_proto(p: &ProverPause) -> pb::ProverPause {
    pb::ProverPause {
        filter: p.filter.clone(),
        frame_number: p.frame_number,
        public_key_signature_bls48581: p
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

pub fn prover_resume_from_proto(pb: &pb::ProverResume) -> ProverResume {
    ProverResume {
        filter: pb.filter.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn prover_resume_to_proto(r: &ProverResume) -> pb::ProverResume {
    pb::ProverResume {
        filter: r.filter.clone(),
        frame_number: r.frame_number,
        public_key_signature_bls48581: r
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

// =====================================================================
// ProverConfirm/Reject ↔ proto
// =====================================================================

pub fn prover_confirm_from_proto(pb: &pb::ProverConfirm) -> ProverConfirm {
    ProverConfirm {
        filter: pb.filter.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
        filters: pb.filters.clone(),
    }
}

pub fn prover_confirm_to_proto(c: &ProverConfirm) -> pb::ProverConfirm {
    pb::ProverConfirm {
        filter: c.filter.clone(),
        frame_number: c.frame_number,
        public_key_signature_bls48581: c
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
        filters: c.filters.clone(),
    }
}

pub fn prover_reject_from_proto(pb: &pb::ProverReject) -> ProverReject {
    ProverReject {
        filter: pb.filter.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
        filters: pb.filters.clone(),
    }
}

pub fn prover_reject_to_proto(r: &ProverReject) -> pb::ProverReject {
    pb::ProverReject {
        filter: r.filter.clone(),
        frame_number: r.frame_number,
        public_key_signature_bls48581: r
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
        filters: r.filters.clone(),
    }
}

// =====================================================================
// ProverUpdate ↔ proto
// =====================================================================

pub fn prover_update_from_proto(pb: &pb::ProverUpdate) -> ProverUpdate {
    ProverUpdate {
        delegate_address: pb.delegate_address.clone(),
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn prover_update_to_proto(u: &ProverUpdate) -> pb::ProverUpdate {
    pb::ProverUpdate {
        delegate_address: u.delegate_address.clone(),
        public_key_signature_bls48581: u
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addr_sig() -> AddressedSignature {
        AddressedSignature {
            signature: vec![0xAAu8; 74],
            address: vec![0xBBu8; 32],
        }
    }

    fn sample_pb_addr_sig() -> keys_pb::Bls48581AddressedSignature {
        keys_pb::Bls48581AddressedSignature {
            signature: vec![0xAAu8; 74],
            address: vec![0xBBu8; 32],
        }
    }

    #[test]
    fn addressed_sig_round_trip() {
        let pb = sample_pb_addr_sig();
        let s = addressed_sig_from_proto(&pb);
        let back = addressed_sig_to_proto(&s);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_join_round_trip() {
        let pb = pb::ProverJoin {
            filters: vec![vec![0x11u8; 32]],
            frame_number: 42,
            public_key_signature_bls48581: Some(
                keys_pb::Bls48581SignatureWithProofOfPossession {
                    signature: vec![0xAAu8; 74],
                    public_key: Some(keys_pb::Bls48581g2PublicKey {
                        key_value: vec![0xBBu8; 585],
                    }),
                    pop_signature: vec![0xCCu8; 74],
                },
            ),
            delegate_address: vec![0xDDu8; 32],
            merge_targets: vec![pb::SeniorityMerge {
                signature: vec![0x11u8; 74],
                key_type: 2,
                prover_public_key: vec![0x22u8; 585],
            }],
            proof: vec![0xEEu8; 128],
        };
        let j = prover_join_from_proto(&pb);
        let back = prover_join_to_proto(&j);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_leave_round_trip() {
        let pb = pb::ProverLeave {
            filters: vec![vec![0x11u8; 32]],
            frame_number: 7,
            public_key_signature_bls48581: Some(sample_pb_addr_sig()),
        };
        let l = prover_leave_from_proto(&pb);
        let back = prover_leave_to_proto(&l);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_pause_round_trip() {
        let pb = pb::ProverPause {
            filter: vec![0x22u8; 16],
            frame_number: 100,
            public_key_signature_bls48581: Some(sample_pb_addr_sig()),
        };
        let p = prover_pause_from_proto(&pb);
        let back = prover_pause_to_proto(&p);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_resume_round_trip() {
        let pb = pb::ProverResume {
            filter: vec![0x33u8; 8],
            frame_number: 200,
            public_key_signature_bls48581: None,
        };
        let r = prover_resume_from_proto(&pb);
        let back = prover_resume_to_proto(&r);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_confirm_round_trip() {
        let pb = pb::ProverConfirm {
            filter: vec![0x44u8; 32],
            frame_number: 50,
            public_key_signature_bls48581: Some(sample_pb_addr_sig()),
            filters: vec![vec![0x55u8; 16], vec![0x66u8; 24]],
        };
        let c = prover_confirm_from_proto(&pb);
        let back = prover_confirm_to_proto(&c);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_reject_round_trip() {
        let pb = pb::ProverReject {
            filter: vec![],
            frame_number: 999,
            public_key_signature_bls48581: None,
            filters: vec![vec![0x77u8; 32]],
        };
        let r = prover_reject_from_proto(&pb);
        let back = prover_reject_to_proto(&r);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_update_round_trip() {
        let pb = pb::ProverUpdate {
            delegate_address: vec![0xAAu8; 32],
            public_key_signature_bls48581: Some(sample_pb_addr_sig()),
        };
        let u = prover_update_from_proto(&pb);
        let back = prover_update_to_proto(&u);
        assert_eq!(back, pb);
    }

    #[test]
    fn prover_join_full_pipeline_proto_to_canonical_to_proto() {
        let pb = pb::ProverJoin {
            filters: vec![vec![0x01u8; 32], vec![0x02u8; 48]],
            frame_number: 0xCAFE,
            public_key_signature_bls48581: Some(
                keys_pb::Bls48581SignatureWithProofOfPossession {
                    signature: vec![0xAAu8; 74],
                    public_key: None,
                    pop_signature: vec![0xBBu8; 74],
                },
            ),
            delegate_address: vec![0xDDu8; 32],
            merge_targets: vec![],
            proof: vec![0xEEu8; 64],
        };
        let j = prover_join_from_proto(&pb);
        let cb = j.to_canonical_bytes().unwrap();
        let j2 = ProverJoin::from_canonical_bytes(&cb).unwrap();
        let pb2 = prover_join_to_proto(&j2);
        assert_eq!(pb2, pb);
    }
}

// =====================================================================
// FrameHeader ↔ proto FrameHeader (Shard variant of MessageRequest)
// =====================================================================

/// Convert a proto FrameHeader (`Request::Shard` variant) to its
/// canonical-bytes counterpart. Used by the materializer when
/// re-serializing a bundle that contains shard-coverage proofs.
pub fn frame_header_from_proto(pb: &pb::FrameHeader) -> FrameHeader {
    let agg_bytes: Vec<u8> = pb
        .public_key_signature_bls48581
        .as_ref()
        .and_then(|sig_pb| {
            // Convert proto aggregate sig → canonical aggregate sig → bytes.
            let pk = sig_pb.public_key.as_ref().and_then(|p| {
                if p.key_value.is_empty() {
                    None
                } else {
                    Some(Bls48581G2PublicKey {
                        key_value: p.key_value.clone(),
                    })
                }
            });
            let canon = CanonicalAggregateSignature {
                signature: sig_pb.signature.clone(),
                public_key: pk,
                bitmask: sig_pb.bitmask.clone(),
            };
            canon.to_canonical_bytes().ok()
        })
        .unwrap_or_default();

    FrameHeader {
        address: pb.address.clone(),
        frame_number: pb.frame_number,
        rank: pb.rank,
        timestamp: pb.timestamp,
        difficulty: pb.difficulty,
        output: pb.output.clone(),
        parent_selector: pb.parent_selector.clone(),
        requests_root: pb.requests_root.clone(),
        state_roots: pb.state_roots.clone(),
        prover: pb.prover.clone(),
        fee_multiplier_vote: pb.fee_multiplier_vote as i64,
        public_key_signature_bls48581: agg_bytes,
    }
}

/// Convert a canonical FrameHeader to its proto representation. Used
/// by `consensus_wire::canonical_request_to_proto` when surfacing a
/// bundle's Shard variant for downstream materialization.
pub fn frame_header_to_proto(h: &FrameHeader) -> pb::FrameHeader {
    let sig_pb = if h.public_key_signature_bls48581.is_empty() {
        None
    } else {
        // Canonical sig bytes decode → split into signature/pubkey/bitmask
        // for the proto. If decoding fails, treat as no signature.
        match CanonicalAggregateSignature::from_canonical_bytes(
            &h.public_key_signature_bls48581,
        ) {
            Ok(canon) => Some(keys_pb::Bls48581AggregateSignature {
                signature: canon.signature,
                public_key: canon.public_key.map(|pk| {
                    keys_pb::Bls48581g2PublicKey {
                        key_value: pk.key_value,
                    }
                }),
                bitmask: canon.bitmask,
            }),
            Err(_) => None,
        }
    };
    pb::FrameHeader {
        address: h.address.clone(),
        frame_number: h.frame_number,
        rank: h.rank,
        timestamp: h.timestamp,
        difficulty: h.difficulty,
        output: h.output.clone(),
        parent_selector: h.parent_selector.clone(),
        requests_root: h.requests_root.clone(),
        state_roots: h.state_roots.clone(),
        prover: h.prover.clone(),
        fee_multiplier_vote: h.fee_multiplier_vote as u64,
        public_key_signature_bls48581: sig_pb,
    }
}
