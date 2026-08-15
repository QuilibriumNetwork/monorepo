//! Conversions between prost-generated global proto types and the
//! canonical-bytes types in this module. Same pattern as
//! `hypergraph_intrinsic/conversions.rs`.

use quil_types::proto::global as pb;
use quil_types::proto::keys as keys_pb;

use super::addressed_signature::AddressedSignature;
use super::prover_filter_ops::{ProverLeave, ProverPause, ProverResume};
use super::prover_join::ProverJoin;
use super::prover_ops::{
    ProverConfirm, ProverKick, ProverReject, ProverSeniorityMerge, ProverUpdate, ShardMerge,
    ShardSplit,
};
use super::consensus_types::AltShardUpdate;
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
// ProverSeniorityMerge ↔ proto::ProverSeniorityMerge (the OUTER request,
// 0x031A; its `merge_targets` are the inner SeniorityMerge records above).
// =====================================================================

pub fn prover_seniority_merge_from_proto(pb: &pb::ProverSeniorityMerge) -> ProverSeniorityMerge {
    ProverSeniorityMerge {
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
        merge_targets: pb.merge_targets.iter().map(seniority_merge_from_proto).collect(),
    }
}

pub fn prover_seniority_merge_to_proto(s: &ProverSeniorityMerge) -> pb::ProverSeniorityMerge {
    pb::ProverSeniorityMerge {
        frame_number: s.frame_number,
        public_key_signature_bls48581: s
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
        merge_targets: s.merge_targets.iter().map(seniority_merge_to_proto).collect(),
    }
}

// =====================================================================
// ProverKick ↔ proto::ProverKick (traversal_proof is a nested proto,
// stored raw-prost in the canonical form).
// =====================================================================

pub fn prover_kick_from_proto(pb: &pb::ProverKick) -> ProverKick {
    ProverKick {
        frame_number: pb.frame_number,
        kicked_prover_public_key: pb.kicked_prover_public_key.clone(),
        conflicting_frame_1: pb.conflicting_frame_1.clone(),
        conflicting_frame_2: pb.conflicting_frame_2.clone(),
        commitment: pb.commitment.clone(),
        proof: pb.proof.clone(),
        traversal_proof: pb
            .traversal_proof
            .as_ref()
            .map(prost::Message::encode_to_vec)
            .unwrap_or_default(),
    }
}

pub fn prover_kick_to_proto(k: &ProverKick) -> pb::ProverKick {
    pb::ProverKick {
        frame_number: k.frame_number,
        kicked_prover_public_key: k.kicked_prover_public_key.clone(),
        conflicting_frame_1: k.conflicting_frame_1.clone(),
        conflicting_frame_2: k.conflicting_frame_2.clone(),
        commitment: k.commitment.clone(),
        proof: k.proof.clone(),
        traversal_proof: if k.traversal_proof.is_empty() {
            None
        } else {
            prost::Message::decode(k.traversal_proof.as_slice()).ok()
        },
    }
}

// =====================================================================
// ShardSplit ↔ proto::ShardSplit
// =====================================================================

pub fn shard_split_from_proto(pb: &pb::ShardSplit) -> ShardSplit {
    ShardSplit {
        shard_address: pb.shard_address.clone(),
        proposed_shards: pb.proposed_shards.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn shard_split_to_proto(s: &ShardSplit) -> pb::ShardSplit {
    pb::ShardSplit {
        shard_address: s.shard_address.clone(),
        proposed_shards: s.proposed_shards.clone(),
        frame_number: s.frame_number,
        public_key_signature_bls48581: s
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

// =====================================================================
// ShardMerge ↔ proto::ShardMerge
// =====================================================================

pub fn shard_merge_from_proto(pb: &pb::ShardMerge) -> ShardMerge {
    ShardMerge {
        shard_addresses: pb.shard_addresses.clone(),
        parent_address: pb.parent_address.clone(),
        frame_number: pb.frame_number,
        public_key_signature_bls48581: pb
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_from_proto),
    }
}

pub fn shard_merge_to_proto(s: &ShardMerge) -> pb::ShardMerge {
    pb::ShardMerge {
        shard_addresses: s.shard_addresses.clone(),
        parent_address: s.parent_address.clone(),
        frame_number: s.frame_number,
        public_key_signature_bls48581: s
            .public_key_signature_bls48581
            .as_ref()
            .map(addressed_sig_to_proto),
    }
}

// =====================================================================
// AltShardUpdate ↔ proto::AltShardUpdate (flat 1:1 field copy)
// =====================================================================

pub fn alt_shard_update_from_proto(p: &pb::AltShardUpdate) -> AltShardUpdate {
    AltShardUpdate {
        public_key: p.public_key.clone(),
        frame_number: p.frame_number,
        vertex_adds_root: p.vertex_adds_root.clone(),
        vertex_removes_root: p.vertex_removes_root.clone(),
        hyperedge_adds_root: p.hyperedge_adds_root.clone(),
        hyperedge_removes_root: p.hyperedge_removes_root.clone(),
        signature: p.signature.clone(),
    }
}

pub fn alt_shard_update_to_proto(a: &AltShardUpdate) -> pb::AltShardUpdate {
    pb::AltShardUpdate {
        public_key: a.public_key.clone(),
        frame_number: a.frame_number,
        vertex_adds_root: a.vertex_adds_root.clone(),
        vertex_removes_root: a.vertex_removes_root.clone(),
        hyperedge_adds_root: a.hyperedge_adds_root.clone(),
        hyperedge_removes_root: a.hyperedge_removes_root.clone(),
        signature: a.signature.clone(),
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
        leaf_roots: pb.leaf_roots.iter().map(confirm_leaf_roots_from_proto).collect(),
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
        leaf_roots: c.leaf_roots.iter().map(confirm_leaf_roots_to_proto).collect(),
    }
}

fn confirm_leaf_roots_from_proto(
    pb: &pb::ConfirmLeafRoots,
) -> super::leaf_root_registration::ConfirmLeafRoots {
    super::leaf_root_registration::ConfirmLeafRoots {
        filter: pb.filter.clone(),
        entries: pb
            .entries
            .iter()
            .map(|e| super::leaf_root_registration::LeafRootEntry {
                prefix: e.prefix.clone(),
                leaf_root: e.leaf_root.clone(),
                num_blocks: e.num_blocks,
            })
            .collect(),
    }
}

fn confirm_leaf_roots_to_proto(
    c: &super::leaf_root_registration::ConfirmLeafRoots,
) -> pb::ConfirmLeafRoots {
    pb::ConfirmLeafRoots {
        filter: c.filter.clone(),
        entries: c
            .entries
            .iter()
            .map(|e| pb::LeafRootEntry {
                prefix: e.prefix.clone(),
                leaf_root: e.leaf_root.clone(),
                num_blocks: e.num_blocks,
            })
            .collect(),
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

    fn sample_pb_addr_sig() -> keys_pb::Bls48581AddressedSignature {
        keys_pb::Bls48581AddressedSignature {
            signature: vec![0xAAu8; 666],
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
                    signature: vec![0xAAu8; 666],
                    public_key: Some(keys_pb::Bls48581g2PublicKey {
                        key_value: vec![0xBBu8; 897],
                    }),
                    pop_signature: vec![0xCCu8; 666],
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
            leaf_roots: vec![],
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
                    signature: vec![0xAAu8; 666],
                    public_key: None,
                    pop_signature: vec![0xBBu8; 666],
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
            // CW finalization cert: a simplex-finalized shard frame
            // carries its magic-prefixed cert opaquely in the proto `signature`
            // field (pk/bitmask empty). Pass it through verbatim — it is not a
            // BLS aggregate and must NOT be re-wrapped as one.
            if sig_pb.public_key.is_none()
                && sig_pb
                    .signature
                    .starts_with(quil_cw_consensus::app_cert::CW_CERT_MAGIC)
            {
                return Some(sig_pb.signature.clone());
            }
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
        storage_attestation_root: pb.storage_attestation_root.clone(),
        global_frame_number: pb.global_frame_number,
        storage_attestation: pb.storage_attestation.clone(),
    }
}

/// Convert a canonical FrameHeader to its proto representation. Used
/// by `consensus_wire::canonical_request_to_proto` when surfacing a
/// bundle's Shard variant for downstream materialization.
pub fn frame_header_to_proto(h: &FrameHeader) -> pb::FrameHeader {
    let sig_pb = if h.public_key_signature_bls48581.is_empty() {
        None
    } else if h
        .public_key_signature_bls48581
        .starts_with(quil_cw_consensus::app_cert::CW_CERT_MAGIC)
    {
        // CW finalization cert: opaque blob, not a BLS aggregate.
        // Carry it raw in the proto `signature` field; pk/bitmask stay empty so
        // `frame_header_from_proto` recognizes and passes it through untouched.
        Some(keys_pb::Bls48581AggregateSignature {
            signature: h.public_key_signature_bls48581.clone(),
            public_key: None,
            bitmask: Vec::new(),
        })
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
        storage_attestation_root: h.storage_attestation_root.clone(),
        global_frame_number: h.global_frame_number,
        storage_attestation: h.storage_attestation.clone(),
    }
}
