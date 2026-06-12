//! Signature-data packer. Mirror of
//! `consensus/signature/packer.go::ConsensusSigDataPacker`.
//!
//! The packer encodes the set of signers that contributed to a QC
//! into a compact bitmask over the full committee, plus the raw
//! aggregate signature bytes. Unpacking is the inverse operation.
//!
//! Bit layout: bit `i` is set iff the `i`-th member of the committee
//! at that rank contributed a signature. Bits are packed little-endian
//! within each byte (bit 0 is the lowest-order bit), matching Go's
//! `indices[i/8] |= 1 << (i%8)`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bitmask::{bit_is_set, set_bit};
use crate::committee::Replicas;
use crate::models::{Identity, WeightedIdentity};
use quil_types::error::{QuilError, Result};

/// Compact state signature data. Mirror of Go's
/// `consensus.StateSignatureData`.
pub struct StateSignatureData {
    pub signers: Vec<Box<dyn WeightedIdentity>>,
    pub signature: Vec<u8>,
}

/// Packs / unpacks [`StateSignatureData`] against a known committee.
pub trait Packer: Send + Sync {
    /// Serialize the signature data into a `(signer_indices, sig_bytes)`
    /// pair. The indices are a bitmask over the full committee at the
    /// given rank.
    fn pack(&self, rank: u64, sig: &StateSignatureData) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Deserialize previously-packed signature data. `signer_identities`
    /// is the decoded committee subset — the caller is expected to
    /// produce it by decoding the bitmask against the committee for the
    /// corresponding rank.
    fn unpack(
        &self,
        signer_identities: Vec<Box<dyn WeightedIdentity>>,
        sig_data: Vec<u8>,
    ) -> Result<StateSignatureData>;
}

/// Concrete packer backed by a [`Replicas`] committee view.
pub struct ConsensusSigDataPacker {
    committees: Arc<dyn Replicas>,
}

impl ConsensusSigDataPacker {
    pub fn new(committees: Arc<dyn Replicas>) -> Self {
        Self { committees }
    }
}

impl Packer for ConsensusSigDataPacker {
    fn pack(&self, rank: u64, sig: &StateSignatureData) -> Result<(Vec<u8>, Vec<u8>)> {
        let full_members = self
            .committees
            .identities_by_rank(rank)
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "could not find consensus committee for rank {}: {}",
                    rank, e
                ))
            })?;

        // Collect the signer set for O(1) membership checks.
        let sig_set: HashSet<Identity> =
            sig.signers.iter().map(|s| s.identity().clone()).collect();

        let indices_len = (full_members.len() + 7) / 8;
        let mut signer_indices = vec![0u8; indices_len];
        for (i, member) in full_members.iter().enumerate() {
            if sig_set.contains(member.identity()) {
                set_bit(&mut signer_indices, i);
            }
        }
        Ok((signer_indices, sig.signature.clone()))
    }

    fn unpack(
        &self,
        signer_identities: Vec<Box<dyn WeightedIdentity>>,
        sig_data: Vec<u8>,
    ) -> Result<StateSignatureData> {
        Ok(StateSignatureData {
            signers: signer_identities,
            signature: sig_data,
        })
    }
}

/// Decode a bitmask against a known full committee, returning the
/// subset of members whose bit is set. Helper for callers that want
/// to reconstruct [`StateSignatureData`] from raw indices.
///
/// Bit layout matches [`crate::bitmask::bit_is_set`] (little-endian
/// within each byte): member `i` is selected iff bit `i` is set in
/// `signer_indices`.
pub fn decode_signer_indices(
    full_members: &[Box<dyn WeightedIdentity>],
    signer_indices: &[u8],
) -> Vec<Identity> {
    let mut out = Vec::new();
    for (i, member) in full_members.iter().enumerate() {
        if bit_is_set(signer_indices, i) {
            out.push(member.identity().clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- stubs ----------
    #[derive(Debug, Clone)]
    struct StubId {
        id: Identity,
    }
    impl WeightedIdentity for StubId {
        fn public_key(&self) -> &[u8] {
            &[]
        }
        fn identity(&self) -> &Identity {
            &self.id
        }
        fn weight(&self) -> u64 {
            1
        }
    }

    struct StubReplicas {
        members: Vec<&'static str>,
    }
    impl Replicas for StubReplicas {
        fn leader_for_rank(&self, _rank: u64) -> Result<Identity> {
            Ok(self.members[0].into())
        }
        fn quorum_threshold_for_rank(&self, _rank: u64) -> Result<u64> {
            Ok((self.members.len() as u64 * 2).div_ceil(3))
        }
        fn timeout_threshold_for_rank(&self, _rank: u64) -> Result<u64> {
            Ok((self.members.len() as u64).div_ceil(3))
        }
        fn self_identity(&self) -> &'static Identity {
            use std::sync::OnceLock;
            static SELF: OnceLock<Identity> = OnceLock::new();
            SELF.get_or_init(|| "self".into())
        }
        fn identities_by_rank(
            &self,
            _rank: u64,
        ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(self
                .members
                .iter()
                .map(|m| Box::new(StubId { id: (*m).into() }) as Box<dyn WeightedIdentity>)
                .collect())
        }
        fn identity_by_rank(
            &self,
            _rank: u64,
            participant_id: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            Ok(Box::new(StubId {
                id: participant_id.clone(),
            }))
        }
    }

    fn stub_packer(members: Vec<&'static str>) -> ConsensusSigDataPacker {
        let committees: Arc<dyn Replicas> = Arc::new(StubReplicas { members });
        ConsensusSigDataPacker::new(committees)
    }

    fn signer(name: &str) -> Box<dyn WeightedIdentity> {
        Box::new(StubId { id: name.into() })
    }

    // ---------- tests ----------

    #[test]
    fn pack_sets_bits_for_members_in_subset() {
        let packer = stub_packer(vec!["alice", "bob", "carol", "dave"]);
        let sig = StateSignatureData {
            signers: vec![signer("alice"), signer("carol")],
            signature: b"agg-sig".to_vec(),
        };
        let (indices, sig_bytes) = packer.pack(5, &sig).unwrap();
        // 4 members → 1 byte; bit 0 (alice) + bit 2 (carol) = 0b00000101
        assert_eq!(indices, vec![0b0000_0101]);
        assert_eq!(sig_bytes, b"agg-sig");
    }

    #[test]
    fn pack_multiple_bytes_for_large_committee() {
        let packer =
            stub_packer(vec!["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"]);
        let sig = StateSignatureData {
            signers: vec![signer("s1"), signer("s8"), signer("s9")],
            signature: vec![],
        };
        let (indices, _) = packer.pack(0, &sig).unwrap();
        // 9 members → 2 bytes. s1 = bit 0 of byte 0, s8 = bit 7 of byte 0,
        // s9 = bit 0 of byte 1.
        assert_eq!(indices, vec![0b1000_0001, 0b0000_0001]);
    }

    #[test]
    fn pack_empty_signer_set_is_zeros() {
        let packer = stub_packer(vec!["alice", "bob"]);
        let sig = StateSignatureData {
            signers: vec![],
            signature: b"empty".to_vec(),
        };
        let (indices, sig_bytes) = packer.pack(0, &sig).unwrap();
        assert_eq!(indices, vec![0]);
        assert_eq!(sig_bytes, b"empty");
    }

    #[test]
    fn unpack_round_trip_preserves_data() {
        let packer = stub_packer(vec!["alice", "bob", "carol"]);
        let sig = StateSignatureData {
            signers: vec![signer("alice"), signer("bob")],
            signature: b"r".to_vec(),
        };
        let (indices, sig_bytes) = packer.pack(0, &sig).unwrap();
        // Decode the subset from the bitmask.
        let full = packer.committees.identities_by_rank(0).unwrap();
        let subset_ids = decode_signer_indices(&full, &indices);
        assert_eq!(subset_ids, vec![b"alice".to_vec(), b"bob".to_vec()]);
        // Reconstruct StateSignatureData through unpack.
        let subset: Vec<Box<dyn WeightedIdentity>> = subset_ids
            .into_iter()
            .map(|id| Box::new(StubId { id }) as Box<dyn WeightedIdentity>)
            .collect();
        let unpacked = packer.unpack(subset, sig_bytes.clone()).unwrap();
        assert_eq!(unpacked.signature, b"r");
        assert_eq!(unpacked.signers.len(), 2);
    }

    #[test]
    fn decode_signer_indices_handles_empty_committee() {
        let full: Vec<Box<dyn WeightedIdentity>> = vec![];
        let decoded = decode_signer_indices(&full, &[]);
        assert!(decoded.is_empty());
    }
}
