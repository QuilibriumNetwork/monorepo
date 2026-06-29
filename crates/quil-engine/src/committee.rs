//! Committee adapter bridging [`quil_types::consensus::ProverRegistry`]
//! to [`quil_consensus::committee::Replicas`] /
//! [`quil_consensus::committee::DynamicCommittee`].
//!
//! The consensus layer models committees as an abstract
//! [`Replicas`] trait: leader selection, quorum/timeout thresholds,
//! and per-participant weight. In Quilibrium, this information lives
//! in the on-chain prover registry — the set of provers whose shard
//! allocations currently cover a particular filter are the "committee"
//! for that filter.
//!
//! [`ProverRegistryCommittee`] captures that mapping: a registry
//! handle, a filter, and this node's own prover address. It computes
//! thresholds from the current active-prover count and selects
//! leaders via the registry's rank-ordered walk.
//!
//! Identity convention: we encode prover addresses as **lowercase
//! hex strings**. This matches the consensus layer's
//! [`Identity`](quil_consensus::models::Identity) type (`String`)
//! while remaining reversible back to the 32-byte address.

use std::sync::Arc;

use quil_consensus::committee::{DynamicCommittee, Replicas};
use quil_consensus::models::{Identity, WeightedIdentity};
use quil_types::consensus::ProverRegistry;
use quil_types::error::{QuilError, Result};

/// Quorum threshold: integer-floor `(total * 2) / 3`. Byte-identical
/// to other implementations; a ceil variant would fork consensus on
/// any committee whose weight isn't divisible by 3.
fn quorum_threshold(total: u64) -> u64 {
    (total * 2) / 3
}

/// Timeout threshold: same `(total * 2) / 3`. A replica can
/// contribute to a timeout certificate once > 2/3 of the weight has
/// signalled.
fn timeout_threshold(total: u64) -> u64 {
    (total * 2) / 3
}

/// Convert a raw prover address into an `Identity` (raw bytes — same value).
pub fn address_to_identity(address: &[u8]) -> Identity {
    address.to_vec()
}

/// Identity bytes are the raw address.
pub fn identity_to_address(id: &Identity) -> Result<Vec<u8>> {
    Ok(id.clone())
}

/// Concrete weighted identity backed by an active prover entry.
#[derive(Debug, Clone)]
pub struct ProverIdentity {
    id: Identity,
    public_key: Vec<u8>,
    weight: u64,
}

impl ProverIdentity {
    pub fn new(address: &[u8], public_key: Vec<u8>, weight: u64) -> Self {
        Self {
            id: address_to_identity(address),
            public_key,
            weight,
        }
    }
}

impl WeightedIdentity for ProverIdentity {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn identity(&self) -> &Identity {
        &self.id
    }
    fn weight(&self) -> u64 {
        self.weight
    }
}

/// Committee adapter for a single filter / shard.
pub struct ProverRegistryCommittee {
    registry: Arc<dyn ProverRegistry>,
    filter: Vec<u8>,
    self_id: Identity,
    self_public_key: Vec<u8>,
}

impl ProverRegistryCommittee {
    /// Construct a committee view for `filter`. `self_public_key`
    /// is used to seed the local node into `active_identities()`
    /// with weight 0 if the registry hasn't yet observed its
    /// ProverConfirm; the real key is used so signatures still
    /// authenticate.
    pub fn new(
        registry: Arc<dyn ProverRegistry>,
        filter: Vec<u8>,
        self_address: &[u8],
        self_public_key: Vec<u8>,
    ) -> Self {
        Self {
            registry,
            filter,
            self_id: address_to_identity(self_address),
            self_public_key,
        }
    }

    /// Accessor: the filter this committee covers.
    pub fn filter(&self) -> &[u8] {
        &self.filter
    }

    /// Active provers under this committee's filter, in
    /// sorted-address order. Mirrors Go's
    /// `AppConsensusEngine.IdentitiesByRank`.
    fn active_identities(&self) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        let active = self.registry.get_active_provers(&self.filter)?;
        Ok(active
            .into_iter()
            .map(|p| {
                Box::new(ProverIdentity::new(&p.address, p.public_key, p.seniority))
                    as Box<dyn WeightedIdentity>
            })
            .collect())
    }

    fn total_weight(&self) -> Result<u64> {
        let active = self.registry.get_active_provers(&self.filter)?;
        Ok(active.iter().map(|p| p.seniority).sum())
    }
}

impl Replicas for ProverRegistryCommittee {
    fn leader_for_rank(&self, rank: u64) -> Result<Identity> {
        // Byte-exact mirror of Go's `ConsensusProtocol.LeaderForRank`
        // (`node/consensus/global/consensus_protocol.go:193`):
        //
        //   input  = poseidon.HashBytes(be8(rank))
        //   set    = GetActiveProvers(filter)   // sorted by address asc
        //   index  = input mod len(set)
        //   leader = set[index].Address
        //
        // Two properties this preserves that the previous
        // `get_next_prover(be8(rank))` walk did NOT:
        //  1. The rank is *hashed* (Poseidon), so consecutive ranks land
        //     on unrelated indices — leadership rotates every rank.
        //  2. Selection is `mod N` into the address-sorted active set,
        //     not "closest address to the seed". The old code seeded with
        //     the bare rank integer and took the nearest address, which is
        //     stable across ±1 — pinning leadership to one prover. A
        //     pinned leader that cannot propose (e.g. on a head it can't
        //     resolve) wedges the chain forever because no timeout ever
        //     rotates past it. Hashing + mod restores Go's per-rank
        //     rotation so a stuck leader is bypassed on the next rank.
        let input = quil_crypto::poseidon::hash_bytes_to_32(&rank.to_be_bytes())
            .map_err(|e| QuilError::Crypto(format!("leader_for_rank poseidon: {e}")))?;

        // Go's `getProversByStatusInternal` returns the active set sorted
        // by address ascending; replicate that ordering so `index` maps
        // to the same prover on every node.
        let mut active = self.registry.get_active_provers(&self.filter)?;
        if active.is_empty() {
            return Err(QuilError::NotFound(format!(
                "no active provers for leader at rank {}",
                rank
            )));
        }
        active.sort_by(|a, b| a.address.cmp(&b.address));

        // index = big-endian(input) mod N, computed via Horner so we need
        // no bignum dependency. N is the prover count (small), so each
        // step stays well within u64.
        let n = active.len() as u64;
        let mut acc: u64 = 0;
        for &b in input.iter() {
            acc = (acc * 256 + b as u64) % n;
        }
        Ok(address_to_identity(&active[acc as usize].address))
    }

    fn quorum_threshold_for_rank(&self, _rank: u64) -> Result<u64> {
        Ok(quorum_threshold(self.total_weight()?))
    }

    fn timeout_threshold_for_rank(&self, _rank: u64) -> Result<u64> {
        Ok(timeout_threshold(self.total_weight()?))
    }

    fn self_identity(&self) -> &Identity {
        &self.self_id
    }

    fn identities_by_rank(&self, _rank: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        self.active_identities()
    }

    fn identity_by_rank(
        &self,
        _rank: u64,
        participant_id: &Identity,
    ) -> Result<Box<dyn WeightedIdentity>> {
        let address = identity_to_address(participant_id)?;
        if let Some(p) = self.registry.get_prover_info(&address)? {
            return Ok(Box::new(ProverIdentity::new(
                &p.address,
                p.public_key,
                p.seniority,
            )));
        }
        if participant_id == &self.self_id && !self.self_public_key.is_empty() {
            return Ok(Box::new(ProverIdentity::new(
                &self.self_id,
                self.self_public_key.clone(),
                0,
            )));
        }
        Err(QuilError::InvalidSigner(format!(
            "prover {} not in committee",
            hex::encode(participant_id)
        )))
    }
}

impl DynamicCommittee for ProverRegistryCommittee {
    fn identities_by_state(
        &self,
        _state_id: &Identity,
    ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        self.active_identities()
    }

    fn identity_by_state(
        &self,
        _state_id: &Identity,
        participant_id: &Identity,
    ) -> Result<Box<dyn WeightedIdentity>> {
        self.identity_by_rank(0, participant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{ProverInfo, ProverStatus};

    use crate::test_support::TestProverRegistry;

    // Small helpers replacing the legacy `StubRegistry::with*` constructors;
    // `TestProverRegistry` is shared with worker_allocator/shard_info/lifecycle
    // tests so the trait impl stays in sync across the crate.
    struct StubRegistry;
    impl StubRegistry {
        fn with(provers: Vec<ProverInfo>) -> Arc<dyn ProverRegistry> {
            Arc::new(TestProverRegistry::with_provers(provers))
        }
    }

    /// Reference computation of Go's leader formula:
    /// `active_sorted_by_addr[ poseidon(be8(rank)) mod N ]`.
    fn expected_leader(provers: &[ProverInfo], rank: u64) -> Identity {
        let mut active: Vec<Vec<u8>> = provers
            .iter()
            .filter(|p| p.status == ProverStatus::Active)
            .map(|p| p.address.clone())
            .collect();
        active.sort();
        let hash = quil_crypto::poseidon::hash_bytes_to_32(&rank.to_be_bytes()).unwrap();
        let mut acc = 0u64;
        for &b in hash.iter() {
            acc = (acc * 256 + b as u64) % active.len() as u64;
        }
        address_to_identity(&active[acc as usize])
    }

    fn make_prover(addr_byte: u8, pk_byte: u8, seniority: u64) -> ProverInfo {
        ProverInfo {
            public_key: vec![pk_byte; 96], // BLS48-581 public keys are 96 bytes
            address: vec![addr_byte; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![],
            available_storage: 0,
            seniority,
            delegate_address: vec![],
        }
    }

    // ---------- threshold math ----------

    // Go uses integer floor division for both thresholds:
    // `(total * 2) / 3`. Interop requires byte-identical values.
    #[test]
    fn quorum_threshold_matches_go_floor_2n_3() {
        assert_eq!(quorum_threshold(1), 0);
        assert_eq!(quorum_threshold(3), 2);
        assert_eq!(quorum_threshold(4), 2);
        assert_eq!(quorum_threshold(6), 4);
        assert_eq!(quorum_threshold(9), 6);
        assert_eq!(quorum_threshold(10), 6);
        assert_eq!(quorum_threshold(100), 66);
    }

    #[test]
    fn timeout_threshold_matches_quorum_threshold() {
        // Go's `TimeoutThresholdForRank` is also `(total * 2) / 3`.
        for n in [1u64, 3, 4, 6, 9, 10, 100] {
            assert_eq!(timeout_threshold(n), quorum_threshold(n));
        }
    }

    // ---------- identity encoding ----------

    #[test]
    fn address_to_identity_is_raw_bytes() {
        let id = address_to_identity(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(id, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn identity_to_address_round_trip() {
        let addr = vec![0xAA; 32];
        let id = address_to_identity(&addr);
        let decoded = identity_to_address(&id).unwrap();
        assert_eq!(decoded, addr);
    }

    // ---------- Replicas impl ----------

    fn make_committee(
        provers: Vec<ProverInfo>,
        self_addr: Vec<u8>,
    ) -> ProverRegistryCommittee {
        let registry = StubRegistry::with(provers);
        ProverRegistryCommittee::new(registry, b"test-filter".to_vec(), &self_addr, Vec::new())
    }

    #[test]
    fn committee_leader_for_rank_matches_go_formula() {
        // Mirror of Go's `LeaderForRank`: hash the rank, index the
        // address-sorted active set by `mod N`.
        let provers = vec![
            make_prover(3, 30, 5),
            make_prover(1, 10, 3),
            make_prover(2, 20, 1),
        ];
        let registry = StubRegistry::with(provers.clone());
        let committee =
            ProverRegistryCommittee::new(registry, b"f".to_vec(), &[1; 32], Vec::new());
        for rank in [0u64, 1, 5, 42, 579_214, u64::MAX] {
            assert_eq!(
                committee.leader_for_rank(rank).unwrap(),
                expected_leader(&provers, rank),
                "leader mismatch at rank {rank}"
            );
        }
    }

    #[test]
    fn committee_leader_rotates_across_ranks() {
        // The previous bare-rank/nearest-address walk pinned leadership to
        // a single prover (the halt). The Go formula must rotate: over a
        // window of consecutive ranks we should see multiple distinct
        // leaders.
        let provers = vec![
            make_prover(1, 10, 1),
            make_prover(2, 20, 1),
            make_prover(3, 30, 1),
            make_prover(4, 40, 1),
        ];
        let committee = make_committee(provers, vec![1; 32]);
        let mut seen = std::collections::HashSet::new();
        for rank in 0..64u64 {
            seen.insert(committee.leader_for_rank(rank).unwrap());
        }
        assert!(
            seen.len() > 1,
            "leadership must rotate across ranks; got {} distinct leader(s)",
            seen.len()
        );
    }

    #[test]
    fn committee_leader_empty_registry_errors() {
        let committee = make_committee(vec![], vec![1; 32]);
        let err = committee.leader_for_rank(0).unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
    }

    #[test]
    fn committee_self_identity_matches_constructor_address() {
        let committee = make_committee(vec![make_prover(1, 10, 1)], vec![0xAA; 32]);
        let id = committee.self_identity();
        let expected = address_to_identity(&[0xAA; 32]);
        assert_eq!(id, &expected);
    }

    #[test]
    fn committee_quorum_threshold_uses_total_seniority() {
        // Three provers with seniorities 3, 3, 3 → total 9 → 2N/3 = 6.
        // Go uses the same `(total * 2) / 3` for both quorum and timeout.
        let provers = vec![
            make_prover(1, 10, 3),
            make_prover(2, 11, 3),
            make_prover(3, 12, 3),
        ];
        let committee = make_committee(provers, vec![1; 32]);
        assert_eq!(committee.quorum_threshold_for_rank(0).unwrap(), 6);
        assert_eq!(committee.timeout_threshold_for_rank(0).unwrap(), 6);
    }

    #[test]
    fn committee_identities_by_rank_returns_active_provers() {
        let provers = vec![
            make_prover(1, 10, 1),
            make_prover(2, 11, 2),
            make_prover(3, 12, 3),
        ];
        let committee = make_committee(provers, vec![1; 32]);
        let ids = committee.identities_by_rank(0).unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0].weight(), 1);
        assert_eq!(ids[1].weight(), 2);
        assert_eq!(ids[2].weight(), 3);
    }

    #[test]
    fn committee_identity_by_rank_finds_member() {
        let target = make_prover(0xAB, 10, 7);
        let committee = make_committee(vec![target.clone()], vec![1; 32]);
        let id = committee
            .identity_by_rank(0, &address_to_identity(&target.address))
            .unwrap();
        assert_eq!(id.weight(), 7);
        assert_eq!(id.identity(), &address_to_identity(&[0xAB; 32]));
    }

    #[test]
    fn committee_identity_by_rank_missing_is_invalid_signer() {
        let committee = make_committee(vec![make_prover(1, 10, 1)], vec![1; 32]);
        let err = committee
            .identity_by_rank(0, &address_to_identity(&[0xFF; 32]))
            .unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn committee_seniority_passes_through_to_weight() {
        // Matches Go's `ConsensusWeightedIdentity.Weight() → c.prover.Seniority`
        // (consensus_protocol.go:114-116) — no zero-pin. A prover with
        // seniority 0 has weight 0 and contributes 0 to total weight.
        let committee = make_committee(vec![make_prover(1, 10, 0)], vec![1; 32]);
        let ids = committee.identities_by_rank(0).unwrap();
        assert_eq!(ids[0].weight(), 0);
        assert_eq!(committee.total_weight().unwrap(), 0);
    }

    // ---------- DynamicCommittee impl ----------

    #[test]
    fn dynamic_committee_identities_by_state_returns_active_set() {
        let committee = make_committee(
            vec![make_prover(1, 10, 1), make_prover(2, 11, 2)],
            vec![1; 32],
        );
        let ids = committee
            .identities_by_state(&b"state-5".to_vec())
            .unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn dynamic_committee_inactive_prover_excluded() {
        let mut inactive = make_prover(9, 20, 1);
        inactive.status = ProverStatus::Leaving;
        let committee = make_committee(
            vec![make_prover(1, 10, 1), inactive],
            vec![1; 32],
        );
        let ids = committee.identities_by_rank(0).unwrap();
        // Only the active prover should be in the committee.
        assert_eq!(ids.len(), 1);
    }
}
