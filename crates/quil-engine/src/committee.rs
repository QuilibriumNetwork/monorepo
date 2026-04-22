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

/// Default quorum threshold (2N/3 rounded up). Matches Go's
/// `consensus_committee.go` semantics.
fn quorum_threshold(total: u64) -> u64 {
    // `ceil(2N/3)` via integer math.
    (2 * total + 2) / 3
}

/// Default timeout threshold (N/3 rounded up). A replica can
/// contribute to a timeout certificate once >1/3 of the committee
/// has signaled.
fn timeout_threshold(total: u64) -> u64 {
    (total + 2) / 3
}

/// Encode a raw prover address as a lowercase hex `Identity` string.
pub fn address_to_identity(address: &[u8]) -> Identity {
    hex::encode(address)
}

/// Decode an `Identity` back to a raw 32-byte address. Returns
/// `QuilError::InvalidArgument` if the string isn't valid hex.
pub fn identity_to_address(id: &Identity) -> Result<Vec<u8>> {
    hex::decode(id).map_err(|e| {
        QuilError::InvalidArgument(format!("identity {} is not valid hex: {}", id, e))
    })
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
}

impl ProverRegistryCommittee {
    /// Construct a committee view for `filter`. `self_address` is the
    /// raw 32-byte prover address of the local node.
    pub fn new(
        registry: Arc<dyn ProverRegistry>,
        filter: Vec<u8>,
        self_address: &[u8],
    ) -> Self {
        Self {
            registry,
            filter,
            self_id: address_to_identity(self_address),
        }
    }

    /// Accessor: the filter this committee covers.
    pub fn filter(&self) -> &[u8] {
        &self.filter
    }

    /// List active provers under this committee's filter. Each
    /// entry becomes a [`ProverIdentity`] with `weight = seniority`
    /// (matching Quilibrium's stake-by-seniority model) and
    /// `public_key = prover.public_key`.
    fn active_identities(&self) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        let active = self.registry.get_active_provers(&self.filter)?;
        let out: Vec<Box<dyn WeightedIdentity>> = active
            .into_iter()
            .map(|p| {
                Box::new(ProverIdentity::new(&p.address, p.public_key, p.seniority.max(1)))
                    as Box<dyn WeightedIdentity>
            })
            .collect();
        Ok(out)
    }

    /// Total stake-weight across the active committee. Used by
    /// [`quorum_threshold_for_rank`] / [`timeout_threshold_for_rank`].
    fn total_weight(&self) -> Result<u64> {
        let active = self.registry.get_active_provers(&self.filter)?;
        Ok(active.iter().map(|p| p.seniority.max(1)).sum())
    }
}

impl Replicas for ProverRegistryCommittee {
    fn leader_for_rank(&self, rank: u64) -> Result<Identity> {
        // Quilibrium's leader selection uses the registry's
        // ordered-prover walk seeded by a hash input. We map `rank`
        // into a 32-byte seed via big-endian embedding + zero pad.
        let mut seed = [0u8; 32];
        seed[24..].copy_from_slice(&rank.to_be_bytes());
        let leader_address = self.registry.get_next_prover(&seed, &self.filter)?;
        if leader_address.is_empty() {
            return Err(QuilError::NotFound(format!(
                "no leader available for rank {}",
                rank
            )));
        }
        Ok(address_to_identity(&leader_address))
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
        match self.registry.get_prover_info(&address)? {
            Some(p) => Ok(Box::new(ProverIdentity::new(
                &p.address,
                p.public_key,
                p.seniority.max(1),
            ))),
            None => Err(QuilError::InvalidSigner(format!(
                "prover {} not in committee",
                participant_id
            ))),
        }
    }
}

impl DynamicCommittee for ProverRegistryCommittee {
    fn identities_by_state(
        &self,
        _state_id: &Identity,
    ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        // Dynamic committees can shift between ranks, but Quilibrium's
        // registry is rank-indexed; the committee membership for a
        // state is identical to the committee membership at that
        // state's rank. Since we don't carry rank information through
        // `state_id` alone, we fall back to the current-active set.
        self.active_identities()
    }

    fn identity_by_state(
        &self,
        _state_id: &Identity,
        participant_id: &Identity,
    ) -> Result<Box<dyn WeightedIdentity>> {
        // Same reasoning as `identities_by_state` — fall back to
        // the rank-based lookup.
        self.identity_by_rank(0, participant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{ProverInfo, ProverShardSummary, ProverStatus};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ---------- registry stub ----------
    struct StubRegistry {
        provers: Mutex<Vec<ProverInfo>>,
        /// Configurable leader returned by `get_next_prover` regardless
        /// of input seed (simpler than faking the full ring hash walk).
        next_leader: Mutex<Option<Vec<u8>>>,
    }

    impl StubRegistry {
        fn with(provers: Vec<ProverInfo>) -> Arc<dyn ProverRegistry> {
            Arc::new(Self {
                provers: Mutex::new(provers),
                next_leader: Mutex::new(None),
            })
        }
        fn with_leader(provers: Vec<ProverInfo>, leader: Vec<u8>) -> Arc<dyn ProverRegistry> {
            Arc::new(Self {
                provers: Mutex::new(provers),
                next_leader: Mutex::new(Some(leader)),
            })
        }
    }

    impl ProverRegistry for StubRegistry {
        fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>> {
            let guard = self.provers.lock().unwrap();
            Ok(guard.iter().find(|p| p.address == address).cloned())
        }
        fn get_next_prover(&self, _input: &[u8; 32], _filter: &[u8]) -> Result<Vec<u8>> {
            if let Some(addr) = self.next_leader.lock().unwrap().clone() {
                Ok(addr)
            } else {
                // Fall back to first prover in list.
                let guard = self.provers.lock().unwrap();
                Ok(guard
                    .first()
                    .map(|p| p.address.clone())
                    .unwrap_or_default())
            }
        }
        fn get_ordered_provers(&self, _input: &[u8; 32], _filter: &[u8]) -> Result<Vec<Vec<u8>>> {
            let guard = self.provers.lock().unwrap();
            Ok(guard.iter().map(|p| p.address.clone()).collect())
        }
        fn get_active_provers(&self, _filter: &[u8]) -> Result<Vec<ProverInfo>> {
            let guard = self.provers.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|p| p.status == ProverStatus::Active)
                .cloned()
                .collect())
        }
        fn get_prover_count(&self, _filter: &[u8]) -> Result<usize> {
            Ok(self.provers.lock().unwrap().len())
        }
        fn get_provers(&self, _filter: &[u8]) -> Result<Vec<ProverInfo>> {
            Ok(self.provers.lock().unwrap().clone())
        }
        fn get_provers_by_status(
            &self,
            _filter: &[u8],
            status: ProverStatus,
        ) -> Result<Vec<ProverInfo>> {
            let guard = self.provers.lock().unwrap();
            Ok(guard.iter().filter(|p| p.status == status).cloned().collect())
        }
        fn update_prover_activity(
            &self,
            _address: &[u8],
            _filter: &[u8],
            _frame_number: u64,
        ) -> Result<()> {
            Ok(())
        }
        fn refresh(&self) -> Result<()> { Ok(()) }
        fn get_all_active_app_shard_provers(&self) -> Result<Vec<ProverInfo>> {
            self.get_active_provers(&[])
        }
        fn get_prover_shard_summaries(&self) -> Result<Vec<ProverShardSummary>> {
            Ok(vec![])
        }
        fn prune_orphan_joins(&self, _frame_number: u64) -> Result<()> {
            Ok(())
        }
        fn evict_inactive_provers(
            &self,
            _frame_number: u64,
            _inactivity_threshold: u64,
            _shard_halt_durations: &HashMap<String, u64>,
        ) -> Result<Vec<Vec<u8>>> {
            Ok(vec![])
        }
        fn current_frame(&self) -> u64 {
            0
        }
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

    #[test]
    fn quorum_threshold_matches_go_ceil_2n_3() {
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(3), 2);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(6), 4);
        assert_eq!(quorum_threshold(9), 6);
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn timeout_threshold_matches_go_ceil_n_3() {
        assert_eq!(timeout_threshold(1), 1);
        assert_eq!(timeout_threshold(3), 1);
        assert_eq!(timeout_threshold(4), 2);
        assert_eq!(timeout_threshold(6), 2);
        assert_eq!(timeout_threshold(9), 3);
        assert_eq!(timeout_threshold(100), 34);
    }

    // ---------- identity encoding ----------

    #[test]
    fn address_to_identity_is_lowercase_hex() {
        let id = address_to_identity(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(id, "abcdef");
    }

    #[test]
    fn identity_to_address_round_trip() {
        let addr = vec![0xAA; 32];
        let id = address_to_identity(&addr);
        let decoded = identity_to_address(&id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn identity_to_address_rejects_invalid_hex() {
        let err = identity_to_address(&"not-hex".to_string()).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    // ---------- Replicas impl ----------

    fn make_committee(
        provers: Vec<ProverInfo>,
        self_addr: Vec<u8>,
    ) -> ProverRegistryCommittee {
        let registry = StubRegistry::with(provers);
        ProverRegistryCommittee::new(registry, b"test-filter".to_vec(), &self_addr)
    }

    #[test]
    fn committee_leader_for_rank_delegates_to_registry() {
        let provers = vec![make_prover(1, 10, 5), make_prover(2, 20, 3)];
        let registry = StubRegistry::with_leader(
            provers,
            vec![2; 32], // leader is prover 2
        );
        let committee = ProverRegistryCommittee::new(
            registry,
            b"f".to_vec(),
            &[1; 32],
        );
        let leader = committee.leader_for_rank(5).unwrap();
        assert_eq!(leader, address_to_identity(&[2; 32]));
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
        // Three provers with seniorities 3, 3, 3 → total 9 → quorum 6.
        let provers = vec![
            make_prover(1, 10, 3),
            make_prover(2, 11, 3),
            make_prover(3, 12, 3),
        ];
        let committee = make_committee(provers, vec![1; 32]);
        assert_eq!(committee.quorum_threshold_for_rank(0).unwrap(), 6);
        assert_eq!(committee.timeout_threshold_for_rank(0).unwrap(), 3);
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
    fn committee_zero_seniority_gets_weight_one() {
        // Seniority=0 is pinned to weight=1 so newly-joined provers
        // can still contribute to quorum.
        let committee = make_committee(vec![make_prover(1, 10, 0)], vec![1; 32]);
        let ids = committee.identities_by_rank(0).unwrap();
        assert_eq!(ids[0].weight(), 1);
        assert_eq!(committee.total_weight().unwrap(), 1);
    }

    // ---------- DynamicCommittee impl ----------

    #[test]
    fn dynamic_committee_identities_by_state_returns_active_set() {
        let committee = make_committee(
            vec![make_prover(1, 10, 1), make_prover(2, 11, 2)],
            vec![1; 32],
        );
        let ids = committee
            .identities_by_state(&"state-5".to_string())
            .unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn dynamic_committee_inactive_prover_excluded() {
        let mut inactive = make_prover(9, 20, 1);
        inactive.status = ProverStatus::Left;
        let committee = make_committee(
            vec![make_prover(1, 10, 1), inactive],
            vec![1; 32],
        );
        let ids = committee.identities_by_rank(0).unwrap();
        // Only the active prover should be in the committee.
        assert_eq!(ids.len(), 1);
    }
}
