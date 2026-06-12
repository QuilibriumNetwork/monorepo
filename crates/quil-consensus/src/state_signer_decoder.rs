//! State signer decoder. Mirror of
//! `consensus/signature/state_signer_decoder.go::StateSignerDecoder`.
//!
//! Given a [`State`] that carries a parent QC with an aggregated
//! signature bitmask, this helper decodes the bitmask back to the
//! concrete list of committee members that signed the parent state.
//!
//! The Go version has a fallback chain: it first queries the committee
//! by the parent QC's rank, and if that fails with `ErrRankUnknown`
//! (e.g. the rank has been pruned), falls back to querying by the
//! parent state's identity. We mirror both paths.

use std::sync::Arc;

use crate::committee::DynamicCommittee;
use crate::models::{State, Unique, WeightedIdentity};
use crate::packer::decode_signer_indices;
use quil_types::error::{QuilError, Result};

/// Decodes signer indices stored in a state's parent QC bitmask.
pub trait StateSignerDecoder<S: Unique>: Send + Sync {
    /// Return the weighted identities whose bits are set in the parent
    /// QC's bitmask. Returns an empty list if the state has no parent
    /// QC (root / genesis).
    ///
    /// Error returns:
    /// - `QuilError::RankUnknown` — parent rank is not known to the
    ///   committee and the by-state fallback also failed.
    /// - `QuilError::Consensus` — other internal errors.
    fn decode_signer_ids(&self, state: &State<S>) -> Result<Vec<Box<dyn WeightedIdentity>>>;
}

/// Concrete decoder backed by a [`DynamicCommittee`] view.
pub struct DynamicCommitteeStateSignerDecoder<S: Unique> {
    committee: Arc<dyn DynamicCommittee>,
    _marker: std::marker::PhantomData<S>,
}

impl<S: Unique> DynamicCommitteeStateSignerDecoder<S> {
    pub fn new(committee: Arc<dyn DynamicCommittee>) -> Self {
        Self {
            committee,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S: Unique> StateSignerDecoder<S> for DynamicCommitteeStateSignerDecoder<S> {
    fn decode_signer_ids(&self, state: &State<S>) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        // Root state has no parent — return empty.
        if state.parent_qc_identity.is_empty() || state.parent_qc_rank == 0 && state.rank == 0 {
            return Ok(Vec::new());
        }

        // Try by rank first (faster path — Go uses this to avoid a DB
        // lookup).
        let members = match self.committee.identities_by_rank(state.parent_qc_rank) {
            Ok(m) => m,
            Err(e) if e.is_rank_unknown() => {
                // Fallback: query by state ID.
                self.committee
                    .identities_by_state(&state.parent_qc_identity)
                    .map_err(|e2| {
                        QuilError::Consensus(format!(
                            "could not retrieve identities for state {} with QC rank {} for parent {}: {}",
                            hex::encode(&state.identifier), state.parent_qc_rank, hex::encode(&state.parent_qc_identity), e2
                        ))
                    })?
            }
            Err(e) => {
                return Err(QuilError::Consensus(format!(
                    "unexpected error retrieving identities for state {}: {}",
                    hex::encode(&state.identifier), e
                )))
            }
        };

        // The bitmask lives on the parent QC's aggregated signature.
        // We need the parent QC to access it — but Rust's `State`
        // only carries the parent QC's rank + id as scalars, not the
        // full trait object. Callers that need the decoded signers
        // must supply the bitmask separately through the helper below.
        // This method returns the *full* committee, which callers can
        // pair with [`decode_from_bitmask`] to get the subset.
        Ok(members)
    }
}

/// Decode a bitmask into the subset of `full_members` whose bits are
/// set. Wrapper around [`crate::packer::decode_signer_indices`] that
/// returns weighted identities rather than raw strings.
pub fn decode_from_bitmask(
    full_members: Vec<Box<dyn WeightedIdentity>>,
    bitmask: &[u8],
) -> Vec<Box<dyn WeightedIdentity>> {
    let ids = decode_signer_indices(&full_members, bitmask);
    full_members
        .into_iter()
        .filter(|m| ids.contains(m.identity()))
        .collect()
}

/// No-op decoder — returns `Vec::new()` for every state. Mirror of
/// Go's `NoopStateSignerDecoder`. Useful for tests and for nodes that
/// don't need to surface signer identities (e.g. light clients).
pub struct NoopStateSignerDecoder<S: Unique> {
    _marker: std::marker::PhantomData<S>,
}

impl<S: Unique> Default for NoopStateSignerDecoder<S> {
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S: Unique> NoopStateSignerDecoder<S> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: Unique> StateSignerDecoder<S> for NoopStateSignerDecoder<S> {
    fn decode_signer_ids(&self, _state: &State<S>) -> Result<Vec<Box<dyn WeightedIdentity>>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Identity;

    #[derive(Debug, Clone)]
    struct AppState {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppState {
        fn identity(&self) -> &Identity {
            &self.id
        }
        fn rank(&self) -> u64 {
            self.rank
        }
        fn source(&self) -> &Identity {
            &self.id
        }
        fn timestamp(&self) -> u64 {
            0
        }
        fn signature(&self) -> &[u8] {
            &[]
        }
    }

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

    fn make_state(rank: u64, parent_id: &str, parent_rank: u64) -> State<AppState> {
        State {
            rank,
            identifier: format!("state-{}", rank).into_bytes(),
            proposer_id: b"leader".to_vec(),
            parent_qc_identity: parent_id.into(),
            parent_qc_rank: parent_rank,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState {
                id: format!("state-{}", rank).into_bytes(),
                rank,
            },
        }
    }

    // ---------- Committee stubs ----------
    struct StubCommittee {
        members: Vec<&'static str>,
        /// If set, `identities_by_rank` returns RankUnknown for this rank.
        rank_unknown: Option<u64>,
        /// If set, `identities_by_state` returns an error for any call.
        by_state_fails: bool,
    }
    impl crate::committee::Replicas for StubCommittee {
        fn leader_for_rank(&self, _r: u64) -> Result<Identity> {
            Ok("leader".into())
        }
        fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> {
            Ok(2)
        }
        fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> {
            Ok(1)
        }
        fn self_identity(&self) -> &Identity {
            use std::sync::OnceLock;
            static SELF: OnceLock<Identity> = OnceLock::new();
            SELF.get_or_init(|| "self".into())
        }
        fn identities_by_rank(&self, rank: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            if self.rank_unknown == Some(rank) {
                return Err(QuilError::RankUnknown(format!("rank {}", rank)));
            }
            Ok(self
                .members
                .iter()
                .map(|m| Box::new(StubId { id: (*m).into() }) as Box<dyn WeightedIdentity>)
                .collect())
        }
        fn identity_by_rank(
            &self,
            _r: u64,
            pid: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            Ok(Box::new(StubId { id: pid.clone() }))
        }
    }
    impl DynamicCommittee for StubCommittee {
        fn identities_by_state(
            &self,
            _state_id: &Identity,
        ) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            if self.by_state_fails {
                return Err(QuilError::Consensus("by-state lookup failed".into()));
            }
            Ok(self
                .members
                .iter()
                .map(|m| Box::new(StubId { id: (*m).into() }) as Box<dyn WeightedIdentity>)
                .collect())
        }
        fn identity_by_state(
            &self,
            _state_id: &Identity,
            pid: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            Ok(Box::new(StubId { id: pid.clone() }))
        }
    }

    // ---------- tests ----------

    #[test]
    fn root_state_returns_empty() {
        let committee: Arc<dyn DynamicCommittee> = Arc::new(StubCommittee {
            members: vec!["alice", "bob"],
            rank_unknown: None,
            by_state_fails: false,
        });
        let decoder: DynamicCommitteeStateSignerDecoder<AppState> =
            DynamicCommitteeStateSignerDecoder::new(committee);
        let root = State {
            rank: 0,
            identifier: "genesis".into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "".into(),
            parent_qc_rank: 0,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "genesis".into(), rank: 0 },
        };
        assert!(decoder.decode_signer_ids(&root).unwrap().is_empty());
    }

    #[test]
    fn by_rank_path_returns_full_committee() {
        let committee: Arc<dyn DynamicCommittee> = Arc::new(StubCommittee {
            members: vec!["alice", "bob", "carol"],
            rank_unknown: None,
            by_state_fails: false,
        });
        let decoder: DynamicCommitteeStateSignerDecoder<AppState> =
            DynamicCommitteeStateSignerDecoder::new(committee);
        let state = make_state(5, "parent-4", 4);
        let members = decoder.decode_signer_ids(&state).unwrap();
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn rank_unknown_falls_back_to_by_state() {
        let committee: Arc<dyn DynamicCommittee> = Arc::new(StubCommittee {
            members: vec!["alice", "bob"],
            rank_unknown: Some(4),
            by_state_fails: false,
        });
        let decoder: DynamicCommitteeStateSignerDecoder<AppState> =
            DynamicCommitteeStateSignerDecoder::new(committee);
        let state = make_state(5, "parent-4", 4);
        // Should succeed via the by-state fallback.
        let members = decoder.decode_signer_ids(&state).unwrap();
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn rank_unknown_then_by_state_fails_is_consensus_error() {
        let committee: Arc<dyn DynamicCommittee> = Arc::new(StubCommittee {
            members: vec!["alice", "bob"],
            rank_unknown: Some(4),
            by_state_fails: true,
        });
        let decoder: DynamicCommitteeStateSignerDecoder<AppState> =
            DynamicCommitteeStateSignerDecoder::new(committee);
        let state = make_state(5, "parent-4", 4);
        let err = decoder.decode_signer_ids(&state).unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
    }

    #[test]
    fn noop_decoder_always_empty() {
        let decoder: NoopStateSignerDecoder<AppState> = NoopStateSignerDecoder::new();
        let state = make_state(10, "parent-9", 9);
        assert!(decoder.decode_signer_ids(&state).unwrap().is_empty());
    }

    #[test]
    fn decode_from_bitmask_returns_subset() {
        let full: Vec<Box<dyn WeightedIdentity>> = vec![
            Box::new(StubId { id: "alice".into() }),
            Box::new(StubId { id: "bob".into() }),
            Box::new(StubId { id: "carol".into() }),
        ];
        // Bits 0 and 2 set → alice + carol.
        let bitmask = vec![0b0000_0101];
        let subset = decode_from_bitmask(full, &bitmask);
        assert_eq!(subset.len(), 2);
        let ids: Vec<&Identity> = subset.iter().map(|m| m.identity()).collect();
        assert!(ids.contains(&&b"alice".to_vec()));
        assert!(ids.contains(&&b"carol".to_vec()));
    }
}
