//! Per-rank timeout aggregation for global consensus.
//!
//! Mirrors [`vote_aggregation`](crate::vote_aggregation) but for
//! `TimeoutState` messages. On reaching the partial-TC (>=1/3 weight)
//! or full-TC (>=2/3 weight) threshold for a rank, the processor fires
//! callbacks that forward into the HotStuff event loop via
//! `submit_partial_timeout_certificate` /
//! `submit_timeout_certificate`.
//!
//! Structurally simpler than the vote aggregator — no Caching/Verifying
//! state machine, because a timeout vote doesn't need to be matched
//! against a proposal first. The `TimeoutProcessor` itself handles
//! both the signature aggregation and the TC finalization.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info, warn};

use quil_consensus::event_loop::EventLoopHandle;
use quil_consensus::models::{TimeoutCertificate, TimeoutState, Unique};
use quil_consensus::signature_aggregator::{
    SignatureAggregator, TimeoutSignatureAggregator, TimeoutSignatureAggregatorImpl,
};
use quil_consensus::timeout_processor::{
    OnPartialTimeoutCertificateCreated, TimeoutProcessor,
};
use quil_consensus::committee::Replicas;
use quil_consensus::validator::Validator;
use quil_consensus::voting_provider::{OnTimeoutCertificateCreated, VotingProvider};
use quil_types::crypto::BlsConstructor;
use quil_types::error::Result;

use crate::bls_signature_aggregator::BlsSignatureAggregator;
use crate::bls_verifier::BlsConsensusVerifier;
use crate::committee::ProverRegistryCommittee;
use crate::consensus_types::{GlobalState, GlobalVote};
use crate::validator::ConsensusValidator;

/// Owns the per-rank timeout-processor map and the glue that turns
/// sufficient weighted timeout signatures into a `TimeoutCertificate`
/// that's submitted back to the HotStuff event loop.
pub struct TimeoutAggregation {
    committee: Arc<ProverRegistryCommittee>,
    voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
    validator: Arc<dyn Validator<GlobalState, GlobalVote>>,
    consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
    bls: Arc<dyn BlsConstructor>,
    timeout_domain: Vec<u8>,
    processors: Mutex<HashMap<u64, Arc<TimeoutProcessor<GlobalState, GlobalVote>>>>,
    min_active_rank: AtomicU64,
}

impl TimeoutAggregation {
    pub fn new(
        committee: Arc<ProverRegistryCommittee>,
        voting_provider: Arc<dyn VotingProvider<GlobalState, GlobalVote>>,
        consensus_handle: Arc<OnceLock<EventLoopHandle<GlobalState, GlobalVote>>>,
        bls: Arc<dyn BlsConstructor>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
    ) -> Self {
        // The validator needs a Verifier that can check both QCs
        // (signed with vote_domain) and TCs (signed with timeout_domain).
        // Pre-fix it used vote_domain for both, which silently broke
        // TC validation as soon as a real TC arrived.
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(bls.clone()));
        let verifier = Arc::new(BlsConsensusVerifier::new_with_timeout_domain(
            raw,
            vote_domain,
            timeout_domain.clone(),
        ));
        let committee_as_replicas: Arc<dyn Replicas> = committee.clone();
        let validator: Arc<dyn Validator<GlobalState, GlobalVote>> = Arc::new(
            ConsensusValidator::<GlobalState, GlobalVote>::new(
                committee_as_replicas,
                verifier,
            ),
        );
        Self {
            committee,
            voting_provider,
            validator,
            consensus_handle,
            bls,
            timeout_domain,
            processors: Mutex::new(HashMap::new()),
            min_active_rank: AtomicU64::new(0),
        }
    }

    /// Feed a reconstructed `TimeoutState` to its rank's processor.
    pub fn handle_timeout(&self, ts: TimeoutState<GlobalVote>) {
        let rank = ts.rank;
        let voter = hex::encode(ts.vote.identity());
        let qc_rank = ts.latest_quorum_certificate.rank();
        let min_active = self.min_active_rank.load(Ordering::Relaxed);
        if rank < min_active {
            info!(rank, min_active, voter = %voter, "dropping timeout below finalized rank");
            return;
        }
        info!(rank, qc_rank, voter = %voter, "ingesting timeout");

        // Capture the embedded prior-rank TC before `ts` is consumed by
        // the processor — used below to converge a split pacemaker.
        let prior_tc = ts.prior_rank_timeout_certificate.clone();

        let proc = match self.get_or_create(rank) {
            Ok(p) => p,
            Err(e) => {
                warn!(rank, error = %e, "timeout processor build failed");
                return;
            }
        };
        if let Err(e) = proc.process(ts) {
            // Surface rejections at info: a stuck chain usually means
            // every peer's timeout is being rejected for the same
            // reason (sig domain mismatch, identity not in registry,
            // etc.), and the only way to spot that without recompiling
            // for debug logs is to print it here.
            info!(rank, voter = %voter, error = %e, "timeout processor rejected timeout");
        }
        // Always log the running weight vs the full-TC threshold. When a
        // rank is stuck, this plateaus below the threshold — direct
        // evidence of a quorum/liveness shortfall (fewer than 2/3-by-
        // seniority of the committee online) rather than a logic bug.
        let (weight, threshold) = proc.weight_and_threshold();
        info!(
            rank,
            weight,
            threshold,
            quorum_met = weight >= threshold,
            "timeout quorum status"
        );

        // Pacemaker convergence: advance on the TC embedded in a peer's
        // timeout. Each node persists its own pacemaker rank, so on a
        // coordinated restart the committee can resume split across
        // adjacent ranks. Once split, NO new TC for the lower rank can
        // form (each rank holds < 2/3 of the voters), so a lagging node
        // can ONLY catch up by observing the TC that already carried the
        // leaders forward — which is embedded as `prior_rank_timeout_
        // certificate` in their timeouts (a non-consecutive timeout is
        // invalid without it). We validate it with the same timeout-
        // domain validator the processor uses, then submit it to the
        // event loop. Validation makes this safe (the reason an earlier
        // revision dropped embedded TCs was malformed-TC poisoning);
        // mirrors Go's pacemaker, which advances on any valid observed TC.
        if let Some(prior_tc) = prior_tc {
            if let Some(handle) = self.consensus_handle.get() {
                let tc_rank = prior_tc.rank();
                match self
                    .validator
                    .validate_timeout_certificate(prior_tc.as_ref())
                {
                    Ok(()) => {
                        debug!(tc_rank, "advancing pacemaker on embedded prior-rank TC");
                        handle.submit_timeout_certificate(prior_tc);
                    }
                    Err(e) => {
                        debug!(tc_rank, error = %e, "embedded prior-rank TC failed validation");
                    }
                }
            }
        }
    }

    pub fn advance_min_active_rank(&self, rank: u64) {
        let prev = self.min_active_rank.fetch_max(rank, Ordering::Relaxed);
        if rank <= prev {
            return;
        }
        let mut map = self.processors.lock().unwrap();
        map.retain(|r, _| *r >= rank);
    }

    fn get_or_create(
        &self,
        rank: u64,
    ) -> Result<Arc<TimeoutProcessor<GlobalState, GlobalVote>>> {
        // Fast path: already instantiated.
        {
            let map = self.processors.lock().unwrap();
            if let Some(p) = map.get(&rank) {
                return Ok(p.clone());
            }
        }

        // Slow path: build a fresh processor for this rank. This involves
        // a registry snapshot via `identities_by_rank`, so we keep the
        // lock released during construction to avoid blocking other
        // callers on a potentially-slow store read.
        let ids = self.committee.identities_by_rank(rank)?;
        let raw: Arc<dyn SignatureAggregator> =
            Arc::new(BlsSignatureAggregator::new(self.bls.clone()));
        let sig_agg: Arc<dyn TimeoutSignatureAggregator> = Arc::new(
            TimeoutSignatureAggregatorImpl::new(
                raw,
                Vec::new(), // global filter
                rank,
                ids,
                self.timeout_domain.clone(),
            )?,
        );

        let qc_threshold = self.committee.quorum_threshold_for_rank(rank)?;
        let timeout_threshold = self.committee.timeout_threshold_for_rank(rank)?;

        let on_partial = self.make_on_partial_tc_created();
        let on_full = self.make_on_tc_created();

        let proc = Arc::new(TimeoutProcessor::new(
            rank,
            self.validator.clone(),
            sig_agg,
            self.voting_provider.clone(),
            qc_threshold,
            timeout_threshold,
            on_partial,
            on_full,
        ));

        let mut map = self.processors.lock().unwrap();
        // Race: another caller may have inserted a processor for this
        // rank. Return that one instead of ours to keep a single
        // source-of-truth per rank.
        if let Some(existing) = map.get(&rank) {
            return Ok(existing.clone());
        }
        map.insert(rank, proc.clone());
        Ok(proc)
    }

    fn make_on_partial_tc_created(&self) -> OnPartialTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        Arc::new(move |partial| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    rank = partial.rank,
                    newest_qc_rank = partial.newest_quorum_certificate.rank(),
                    "submitting partial TC to event loop"
                );
                handle.submit_partial_timeout_certificate(partial);
            }
        })
    }

    fn make_on_tc_created(&self) -> OnTimeoutCertificateCreated {
        let handle_cell = self.consensus_handle.clone();
        Arc::new(move |tc: Arc<dyn TimeoutCertificate>| {
            if let Some(handle) = handle_cell.get() {
                info!(
                    rank = tc.rank(),
                    "submitting locally-aggregated TC to event loop"
                );
                handle.submit_timeout_certificate(tc);
            }
        })
    }
}

/// Convert a wire `TimeoutState` (plus its embedded QC/TC already in
/// trait-object form) into the typed `TimeoutState<GlobalVote>` the
/// processor accepts.
pub fn wire_timeout_to_typed(
    wire: crate::consensus_wire::TimeoutState,
) -> TimeoutState<GlobalVote> {
    let latest_qc = wire.latest_quorum_certificate.into_trait_object();
    let prior_tc = wire
        .prior_rank_timeout_certificate
        .map(|tc| tc.into_trait_object());
    let vote = crate::vote_aggregation::wire_vote_to_global_vote(wire.vote);
    TimeoutState {
        rank: vote.rank(),
        latest_quorum_certificate: latest_qc,
        prior_rank_timeout_certificate: prior_tc,
        vote,
        timeout_tick: wire.timeout_tick,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_consensus::models::Unique;

    fn sample_wire_vote(rank: u64) -> crate::consensus_wire::ProposalVote {
        crate::consensus_wire::ProposalVote {
            filter: Vec::new(),
            rank,
            frame_number: rank.saturating_sub(1),
            selector: vec![0xAAu8; 32],
            timestamp: 1_700_000_000,
            signature: vec![0xBBu8; 74],
            address: vec![0xCCu8; 32],
            openings: Vec::new(),
        }
    }

    fn sample_wire_timeout(rank: u64, with_prior_tc: bool) -> crate::consensus_wire::TimeoutState {
        let qc = crate::consensus_wire::QuorumCertificate::genesis(
            rank.saturating_sub(1),
            vec![0xDDu8; 32],
        );
        let prior_tc = if with_prior_tc {
            Some(crate::consensus_wire::TimeoutCertificate {
                filter: Vec::new(),
                rank: rank.saturating_sub(1),
                latest_ranks: Vec::new(),
                latest_quorum_certificate: Some(qc.clone()),
                timestamp: 0,
                aggregate_signature: crate::consensus_wire::AggregateSignature::empty(),
            })
        } else {
            None
        };
        crate::consensus_wire::TimeoutState {
            latest_quorum_certificate: qc,
            prior_rank_timeout_certificate: prior_tc,
            vote: sample_wire_vote(rank),
            timeout_tick: 99,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn wire_timeout_derives_rank_from_vote() {
        let typed = wire_timeout_to_typed(sample_wire_timeout(50, false));
        // The typed timeout's rank must come from the embedded vote.
        assert_eq!(typed.rank, 50);
        assert_eq!(typed.vote.rank(), 50);
        assert_eq!(typed.timeout_tick, 99);
    }

    #[test]
    fn wire_timeout_without_prior_tc_yields_none() {
        let typed = wire_timeout_to_typed(sample_wire_timeout(10, false));
        assert!(typed.prior_rank_timeout_certificate.is_none());
        // The latest QC trait object is always present (genesis QC has rank 0).
        assert_eq!(typed.latest_quorum_certificate.rank(), 0);
    }

    #[test]
    fn wire_timeout_with_prior_tc_is_carried_through() {
        let typed = wire_timeout_to_typed(sample_wire_timeout(20, true));
        let tc = typed
            .prior_rank_timeout_certificate
            .expect("prior TC should be present");
        assert_eq!(tc.rank(), 19);
    }

    #[test]
    fn wire_timeout_preserves_vote_identity_and_source() {
        let wire = sample_wire_timeout(7, false);
        let voter = wire.vote.address.clone();
        let proposal = wire.vote.selector.clone();
        let typed = wire_timeout_to_typed(wire);
        assert_eq!(typed.vote.identity(), &voter);
        assert_eq!(typed.vote.source(), &proposal);
    }
}
