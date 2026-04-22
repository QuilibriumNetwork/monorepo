//! Consensus activation — assembles all components and starts the
//! HotStuff event loop when this node becomes an active prover.
//!
//! All component implementations are built and tested (199 consensus +
//! 206 engine tests). This module provides `activate_consensus()` which
//! wires them together and starts the event loop.

use std::sync::Arc;

use tracing::info;

use quil_consensus::models::{
    AggregatedSignature, Identity, QuorumCertificate, State, TimeoutCertificate,
};
use quil_consensus::signature_aggregator::TimeoutSignerInfo;
use quil_consensus::signer::VotingProviderSigner;
use quil_types::consensus::ProverRegistry;
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};

use crate::committee::ProverRegistryCommittee;
use crate::consensus_bootstrap::{spawn_global_consensus, ConsensusConfig};
use crate::consensus_glue::{
    GlobalConsumer, GlobalFinalizer, GlobalFollower, GlobalParticipantConsumer,
};
use crate::consensus_types::{
    build_genesis_certified_state, GlobalEventLoopHandle, GlobalState, GlobalVote,
};
use crate::leader_provider::GlobalLeaderProvider;
use crate::message_collector::MessageCollector;
use crate::voting_provider::{AddressDerivation, BlsVotingProvider, VotingProviderFactory};

/// Dependencies for starting the consensus event loop.
pub struct ConsensusActivationParams {
    pub prover_registry: Arc<dyn ProverRegistry>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub difficulty_adjuster: Arc<dyn quil_types::consensus::DifficultyAdjuster>,
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    pub message_collector: Arc<MessageCollector>,
    pub local_prover_address: Vec<u8>,
    pub local_bls_pubkey: Vec<u8>,
    pub bls_signer: Box<dyn quil_types::crypto::Signer>,
    pub genesis_frame: quil_types::proto::global::GlobalFrame,
    pub publisher: Option<Arc<dyn crate::consensus_glue::ConsensusPublisher>>,
    /// Optional callback invoked by the forks tree when a state is
    /// finalized. Used to prune per-rank aggregator state.
    pub on_finalized_state: Option<crate::consensus_glue::FinalizedStateHook>,
}

/// What `activate_consensus` produces: the event-loop handle plus
/// reusable pieces the caller needs to wire inbound aggregation.
pub struct ConsensusActivation {
    pub handle: GlobalEventLoopHandle,
    pub committee: Arc<ProverRegistryCommittee>,
    pub voting_provider: Arc<dyn quil_consensus::voting_provider::VotingProvider<GlobalState, GlobalVote>>,
    pub vote_domain: Vec<u8>,
    pub timeout_domain: Vec<u8>,
}

/// Start the consensus event loop.
pub fn activate_consensus(params: ConsensusActivationParams) -> Result<ConsensusActivation> {
    let config = ConsensusConfig::default();

    let leader_provider = Arc::new(GlobalLeaderProvider::new(
        params.prover_registry.clone(),
        params.frame_prover,
        params.difficulty_adjuster,
        params.clock_store,
        params.message_collector,
        params.local_prover_address.clone(),
        params.local_bls_pubkey.clone(),
    ));

    let committee = Arc::new(ProverRegistryCommittee::new(
        params.prover_registry,
        vec![0x00],
        &params.local_prover_address,
    ));

    // BLS voting provider
    let derive_address: AddressDerivation = Arc::new(|pubkey: &[u8]| {
        quil_crypto::poseidon::hash_bytes_to_32(pubkey)
            .unwrap_or_default()
            .to_vec()
    });
    let vote_domain =
        quil_crypto::poseidon::hash_bytes_to_32(b"GLOBAL_CONSENSUS_VOTE")
            .unwrap_or_default()
            .to_vec();
    let vote_domain_for_return = vote_domain.clone();
    let timeout_domain =
        quil_crypto::poseidon::hash_bytes_to_32(b"GLOBAL_CONSENSUS_TIMEOUT")
            .unwrap_or_default()
            .to_vec();
    let timeout_domain_for_return = timeout_domain.clone();

    let factory = Arc::new(GlobalVoteFactory);
    let voting_provider: Arc<dyn quil_consensus::voting_provider::VotingProvider<GlobalState, GlobalVote>> = Arc::new(
        BlsVotingProvider::<GlobalState, GlobalVote, GlobalVoteFactory>::new(
            params.bls_signer,
            vote_domain,
            timeout_domain,
            derive_address,
            factory,
        ),
    );
    let signer: Arc<dyn quil_consensus::signer::Signer<GlobalState, GlobalVote>> =
        Arc::new(VotingProviderSigner::new(voting_provider.clone()));

    let consumer: Arc<dyn quil_consensus::event_handler::Consumer<GlobalState, GlobalVote>> =
        match params.publisher {
            Some(p) => Arc::new(GlobalConsumer::with_publisher(p)),
            None => Arc::new(GlobalConsumer::new()),
        };
    let participant: Arc<
        dyn quil_consensus::pacemaker::ParticipantConsumer<GlobalState, GlobalVote>,
    > = Arc::new(GlobalParticipantConsumer);

    let store: Arc<dyn quil_consensus::event_handler::ConsensusStore<GlobalVote>> =
        Arc::new(MemConsensusStore::new());

    let components = spawn_global_consensus(
        config,
        signer,
        store,
        committee.clone() as Arc<dyn quil_consensus::committee::Replicas>,
        committee.clone() as Arc<dyn quil_consensus::committee::DynamicCommittee>,
        leader_provider as Arc<dyn quil_consensus::leader_provider::LeaderProvider<GlobalState>>,
        consumer,
        participant,
    )?;

    let certified_root = build_genesis_certified_state(&params.genesis_frame);
    info!(
        frame = certified_root.state.state.frame_number,
        rank = certified_root.state.rank,
        "bootstrapping consensus from frame"
    );

    let finalizer: Arc<dyn quil_consensus::forest::Finalizer> = Arc::new(GlobalFinalizer);
    let follower: Arc<dyn quil_consensus::forest::FollowerConsumer<GlobalState>> =
        match params.on_finalized_state {
            Some(hook) => Arc::new(GlobalFollower::with_on_finalized(hook)),
            None => Arc::new(GlobalFollower::new()),
        };

    let handle = components.start(certified_root, finalizer, follower)?;
    info!("HotStuff consensus event loop running");
    Ok(ConsensusActivation {
        handle,
        committee,
        voting_provider,
        vote_domain: vote_domain_for_return,
        timeout_domain: timeout_domain_for_return,
    })
}

// =====================================================================
// GlobalVoteFactory — creates votes from BLS signatures
// =====================================================================

pub struct GlobalVoteFactory;

impl VotingProviderFactory<GlobalState, GlobalVote> for GlobalVoteFactory {
    fn make_vote(
        &self,
        state_rank: u64,
        state_id: &Identity,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<GlobalVote> {
        Ok(GlobalVote::new(
            state_id.clone(),
            state_rank,
            hex::encode(voter_address),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
        ))
    }

    fn make_timeout_vote(
        &self,
        rank: u64,
        _newest_qc_rank: u64,
        signature: Vec<u8>,
        voter_address: &[u8],
    ) -> Result<GlobalVote> {
        Ok(GlobalVote::new(
            String::new(),
            rank,
            hex::encode(voter_address),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature,
            Vec::new(),
        ))
    }

    fn make_quorum_certificate(
        &self,
        state: &State<GlobalState>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn QuorumCertificate>> {
        Ok(Arc::new(SimpleQC {
            filter: Vec::new(),
            rank: state.rank,
            frame_number: state.state.frame_number,
            identity: state.identifier.clone(),
            timestamp: state.timestamp,
            sig: aggregated_sig,
        }))
    }

    fn make_timeout_certificate(
        &self,
        rank: u64,
        newest_qc: Arc<dyn QuorumCertificate>,
        signers: Vec<TimeoutSignerInfo>,
        aggregated_sig: Arc<dyn AggregatedSignature>,
    ) -> Result<Arc<dyn TimeoutCertificate>> {
        let latest_ranks: Vec<u64> = signers.iter().map(|s| s.newest_qc_rank).collect();
        Ok(Arc::new(SimpleTC {
            filter: Vec::new(),
            rank,
            latest_ranks,
            latest_qc: newest_qc,
            sig: aggregated_sig,
        }))
    }
}

// =====================================================================
// Simple QC/TC implementations for the factory
// =====================================================================

#[derive(Debug)]
struct SimpleQC {
    filter: Vec<u8>,
    rank: u64,
    frame_number: u64,
    identity: Identity,
    timestamp: u64,
    sig: Arc<dyn AggregatedSignature>,
}

impl QuorumCertificate for SimpleQC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { self.frame_number }
    fn identity(&self) -> &Identity { &self.identity }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.sig.as_ref() }
    fn equals(&self, other: &dyn QuorumCertificate) -> bool {
        self.rank == other.rank() && self.identity == *other.identity()
    }
}

#[derive(Debug)]
struct SimpleTC {
    filter: Vec<u8>,
    rank: u64,
    latest_ranks: Vec<u64>,
    latest_qc: Arc<dyn QuorumCertificate>,
    sig: Arc<dyn AggregatedSignature>,
}

impl TimeoutCertificate for SimpleTC {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
    fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { self.latest_qc.as_ref() }
    fn aggregated_signature(&self) -> &dyn AggregatedSignature { self.sig.as_ref() }
    fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
        self.rank == other.rank()
    }
}

// =====================================================================
// In-memory consensus store
// =====================================================================

use std::sync::Mutex;

struct MemConsensusStore {
    consensus: Mutex<Option<quil_consensus::models::ConsensusState<GlobalVote>>>,
    liveness: Mutex<Option<quil_consensus::models::LivenessState>>,
}

impl MemConsensusStore {
    fn new() -> Self {
        Self {
            consensus: Mutex::new(None),
            liveness: Mutex::new(None),
        }
    }
}

impl quil_consensus::event_handler::ConsensusStore<GlobalVote> for MemConsensusStore {
    fn get_consensus_state(
        &self,
        _filter: &[u8],
    ) -> Result<quil_consensus::models::ConsensusState<GlobalVote>> {
        self.consensus
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| QuilError::NotFound("no consensus state".into()))
    }

    fn put_consensus_state(
        &self,
        state: &quil_consensus::models::ConsensusState<GlobalVote>,
    ) -> Result<()> {
        *self.consensus.lock().unwrap() = Some(state.clone());
        Ok(())
    }

    fn get_liveness_state(
        &self,
        _filter: &[u8],
    ) -> Result<quil_consensus::models::LivenessState> {
        self.liveness
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| QuilError::NotFound("no liveness state".into()))
    }

    fn put_liveness_state(
        &self,
        state: &quil_consensus::models::LivenessState,
    ) -> Result<()> {
        *self.liveness.lock().unwrap() = Some(state.clone());
        Ok(())
    }
}
