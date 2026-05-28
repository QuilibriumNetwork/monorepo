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
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
    pub genesis_frame: quil_types::proto::global::GlobalFrame,
    pub publisher: Option<Arc<dyn crate::consensus_glue::ConsensusPublisher>>,
    /// Optional callback invoked by the forks tree when a state is
    /// finalized. Used to prune per-rank aggregator state.
    pub on_finalized_state: Option<crate::consensus_glue::FinalizedStateHook>,
    /// Hook invoked when a state is added to the forks tree (before
    /// finalization). The wired callback writes the corresponding
    /// `GlobalFrame` to the clock store as a candidate so the leader
    /// can chain rank+1 proposals on top of its own as-yet-unfinalized
    /// state.
    pub on_incorporated_state: Option<crate::consensus_glue::IncorporatedStateHook>,
    /// Hook fired when a QC is observed (received over the wire or
    /// constructed locally). The wired callback persists the QC to
    /// the clock store so `prove_next_state` for rank+1 can resolve
    /// the latest-QC frame_number/identity.
    pub on_qc_observed: Option<crate::consensus_glue::QcObservedHook>,
    /// Override the consensus configuration. Production callers
    /// leave this at `None` to use the default 45s startup delay +
    /// 10s proposal duration. Integration tests set
    /// `startup_delay: Duration::ZERO` so the event loop runs
    /// immediately.
    pub config_override: Option<ConsensusConfig>,
    /// Override the genesis quorum certificate seeded into the
    /// liveness store. Production passes `None` and accepts the
    /// default empty-signature genesis (the happy path embeds it
    /// but never re-verifies). Integration tests that drive the
    /// loop into timeout/recovery paths need a real BLS-aggregated
    /// signature here — otherwise `BlsConsensusVerifier::verify_quorum_certificate`
    /// rejects the embedded genesis QC and the chain stalls.
    pub genesis_qc_override:
        Option<crate::consensus_wire::QuorumCertificate>,
    /// Backing KV store for persistent consensus + liveness state.
    /// `None` falls back to an in-memory store (tests, ad-hoc
    /// bootstraps); production wires this to the node's RocksDB
    /// so safety / liveness state survives restarts. Without
    /// persistence, a node that restarts after a crash forgets
    /// `finalized_rank` and could vote for a conflicting QC —
    /// a real safety hazard, not just a perf concern.
    pub kv_db: Option<Arc<dyn quil_types::store::KvDb>>,
}

/// What `activate_consensus` produces: the event-loop handle plus
/// reusable pieces the caller needs to wire inbound aggregation.
///
/// **Important**: `run_future` MUST be scheduled on a supervised task.
/// Dropping it without driving it leaves the consensus loop unstarted;
/// calling `tokio::spawn` directly buries panics. Register it with the
/// supervisor (via `sup.spawn` or `DetachedSpawner::detach`) so a panic
/// surfaces as `JoinError` and shuts the node down cleanly.
pub struct ConsensusActivation {
    pub handle: GlobalEventLoopHandle,
    pub committee: Arc<ProverRegistryCommittee>,
    pub voting_provider: Arc<dyn quil_consensus::voting_provider::VotingProvider<GlobalState, GlobalVote>>,
    pub vote_domain: Vec<u8>,
    pub timeout_domain: Vec<u8>,
    pub run_future: std::pin::Pin<
        Box<dyn std::future::Future<Output = quil_types::error::Result<()>> + Send + 'static>,
    >,
}

/// Start the consensus event loop.
pub fn activate_consensus(params: ConsensusActivationParams) -> Result<ConsensusActivation> {
    let config = params.config_override.clone().unwrap_or_default();

    // The bls_signer is consumed: leader_provider needs it to sign the
    // (challenge||output) payload inside ProveGlobalFrameHeader. Convert
    // the Box<dyn Signer> into Arc<dyn Signer> so it can be shared.
    let signer: Arc<dyn quil_types::crypto::Signer> = Arc::from(params.bls_signer);

    let leader_provider = Arc::new(GlobalLeaderProvider::new(
        params.prover_registry.clone(),
        params.frame_prover,
        params.difficulty_adjuster,
        params.clock_store,
        params.message_collector,
        params.local_prover_address.clone(),
        params.local_bls_pubkey.clone(),
        signer.clone(),
        params.inclusion_prover,
    ));

    // Global consensus uses the empty filter — `SharedProverRegistry`
    // routes `get_ordered_provers([])` / `get_next_prover([])` through
    // the global cache (every distinct prover address). Passing
    // `vec![0x00]` here would route through the per-filter cache,
    // which is keyed by 32-byte allocation `confirmation_filter` and
    // has no entry for that specific 1-byte filter — leader election
    // then errors with "shard trie empty" and the event loop exits.
    let committee = Arc::new(ProverRegistryCommittee::new(
        params.prover_registry,
        Vec::new(),
        &params.local_prover_address,
        params.local_bls_pubkey.clone(),
    ));

    // BLS voting provider
    let derive_address: AddressDerivation = Arc::new(|pubkey: &[u8]| {
        quil_crypto::poseidon::hash_bytes_to_32(pubkey)
            .unwrap_or_default()
            .to_vec()
    });
    // Domain separation tags — MUST match Go byte-for-byte so QCs and
    // TCs produced by either side cross-verify. Go uses literal ASCII
    // (`node/consensus/global/consensus_voting_provider.go:111,155`):
    //   - vote:    `[]byte("global")`
    //   - timeout: `[]byte("globaltimeout")`
    // Earlier we used poseidon hashes of `"GLOBAL_CONSENSUS_VOTE"` /
    // `"GLOBAL_CONSENSUS_TIMEOUT"`; that's domain-correct between two
    // Rust nodes but unable to verify any QC formed by Go (which is
    // exactly what a migrated store ships — the persisted rank-N QC
    // was signed by Go before migration, and every restart embeds it
    // as `latest_quorum_certificate` in every outgoing timeout, so
    // every node rejects every timeout and the chain stalls).
    let vote_domain = b"global".to_vec();
    let vote_domain_for_return = vote_domain.clone();
    let timeout_domain = b"globaltimeout".to_vec();
    let timeout_domain_for_return = timeout_domain.clone();

    let factory = Arc::new(GlobalVoteFactory);
    let voting_provider: Arc<dyn quil_consensus::voting_provider::VotingProvider<GlobalState, GlobalVote>> = Arc::new(
        BlsVotingProvider::<GlobalState, GlobalVote, GlobalVoteFactory>::new(
            signer.clone(),
            vote_domain,
            timeout_domain,
            derive_address,
            factory,
        ),
    );
    let signer: Arc<dyn quil_consensus::signer::Signer<GlobalState, GlobalVote>> =
        Arc::new(VotingProviderSigner::new(voting_provider.clone()));

    // Keep a clone of the publisher so the follower can broadcast
    // ProverKick messages on equivocation.
    let publisher_for_follower = params.publisher.clone();
    let consumer: Arc<dyn quil_consensus::event_handler::Consumer<GlobalState, GlobalVote>> =
        match (params.publisher, params.on_qc_observed) {
            (Some(p), Some(qc_hook)) => {
                Arc::new(GlobalConsumer::with_publisher_and_qc_hook(p, qc_hook))
            }
            (Some(p), None) => Arc::new(GlobalConsumer::with_publisher(p)),
            (None, _) => Arc::new(GlobalConsumer::new()),
        };
    let participant: Arc<
        dyn quil_consensus::pacemaker::ParticipantConsumer<GlobalState, GlobalVote>,
    > = Arc::new(GlobalParticipantConsumer);

    // Seed the in-memory store with a genesis liveness state so the
    // pacemaker's RankTracker can boot. The HotStuff event loop calls
    // `store.get_liveness_state(filter)` on construction; without a
    // pre-existing record it returns NotFound and activation aborts
    // with "could not load liveness data". Mirror Go's startup path
    // which writes this record before spawning the loop on a fresh
    // testnet/devnet bootstrap.
    // Choose backing store. Production wires `kv_db = Some(...)`
    // so safety + liveness state survive restarts; tests pass
    // `None` for a transient in-memory store.
    let store: Arc<dyn quil_consensus::event_handler::ConsensusStore<GlobalVote>> =
        match params.kv_db.as_ref() {
            Some(kv) => Arc::new(crate::consensus_store::KvConsensusStore::new(
                kv.clone(),
                Arc::new(crate::consensus_glue::GlobalConsensusCodec),
                Arc::new(|_filter: &[u8]| panic!(
                    "bootstrap_consensus closure invoked — should be seeded \
                     before first read; see consensus_activation.rs"
                )),
                Arc::new(|_filter: &[u8]| panic!(
                    "bootstrap_liveness closure invoked — should be seeded \
                     before first read; see consensus_activation.rs"
                )),
            )),
            None => Arc::new(MemConsensusStore::new()),
        };
    let seed_store = store.clone();
    // If the persistent store already has consensus state for this
    // filter, leave it alone — overwriting on every restart would
    // erase the finalized_rank / latest_QC the previous run worked
    // hard to advance. Only seed when the store is fresh.
    // The pacemaker and safety_rules both read state keyed by
    // `config.filter`. For global consensus that's empty (matching
    // Go's `nil` filter on CONSENSUS keys), but the test path passes
    // a `config_override`, so use whatever the live config carries
    // rather than hardcoding empty.
    let consensus_filter: Vec<u8> = config.filter.clone();
    let needs_seed: bool = match params.kv_db.as_ref() {
        Some(kv) => {
            let key = quil_store::encoding::consensus_state_key(&consensus_filter);
            match kv.get(&key) {
                Ok(Some(_)) => false,
                _ => true,
            }
        }
        None => true,
    };
    if needs_seed {
        // For migrated stores the "genesis_frame" caller passes is
        // actually the LATEST finalized frame (see the comment on
        // `build_genesis_certified_state` — same misnomer). The QC
        // identity must hash the *current* trusted root's header
        // output, not the literal genesis output, otherwise the
        // event handler's parent-QC check fails the moment a real
        // proposal arrives.
        let frame_identity: Vec<u8> = match params.genesis_frame.header.as_ref() {
            Some(h) => quil_crypto::poseidon::hash_bytes_to_32(&h.output)
                .map(|hash| hash.to_vec())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        // Where we are in the chain. A fresh testnet bootstrap has
        // rank=0 here; a node migrated from a Go store has whatever
        // rank its latest finalized frame carries (e.g. 414).
        let trusted_rank: u64 = params
            .genesis_frame
            .header
            .as_ref()
            .map(|h| h.rank)
            .unwrap_or(0);

        // Seed QC for the trusted root. Identity = poseidon(output)
        // (matches `build_genesis_certified_state`'s `qc_identity`),
        // rank = `trusted_rank` so the event handler's
        // `qc.rank() + 1 == cur_rank` happy-path check accepts it as
        // the previous-round QC. Caller override (a real QC loaded
        // from store) takes precedence.
        let seed_qc = params.genesis_qc_override.clone().unwrap_or_else(|| {
            crate::consensus_wire::QuorumCertificate::genesis(
                trusted_rank,
                frame_identity.clone(),
            )
        });
        let seed_qc_obj: Arc<dyn quil_consensus::models::QuorumCertificate> =
            seed_qc.into_trait_object();
        // current_rank = trusted_rank + 1 so the leader at the next
        // rank sees the seed QC as its previous-round QC. On a fresh
        // testnet bootstrap (trusted_rank=0) this is 1, matching
        // pre-migration behaviour. On a migrated store
        // (trusted_rank=414) this is 415.
        let liveness = quil_consensus::models::LivenessState {
            filter: consensus_filter.clone(),
            current_rank: trusted_rank.saturating_add(1),
            latest_quorum_certificate: seed_qc_obj,
            prior_rank_timeout_certificate: None,
        };
        if let Err(e) = quil_consensus::event_handler::ConsensusStore::<GlobalVote>::put_liveness_state(
            seed_store.as_ref(),
            &liveness,
        ) {
            return Err(QuilError::Consensus(format!(
                "failed to seed liveness state: {}", e
            )));
        }

        // Safety data: finalized_rank tracks the highest rank we've
        // committed locally. For a migrated store that's `trusted_rank`
        // (everything up to and including it is on disk). For a fresh
        // bootstrap it's 0.
        let consensus_state = quil_consensus::models::ConsensusState::<GlobalVote> {
            filter: consensus_filter.clone(),
            finalized_rank: trusted_rank,
            latest_acknowledged_rank: trusted_rank,
            latest_timeout: None,
        };
        if let Err(e) = quil_consensus::event_handler::ConsensusStore::<GlobalVote>::put_consensus_state(
            seed_store.as_ref(),
            &consensus_state,
        ) {
            return Err(QuilError::Consensus(format!(
                "failed to seed genesis consensus state: {}", e
            )));
        }
    }
    // `store` was created above; `seed_store` is the same Arc.
    drop(seed_store);

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
    let follower: Arc<dyn quil_consensus::forest::FollowerConsumer<GlobalState>> = Arc::new(
        GlobalFollower::with_hooks(
            params.on_finalized_state,
            params.on_incorporated_state,
            publisher_for_follower,
        ),
    );

    let start = components.start(certified_root, finalizer, follower)?;
    info!("HotStuff consensus event loop ready (caller must spawn run_future)");
    Ok(ConsensusActivation {
        handle: start.handle,
        committee,
        voting_provider,
        vote_domain: vote_domain_for_return,
        timeout_domain: timeout_domain_for_return,
        run_future: start.run_future,
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
            voter_address.to_vec(),
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
            Vec::new(),
            rank,
            voter_address.to_vec(),
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
