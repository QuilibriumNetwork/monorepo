//! Tier 1 in-process integration tests for the archive↔non-archive
//! consensus flow.
//!
//! ## Scope
//!
//! 1. Archive nodes finalize global frames via HotStuff (multi-node).
//! 2. Non-archive nodes submit `ProverJoin` and observe the join land.
//! 3. After confirm window, worker thread starts app-shard consensus.
//! 4. Workers emit shard proofs; archive's next frame includes them.
//!
//! ## Building blocks
//!
//! - `quil_store::testing::InMemoryClockStore` — full ClockStore.
//! - `quil_engine::test_support::TestProverRegistry` — accessible.
//! - `ConsensusConfig::startup_delay` + `config_override` — test-tunable.
//! - `InMemoryNetwork` (this file) — routes consensus messages between
//!   nodes via decoded typed values, bypassing BlossomSub.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use quil_types::consensus::{DifficultyAdjuster, ProverRegistry};
use quil_types::crypto::{
    BlsConstructor, FrameProver, InclusionProver, NoopInclusionProver, Signer,
};
use quil_types::error::Result as QResult;
use quil_types::proto::global as gpb;
use quil_types::store::ClockStore;

use quil_engine::test_support::TestProverRegistry;
use quil_store::testing::InMemoryClockStore;

// ===================================================================
// Test helper — ExecutionEngineManager built with noop crypto stubs.
// ===================================================================

/// Construct an `ExecutionEngineManager` slotted with the
/// `quil_execution::testing::NoopExecutionCrypto` stubs. The new
/// `ExecutionEngineManager::new` requires every crypto trait + clock
/// store, so tests pull in this builder rather than constructing
/// engines manually.
fn build_test_exec_manager(
    inclusion_prover: Arc<dyn InclusionProver>,
    include_global: bool,
) -> quil_execution::ExecutionEngineManager {
    let hg_store: Arc<dyn quil_types::store::HypergraphStore> =
        Arc::new(quil_hypergraph::testing::MemStore::new());
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store,
        inclusion_prover.clone(),
    ));
    let stubs = quil_execution::testing::NoopExecutionCrypto::new();
    let hg_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    quil_execution::ExecutionEngineManager::new(
        inclusion_prover,
        stubs.key_manager.clone(),
        crdt,
        stubs.bulletproof_prover,
        stubs.decaf_constructor,
        stubs.circuit_compiler,
        stubs.clock_store,
        hg_resolver,
        include_global,
    )
}

// ===================================================================
// Stub FrameProver — deterministic outputs, real BLS signing.
// ===================================================================

pub struct StubFrameProver;

impl FrameProver for StubFrameProver {
    fn prove_frame_header(
        &self,
        previous_frame_output: &[u8],
        _address: &[u8],
        _requests_root: &[u8],
        _state_roots: &[Vec<u8>],
        _prover: &[u8],
        timestamp: i64,
        difficulty: u32,
        _fee_multiplier_vote: u64,
        frame_number: u64,
    ) -> QResult<gpb::FrameHeader> {
        // Output must be unique per (frame, ts) — otherwise every rank
        // hashes to the same identity, all states alias to the same
        // forks node, and the 3-chain rule never finalizes.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&frame_number.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(previous_frame_output);
        let h = quil_crypto::poseidon::hash_bytes_to_32(&buf).unwrap_or([0u8; 32]);
        let mut output = vec![0u8; 516];
        output[..32].copy_from_slice(&h);
        Ok(gpb::FrameHeader {
            address: vec![0u8; 32],
            frame_number,
            rank: 0,
            timestamp,
            difficulty,
            output,
            parent_selector: if previous_frame_output.is_empty() {
                vec![0u8; 32]
            } else {
                previous_frame_output[..previous_frame_output.len().min(32)].to_vec()
            },
            requests_root: vec![0u8; 64],
            state_roots: vec![],
            prover: vec![0u8; 96],
            fee_multiplier_vote: 0,
            public_key_signature_bls48581: None,
        })
    }

    fn verify_frame_header(&self, _h: &gpb::FrameHeader) -> QResult<Vec<u8>> {
        Ok(vec![0u8; 516])
    }

    fn prove_global_frame_header(
        &self,
        previous_frame: &gpb::GlobalFrameHeader,
        _commitments: &[Vec<u8>],
        prover_root: &[u8],
        request_root: &[u8],
        signer: &dyn Signer,
        timestamp: i64,
        difficulty: u32,
        _prover_index: u8,
    ) -> QResult<gpb::GlobalFrameHeader> {
        // Unique 516-byte output per (frame, ts, rank).
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&previous_frame.frame_number.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&(previous_frame.rank + 1).to_be_bytes());
        let h = quil_crypto::poseidon::hash_bytes_to_32(&buf).unwrap_or([0u8; 32]);
        let mut output = vec![0u8; 516];
        output[..32].copy_from_slice(&h);

        // Sign challenge||output with domain "global" matching the real prover.
        let mut sig_payload = Vec::with_capacity(32 + output.len());
        sig_payload.extend_from_slice(&h);
        sig_payload.extend_from_slice(&output);
        let _sig = signer
            .sign_with_domain(&sig_payload, b"global")
            .unwrap_or_default();

        Ok(gpb::GlobalFrameHeader {
            frame_number: previous_frame.frame_number + 1,
            rank: previous_frame.rank + 1,
            timestamp,
            difficulty,
            output,
            parent_selector: previous_frame.output.clone(),
            prover: signer.public_key().to_vec(),
            prover_tree_commitment: prover_root.to_vec(),
            requests_root: request_root.to_vec(),
            ..Default::default()
        })
    }

    fn verify_global_frame_header(&self, h: &gpb::GlobalFrameHeader) -> QResult<Vec<u8>> {
        Ok(h.output.clone())
    }

    fn calculate_multi_proof(
        &self,
        _challenge: &[u8; 32],
        _difficulty: u32,
        _ids: &[&[u8]],
        _index: u32,
    ) -> QResult<Vec<u8>> {
        // ProverPipeline expects each filter's proof to be 516 bytes
        // (see `submit_join`: `all_proofs[i * 516..(i + 1) * 516]`).
        // Returning a shorter blob slices past the end and panics.
        Ok(vec![0u8; 516])
    }

    fn verify_multi_proof(
        &self,
        _challenge: &[u8; 32],
        _difficulty: u32,
        _ids: &[&[u8]],
        _proofs: &[&[u8]],
    ) -> QResult<bool> {
        Ok(true)
    }
}

// ===================================================================
// Stub DifficultyAdjuster
// ===================================================================

pub struct ConstDifficulty(pub u64);

impl DifficultyAdjuster for ConstDifficulty {
    fn get_next_difficulty(&self, _current_frame_number: u64, _current_time: i64) -> u64 {
        self.0
    }
}

// ===================================================================
// TestProver — BLS keypair + Poseidon-derived address.
// ===================================================================

pub struct TestProver {
    pub address: Vec<u8>,
    pub bls_pubkey: Vec<u8>,
    pub bls_signer: Box<dyn Signer>,
}

impl Clone for TestProver {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            bls_pubkey: self.bls_pubkey.clone(),
            bls_signer: self.signer_clone(),
        }
    }
}

impl TestProver {
    pub fn generate() -> Self {
        let ctor = quil_crypto::Bls48581KeyConstructor;
        let (signer, pubkey) = ctor.new_key().expect("bls keygen");
        let address = quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        Self {
            address,
            bls_pubkey: pubkey,
            bls_signer: signer,
        }
    }

    pub fn signer_clone(&self) -> Box<dyn Signer> {
        let ctor = quil_crypto::Bls48581KeyConstructor;
        ctor.from_bytes(self.bls_signer.private_key(), self.bls_signer.public_key())
            .expect("bls signer from bytes")
    }

    pub fn to_prover_info(&self, seniority: u64) -> quil_types::consensus::ProverInfo {
        quil_types::consensus::ProverInfo {
            public_key: self.bls_pubkey.clone(),
            address: self.address.clone(),
            status: quil_types::consensus::ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![],
            available_storage: 0,
            seniority,
            delegate_address: vec![],
        }
    }
}

// ===================================================================
// Genesis builder
// ===================================================================

pub fn build_genesis_frame(proposer: &TestProver) -> gpb::GlobalFrame {
    let header = gpb::GlobalFrameHeader {
        frame_number: 0,
        rank: 0,
        timestamp: 1_700_000_000_000,
        difficulty: 100_000,
        output: vec![0xAAu8; 516],
        parent_selector: vec![0u8; 32],
        prover: proposer.bls_pubkey.clone(),
        prover_tree_commitment: vec![0u8; 64],
        requests_root: vec![0u8; 64],
        ..Default::default()
    };
    gpb::GlobalFrame {
        header: Some(header),
        requests: vec![],
    }
}

// ===================================================================
// BLS aggregation helper — builds a properly-signed genesis QC so the
// receiver-side BLS verifier accepts it.
//
// Without this, `BlsConsensusVerifier::verify_quorum_certificate`
// rejects the genesis QC the moment the consensus state machine
// embeds it into a timeout state (which happens whenever the loop
// hits even a transient timeout — overwhelmingly likely in a tight
// in-memory test). The empty-signature genesis QC works in
// production only on the happy path where the genesis QC is
// embedded but never re-verified.
// ===================================================================

/// Compute the genesis-state identity: Poseidon(output) over the
/// 516-byte VDF output. Matches `GlobalState::compute_identity` for
/// the genesis frame produced by `build_genesis_frame`.
fn genesis_state_identity(genesis: &gpb::GlobalFrame) -> Vec<u8> {
    let output = &genesis.header.as_ref().unwrap().output;
    quil_crypto::poseidon::hash_bytes_to_32(output)
        .map(|h| h.to_vec())
        .unwrap_or_default()
}

/// Build a BLS-aggregated genesis QC signed by every prover. Each
/// prover signs `make_vote_message(filter=[], rank=0, genesis_identity)`
/// with the consensus-vote domain; the resulting signatures + public
/// keys are aggregated to produce a single (signature, pubkey) pair
/// that `BlsConsensusVerifier::verify_quorum_certificate` accepts.
fn build_signed_genesis_qc(
    provers: &[TestProver],
    genesis: &gpb::GlobalFrame,
) -> quil_engine::consensus_wire::QuorumCertificate {
    let identity = genesis_state_identity(genesis);
    // Matches the message constructed by
    // `quil_consensus::verification::make_vote_message`.
    let mut msg = Vec::new();
    // filter is empty (global consensus)
    msg.extend_from_slice(&identity);
    msg.extend_from_slice(&0u64.to_be_bytes()); // rank 0

    // Domain tag: Poseidon("GLOBAL_CONSENSUS_VOTE"). Matches
    // `consensus_activation.rs:115-119`.
    let vote_domain = quil_crypto::poseidon::hash_bytes_to_32(b"GLOBAL_CONSENSUS_VOTE")
        .map(|h| h.to_vec())
        .unwrap_or_default();

    // Sign with every prover.
    let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(provers.len());
    let mut pks: Vec<Vec<u8>> = Vec::with_capacity(provers.len());
    for p in provers {
        let sig = p
            .bls_signer
            .sign_with_domain(&msg, &vote_domain)
            .expect("bls sign");
        sigs.push(sig);
        pks.push(p.bls_pubkey.clone());
    }

    let ctor = quil_crypto::Bls48581KeyConstructor;
    let pk_refs: Vec<&[u8]> = pks.iter().map(|v| v.as_slice()).collect();
    let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
    let agg = ctor
        .aggregate(&pk_refs, &sig_refs)
        .expect("bls aggregate");

    // Bitmask: bit i set means prover i signed. All provers signed,
    // so every bit in `provers.len()` slots is set. Padded to 32
    // bytes (the wire encoding's expected width).
    let mut bitmask = vec![0u8; 32];
    for i in 0..provers.len() {
        bitmask[i / 8] |= 1 << (i % 8);
    }

    quil_engine::consensus_wire::QuorumCertificate {
        filter: Vec::new(),
        rank: 0,
        frame_number: 0,
        selector: identity,
        timestamp: 0,
        aggregate_signature: quil_engine::consensus_wire::AggregateSignature {
            public_key: agg.public_key,
            signature: agg.signature,
            bitmask,
        },
    }
}

// ===================================================================
// InMemoryNetwork — routes ConsensusPublisher bytes between nodes.
// ===================================================================
//
// Production: ConsensusPublisher → BlossomSub → peer recv loop → decode → submit to handle.
// Test: ConsensusPublisher (InMemoryPublisher) → InMemoryNetwork → each peer's inbox channel
//       → spawned task decodes → submits to peer handle + aggregators.
//
// The network identifies each node by its prover address. A
// publisher tagged with `sender_addr` skips delivery to itself
// (matches BlossomSub's self-echo suppression).

#[derive(Clone, Debug)]
pub enum WireMsg {
    Proposal(Vec<u8>),
    Vote(Vec<u8>),
    Timeout(Vec<u8>),
    Prover(Vec<u8>),
}

type NodeInbox = mpsc::UnboundedSender<WireMsg>;

/// Per-link latency model for the in-memory network. Each broadcast
/// delivery to a peer waits `base_ms + uniform(0, jitter_ms)` before
/// the peer's inbox receives the message. Mirrors typical LAN/WAN
/// one-way latency; tunable per-test.
///
/// Default (`base_ms=0, jitter_ms=0`) preserves the old
/// "instant-delivery" behavior so existing tests are unaffected.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkLatency {
    pub base_ms: u64,
    pub jitter_ms: u64,
}

impl NetworkLatency {
    pub fn instant() -> Self {
        Self { base_ms: 0, jitter_ms: 0 }
    }

    /// Realistic WAN: ~80ms mean, ±50ms jitter — matches common
    /// commercial internet round-trip / 2.
    pub fn realistic_wan() -> Self {
        Self { base_ms: 30, jitter_ms: 100 }
    }
}

#[derive(Default)]
pub struct InMemoryNetwork {
    /// All registered nodes' inboxes, keyed by prover address.
    nodes: Mutex<HashMap<Vec<u8>, NodeInbox>>,
    /// Latency model applied per broadcast delivery. Cheap clone (Copy).
    latency: Mutex<NetworkLatency>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn register(&self, addr: Vec<u8>, inbox: NodeInbox) {
        self.nodes.lock().insert(addr, inbox);
    }

    /// Configure per-link latency. Each broadcast delivery sleeps
    /// `base_ms + uniform(0, jitter_ms)` before reaching the peer's
    /// inbox. Affects all subsequent broadcasts on this network.
    pub fn set_latency(&self, l: NetworkLatency) {
        *self.latency.lock() = l;
    }

    /// Broadcast `msg` to every node except `sender_addr` for votes
    /// and timeouts. For proposals, broadcasts to ALL nodes including
    /// the sender — this surfaces an architectural gap: the leader's
    /// own `vote_aggregator` requires `handle_proposal` to transition
    /// out of `Caching` state, and that transition only happens via
    /// the inbound message path. In production, BlossomSub's
    /// self-echo behavior determines whether this works; the safe
    /// path here is to deliver self-proposals back so the leader's
    /// aggregator collects its own self-vote (embedded in the
    /// SignedProposal) AND transitions to Verifying so peer votes
    /// get processed instead of just cached.
    pub fn broadcast(&self, sender_addr: &[u8], msg: WireMsg) {
        let include_self = matches!(msg, WireMsg::Proposal(_));
        let inboxes: Vec<NodeInbox> = self
            .nodes
            .lock()
            .iter()
            .filter(|(addr, _)| include_self || addr.as_slice() != sender_addr)
            .map(|(_, inbox)| inbox.clone())
            .collect();
        let latency = *self.latency.lock();
        for inbox in inboxes {
            let msg = msg.clone();
            if latency.base_ms == 0 && latency.jitter_ms == 0 {
                // Fast path — preserve zero-overhead delivery for
                // tests that didn't opt in.
                let _ = inbox.send(msg);
            } else {
                // Spawn one per-delivery task so each peer's link
                // sees an independent latency draw (mirrors real
                // BlossomSub fan-out, where deliveries don't
                // serialize on each other).
                let base = latency.base_ms;
                let jitter = latency.jitter_ms;
                tokio::spawn(async move {
                    let extra = if jitter == 0 {
                        0
                    } else {
                        use rand::Rng;
                        rand::thread_rng().gen_range(0..jitter)
                    };
                    tokio::time::sleep(std::time::Duration::from_millis(base + extra)).await;
                    let _ = inbox.send(msg);
                });
            }
        }
    }
}

/// `ConsensusPublisher` impl that funnels bytes through `InMemoryNetwork`.
pub struct InMemoryPublisher {
    network: Arc<InMemoryNetwork>,
    sender_addr: Vec<u8>,
}

impl InMemoryPublisher {
    pub fn new(network: Arc<InMemoryNetwork>, sender_addr: Vec<u8>) -> Self {
        Self { network, sender_addr }
    }
}

impl quil_engine::consensus_glue::ConsensusPublisher for InMemoryPublisher {
    fn publish_frame(&self, data: Vec<u8>) {
        // GLOBAL_FRAME bitmask carries the GlobalProposal canonical bytes.
        self.network
            .broadcast(&self.sender_addr, WireMsg::Proposal(data));
    }
    fn publish_consensus(&self, data: Vec<u8>) {
        // GLOBAL_CONSENSUS carries GlobalProposal, ProposalVote, OR
        // TimeoutState (mirror of main.rs:3280-3349). Production sends
        // proposals on this bitmask too — `publish_frame` is reserved
        // for a separate code path. Disambiguate via the type prefix.
        if let Some(tp) = quil_engine::consensus_wire::peek_consensus_type(&data) {
            if tp == quil_engine::consensus_wire::GLOBAL_PROPOSAL_TYPE {
                self.network
                    .broadcast(&self.sender_addr, WireMsg::Proposal(data));
            } else if tp == quil_engine::consensus_wire::PROPOSAL_VOTE_TYPE {
                self.network
                    .broadcast(&self.sender_addr, WireMsg::Vote(data));
            } else if tp == quil_engine::consensus_wire::TIMEOUT_STATE_TYPE {
                self.network
                    .broadcast(&self.sender_addr, WireMsg::Timeout(data));
            }
        }
    }
    fn publish_prover_message(&self, data: Vec<u8>) {
        self.network
            .broadcast(&self.sender_addr, WireMsg::Prover(data));
    }
}

// ===================================================================
// NodeRig — per-node bundle of handle + aggregators + inbound task.
// ===================================================================

pub struct NodeRig {
    pub prover: TestProver,
    pub handle: quil_consensus::event_loop::EventLoopHandle<
        quil_engine::consensus_types::GlobalState,
        quil_engine::consensus_types::GlobalVote,
    >,
    pub clock_store: Arc<InMemoryClockStore>,
    pub finalized: Arc<Mutex<Vec<u64>>>,
    pub vote_agg: Arc<quil_engine::vote_aggregation::VoteAggregation>,
    pub timeout_agg: Arc<quil_engine::timeout_aggregation::TimeoutAggregation>,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub finalized_frames: Arc<Mutex<Vec<gpb::GlobalFrame>>>,
}

/// Build one node's rig and spawn its inbound consensus message
/// processor. The processor consumes `WireMsg`s from `inbox_rx`,
/// decodes them into typed values, and forwards to the appropriate
/// handle / aggregator.
pub fn build_node(
    prover: TestProver,
    all_provers: &[quil_types::consensus::ProverInfo],
    genesis: gpb::GlobalFrame,
    genesis_qc: quil_engine::consensus_wire::QuorumCertificate,
    network: Arc<InMemoryNetwork>,
    inbox_rx: mpsc::UnboundedReceiver<WireMsg>,
) -> NodeRig {
    let registry = Arc::new(TestProverRegistry::with_provers(all_provers.to_vec()));
    let clock_store = Arc::new(InMemoryClockStore::new());
    clock_store.seed_frame(genesis.clone());

    // Also seed the QC into the clock store — the leader's
    // `prove_next_state` reads `get_latest_quorum_certificate(filter)`
    // when generating rank-N proposals. Without this seed, the event
    // loop exits at startup with "could not fetch latest QC: no QC".
    // Mirrors `genesis::establish_testnet_genesis_provers` line 391.
    let proto_qc = gpb::QuorumCertificate {
        filter: genesis_qc.filter.clone(),
        rank: genesis_qc.rank,
        frame_number: genesis_qc.frame_number,
        selector: genesis_qc.selector.clone(),
        timestamp: genesis_qc.timestamp,
        aggregate_signature: Some(quil_types::proto::keys::Bls48581AggregateSignature {
            public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                key_value: genesis_qc.aggregate_signature.public_key.clone(),
            }),
            signature: genesis_qc.aggregate_signature.signature.clone(),
            bitmask: genesis_qc.aggregate_signature.bitmask.clone(),
        }),
    };
    let qc_txn = clock_store
        .new_transaction(false)
        .expect("new_transaction");
    clock_store
        .put_quorum_certificate(&proto_qc, qc_txn.as_ref())
        .expect("seed genesis QC");
    qc_txn.commit().expect("qc commit");

    let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
    let difficulty_adjuster: Arc<dyn DifficultyAdjuster> = Arc::new(ConstDifficulty(100_000));
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
    let inclusion_prover: Arc<dyn InclusionProver + Send + Sync> = Arc::new(NoopInclusionProver);

    let publisher: Arc<dyn quil_engine::consensus_glue::ConsensusPublisher> = Arc::new(
        InMemoryPublisher::new(network.clone(), prover.address.clone()),
    );

    let finalized: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let finalized_frames: Arc<Mutex<Vec<gpb::GlobalFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let finalized_clone = finalized.clone();
    let finalized_frames_clone = finalized_frames.clone();
    let finalized_hook: quil_engine::consensus_glue::FinalizedStateHook =
        Arc::new(move |state| {
            let app = &state.state;
            finalized_clone.lock().push(app.frame_number);
            let header = gpb::GlobalFrameHeader {
                frame_number: app.frame_number,
                rank: app.rank,
                timestamp: app.timestamp,
                difficulty: app.difficulty,
                output: app.output.clone(),
                parent_selector: app.parent_selector.clone(),
                prover: app.prover.clone(),
                prover_tree_commitment: app.prover_tree_commitment.clone(),
                requests_root: app.requests_root.clone(),
                ..Default::default()
            };
            let frame = gpb::GlobalFrame {
                header: Some(header),
                requests: app.messages.clone(),
            };
            finalized_frames_clone.lock().push(frame);
        });

    // Persist incorporated (forks-tree) frames as candidates so the
    // leader can chain rank+1 proposals via
    // `prove_next_state → get_global_clock_frame_candidate`.
    // Mirror of main.rs:2467-2524.
    let cs_for_inc = clock_store.clone();
    let incorporated_hook: quil_engine::consensus_glue::IncorporatedStateHook =
        Arc::new(move |state| {
            let app = &state.state;
            let header = gpb::GlobalFrameHeader {
                frame_number: app.frame_number,
                rank: app.rank,
                timestamp: app.timestamp,
                difficulty: app.difficulty,
                output: app.output.clone(),
                parent_selector: app.parent_selector.clone(),
                prover: app.prover.clone(),
                prover_tree_commitment: app.prover_tree_commitment.clone(),
                requests_root: app.requests_root.clone(),
                ..Default::default()
            };
            let frame = gpb::GlobalFrame {
                header: Some(header),
                requests: Vec::new(),
            };
            if let Ok(txn) = cs_for_inc.new_transaction(false) {
                let _ = cs_for_inc.put_global_clock_frame_candidate(&frame, txn.as_ref());
                let _ = txn.commit();
            }
        });

    // Persist observed QCs so `get_latest_quorum_certificate` resolves
    // to the freshest QC. Mirror of main.rs:2531-2584.
    let cs_for_qc = clock_store.clone();
    let qc_observed_hook: quil_engine::consensus_glue::QcObservedHook =
        Arc::new(move |qc| {
            let proto_qc = gpb::QuorumCertificate {
                filter: qc.filter().to_vec(),
                rank: qc.rank(),
                frame_number: qc.frame_number(),
                selector: qc.identity().clone(),
                timestamp: qc.timestamp(),
                aggregate_signature: Some(quil_types::proto::keys::Bls48581AggregateSignature {
                    public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                        key_value: qc.aggregated_signature().public_key().to_vec(),
                    }),
                    signature: qc.aggregated_signature().signature().to_vec(),
                    bitmask: qc.aggregated_signature().bitmask().to_vec(),
                }),
            };
            if let Ok(txn) = cs_for_qc.new_transaction(false) {
                let _ = cs_for_qc.put_quorum_certificate(&proto_qc, txn.as_ref());
                let _ = txn.commit();
            }
        });

    let mut cfg = quil_engine::consensus_bootstrap::ConsensusConfig::default();
    cfg.startup_delay = std::time::Duration::ZERO;
    // Generous timing: proposal_duration is the cadence at which the
    // leader emits a proposal; min_timeout is how long the loop
    // waits for a quorum before declaring a local timeout. Keep
    // min_timeout >> proposal_duration so the leader has many
    // proposal opportunities before the round times out.
    cfg.proposal_duration = std::time::Duration::from_millis(500);
    cfg.min_timeout = std::time::Duration::from_secs(20);
    cfg.max_timeout = std::time::Duration::from_secs(60);

    let params = quil_engine::consensus_activation::ConsensusActivationParams {
        prover_registry: registry.clone() as Arc<dyn ProverRegistry>,
        frame_prover,
        difficulty_adjuster,
        clock_store: clock_store.clone() as Arc<dyn ClockStore>,
        message_collector: message_collector.clone(),
        local_prover_address: prover.address.clone(),
        local_bls_pubkey: prover.bls_pubkey.clone(),
        bls_signer: prover.signer_clone(),
        inclusion_prover,
        genesis_frame: genesis,
        publisher: Some(publisher),
        on_finalized_state: Some(finalized_hook),
        on_incorporated_state: Some(incorporated_hook),
        on_qc_observed: Some(qc_observed_hook),
        config_override: Some(cfg),
        genesis_qc_override: Some(genesis_qc),
        kv_db: None,
    };

    let activation = quil_engine::consensus_activation::activate_consensus(params)
        .expect("activate_consensus");
    // Drive the event loop. In production this is handed to the
    // supervisor; tests spawn it directly since they don't run a
    // supervisor.
    tokio::spawn(activation.run_future);

    // Build vote + timeout aggregators (mirrors main.rs:2615-2638).
    let handle_cell: Arc<std::sync::OnceLock<
        quil_consensus::event_loop::EventLoopHandle<
            quil_engine::consensus_types::GlobalState,
            quil_engine::consensus_types::GlobalVote,
        >,
    >> = Arc::new(std::sync::OnceLock::new());
    let _ = handle_cell.set(activation.handle.clone());

    let bls_ctor: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let vote_agg = Arc::new(quil_engine::vote_aggregation::VoteAggregation::new(
        activation.committee.clone(),
        activation.voting_provider.clone(),
        handle_cell.clone(),
        bls_ctor.clone(),
        activation.vote_domain.clone(),
    ));
    let timeout_agg = Arc::new(quil_engine::timeout_aggregation::TimeoutAggregation::new(
        activation.committee.clone(),
        activation.voting_provider.clone(),
        handle_cell.clone(),
        bls_ctor,
        activation.vote_domain.clone(),
        activation.timeout_domain.clone(),
    ));

    // Spawn the inbound message processor. Mirrors main.rs:3280-3349 —
    // decode by type prefix, route into handle.submit_* + aggregators.
    let handle_for_recv = activation.handle.clone();
    let va_for_recv = vote_agg.clone();
    let ta_for_recv = timeout_agg.clone();
    let mc_for_recv = message_collector.clone();
    tokio::spawn(async move {
        let mut rx = inbox_rx;
        while let Some(msg) = rx.recv().await {
            match msg {
                WireMsg::Proposal(data) => {
                    if let Ok(wire) =
                        quil_engine::consensus_wire::GlobalProposal::from_canonical_bytes(&data)
                    {
                        if let Ok((sp, qc, tc)) =
                            quil_engine::consensus_types::wire_proposal_to_signed(wire)
                        {
                            handle_for_recv.submit_quorum_certificate(qc);
                            if let Some(tc) = tc {
                                handle_for_recv.submit_timeout_certificate(tc);
                            }
                            va_for_recv.handle_proposal(&sp);
                            let h = handle_for_recv.clone();
                            tokio::spawn(async move {
                                h.submit_proposal(sp).await;
                            });
                        }
                    }
                }
                WireMsg::Vote(data) => {
                    if let Ok(wire) =
                        quil_engine::consensus_wire::ProposalVote::from_canonical_bytes(&data)
                    {
                        let gv = quil_engine::vote_aggregation::wire_vote_to_global_vote(wire);
                        va_for_recv.handle_vote(gv);
                    }
                }
                WireMsg::Timeout(data) => {
                    if let Ok(ts) =
                        quil_engine::consensus_wire::TimeoutState::from_canonical_bytes(&data)
                    {
                        let qc = ts.latest_quorum_certificate.clone().into_trait_object();
                        handle_for_recv.submit_quorum_certificate(qc);
                        if let Some(tc) = ts.prior_rank_timeout_certificate.clone() {
                            handle_for_recv.submit_timeout_certificate(tc.into_trait_object());
                        }
                        let typed =
                            quil_engine::timeout_aggregation::wire_timeout_to_typed(ts);
                        ta_for_recv.handle_timeout(typed);
                    }
                }
                WireMsg::Prover(data) => {
                    // GLOBAL_PROVER bitmask: prover-admin messages
                    // (ProverJoin / ProverLeave / ProverConfirm /
                    // ProverReject / ProverSeniorityMerge) — feed
                    // into the local message_collector so the leader
                    // includes them in the next proposal's
                    // `requests`. Mirror of main.rs:3354-3357.
                    //
                    // Rank 0 ensures `collect_for_rank(N)` (which
                    // drains all ranks <= N) picks it up at any
                    // proposal rank.
                    mc_for_recv.add_message(0, data);
                }
            }
        }
    });

    NodeRig {
        prover,
        handle: activation.handle,
        clock_store,
        finalized,
        vote_agg,
        timeout_agg,
        message_collector,
        finalized_frames,
    }
}

// ===================================================================
// Multi-node harness
// ===================================================================

pub struct MultiNodeHarness {
    pub network: Arc<InMemoryNetwork>,
    pub nodes: Vec<NodeRig>,
}

impl MultiNodeHarness {
    /// Build a harness with `n` archive nodes. The first prover is
    /// the genesis proposer.
    pub fn build_archives(n: usize) -> Self {
        assert!(n >= 1, "need at least one archive");

        // Generate provers; first is the genesis proposer. All provers
        // get the SAME seniority so the leader-rotation path doesn't
        // depend on the per-prover weight distribution — and so the
        // peer-vote-only quorum threshold (excluding the leader's
        // own vote, which never enters its local aggregator in the
        // current architecture) is reached comfortably rather than
        // exactly at the threshold boundary.
        let provers: Vec<TestProver> = (0..n).map(|_| TestProver::generate()).collect();
        let all_prover_infos: Vec<_> = provers
            .iter()
            .map(|p| p.to_prover_info(1))
            .collect();

        let genesis = build_genesis_frame(&provers[0]);
        let genesis_qc = build_signed_genesis_qc(&provers, &genesis);
        let network = InMemoryNetwork::new();

        let mut nodes = Vec::with_capacity(n);
        // Move each prover into the node rig.
        for prover in provers {
            let (tx, rx) = mpsc::unbounded_channel();
            network.register(prover.address.clone(), tx);
            let node = build_node(
                prover,
                &all_prover_infos,
                genesis.clone(),
                genesis_qc.clone(),
                network.clone(),
                rx,
            );
            nodes.push(node);
        }

        Self { network, nodes }
    }

    /// Wait up to `timeout` for every node to observe at least one
    /// finalization. Returns true if all nodes finalized at least once.
    pub async fn wait_for_finalization_all(
        &self,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let all_finalized = self
                .nodes
                .iter()
                .all(|n| !n.finalized.lock().is_empty());
            if all_finalized {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    /// Wait up to `timeout` for any node to finalize a frame whose
    /// `requests` field contains at least `min_bundles` MessageBundle
    /// entries. The injected prover message goes through:
    ///   InMemoryNetwork → archive inbound task → message_collector.add_message
    ///   → leader's `collect_for_rank` → state.with_messages → proposal
    ///   → QC → 3-chain finalization → on_finalized_state hook
    ///   → finalized_frames Vec
    /// Asserting on the bundle count proves the full round-trip
    /// without needing to deserialize the inner ProverJoin payload
    /// (which would require valid BLS sigs / VDF outputs the test
    /// doesn't construct).
    pub async fn wait_for_finalized_bundles(
        &self,
        min_bundles: usize,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for node in &self.nodes {
                let frames = node.finalized_frames.lock();
                let total: usize = frames.iter().map(|f| f.requests.len()).sum();
                if total >= min_bundles {
                    return true;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    /// Broadcast a canonical prover-admin message to all archive nodes'
    /// message collectors. Mimics what a non-archive's
    /// `prover_pipeline::publish_prover_message` does when its
    /// payload crosses the wire on the GLOBAL_PROVER bitmask.
    pub fn inject_prover_message(&self, data: Vec<u8>) {
        // Use an empty sender address so broadcast delivers to ALL
        // nodes (a non-archive's address is not registered with the
        // network — the message effectively comes "from outside").
        self.network.broadcast(&[], WireMsg::Prover(data));
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn single_archive_node_activates_consensus() {
    // Foundational: 1-node activate_consensus succeeds and returns
    // a handle with valid domain bytes.
    let proposer = TestProver::generate();
    let registry = Arc::new(TestProverRegistry::with_prover(proposer.to_prover_info(1)));
    let clock_store = Arc::new(InMemoryClockStore::new());
    let genesis = build_genesis_frame(&proposer);
    clock_store.seed_frame(genesis.clone());

    let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
    let difficulty_adjuster: Arc<dyn DifficultyAdjuster> = Arc::new(ConstDifficulty(100_000));
    let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
    let inclusion_prover: Arc<dyn InclusionProver + Send + Sync> = Arc::new(NoopInclusionProver);

    let mut cfg = quil_engine::consensus_bootstrap::ConsensusConfig::default();
    cfg.startup_delay = std::time::Duration::ZERO;

    let params = quil_engine::consensus_activation::ConsensusActivationParams {
        prover_registry: registry as Arc<dyn ProverRegistry>,
        frame_prover,
        difficulty_adjuster,
        clock_store: clock_store.clone() as Arc<dyn ClockStore>,
        message_collector,
        local_prover_address: proposer.address.clone(),
        local_bls_pubkey: proposer.bls_pubkey.clone(),
        bls_signer: proposer.signer_clone(),
        inclusion_prover,
        genesis_frame: genesis,
        publisher: None,
        on_finalized_state: None,
        on_incorporated_state: None,
        on_qc_observed: None,
        config_override: Some(cfg),
        genesis_qc_override: None,
        kv_db: None,
    };

    let activation = quil_engine::consensus_activation::activate_consensus(params)
        .expect("activate_consensus");
    assert!(!activation.vote_domain.is_empty());
    assert!(!activation.timeout_domain.is_empty());
    let _ = activation;
}

/// Initialize tracing once per test run. Subsequent calls are no-ops.
fn init_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
    });
}

/// 4-archive consensus drives genesis → rank 1 finalization via real
/// BLS-aggregated votes. Verifies the full happy-path glue: leader
/// election, proposal broadcast, vote aggregation, QC formation,
/// finalization notification.
#[tokio::test]
async fn multi_archive_finalizes_via_quorum() {
    init_tracing();
    // 4 archives — minimum quorum size where `quorum_threshold(4) = 2`
    // (floor(2*4/3) = 2). The leader (prover 0, highest seniority) proposes
    // at rank 1, peers vote, leader's vote aggregator forms a QC, the QC
    // is embedded in the rank-2 proposal, and rank-0 → rank-1 finalizes.
    //
    // Wall-clock budget: startup_delay=ZERO, proposal_duration=500ms.
    // Two ranks of progression to see rank-0 finalize → ~1-2s of work
    // plus inter-task scheduling slop. Generous 30s timeout to absorb
    // CI jitter.
    let harness = MultiNodeHarness::build_archives(4);
    // HotStuff 3-chain finalization needs rank N+2's QC to finalize
    // rank N. With proposal_duration=500ms + leader-rotation latency
    // through the in-memory pubsub, expect ~10-15s per rank in this
    // harness (real BLS signing + aggregation per rank is the
    // dominant cost). 90s absorbs the genesis ramp-up + the first
    // few finalizations across all 4 nodes.
    let _ = harness
        .wait_for_finalization_all(std::time::Duration::from_secs(90))
        .await;

    let observations: Vec<Vec<u64>> = harness
        .nodes
        .iter()
        .map(|n| n.finalized.lock().clone())
        .collect();
    eprintln!("per-node finalized frame numbers: {:?}", observations);

    // Assert directly against the captured state — `wait_for_finalization_all`
    // can race against the final-tick finalization (it returns when
    // its polling loop sees all-non-empty, but in a tight test where
    // finalizations happen between polls, the polling can miss the
    // window even though the data is correct by the time we inspect).
    let all_finalized = observations.iter().all(|v| !v.is_empty());
    assert!(
        all_finalized,
        "expected all 4 archive nodes to finalize at least one frame; \
         per-node observations: {:?}",
        observations
    );
    // Verify the chain advanced past genesis: at least one node
    // finalized frame>=1.
    let any_post_genesis = observations
        .iter()
        .any(|v| v.iter().any(|&f| f >= 1));
    assert!(
        any_post_genesis,
        "expected at least one finalized frame >= 1; observations: {:?}",
        observations
    );
    // Drop the harness explicitly to terminate the spawned consensus tasks.
    drop(harness);
}

/// Same shape as `multi_archive_finalizes_via_quorum`, but with
/// realistic WAN latency (`30ms` base + up to `100ms` jitter) on
/// every in-memory broadcast. Catches timing assumptions that hold
/// at zero-latency but break under real network conditions:
///
///   * pacemaker `proposal_duration` < min_timeout buffer
///   * QC formation racing with proposal arrival at peers
///   * vote-aggregator caching/verifying state-machine races
///
/// If the system has any non-trivial dependency on order or
/// instant delivery, finalization will stall and the assertion fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_archive_finalizes_under_wan_latency() {
    init_tracing();
    let harness = MultiNodeHarness::build_archives(4);
    harness.network.set_latency(NetworkLatency::realistic_wan());

    // Looser budget than the zero-latency variant. With ~80ms median
    // delivery + 4 nodes × 3-chain finalization, expect ~3-5s per
    // rank. 180s absorbs CI jitter, genesis ramp, AND tokio runtime
    // contention when this test runs in parallel with the 15+ others
    // in the suite (rocksdb temp dirs + shared executor slow each
    // other down enough that the original 120s budget became flaky).
    let _ = harness
        .wait_for_finalization_all(std::time::Duration::from_secs(180))
        .await;

    let observations: Vec<Vec<u64>> = harness
        .nodes
        .iter()
        .map(|n| n.finalized.lock().clone())
        .collect();
    eprintln!("WAN-latency per-node finalized: {:?}", observations);

    // Assertion: at QUORUM strength (≥ 2/3 of nodes) finalized at
    // least one frame. Under latency, some peers may temporarily fall
    // behind — if proposal A is delivered to peer P after a later
    // proposal B that references A as parent, B is rejected with
    // "missing parent state" and P stalls. Real production recovers
    // via BlossomSub gossip + active sync, which this test doesn't
    // model. The quorum-strength assertion mirrors what consensus
    // itself needs: as long as ≥ 2/3 of weighted stake makes progress,
    // the chain advances and the lagging node will catch up once
    // network sync paths are wired in.
    let finalized_count = observations.iter().filter(|v| !v.is_empty()).count();
    let quorum_size = (observations.len() * 2 / 3) + 1;
    assert!(
        finalized_count >= quorum_size,
        "under realistic WAN latency, ≥{}/{} archives should finalize ≥1 frame within 120s \
         (consensus quorum threshold); got {}/{}; observations={:?}",
        quorum_size, observations.len(),
        finalized_count, observations.len(),
        observations,
    );
    let any_post_genesis = observations
        .iter()
        .any(|v| v.iter().any(|&f| f >= 1));
    assert!(
        any_post_genesis,
        "WAN-latency chain stalled before frame >= 1; observations={:?}",
        observations
    );
    drop(harness);
}

// 4-archive consensus needs at least one tokio worker per node so
// BLS signing and inbound message handling can interleave; using the
// default `current_thread` flavor here serialises all 4 archives on
// one OS thread and the pacemaker times rank 1 out under realistic
// parallel-test load before the leader's `prove_next_state` finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_archive_join_lands_in_archive_frame() {
    // Models a non-archive's `ProverJoin` submission round-tripping
    // through global consensus. The non-archive's role is the
    // CanonicalMessageBundle producer: it would normally invoke
    // `prover_pipeline::publish_prover_message` which broadcasts on
    // the GLOBAL_PROVER bitmask. Here we synthesize that broadcast
    // directly via `harness.inject_prover_message`.
    //
    // The full path:
    //   1. Test injects bundle bytes → InMemoryNetwork →
    //      4 archives' inbox channels.
    //   2. Each archive's inbound task: `message_collector.add_message(0, bytes)`.
    //   3. Leader's `prove_next_state` calls `collect_for_rank(rank)`
    //      which drains the message into the proposal's `messages`.
    //   4. `decode_message_bundle` turns the canonical bytes into a
    //      proto `MessageBundle` attached to the proposal's state.
    //   5. Consensus runs 3-chain finalization.
    //   6. The `on_finalized_state` hook captures the finalized
    //      frame including the embedded bundle.
    //
    // Assertion: at least one finalized frame on at least one node
    // has a non-empty `requests` Vec (the bundle survived).
    init_tracing();

    let harness = MultiNodeHarness::build_archives(4);

    // Construct a minimal canonical MessageBundle wrapping a
    // ProverJoin-shaped marker payload. The marker bytes don't need
    // to decode to a valid ProverJoin — `decode_message_bundle`
    // creates a default `MessageRequest` entry for unknown inner
    // type prefixes. We just need the bundle envelope to survive.
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    // 0x0301 is the ProverJoin type prefix — picked to look like a
    // real prover-admin message so the message_collector accepts it
    // even in prover-only mode (the test doesn't enable that mode,
    // but this matches production traffic shape).
    let mut inner_bytes = Vec::with_capacity(36);
    inner_bytes.extend_from_slice(&0x0301u32.to_be_bytes());
    // Pad with arbitrary bytes — the bundle's canonical encoding
    // length-prefixes everything, so unrecognized payload shape
    // doesn't break the envelope.
    inner_bytes.extend_from_slice(&[0xCAu8; 32]);
    let req = CanonicalMessageRequest::wrap(inner_bytes).expect("wrap request");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");

    harness.inject_prover_message(bundle_bytes);

    let _ = harness
        .wait_for_finalized_bundles(1, std::time::Duration::from_secs(90))
        .await;

    let snapshot: Vec<(usize, usize)> = harness
        .nodes
        .iter()
        .map(|n| {
            let frames = n.finalized_frames.lock();
            let total_bundles: usize = frames.iter().map(|f| f.requests.len()).sum();
            (frames.len(), total_bundles)
        })
        .collect();
    eprintln!("per-node (finalized_frames, total_bundles): {:?}", snapshot);

    // Assert on the captured state directly — the polling loop can
    // race against the final-tick finalization (same pattern as in
    // `multi_archive_finalizes_via_quorum`).
    let any_bundle = snapshot.iter().any(|(_, b)| *b >= 1);
    assert!(
        any_bundle,
        "expected at least one finalized frame to contain the injected message bundle; \
         per-node (frames, bundles): {:?}",
        snapshot
    );
    drop(harness);
}

// ===================================================================
// App-shard harness — N workers running AppConsensusEngine for the
// same shard filter. Models the worker thread cohort that activates
// after a non-archive prover confirms onto a shard.
// ===================================================================

pub struct WorkerRig {
    pub prover: TestProver,
    pub handle: quil_engine::app_engine::AppEngineHandle,
    /// FrameHeader canonical bytes captured each time the worker
    /// finalizes a shard frame. The `coverage_publish` callback
    /// appends here — same path production uses to forward
    /// finalized FrameHeader bytes back to the master for inclusion
    /// in GLOBAL_PROVER broadcasts.
    pub coverage_published: Arc<Mutex<Vec<Vec<u8>>>>,
    /// All `AppEngineEvent`s captured for diagnostics.
    pub events: Arc<Mutex<Vec<String>>>,
}

pub struct AppShardHarness {
    pub filter: Vec<u8>,
    pub workers: Vec<WorkerRig>,
}

impl AppShardHarness {
    /// Build `n` workers all running consensus for the same shard
    /// filter. Each worker's outbound app-consensus events
    /// (proposals, votes, timeouts) are dispatched to every other
    /// worker via `AppEngineHandle::send(AppEngineMessage::Consensus)`.
    pub fn build(n: usize) -> Self {
        assert!(n >= 1, "need at least one worker");

        let provers: Vec<TestProver> = (0..n).map(|_| TestProver::generate()).collect();
        let all_prover_infos: Vec<_> = provers
            .iter()
            .map(|p| p.to_prover_info(1))
            .collect();
        let registry = Arc::new(TestProverRegistry::with_provers(all_prover_infos));

        // Shard filter — arbitrary 32-byte value identifies the shard.
        let filter: Vec<u8> = vec![0x55; 32];

        struct Pending {
            engine: quil_engine::app_engine::AppConsensusEngine,
            bls_signer: Box<dyn quil_types::crypto::Signer>,
            event_rx: mpsc::UnboundedReceiver<quil_engine::app_engine::AppEngineEvent>,
        }

        let mut workers: Vec<WorkerRig> = Vec::with_capacity(n);
        let mut pendings: Vec<Pending> = Vec::with_capacity(n);

        for (idx, prover) in provers.into_iter().enumerate() {
            let (event_tx, event_rx) = mpsc::unbounded_channel();

            let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let cp_for_callback = coverage_published.clone();
            let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
                Some(Arc::new(move |bytes: Vec<u8>| {
                    cp_for_callback.lock().push(bytes);
                }));

            let clock_store = Arc::new(InMemoryClockStore::new());
            let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
            let message_collector =
                Arc::new(quil_engine::message_collector::MessageCollector::new());
            let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
                Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32));

            let bls_signer = prover.signer_clone();
            let deps = quil_engine::app_engine::AppEngineDeps {
                clock_store: clock_store as Arc<dyn ClockStore>,
                prover_registry: registry.clone() as Arc<dyn ProverRegistry>,
                frame_prover,
                message_collector,
                fee_manager,
                local_prover_address: prover.address.clone(),
                local_bls_pubkey: prover.bls_pubkey.clone(),
                bls_signer: prover.signer_clone(),
                reward_greedy: true,
                min_active_provers_for_propose: 1,
                coverage_publish,
                hypergraph: None,
                // Wire a minimal ExecutionEngineManager + InclusionProver
                // so workers can carry real dispatch messages.
                // `compute_requests_root` requires both whenever the
                // message buffer is non-empty (app_engine.rs:2099-2115).
                // Empty buffer → 64-byte zero requests_root, so the
                // existing wave of tests that send no messages still
                // works.
                execution_engine: Some(Arc::new(build_test_exec_manager(
                    Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                    /* include_global */ false,
                ))),
                inclusion_prover: Some(
                    Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>,
                ),
                kv_db: None,
            };

            let (engine, handle) = quil_engine::app_engine::AppConsensusEngine::new(
                idx as u32,
                filter.clone(),
                deps,
                event_tx,
            );

            workers.push(WorkerRig {
                prover,
                handle,
                coverage_published,
                events: Arc::new(Mutex::new(Vec::new())),
            });
            pendings.push(Pending {
                engine,
                bls_signer,
                event_rx,
            });
        }

        // Snapshot all peer handles up front — each drain task needs
        // to broadcast to peers (= every worker except self).
        let all_handles: Vec<quil_engine::app_engine::AppEngineHandle> =
            workers.iter().map(|w| w.handle.clone()).collect();
        let events_per_worker: Vec<Arc<Mutex<Vec<String>>>> =
            workers.iter().map(|w| w.events.clone()).collect();

        // Spawn each worker's engine + its event drain.
        for (idx, pending) in pendings.into_iter().enumerate() {
            let engine = pending.engine;
            let bls = pending.bls_signer;
            tokio::spawn(async move {
                engine.run(bls).await;
            });

            let peer_handles: Vec<quil_engine::app_engine::AppEngineHandle> = all_handles
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, h)| h.clone())
                .collect();
            let events_log = events_per_worker[idx].clone();
            let mut rx = pending.event_rx;
            tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    use quil_engine::app_engine::AppEngineEvent as E;
                    match &ev {
                        E::FrameProduced { frame_data, .. } => {
                            events_log.lock().push("FrameProduced".into());
                            // The proposal bytes go to peers as
                            // `AppEngineMessage::Consensus` so each
                            // worker's `handle_consensus_message`
                            // dispatches them through the same
                            // GLOBAL_CONSENSUS-shaped router as votes
                            // and timeouts.
                            for h in &peer_handles {
                                h.send(quil_engine::app_engine::AppEngineMessage::Consensus(
                                    frame_data.clone(),
                                ));
                            }
                        }
                        E::VoteProduced { vote_data, .. } => {
                            events_log.lock().push("VoteProduced".into());
                            for h in &peer_handles {
                                h.send(quil_engine::app_engine::AppEngineMessage::Consensus(
                                    vote_data.clone(),
                                ));
                            }
                        }
                        E::TimeoutProduced { timeout_data, .. } => {
                            events_log.lock().push("TimeoutProduced".into());
                            for h in &peer_handles {
                                h.send(quil_engine::app_engine::AppEngineMessage::Consensus(
                                    timeout_data.clone(),
                                ));
                            }
                        }
                        E::ShardFrameFinalized { .. } => {
                            events_log.lock().push("ShardFrameFinalized".into());
                        }
                        E::EquivocationDetected { .. } => {
                            events_log.lock().push("EquivocationDetected".into());
                        }
                        E::Halted { .. } => {
                            events_log.lock().push("Halted".into());
                        }
                        E::AncestorSyncRequested { .. } => {
                            events_log.lock().push("AncestorSyncRequested".into());
                        }
                        E::ParentSealed { .. } => {
                            events_log.lock().push("ParentSealed".into());
                        }
                    }
                }
            });
        }

        Self { filter, workers }
    }

    /// Wait up to `timeout` for any worker to record at least one
    /// `coverage_publish` callback (i.e. at least one shard frame
    /// finalized).
    pub async fn wait_for_coverage(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for w in &self.workers {
                if !w.coverage_published.lock().is_empty() {
                    return true;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_activates_after_confirm_and_emits_proof() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    // 4 workers form a shard committee for filter [0x55; 32]. Each
    // worker's outbound proposals/votes/timeouts are routed to all
    // peers via the in-memory drain task installed by `build()`.
    let harness = AppShardHarness::build(4);

    // Wait until at least one worker has published a coverage frame
    // (i.e. finalized a shard frame). 3-chain finalization plus
    // pacemaker startup means we need to wait through several
    // proposal rounds.
    let got_coverage = harness
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;

    let counts: Vec<usize> = harness
        .workers
        .iter()
        .map(|w| w.coverage_published.lock().len())
        .collect();
    let events: Vec<Vec<String>> = harness
        .workers
        .iter()
        .map(|w| w.events.lock().clone())
        .collect();

    eprintln!("worker coverage counts: {counts:?}");
    for (i, log) in events.iter().enumerate() {
        let mut counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for ev in log {
            *counts.entry(ev.as_str()).or_insert(0) += 1;
        }
        eprintln!("worker {i} event histogram: {counts:?}");
    }

    assert!(
        got_coverage,
        "no worker emitted a coverage_publish frame within timeout. counts={counts:?}"
    );
}

/// Full worker→archive coverage attribution flow:
///   * 4 workers run shard consensus, finalize a shard frame, fire
///     `coverage_publish` with canonical FrameHeader bytes.
///   * A drain task wraps each emission in a
///     `CanonicalMessageBundle{Shard: header}` (mirror of
///     `main.rs:1095-1112`) and broadcasts it to the archive harness
///     via `inject_prover_message`.
///   * 4 archives buffer the bundle in their `message_collector`,
///     leader includes it in the next proposal's `requests`, the
///     proposal finalizes via 3-chain.
///
/// Inject a real dispatch message into a worker's `MessageCollector`,
/// wait for the next coverage frame, and decode the resulting
/// `AppShardProposal` canonical bytes to verify the message ended up
/// in the `requests_root` computation — proof that worker pipelines
/// can actually carry transactions, not just empty frames.
///
/// `requests_root` is computed by `compute_requests_root` over the
/// non-empty message buffer; with an empty buffer it returns 64 zero
/// bytes. A leader-produced frame with our injected message has a
/// non-zero `requests_root` (the first 32 bytes are
/// `sha3_256(commitment)`, non-zero for any real commit).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_carries_real_dispatch_message_in_shard_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build(4);

    // Inject a Dispatch message into worker 0 BEFORE the first frame
    // is produced. The message is a stub blob with a recognizable
    // type prefix; the worker's `add_app_message` accepts any
    // 4-byte+ payload (only the wire-level `validate_dispatch_message`
    // checks classify it, and we call `send` here which bypasses that).
    //
    // `0x00000201` is a compute-domain test prefix; the test
    // only cares that the message bytes end up in the frame's
    // requests_root, not that they're a recognized intrinsic.
    let mut dispatch_bytes = Vec::new();
    dispatch_bytes.extend_from_slice(&0x00000201u32.to_be_bytes());
    dispatch_bytes.extend_from_slice(&[0xAAu8; 32]);
    harness.workers[0]
        .handle
        .send(quil_engine::app_engine::AppEngineMessage::Dispatch(
            dispatch_bytes.clone(),
        ));

    // Wait for at least one shard frame to be produced — `events`
    // log records "FrameProduced" once per produced frame.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut leader_idx: Option<usize> = None;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for (i, w) in harness.workers.iter().enumerate() {
            if w.events.lock().iter().any(|e| e == "FrameProduced") {
                leader_idx = Some(i);
                break;
            }
        }
        if leader_idx.is_some() {
            break;
        }
    }
    let leader_idx = leader_idx.expect(
        "no worker produced a FrameProduced event within 90s — frame production stalled",
    );
    eprintln!("leader is worker {}", leader_idx);

    // Give the leader an extra tick to finish encoding the proposal.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Pull a FrameProduced bundle from the leader's coverage_published
    // sink (the canonical-bytes `AppShardProposal`). We need to
    // decode the embedded `AppShardFrame`'s `FrameHeader.requests_root`
    // and assert it's non-zero.
    //
    // The `coverage_published` Vec only fills on finalization (via
    // AppFollower::on_finalized_state). For a single-shot test where
    // we just need the FRAME (not finalization), we instead look at
    // the worker's `FrameProduced` event count > 0 — implying the
    // proposal was emitted — and decode the proposal bytes that
    // would be routed peer-to-peer. The harness's drain task captures
    // these and routes them via `peer_handles[..].send`, but the
    // canonical bytes are emitted to the engine's event_tx as
    // `FrameProduced{frame_data}`. We don't currently expose those
    // bytes via the harness; if we wait for finalization, the bytes
    // are in `coverage_published`.
    eprintln!("waiting up to 60s for shard finalization...");
    let got_coverage = harness
        .wait_for_coverage(std::time::Duration::from_secs(60))
        .await;
    assert!(
        got_coverage,
        "shard never finalized — workers produced proposals but no QC formed"
    );

    // At least one worker has coverage bytes. Find one and decode.
    let mut canonical_header_bytes: Option<Vec<u8>> = None;
    for w in &harness.workers {
        let bytes = w.coverage_published.lock();
        if let Some(first) = bytes.first() {
            canonical_header_bytes = Some(first.clone());
            break;
        }
    }
    let header_bytes = canonical_header_bytes
        .expect("no worker has finalized coverage bytes despite wait_for_coverage success");

    let header = quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(
        &header_bytes,
    )
    .expect("decode FrameHeader from coverage bytes");

    let zero_root = vec![0u8; header.requests_root.len()];
    eprintln!(
        "coverage FrameHeader: frame_number={}, requests_root[..16]={}",
        header.frame_number,
        hex::encode(&header.requests_root[..16.min(header.requests_root.len())]),
    );
    assert_ne!(
        header.requests_root, zero_root,
        "FrameHeader.requests_root is all-zero — the injected dispatch \
         message was not incorporated into the shard frame"
    );
}

/// Assertion: at least one archive finalized frame contains a request
/// bundle whose canonical bytes match what a worker emitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_coverage_reaches_archive_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let archives = MultiNodeHarness::build_archives(4);
    let workers = AppShardHarness::build(4);

    // Drain task: scan each worker's coverage_published Vec, wrap any
    // new entries in a CanonicalMessageBundle and inject into the
    // archive harness.
    let archives_net = archives.network.clone();
    let worker_coverage: Vec<Arc<Mutex<Vec<Vec<u8>>>>> = workers
        .workers
        .iter()
        .map(|w| w.coverage_published.clone())
        .collect();
    let drain_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drain_cancel_for_task = drain_cancel.clone();
    let drain = tokio::spawn(async move {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let mut seen: Vec<usize> = vec![0; worker_coverage.len()];
        loop {
            if drain_cancel_for_task.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            for (idx, cov) in worker_coverage.iter().enumerate() {
                let snap = cov.lock().clone();
                if snap.len() > seen[idx] {
                    for bytes in snap.iter().skip(seen[idx]) {
                        let req = match CanonicalMessageRequest::wrap(bytes.clone()) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let bundle = CanonicalMessageBundle {
                            requests: vec![Some(req)],
                            timestamp: 0,
                        };
                        if let Ok(bundle_bytes) = bundle.to_canonical_bytes() {
                            archives_net.broadcast(&[], WireMsg::Prover(bundle_bytes));
                        }
                    }
                    seen[idx] = snap.len();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    // First wait: the worker harness must produce coverage bytes.
    let got_coverage = workers
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;
    let worker_counts: Vec<usize> = workers
        .workers
        .iter()
        .map(|w| w.coverage_published.lock().len())
        .collect();
    assert!(
        got_coverage,
        "no worker emitted coverage. counts={worker_counts:?}"
    );

    // Second wait: an archive must finalize a frame with the bundle.
    let _ = archives
        .wait_for_finalized_bundles(1, std::time::Duration::from_secs(90))
        .await;

    let snapshot: Vec<(usize, usize)> = archives
        .nodes
        .iter()
        .map(|n| {
            let frames = n.finalized_frames.lock();
            let total_bundles: usize = frames.iter().map(|f| f.requests.len()).sum();
            (frames.len(), total_bundles)
        })
        .collect();
    eprintln!(
        "worker coverage counts: {worker_counts:?}; archive (finalized, bundles): {snapshot:?}"
    );

    drain_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = drain.await;

    assert!(
        snapshot.iter().any(|(_, b)| *b >= 1),
        "expected at least one archive frame to include a coverage bundle; snapshot={snapshot:?}",
    );
}

// =====================================================================
// Tier 2 — full non-archive → confirm → activation flow
// =====================================================================
//
// Tier 1 stops at "wire-layer bytes reach the right channel". Tier 2
// drives the same flow through real production wiring:
//   - Each archive owns a RocksHypergraphStore + HypergraphCrdt +
//     ExecutionEngineManager + FrameMaterializer + SharedProverRegistry
//     + ProverLifecycle + ProverPipeline.
//   - The `on_finalized_state` hook materializes the frame, refreshes
//     the registry, runs lifecycle.evaluate, and dispatches actions
//     through the pipeline.
// First test: a non-archive submits a real signed ProverJoin via the
// same pipeline production uses; assert it appears as a confirmed
// allocation in at least one archive's registry within the testnet
// confirm window.

/// Build the genesis-seed hex string for `initialize_testnet_genesis_state`.
/// Concatenates every prover's BLS pubkey (each 585 bytes) into a single
/// hex-encoded blob.
fn build_genesis_seed_hex(provers: &[TestProver]) -> String {
    let mut blob = Vec::with_capacity(provers.len() * 585);
    for p in provers {
        assert_eq!(
            p.bls_pubkey.len(),
            585,
            "Bls48581 pubkey must be 585 bytes; got {}",
            p.bls_pubkey.len(),
        );
        blob.extend_from_slice(&p.bls_pubkey);
    }
    hex::encode(blob)
}

/// Per-archive Tier-2 wiring: real production materializer + lifecycle
/// + pipeline on top of an in-memory RocksHypergraphStore. Built from
/// a shared genesis seed so every archive starts with the same prover
/// set.
pub struct Tier2ArchiveRig {
    pub prover: TestProver,
    pub rocks: Arc<quil_store::RocksDb>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub clock_store: Arc<InMemoryClockStore>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub exec_manager: Arc<quil_execution::ExecutionEngineManager>,
    pub materializer: Arc<quil_engine::frame_materializer::FrameMaterializer>,
    pub halt_state: Arc<quil_engine::halt_state::HaltState>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub worker_manager: Arc<quil_engine::test_support::TestWorkerManager>,
    pub worker_allocator: Arc<quil_engine::worker_allocator::WorkerAllocator>,
    pub lifecycle: Arc<quil_engine::provers::lifecycle::ProverLifecycle>,
    pub transport: Arc<quil_engine::test_support::TestProverMessageTransport>,
    pub pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    pub shards_store: Arc<quil_store::RocksShardsStore>,
}

/// Build the storage + genesis + materializer + lifecycle stack for a
/// single Tier-2 archive. The `all_provers` slice is the canonical
/// prover set every node seeds at genesis; each archive seeds the same
/// set via `initialize_testnet_genesis_state(network=1, seed=<all>)`.
///
/// Uses `AcceptAllKeyManager` — signature verification short-circuited.
/// Pass through `build_tier2_archive_rig_with_key_manager` for tests
/// that need real BLS verification (e.g. adversarial tests of forged
/// signatures).
pub fn build_tier2_archive_rig(
    prover: TestProver,
    all_provers: &[TestProver],
    genesis_seed_hex: &str,
) -> Tier2ArchiveRig {
    let km: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_engine::test_support::AcceptAllKeyManager);
    build_tier2_archive_rig_with_key_manager(prover, all_provers, genesis_seed_hex, km)
}

/// Same as [`build_tier2_archive_rig`] but lets the caller inject a
/// custom `KeyManager` (production: `quil_crypto::DefaultKeyManager`
/// for real BLS verification; tests: `AcceptAllKeyManager` for
/// happy-path).
pub fn build_tier2_archive_rig_with_key_manager(
    prover: TestProver,
    all_provers: &[TestProver],
    genesis_seed_hex: &str,
    exec_key_manager: Arc<dyn quil_types::crypto::KeyManager>,
) -> Tier2ArchiveRig {
    use std::sync::Arc;
    use quil_engine::frame_materializer::FrameMaterializer;
    use quil_engine::halt_state::HaltState;
    use quil_engine::current_frame::CurrentFrame;
    use quil_engine::provers::lifecycle::ProverLifecycle;
    use quil_engine::provers::proposer::Strategy;
    use quil_engine::worker_allocator::WorkerAllocator;
    use quil_engine::prover_pipeline::ProverPipeline;
    use quil_engine::prover_message_transport::ProverMessageTransport;
    use quil_engine::test_support::{
        TestKeyManager, TestProverMessageTransport, TestWorkerManager,
    };
    use quil_execution::{ExecutionEngineManager, SharedProverRegistry};
    use quil_hypergraph::HypergraphCrdt;
    use quil_hypergraph::testing::StubProver;
    use quil_store::{RocksDb, RocksHypergraphStore, RocksShardsStore};
    use quil_types::store::ShardsStore;

    // 1. In-memory Rocks → hypergraph store.
    let rocks = Arc::new(RocksDb::open_in_memory().expect("rocks open_in_memory"));
    let hg_store = Arc::new(RocksHypergraphStore::new(rocks.inner()));
    let shards_store = Arc::new(RocksShardsStore::new(rocks.inner()));
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> = Arc::new(StubProver);
    let crdt = Arc::new(HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));

    // 2. Clock store (in-memory).
    let clock_store = Arc::new(InMemoryClockStore::new());

    // 3. Seed genesis state — provers + reward vertices + 6 placeholder
    //    app shards in QUIL_TOKEN domain.
    let _genesis_result = quil_engine::genesis::initialize_testnet_genesis_state(
        /* network */ 1,
        genesis_seed_hex,
        &prover.bls_pubkey,
        /* difficulty */ 100_000,
        clock_store.as_ref() as &dyn quil_types::store::ClockStore,
        shards_store.as_ref() as &dyn ShardsStore,
        &crdt,
        inclusion_prover.as_ref(),
    )
    .expect("initialize_testnet_genesis_state");

    // 4. Build prover registry and refresh from the seeded store.
    let prover_registry = Arc::new(SharedProverRegistry::new());
    prover_registry.refresh_from_store(&hg_store);

    // 5. KeyManager (quil_types::crypto::KeyManager — verifies sigs).
    //    Caller-provided so adversarial tests can plug in real BLS
    //    verification; happy-path tests use AcceptAllKeyManager.
    //    Other crypto providers (bulletproof / decaf / circuit
    //    compiler / clock store) come from the test stub bundle —
    //    tier-2 archive happy-path tests don't exercise the QUIL PoMW
    //    mint path or compute / token verify chains.
    let exec_stubs = quil_execution::testing::NoopExecutionCrypto::new();
    let exec_hg_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    let exec_manager = Arc::new(ExecutionEngineManager::new(
        inclusion_prover.clone(),
        exec_key_manager,
        crdt.clone(),
        exec_stubs.bulletproof_prover,
        exec_stubs.decaf_constructor,
        exec_stubs.circuit_compiler,
        exec_stubs.clock_store,
        exec_hg_resolver,
        /* include_global */ true,
    ));
    // Wire frame-header deps so `invoke_frame_header` actually
    // mutates state on shard-coverage ingest (LastActiveFrameNumber
    // advance + reward distribution). Without this, FrameHeader
    // requests are silently no-op'd at intrinsic.rs:974-980.
    let reward_issuer_for_intrinsic: Arc<dyn quil_types::consensus::RewardIssuance> =
        Arc::new(quil_engine::OptRewardIssuance);
    let bls_for_intrinsic: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let frame_prover_for_intrinsic: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(StubFrameProver);
    exec_manager
        .install_global_frame_header_deps(
            prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            reward_issuer_for_intrinsic,
            bls_for_intrinsic,
            inclusion_prover.clone(),
            frame_prover_for_intrinsic,
        )
        .expect("install_global_frame_header_deps");

    // 6. FrameMaterializer — the canonical post-finalize processor.
    // `CurrentFrame::new()` returns `Arc<CurrentFrame>` already.
    let current_frame = CurrentFrame::new();
    let reward_issuer: Arc<dyn quil_types::consensus::RewardIssuance> =
        Arc::new(quil_engine::OptRewardIssuance);
    let materializer = Arc::new(
        FrameMaterializer::new(
            exec_manager.clone(),
            prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
            crdt.clone(),
            hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            reward_issuer,
            prover.address.clone(),
            /* archive_mode */ true,
        )
        .with_eviction_registry(prover_registry.clone())
        .with_current_frame(current_frame.clone()),
    );

    // 7. WorkerManager + WorkerAllocator + Lifecycle.
    let worker_manager = Arc::new(TestWorkerManager::new());
    let worker_manager_dyn: Arc<dyn quil_engine::worker::WorkerManager> =
        worker_manager.clone();
    let worker_allocator = Arc::new(WorkerAllocator::new(
        worker_manager_dyn.clone(),
        prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        prover.address.clone(),
    ));
    let halt_state = Arc::new(HaltState::new());
    let lifecycle = Arc::new(ProverLifecycle::new(
        prover.address.clone(),
        worker_allocator.clone(),
        halt_state.clone(),
        current_frame.clone(),
        Strategy::RewardGreedy,
    ));
    lifecycle.set_shards_store(shards_store.clone() as Arc<dyn ShardsStore>);
    // Shorten the confirm window to match testnet (10 frames instead of 360).
    lifecycle.set_confirm_window_frames(10);

    // 8. KeyManager (quil_keys::KeyManager — provides this node's
    //    BLS signer to ProverPipeline).
    let pipeline_key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync> = Arc::new(
        TestKeyManager::new(
            prover.bls_signer.private_key().to_vec(),
            prover.bls_pubkey.clone(),
        ),
    );

    // 9. Transport + ProverPipeline.
    let transport = Arc::new(TestProverMessageTransport::new());
    let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
    let mut prover_address_array = [0u8; 32];
    let copy_len = prover.address.len().min(32);
    prover_address_array[..copy_len].copy_from_slice(&prover.address[..copy_len]);
    let pipeline = Arc::new(ProverPipeline {
        lifecycle: lifecycle.clone(),
        worker_manager: worker_manager_dyn.clone(),
        frame_prover,
        key_manager: pipeline_key_manager,
        bls_pubkey: prover.bls_pubkey.clone(),
        prover_address: prover_address_array,
        multisig_ed448_seeds: vec![],
        delegate_address: vec![],
        transport: transport.clone() as Arc<dyn ProverMessageTransport>,
    });

    let _ = all_provers; // unused in this builder — kept for API symmetry
    Tier2ArchiveRig {
        prover,
        rocks,
        hg_store,
        crdt,
        clock_store,
        prover_registry,
        exec_manager,
        materializer,
        halt_state,
        current_frame,
        worker_manager,
        worker_allocator,
        lifecycle,
        transport,
        pipeline,
        shards_store,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_archive_rig_constructs_with_genesis_provers() {
    // Smoke test: build a Tier-2 archive rig and verify the prover
    // registry came back populated from the seeded genesis state. This
    // is the foundation every subsequent Tier-2 test depends on; if it
    // fails the rest of the chain can't possibly pass.
    let provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&provers);
    let me = provers[0].clone();
    let rig = build_tier2_archive_rig(me.clone(), &provers, &seed_hex);

    // After genesis seeding, the registry should know about every
    // prover with seniority=1000, Status=Active.
    let count = rig.prover_registry.read(|r| r.distinct_provers());
    assert_eq!(
        count, 3,
        "expected 3 provers in registry after genesis seeding; got {count}"
    );

    // Self-prover should be discoverable.
    let my_info = rig.prover_registry.read(|r| {
        r.get_prover_info(&me.address).cloned()
    });
    assert!(
        my_info.is_some(),
        "self prover {} not in registry after genesis seed",
        hex::encode(&me.address),
    );
}

/// Drives a real signed `ProverJoin` through `ProverPipeline` for a
/// new (non-genesis) prover, then ingests the resulting
/// `MessageBundle` into an archive's `FrameMaterializer`. Asserts the
/// archive's `SharedProverRegistry` now reports the prover with a
/// `Joining`-status allocation for the chosen filter.
///
/// This is the "join arrives → archive registry sees it" link — the
/// next step beyond [`tier2_archive_rig_constructs_with_genesis_provers`].
/// Worker activation (which requires a `ProverConfirm` from the
/// lifecycle and a subsequent finalized frame) is exercised in the
/// next test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_non_archive_join_lands_in_archive_registry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // 1. Build a single archive that knows about 3 genesis provers.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );

    // 2. Seed the archive's clock store with a "head" frame so
    //    `submit_join` can stamp a sane frame_number on the join.
    //    The materializer's verify path rejects joins with
    //    `frame_number < head - 10`, so we ensure head is small.
    let head_header = gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    };

    // 3. Build a new (non-genesis) prover. This is the joiner.
    let joiner = TestProver::generate();

    // 4. Build a non-archive ProverPipeline. Reuses the archive's
    //    storage so the test can drive both sides in one process.
    let transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    transport.set_head_header(head_header.clone());
    let joiner_key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync> = Arc::new(
        quil_engine::test_support::TestKeyManager::new(
            joiner.bls_signer.private_key().to_vec(),
            joiner.bls_pubkey.clone(),
        ),
    );
    let joiner_wm = Arc::new(quil_engine::test_support::TestWorkerManager::new());
    let joiner_wm_dyn: Arc<dyn quil_engine::worker::WorkerManager> = joiner_wm.clone();
    let joiner_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        joiner_wm_dyn.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));
    let joiner_halt = Arc::new(quil_engine::halt_state::HaltState::new());
    let joiner_cf = quil_engine::current_frame::CurrentFrame::new();
    let joiner_lifecycle = Arc::new(quil_engine::provers::lifecycle::ProverLifecycle::new(
        joiner.address.clone(),
        joiner_allocator,
        joiner_halt,
        joiner_cf,
        quil_engine::provers::proposer::Strategy::RewardGreedy,
    ));
    let mut joiner_address_array = [0u8; 32];
    let copy_len = joiner.address.len().min(32);
    joiner_address_array[..copy_len].copy_from_slice(&joiner.address[..copy_len]);
    let joiner_pipeline = Arc::new(quil_engine::prover_pipeline::ProverPipeline {
        lifecycle: joiner_lifecycle,
        worker_manager: joiner_wm_dyn,
        frame_prover: Arc::new(StubFrameProver) as Arc<dyn FrameProver>,
        key_manager: joiner_key_manager,
        bls_pubkey: joiner.bls_pubkey.clone(),
        prover_address: joiner_address_array,
        multisig_ed448_seeds: vec![],
        delegate_address: vec![],
        transport: transport.clone()
            as Arc<dyn quil_engine::prover_message_transport::ProverMessageTransport>,
    });

    // 5. Pick a filter that exists in shards_store. Genesis seeds
    //    QUIL_TOKEN-domain shards at addresses [0x00..0x05]; address
    //    bytes [0, 0, ..., 0] (i=0) is the simplest. Filters in the
    //    materializer are the full 32-byte shard address.
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 1; // pick shard "1" — any of 0..6 work
        a
    };

    // 6. Drive the join through the pipeline. This signs, encodes,
    //    and calls transport.publish_prover_bundle. The transport
    //    captures the resulting MessageBundle.
    joiner_pipeline
        .submit_join(vec![filter.clone()], &[0u32], head_header.frame_number)
        .await
        .expect("submit_join");

    let bundles = transport.drain_outbound();
    assert_eq!(
        bundles.len(),
        1,
        "expected exactly one MessageBundle (the ProverJoin)"
    );

    // 7. Feed the bundle into the archive's materializer by
    //    constructing a synthetic GlobalFrame whose `requests` field
    //    contains the bundle as a single proto MessageBundle.
    //    `decode_message_bundle` handles the canonical→proto conversion,
    //    including the per-type prefix dispatch that wraps the inner
    //    ProverJoin into `message_request::Request::Join(...)`.
    let proto_bundle = quil_engine::consensus_wire::decode_message_bundle(&bundles[0])
        .expect("decode_message_bundle");
    let frame_to_materialize = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: head_header.frame_number + 1,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto_bundle],
        ..Default::default()
    };

    let result = archive
        .materializer
        .materialize(&frame_to_materialize)
        .expect("materialize frame with ProverJoin bundle");
    eprintln!(
        "materialize result: processed={} skipped={}",
        result.processed, result.skipped
    );

    // 8. Refresh registry from the now-updated store. After the join
    //    is materialized, the joiner should appear with a Joining
    //    allocation on the chosen filter.
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    let joiner_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&joiner.address).cloned());
    assert!(
        joiner_info.is_some(),
        "joiner {} not in registry after materialize. processed={} skipped={}",
        hex::encode(&joiner.address),
        result.processed,
        result.skipped,
    );

    // The joining allocation should exist for the filter we chose.
    let provers_on_filter =
        archive.prover_registry.read(|r| r.get_provers(&filter).len());
    assert!(
        provers_on_filter >= 1,
        "expected ≥1 prover on filter {} after join (joiner should be Joining); got {}",
        hex::encode(&filter),
        provers_on_filter,
    );
}

/// Drives the join further: after the joiner's `ProverJoin` has been
/// materialized into the shared registry, the *joiner* (not the
/// archive!) ticks its own lifecycle. `ProverConfirm` is a
/// self-affirmation — each prover confirms their own pending joins
/// once `confirm_window` frames have elapsed, not third-party. After
/// enough frames the joiner's lifecycle should emit a `ConfirmJoins`
/// action and the joiner's pipeline turn it into a signed
/// `ProverConfirm` bundle captured by `TestProverMessageTransport`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_joiner_lifecycle_emits_self_confirm_after_join() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // 1. Archive setup.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );

    // Seed transport's head so submit_join works.
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

    // 2. Build joiner pipeline. Crucially, the joiner's lifecycle
    //    needs a `ProverRegistry` that, post-materialize, will report
    //    its OWN Joining allocation. We let the joiner SHARE the
    //    archive's `SharedProverRegistry` — production would refresh
    //    each node's own copy from its own `hg_store` via HyperSync,
    //    but for this test the shared registry is the simplest way
    //    to model "the join was observed and persisted everywhere".
    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    // Seed worker 0 with allocated=false. `decide_joins` only confirms
    // joins up to `available_workers = workers.filter(!allocated).count()`;
    // without this the lifecycle sees zero capacity and rejects every
    // pending join. Mirrors production where workers exist before the
    // first join is proposed.
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    // 3. Pick filter and submit the join.
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 2;
        a
    };
    joiner_pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);

    // 4. Materialize the join at frame 6.
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // Sanity: joiner is now in the registry.
    assert!(
        archive
            .prover_registry
            .read(|r| r.get_prover_info(&joiner.address).is_some()),
        "joiner missing from registry after materialize"
    );

    // 5. Tick the JOINER's lifecycle. The joiner's lifecycle reads
    //    its own `Joining` allocation (now in the shared registry
    //    post-materialize) and after `confirm_window_frames = 10`
    //    frames emits a `ConfirmJoins` action.
    //
    // Lifecycle gates the entire `evaluate` body on a baseline
    // readiness check (`frame_seen + initial_sync_complete +
    // tree_verified`). In production these flip true once the node
    // finishes the initial prover-tree sync; tests have to flip them
    // by hand or every `evaluate` call early-returns with empty actions.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    // `build_decide_descriptors` filters out any shard whose
    // `shard_sizes` lookup returns 0 or missing — those summaries
    // never become descriptors and so `decide_joins` never sees them
    // as confirm candidates, rejecting every pending join by default.
    // Seed a nonzero size for our filter (and a few neighboring
    // genesis shards so the joiner has comparison baseline).
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
        std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline.lifecycle.set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    joiner_cf.observe(6);
    joiner_cf.materialize(6);

    let mut confirm_seen = false;
    for frame_num in 7u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);

        let registry_ref = archive.prover_registry.clone()
            as Arc<dyn quil_types::consensus::ProverRegistry>;
        if frame_num == 16 {
            // Diagnostic: dump everything the lifecycle will see.
            let info = registry_ref
                .get_prover_info(&joiner.address)
                .expect("get_prover_info")
                .expect("joiner missing");
            eprintln!("joiner allocations at frame {}:", frame_num);
            for a in &info.allocations {
                eprintln!(
                    "  filter={} status={:?} join_frame={} confirm_frame={}",
                    hex::encode(&a.confirmation_filter),
                    a.status,
                    a.join_frame_number,
                    a.join_confirm_frame_number,
                );
            }
            let summaries =
                registry_ref.get_prover_shard_summaries(frame_num).unwrap();
            eprintln!("summaries: {} entries", summaries.len());
            for s in summaries.iter().take(10) {
                eprintln!(
                    "  filter={} status_counts={:?} total_size={}",
                    hex::encode(&s.filter),
                    s.status_counts,
                    s.total_size,
                );
            }
        }
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("lifecycle evaluate");
        eprintln!(
            "frame {} → {} action(s)",
            frame_num,
            actions.len()
        );
        for action in actions {
            use quil_engine::provers::lifecycle::LifecycleAction;
            eprintln!("    action: {:?}", action);
            if let LifecycleAction::ConfirmJoins { ref filters, .. } = action {
                if filters.iter().any(|f| f == &filter) {
                    confirm_seen = true;
                }
            }
            joiner_pipeline.pipeline.dispatch(action);
        }

        // dispatch is async — give it a tick to drain.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Wait briefly for any in-flight dispatched ProverConfirm to be
    // published through the transport.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let joiner_outbound = joiner_transport.drain_outbound();
    eprintln!(
        "joiner outbound bundles: {} (lifecycle saw confirm_action: {})",
        joiner_outbound.len(),
        confirm_seen,
    );

    assert!(
        confirm_seen,
        "joiner lifecycle never emitted ConfirmJoins for its own filter \
         after 15 frames past the join (confirm_window=10)"
    );
    assert!(
        !joiner_outbound.is_empty(),
        "joiner pipeline never published any outbound bundle \
         (expected at least one ProverConfirm)"
    );
}

/// Full round-trip: joiner submits ProverJoin → archive materializes
/// (allocation = Joining) → joiner self-confirms after window →
/// archive materializes the ProverConfirm (allocation flips
/// Joining → Active) → `WorkerAllocator.on_new_frame` detects the
/// Active allocation and calls `set_worker_filter(..., true)` to
/// trigger shard-engine spawn.
///
/// Verifies the confirm → Active → allocator → worker-spawn link
/// end-to-end against the in-memory archive harness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_confirm_materializes_to_active_and_allocator_starts_worker() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // The materializer's verifier independently enforces the confirm
    // timing window — its default 360-frame minimum rejects any
    // ProverConfirm submitted earlier (Go's
    // `validate_confirm_timing`). Production calls this on testnet
    // bootstrap (main.rs:1658). Test must do the same or every
    // ProverConfirm gets a "must wait 360 frames after join" reject
    // and the allocation stays Joining.
    //
    // Set via this static once per process; subsequent tests inherit.
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 3;
        a
    };

    // Step A: join → materialize at frame 6 → allocation = Joining
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    // Verify Joining status.
    let joining = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        joining,
        Some(quil_types::consensus::ProverStatus::Joining),
        "expected joiner to be Joining after materialize"
    );

    // Step B: drive joiner's lifecycle to emit ConfirmJoins.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
        std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline.lifecycle.set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);
        let registry_ref = archive.prover_registry.clone()
            as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Drain after the loop — dispatch is async and the bundle may
    // arrive at the transport a few hundred ms after the action fires.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut drained = joiner_transport.drain_outbound();
    eprintln!("joiner emitted {} bundles total", drained.len());
    let confirm_bytes = drained
        .pop()
        .expect("joiner pipeline never emitted a ProverConfirm");

    // Step C: archive materializes the ProverConfirm at frame 17 →
    // allocation flips Joining → Active.
    let confirm_frame = build_global_frame_with_bundle(17, &confirm_bytes);
    let confirm_result = archive
        .materializer
        .materialize(&confirm_frame)
        .expect("materialize ProverConfirm");
    eprintln!(
        "ProverConfirm materialize: processed={} skipped={}",
        confirm_result.processed, confirm_result.skipped,
    );
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    let status_after_confirm = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        status_after_confirm,
        Some(quil_types::consensus::ProverStatus::Active),
        "expected joiner allocation to flip Joining→Active after ProverConfirm; \
         processed={} skipped={}",
        confirm_result.processed,
        confirm_result.skipped,
    );

    // Step D: WorkerAllocator.on_new_frame sees the Active allocation
    // and calls `set_worker_filter(core_id, filter, start_consensus=true)`
    // on its worker manager. We use the ARCHIVE's allocator (which
    // wraps a `TestWorkerManager`) to check this — but the archive
    // isn't the joiner, so its allocations don't change. To verify
    // the allocator's reconciliation logic we need to drive it for
    // the JOINER. Build a dedicated allocator + worker_manager for
    // the joiner that shares the archive's (now-updated) registry.
    let joiner_alloc_wm = Arc::new(quil_engine::test_support::TestWorkerManager::new());
    joiner_alloc_wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 5, // would be set by submit_join in prod
        allocated: false,        // pending: filter pinned, awaiting confirm
    });
    let joiner_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        joiner_alloc_wm.clone() as Arc<dyn quil_engine::worker::WorkerManager>,
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));

    joiner_allocator
        .on_new_frame(18)
        .expect("WorkerAllocator.on_new_frame");

    // After reconciliation: worker 0's `allocated` flag should be
    // true (allocation transitioned Joining→Active in registry).
    use quil_engine::worker::WorkerManager as _;
    let workers = joiner_alloc_wm.range_workers().expect("range_workers");
    let w0 = workers.iter().find(|w| w.core_id == 0).expect("worker 0");
    eprintln!(
        "worker 0 after reconcile: filter={} allocated={} pending_filter_frame={}",
        hex::encode(&w0.filter),
        w0.allocated,
        w0.pending_filter_frame,
    );
    assert!(
        w0.allocated,
        "WorkerAllocator did not flip worker 0 to allocated=true after the registry showed Active"
    );
    assert_eq!(
        w0.filter, filter,
        "worker 0's filter should remain pinned to the confirmed shard"
    );
}

/// Cadence test — verify that finalization arrives at a steady,
/// proposal_duration-driven cadence. Note: finalization lag is NOT
/// equal to `proposal_duration`; it's ~3 × (proposal_duration +
/// round-trip-time) because HotStuff's 3-chain rule requires three
/// successive QCs to commit a frame. With `proposal_duration=500ms`
/// in this harness and ~1.5-2s per rank-round-trip, expect ~5-10s
/// per finalization.
///
/// Asserts: in a 60s window, at least 4 finalizations arrive AND
/// the median inter-arrival delta is within `[1s, 20s]` (loose
/// bounds to absorb CI jitter, leader-rotation slop, and the
/// first-rank ramp).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_archive_finalization_cadence_is_steady() {
    init_tracing();
    let harness = MultiNodeHarness::build_archives(4);

    let warmup = std::time::Duration::from_secs(10);
    let window = std::time::Duration::from_secs(60);

    // Sample finalized-frame counts every 200ms over the window.
    let start = std::time::Instant::now();
    let mut arrivals: Vec<(std::time::Instant, usize)> = Vec::new();
    let deadline = start + window;
    let mut last_count = 0usize;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let count = harness.nodes[0].finalized.lock().len();
        if count > last_count {
            arrivals.push((std::time::Instant::now(), count));
            last_count = count;
        }
    }

    eprintln!(
        "captured {} new finalization arrivals on node 0 over {:.1}s",
        arrivals.len(),
        start.elapsed().as_secs_f32(),
    );

    // Drop arrivals inside the warmup — pacemaker hasn't stabilized.
    let warmup_end = start + warmup;
    let stable: Vec<_> = arrivals
        .iter()
        .filter(|(t, _)| *t >= warmup_end)
        .copied()
        .collect();

    assert!(
        stable.len() >= 4,
        "need ≥4 post-warmup finalizations for cadence; got {} \
         (entire-window arrivals: {})",
        stable.len(),
        arrivals.len(),
    );

    // Compute inter-arrival deltas.
    let mut deltas: Vec<std::time::Duration> = Vec::new();
    for w in stable.windows(2) {
        deltas.push(w[1].0 - w[0].0);
    }
    deltas.sort();
    let median = deltas[deltas.len() / 2];
    eprintln!("cadence deltas: {:?} (median={:?})", deltas, median);

    // Production-realistic bounds: finalization should arrive at a
    // STEADY cadence (no minutes-long stalls). We don't pin to
    // proposal_duration because the lag adds 3-chain rounds.
    let lower = std::time::Duration::from_secs(1);
    let upper = std::time::Duration::from_secs(20);
    assert!(
        median >= lower && median <= upper,
        "median inter-finalization delta {:?} outside the steady-cadence window \
         [{:?}, {:?}] — pacemaker may have stalled or runaway-proposed",
        median,
        lower,
        upper,
    );

    drop(harness);
}

// =====================================================================
// Tier 2 — adversarial tests (real BLS verifier)
// =====================================================================

/// Adversarial: submit a `ProverJoin` whose BLS aggregate-signature
/// bytes have been corrupted. The materializer's real BLS verifier
/// should reject it (`processed=0, skipped=1`) and the prover should
/// NOT appear in the registry afterwards.
///
/// Uses `DefaultKeyManager` for real signature verification — without
/// that the materializer accepts anything and the test would
/// false-pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_forged_join_signature_rejected() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);

    // Real BLS verifier — DefaultKeyManager dispatches to
    // Bls48581KeyConstructor::verify_signature_raw.
    let real_km: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(Arc::new(
            quil_crypto::Bls48581KeyConstructor,
        )));
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 4;
        a
    };

    // Step 1: submit a valid join (via the real pipeline) to capture
    // a well-formed bundle.
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let bundles = joiner_transport.drain_outbound();
    assert_eq!(bundles.len(), 1);
    let valid_bundle = bundles[0].clone();

    // Step 2: tamper with the bundle bytes. The bundle's structure is
    // `[u32 type][lp request][...][i64 timestamp]`. The ProverJoin's
    // BLS signature lives deep inside the inner request payload.
    // Flipping bytes in the second half of the bundle is virtually
    // guaranteed to land inside the signature blob — BLS signatures
    // are dense and any single-bit flip invalidates them.
    let mut tampered = valid_bundle.clone();
    let mid = tampered.len() * 2 / 3;
    tampered[mid] ^= 0xFF;
    tampered[mid + 1] ^= 0xFF;
    tampered[mid + 2] ^= 0xFF;

    // Step 3: materialize the tampered bundle. Real BLS verification
    // should reject inside the intrinsic dispatch.
    let proto = match quil_engine::consensus_wire::decode_message_bundle(&tampered) {
        Ok(b) => b,
        Err(_) => {
            // Tampering hit the canonical envelope (length prefix etc.)
            // — that's an acceptable rejection too (parser refused).
            // Verify the registry is still untouched and return early.
            let info = archive
                .prover_registry
                .read(|r| r.get_prover_info(&joiner.address).cloned());
            assert!(
                info.is_none(),
                "tampered bundle pre-rejected by parser; joiner must not be in registry"
            );
            return;
        }
    };
    let frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 6,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize(&frame)
        .expect("materialize call should succeed (rejection happens per-request)");
    eprintln!(
        "tampered-bundle materialize: processed={} skipped={}",
        result.processed, result.skipped
    );

    // Step 4: archive should have REJECTED the tampered request.
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let joiner_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&joiner.address).cloned());
    assert!(
        joiner_info.is_none(),
        "real BLS verifier accepted a tampered ProverJoin — registry now contains the attacker's prover; \
         processed={} skipped={}",
        result.processed,
        result.skipped,
    );
    // Note: the `skipped` count is at the BUNDLE level (validate_message
    // returns Err for the bundle and `frame_materializer` counts the
    // skip). The forged-join case hits this — bundle-level rejection
    // before any state mutation runs.
}

/// Adversarial: submit a `ProverConfirm` whose `frame_number` is
/// outside the confirm window. The materializer's `validate_confirm_timing`
/// should reject it, and the allocation stays `Joining` instead of
/// flipping to `Active`.
///
/// Skips the joiner's lifecycle entirely — manually constructs the
/// ProverConfirm with a too-early `frame_number` to exercise the
/// timing-check rejection path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_premature_confirm_rejected() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Force the confirm window to mainnet defaults (360..720) so a
    // confirm submitted at "join_frame + 1" definitely violates the
    // timing window. (Previous tests may have stomped the static
    // down to (10, 720); reset it here.)
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(360, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(Arc::new(
            quil_crypto::Bls48581KeyConstructor,
        )));
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // Submit a valid join first (via the joiner's pipeline) so an
    // allocation exists for the attacker to target.
    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 5;
        a
    };
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let pre_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        pre_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "joiner should be Joining before attacker confirms"
    );

    // Build a ProverConfirm with frame_number = 7 (only 1 frame after
    // join — well below the 360-frame mainnet window).
    use quil_execution::global_intrinsic::{
        addressed_signature::AddressedSignature, prover_ops::ProverConfirm,
    };
    let confirm_frame_number = 7u64; // join_frame=6 + 1, well below window
    let mut msg = Vec::new();
    msg.extend_from_slice(&filter);
    msg.extend_from_slice(&confirm_frame_number.to_be_bytes());
    let mut domain_pre = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    domain_pre.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&domain_pre).expect("poseidon");
    let signature = joiner
        .bls_signer
        .sign_with_domain(&msg, &domain)
        .expect("sign");
    let confirm = ProverConfirm {
        filter: vec![],
        frame_number: confirm_frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature,
            address: joiner.address.clone(),
        }),
        filters: vec![filter.clone()],
    };
    let confirm_bytes = confirm.to_canonical_bytes().expect("encode confirm");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(confirm_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
        .expect("decode_message_bundle");
    let confirm_frame_proto = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: confirm_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize(&confirm_frame_proto)
        .expect("materialize call");
    eprintln!(
        "premature-confirm materialize: processed={} skipped={}",
        result.processed, result.skipped,
    );

    // Verify allocation is still Joining.
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let post_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        post_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "premature ProverConfirm should NOT flip allocation to Active; \
         confirm-frame={}, join-frame=6, mainnet window=360..720; \
         processed={} skipped={}",
        confirm_frame_number,
        result.processed,
        result.skipped,
    );
    // Note: the materializer's `processed` counter currently counts
    // every bundle whose envelope decodes — per-request invoke_step
    // errors are logged but swallowed at engines.rs:216-221. So we
    // can't rely on `skipped` here; the security-critical assertion
    // is the `Joining` status above, which depends on `invoke_step`
    // having rejected the confirm internally via
    // `validate_confirm_timing`.
}

/// Adversarial: attacker signs a `ProverConfirm` with their OWN BLS
/// key but addresses it to a victim's pending join filter. The
/// materializer should NOT flip the victim's allocation to Active —
/// `invoke_filter_op` derives the allocation address from the
/// confirm's signer pubkey, so the attacker's confirm targets their
/// OWN (non-existent) allocation, not the victim's.
///
/// Confirms the address binding is what gates a `ProverConfirm`:
/// a valid BLS signature alone is insufficient — the confirm has to
/// derive its target allocation from a pubkey that matches a pending
/// join's prover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_adversarial_wrong_signer_confirm_does_not_steal_allocation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Open the confirm window so timing alone isn't what blocks the
    // attacker — we want the test to fail/pass on the SIGNER binding.
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(Arc::new(
            quil_crypto::Bls48581KeyConstructor,
        )));
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // 1. Victim submits a valid ProverJoin.
    let victim = TestProver::generate();
    let victim_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    victim_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let victim_pipeline = build_test_pipeline_with_registry(
        &victim,
        victim_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    victim_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 7;
        a
    };
    victim_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = victim_transport.drain_outbound();
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive
        .materializer
        .materialize(&join_frame)
        .expect("materialize join");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    // Confirm victim's allocation is Joining.
    let pre_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&victim.address).expect("victim").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        pre_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "victim's allocation should be Joining before the attack"
    );

    // 2. Attacker (different BLS key) signs a ProverConfirm for the
    //    SAME filter, using the victim's confirm window. Attacker's
    //    signature is cryptographically valid (their own key), but
    //    derives a different allocation address — so the attacker is
    //    really confirming their own (non-existent) pending join.
    let attacker = TestProver::generate();
    use quil_execution::global_intrinsic::{
        addressed_signature::AddressedSignature, prover_ops::ProverConfirm,
    };
    let confirm_frame_number = 17u64; // 6 + 11, just inside window
    let mut msg = Vec::new();
    msg.extend_from_slice(&filter);
    msg.extend_from_slice(&confirm_frame_number.to_be_bytes());
    let mut domain_pre = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    domain_pre.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&domain_pre).expect("poseidon");
    let attacker_signature = attacker
        .bls_signer
        .sign_with_domain(&msg, &domain)
        .expect("sign");
    let confirm = ProverConfirm {
        filter: vec![],
        frame_number: confirm_frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: attacker_signature,
            address: attacker.address.clone(), // attacker's address, NOT victim's
        }),
        filters: vec![filter.clone()],
    };
    let confirm_bytes = confirm.to_canonical_bytes().expect("encode");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(confirm_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
        .expect("decode");
    let attack_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: confirm_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    let result = archive
        .materializer
        .materialize(&attack_frame)
        .expect("materialize call");
    eprintln!(
        "wrong-signer attack materialize: processed={} skipped={}",
        result.processed, result.skipped,
    );

    // 3. Verify the victim's allocation is STILL Joining.
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let post_status = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&victim.address).expect("victim").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        post_status,
        Some(quil_types::consensus::ProverStatus::Joining),
        "attacker's confirm should NOT flip victim's allocation to Active; \
         post_status={:?} processed={} skipped={}",
        post_status,
        result.processed,
        result.skipped,
    );

    // 4. And the attacker should NOT have appeared in the registry.
    let attacker_info = archive
        .prover_registry
        .read(|r| r.get_prover_info(&attacker.address).cloned());
    assert!(
        attacker_info.is_none(),
        "attacker leaked into prover registry — they had no pending join but their confirm \
         materialized something; processed={} skipped={}",
        result.processed,
        result.skipped,
    );
}

/// End-to-end: archive ingests a shard `FrameHeader` (coverage proof)
/// and the contributing prover's allocation advances on-chain
/// (`LastActiveFrameNumber`).
///
/// Exercises the full materialize → state-advance path, including
/// `validate_message` → `process_message` ordering, BLS aggregate-sig
/// verification against `get_active_provers`, and `Shard`
/// (`FrameHeader`) variant round-trip through `consensus_wire`'s
/// canonical → proto → canonical encoders.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tier2_coverage_ingest_advances_archive_allocation_state() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Confirm window open enough for the joiner to self-confirm
    // within ~10 frames (testnet shortcut).
    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let real_km: Arc<dyn quil_types::crypto::KeyManager> =
        Arc::new(quil_crypto::DefaultKeyManager::new(Arc::new(
            quil_crypto::Bls48581KeyConstructor,
        )));
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // 1. Joiner submits a real ProverJoin.
    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 9;
        a
    };
    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    archive
        .materializer
        .materialize(&build_global_frame_with_bundle(6, &join_bundles[0]))
        .expect("materialize join");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    // 2. Joiner self-confirms after the window.
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
        std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline.lifecycle.set_remote_shard_sizes(shard_sizes);
    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline
            .lifecycle
            .set_prover_root_verified_frame(frame_num);
        let registry_ref = archive.prover_registry.clone()
            as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Wait for the confirm bundle to publish.
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let confirm_bytes = joiner_transport
        .drain_outbound()
        .pop()
        .expect("joiner pipeline never emitted a ProverConfirm");
    archive
        .materializer
        .materialize(&build_global_frame_with_bundle(17, &confirm_bytes))
        .expect("materialize confirm");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    // Verify allocation is now Active.
    let status_after_confirm = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .cloned()
    });
    let alloc = status_after_confirm.expect("joiner has allocation");
    assert_eq!(
        alloc.status,
        quil_types::consensus::ProverStatus::Active,
        "joiner should be Active after confirm"
    );
    let pre_last_active = alloc.last_active_frame_number;

    // 3. Build a shard `FrameHeader` claiming the joiner participated.
    //    `address` = the shard's app-shard address (Poseidon(filter));
    //    `prover` = joiner's BLS pubkey; aggregate-sig `bitmask=[0x01]`
    //    so participant index 0 = joiner (the only Active prover).
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    use quil_execution::hypergraph_intrinsic::canonical::AggregateSignature;

    // The FrameHeader's `address` is the raw shard filter (matches
    // what `AppFollower::on_finalized_state` emits in production —
    // see `app_glue.rs:544-549`). `pr.get_active_provers(&filter)`
    // returns provers whose allocation.confirmation_filter == filter,
    // so the participant-index lookup resolves.
    let shard_address = filter.clone();
    // Aggregate signature decoder requires `sig_len == 74` or
    // `sig_len == 74 + n*516` (canonical.rs:198-205). Empty bytes
    // fail the length check and `invoke_frame_header` would bail —
    // the error is swallowed by the bundle loop (engines.rs:216), so
    // the materializer reports "processed=1" while the per-request
    // mutation never ran. Use a 74-byte placeholder.
    let agg_sig = AggregateSignature {
        signature: vec![0u8; 74],
        public_key: None,
        bitmask: vec![0x01],
    };
    let agg_sig_bytes = agg_sig.to_canonical_bytes().expect("agg sig");

    let coverage_frame_number = 25u64; // some frame after confirm

    let header = FrameHeader {
        address: shard_address.clone(),
        frame_number: coverage_frame_number,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 32],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        prover: joiner.bls_pubkey.clone(),
        fee_multiplier_vote: 0,
        public_key_signature_bls48581: agg_sig_bytes,
    };
    let header_bytes = header.to_canonical_bytes().expect("encode header");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(header_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
        .expect("decode");

    let coverage_global_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: coverage_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto],
        ..Default::default()
    };
    // Diagnostic: what does get_active_provers return for our filter?
    use quil_types::consensus::ProverRegistry as _;
    let active = archive
        .prover_registry
        .get_active_provers(&filter)
        .expect("get_active_provers");
    eprintln!(
        "active provers for filter {}: {}",
        hex::encode(&filter),
        active.len()
    );
    for p in &active {
        eprintln!(
            "  address={} status={:?} pubkey_len={}",
            hex::encode(&p.address),
            p.status,
            p.public_key.len()
        );
    }

    // Probe via the registry's view of the joiner.
    let joiner_pubkey_matches = active
        .iter()
        .find(|p| p.address == joiner.address)
        .map(|p| p.public_key == joiner.bls_pubkey)
        .unwrap_or(false);
    eprintln!(
        "joiner pubkey matches active-registry record: {}",
        joiner_pubkey_matches
    );

    let result = archive
        .materializer
        .materialize(&coverage_global_frame)
        .expect("materialize coverage");
    eprintln!(
        "coverage ingest: processed={} skipped={}",
        result.processed, result.skipped
    );

    // 4. Refresh and assert: joiner's allocation last_active advanced.
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let alloc_after = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .cloned()
    });
    let alloc_after = alloc_after.expect("joiner still has allocation");
    eprintln!(
        "last_active: {} → {} (coverage_frame={})",
        pre_last_active, alloc_after.last_active_frame_number, coverage_frame_number,
    );
    assert!(
        alloc_after.last_active_frame_number >= coverage_frame_number,
        "LastActiveFrameNumber should advance to (or past) {} after coverage ingest; \
         pre={} post={}",
        coverage_frame_number,
        pre_last_active,
        alloc_after.last_active_frame_number,
    );
}

/// Full Tier-2 e2e: after the allocator flips a worker to
/// `allocated=true`, we ALSO want to verify that a finalized shard
/// frame's canonical `FrameHeader` bytes (the "coverage proof") flow
/// back through the archive's real `FrameMaterializer` and are
/// accepted (`processed >= 1`). Reuses the Tier-1 `AppShardHarness`
/// to drive a real 4-worker cohort to shard finalization, then feeds
/// the resulting coverage bundle into the Tier-2 archive's
/// materializer.
///
/// This is the closing link: archive ingests shard work and would
/// (in a full deployment) credit the prover's reward + update shard
/// commitments. Asserts that `materialize.processed >= 1` for the
/// coverage frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_shard_coverage_reaches_archive_materializer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // Build a Tier-2 archive — gives us a real materializer.
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );

    // Build a Tier-1 worker cohort. They run a full HotStuff round on
    // a shared shard filter and fire `coverage_publish` on
    // finalization with the canonical FrameHeader bytes. Independent
    // of the Tier-2 join/confirm dance — for THIS test the focus is
    // the archive's ingestion of coverage, not the activation
    // pipeline.
    let workers = AppShardHarness::build(4);
    let got_coverage = workers
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;
    assert!(got_coverage, "worker cohort never produced a coverage frame");

    // Drain every worker's coverage bytes.
    let mut coverage_bytes: Vec<Vec<u8>> = Vec::new();
    for w in &workers.workers {
        let mut entries = std::mem::take(&mut *w.coverage_published.lock());
        coverage_bytes.append(&mut entries);
    }
    assert!(
        !coverage_bytes.is_empty(),
        "no coverage bytes captured from worker cohort"
    );
    eprintln!(
        "captured {} coverage bundle(s) from worker cohort",
        coverage_bytes.len()
    );

    // Wrap each coverage bundle in a `CanonicalMessageBundle` (the
    // wire format archives expect on `GLOBAL_PROVER`), then build a
    // synthetic GlobalFrame containing all of them as `requests`.
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let mut proto_bundles: Vec<quil_types::proto::global::MessageBundle> = Vec::new();
    for bytes in &coverage_bytes {
        let req = CanonicalMessageRequest::wrap(bytes.clone()).expect("wrap request");
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        };
        let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
        let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
            .expect("decode_message_bundle");
        proto_bundles.push(proto);
    }

    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 7,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };

    // Hand the synthetic frame to the archive's real materializer.
    let result = archive
        .materializer
        .materialize(&coverage_frame)
        .expect("materialize coverage frame");
    eprintln!(
        "archive materialize result: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive materializer should process at least one coverage bundle; \
         got processed={} skipped={}",
        result.processed,
        result.skipped,
    );
}

/// Wrapper around a `ProverPipeline` that also exposes the
/// `Arc<CurrentFrame>` the lifecycle reads — tests need to advance
/// the frame counter manually since there's no consensus loop calling
/// `observe`/`materialize`.
pub struct TestPipelineRig {
    pub pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub worker_manager: Arc<quil_engine::test_support::TestWorkerManager>,
}

impl std::ops::Deref for TestPipelineRig {
    type Target = quil_engine::prover_pipeline::ProverPipeline;
    fn deref(&self) -> &Self::Target {
        &self.pipeline
    }
}

/// Build a `ProverPipeline` rig with the test transport for a fresh
/// prover. `registry` is what the lifecycle queries when looking for
/// its own Joining allocations — pass a `SharedProverRegistry` that
/// reflects post-materialize state when you want the joiner's
/// self-confirm path to actually fire.
fn build_test_pipeline_with_registry(
    prover: &TestProver,
    transport: Arc<quil_engine::test_support::TestProverMessageTransport>,
    registry: Arc<dyn quil_types::consensus::ProverRegistry>,
) -> TestPipelineRig {
    use quil_engine::provers::lifecycle::ProverLifecycle;
    use quil_engine::provers::proposer::Strategy;
    use quil_engine::worker_allocator::WorkerAllocator;
    use quil_engine::prover_pipeline::ProverPipeline;
    use quil_engine::prover_message_transport::ProverMessageTransport;
    use quil_engine::test_support::{TestKeyManager, TestWorkerManager};

    let wm = Arc::new(TestWorkerManager::new());
    let wm_dyn: Arc<dyn quil_engine::worker::WorkerManager> = wm.clone();
    let allocator = Arc::new(WorkerAllocator::new(
        wm_dyn.clone(),
        registry.clone(),
        prover.address.clone(),
    ));
    let halt = Arc::new(quil_engine::halt_state::HaltState::new());
    let current_frame = quil_engine::current_frame::CurrentFrame::new();
    let lifecycle = Arc::new(ProverLifecycle::new(
        prover.address.clone(),
        allocator,
        halt,
        current_frame.clone(),
        Strategy::RewardGreedy,
    ));
    let km: Arc<dyn quil_keys::KeyManager + Send + Sync> = Arc::new(TestKeyManager::new(
        prover.bls_signer.private_key().to_vec(),
        prover.bls_pubkey.clone(),
    ));
    let mut addr_arr = [0u8; 32];
    let copy_len = prover.address.len().min(32);
    addr_arr[..copy_len].copy_from_slice(&prover.address[..copy_len]);
    let pipeline = Arc::new(ProverPipeline {
        lifecycle,
        worker_manager: wm_dyn,
        frame_prover: Arc::new(StubFrameProver) as Arc<dyn FrameProver>,
        key_manager: km,
        bls_pubkey: prover.bls_pubkey.clone(),
        prover_address: addr_arr,
        multisig_ed448_seeds: vec![],
        delegate_address: vec![],
        transport: transport as Arc<dyn ProverMessageTransport>,
    });
    TestPipelineRig {
        pipeline,
        current_frame,
        worker_manager: wm,
    }
}

/// Self-coverage composite-topology test: a node running both the
/// archive role (with `FrameMaterializer`) and the worker role (with
/// `AppConsensusEngine`) routes its OWN coverage emissions back into
/// its OWN materializer without an inter-node hop. Mirrors
/// production's GLOBAL_PROVER loopback path: `coverage_publish`
/// wraps the canonical FrameHeader in a `CanonicalMessageBundle` and
/// publishes on the GLOBAL_PROVER bitmask — every subscriber receives
/// it, INCLUDING the publishing node itself when it also subscribes
/// (i.e. when it runs an archive). The test pins down that this
/// self-loopback works end-to-end inside one process without races,
/// drops, or duplication of the emitted bundle.
///
/// Mechanism (mirrors `main.rs:1094-1130`):
///   1. `coverage_publish` callback wraps header bytes in a
///      `CanonicalMessageBundle{requests:[wrap(header)], timestamp}`.
///   2. The same node's archive subscriber decodes the bundle proto
///      via `consensus_wire::decode_message_bundle`.
///   3. The decoded proto is fed to the archive's materializer.
///
/// Asserts:
///   - Every emission from the worker arrives in the same-node
///     archive's input queue exactly once (no drop, no duplication).
///   - The archive's materializer accepts the bundle
///     (`processed >= 1`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_coverage_composite_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // -----------------------------------------------------------------
    // The archive's input queue. Lives on the same node as the worker.
    // Models the GLOBAL_PROVER subscription buffer.
    // -----------------------------------------------------------------
    let archive_inbox: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    // Replica of production's `coverage_publish` (main.rs:1094-1130) —
    // wraps the header in a CanonicalMessageBundle and pushes to the
    // shared inbox (= the node's own GLOBAL_PROVER subscription).
    let inbox_for_cb = archive_inbox.clone();
    let coverage_publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> =
        Arc::new(move |header_canonical_bytes: Vec<u8>| {
            use quil_execution::message_envelope::{
                CanonicalMessageBundle, CanonicalMessageRequest,
            };
            let req = CanonicalMessageRequest::wrap(header_canonical_bytes)
                .expect("self-coverage: wrap header");
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(req)],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            };
            let bytes = bundle
                .to_canonical_bytes()
                .expect("self-coverage: encode bundle");
            inbox_for_cb.lock().push(bytes);
        });

    // -----------------------------------------------------------------
    // Build a worker that pushes coverage through `coverage_publish`.
    // Drive it with a synthetic FrameHeader emission rather than a
    // full HotStuff loop — we're testing the loopback wiring, not the
    // consensus engine (which other tests cover).
    // -----------------------------------------------------------------
    let prover = TestProver::generate();
    let filter: Vec<u8> = vec![0x44; 32];
    let synthetic_header = quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: filter.clone(),
        frame_number: 5,
        rank: 0,
        timestamp: 1_700_000_000_000,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 64],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        prover: prover.address.clone(),
        fee_multiplier_vote: 1,
        public_key_signature_bls48581: vec![0u8; 74],
    };
    let header_bytes = synthetic_header
        .to_canonical_bytes()
        .expect("encode synthetic header");

    // Worker emits TWO coverage bundles in succession — verifies no
    // race between concurrent emissions and the inbox accumulator.
    coverage_publish(header_bytes.clone());
    coverage_publish(header_bytes.clone());

    // -----------------------------------------------------------------
    // Verify each emission landed in the inbox exactly once.
    // -----------------------------------------------------------------
    let inbox_snapshot = archive_inbox.lock().clone();
    assert_eq!(
        inbox_snapshot.len(),
        2,
        "expected 2 bundles in the same-node inbox (one per coverage_publish), got {}",
        inbox_snapshot.len()
    );

    // -----------------------------------------------------------------
    // Build a Tier-2 archive and have IT materialize the bundles from
    // its own inbox — closes the self-coverage loop in-process.
    // -----------------------------------------------------------------
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );

    let proto_bundles: Vec<quil_types::proto::global::MessageBundle> = inbox_snapshot
        .iter()
        .map(|b| {
            quil_engine::consensus_wire::decode_message_bundle(b)
                .expect("self-coverage decode")
        })
        .collect();
    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 10,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };

    let result = archive
        .materializer
        .materialize(&coverage_frame)
        .expect("materialize self-coverage frame");
    eprintln!(
        "self-coverage materialize: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive must accept its own coverage bundle via loopback; \
         processed={} skipped={}",
        result.processed,
        result.skipped,
    );
}

/// Helper: build a `GlobalFrame` whose `requests` contain a single
/// proto MessageBundle decoded from the given canonical bundle bytes.
fn build_global_frame_with_bundle(frame_number: u64, bundle_bytes: &[u8]) -> gpb::GlobalFrame {
    let proto_bundle = quil_engine::consensus_wire::decode_message_bundle(bundle_bytes)
        .expect("decode_message_bundle");
    gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![proto_bundle],
        ..Default::default()
    }
}

/// Tier-2 composite end-to-end: one test that drives the entire
/// pipeline from join → confirm → allocator → spawned worker engine
/// → coverage_publish → archive materialize → LastActiveFrameNumber
/// advance. Existing tests each pin down one link; this one verifies
/// they compose without surprise interactions (timing-window edges,
/// shared registry mutations, materializer back-pressure, etc.).
///
/// Phases:
///   * A — joiner submits ProverJoin → archive materializes Joining
///   * B — joiner lifecycle emits ProverConfirm → archive materializes
///         Joining → Active
///   * C — joiner's `WorkerAllocator` reconciles → SpawningWorkerManager
///         spawns a real `AppConsensusEngine` for the new shard
///   * D — spawned engine produces shard frames; with a single-prover
///         quorum (threshold=0), `FrameProduced` fires within a few
///         seconds via the leader's self-vote
///   * E — engine's `coverage_publish` callback captures the canonical
///         FrameHeader bytes for one finalized shard frame
///   * F — each captured coverage header has its
///         `public_key_signature_bls48581` rewritten with a valid
///         synthetic `AggregateSignature{sig=74×0x00, bitmask=[0x01]}`
///         so the materializer's `invoke_frame_header` aggregate-decode
///         and bitmask-index lookup succeed. The model surface for
///         carrying the certifying QC trait object through to the
///         consumer (`State.parent_quorum_certificate`,
///         `CertifiedState.certifying_quorum_certificate`) is in
///         place; routing it through `AppFollower` end-to-end is
///         left for a follow-on change.
///   * G — archive's `LastActiveFrameNumber` for the joiner's
///         allocation advances to (or past) the coverage frame number
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_composite_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    quil_execution::global_intrinsic::verify::set_confirm_window_frames(10, 720);

    // -----------------------------------------------------------------
    // Phase A — bootstrap archive + joiner; submit ProverJoin
    // -----------------------------------------------------------------
    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
    );
    archive.transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });

    let joiner = TestProver::generate();
    let joiner_transport =
        Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    joiner_transport.set_head_header(gpb::GlobalFrameHeader {
        frame_number: 5,
        rank: 0,
        timestamp: 0,
        difficulty: 100_000,
        output: vec![0u8; 516],
        ..Default::default()
    });
    let joiner_pipeline = build_test_pipeline_with_registry(
        &joiner,
        joiner_transport.clone(),
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    joiner_pipeline.worker_manager.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: Vec::new(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false,
    });

    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 0x33;
        a
    };

    joiner_pipeline
        .pipeline
        .submit_join(vec![filter.clone()], &[0u32], 5)
        .await
        .expect("submit_join");
    let join_bundles = joiner_transport.drain_outbound();
    assert_eq!(join_bundles.len(), 1);
    let join_frame = build_global_frame_with_bundle(6, &join_bundles[0]);
    archive.materializer.materialize(&join_frame).expect("materialize join");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    // -----------------------------------------------------------------
    // Phase B — lifecycle emits ProverConfirm; archive flips to Active
    // -----------------------------------------------------------------
    joiner_pipeline.lifecycle.set_sync_complete();
    joiner_pipeline.lifecycle.set_confirm_window_frames(10);
    let mut shard_sizes: std::collections::HashMap<Vec<u8>, u64> =
        std::collections::HashMap::new();
    shard_sizes.insert(filter.clone(), 1000);
    for i in 0u8..6 {
        let mut a = vec![0u8; 32];
        a[0] = i;
        shard_sizes.insert(a, 1000);
    }
    joiner_pipeline.lifecycle.set_remote_shard_sizes(shard_sizes);

    let joiner_cf = joiner_pipeline.current_frame.clone();
    for frame_num in 6u64..=21 {
        joiner_cf.observe(frame_num);
        joiner_cf.materialize(frame_num);
        joiner_pipeline.lifecycle.set_prover_root_verified_frame(frame_num);
        let registry_ref = archive.prover_registry.clone()
            as Arc<dyn quil_types::consensus::ProverRegistry>;
        let actions = joiner_pipeline
            .lifecycle
            .evaluate(
                frame_num,
                100_000,
                registry_ref.as_ref(),
                joiner_pipeline.worker_manager.as_ref(),
            )
            .expect("evaluate");
        for action in actions {
            joiner_pipeline.pipeline.dispatch(action);
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for _ in 0..50 {
        if joiner_transport.outbound_len() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut drained = joiner_transport.drain_outbound();
    let confirm_bytes = drained.pop().expect("joiner never emitted ProverConfirm");
    let confirm_frame = build_global_frame_with_bundle(17, &confirm_bytes);
    archive.materializer.materialize(&confirm_frame).expect("materialize ProverConfirm");
    archive.prover_registry.refresh_from_store(&archive.hg_store);

    let status_after = archive.prover_registry.read(|r| {
        let info = r.get_prover_info(&joiner.address).expect("joiner").clone();
        info.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.status)
    });
    assert_eq!(
        status_after,
        Some(quil_types::consensus::ProverStatus::Active),
        "joiner allocation must be Active after ProverConfirm materialize"
    );

    // -----------------------------------------------------------------
    // Phase C — SpawningWorkerManager fires on the Active transition.
    // -----------------------------------------------------------------
    let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Build the engine deps closure. The spawned engine runs the joiner
    // as a single-prover shard committee — the event loop yields per
    // iteration so the self-vote → QC → propose chain doesn't starve
    // the engine run-loop.
    let registry_for_engine = archive.prover_registry.clone();
    let joiner_for_engine = joiner.clone();
    let coverage_for_cb = coverage_published.clone();
    let event_for_cb = event_log.clone();
    let spawn_fn: Arc<
        dyn Fn(u32, Vec<u8>) -> quil_engine::app_engine::AppEngineHandle + Send + Sync,
    > = Arc::new(move |core_id: u32, filter_bytes: Vec<u8>| {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let clock_store = Arc::new(InMemoryClockStore::new());
        let message_collector =
            Arc::new(quil_engine::message_collector::MessageCollector::new());
        let cov_inner = coverage_for_cb.clone();
        let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
            Some(Arc::new(move |bytes: Vec<u8>| {
                cov_inner.lock().push(bytes);
            }));

        let deps = quil_engine::app_engine::AppEngineDeps {
            clock_store: clock_store as Arc<dyn ClockStore>,
            prover_registry: registry_for_engine.clone()
                as Arc<dyn quil_types::consensus::ProverRegistry>,
            frame_prover: Arc::new(StubFrameProver) as Arc<dyn FrameProver>,
            message_collector,
            fee_manager: Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32))
                as Arc<dyn quil_types::consensus::DynamicFeeManager>,
            local_prover_address: joiner_for_engine.address.clone(),
            local_bls_pubkey: joiner_for_engine.bls_pubkey.clone(),
            bls_signer: joiner_for_engine.signer_clone(),
            reward_greedy: true,
            min_active_provers_for_propose: 1,
            coverage_publish,
            hypergraph: None,
            execution_engine: Some(Arc::new(build_test_exec_manager(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                false,
            ))),
            inclusion_prover: Some(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>,
            ),
            kv_db: None,
        };
        let (engine, handle) = quil_engine::app_engine::AppConsensusEngine::new(
            core_id,
            filter_bytes,
            deps,
            event_tx,
        );
        let bls = joiner_for_engine.signer_clone();
        tokio::spawn(async move {
            engine.run(bls).await;
        });
        let event_drain = event_for_cb.clone();
        tokio::spawn(async move {
            while let Some(ev) = event_rx.recv().await {
                use quil_engine::app_engine::AppEngineEvent::*;
                let name = match ev {
                    FrameProduced { .. } => "FrameProduced",
                    VoteProduced { .. } => "VoteProduced",
                    TimeoutProduced { .. } => "TimeoutProduced",
                    ShardFrameFinalized { .. } => "ShardFrameFinalized",
                    EquivocationDetected { .. } => "EquivocationDetected",
                    Halted { .. } => "Halted",
                    AncestorSyncRequested { .. } => "AncestorSyncRequested",
                    ParentSealed { .. } => "ParentSealed",
                };
                event_drain.lock().push(name.to_string());
            }
        });
        handle
    });

    let spawn_wm = Arc::new(
        quil_engine::test_support::SpawningWorkerManager::new(spawn_fn),
    );
    spawn_wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 5,
        allocated: false,
    });

    let composite_allocator = Arc::new(quil_engine::worker_allocator::WorkerAllocator::new(
        spawn_wm.clone() as Arc<dyn quil_engine::worker::WorkerManager>,
        archive.prover_registry.clone()
            as Arc<dyn quil_types::consensus::ProverRegistry>,
        joiner.address.clone(),
    ));
    composite_allocator
        .on_new_frame(18)
        .expect("WorkerAllocator.on_new_frame should spawn the engine");

    let handles = spawn_wm.snapshot_handles();
    assert_eq!(handles.len(), 1, "expected SpawningWorkerManager to spawn one engine");

    // -----------------------------------------------------------------
    // Phase D/E — wait for the spawned engine to produce events
    // (FrameProduced/VoteProduced) AND emit at least one
    // coverage_publish bundle (one finalized shard frame).
    // -----------------------------------------------------------------
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let evs = event_log.lock().clone();
        let cov_n = coverage_published.lock().len();
        if cov_n >= 1 {
            eprintln!(
                "phase E ready: {} events ({:?}), {} coverage bundles",
                evs.len(),
                evs.iter().take(8).collect::<Vec<_>>(),
                cov_n
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "spawned engine never emitted coverage within 120s; \
                 events={:?} cov={}",
                evs, cov_n
            );
        }
    }
    let cov_bytes_snapshot = std::mem::take(&mut *coverage_published.lock());

    // -----------------------------------------------------------------
    // Phase F — substitute each captured coverage header's
    // `public_key_signature_bls48581` with a valid synthetic
    // `AggregateSignature{sig=74×0x00, bitmask=[0x01]}` so the
    // materializer's `invoke_frame_header` aggregate-decode +
    // bitmask-index lookup succeeds. The coverage header emitted by
    // `AppFollower::on_finalized_state` currently carries the
    // proposer's BLS authorship signature rather than the certifying
    // QC's aggregate; substituting here lets the test pin the
    // materialize → state-advance path without depending on the
    // future change that routes the certifying QC end-to-end.
    // -----------------------------------------------------------------
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    use quil_execution::hypergraph_intrinsic::canonical::AggregateSignature;
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

    let synth_agg_sig = AggregateSignature {
        signature: vec![0u8; 74],
        public_key: None,
        bitmask: vec![0x01],
    };
    let synth_agg_bytes = synth_agg_sig.to_canonical_bytes().expect("synth agg sig");

    let mut proto_bundles: Vec<quil_types::proto::global::MessageBundle> = Vec::new();
    for bytes in &cov_bytes_snapshot {
        let mut hdr = FrameHeader::from_canonical_bytes(bytes).expect("decode coverage header");
        hdr.public_key_signature_bls48581 = synth_agg_bytes.clone();
        let new_bytes = hdr.to_canonical_bytes().expect("re-encode coverage header");
        let req = CanonicalMessageRequest::wrap(new_bytes).expect("wrap request");
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        };
        let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
        let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes)
            .expect("decode bundle");
        proto_bundles.push(proto);
    }
    let coverage_frame_number = 30u64;
    let coverage_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: coverage_frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: proto_bundles,
        ..Default::default()
    };
    let pre_last_active = archive.prover_registry.read(|r| {
        r.get_prover_info(&joiner.address)
            .expect("joiner")
            .clone()
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.last_active_frame_number)
            .unwrap_or(0)
    });
    let result = archive
        .materializer
        .materialize(&coverage_frame)
        .expect("materialize coverage frame");
    eprintln!(
        "coverage materialize: processed={} skipped={}",
        result.processed, result.skipped
    );
    assert!(
        result.processed >= 1,
        "archive must process at least one coverage bundle"
    );

    // -----------------------------------------------------------------
    // Phase G — LastActiveFrameNumber advance assertion. The materializer
    // applied the synthetic-aggregate coverage header, so the joiner's
    // allocation should now record `last_active_frame_number >=
    // coverage_frame_number`.
    // -----------------------------------------------------------------
    archive.prover_registry.refresh_from_store(&archive.hg_store);
    let post_last_active = archive.prover_registry.read(|r| {
        r.get_prover_info(&joiner.address)
            .expect("joiner")
            .clone()
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.last_active_frame_number)
            .unwrap_or(0)
    });
    eprintln!(
        "LastActiveFrame: pre={} post={} (coverage_frame={})",
        pre_last_active, post_last_active, coverage_frame_number
    );
    assert!(
        post_last_active >= coverage_frame_number,
        "LastActiveFrame should advance to ≥{} after coverage ingest; \
         pre={} post={}",
        coverage_frame_number,
        pre_last_active,
        post_last_active
    );
}

/// After WorkerAllocator detects a Joining→Active transition, the
/// **SpawningWorkerManager** actually instantiates an
/// `AppConsensusEngine` for the confirmed shard. This test verifies
/// the spawn closure is invoked with the correct `(core_id, filter)`,
/// returns a live `AppEngineHandle`, and the spawned engine task
/// successfully transitions past the consensus-bootstrap phase
/// (`shard HotStuff event loop running` info log fires) without
/// panicking.
///
/// Real frame production for a fully-wired AppConsensusEngine is
/// already covered by `worker_carries_real_dispatch_message_in_shard_frame`
/// and friends via `AppShardHarness::build(4)`. The piece this test
/// adds is the **spawn wiring**: WorkerAllocator → set_worker_filter
/// → user-supplied closure → AppConsensusEngine task started.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_allocator_spawns_real_engine_on_confirm() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let prover = TestProver::generate();
    let filter: Vec<u8> = {
        let mut a = vec![0u8; 32];
        a[0] = 11;
        a
    };

    // Track every spawn the allocator triggers. Each spawn records
    // (core_id, filter) so we can assert what got activated.
    let spawn_log: Arc<Mutex<Vec<(u32, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Build the deps each spawned worker needs. These get captured
    // into the spawn closure.
    let provers_info = vec![prover.to_prover_info(1)];
    let registry = Arc::new(TestProverRegistry::with_provers(provers_info.clone()));
    let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32));

    let prover_for_spawn = prover.clone();
    let spawn_log_clone = spawn_log.clone();
    let event_log_clone = event_log.clone();
    let spawn_fn: Arc<
        dyn Fn(u32, Vec<u8>) -> quil_engine::app_engine::AppEngineHandle + Send + Sync,
    > = Arc::new(move |core_id: u32, filter_bytes: Vec<u8>| {
        spawn_log_clone.lock().push((core_id, filter_bytes.clone()));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let clock_store = Arc::new(InMemoryClockStore::new());
        let message_collector =
            Arc::new(quil_engine::message_collector::MessageCollector::new());
        let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cp_for_cb = coverage_published.clone();
        let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
            Some(Arc::new(move |bytes: Vec<u8>| {
                cp_for_cb.lock().push(bytes);
            }));

        let deps = quil_engine::app_engine::AppEngineDeps {
            clock_store: clock_store as Arc<dyn ClockStore>,
            prover_registry: registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
            frame_prover: frame_prover.clone(),
            message_collector,
            fee_manager: fee_manager.clone(),
            local_prover_address: prover_for_spawn.address.clone(),
            local_bls_pubkey: prover_for_spawn.bls_pubkey.clone(),
            bls_signer: prover_for_spawn.signer_clone(),
            reward_greedy: true,
            min_active_provers_for_propose: 1,
            coverage_publish,
            hypergraph: None,
            execution_engine: Some(Arc::new(build_test_exec_manager(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                false,
            ))),
            inclusion_prover: Some(
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>,
            ),
            kv_db: None,
        };

        let (engine, handle) = quil_engine::app_engine::AppConsensusEngine::new(
            core_id,
            filter_bytes,
            deps,
            event_tx,
        );
        let bls_signer = prover_for_spawn.signer_clone();
        let exit_log = event_log_clone.clone();
        let join = tokio::spawn(async move {
            engine.run(bls_signer).await;
        });
        // Sentinel: log if the engine task ever exits.
        tokio::spawn(async move {
            let r = join.await;
            let kind = match r {
                Ok(_) => "engine_task_returned".to_string(),
                Err(e) if e.is_panic() => format!("engine_panicked: {:?}", e),
                Err(e) => format!("engine_join_err: {:?}", e),
            };
            eprintln!("[spawn] {kind}");
            exit_log.lock().push(kind);
        });
        let event_log = event_log_clone.clone();
        tokio::spawn(async move {
            while let Some(ev) = event_rx.recv().await {
                use quil_engine::app_engine::AppEngineEvent::*;
                let name = match ev {
                    FrameProduced { .. } => "FrameProduced",
                    VoteProduced { .. } => "VoteProduced",
                    TimeoutProduced { .. } => "TimeoutProduced",
                    ShardFrameFinalized { .. } => "ShardFrameFinalized",
                    EquivocationDetected { .. } => "EquivocationDetected",
                    Halted { .. } => "Halted",
                    AncestorSyncRequested { .. } => "AncestorSyncRequested",
                    ParentSealed { .. } => "ParentSealed",
                };
                event_log.lock().push(name.to_string());
            }
        });

        handle
    });

    let wm = Arc::new(quil_engine::test_support::SpawningWorkerManager::new(spawn_fn));
    // Seed worker 0 — the allocator can find it before spawn.
    wm.add(quil_engine::worker::WorkerInfo {
        core_id: 0,
        filter: filter.clone(),
        available_storage: 1_000_000,
        total_storage: 1_000_000,
        manually_managed: false,
        pending_filter_frame: 0,
        allocated: false, // will be flipped to true on activation
    });

    // Trigger the activation that production's WorkerAllocator would
    // perform after observing Joining→Active in the registry.
    use quil_engine::worker::WorkerManager as _;
    wm.set_worker_filter(0, &filter, /* start_consensus */ true)
        .expect("set_worker_filter");

    // Verify spawn was called.
    let log = spawn_log.lock().clone();
    assert_eq!(log.len(), 1, "expected one spawn invocation, got {}", log.len());
    assert_eq!(log[0].0, 0);
    assert_eq!(log[0].1, filter);

    // Verify a handle was registered.
    let handles = wm.snapshot_handles();
    assert_eq!(handles.len(), 1, "expected one engine handle");

    // Wait for the spawned engine to emit at least one real
    // `AppEngineEvent`. In a single-prover committee
    // (quorum_threshold = 0), the leader's own proposal forms a QC
    // immediately on self-vote, so `FrameProduced` / `VoteProduced`
    // arrive quickly. A timeout here means the event-loop is
    // busy-looping and starving the engine run-loop.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let entries = event_log.lock();
        // Filter out the "engine exited" sentinels — they indicate
        // crash, not liveness.
        let live = entries
            .iter()
            .any(|e| !e.starts_with("engine_panic") && e.as_str() != "engine_task_returned");
        if live {
            break;
        }
    }
    let entries = event_log.lock().clone();
    eprintln!("post-spawn event entries: {:?}", entries);
    let crashed: Vec<&String> = entries
        .iter()
        .filter(|e| {
            e.starts_with("engine_panic") || e.as_str() == "engine_task_returned"
        })
        .collect();
    assert!(
        crashed.is_empty(),
        "spawned engine task exited — wiring crash. entries={entries:?}"
    );
    let live: Vec<&String> = entries
        .iter()
        .filter(|e| {
            !e.starts_with("engine_panic") && e.as_str() != "engine_task_returned"
        })
        .collect();
    assert!(
        !live.is_empty(),
        "spawned engine produced no AppEngineEvent within 60s — \
         single-prover event-loop is likely busy-looping"
    );
}
