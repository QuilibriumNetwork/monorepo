//! Shared rig helpers (generated copy) for the e2e_epoch_confirm binary.
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

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
pub fn build_test_exec_manager(
    inclusion_prover: Arc<dyn InclusionProver>,
    include_global: bool,
) -> quil_execution::ExecutionEngineManager {
    let hg_store: Arc<dyn quil_types::store::HypergraphStore> =
        Arc::new(quil_hypergraph::testing::MemStore::new());
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store,
        inclusion_prover.clone(),
    ));
    build_test_exec_manager_on(crdt, inclusion_prover, include_global)
}

/// [`build_test_exec_manager`] over a caller-supplied CRDT, as production
/// wires it: the worker's hypergraph IS the execution manager's state store.
pub fn build_test_exec_manager_on(
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    inclusion_prover: Arc<dyn InclusionProver>,
    include_global: bool,
) -> quil_execution::ExecutionEngineManager {
    let stubs = quil_execution::testing::NoopExecutionCrypto::new();
    let hg_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
    quil_execution::ExecutionEngineManager::new(
        inclusion_prover,
        stubs.key_manager.clone(),
        crdt,
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
        _storage_attestation_root: &[u8],
        global_frame_number: u64,
    ) -> QResult<gpb::FrameHeader> {
        // Match the production constructor: AppLeaderProvider fills the
        // deterministic app output after completing the header.
        Ok(gpb::FrameHeader {
            address: vec![0u8; 32],
            frame_number,
            rank: 0,
            timestamp,
            difficulty,
            output: Vec::new(),
            parent_selector: if previous_frame_output.is_empty() {
                vec![0u8; 32]
            } else {
                quil_crypto::poseidon::hash_bytes_to_32(previous_frame_output)?.to_vec()
            },
            requests_root: vec![0u8; 64],
            state_roots: vec![],
            prover: vec![0u8; 96],
            fee_multiplier_vote: 0,
            public_key_signature_bls48581: None,
            storage_attestation_root: Vec::new(),
            global_frame_number,
            storage_attestation: Vec::new(),
            fee_total: vec![0u8; 16],
            settlements: Vec::new(),
            accumulator: Vec::new(),
            spends: Vec::new(),
        })
    }

    // Accept any shard FrameHeader's signature. The stub prover produces
    // no real VDF multiproof, so the archive's per-bundle verify path
    // (which the real prover would use for BLS + multiproof) is a no-op
    // here. The aggregate-pubkey/committee check in the intrinsic still
    // runs (and is exercised by the tier-2 coverage tests, which seed the
    // worker committee into the archive registry); this only short-
    // circuits the stubbed VDF/BLS proof verification.
    fn verify_frame_header_signature(
        &self,
        _header: &gpb::FrameHeader,
        _bls: &dyn quil_types::crypto::BlsConstructor,
        _ids: Option<&[&[u8]]>,
    ) -> QResult<bool> {
        Ok(true)
    }

    fn prove_global_frame_header(
        &self,
        previous_frame: &gpb::GlobalFrameHeader,
        _commitments: &[Vec<u8>],
        prover_root: &[u8],
        _prover_aux_roots: &[Vec<u8>],
        request_root: &[u8],
        _world_state_size: u64,
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
            parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&previous_frame.output)?.to_vec(),
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

/// Build a single-signer (`bitmask=[0x01]`) shard-FrameHeader aggregate
/// signature whose DECLARED aggregate public key matches what the
/// intrinsic's attestation verifier reconstructs via
/// `bls.aggregate_public_keys([member_pubkey])`. The 74-byte `signature` is a
/// placeholder: a 74-byte single-signer attestation carries no VDF
/// multiproof, and `StubFrameProver::verify_frame_header_signature`
/// accepts it. Used by the synthetic-coverage tier-2 tests so their
/// hand-built coverage FrameHeader survives the aggregate-pubkey
/// consistency check (which only needs `member_pubkey` to be an Active
/// prover under the frame's shard filter in the verifying registry).
pub fn single_signer_agg_sig(
    member_pubkey: &[u8],
) -> quil_execution::hypergraph_intrinsic::canonical::AggregateSignature {
    use quil_types::crypto::BlsConstructor;
    let bls = quil_crypto::FalconKeyConstructor;
    let agg_pubkey = bls
        .aggregate_public_keys(&[member_pubkey])
        .expect("aggregate single member pubkey");
    quil_execution::hypergraph_intrinsic::canonical::AggregateSignature {
        signature: vec![0u8; 666],
        public_key: Some(
            quil_execution::hypergraph_intrinsic::canonical::Bls48581G2PublicKey {
                key_value: agg_pubkey,
            },
        ),
        bitmask: vec![0x01],
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
        let ctor = quil_crypto::FalconKeyConstructor;
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
        let ctor = quil_crypto::FalconKeyConstructor;
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
pub fn genesis_state_identity(genesis: &gpb::GlobalFrame) -> Vec<u8> {
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
pub fn build_signed_genesis_qc(
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

    let ctor = quil_crypto::FalconKeyConstructor;
    let pk_refs: Vec<&[u8]> = pks.iter().map(|v| v.as_slice()).collect();
    let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
    let agg = ctor.aggregate(&pk_refs, &sig_refs).expect("bls aggregate");

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

pub type NodeInbox = mpsc::UnboundedSender<WireMsg>;

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
        Self {
            base_ms: 0,
            jitter_ms: 0,
        }
    }

    /// Realistic WAN: ~80ms mean, ±50ms jitter — matches common
    /// commercial internet round-trip / 2.
    pub fn realistic_wan() -> Self {
        Self {
            base_ms: 30,
            jitter_ms: 100,
        }
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


// ===================================================================
// Tests
// ===================================================================

/// Initialize tracing once per test run. Subsequent calls are no-ops.
pub fn init_tracing() {
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
    /// Serialized `AppShardFrame` bytes from each `FullFrameProduced`
    /// event — the authoritative state-distribution payload that carries
    /// the out-of-band `StorageAttestation` on the active PoRep path.
    pub full_frames: Arc<Mutex<Vec<Vec<u8>>>>,
    /// All `AppEngineEvent`s captured for diagnostics.
    pub events: Arc<Mutex<Vec<String>>>,
    /// The worker's own shard CRDT, where its state, cursor and outgoing
    /// history commit (session harnesses only).
    pub shard: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
}

pub struct AppShardHarness {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    pub filter: Vec<u8>,
    pub workers: Vec<WorkerRig>,
}

/// Shared inputs that put the PoRep producer path LIVE for the harness:
/// a committed CRDT (vertices under the harness filter `[0x55;32]`) and a
/// global beacon frame at `global_frame_number`. Built once, cloned into
/// every worker's deps by `build_with_storage`.
pub struct StorageHarness {
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub global_frame: gpb::GlobalFrame,
}

impl StorageHarness {
    /// Seed a CRDT with a handful of committed vertices under the harness
    /// filter and a global frame at `global_frame_number` carrying a
    /// non-empty output (the ρ_N beacon source). Storage attestation is
    /// always-on, so seeding a global frame (`global_frame_number > 0`) is all
    /// it takes to engage the storage path.
    pub fn seeded(global_frame_number: u64) -> Self {
        quil_crypto::init();
        assert!(
            global_frame_number > 0,
            "storage path needs a real global anchor"
        );

        let store: Arc<dyn quil_types::store::HypergraphStore> =
            Arc::new(quil_hypergraph::testing::MemStore::new());
        let prover: Arc<dyn quil_types::crypto::InclusionProver> =
            Arc::new(quil_hypergraph::testing::StubProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, prover));
        // Filter is `[0x55;32]` (== app_address) — matches `build_inner`.
        for d in 0u8..4 {
            crdt.add_vertex(
                &quil_hypergraph::Location {
                    app_address: [0x55; 32],
                    data_address: [d; 32],
                },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();

        let global_frame = gpb::GlobalFrame {
            header: Some(gpb::GlobalFrameHeader {
                frame_number: global_frame_number,
                output: vec![0xABu8; 64],
                ..Default::default()
            }),
            requests: vec![],
        };
        Self { crdt, global_frame }
    }
}

impl AppShardHarness {
    /// Build `n` workers all running consensus for the same shard
    /// filter. Each worker's outbound app-consensus events
    /// (proposals, votes, timeouts) are dispatched to every other
    /// worker via `AppEngineHandle::send(AppEngineMessage::Consensus)`.
    pub fn build(n: usize) -> Self {
        assert!(n >= 1, "need at least one worker");
        let provers: Vec<TestProver> = (0..n).map(|_| TestProver::generate()).collect();
        let all_prover_infos: Vec<_> = provers.iter().map(|p| p.to_prover_info(1)).collect();
        let registry =
            Arc::new(TestProverRegistry::with_provers(all_prover_infos)) as Arc<dyn ProverRegistry>;
        Self::build_with_registry(provers, registry)
    }

    /// Build a worker cohort from a caller-supplied prover set and a
    /// SHARED prover registry. Used by the tier-2 coverage tests, which
    /// pass the archive's `SharedProverRegistry` (pre-seeded with these
    /// same provers as Active on the shard filter) so the committee the
    /// workers sign with is byte-identical to the one the archive's
    /// FrameHeader verifier reconstructs. `build(n)` is the standalone
    /// path: it generates fresh provers + an in-test registry.
    pub fn build_with_registry(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
    ) -> Self {
        Self::build_inner(provers, registry, None, false, None, None)
    }

    /// Build `n` workers driving the shard with commonware-simplex + Falcon
    /// (`app_consensus_cw = true`). For `n == 1` the single committee member
    /// self-proposes + self-finalizes (the `NoopAppTransport` in the engine has
    /// no peers to reach); multi-worker CW needs the gossip transport wired.
    pub fn build_cw(n: usize) -> Self {
        assert!(n >= 1, "need at least one worker");
        let provers: Vec<TestProver> = (0..n).map(|_| TestProver::generate()).collect();
        let all_prover_infos: Vec<_> = provers.iter().map(|p| p.to_prover_info(1)).collect();
        let registry =
            Arc::new(TestProverRegistry::with_provers(all_prover_infos)) as Arc<dyn ProverRegistry>;
        Self::build_inner(provers, registry, None, true, None, None)
    }

    /// Active-path PoRep variant: every worker gets a shared committed CRDT, an
    /// in-memory replica store seeded with its confirmed leaf replicas, and a
    /// global frame at `global_frame_number` (> 0) so the storage-attestation
    /// producer path is LIVE — votes carry openings and finalized frames carry
    /// a `StorageAttestation`. Storage attestation is always-on, so a non-zero
    /// global anchor is all it takes (no activation override).
    pub fn build_with_storage(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
        storage: StorageHarness,
    ) -> Self {
        Self::build_inner(provers, registry, Some(storage), false, None, None)
    }

    /// CW workers that run GLOBALLY AUTHORIZED committee sessions: every worker
    /// reads `global` (the authenticated GLOBAL hypergraph) and owns a
    /// RocksDB-backed shard CRDT with a persistent forest, which the session's
    /// committed checkpoint reads require.
    pub fn build_cw_sessions(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Self {
        Self::build_inner(provers, registry, None, true, Some(global), None)
    }

    /// [`Self::build_cw_sessions`] with application state `seed` committed
    /// into every worker's shard CRDT before its engine starts.
    pub fn build_cw_sessions_seeded(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
        global: Arc<quil_hypergraph::HypergraphCrdt>,
        seed: fn(&quil_hypergraph::HypergraphCrdt),
    ) -> Self {
        Self::build_inner(provers, registry, None, true, Some(global), Some(seed))
    }

    fn build_inner(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
        storage: Option<StorageHarness>,
        app_cw: bool,
        session_global: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
        seed: Option<fn(&quil_hypergraph::HypergraphCrdt)>,
    ) -> Self {
        let n = provers.len();
        assert!(n >= 1, "need at least one worker");

        // Run the app-shard cadence fast so the in-process harness reaches
        // finalization within the test budget (production paces at 10 s).
        quil_engine::app_engine::set_app_proposal_duration_ms(200);

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
            // A session member's per-frame history records (fee total,
            // settlements, spends, accumulator) commit with its state into the
            // CRDT's database, and production reads them back through a clock
            // store over that same database. A separate in-memory clock store
            // cannot see them once the engine's in-memory copy is gone, as for a
            // successor restarted under its new session.
            let mut member_clock: Option<Arc<dyn ClockStore>> = None;
            // Active-path PoRep wiring: seed the global beacon frame, build the
            // worker's replica store + confirm its leaf replicas, and pass the
            // shared CRDT so `storage_vote_openings` / the seal can run.
            let (hypergraph_dep, kv_db_dep): (
                Option<Arc<quil_hypergraph::HypergraphCrdt>>,
                Option<Arc<dyn quil_types::store::KvDb>>,
            ) = if let Some(sh) = storage.as_ref() {
                clock_store.seed_frame(sh.global_frame.clone());
                let rocks = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
                let kv: Arc<dyn quil_types::store::KvDb> = rocks.clone();
                let rs = quil_store::replica_store::ReplicaStore::new(kv.clone());
                let gfn = sh
                    .global_frame
                    .header
                    .as_ref()
                    .map(|h| h.frame_number)
                    .unwrap_or(0);
                let epoch = quil_types::consensus::epoch_for_frame(gfn);
                quil_engine::app_shard_metadata::compute_storage_confirm(
                    &sh.crdt,
                    &rs,
                    std::slice::from_ref(&filter),
                    &prover.address,
                    epoch,
                    quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                    &quil_crypto::sdr::SdrParams::default(),
                )
                .expect("seed worker storage confirm");
                (Some(sh.crdt.clone()), Some(kv))
            } else if session_global.is_some() {
                let rocks: &'static quil_store::RocksDb =
                    Box::leak(Box::new(quil_store::RocksDb::open_in_memory().unwrap()));
                let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                    Arc::new(quil_store::RocksHypergraphStore::new(rocks.inner()))
                        as Arc<dyn quil_types::store::HypergraphStore>,
                    Arc::new(quil_hypergraph::testing::StubProver)
                        as Arc<dyn quil_types::crypto::InclusionProver>,
                ));
                crdt.set_forest(quil_forest::Forest::with_namespace(
                    rocks.inner(),
                    quil_store::FOREST_NAMESPACE,
                ));
                if let Some(seed) = seed {
                    seed(&crdt);
                }
                member_clock = Some(Arc::new(quil_store::RocksClockStore::new(rocks.inner())));
                (Some(crdt), None)
            } else {
                // No storage path, but the CW proposer and voter still need
                // the request-root validator, which requires a hypergraph.
                (
                    Some(Arc::new(quil_hypergraph::HypergraphCrdt::new(
                        Arc::new(quil_hypergraph::testing::MemStore::new())
                            as Arc<dyn quil_types::store::HypergraphStore>,
                        Arc::new(quil_hypergraph::testing::StubProver)
                            as Arc<dyn quil_types::crypto::InclusionProver>,
                    ))),
                    None,
                )
            };
            // Exercise the production app constructor under CW: it hashes the
            // full parent output and never solves an app VDF.
            let frame_prover: Arc<dyn FrameProver> = if app_cw {
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048))
            } else {
                Arc::new(StubFrameProver)
            };
            let message_collector =
                Arc::new(quil_engine::message_collector::MessageCollector::new());
            let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
                Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32));

            let bls_signer = prover.signer_clone();
            let deps = quil_engine::app_engine::AppEngineDeps {
            delivery_frame_source: None,
                clock_store: member_clock.unwrap_or_else(|| clock_store as Arc<dyn ClockStore>),
                global_anchor_store: None,
                global_hypergraph: session_global.clone(),
                storage_source_hypergraph: None, topology: None,
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
                hypergraph: hypergraph_dep.clone(),
                // Wire a minimal ExecutionEngineManager + InclusionProver
                // so workers can carry real dispatch messages.
                // `compute_requests_root` requires both whenever the
                // message buffer is non-empty (app_engine.rs:2099-2115).
                // Empty buffer → 64-byte zero requests_root, so the
                // existing wave of tests that send no messages still
                // works.
                execution_engine: Some(Arc::new(match (session_global.as_ref(), hypergraph_dep.as_ref()) {
                    (Some(_), Some(crdt)) => build_test_exec_manager_on(
                        crdt.clone(),
                        Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                        false,
                    ),
                    _ => build_test_exec_manager(
                        Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver>,
                        /* include_global */ false,
                    ),
                })),
                inclusion_prover: Some(
                    Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>
                ),
                kv_db: kv_db_dep,
                app_consensus_cw: app_cw,
            db_config: quil_config::DbConfig { path: String::new(), worker_path_prefix: String::new(), worker_paths: vec![], ..Default::default() }, // ephemeral journal in tests
            unified_cutover_hook: None,
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
                full_frames: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
                shard: session_global.as_ref().and(hypergraph_dep.clone()),
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
        // Each worker's committee Falcon pubkey, so the CW event drain can
        // tag `CwIn.from` when routing `CwOut` to peers (in-memory transport).
        let all_pubkeys: Vec<Vec<u8>> =
            workers.iter().map(|w| w.prover.bls_pubkey.clone()).collect();
        let events_per_worker: Vec<Arc<Mutex<Vec<String>>>> =
            workers.iter().map(|w| w.events.clone()).collect();
        let full_frames_per_worker: Vec<Arc<Mutex<Vec<Vec<u8>>>>> =
            workers.iter().map(|w| w.full_frames.clone()).collect();

        let mut tasks = Vec::new();
        // Spawn each worker's engine + its event drain.
        for (idx, pending) in pendings.into_iter().enumerate() {
            let engine = pending.engine;
            // `run` takes a signer FACTORY now (CW-activation retry); rebuild from key.
            let sk = pending.bls_signer.private_key().to_vec();
            let pk = pending.bls_signer.public_key().to_vec();
            let factory: std::sync::Arc<
                dyn Fn() -> Box<dyn quil_types::crypto::Signer> + Send + Sync,
            > = std::sync::Arc::new(move || {
                Box::new(quil_crypto::FalconSigner::from_bytes(&sk, &pk))
            });
            tasks.push(tokio::spawn(async move {
                engine.run(factory).await;
            }));

            let peer_handles: Vec<quil_engine::app_engine::AppEngineHandle> = all_handles
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, h)| h.clone())
                .collect();
            let my_pubkey = all_pubkeys[idx].clone();
            let my_handle = all_handles[idx].clone();
            let events_log = events_per_worker[idx].clone();
            let full_frames_log = full_frames_per_worker[idx].clone();
            let mut rx = pending.event_rx;
            tasks.push(tokio::spawn(async move {
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
                        E::FullFrameProduced { frame_data, .. } => {
                            events_log.lock().push("FullFrameProduced".into());
                            full_frames_log.lock().push(frame_data.clone());
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
                        E::ShardDataBootstrapRequested { .. } => {
                            events_log.lock().push("ShardDataBootstrapRequested".into());
                            // The harness shard is genuinely empty (or already
                            // seeded in-process), so the bootstrap converges at
                            // once — as the production syncer reports for an
                            // empty shard — and un-gates propose/vote.
                            my_handle.send(quil_engine::app_engine::AppEngineMessage::ShardSyncCompleted {
                                synced_to_frame: 0,
                            });
                        }
                        E::CwOut { channel, bytes, .. } => {
                            events_log.lock().push("CwOut".into());
                            // In-memory CW transport: deliver to every peer's
                            // `CwIn`, tagged with this worker's committee key.
                            for h in &peer_handles {
                                h.send(quil_engine::app_engine::AppEngineMessage::CwIn {
                                    channel: *channel,
                                    from: my_pubkey.clone(),
                                    data: bytes.clone(),
                                });
                            }
                        }
                    }
                }
            }));
        }

        // The in-memory harness wires every CW peer directly through the event
        // drains above, so its transport is ready as soon as those drains exist.
        // Production releases this barrier only after BlossomSub observes a
        // connected topic subscriber; make the equivalent condition explicit
        // here rather than letting tests bypass the startup contract.
        for handle in &all_handles {
            handle.set_cw_transport_ready();
        }

        Self { filter, workers, tasks }
    }

    /// Stop engines cooperatively and wait for engines and event drains.
    pub async fn shutdown(self) {
        for worker in &self.workers {
            worker.handle.stop();
        }
        for task in self.tasks {
            tokio::time::timeout(std::time::Duration::from_secs(30), task)
                .await
                .expect("harness shutdown timed out")
                .expect("harness task panicked");
        }
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

    /// Wait up to `timeout` for any worker to emit a `FullFrameProduced`
    /// event, then decode and return the first such `AppShardFrame`.
    pub async fn wait_for_full_frame(
        &self,
        timeout: std::time::Duration,
    ) -> Option<gpb::AppShardFrame> {
        use prost::Message;
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for w in &self.workers {
                if let Some(bytes) = w.full_frames.lock().first().cloned() {
                    return gpb::AppShardFrame::decode(bytes.as_slice()).ok();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }
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
/// Concatenates every prover's Falcon consensus pubkey (each 897 bytes) into a
/// single hex-encoded blob.
pub fn build_genesis_seed_hex(provers: &[TestProver]) -> String {
    let mut blob = Vec::with_capacity(provers.len() * 897);
    for p in provers {
        assert_eq!(
            p.bls_pubkey.len(),
            897,
            "Falcon consensus pubkey must be 897 bytes; got {}",
            p.bls_pubkey.len(),
        );
        blob.extend_from_slice(&p.bls_pubkey);
    }
    hex::encode(blob)
}

/// Fill an app-shard `FrameHeader`'s `output` with the deterministic digest the
/// producer stamps.
///
/// App-shard frames carry no VDF — `AppLeaderProvider` sets `output` to
/// `porep::deterministic_app_frame_output`, and the attestation verifier
/// recomputes it. A genesis / no-global-anchor header (`global_frame_number ==
/// 0`) binds the ZERO-ANCHOR ρ_N, since there is no global VDF output to bind
/// freshness to. Synthetic headers must be stamped or they are (correctly)
/// rejected as not matching their own digest.
pub fn stamp_app_frame_output(
    h: &mut quil_execution::global_intrinsic::frame_header::FrameHeader,
) {
    stamp_anchored_app_frame_output(h, &[]);
}

/// [`stamp_app_frame_output`] for a storage frame anchored to global frame
/// `h.global_frame_number`, whose VDF output is `anchor_output`. The verifier
/// recomputes ρ_N from its own clock store, so the anchor frame must be seeded
/// there with the same output.
pub fn stamp_anchored_app_frame_output(
    h: &mut quil_execution::global_intrinsic::frame_header::FrameHeader,
    anchor_output: &[u8],
) {
    let rho_n = quil_crypto::porep::derive_storage_beacon(h.global_frame_number, anchor_output);
    h.output = quil_crypto::porep::deterministic_app_frame_output(
        &h.parent_selector,
        &h.requests_root,
        &h.state_roots,
        &rho_n,
        h.frame_number,
        h.rank,
        &h.prover,
        h.difficulty,
        h.fee_multiplier_vote as u64,
        h.timestamp,
        &h.storage_attestation_root,
        h.fee_total_value(),
        &h.settlements,
        &h.accumulator,
        &h.spends,
    );
}

/// Apply a frame as a node already synced to its PARENT.
///
/// The materializer enforces an in-order invariant: it refuses to apply a frame
/// ahead of its cursor (`frame_number > last + 1`), since building on state we
/// don't hold forks the prover root. These tests hand it a single frame at an
/// arbitrary height, so seed the cursor to `N-1` first — exactly what production
/// does via `seed_cursor` at startup / after a state jump.
pub trait MaterializeSynced {
    fn materialize_synced(
        &self,
        frame: &gpb::GlobalFrame,
    ) -> QResult<quil_engine::frame_materializer::MaterializeResult>;
}

impl MaterializeSynced for quil_engine::frame_materializer::FrameMaterializer {
    fn materialize_synced(
        &self,
        frame: &gpb::GlobalFrame,
    ) -> QResult<quil_engine::frame_materializer::MaterializeResult> {
        let n = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
        self.seed_cursor(n.saturating_sub(1));
        self.materialize(frame)
    }
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
    pub clock_store: Arc<quil_store::RocksClockStore>,
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
    use quil_engine::current_frame::CurrentFrame;
    use quil_engine::frame_materializer::FrameMaterializer;
    use quil_engine::halt_state::HaltState;
    use quil_engine::prover_message_transport::ProverMessageTransport;
    use quil_engine::prover_pipeline::ProverPipeline;
    use quil_engine::provers::lifecycle::ProverLifecycle;
    use quil_engine::provers::proposer::Strategy;
    use quil_engine::test_support::{
        TestKeyManager, TestProverMessageTransport, TestWorkerManager,
    };
    use quil_engine::worker_allocator::WorkerAllocator;
    use quil_execution::{ExecutionEngineManager, SharedProverRegistry};
    use quil_hypergraph::testing::StubProver;
    use quil_hypergraph::HypergraphCrdt;
    use quil_store::{RocksDb, RocksHypergraphStore, RocksShardsStore};
    use quil_types::store::ShardsStore;
    use std::sync::Arc;

    // 1. In-memory Rocks → hypergraph store.
    let rocks = Arc::new(RocksDb::open_in_memory().expect("rocks open_in_memory"));
    let hg_store = Arc::new(RocksHypergraphStore::new(rocks.inner()));
    let shards_store = Arc::new(RocksShardsStore::new(rocks.inner()));
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> = Arc::new(StubProver);
    let crdt = Arc::new(HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover.clone(),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        rocks.inner(),
        quil_store::FOREST_NAMESPACE,
    ));

    // 2. Clock, forest and state share the execution database, as in production.
    let clock_store = Arc::new(quil_store::RocksClockStore::new(rocks.inner()));

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

    // 3b. Seed a synthetic head frame (frame 5) that every tier-2 test
    //     references as the join/confirm `frame_number` (they also set it
    //     on the transport via `set_head_header`). The ProverJoin VDF
    //     gate (`global_intrinsic/intrinsic.rs`) resolves this referenced
    //     frame via the clock store; without it, joins are rejected with
    //     "referenced frame 5 not in clock store" and skipped.
    let referenced_frame = gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 5,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![],
    };
    let txn = clock_store.new_transaction(false).expect("clock transaction");
    clock_store.put_global_clock_frame(&referenced_frame, txn.as_ref())
        .expect("seed referenced frame");
    txn.commit().expect("commit referenced frame");

    // 4. Build prover registry and refresh from the seeded store.
    let prover_registry = Arc::new(SharedProverRegistry::new());
    prover_registry.refresh_from_store(hg_store.as_ref()).unwrap();

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
        exec_stubs.circuit_compiler,
        // Use the REAL clock store (not the noop stub) — mirrors production
        // (`master_node/engines.rs` wires `storage.clock_store`). The
        // ProverJoin VDF-verification gate (`global_intrinsic/intrinsic.rs`)
        // looks up the join's referenced frame via this clock store; with
        // the noop stub every join was rejected with "referenced frame N
        // not in clock store" and materialized as skipped.
        clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
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
        Arc::new(quil_crypto::FalconKeyConstructor);
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
    let worker_manager_dyn: Arc<dyn quil_engine::worker::WorkerManager> = worker_manager.clone();
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
    let pipeline_key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync> =
        Arc::new(TestKeyManager::new(
            prover.bls_signer.private_key().to_vec(),
            prover.bls_pubkey.clone(),
        ));

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
        hypergraph: None,
        replica_store: None,
        storage_for_filter: None,
        remote_storage_confirm: None,
        pending_shard_changes: None,
        local_message_collector: None,
        current_frame: None,
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

// =====================================================================
// Tier 2 — adversarial tests (real BLS verifier)
// =====================================================================

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
pub fn build_test_pipeline_with_registry(
    prover: &TestProver,
    transport: Arc<quil_engine::test_support::TestProverMessageTransport>,
    registry: Arc<dyn quil_types::consensus::ProverRegistry>,
) -> TestPipelineRig {
    use quil_engine::prover_message_transport::ProverMessageTransport;
    use quil_engine::prover_pipeline::ProverPipeline;
    use quil_engine::provers::lifecycle::ProverLifecycle;
    use quil_engine::provers::proposer::Strategy;
    use quil_engine::test_support::{TestKeyManager, TestWorkerManager};
    use quil_engine::worker_allocator::WorkerAllocator;

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
        // Data-shard confirmations prepare next-epoch replicas before they are
        // signed (`storage_confirm_leaf_roots`), so the rig carries a local
        // (empty) hypergraph and an in-memory replica store like production.
        hypergraph: Some(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new())
                as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_hypergraph::testing::StubProver)
                as Arc<dyn quil_types::crypto::InclusionProver>,
        ))),
        replica_store: Some(quil_store::replica_store::ReplicaStore::new(
            Arc::new(quil_store::RocksDb::open_in_memory().expect("in-memory replica db"))
                as Arc<dyn quil_types::store::KvDb>,
        )),
        storage_for_filter: None,
        remote_storage_confirm: None,
        pending_shard_changes: None,
        local_message_collector: None,
        current_frame: None,
    });
    TestPipelineRig {
        pipeline,
        current_frame,
        worker_manager: wm,
    }
}

/// Helper: build a `GlobalFrame` whose `requests` contain a single
/// proto MessageBundle decoded from the given canonical bundle bytes.
pub fn build_global_frame_with_bundle(frame_number: u64, bundle_bytes: &[u8]) -> gpb::GlobalFrame {
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
