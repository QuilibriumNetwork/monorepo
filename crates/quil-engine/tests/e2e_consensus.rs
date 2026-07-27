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
            storage_attestation_root: Vec::new(),
            global_frame_number,
            storage_attestation: Vec::new(),
        })
    }

    fn verify_frame_header(&self, _h: &gpb::FrameHeader) -> QResult<Vec<u8>> {
        Ok(vec![0u8; 516])
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

/// Build a single-signer (`bitmask=[0x01]`) shard-FrameHeader aggregate
/// signature whose DECLARED aggregate public key matches what the
/// intrinsic's attestation verifier reconstructs via
/// `bls.aggregate_public_keys([member_pubkey])`. The 74-byte `signature` is a
/// placeholder.
fn single_signer_agg_sig(
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
// Tests
// ===================================================================

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
}

pub struct AppShardHarness {
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
        Self::build_inner(provers, registry, None, false)
    }

    /// (P3) Build `n` workers driving the shard with commonware-simplex + Falcon
    /// (`app_consensus_cw = true`). For `n == 1` the single committee member
    /// self-proposes + self-finalizes (the `NoopAppTransport` in the engine has
    /// no peers to reach); multi-worker CW needs the gossip transport wired.
    pub fn build_cw(n: usize) -> Self {
        assert!(n >= 1, "need at least one worker");
        let provers: Vec<TestProver> = (0..n).map(|_| TestProver::generate()).collect();
        let all_prover_infos: Vec<_> = provers.iter().map(|p| p.to_prover_info(1)).collect();
        let registry =
            Arc::new(TestProverRegistry::with_provers(all_prover_infos)) as Arc<dyn ProverRegistry>;
        Self::build_inner(provers, registry, None, true)
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
        Self::build_inner(provers, registry, Some(storage), false)
    }

    fn build_inner(
        provers: Vec<TestProver>,
        registry: Arc<dyn ProverRegistry>,
        storage: Option<StorageHarness>,
        app_cw: bool,
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
            } else {
                (None, None)
            };
            let frame_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
            let message_collector =
                Arc::new(quil_engine::message_collector::MessageCollector::new());
            let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
                Arc::new(quil_engine::InMemoryDynamicFeeManager::new(32));

            let bls_signer = prover.signer_clone();
            let deps = quil_engine::app_engine::AppEngineDeps {
                clock_store: clock_store as Arc<dyn ClockStore>,
            global_anchor_store: None,
            storage_source_hypergraph: None,
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
                hypergraph: hypergraph_dep,
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
                    Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>
                ),
                kv_db: kv_db_dep,
                app_consensus_cw: app_cw,
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
        // (P3) Each worker's committee Falcon pubkey, so the CW event drain can
        // tag `CwIn.from` when routing `CwOut` to peers (in-memory transport).
        let all_pubkeys: Vec<Vec<u8>> =
            workers.iter().map(|w| w.prover.bls_pubkey.clone()).collect();
        let events_per_worker: Vec<Arc<Mutex<Vec<String>>>> =
            workers.iter().map(|w| w.events.clone()).collect();
        let full_frames_per_worker: Vec<Arc<Mutex<Vec<Vec<u8>>>>> =
            workers.iter().map(|w| w.full_frames.clone()).collect();

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
            let full_frames_log = full_frames_per_worker[idx].clone();
            let my_pubkey = all_pubkeys[idx].clone();
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
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
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

/// (P3) A single-prover shard driven by commonware-simplex + Falcon
/// (`app_consensus_cw = true`, EQUAL VOTES, quorum 1) self-proposes and
/// self-finalizes app frames end-to-end: `start_consensus_cw` builds the
/// committee (this node's Falcon key, the only active prover), the seam
/// proposer proves + assembles + verifies each frame, simplex finalizes it,
/// and `handle_cw_finalized_frame` persists the shard clock frame + materializes
/// + emits `FullFrameProduced`. Asserts a full `AppShardFrame` is produced and
/// the chain advances past genesis (frame_number >= 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_consensus_cw_single_prover_finalizes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build_cw(1);
    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(60))
        .await;
    assert!(
        frame.is_some(),
        "app CW single-prover did not finalize a shard frame within 60s"
    );
    let header = frame.unwrap().header.expect("finalized frame has a header");
    assert!(
        header.frame_number >= 1,
        "app CW chain did not advance past genesis (frame_number = {})",
        header.frame_number
    );
}

/// (P3) A 3-prover shard committee driven by commonware-simplex + Falcon
/// (EQUAL VOTES, quorum 3) finalizes app frames via CROSS-NODE voting: the
/// RoundRobin leader proves + ships its block over the CW block channel, each
/// follower ingests it (`CwIn` → `BlockStore`), verifies (`validate_proposal`),
/// and votes (`CwIn` vote channel, sender resolved to its committee Falcon key);
/// quorum finalizes. Exercises the full in-memory CW transport (CwOut → CwIn)
/// end-to-end — the same round-trip the master's BlossomSub path will carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn app_consensus_cw_multi_prover_finalizes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let harness = AppShardHarness::build_cw(3);
    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(90))
        .await;
    assert!(
        frame.is_some(),
        "3-prover app CW committee did not finalize a shard frame within 90s"
    );
    let header = frame.unwrap().header.expect("finalized frame has a header");
    assert!(
        header.frame_number >= 1,
        "app CW chain did not advance past genesis (frame_number = {})",
        header.frame_number
    );
}

/// Active PoRep path end-to-end through the live consensus harness.
///
/// Each of the 4 workers gets a shared committed CRDT (vertices under the
/// shard filter), an in-memory replica store pre-seeded with its confirmed
/// leaf replicas, and a global beacon frame at frame 1000 — and the
/// process-global activation frame is lowered to 1000. With the storage
/// fork live (`global_frame_number >= storage_activation_frame()`):
///   * the producer omits the app-shard VDF and binds a deterministic
///     ρ_N-bound `header.output`,
///   * each follower's vote carries serialized `StorageOpening`s,
///   * the aggregator stashes the openings by rank, and
///   * the seal recomputes the 74-byte BLS48-581 G1 aggregate
///     `storage_attestation_root` and attaches the `StorageAttestation`.
///
/// Asserts the finalized `AppShardFrame` carries that attestation + root —
/// the inverse of every other harness test, where the (un-activated) path
/// leaves both empty and byte-identical to the legacy frame.
// P4/CW FOLLOW-UP: PoRep storage-attestation assembly is a LEGACY-consensus
// feature — the old app path assembled the committee `StorageAttestation` from
// per-vote openings at QC time. The commonware-simplex path votes are plain
// simplex votes (no openings), so CW-finalized frames carry no attestation yet.
// Porting PoRep to CW (openings in CW votes + assembly on finalize) is tracked
// separately; the core consensus migration does not depend on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn worker_active_storage_attestation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let provers: Vec<TestProver> = (0..4).map(|_| TestProver::generate()).collect();
    let infos: Vec<_> = provers.iter().map(|p| p.to_prover_info(1)).collect();
    let registry = Arc::new(TestProverRegistry::with_provers(infos));

    // `seeded` lowers `storage_activation_frame()` to 1000 and builds the
    // shared CRDT + a global frame at 1000 (≥ activation → fork live).
    let storage = StorageHarness::seeded(1000);

    // Register every member's storage leaf roots into the registry so the frame
    // validator's registered-leaf cross-check on the proposer's self
    // storage-attestation passes. Production writes these via the confirm
    // intrinsic (prover trie); the harness wires them directly, mirroring the
    // per-worker `compute_storage_confirm` seeding inside `build_inner`. The
    // filter/epoch match `build_inner` (`[0x55;32]`, `epoch_for_frame(1000)`).
    {
        let filter: Vec<u8> = vec![0x55; 32];
        let epoch = quil_types::consensus::epoch_for_frame(1000);
        let rocks = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let rs = quil_store::replica_store::ReplicaStore::new(
            rocks as Arc<dyn quil_types::store::KvDb>,
        );
        for p in &provers {
            let roots = quil_engine::app_shard_metadata::compute_storage_confirm(
                &storage.crdt,
                &rs,
                std::slice::from_ref(&filter),
                &p.address,
                epoch,
                quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                &quil_crypto::sdr::SdrParams::default(),
            )
            .expect("compute leaf roots for registration");
            for cr in &roots {
                for e in &cr.entries {
                    let lid = quil_execution::global_intrinsic::leaf_id_bytes(&filter, &e.prefix);
                    registry.register_leaf_root(
                        &p.address,
                        &lid,
                        e.leaf_root.clone(),
                        e.num_blocks,
                        epoch,
                    );
                }
            }
        }
    }

    let registry = registry as Arc<dyn ProverRegistry>;
    let harness = AppShardHarness::build_with_storage(provers, registry, storage);

    let frame = harness
        .wait_for_full_frame(std::time::Duration::from_secs(90))
        .await
        .expect("expected a FullFrameProduced AppShardFrame within timeout");

    assert!(
        frame.storage_attestation.is_some(),
        "active-path full frame must carry a StorageAttestation",
    );
    let root = frame
        .header
        .as_ref()
        .map(|h| h.storage_attestation_root.clone())
        .unwrap_or_default();
    assert_eq!(
        root.len(),
        74,
        "storage_attestation_root must be the 74-byte BLS48-581 G1 aggregate; got {} bytes",
        root.len(),
    );

    // The reward proof — the canonical FrameHeader published on GLOBAL_PROVER
    // (captured via coverage_publish) — must ALSO carry the root + the openings
    // blob, since that is the payload the global frame recomputes + audits.
    let cov = harness
        .workers
        .iter()
        .flat_map(|w| w.coverage_published.lock().clone())
        .next()
        .expect("a coverage reward proof must have been published");
    let cov_header =
        quil_execution::global_intrinsic::frame_header::FrameHeader::from_canonical_bytes(&cov)
            .expect("coverage bytes decode as a canonical FrameHeader");
    assert_eq!(
        cov_header.storage_attestation_root.len(),
        74,
        "reward-proof storage_attestation_root must be the 74-byte aggregate",
    );
    assert!(
        !cov_header.storage_attestation.is_empty(),
        "reward proof must carry the StorageAttestation openings for the global audit",
    );
    // And the carried blob must decode as a StorageAttestation with openings.
    let att = <quil_types::proto::global::StorageAttestation as prost::Message>::decode(
        cov_header.storage_attestation.as_slice(),
    )
    .expect("carried attestation decodes");
    assert!(
        !att.openings.is_empty(),
        "carried StorageAttestation must contain member openings",
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
// CW EVENT MODEL: the commonware-simplex path does NOT emit the legacy
// `FrameProduced` proposal-broadcast event — the CW proposer proves the frame
// inside the seam and ships the block over `CwOut`, surfacing `FullFrameProduced`
// on finalize. So this test locates the leader (and confirms production) via
// `FullFrameProduced`. The kept-request assembly is unchanged, so the injected
// dispatch still rides the frame's `requests_root`.
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
    // The proposal path (`app_engine.rs:401-417`) decodes each buffered
    // dispatch via `decode_message_bundle`, which requires a canonical
    // `MessageBundle` (type 0x0312). A bare op blob fails to decode and
    // is dropped, leaving `requests_root` zero — so wrap the op in a
    // `CanonicalMessageBundle` exactly as the wire path delivers it.
    let mut op_bytes = Vec::new();
    op_bytes.extend_from_slice(&0x00000201u32.to_be_bytes());
    op_bytes.extend_from_slice(&[0xAAu8; 32]);
    let dispatch_bytes = {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let req = CanonicalMessageRequest::wrap(op_bytes).expect("wrap dispatch request");
        CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .expect("encode dispatch bundle")
    };
    // Inject into EVERY worker's collector. Dispatch messages are not
    // relayed by the harness's consensus drain (only proposals/votes/
    // timeouts are), and the frame is built by whichever worker leads
    // the finalized rank — which need not be worker 0. In production a
    // dispatch gossips to all shard members, so each buffers it and the
    // leader folds it into `requests_root`; mirror that here so the
    // assertion doesn't hinge on worker 0 happening to be the leader.
    for w in &harness.workers {
        w.handle
            .send(quil_engine::app_engine::AppEngineMessage::Dispatch(
                dispatch_bytes.clone(),
            ));
    }

    // Wait for at least one shard frame to be produced. Under commonware-simplex
    // the drain records "FullFrameProduced" (the CW analog of the legacy
    // "FrameProduced") once a frame finalizes and its full block is shipped.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut leader_idx: Option<usize> = None;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for (i, w) in harness.workers.iter().enumerate() {
            if w.events.lock().iter().any(|e| e == "FullFrameProduced") {
                leader_idx = Some(i);
                break;
            }
        }
        if leader_idx.is_some() {
            break;
        }
    }
    let leader_idx = leader_idx
        .expect("no worker produced a FullFrameProduced event within 90s — frame production stalled");
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

    // The injected dispatch lands in exactly ONE finalized frame (once
    // buffered it stays in the collector until `mark_finalized` removes
    // it on inclusion), and NOT necessarily frame 1 — the first frame
    // can be proposed before the async `Dispatch` is drained from the
    // engine's channel. So poll until SOME finalized coverage frame
    // (across all workers, all entries) carries a non-zero
    // `requests_root`, rather than inspecting only the first.
    use quil_execution::global_intrinsic::frame_header::FrameHeader;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut carrying: Option<FrameHeader> = None;
    'outer: while std::time::Instant::now() < deadline {
        for w in &harness.workers {
            let entries: Vec<Vec<u8>> = w.coverage_published.lock().clone();
            for bytes in &entries {
                if let Ok(h) = FrameHeader::from_canonical_bytes(bytes) {
                    let zero_root = vec![0u8; h.requests_root.len()];
                    if h.requests_root != zero_root {
                        carrying = Some(h);
                        break 'outer;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let header = carrying.expect(
        "no finalized coverage frame carried a non-zero requests_root — the \
         injected dispatch message was never incorporated into a shard frame",
    );
    eprintln!(
        "carrying coverage FrameHeader: frame_number={}, requests_root[..16]={}",
        header.frame_number,
        hex::encode(&header.requests_root[..16.min(header.requests_root.len())]),
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

    // 3b. Seed a synthetic head frame (frame 5) that every tier-2 test
    //     references as the join/confirm `frame_number` (they also set it
    //     on the transport via `set_head_header`). The ProverJoin VDF
    //     gate (`global_intrinsic/intrinsic.rs`) resolves this referenced
    //     frame via the clock store; without it, joins are rejected with
    //     "referenced frame 5 not in clock store" and skipped.
    clock_store.seed_frame(gpb::GlobalFrame {
        header: Some(gpb::GlobalFrameHeader {
            frame_number: 5,
            rank: 0,
            timestamp: 0,
            difficulty: 100_000,
            output: vec![0u8; 516],
            ..Default::default()
        }),
        requests: vec![],
    });

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
    let my_info = rig
        .prover_registry
        .read(|r| r.get_prover_info(&me.address).cloned());
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
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

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
    // (The archive rig already seeds frame 5 into its clock store so the
    // ProverJoin VDF gate can resolve the join's referenced frame.)

    // 3. Build a new (non-genesis) prover. This is the joiner.
    let joiner = TestProver::generate();

    // 4. Build a non-archive ProverPipeline. Reuses the archive's
    //    storage so the test can drive both sides in one process.
    let transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
    transport.set_head_header(head_header.clone());
    let joiner_key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync> =
        Arc::new(quil_engine::test_support::TestKeyManager::new(
            joiner.bls_signer.private_key().to_vec(),
            joiner.bls_pubkey.clone(),
        ));
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
        hypergraph: None,
        replica_store: None,
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

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
    let provers_on_filter = archive
        .prover_registry
        .read(|r| r.get_provers(&filter).len());
    assert!(
        provers_on_filter >= 1,
        "expected ≥1 prover on filter {} after join (joiner should be Joining); got {}",
        hex::encode(&filter),
        provers_on_filter,
    );
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
    // FalconKeyConstructor::verify_signature_raw.
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    let joiner = TestProver::generate();
    let joiner_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
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
    joiner_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
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
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // Submit a valid join first (via the joiner's pipeline) so an
    // allocation exists for the attacker to target.
    let joiner = TestProver::generate();
    let joiner_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
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
    joiner_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
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
        leaf_roots: Vec::new(),
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
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
    let real_km: Arc<dyn quil_types::crypto::KeyManager> = Arc::new(
        quil_crypto::DefaultKeyManager::new(),
    );
    let archive = build_tier2_archive_rig_with_key_manager(
        genesis_provers[0].clone(),
        &genesis_provers,
        &seed_hex,
        real_km,
    );

    // 1. Victim submits a valid ProverJoin.
    let victim = TestProver::generate();
    let victim_transport = Arc::new(quil_engine::test_support::TestProverMessageTransport::new());
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
    victim_pipeline
        .worker_manager
        .add(quil_engine::worker::WorkerInfo {
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

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
        leaf_roots: Vec::new(),
    };
    let confirm_bytes = confirm.to_canonical_bytes().expect("encode");

    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let req = CanonicalMessageRequest::wrap(confirm_bytes).expect("wrap");
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: 0,
    };
    let bundle_bytes = bundle.to_canonical_bytes().expect("encode bundle");
    let proto = quil_engine::consensus_wire::decode_message_bundle(&bundle_bytes).expect("decode");
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
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
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
// P4/CW FOLLOW-UP — the significant one: REWARD ATTRIBUTION under CW. The
// coverage bundle DOES reach the archive now (CW finalizer emits ShardFrameFinalized
// + coverage_publish), but the archive materializer SKIPS it (processed=0,
// skipped=1) because a CW-finalized shard-frame header has no BLS AGGREGATE
// SIGNATURE (simplex certifies the frame via its own Falcon cert, not a header
// agg sig). The global reward path currently verifies that agg sig to credit
// shard work, so CW shard provers would not be credited. This needs a design
// decision: how the GLOBAL level verifies CW-finalized shard work (accept the
// VDF + a CW committee attestation, or carry the simplex cert into the coverage
// bundle). PRIORITY follow-up — see CUTOVER §7.
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
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Build a Tier-1 worker cohort. They run a full HotStuff round on
    // a shared shard filter and fire `coverage_publish` on
    // finalization with the canonical FrameHeader bytes. The cohort
    // SHARES the archive's prover registry, seeded below with these
    // provers as Active on the shard filter — so the committee the
    // workers sign their coverage FrameHeader with is byte-identical to
    // the one the archive's FrameHeader verifier reconstructs from
    // `get_active_provers(filter)`. Without this the archive's active
    // set for the shard is empty and verification fails with
    // "aggregate pubkey ... active_count=0".
    // Single-signer cohort: a stub-crypto coverage FrameHeader carries a
    // bare 74-byte BLS aggregate with NO VDF multiproof bytes appended.
    // The intrinsic's attestation check treats a 74-byte signature as
    // single-signer (a real multi-signer attestation is >74 bytes — it
    // appends the per-member Wesolowski multiproofs the stub can't
    // produce). So coverage ingest is exercised with one prover; the
    // multi-prover consensus path is covered separately by
    // `worker_activates_after_confirm_and_emits_proof`.
    let shard_filter: Vec<u8> = vec![0x55; 32];
    let worker_provers: Vec<TestProver> = (0..1).map(|_| TestProver::generate()).collect();
    for p in &worker_provers {
        quil_engine::genesis::seed_active_prover_on_filter(
            &archive.crdt,
            &p.bls_pubkey,
            /* seniority */ 1,
            /* frame_number */ 1,
            &shard_filter,
        )
        .expect("seed worker prover as Active on shard filter");
    }
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    // The PoMW reward needs a non-zero shard `state_size`. Seed ~1 MiB of
    // committed data on the worker's shard so `shard_metadata_for_address`
    // reports a real size (fixed 2026-06-29 — was hardcoded zero, which made
    // every reward compute to zero). Without committed data the reward stays 0.
    let worker_pubkey = worker_provers[0].bls_pubkey.clone();
    {
        let mut app = [0u8; 32];
        app.copy_from_slice(&shard_filter);
        archive
            .crdt
            .add_vertex(
                &quil_hypergraph::Location { app_address: app, data_address: [0x01; 32] },
                &vec![0xEEu8; 1 << 20],
            )
            .unwrap();
        // Commit BEFORE the coverage frame (frame 7) so the size is populated
        // when the materializer sources it.
        archive.crdt.commit(6).unwrap();
    }

    let workers = AppShardHarness::build_with_registry(
        worker_provers,
        archive.prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
    );
    let got_coverage = workers
        .wait_for_coverage(std::time::Duration::from_secs(90))
        .await;
    assert!(
        got_coverage,
        "worker cohort never produced a coverage frame"
    );

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

    // The fix's payoff (the missing reward leg): the participating worker
    // prover received a NON-ZERO reward through the real frame-header
    // materialize path. Before the per-shard-size fix this was always 0.
    use quil_execution::global_intrinsic::materialize::{prover_address_from_pubkey, reward_address};
    let prover_addr = prover_address_from_pubkey(&worker_pubkey).unwrap();
    let reward_addr = reward_address(&prover_addr).unwrap();
    let reward_loc = quil_hypergraph::Location {
        app_address: quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS,
        data_address: reward_addr,
    };
    let blob = archive
        .crdt
        .get_vertex_data(&reward_loc)
        .expect("worker prover reward vertex must exist after coverage materialize");
    let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    let bal_bytes = quil_execution::global_schema::read_field(&tree, "reward:ProverReward", "Balance")
        .unwrap_or_default();
    let balance = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal_bytes);
    assert!(
        balance > num_bigint::BigInt::from(0),
        "worker prover must receive a non-zero reward (got {balance})"
    );
    eprintln!("worker prover reward balance: {balance}");
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
        hypergraph: None,
        replica_store: None,
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
        // `prover` is the BLS pubkey (a real G2 point) — the committee
        // member; the attestation verifier reconstructs the aggregate
        // pubkey from the registry's active member, so the declared
        // pubkey in `single_signer_agg_sig` must use the same key.
        prover: prover.bls_pubkey.clone(),
        fee_multiplier_vote: 1,
        public_key_signature_bls48581: single_signer_agg_sig(&prover.bls_pubkey)
            .to_canonical_bytes()
            .expect("self-coverage agg sig"),
        storage_attestation_root: Vec::new(),
        global_frame_number: 0,
        storage_attestation: Vec::new(),
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
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Seed the synthetic worker as an Active prover on the coverage
    // frame's shard filter so the archive's attestation verifier can
    // reconstruct the (single-member) committee that signed it.
    quil_engine::genesis::seed_active_prover_on_filter(
        &archive.crdt,
        &prover.bls_pubkey,
        /* seniority */ 1,
        /* frame_number */ 1,
        &filter,
    )
    .expect("seed self-coverage prover as Active on shard filter");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let proto_bundles: Vec<quil_types::proto::global::MessageBundle> = inbox_snapshot
        .iter()
        .map(|b| {
            quil_engine::consensus_wire::decode_message_bundle(b).expect("self-coverage decode")
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

/// End-to-end PoRep storage audit + eviction THROUGH the real global
/// materialize path (`FrameMaterializer` → `invoke_frame_header` → sig verify
/// → archive-mode gate → `audit_storage_attestation` → `kick_prover_by_address`).
///
/// A prover is Active on a shard but submits a reward proof whose carried
/// `StorageAttestation` opening is UNREGISTERED (no on-chain
/// `leafroot:LeafRootRegistration` vertex), so the ρ_N-sampled audit's registry
/// cross-check fails → the member is evicted. Asserts the on-chain eviction
/// signature (Seniority zeroed + KickFrameNumber set), proving the audit is
/// actually reached in the materialize pipeline (not just the unit-tested
/// helper) and that it mutates committed prover state.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tier2_storage_audit_evicts_cheating_member() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    quil_crypto::init();

    let prover = TestProver::generate();
    let filter: Vec<u8> = vec![0x46; 32];

    // One opening for `prover`, at the current epoch, but with NO matching
    // leaf-root registration on chain → the audit's registry cross-check fails.
    let opening = quil_types::proto::global::StorageOpening {
        shard_id: vec![0x07u8; 32],
        epoch: quil_types::consensus::epoch_for_frame(1000),
        member_id: prover.address.clone(),
        query: 0,
        leaf_root: vec![0u8; 666],
        num_blocks: 1,
        path_commits: vec![],
        path_proofs: vec![],
        commitment: vec![0u8; 666],
        value: vec![0u8; 32],
        proof: vec![0u8; 666],
    };
    let att = quil_types::proto::global::StorageAttestation {
        openings: vec![opening],
    };

    // Reward proof anchored to a real global frame (gfn=1000 → storage active),
    // signed by the single-member committee (this prover). `output=[0;516]` is
    // accepted by the rig's frame prover (same as `self_coverage_*`).
    let reward = quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: filter.clone(),
        frame_number: 5,
        rank: 0,
        timestamp: 1_700_000_000_000,
        difficulty: 100_000,
        output: vec![0u8; 516],
        parent_selector: vec![0u8; 64],
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 64]; 4],
        prover: prover.bls_pubkey.clone(),
        fee_multiplier_vote: 1,
        public_key_signature_bls48581: single_signer_agg_sig(&prover.bls_pubkey)
            .to_canonical_bytes()
            .expect("agg sig"),
        storage_attestation_root: vec![0u8; 666],
        global_frame_number: 1000,
        storage_attestation: prost::Message::encode_to_vec(&att),
    };
    let header_bytes = reward.to_canonical_bytes().expect("encode reward proof");
    let bundle = {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let req = CanonicalMessageRequest::wrap(header_bytes).expect("wrap reward");
        CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .expect("encode bundle")
    };

    let genesis_provers: Vec<TestProver> = (0..3).map(|_| TestProver::generate()).collect();
    let seed_hex = build_genesis_seed_hex(&genesis_provers);
    let archive = build_tier2_archive_rig(genesis_provers[0].clone(), &genesis_provers, &seed_hex);

    // Seed the cheating prover Active on the shard (seniority 1) so the
    // attestation verifier reconstructs the single-member committee + the kick
    // has a prover vertex to mutate.
    quil_engine::genesis::seed_active_prover_on_filter(
        &archive.crdt,
        &prover.bls_pubkey,
        /* seniority */ 1,
        /* frame_number */ 1,
        &filter,
    )
    .expect("seed cheating prover Active on shard filter");
    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);

    let before = archive
        .prover_registry
        .read(|r| r.get_prover_info(&prover.address).cloned())
        .expect("prover present before audit");
    assert_eq!(
        before.seniority, 1,
        "precondition: prover Active with seniority 1"
    );
    assert_eq!(before.kick_frame_number, 0, "precondition: not yet kicked");

    // STRICT LOCKSTEP: a storage frame's attestation must anchor to the
    // IMMEDIATELY PRECEDING global frame, so the enclosing global frame number
    // must be `global_frame_number + 1` (= 1001) to satisfy the
    // `anchor == frame_number - 1` gate in `audit_storage_attestation`.
    let coverage_frame = build_global_frame_with_bundle(1001, &bundle);
    let result = archive
        .materializer
        .materialize(&coverage_frame)
        .expect("materialize reward proof with cheating attestation");
    assert!(
        result.processed >= 1,
        "reward proof must be processed by the materializer; processed={} skipped={}",
        result.processed,
        result.skipped,
    );

    archive
        .prover_registry
        .refresh_from_store(&archive.hg_store);
    let after = archive
        .prover_registry
        .read(|r| r.get_prover_info(&prover.address).cloned())
        .expect("prover present after audit");
    // Eviction signature: the kick zeroes the prover's seniority and stamps the
    // allocation with the kick frame (the same `materialize_prover_kick` path a
    // signed ProverKick uses).
    assert_eq!(
        after.seniority, 0,
        "storage audit must evict the unregistered member (Seniority → 0)",
    );
    assert!(
        after.allocations.iter().any(|a| a.kick_frame_number > 0),
        "evicted member's allocation must carry a KickFrameNumber; allocs={:?}",
        after
            .allocations
            .iter()
            .map(|a| (a.status, a.kick_frame_number))
            .collect::<Vec<_>>(),
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
        let message_collector = Arc::new(quil_engine::message_collector::MessageCollector::new());
        let coverage_published: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cp_for_cb = coverage_published.clone();
        let coverage_publish: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> =
            Some(Arc::new(move |bytes: Vec<u8>| {
                cp_for_cb.lock().push(bytes);
            }));

        let deps = quil_engine::app_engine::AppEngineDeps {
            clock_store: clock_store as Arc<dyn ClockStore>,
            global_anchor_store: None,
            storage_source_hypergraph: None,
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
                Arc::new(NoopInclusionProver) as Arc<dyn InclusionProver + Send + Sync>
            ),
            kv_db: None,
            app_consensus_cw: false,
        };

        let (engine, handle) =
            quil_engine::app_engine::AppConsensusEngine::new(core_id, filter_bytes, deps, event_tx);
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
                    FullFrameProduced { .. } => "FullFrameProduced",
                    VoteProduced { .. } => "VoteProduced",
                    TimeoutProduced { .. } => "TimeoutProduced",
                    ShardFrameFinalized { .. } => "ShardFrameFinalized",
                    EquivocationDetected { .. } => "EquivocationDetected",
                    Halted { .. } => "Halted",
                    AncestorSyncRequested { .. } => "AncestorSyncRequested",
                    ParentSealed { .. } => "ParentSealed",
                    CwOut { .. } => "CwOut",
                };
                event_log.lock().push(name.to_string());
            }
        });

        handle
    });

    let wm = Arc::new(quil_engine::test_support::SpawningWorkerManager::new(
        spawn_fn,
    ));
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
    assert_eq!(
        log.len(),
        1,
        "expected one spawn invocation, got {}",
        log.len()
    );
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
        .filter(|e| e.starts_with("engine_panic") || e.as_str() == "engine_task_returned")
        .collect();
    assert!(
        crashed.is_empty(),
        "spawned engine task exited — wiring crash. entries={entries:?}"
    );
    let live: Vec<&String> = entries
        .iter()
        .filter(|e| !e.starts_with("engine_panic") && e.as_str() != "engine_task_returned")
        .collect();
    assert!(
        !live.is_empty(),
        "spawned engine produced no AppEngineEvent within 60s — \
         single-prover event-loop is likely busy-looping"
    );
}
