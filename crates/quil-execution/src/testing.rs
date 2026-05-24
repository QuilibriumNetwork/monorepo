//! Test-only stubs for the crypto and store traits the execution
//! engines now require. Each impl returns a reasonable default (empty
//! `Vec`, `false`, or a `not supported` error). Tests that need
//! signature-validation semantics should swap in real verifiers.
//!
//! Gated behind `cfg(any(test, feature = "testing-stubs"))` so the
//! stubs compile out of release builds: production code must never
//! reach these.
//!
//! The execution-engine constructors require crypto providers (no
//! `None` accepted), so test setups have to plumb _something_; these
//! are the minimal compileable defaults.

#![cfg(any(test, feature = "testing-stubs"))]

use std::collections::HashMap;
use std::sync::Arc;

use num_bigint::BigInt;

use quil_types::crypto::{
    BulletproofProver, DecafAgreement, DecafConstructor, KeyManager, KeyType,
    RangeProofResult,
};
use quil_types::error::{QuilError, Result};
use quil_types::execution::CircuitCompiler;
use quil_types::proto;
use quil_types::store::{ClockStore, Iterator as KvIterator, Transaction};

// ---------------------------------------------------------------------------
// Noop transaction
// ---------------------------------------------------------------------------

/// Throwaway `Transaction` impl — accepts all writes, returns nothing.
/// Only useful so `ClockStore::new_transaction` can hand back _something_;
/// stubs never persist anything that subsequent reads have to see.
pub struct NoopTxn;

impl Transaction for NoopTxn {
    fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn set(&self, _: &[u8], _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn delete(&self, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn KvIterator>> {
        Err(QuilError::Internal("noop: iterator not supported".into()))
    }
    fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// NoopBulletproofProver
// ---------------------------------------------------------------------------

/// Bulletproof prover that returns empty proofs and never verifies.
/// All `verify_*` methods return `false`, all `sign_*` methods return
/// empty bytes, and proof generation returns empty bytes. Real crypto
/// is mandatory for the verification gates the execution engines
/// install — this stub satisfies the type signature and nothing else.
pub struct NoopBulletproofProver;

impl BulletproofProver for NoopBulletproofProver {
    fn generate_range_proof(
        &self,
        _values: &[Vec<u8>],
        _blinding: &[u8],
        _bit_size: u64,
    ) -> Result<RangeProofResult> {
        Ok(RangeProofResult {
            proof: Vec::new(),
            commitments: Vec::new(),
        })
    }

    fn generate_input_commitments(
        &self,
        _values: &[Vec<u8>],
        _blinding: &[u8],
    ) -> Vec<u8> {
        Vec::new()
    }

    fn verify_range_proof(
        &self,
        _proof: &[u8],
        _commitment: &[u8],
        _bit_size: u64,
    ) -> bool {
        false
    }

    fn sum_check(
        &self,
        _inputs: &[Vec<u8>],
        _additional_inputs: &[Vec<u8>],
        _outputs: &[Vec<u8>],
        _additional_outputs: &[Vec<u8>],
    ) -> bool {
        false
    }

    fn sign_hidden(
        &self,
        _x: &[u8],
        _t: &[u8],
        _a: &[u8],
        _r: &[u8],
    ) -> Vec<u8> {
        Vec::new()
    }

    fn verify_hidden(
        &self,
        _challenge: &[u8],
        _ext_transcript: &[u8],
        _s1: &[u8],
        _s2: &[u8],
        _s3: &[u8],
        _point: &[u8],
        _commitment: &[u8],
    ) -> bool {
        false
    }

    fn simple_sign(&self, _secret_key: &[u8], _message: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn simple_verify(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _point: &[u8],
    ) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// NoopDecafConstructor
// ---------------------------------------------------------------------------

/// Decaf448 constructor that returns empty bytes / `not supported`
/// errors from every method.
pub struct NoopDecafConstructor;

impl DecafConstructor for NoopDecafConstructor {
    fn new_key(&self) -> Result<Box<dyn DecafAgreement>> {
        Err(QuilError::Internal("noop decaf constructor".into()))
    }

    fn from_bytes(&self, _private_key: &[u8]) -> Result<Box<dyn DecafAgreement>> {
        Err(QuilError::Internal("noop decaf constructor".into()))
    }

    fn hash_to_scalar(&self, _data: &[u8]) -> Result<Vec<u8>> {
        // Fail-closed: returning a fabricated zero scalar would let
        // signing/verification math proceed on a known-bad value.
        // Stub must reject so the upstream verify gate observes a
        // crypto failure, not a degenerate "valid" result.
        Err(QuilError::Internal("noop decaf constructor".into()))
    }

    fn new_from_scalar(
        &self,
        _scalar: &[u8],
    ) -> Result<Box<dyn DecafAgreement>> {
        Err(QuilError::Internal("noop decaf constructor".into()))
    }

    fn alt_generator(&self) -> Vec<u8> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// NoopKeyManager
// ---------------------------------------------------------------------------

/// Key manager that rejects every signature. Pair with a stub
/// transport layer when testing materializer failure paths — the
/// global engine's validate-signature gates short-circuit on `Ok(false)`
/// from this manager and surface `signature verification failed`.
///
/// For tests that need permissive behaviour (i.e. happy-path
/// materializer runs), use `quil_engine::test_support::AcceptAllKeyManager`
/// instead.
pub struct NoopKeyManager;

impl KeyManager for NoopKeyManager {
    fn validate_signature(
        &self,
        _key_type: KeyType,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
        _domain: &[u8],
    ) -> Result<bool> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// NoopCircuitCompiler
// ---------------------------------------------------------------------------

/// Circuit compiler that errors on every call. `validate_circuit` is
/// the only method `verify_code_deployment` calls, and it must
/// fail-closed — accepting every circuit would silently admit
/// unvalidated code deploys.
pub struct NoopCircuitCompiler;

impl CircuitCompiler for NoopCircuitCompiler {
    fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
        Err(QuilError::Internal("noop circuit compiler".into()))
    }

    fn validate_circuit(&self, _circuit: &[u8]) -> Result<()> {
        Err(QuilError::Internal("noop circuit compiler".into()))
    }
}

// ---------------------------------------------------------------------------
// NoopClockStore
// ---------------------------------------------------------------------------

/// ClockStore that errors on every read and accepts every write. Used
/// only to satisfy the `Arc<dyn ClockStore>` slot on `TokenExecutionEngine`
/// for tests that don't actually exercise PoMW mints (the only
/// dispatch path that reads from the clock store).
pub struct NoopClockStore;

impl ClockStore for NoopClockStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(NoopTxn))
    }

    fn get_latest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_earliest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_global_clock_frame(
        &self,
        _frame_number: u64,
    ) -> Result<proto::global::GlobalFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn put_global_clock_frame(
        &self,
        _frame: &proto::global::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }
    fn put_global_clock_frame_candidate(
        &self,
        _frame: &proto::global::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }
    fn get_global_clock_frame_candidate(
        &self,
        _frame_number: u64,
        _selector: &[u8],
    ) -> Result<proto::global::GlobalFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn delete_global_clock_frame_range(
        &self,
        _min_frame: u64,
        _max_frame: u64,
    ) -> Result<()> {
        Ok(())
    }
    fn reset_global_clock_frames(&self) -> Result<()> {
        Ok(())
    }

    fn get_latest_certified_global_state(
        &self,
    ) -> Result<proto::global::GlobalProposal> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_earliest_certified_global_state(
        &self,
    ) -> Result<proto::global::GlobalProposal> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_certified_global_state(
        &self,
        _rank: u64,
    ) -> Result<proto::global::GlobalProposal> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn put_certified_global_state(
        &self,
        _state: &proto::global::GlobalProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }

    fn get_latest_quorum_certificate(
        &self,
        _filter: &[u8],
    ) -> Result<proto::global::QuorumCertificate> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_quorum_certificate(
        &self,
        _filter: &[u8],
        _rank: u64,
    ) -> Result<proto::global::QuorumCertificate> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn put_quorum_certificate(
        &self,
        _qc: &proto::global::QuorumCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }

    fn get_latest_timeout_certificate(
        &self,
        _filter: &[u8],
    ) -> Result<proto::global::TimeoutCertificate> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_timeout_certificate(
        &self,
        _filter: &[u8],
        _rank: u64,
    ) -> Result<proto::global::TimeoutCertificate> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn put_timeout_certificate(
        &self,
        _tc: &proto::global::TimeoutCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }

    fn get_latest_shard_clock_frame(
        &self,
        _filter: &[u8],
    ) -> Result<proto::global::AppShardFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _truncate: bool,
    ) -> Result<proto::global::AppShardFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn commit_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _selector: &[u8],
        _txn: &dyn Transaction,
        _backfill: bool,
    ) -> Result<()> {
        Ok(())
    }
    fn stage_shard_clock_frame(
        &self,
        _selector: &[u8],
        _frame: &proto::global::AppShardFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }
    fn get_staged_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _parent_selector: &[u8],
        _truncate: bool,
    ) -> Result<proto::global::AppShardFrame> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn set_latest_shard_clock_frame_number(
        &self,
        _filter: &[u8],
        _frame_number: u64,
    ) -> Result<()> {
        Ok(())
    }
    fn delete_shard_clock_frame_range(
        &self,
        _filter: &[u8],
        _min_frame: u64,
        _max_frame: u64,
    ) -> Result<()> {
        Ok(())
    }
    fn reset_shard_clock_frames(&self, _filter: &[u8]) -> Result<()> {
        Ok(())
    }

    fn get_latest_certified_app_shard_state(
        &self,
        _filter: &[u8],
    ) -> Result<proto::global::AppShardProposal> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn put_certified_app_shard_state(
        &self,
        _state: &proto::global::AppShardProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        Ok(())
    }

    fn put_proposal_vote(
        &self,
        _txn: &dyn Transaction,
        _vote: &proto::global::ProposalVote,
    ) -> Result<()> {
        Ok(())
    }
    fn get_proposal_vote(
        &self,
        _filter: &[u8],
        _rank: u64,
        _identity: &[u8],
    ) -> Result<proto::global::ProposalVote> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_proposal_votes(
        &self,
        _filter: &[u8],
        _rank: u64,
    ) -> Result<Vec<proto::global::ProposalVote>> {
        Ok(Vec::new())
    }
    fn put_timeout_vote(
        &self,
        _txn: &dyn Transaction,
        _vote: &proto::global::TimeoutState,
    ) -> Result<()> {
        Ok(())
    }
    fn get_timeout_vote(
        &self,
        _filter: &[u8],
        _rank: u64,
        _identity: &[u8],
    ) -> Result<proto::global::TimeoutState> {
        Err(QuilError::NotFound("noop clock store".into()))
    }
    fn get_timeout_votes(
        &self,
        _filter: &[u8],
        _rank: u64,
    ) -> Result<Vec<proto::global::TimeoutState>> {
        Ok(Vec::new())
    }

    fn get_total_distance(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _selector: &[u8],
    ) -> Result<BigInt> {
        Ok(BigInt::from(0))
    }
    fn set_total_distance(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _selector: &[u8],
        _total_distance: &BigInt,
    ) -> Result<()> {
        Ok(())
    }
    fn get_peer_seniority_map(
        &self,
        _filter: &[u8],
    ) -> Result<HashMap<String, u64>> {
        Ok(HashMap::new())
    }
    fn put_peer_seniority_map(
        &self,
        _txn: &dyn Transaction,
        _filter: &[u8],
        _seniority_map: &HashMap<String, u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn compact_data(&self, _data_filter: &[u8]) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NoopHypergraphConfigResolver
// ---------------------------------------------------------------------------

/// Hypergraph config resolver that returns no write key for every
/// domain. Pairs the resolver-mandatory contract with fail-closed
/// semantics: every signature-verification call resolves to
/// `AuthCheck::UnknownDomain`, which the engine rejects. Tests that
/// need to validate genuine signature paths should construct a
/// resolver that returns a real Ed448 public key for the test domain.
pub struct NoopHypergraphConfigResolver;

impl crate::hypergraph_intrinsic::HypergraphConfigResolver
    for NoopHypergraphConfigResolver
{
    fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

// ---------------------------------------------------------------------------
// Bundle helper
// ---------------------------------------------------------------------------

/// Convenience: bundle the four crypto/store stubs into the right
/// trait-object types for `TokenExecutionEngine::new` /
/// `ComputeExecutionEngine::new`. Tests that don't care about which
/// stubs they use should call this rather than naming each one.
pub struct NoopExecutionCrypto {
    pub bulletproof_prover: Arc<dyn BulletproofProver>,
    pub decaf_constructor: Arc<dyn DecafConstructor>,
    pub key_manager: Arc<dyn KeyManager>,
    pub circuit_compiler: Arc<dyn CircuitCompiler>,
    pub clock_store: Arc<dyn ClockStore>,
}

impl NoopExecutionCrypto {
    pub fn new() -> Self {
        Self {
            bulletproof_prover: Arc::new(NoopBulletproofProver),
            decaf_constructor: Arc::new(NoopDecafConstructor),
            key_manager: Arc::new(NoopKeyManager),
            circuit_compiler: Arc::new(NoopCircuitCompiler),
            clock_store: Arc::new(NoopClockStore),
        }
    }
}

impl Default for NoopExecutionCrypto {
    fn default() -> Self {
        Self::new()
    }
}
