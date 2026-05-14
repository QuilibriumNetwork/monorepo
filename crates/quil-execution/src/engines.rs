use std::sync::Arc;

use num_bigint::BigInt;
use prost::Message as _;
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::execution::{ProcessMessageResult, ShardExecutionEngine};
use quil_types::proto::{global, node};
use quil_types::proto::global::message_request::Request as MessageRequestInner;

use crate::domains;
use crate::hypergraph_intrinsic::dispatch as hg_dispatch;
use crate::message_envelope::{
    CanonicalMessageBundle, CanonicalMessageRequest,
    TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
};

/// Shared helper: decode `bytes` as a prost-encoded `MessageRequest`
/// (the wire format clients use for the consensus RPCs), confirm the
/// oneof variant routes to the engine identified by `engine_name`,
/// and return the proto. The `accepts` predicate inspects the inner
/// variant — each engine impl supplies its own accept set so the
/// dispatcher stays type-safe.
fn decode_proto_message_request_for_engine<F>(
    bytes: &[u8],
    accepts: F,
    engine_name: &'static str,
) -> Result<global::MessageRequest>
where
    F: FnOnce(&Option<MessageRequestInner>) -> bool,
{
    let req = global::MessageRequest::decode(bytes).map_err(|e| {
        QuilError::InvalidArgument(format!(
            "{} prove: decode MessageRequest proto failed: {e}",
            engine_name
        ))
    })?;
    if !accepts(&req.request) {
        return Err(QuilError::InvalidArgument(format!(
            "{} prove: oneof variant does not route to this engine",
            engine_name
        )));
    }
    Ok(req)
}

/// Engine type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineType {
    Global,
    Token,
    Compute,
    Hypergraph,
}

impl EngineType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Global => "global",
            Self::Token => "token",
            Self::Compute => "compute",
            Self::Hypergraph => "hypergraph",
        }
    }
}

/// Execution mode — global engines only handle deploys, app engines
/// handle both deploys and invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Global,
    Application,
}

/// Global execution engine — handles prover joins/leaves, shard management,
/// and global state transitions.
pub struct GlobalExecutionEngine {
    inclusion_prover: Arc<dyn InclusionProver>,
    intrinsic: Option<crate::global_intrinsic::intrinsic::GlobalIntrinsic>,
    crdt: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// The HypergraphState used for invoke_step materialization.
    /// Created lazily when the CRDT is available.
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
}

impl GlobalExecutionEngine {
    pub fn new(inclusion_prover: Arc<dyn InclusionProver>) -> Self {
        Self {
            inclusion_prover,
            intrinsic: None,
            crdt: None,
            state: None,
        }
    }

    /// Install the prover_registry + reward_issuance + hypergraph
    /// dependencies that `invoke_frame_header` needs to actually
    /// mutate state. Without this call, FrameHeader requests
    /// (shard-coverage attributions) reach `invoke_frame_header` but
    /// return `Ok(())` early — no `LastActiveFrameNumber` advance, no
    /// reward distribution, no eviction tracking. Mirrors Go's
    /// `materializer.NewProverShardUpdateMaterializer` wiring.
    ///
    /// The hypergraph dep is needed for `shard_metadata_for_address`
    /// (the per-ring reward calculation reads state size / shard
    /// count from the CRDT). It's normally available because the
    /// engine was built `new_with_intrinsic(.., crdt)`, but the
    /// intrinsic's internal hypergraph slot is separate from the
    /// engine's `crdt` field and has to be set independently.
    pub fn install_frame_header_deps(
        &mut self,
        prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
        reward_issuance: Arc<dyn quil_types::consensus::RewardIssuance>,
        bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor>,
        inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    ) {
        if let Some(intrinsic) = self.intrinsic.take() {
            let mut updated = intrinsic
                .with_frame_header_deps(prover_registry, reward_issuance);
            if let Some(crdt) = self.crdt.clone() {
                updated = updated.with_kick_verify_deps(
                    bls_constructor,
                    crdt,
                    inclusion_prover,
                );
            }
            self.intrinsic = Some(updated);
        }
    }

    /// Create with full dependencies for real signature verification
    /// and state materialization.
    pub fn new_with_intrinsic(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt.clone()));
        Self {
            inclusion_prover,
            intrinsic: Some(crate::global_intrinsic::intrinsic::GlobalIntrinsic::new(key_manager)),
            crdt: Some(crdt),
            state: Some(state),
        }
    }
}

impl ShardExecutionEngine for GlobalExecutionEngine {
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn get_name(&self) -> &str {
        "global"
    }

    fn validate_message(&self, frame_number: u64, address: &[u8], message: &[u8]) -> Result<()> {
        if address != domains::GLOBAL {
            return Err(QuilError::InvalidArgument("not a global message".into()));
        }
        if message.len() < 4 {
            return Ok(());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        // Helper: validate a single inner op with full signature verification.
        // Loads prover/allocation trees from the CRDT for BLS signature checks.
        let validate_inner = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::global_engine::is_global_type_prefix(inner_tp) {
                return Ok(()); // not a global op, skip
            }
            if let (Some(ref intrinsic), Some(ref state)) = (&self.intrinsic, &self.state) {
                // Extract the prover address from the addressed signature
                // to load the prover and allocation trees.
                let (prover_tree, alloc_tree) = load_trees_for_validation(
                    inner_bytes, inner_tp, state,
                );
                match intrinsic.validate(
                    frame_number,
                    inner_bytes,
                    prover_tree.as_ref(),
                    alloc_tree.as_ref(),
                )? {
                    true => Ok(()),
                    false => Err(QuilError::InvalidArgument(
                        "global: signature verification failed".into(),
                    )),
                }
            } else if let Some(ref intrinsic) = self.intrinsic {
                // Intrinsic present but no state — structural only
                match intrinsic.validate(frame_number, inner_bytes, None, None)? {
                    true => Ok(()),
                    false => Err(QuilError::InvalidArgument(
                        "global: signature verification failed".into(),
                    )),
                }
            } else {
                crate::global_engine::peek_global_message_kind(inner_bytes)?;
                Ok(())
            }
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        validate_inner(&r.inner_bytes, r.inner_type_prefix)?;
                    }
                }
                Ok(())
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                validate_inner(&req.inner_bytes, req.inner_type_prefix)
            }
            _ => Err(QuilError::InvalidArgument(
                "global: unsupported message type".into(),
            )),
        }
    }

    fn process_message(
        &self,
        _frame_number: u64,
        _fee_multiplier: &BigInt,
        _address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        if message.len() < 4 {
            return Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() });
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        // Helper: invoke_step on a single inner op if it's a global type
        let invoke = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::global_engine::is_global_type_prefix(inner_tp) {
                return Ok(());
            }
            if let (Some(ref intrinsic), Some(ref state)) = (&self.intrinsic, &self.state) {
                intrinsic.invoke_step(_frame_number, inner_bytes, state)?;
            }
            Ok(())
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if let Err(e) = invoke(&r.inner_bytes, r.inner_type_prefix) {
                            eprintln!(
                                "[WARN] global invoke_step failed for bundle request type=0x{:08x}: {}",
                                r.inner_type_prefix, e
                            );
                        }
                    }
                }
                // `invoke_step` only buffers writes onto the
                // HypergraphState changeset — nothing reaches the CRDT
                // (and therefore the on-disk hypergraph trees) until
                // `state.commit()` runs. Without this commit, the
                // prover registry's `refresh_from_store` can never
                // observe new ProverJoin/Confirm/Leave entries: each
                // node materializes correctly in memory but its tree
                // blobs stay frozen at genesis. Mirrors Go's
                // `frame_materializer.go:235` `state.Commit()` call
                // after every materialize_X.
                if let Some(ref state) = self.state {
                    if let Err(e) = state.commit() {
                        eprintln!("[WARN] global state.commit failed: {}", e);
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                if let Err(e) = invoke(&req.inner_bytes, req.inner_type_prefix) {
                    eprintln!(
                        "[WARN] global invoke_step failed for single request type=0x{:08x}: {}",
                        req.inner_type_prefix, e
                    );
                }
                if let Some(ref state) = self.state {
                    if let Err(e) = state.commit() {
                        eprintln!("[WARN] global state.commit failed: {}", e);
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            _ => Err(QuilError::InvalidArgument(
                "global: unsupported message type".into(),
            )),
        }
    }

    fn prove(
        &self,
        _domain: &[u8],
        _frame_number: u64,
        message: &[u8],
    ) -> Result<global::MessageRequest> {
        // Client-side helper: decode `message` as a prost-encoded
        // MessageRequest and confirm its oneof variant routes to the
        // global engine. Proving (signature/proof generation) is the
        // caller's responsibility — by the time bytes reach this
        // method they are expected to be a fully-proven request.
        decode_proto_message_request_for_engine(message, |inner| match inner {
            Some(MessageRequestInner::Join(_))
            | Some(MessageRequestInner::Leave(_))
            | Some(MessageRequestInner::Pause(_))
            | Some(MessageRequestInner::Resume(_))
            | Some(MessageRequestInner::Confirm(_))
            | Some(MessageRequestInner::Reject(_))
            | Some(MessageRequestInner::Kick(_))
            | Some(MessageRequestInner::Update(_))
            | Some(MessageRequestInner::Shard(_))
            | Some(MessageRequestInner::SeniorityMerge(_)) => true,
            _ => false,
        }, "global")
    }

    fn lock(&self, _frame_number: u64, _address: &[u8], _message: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Global ops don't declare lock addresses in the current protocol.
        Ok(Vec::new())
    }

    fn unlock(&self) -> Result<()> {
        Ok(())
    }

    fn get_cost(&self, message: &[u8]) -> Result<BigInt> {
        Ok(crate::global_engine::global_engine_cost(message))
    }

    fn get_capabilities(&self) -> Vec<node::Capability> {
        crate::global_engine::global_engine_capabilities()
    }
}

/// Token execution engine — handles token deploys, transfers,
/// minting, and pending transactions.
///
/// Crypto dependencies: structural validation runs without them, but
/// the full hidden-Schnorr + bulletproof + Decaf-scalar verify paths
/// at dispatch time need `BulletproofProver` (range proofs + sum
/// checks + hidden-sig verify) and `DecafConstructor`
/// (`hash_to_scalar` for transcript → challenge). Keep them optional
/// so test contexts without real crypto can still construct the
/// engine — `process_message` falls back to structural-only on `None`.
pub struct TokenExecutionEngine {
    mode: ExecutionMode,
    inclusion_prover: Arc<dyn InclusionProver>,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    bulletproof_prover: Option<Arc<dyn quil_types::crypto::BulletproofProver>>,
    decaf_constructor: Option<Arc<dyn quil_types::crypto::DecafConstructor>>,
    key_manager: Option<Arc<dyn quil_types::crypto::KeyManager>>,
    clock_store: Option<Arc<dyn quil_types::store::ClockStore>>,
    config_resolver: Arc<dyn crate::token_intrinsic::config_resolver::TokenConfigResolver>,
}

impl TokenExecutionEngine {
    pub fn new(mode: ExecutionMode) -> Self {
        Self {
            mode,
            inclusion_prover: Arc::new(NoopInclusionProver),
            state: None,
            bulletproof_prover: None,
            decaf_constructor: None,
            key_manager: None,
            clock_store: None,
            config_resolver: Arc::new(
                crate::token_intrinsic::config_resolver::QuilOnlyConfigResolver,
            ),
        }
    }

    pub fn new_with_state(
        mode: ExecutionMode,
        inclusion_prover: Arc<dyn InclusionProver>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            inclusion_prover,
            state: Some(state),
            bulletproof_prover: None,
            decaf_constructor: None,
            key_manager: None,
            clock_store: None,
            config_resolver: Arc::new(
                crate::token_intrinsic::config_resolver::QuilOnlyConfigResolver,
            ),
        }
    }

    /// Install the crypto providers so `process_message` runs full
    /// hidden-Schnorr + bulletproof + sum-check verify (not just
    /// structural) before state mutation. Without these the dispatch
    /// falls back to structural-only validation matching the pre-crypto
    /// port behaviour.
    pub fn with_crypto(
        mut self,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    ) -> Self {
        self.bulletproof_prover = Some(bulletproof_prover);
        self.decaf_constructor = Some(decaf_constructor);
        self.key_manager = Some(key_manager);
        self
    }

    /// Install a ClockStore so per-input PoMW verify can resolve the
    /// cited frame's `prover_tree_commitment` for the reward-tree
    /// traversal proof. Without this, QUIL PoMW mints are only checked
    /// structurally + bulletproof + balance-sufficient in materialize.
    pub fn with_clock_store(
        mut self,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        self.clock_store = Some(clock_store);
        self
    }

    /// Install a `TokenConfigResolver` for non-QUIL mint dispatch.
    /// Needed when the engine must verify+materialize mints for
    /// custom-deployed tokens using MintWithAuthority/Signature/Verkle
    /// /Payment variants. The default is `QuilOnlyConfigResolver`.
    pub fn with_config_resolver(
        mut self,
        resolver: Arc<dyn crate::token_intrinsic::config_resolver::TokenConfigResolver>,
    ) -> Self {
        self.config_resolver = resolver;
        self
    }
}

/// Stub inclusion prover for when no real prover is available.
struct NoopInclusionProver;
impl InclusionProver for NoopInclusionProver {
    fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
    fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
    fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn quil_types::crypto::Multiproof>> { Err(QuilError::Internal("batch multiproof generation not supported".into())) }
    fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
}

impl ShardExecutionEngine for TokenExecutionEngine {
    fn get_name(&self) -> &str {
        "token"
    }

    fn validate_message(&self, _frame_number: u64, _address: &[u8], message: &[u8]) -> Result<()> {
        if message.len() < 4 {
            return Ok(());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        // Validate a single inner token op — decode + structural checks
        let validate_token_inner = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::token_engine::is_token_type_prefix(inner_tp) {
                return Ok(());
            }
            match inner_tp {
                crate::token_engine::TYPE_TRANSACTION => {
                    let tx = crate::token_intrinsic::Transaction::from_canonical_bytes(inner_bytes)?;
                    crate::token_intrinsic::verify::validate_transaction_structural(
                        tx.inputs.len(), tx.outputs.len(), &tx.fees,
                        crate::token_intrinsic::constants::QUIL_BEHAVIOR, tx.inputs.len(),
                    )?;
                    // Validate individual input field lengths
                    for raw_input in &tx.inputs {
                        let input = crate::token_intrinsic::TransactionInput::from_canonical_bytes(raw_input)?;
                        crate::token_intrinsic::verify::validate_input_structural(
                            &input.commitment, &input.signature,
                        )?;
                    }
                }
                crate::token_engine::TYPE_MINT_TRANSACTION => {
                    let tx = crate::token_intrinsic::MintTransaction::from_canonical_bytes(inner_bytes)?;
                    crate::token_intrinsic::verify::validate_mint_transaction_structural(
                        tx.inputs.len(), tx.outputs.len(), &tx.fees,
                        crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                    )?;
                }
                crate::token_engine::TYPE_PENDING_TRANSACTION => {
                    let tx = crate::token_intrinsic::PendingTransaction::from_canonical_bytes(inner_bytes)?;
                    // Structural-only validation at the validate_message
                    // phase: ACCEPTABLE flag check + exactly-2-outputs +
                    // fee bounds + non-divisible I/O-count parity. Full
                    // crypto verify runs later in process_message via
                    // `pending::verify_pending_transaction` once the
                    // hypergraph CRDT and BulletproofProver+DecafConstructor
                    // are available.
                    crate::token_intrinsic::pending::validate_pending_structural(
                        &tx,
                        crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                    )?;
                    // Per-input structural: 336/259-byte sig length, commitment=56B
                    // Mirror of Go `PendingTransactionInput.Verify` structural checks.
                    // Legacy 259-byte sigs only allowed for QUIL domain.
                    let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                    let check_legacy = is_quil;
                    for raw in &tx.inputs {
                        let input = crate::token_intrinsic::PendingTransactionInput::from_canonical_bytes(raw)?;
                        crate::token_intrinsic::pending::validate_pending_input_structural(
                            &input,
                            crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                            check_legacy,
                        )?;
                    }
                    // Per-output structural: commitment/recipient field sizes,
                    // non-divisible addref parity.
                    for raw in &tx.outputs {
                        let output = crate::token_intrinsic::PendingTransactionOutput::from_canonical_bytes(raw)?;
                        crate::token_intrinsic::pending::validate_pending_output_structural(
                            &output,
                            crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                        )?;
                    }
                }
                _ => {
                    crate::token_engine::peek_token_message_kind(inner_bytes)?;
                }
            }
            Ok(())
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        validate_token_inner(&r.inner_bytes, r.inner_type_prefix)?;
                    }
                }
                Ok(())
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                validate_token_inner(&req.inner_bytes, req.inner_type_prefix)
            }
            _ => Err(QuilError::InvalidArgument("token: unsupported message type".into())),
        }
    }

    fn process_message(
        &self,
        _frame_number: u64,
        _fee_multiplier: &BigInt,
        _address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        if message.len() < 4 {
            return Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() });
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        let invoke_token = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::token_engine::is_token_type_prefix(inner_tp) {
                return Ok(());
            }
            let state = match &self.state {
                Some(s) => s,
                None => return Ok(()), // no state = skip materialization
            };
            let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;

            match inner_tp {
                crate::token_engine::TYPE_TRANSACTION => {
                    let tx = crate::token_intrinsic::Transaction::from_canonical_bytes(inner_bytes)?;

                    // Full crypto verify when the engine has the
                    // providers installed (via `with_crypto`). Without
                    // them we fall back to the validator's
                    // structural-only path — matches Go's pre-2.1
                    // behaviour on the same path. Any caller who wants
                    // mainnet-parity MUST call `with_crypto` at engine
                    // construction.
                    if let (Some(bp), Some(decaf)) = (
                        self.bulletproof_prover.as_deref(),
                        self.decaf_constructor.as_deref(),
                    ) {
                        let transcript = crate::token_intrinsic::verify::build_transaction_transcript(&tx)?;
                        let challenge = decaf.hash_to_scalar(&transcript)?;
                        // Per-input hidden Schnorr verify. Go fails the
                        // whole transaction on any single input reject,
                        // matching our short-circuit here.
                        for (idx, raw) in tx.inputs.iter().enumerate() {
                            let input = crate::token_intrinsic::TransactionInput::from_canonical_bytes(raw)?;
                            crate::token_intrinsic::verify::validate_input_structural(
                                &input.commitment,
                                &input.signature,
                            )?;
                            let ok = crate::token_intrinsic::verify::verify_input_hidden_signature(
                                bp,
                                &input.signature,
                                &challenge,
                            )?;
                            if !ok {
                                return Err(QuilError::InvalidArgument(format!(
                                    "transaction: input {} hidden-signature verify failed",
                                    idx
                                )));
                            }
                        }
                        // Bulletproof range proof + sum check on output
                        // commitments. `verify_transaction_crypto`
                        // handles the quil-vs-other-domain fee inclusion
                        // internally.
                        let input_commits: Vec<Vec<u8>> = tx.inputs
                            .iter()
                            .map(|raw| {
                                crate::token_intrinsic::TransactionInput::from_canonical_bytes(raw)
                                    .map(|i| i.commitment)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let output_commits: Vec<Vec<u8>> = tx.outputs
                            .iter()
                            .map(|raw| {
                                crate::token_intrinsic::TransactionOutput::from_canonical_bytes(raw)
                                    .map(|o| o.commitment)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                        let verified = crate::token_intrinsic::verify::verify_transaction_crypto(
                            bp,
                            &input_commits,
                            &output_commits,
                            &tx.fees,
                            &tx.range_proof,
                            is_quil,
                        )?;
                        if !verified {
                            return Err(QuilError::InvalidArgument(
                                "transaction: bulletproof range/sum verify failed".into(),
                            ));
                        }
                    }

                    let mat_outputs = parse_tx_outputs(&tx.outputs, _frame_number)?;
                    let sigs = parse_tx_input_sigs(&tx.inputs)?;
                    let result = crate::token_intrinsic::materialize::materialize_transaction(
                        _address, &mat_outputs, &sigs, self.inclusion_prover.as_ref(),
                    )?;
                    write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                }
                crate::token_engine::TYPE_MINT_TRANSACTION => {
                    let tx = crate::token_intrinsic::MintTransaction::from_canonical_bytes(inner_bytes)?;

                    // Mint verify pipeline (Go `MintTransaction.Verify`
                    // + per-input `MintTransactionInput.Verify`):
                    //
                    // 1. Decode all inputs + outputs (needed for
                    //    per-input verify and transcript + bulletproof).
                    // 2. Bulletproof range-proof over concat output
                    //    commitments + sum check inputs==outputs (no
                    //    fees for mints).
                    // 3. Per-input PoMW verify via
                    //    `verify_mint_transaction_pomw`: resolves the
                    //    cited frame's reward root (QUIL: ClockStore
                    //    prover_tree_commitment; non-QUIL: shard
                    //    vertex_adds commit) and runs the 13-check
                    //    `verify_pomw_input` chain per input. Currently
                    //    assumes PoMW behavior for all tokens — once
                    //    token config lookup by `_address` lands, route
                    //    Authority-configured tokens through
                    //    `verify_authority` instead.
                    let mut decoded_inputs: Vec<crate::token_intrinsic::MintTransactionInput> =
                        Vec::with_capacity(tx.inputs.len());
                    for raw in &tx.inputs {
                        decoded_inputs.push(
                            crate::token_intrinsic::MintTransactionInput::from_canonical_bytes(raw)?,
                        );
                    }
                    let mut decoded_outputs: Vec<crate::token_intrinsic::MintTransactionOutput> =
                        Vec::with_capacity(tx.outputs.len());
                    for raw in &tx.outputs {
                        decoded_outputs.push(
                            crate::token_intrinsic::MintTransactionOutput::from_canonical_bytes(raw)?,
                        );
                    }

                    // Resolve the per-token mint variant from the
                    // TokenConfigResolver. Default resolver routes QUIL
                    // → PoMW; custom deployments can install a richer
                    // resolver via `with_config_resolver`.
                    use crate::token_intrinsic::config_resolver::MintVariant;
                    let variant = self
                        .config_resolver
                        .mint_variant_for_domain(_address)
                        .unwrap_or(MintVariant::Unknown);

                    if matches!(variant, MintVariant::NoMint) {
                        return Err(QuilError::InvalidArgument(
                            "mint transaction: token has NoMintBehavior (not mintable)".into(),
                        ));
                    }
                    if matches!(variant, MintVariant::Unknown) {
                        return Err(QuilError::InvalidArgument(
                            "mint transaction: unrecognized MintBehavior/ProofBasis combination \
                             or token config resolver unavailable for domain".into(),
                        ));
                    }

                    // Crypto verify: bulletproof range + sum, then
                    // variant-specific per-input verify.
                    if let Some(bp) = self.bulletproof_prover.as_deref() {
                        let input_commits: Vec<Vec<u8>> =
                            decoded_inputs.iter().map(|i| i.commitment.clone()).collect();
                        let output_commits: Vec<Vec<u8>> =
                            decoded_outputs.iter().map(|o| o.commitment.clone()).collect();
                        let verified = crate::token_intrinsic::verify::verify_mint_transaction_crypto(
                            bp, &input_commits, &output_commits, &tx.range_proof,
                        )?;
                        if !verified {
                            return Err(QuilError::InvalidArgument(
                                "mint transaction: bulletproof range/sum verify failed".into(),
                            ));
                        }

                        match variant {
                            MintVariant::ProofOfMeaningfulWork => {
                                if let Some(km) = self.key_manager.as_deref() {
                                    let hg_arc: Arc<quil_hypergraph::HypergraphCrdt> =
                                        state.crdt().clone();
                                    crate::token_intrinsic::mint::verify_mint_transaction_pomw(
                                        &tx,
                                        &hg_arc,
                                        self.clock_store.as_deref(),
                                        self.inclusion_prover.as_ref(),
                                        bp,
                                        km,
                                    )?;
                                }
                            }
                            MintVariant::Authority | MintVariant::Signature => {
                                // Both variants run the identical
                                // 9-check chain. Requires the
                                // authority key type + pubkey from the
                                // resolver.
                                if let Some(km) = self.key_manager.as_deref() {
                                    if let (Some(decaf), Some(kt), Some(pk)) = (
                                        self.decaf_constructor.as_deref(),
                                        self.config_resolver.authority_key_type(_address),
                                        self.config_resolver.authority_public_key(_address),
                                    ) {
                                        let ok = crate::token_intrinsic::mint::verify_authority(
                                            &tx, _frame_number, kt, &pk,
                                            crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                                            bp, decaf, km,
                                        )?;
                                        if !ok {
                                            return Err(QuilError::InvalidArgument(
                                                "mint authority/signature: verify failed".into(),
                                            ));
                                        }
                                    }
                                }
                            }
                            MintVariant::VerkleMultiproofWithSignature => {
                                if let Some(vk_root) = self.config_resolver.verkle_root(_address) {
                                    // Build the output transcript via
                                    // the standard helper then run the
                                    // per-input verkle verify. (decaf
                                    // is not needed for verkle — the
                                    // transcript is byte-concat only.)
                                    let recipients: Vec<crate::token_intrinsic::transaction::RecipientBundle> =
                                        decoded_outputs.iter()
                                            .map(|o| crate::token_intrinsic::transaction::RecipientBundle::from_canonical_bytes(&o.recipient_output))
                                            .collect::<Result<Vec<_>>>()?;
                                    let input_proofs: Vec<Vec<Vec<u8>>> =
                                        decoded_inputs.iter().map(|i| i.proofs.clone()).collect();
                                    let transcript = crate::token_intrinsic::verify::build_mint_transaction_transcript(
                                        &tx.domain, &input_proofs, &decoded_outputs, &recipients,
                                    )?;
                                    for input in &decoded_inputs {
                                        crate::token_intrinsic::mint::verify_verkle_multiproof_input(
                                            input, &transcript, &vk_root,
                                            self.inclusion_prover.as_ref(),
                                            bp,
                                        )?;
                                    }
                                }
                            }
                            MintVariant::Payment => {
                                // MintWithPayment paths:
                                // - free mint (fee_baseline None or 0):
                                //   no nested tx; verify_with_payment_input
                                //   short-circuits before the callback.
                                // - paid mint: nested PendingTransaction
                                //   verify runs through the callback,
                                //   which parses `proof[..n-224]` as a
                                //   PendingTransaction and re-validates
                                //   it against the hypergraph.
                                if let Some(decaf) = self.decaf_constructor.as_deref() {
                                    let fee_baseline =
                                        self.config_resolver.payment_fee_baseline(_address);
                                    let payment_addr = self
                                        .config_resolver
                                        .payment_address(_address)
                                        .ok_or_else(|| QuilError::InvalidArgument(
                                            "mint payment: resolver missing payment_address".into(),
                                        ))?;
                                    let cfg = crate::token_intrinsic::mint::MintWithPaymentConfig {
                                        fee_baseline: fee_baseline.as_ref(),
                                        payment_address: &payment_addr,
                                    };
                                    // Build transcript once.
                                    let recipients: Vec<crate::token_intrinsic::transaction::RecipientBundle> =
                                        decoded_outputs.iter()
                                            .map(|o| crate::token_intrinsic::transaction::RecipientBundle::from_canonical_bytes(&o.recipient_output))
                                            .collect::<Result<Vec<_>>>()?;
                                    let input_proofs: Vec<Vec<Vec<u8>>> =
                                        decoded_inputs.iter().map(|i| i.proofs.clone()).collect();
                                    let transcript = crate::token_intrinsic::verify::build_mint_transaction_transcript(
                                        &tx.domain, &input_proofs, &decoded_outputs, &recipients,
                                    )?;
                                    let frame = _frame_number;
                                    let hg_arc: Arc<quil_hypergraph::HypergraphCrdt> =
                                        state.crdt().clone();
                                    for (idx, input) in decoded_inputs.iter().enumerate() {
                                        crate::token_intrinsic::mint::verify_with_payment_input(
                                            input, &transcript, idx, &cfg,
                                            decaf, bp,
                                            |nested_bytes, output_idx, _pa| {
                                                // Parse the nested
                                                // PendingTransaction
                                                // canonical bytes.
                                                let nested_tx = crate::token_intrinsic::PendingTransaction::from_canonical_bytes(nested_bytes)?;
                                                // Paid-mint always uses
                                                // the QUIL domain for
                                                // the payment (Go hard-
                                                // codes QUIL_TOKEN_CONFIGURATION
                                                // at line 1224). Call
                                                // full crypto verify
                                                // against the current
                                                // hypergraph.
                                                let verified = crate::token_intrinsic::pending::verify_pending_transaction(
                                                    &nested_tx,
                                                    frame,
                                                    crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                                                    /* is_quil_domain */ true,
                                                    bp,
                                                    decaf,
                                                    Some(hg_arc.as_ref()),
                                                )?;
                                                if !verified {
                                                    return Err(QuilError::InvalidArgument(
                                                        "mint payment: nested PendingTransaction verify failed".into(),
                                                    ));
                                                }
                                                // Decode the referenced output so the
                                                // caller can run the rate-scaled
                                                // commitment + VK checks.
                                                if output_idx >= nested_tx.outputs.len() {
                                                    return Err(QuilError::InvalidArgument(format!(
                                                        "mint payment: nested output_idx {} >= outputs len {}",
                                                        output_idx, nested_tx.outputs.len()
                                                    )));
                                                }
                                                let raw_out = &nested_tx.outputs[output_idx];
                                                let out = crate::token_intrinsic::PendingTransactionOutput::from_canonical_bytes(raw_out)?;
                                                let to_recipient = crate::token_intrinsic::transaction::RecipientBundle::from_canonical_bytes(&out.to)?;
                                                let refund_recipient = crate::token_intrinsic::transaction::RecipientBundle::from_canonical_bytes(&out.refund)?;
                                                Ok(crate::token_intrinsic::mint::NestedPendingResult {
                                                    output_commitment: out.commitment,
                                                    to_verification_key: to_recipient.verification_key,
                                                    refund_verification_key: refund_recipient.verification_key,
                                                })
                                            },
                                        )?;
                                    }
                                }
                            }
                            MintVariant::NoMint | MintVariant::Unknown => unreachable!(
                                "rejected above before crypto verify"
                            ),
                        }
                    }

                    // Materialize: PoMW decrements prover balance,
                    // everything else uses the common authority path
                    // (same coin-vertex + spent-marker writes).
                    let result = match variant {
                        MintVariant::ProofOfMeaningfulWork => {
                            let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                            crate::token_intrinsic::mint::materialize_pomw(
                                &tx, state, _frame_number, is_quil,
                                self.inclusion_prover.as_ref(),
                            )?
                        }
                        _ => crate::token_intrinsic::mint::materialize_authority(
                            &tx, self.inclusion_prover.as_ref(),
                        )?,
                    };
                    write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                }
                crate::token_engine::TYPE_PENDING_TRANSACTION => {
                    let tx = crate::token_intrinsic::PendingTransaction::from_canonical_bytes(inner_bytes)?;
                    // Structural validation is always run.
                    crate::token_intrinsic::pending::validate_pending_structural(
                        &tx,
                        crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                    )?;

                    // Full crypto verify when crypto providers are
                    // installed. Matches Go's Verify → Materialize pattern.
                    // Legacy pre-2.1 259-byte ed448 inputs are handled
                    // inside `verify_pending_transaction` via the
                    // hypergraph CRDT reference below.
                    if let (Some(bp), Some(decaf)) = (
                        self.bulletproof_prover.as_deref(),
                        self.decaf_constructor.as_deref(),
                    ) {
                        let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                        let hg_ref = Some(state.crdt().as_ref());
                        let verified = crate::token_intrinsic::pending::verify_pending_transaction(
                            &tx,
                            _frame_number,
                            crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                            is_quil,
                            bp,
                            decaf,
                            hg_ref,
                        )?;
                        if !verified {
                            return Err(QuilError::InvalidArgument(
                                "pending transaction: crypto verify failed".into(),
                            ));
                        }
                    }

                    // PendingTransaction emits a `pending:PendingTransaction`
                    // tree per canonical output (Go
                    // `buildPendingTransactionTrees:1085-1297`),
                    // not coin vertices. Coin vertices are produced
                    // later when a recipient claims via Transaction.
                    let result = crate::token_intrinsic::pending::materialize_pending_transaction(
                        &tx,
                        _frame_number,
                        crate::token_intrinsic::constants::QUIL_BEHAVIOR,
                        self.inclusion_prover.as_ref(),
                    )?;
                    for (addr, tree) in &result.pendings {
                        let blob = crate::prover_registry::vertex_tree_to_blob(tree);
                        state.set(_address, addr, &va_disc, _frame_number, blob)?;
                    }
                    for (addr, tree) in &result.spent_markers {
                        let blob = crate::prover_registry::vertex_tree_to_blob(tree);
                        state.set(_address, addr, &va_disc, _frame_number, blob)?;
                    }
                }
                // TokenDeploy / TokenUpdate: write the
                // `TokenConfigurationMetadata` tree at the metadata
                // vertex's outer key `[16<<2]`. Mirrors Go
                // `TokenIntrinsic.Deploy` at
                // `node/execution/intrinsics/token/token_intrinsic.go:208-248`.
                // Deploy gates on owner_public_key signature; Update
                // additionally validates Behavior parity + supply
                // non-decrease. The domain comes from the message
                // envelope (`_address`).
                crate::token_intrinsic::TYPE_TOKEN_DEPLOY => {
                    if _address.len() == 32 {
                        let deploy = crate::token_intrinsic::TokenDeploy::from_canonical_bytes(inner_bytes)?;
                        if !deploy.config.is_empty() {
                            let cfg = crate::token_intrinsic::TokenConfiguration::from_canonical_bytes(&deploy.config)?;
                            crate::token_intrinsic::materialize::materialize_token_deploy(
                                state,
                                _address,
                                &cfg,
                                _frame_number,
                                self.inclusion_prover.as_ref(),
                            )?;
                        }
                        self.config_resolver.invalidate(_address);
                    }
                }
                crate::token_intrinsic::TYPE_TOKEN_UPDATE => {
                    if _address.len() == 32 {
                        let update = crate::token_intrinsic::TokenUpdate::from_canonical_bytes(inner_bytes)?;
                        if !update.config.is_empty() {
                            let new_cfg = crate::token_intrinsic::TokenConfiguration::from_canonical_bytes(&update.config)?;

                            // Update gates: behavior parity + supply non-decrease.
                            // Read prior config from the metadata vertex if present.
                            let metadata_addr =
                                crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
                            if let Ok(Some(blob)) =
                                state.get(_address, &metadata_addr, &va_disc)
                            {
                                if let Ok(root) = quil_tries::deserialize_go_tree(&blob) {
                                    let outer = quil_tries::VectorCommitmentTree { root };
                                    if let Some(inner_blob) = outer.get(
                                        &crate::token_intrinsic::materialize::TOKEN_CONFIG_OUTER_KEY,
                                    ) {
                                        if let Ok(inner_root) =
                                            quil_tries::deserialize_go_tree(inner_blob)
                                        {
                                            let inner_tree =
                                                quil_tries::VectorCommitmentTree { root: inner_root };
                                            if let Ok(prior) =
                                                crate::token_intrinsic::metadata_schema::decode_token_config_from_tree(&inner_tree)
                                            {
                                                if prior.behavior != new_cfg.behavior {
                                                    return Err(QuilError::InvalidArgument(
                                                        "token update: behavior cannot be updated".into(),
                                                    ));
                                                }
                                                // Supply non-decrease (compare big-endian unsigned).
                                                if !prior.supply.is_empty()
                                                    && !new_cfg.supply.is_empty()
                                                {
                                                    use num_bigint::BigUint;
                                                    let prior_sup = BigUint::from_bytes_be(&prior.supply);
                                                    let new_sup = BigUint::from_bytes_be(&new_cfg.supply);
                                                    if new_sup < prior_sup {
                                                        return Err(QuilError::InvalidArgument(
                                                            "token update: supply cannot be reduced".into(),
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            crate::token_intrinsic::materialize::materialize_token_deploy(
                                state,
                                _address,
                                &new_cfg,
                                _frame_number,
                                self.inclusion_prover.as_ref(),
                            )?;
                        }
                        self.config_resolver.invalidate(_address);
                    }
                }
                _ => {}
            }
            Ok(())
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if let Err(e) = invoke_token(&r.inner_bytes, r.inner_type_prefix) {
                            eprintln!("[WARN] token invoke_step failed type=0x{:08x}: {}", r.inner_type_prefix, e);
                        }
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                if let Err(e) = invoke_token(&req.inner_bytes, req.inner_type_prefix) {
                    eprintln!("[WARN] token invoke_step failed type=0x{:08x}: {}", req.inner_type_prefix, e);
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            _ => Err(QuilError::InvalidArgument("token: unsupported message type".into())),
        }
    }

    fn prove(&self, _domain: &[u8], _frame_number: u64, message: &[u8]) -> Result<global::MessageRequest> {
        decode_proto_message_request_for_engine(message, |inner| matches!(
            inner,
            Some(MessageRequestInner::TokenDeploy(_))
            | Some(MessageRequestInner::TokenUpdate(_))
            | Some(MessageRequestInner::Transaction(_))
            | Some(MessageRequestInner::PendingTransaction(_))
            | Some(MessageRequestInner::MintTransaction(_)),
        ), "token")
    }

    fn lock(&self, _frame_number: u64, _address: &[u8], _message: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    fn unlock(&self) -> Result<()> {
        Ok(())
    }

    fn get_cost(&self, message: &[u8]) -> Result<BigInt> {
        if message.len() < 8 {
            return Ok(BigInt::from(0));
        }
        // Try to decode as MessageRequest and dispatch to per-type cost.
        if let Ok(req) = CanonicalMessageRequest::from_canonical_bytes(message) {
            if crate::token_engine::is_token_type_prefix(req.inner_type_prefix) {
                match req.inner_type_prefix {
                    crate::token_intrinsic::TYPE_TOKEN_DEPLOY => {
                        let d = crate::token_intrinsic::TokenDeploy::from_canonical_bytes(&req.inner_bytes)?;
                        return Ok(BigInt::from(d.config.len() as i64));
                    }
                    crate::token_intrinsic::TYPE_TOKEN_UPDATE => {
                        let u = crate::token_intrinsic::TokenUpdate::from_canonical_bytes(&req.inner_bytes)?;
                        return Ok(BigInt::from(u.config.len() as i64));
                    }
                    crate::token_engine::TYPE_TRANSACTION => {
                        let tx = crate::token_intrinsic::Transaction::from_canonical_bytes(&req.inner_bytes)?;
                        return tx.get_cost();
                    }
                    crate::token_engine::TYPE_PENDING_TRANSACTION => {
                        let tx = crate::token_intrinsic::PendingTransaction::from_canonical_bytes(&req.inner_bytes)?;
                        return tx.get_cost();
                    }
                    crate::token_engine::TYPE_MINT_TRANSACTION => {
                        let tx = crate::token_intrinsic::MintTransaction::from_canonical_bytes(&req.inner_bytes)?;
                        return tx.get_cost(crate::token_intrinsic::constants::QUIL_BEHAVIOR);
                    }
                    _ => {}
                }
            }
        }
        Ok(BigInt::from(0))
    }

    fn get_capabilities(&self) -> Vec<node::Capability> {
        crate::token_engine::token_engine_capabilities()
    }
}

// =====================================================================
// Global validation helpers — tree loading for signature verification
// =====================================================================

/// Extract the prover address from a global op's addressed signature,
/// then load the prover vertex tree (and optionally the allocation tree)
/// from the HypergraphState for BLS signature verification.
///
/// Returns `(Option<prover_tree>, Option<allocation_tree>)`.
/// Both are None if the address can't be extracted or the vertex doesn't
/// exist (which means structural-only validation runs).
fn load_trees_for_validation(
    inner_bytes: &[u8],
    inner_tp: u32,
    state: &crate::hypergraph_state::HypergraphState,
) -> (
    Option<quil_tries::VectorCommitmentTree>,
    Option<quil_tries::VectorCommitmentTree>,
) {
    // Extract the 32-byte prover address from the op's addressed signature.
    let prover_address = extract_prover_address(inner_bytes, inner_tp);
    let prover_address = match prover_address {
        Some(addr) if addr.len() >= 32 => addr,
        _ => return (None, None),
    };

    let va_disc = match crate::hypergraph_state::vertex_adds_discriminator() {
        Ok(d) => d,
        Err(_) => return (None, None),
    };

    let domain = &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS[..];

    // Load prover vertex
    let prover_tree = state
        .get(domain, &prover_address, &va_disc)
        .ok()
        .flatten()
        .and_then(|data| {
            if data.is_empty() { return None; }
            let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&data);
            Some(tree)
        });

    // For filter-based ops (Pause/Resume/Leave), also load the allocation tree.
    let alloc_tree = if needs_allocation_tree(inner_tp) {
        extract_filter_and_load_alloc(inner_bytes, inner_tp, &prover_address, state, domain, &va_disc)
    } else {
        None
    };

    (prover_tree, alloc_tree)
}

/// Extract the prover address from an op's addressed signature field.
/// Each global op type stores the signature differently.
fn extract_prover_address(inner_bytes: &[u8], inner_tp: u32) -> Option<Vec<u8>> {
    use crate::global_intrinsic::prover_filter_ops::*;
    use crate::global_intrinsic::prover_ops::*;
    use crate::global_intrinsic::prover_join::*;

    match inner_tp {
        TYPE_PROVER_PAUSE => ProverPause::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_RESUME => ProverResume::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_LEAVE => ProverLeave::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_CONFIRM => ProverConfirm::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_REJECT => ProverReject::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_UPDATE => crate::global_intrinsic::prover_ops::ProverUpdate::from_canonical_bytes(inner_bytes).ok()
            .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        TYPE_PROVER_JOIN => {
            // ProverJoin uses a different signature structure (SignatureWithPop)
            ProverJoin::from_canonical_bytes(inner_bytes).ok()
                .and_then(|op| op.public_key_signature_bls48581.as_ref()
                    .and_then(|s| s.public_key.as_ref())
                    .and_then(|pk| crate::global_intrinsic::materialize::prover_address_from_pubkey(pk).ok())
                    .map(|addr| addr.to_vec()))
        }
        _ => None,
    }
}

/// Whether this op type needs an allocation tree for validation.
fn needs_allocation_tree(inner_tp: u32) -> bool {
    use crate::global_intrinsic::prover_filter_ops::*;
    matches!(inner_tp, TYPE_PROVER_PAUSE | TYPE_PROVER_RESUME)
}

/// Load the allocation tree for filter-based ops.
fn extract_filter_and_load_alloc(
    inner_bytes: &[u8],
    inner_tp: u32,
    prover_address: &[u8],
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    va_disc: &[u8; 32],
) -> Option<quil_tries::VectorCommitmentTree> {
    use crate::global_intrinsic::prover_filter_ops::*;

    // Get the filter from the op
    let filter = match inner_tp {
        TYPE_PROVER_PAUSE => ProverPause::from_canonical_bytes(inner_bytes).ok().map(|op| op.filter),
        TYPE_PROVER_RESUME => ProverResume::from_canonical_bytes(inner_bytes).ok().map(|op| op.filter),
        _ => None,
    }?;

    // Load the prover tree to get public key for allocation address computation
    let prover_data = state.get(domain, prover_address, va_disc).ok()??;
    if prover_data.is_empty() { return None; }
    let prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
    let pubkey = crate::global_schema::read_field(&prover_tree, "prover:Prover", "PublicKey")?;
    if pubkey.is_empty() { return None; }

    // Compute allocation address
    let alloc_addr = crate::global_intrinsic::materialize::allocation_address(&pubkey, &filter).ok()?;

    // Load allocation vertex
    let alloc_data = state.get(domain, &alloc_addr, va_disc).ok()??;
    if alloc_data.is_empty() { return None; }
    Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&alloc_data))
}

// =====================================================================
// Token transaction helpers
// =====================================================================

/// Parse nested TransactionOutput / MintTransactionOutput /
/// PendingTransactionOutput canonical bytes into materialize inputs.
/// PendingTransactionOutput has two recipients (`to` + `refund`);
/// both produce a coin vertex.
fn parse_tx_outputs(
    raw_outputs: &[Vec<u8>],
    frame_number: u64,
) -> Result<Vec<crate::token_intrinsic::materialize::TransactionOutput>> {
    let mut result = Vec::with_capacity(raw_outputs.len());
    for raw in raw_outputs {
        if raw.len() < 4 { continue; }
        let tp = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let frame_bytes = frame_number.to_be_bytes().to_vec();

        if tp == crate::token_intrinsic::TYPE_PENDING_TRANSACTION_OUTPUT {
            let txo = crate::token_intrinsic::PendingTransactionOutput::from_canonical_bytes(raw)?;
            // `to` recipient
            if !txo.to.is_empty() {
                let r = crate::token_intrinsic::RecipientBundle::from_canonical_bytes(&txo.to)?;
                result.push(crate::token_intrinsic::materialize::TransactionOutput {
                    frame_number: frame_bytes.clone(), commitment: txo.commitment.clone(), recipient: r,
                });
            }
            // `refund` recipient (if present)
            if !txo.refund.is_empty() {
                if let Ok(r) = crate::token_intrinsic::RecipientBundle::from_canonical_bytes(&txo.refund) {
                    result.push(crate::token_intrinsic::materialize::TransactionOutput {
                        frame_number: frame_bytes, commitment: txo.commitment, recipient: r,
                    });
                }
            }
        } else if tp == crate::token_intrinsic::TYPE_MINT_TRANSACTION_OUTPUT {
            let txo = crate::token_intrinsic::MintTransactionOutput::from_canonical_bytes(raw)?;
            let r = crate::token_intrinsic::RecipientBundle::from_canonical_bytes(&txo.recipient_output)?;
            result.push(crate::token_intrinsic::materialize::TransactionOutput {
                frame_number: frame_bytes, commitment: txo.commitment, recipient: r,
            });
        } else {
            // Standard TransactionOutput
            let txo = crate::token_intrinsic::TransactionOutput::from_canonical_bytes(raw)?;
            let r = crate::token_intrinsic::RecipientBundle::from_canonical_bytes(&txo.recipient_output)?;
            result.push(crate::token_intrinsic::materialize::TransactionOutput {
                frame_number: frame_bytes, commitment: txo.commitment, recipient: r,
            });
        }
    }
    Ok(result)
}

/// Extract input signatures from nested TransactionInput or
/// PendingTransactionInput canonical bytes. Both have the same
/// layout (commitment, signature, proofs) but different type prefixes.
fn parse_tx_input_sigs(raw_inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut sigs = Vec::with_capacity(raw_inputs.len());
    for raw in raw_inputs {
        // Peek type prefix to decide which parser to use.
        if raw.len() < 4 { continue; }
        let tp = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let sig = if tp == crate::token_intrinsic::TYPE_PENDING_TRANSACTION_INPUT {
            crate::token_intrinsic::PendingTransactionInput::from_canonical_bytes(raw)?.signature
        } else if tp == crate::token_intrinsic::TYPE_MINT_TRANSACTION_INPUT {
            crate::token_intrinsic::MintTransactionInput::from_canonical_bytes(raw)?.signature
        } else {
            crate::token_intrinsic::TransactionInput::from_canonical_bytes(raw)?.signature
        };
        sigs.push(sig);
    }
    Ok(sigs)
}

/// Write materialized coin and spent marker vertices to the HypergraphState.
fn write_tx_result(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    va_disc: &[u8; 32],
    frame_number: u64,
    result: &crate::token_intrinsic::materialize::TransactionMaterializeOutput,
) -> Result<()> {
    for (addr, tree) in &result.coins {
        let blob = crate::prover_registry::vertex_tree_to_blob(tree);
        state.set(domain, addr, va_disc, frame_number, blob)?;
    }
    for (addr, tree) in &result.spent_markers {
        let blob = crate::prover_registry::vertex_tree_to_blob(tree);
        state.set(domain, addr, va_disc, frame_number, blob)?;
    }
    Ok(())
}

/// Compute execution engine — handles circuit deployment and execution.
pub struct ComputeExecutionEngine {
    mode: ExecutionMode,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    bulletproof_prover: Option<Arc<dyn quil_types::crypto::BulletproofProver>>,
    key_manager: Option<Arc<dyn quil_types::crypto::KeyManager>>,
    circuit_compiler: Option<Arc<dyn quil_types::execution::CircuitCompiler>>,
}

impl ComputeExecutionEngine {
    pub fn new(mode: ExecutionMode) -> Self {
        Self {
            mode,
            state: None,
            bulletproof_prover: None,
            key_manager: None,
            circuit_compiler: None,
        }
    }

    /// Construct with hypergraph state so materialize writes the
    /// deploy / execute / finalize vertices.
    pub fn new_with_state(
        mode: ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            state: Some(state),
            bulletproof_prover: None,
            key_manager: None,
            circuit_compiler: None,
        }
    }

    /// Install crypto + circuit compiler dependencies so dispatch
    /// runs `verify_code_deployment`, `verify_code_execute`, and
    /// `verify_code_finalize` rather than just structural peek.
    pub fn with_crypto(
        mut self,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        self.bulletproof_prover = Some(bulletproof_prover);
        self.key_manager = Some(key_manager);
        self.circuit_compiler = Some(circuit_compiler);
        self
    }
}

impl ShardExecutionEngine for ComputeExecutionEngine {
    fn get_name(&self) -> &str { "compute" }

    fn validate_message(&self, _: u64, _: &[u8], message: &[u8]) -> Result<()> {
        if message.len() < 4 { return Ok(()); }
        let mut buf = [0u8; 4]; buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);
        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if crate::compute_engine::is_compute_type_prefix(r.inner_type_prefix) {
                            crate::compute_engine::peek_compute_message_kind(&r.inner_bytes)?;
                        }
                    }
                }
                Ok(())
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                if crate::compute_engine::is_compute_type_prefix(req.inner_type_prefix) {
                    crate::compute_engine::peek_compute_message_kind(&req.inner_bytes)?;
                }
                Ok(())
            }
            _ => Err(QuilError::InvalidArgument("compute: unsupported message type".into())),
        }
    }

    fn process_message(&self, frame_number: u64, _: &BigInt, address: &[u8], message: &[u8]) -> Result<ProcessMessageResult> {
        if message.len() < 4 { return Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() }); }
        let mut buf = [0u8; 4]; buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        let invoke_compute = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::compute_engine::is_compute_type_prefix(inner_tp) {
                return Ok(());
            }
            // State is required for materialization; if absent, we run
            // verify-only and skip the state writes.
            let state = self.state.as_deref();
            match inner_tp {
                crate::compute_intrinsic::TYPE_CODE_DEPLOYMENT => {
                    let dep = crate::compute_intrinsic::CodeDeployment::from_canonical_bytes(inner_bytes)?;
                    if let Some(c) = self.circuit_compiler.as_deref() {
                        let _ = crate::compute_intrinsic::intrinsic::verify_code_deployment(c, &dep.circuit)?;
                    }
                    if let Some(s) = state {
                        let _ = crate::compute_intrinsic::materialize::materialize_code_deploy(
                            s, &dep, frame_number,
                        )?;
                    }
                }
                crate::compute_intrinsic::TYPE_CODE_EXECUTE => {
                    let ex = crate::compute_intrinsic::CodeExecute::from_canonical_bytes(inner_bytes)?;
                    if let Some(bp) = self.bulletproof_prover.as_deref() {
                        let ok = crate::compute_intrinsic::intrinsic::verify_code_execute(&ex, bp)?;
                        if !ok {
                            return Err(QuilError::InvalidArgument(
                                "code execute: verify failed".into(),
                            ));
                        }
                    }
                    if let Some(s) = state {
                        let _ = crate::compute_intrinsic::materialize::materialize_code_execute(
                            s, &ex, frame_number,
                        )?;
                    }
                }
                crate::compute_intrinsic::TYPE_CODE_FINALIZE => {
                    let fin = crate::compute_intrinsic::CodeFinalize::from_canonical_bytes(inner_bytes)?;
                    let mut domain = [0u8; 32];
                    if address.len() >= 32 {
                        domain.copy_from_slice(&address[..32]);
                    }
                    if let Some(km) = self.key_manager.as_deref() {
                        let _ = crate::compute_intrinsic::intrinsic::verify_code_finalize(
                            &fin, &domain, address, km,
                        )?;
                    }
                    if let Some(s) = state {
                        crate::compute_intrinsic::materialize::materialize_code_finalize(
                            s, &fin, &domain, frame_number,
                        )?;
                    }
                }
                _ => {
                    crate::compute_engine::peek_compute_message_kind(inner_bytes)?;
                }
            }
            Ok(())
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        invoke_compute(&r.inner_bytes, r.inner_type_prefix)?;
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                invoke_compute(&req.inner_bytes, req.inner_type_prefix)?;
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            _ => Err(QuilError::InvalidArgument("compute: unsupported message type".into())),
        }
    }

    fn prove(&self, _: &[u8], _: u64, message: &[u8]) -> Result<global::MessageRequest> {
        decode_proto_message_request_for_engine(message, |inner| matches!(
            inner,
            Some(MessageRequestInner::ComputeDeploy(_))
            | Some(MessageRequestInner::ComputeUpdate(_))
            | Some(MessageRequestInner::CodeDeploy(_))
            | Some(MessageRequestInner::CodeExecute(_))
            | Some(MessageRequestInner::CodeFinalize(_)),
        ), "compute")
    }
    fn lock(&self, _: u64, _: &[u8], _: &[u8]) -> Result<Vec<Vec<u8>>> { Ok(Vec::new()) }
    fn unlock(&self) -> Result<()> { Ok(()) }
    fn get_cost(&self, _: &[u8]) -> Result<BigInt> { Ok(BigInt::from(0)) }
    fn get_capabilities(&self) -> Vec<node::Capability> {
        crate::compute_engine::compute_engine_capabilities()
    }
}

/// Hypergraph execution engine — handles vertex/hyperedge add/remove.
pub struct HypergraphExecutionEngine {
    mode: ExecutionMode,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    inclusion_prover: Arc<dyn InclusionProver>,
}

impl HypergraphExecutionEngine {
    pub fn new(mode: ExecutionMode) -> Self {
        Self {
            mode,
            state: None,
            inclusion_prover: Arc::new(NoopInclusionProver),
        }
    }

    pub fn new_with_state(
        mode: ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            state: Some(state),
            inclusion_prover: Arc::new(NoopInclusionProver),
        }
    }

    pub fn with_inclusion_prover(
        mut self,
        inclusion_prover: Arc<dyn InclusionProver>,
    ) -> Self {
        self.inclusion_prover = inclusion_prover;
        self
    }

    fn inclusion_prover(&self) -> &Arc<dyn InclusionProver> {
        &self.inclusion_prover
    }
}

impl HypergraphExecutionEngine {
    /// Materialize a single hypergraph op (VertexAdd/Remove, HyperedgeAdd/Remove).
    fn invoke_hypergraph_op(
        &self,
        frame_number: u64,
        inner_bytes: &[u8],
        domain: &[u8],
    ) -> Result<()> {
        let state = match &self.state {
            Some(s) => s,
            None => return Ok(()), // no state = skip
        };
        let msg = hg_dispatch::decode_and_validate(inner_bytes)?;
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        let vr_disc = crate::hypergraph_state::vertex_removes_discriminator()?;
        let ha_disc = crate::hypergraph_state::hyperedge_adds_discriminator()?;
        let hr_disc = crate::hypergraph_state::hyperedge_removes_discriminator()?;

        match msg {
            hg_dispatch::DispatchedMessage::VertexAdd(v) => {
                // Go writes a VECTOR-COMMITMENT TREE built from each
                // proof's compressed Encrypted form
                // (`EncryptedToVertexTree`). The Rust `v.data` field
                // holds the wire-encoded list of proofs (u16 count +
                // per-proof u16 size + bytes). Decode chunks, compress
                // each VerEncProof, then build the tree.
                let chunks =
                    crate::hypergraph_intrinsic::split_vertex_add_proof_chunks(&v.data)
                        .unwrap_or_default();
                let tree =
                    crate::hypergraph_intrinsic::encrypted_to_vertex_tree(
                        &chunks,
                        self.inclusion_prover().as_ref(),
                    )?;
                let blob =
                    crate::prover_registry::vertex_tree_to_blob(&tree);
                state.set(&v.domain, &v.data_address, &va_disc, frame_number, blob)?;
            }
            hg_dispatch::DispatchedMessage::VertexRemove(v) => {
                state.delete(&v.domain, &v.data_address, &vr_disc, frame_number)?;
            }
            hg_dispatch::DispatchedMessage::HyperedgeAdd(h) => {
                // Hyperedge address is the data_address half of the
                // hyperedge ID, NOT a recomputed `poseidon(value)`. Go
                // writes at `hyperedgeID[32:]`. See
                // `hypergraph_hyperedge_add.go:57-83`.
                let addr =
                    crate::hypergraph_intrinsic::extract_hyperedge_id(&h.value)
                        .map(|id| {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(
                                crate::hypergraph_intrinsic::hyperedge_id_data_address(&id),
                            );
                            a
                        })
                        .unwrap_or([0u8; 32]);
                state.set(&h.domain, &addr, &ha_disc, frame_number, h.value.clone())?;
            }
            hg_dispatch::DispatchedMessage::HyperedgeRemove(h) => {
                let addr =
                    crate::hypergraph_intrinsic::extract_hyperedge_id(&h.value)
                        .map(|id| {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(
                                crate::hypergraph_intrinsic::hyperedge_id_data_address(&id),
                            );
                            a
                        })
                        .unwrap_or([0u8; 32]);
                state.delete(&h.domain, &addr, &hr_disc, frame_number)?;
            }
        }
        Ok(())
    }
}

impl ShardExecutionEngine for HypergraphExecutionEngine {
    fn get_name(&self) -> &str { "hypergraph" }

    fn validate_message(&self, _frame_number: u64, _address: &[u8], message: &[u8]) -> Result<()> {
        let kind = crate::hypergraph_engine::peek_top_level_kind(message)?;
        match kind {
            crate::hypergraph_engine::MessageKindTopLevel::Bundle => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                // Validate each hypergraph op in the bundle structurally.
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if crate::hypergraph_engine::is_hypergraph_type_prefix(r.inner_type_prefix) {
                            hg_dispatch::decode_and_validate(&r.inner_bytes)?;
                        }
                    }
                }
                Ok(())
            }
            crate::hypergraph_engine::MessageKindTopLevel::Request => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                if crate::hypergraph_engine::is_hypergraph_type_prefix(req.inner_type_prefix) {
                    hg_dispatch::decode_and_validate(&req.inner_bytes)?;
                }
                Ok(())
            }
        }
    }

    fn process_message(
        &self,
        _frame_number: u64,
        _fee_multiplier: &BigInt,
        _address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let kind = crate::hypergraph_engine::peek_top_level_kind(message)?;
        match kind {
            crate::hypergraph_engine::MessageKindTopLevel::Bundle => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if crate::hypergraph_engine::is_hypergraph_type_prefix(r.inner_type_prefix) {
                            if let Err(e) = self.invoke_hypergraph_op(
                                _frame_number, &r.inner_bytes, _address,
                            ) {
                                eprintln!("[WARN] hypergraph invoke_step failed: {}", e);
                            }
                        }
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            crate::hypergraph_engine::MessageKindTopLevel::Request => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                if crate::hypergraph_engine::is_hypergraph_type_prefix(req.inner_type_prefix) {
                    if let Err(e) = self.invoke_hypergraph_op(
                        _frame_number, &req.inner_bytes, _address,
                    ) {
                        eprintln!("[WARN] hypergraph invoke_step failed: {}", e);
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
        }
    }

    fn prove(&self, _: &[u8], _: u64, message: &[u8]) -> Result<global::MessageRequest> {
        decode_proto_message_request_for_engine(message, |inner| matches!(
            inner,
            Some(MessageRequestInner::HypergraphDeploy(_))
            | Some(MessageRequestInner::HypergraphUpdate(_))
            | Some(MessageRequestInner::VertexAdd(_))
            | Some(MessageRequestInner::VertexRemove(_))
            | Some(MessageRequestInner::HyperedgeAdd(_))
            | Some(MessageRequestInner::HyperedgeRemove(_)),
        ), "hypergraph")
    }

    fn lock(&self, _frame_number: u64, _address: &[u8], message: &[u8]) -> Result<Vec<Vec<u8>>> {
        if message.len() < 4 {
            return Ok(Vec::new());
        }
        let kind = crate::hypergraph_engine::peek_top_level_kind(message);
        match kind {
            Ok(crate::hypergraph_engine::MessageKindTopLevel::Bundle) => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                let mut all_addrs = Vec::new();
                for req in &bundle.requests {
                    if let Some(r) = req {
                        if crate::hypergraph_engine::is_hypergraph_type_prefix(r.inner_type_prefix) {
                            if let Ok(msg) = hg_dispatch::decode_message(&r.inner_bytes) {
                                let (_, writes) = msg.lock_addresses()?;
                                all_addrs.extend(writes);
                            }
                        }
                    }
                }
                Ok(all_addrs)
            }
            _ => {
                // Try as a single op
                if let Ok(msg) = hg_dispatch::decode_message(message) {
                    let (_, writes) = msg.lock_addresses()?;
                    return Ok(writes);
                }
                Ok(Vec::new())
            }
        }
    }

    fn unlock(&self) -> Result<()> { Ok(()) }

    fn get_cost(&self, message: &[u8]) -> Result<BigInt> {
        if message.len() < 8 {
            return Ok(BigInt::from(0));
        }
        let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
        // Route based on inner type prefix to the per-op cost helpers.
        match req.inner_type_prefix {
            crate::hypergraph_intrinsic::canonical::TYPE_VERTEX_ADD => {
                let va = crate::hypergraph_intrinsic::VertexAdd::from_canonical_bytes(&req.inner_bytes)?;
                va.get_cost()
            }
            crate::hypergraph_intrinsic::canonical::TYPE_VERTEX_REMOVE => {
                Ok(BigInt::from(crate::hypergraph_intrinsic::VERTEX_REMOVE_COST))
            }
            crate::hypergraph_intrinsic::canonical::TYPE_HYPEREDGE_REMOVE => {
                Ok(BigInt::from(crate::hypergraph_intrinsic::HYPEREDGE_REMOVE_COST))
            }
            crate::hypergraph_intrinsic::canonical::TYPE_HYPERGRAPH_DEPLOYMENT
            | crate::hypergraph_intrinsic::canonical::TYPE_HYPERGRAPH_UPDATE => {
                // Deploy/update cost is schema+keys — needs config decode
                // which we have but don't want to duplicate the logic from
                // hypergraph_engine::get_cost_from_request. For now return 0.
                Ok(BigInt::from(0))
            }
            _ => Ok(BigInt::from(0)),
        }
    }

    fn get_capabilities(&self) -> Vec<node::Capability> {
        crate::hypergraph_engine::hypergraph_capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Multiproof;

    // Stub InclusionProver for GlobalExecutionEngine construction.
    struct StubInclusionProver;
    impl InclusionProver for StubInclusionProver {
        fn commit_raw(&self, _data: &[u8], _poly_size: u64) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn prove_raw(
            &self,
            _data: &[u8],
            _index: u64,
            _poly_size: u64,
        ) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn verify_raw(
            &self,
            _data: &[u8],
            _commit: &[u8],
            _index: u64,
            _proof: &[u8],
            _poly_size: u64,
        ) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _commitments: &[&[u8]],
            _polys: &[&[u8]],
            _indices: &[u64],
            _poly_size: u64,
        ) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("batch multiproof generation not supported".into()))
        }
        fn verify_multiple(
            &self,
            _commitments: &[&[u8]],
            _evaluations: &[&[u8]],
            _indices: &[u64],
            _poly_size: u64,
            _multi_commitment: &[u8],
            _proof: &[u8],
        ) -> bool {
            true
        }
    }

    fn global_engine() -> GlobalExecutionEngine {
        GlobalExecutionEngine::new(Arc::new(StubInclusionProver))
    }

    // =================================================================
    // EngineType
    // =================================================================

    #[test]
    fn engine_type_as_str_covers_all_variants() {
        assert_eq!(EngineType::Global.as_str(), "global");
        assert_eq!(EngineType::Token.as_str(), "token");
        assert_eq!(EngineType::Compute.as_str(), "compute");
        assert_eq!(EngineType::Hypergraph.as_str(), "hypergraph");
    }

    #[test]
    fn engine_type_variants_are_distinct() {
        let all = [
            EngineType::Global,
            EngineType::Token,
            EngineType::Compute,
            EngineType::Hypergraph,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // =================================================================
    // ExecutionMode
    // =================================================================

    #[test]
    fn execution_mode_variants_are_distinct() {
        assert_ne!(ExecutionMode::Global, ExecutionMode::Application);
    }

    // =================================================================
    // GlobalExecutionEngine
    // =================================================================

    #[test]
    fn global_engine_name_is_global() {
        let e = global_engine();
        assert_eq!(e.get_name(), "global");
    }

    #[test]
    fn global_engine_validate_accepts_global_domain_address() {
        let e = global_engine();
        assert!(e.validate_message(0, &domains::GLOBAL, b"").is_ok());
    }

    #[test]
    fn global_engine_validate_rejects_non_global_address() {
        let e = global_engine();
        let err = e
            .validate_message(0, &[0x11u8; 32], b"")
            .unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn global_engine_validate_rejects_short_address() {
        let e = global_engine();
        let err = e
            .validate_message(0, &[0xFFu8; 16], b"")
            .unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn global_engine_process_message_returns_empty_result() {
        // Current stub — verify it returns empty but doesn't panic.
        let e = global_engine();
        let r = e
            .process_message(0, &BigInt::from(1), &domains::GLOBAL, b"")
            .unwrap();
        assert!(r.messages.is_empty());
        assert!(r.state.is_empty());
    }

    #[test]
    fn global_engine_capabilities_advertise_protocol_v1() {
        let e = global_engine();
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::capabilities::GLOBAL_PROTOCOL_V1
        );
        assert!(caps[0].additional_metadata.is_empty());
    }

    #[test]
    fn global_engine_lock_and_unlock_are_noops() {
        let e = global_engine();
        assert!(e.lock(0, &domains::GLOBAL, b"").unwrap().is_empty());
        assert!(e.unlock().is_ok());
    }

    #[test]
    fn global_engine_get_cost_is_zero() {
        let e = global_engine();
        assert_eq!(e.get_cost(b"any-message").unwrap(), BigInt::from(0));
    }

    // =================================================================
    // TokenExecutionEngine
    // =================================================================

    #[test]
    fn token_engine_name_is_token() {
        let e = TokenExecutionEngine::new(ExecutionMode::Application);
        assert_eq!(e.get_name(), "token");
    }

    #[test]
    fn token_engine_accepts_any_address() {
        // Token engine currently has no address restrictions.
        let e = TokenExecutionEngine::new(ExecutionMode::Application);
        assert!(e.validate_message(0, &[0u8; 32], b"").is_ok());
        assert!(e.validate_message(0, &[0xFFu8; 32], b"").is_ok());
    }

    #[test]
    fn token_engine_capabilities_advertise_protocol_v1() {
        let e = TokenExecutionEngine::new(ExecutionMode::Application);
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::capabilities::TOKEN_PROTOCOL_V1
        );
    }

    #[test]
    fn token_engine_can_be_constructed_in_both_modes() {
        let app = TokenExecutionEngine::new(ExecutionMode::Application);
        let global = TokenExecutionEngine::new(ExecutionMode::Global);
        assert_eq!(app.get_name(), "token");
        assert_eq!(global.get_name(), "token");
    }

    // =================================================================
    // ComputeExecutionEngine
    // =================================================================

    #[test]
    fn compute_engine_name_is_compute() {
        let e = ComputeExecutionEngine::new(ExecutionMode::Application);
        assert_eq!(e.get_name(), "compute");
    }

    #[test]
    fn compute_engine_capabilities_advertise_protocol_v1() {
        let e = ComputeExecutionEngine::new(ExecutionMode::Application);
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 12);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::capabilities::COMPUTE_PROTOCOL_V1
        );
    }

    #[test]
    fn compute_engine_process_returns_empty() {
        let e = ComputeExecutionEngine::new(ExecutionMode::Application);
        let r = e
            .process_message(0, &BigInt::from(1), &domains::COMPUTE, b"")
            .unwrap();
        assert!(r.messages.is_empty());
        assert!(r.state.is_empty());
    }

    // =================================================================
    // HypergraphExecutionEngine
    // =================================================================

    #[test]
    fn hypergraph_engine_name_is_hypergraph() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        assert_eq!(e.get_name(), "hypergraph");
    }

    #[test]
    fn hypergraph_engine_advertises_four_capabilities() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::hypergraph_engine::HYPERGRAPH_PROTOCOL_V1
        );
    }

    #[test]
    fn hypergraph_engine_process_rejects_short_message() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        assert!(e.process_message(0, &BigInt::from(1), &[0u8; 32], b"").is_err());
    }

    // =================================================================
    // Cost / lock / unlock uniformity across engines
    // =================================================================

    #[test]
    fn all_engines_report_zero_cost() {
        let g = global_engine();
        let t = TokenExecutionEngine::new(ExecutionMode::Application);
        let c = ComputeExecutionEngine::new(ExecutionMode::Application);
        let h = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let zero = BigInt::from(0);
        assert_eq!(g.get_cost(b"").unwrap(), zero);
        assert_eq!(t.get_cost(b"").unwrap(), zero);
        assert_eq!(c.get_cost(b"").unwrap(), zero);
        assert_eq!(h.get_cost(b"").unwrap(), zero);
    }

    #[test]
    fn all_engines_lock_unlock_are_noops() {
        let g = global_engine();
        let t = TokenExecutionEngine::new(ExecutionMode::Application);
        let c = ComputeExecutionEngine::new(ExecutionMode::Application);
        let h = HypergraphExecutionEngine::new(ExecutionMode::Application);
        for e in [
            &g as &dyn ShardExecutionEngine,
            &t as &dyn ShardExecutionEngine,
            &c as &dyn ShardExecutionEngine,
            &h as &dyn ShardExecutionEngine,
        ] {
            assert!(e.lock(0, &[0u8; 32], b"").unwrap().is_empty());
            assert!(e.unlock().is_ok());
        }
    }

    // =================================================================
    // GlobalExecutionEngine: wire-to-dispatch integration tests
    // =================================================================

    fn make_prover_pause_canonical() -> Vec<u8> {
        use crate::global_intrinsic::AddressedSignature;
        crate::global_intrinsic::ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 42,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn make_prover_join_canonical() -> Vec<u8> {
        crate::global_intrinsic::ProverJoin {
            filters: vec![vec![0x01u8; 32]],
            frame_number: 100,
            public_key_signature_bls48581: None,
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![],
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn global_engine_validate_accepts_bundle_with_prover_ops() {
        let e = global_engine();
        let bundle = make_bundle(vec![
            make_prover_pause_canonical(),
            make_prover_join_canonical(),
        ]);
        assert!(e.validate_message(1, &domains::GLOBAL, &bundle).is_ok());
    }

    #[test]
    fn global_engine_validate_accepts_single_request_with_prover_op() {
        let e = global_engine();
        let inner = make_prover_pause_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(e.validate_message(1, &domains::GLOBAL, &req).is_ok());
    }

    #[test]
    fn global_engine_validate_rejects_unknown_top_level_prefix() {
        let e = global_engine();
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        assert!(e.validate_message(1, &domains::GLOBAL, &garbage).is_err());
    }

    #[test]
    fn global_engine_process_accepts_bundle_with_prover_ops() {
        let e = global_engine();
        let bundle = make_bundle(vec![make_prover_pause_canonical()]);
        let r = e.process_message(1, &BigInt::from(1), &domains::GLOBAL, &bundle).unwrap();
        assert!(r.messages.is_empty());
    }

    // =================================================================
    // HypergraphExecutionEngine: wire-to-dispatch integration tests
    // =================================================================

    /// Helper: wrap a canonical-bytes inner payload in a MessageRequest
    /// envelope, then in a MessageBundle envelope.
    fn make_bundle(inner_payloads: Vec<Vec<u8>>) -> Vec<u8> {
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let requests: Vec<Option<CanonicalMessageRequest>> = inner_payloads
            .into_iter()
            .map(|inner| Some(CanonicalMessageRequest::wrap(inner).unwrap()))
            .collect();
        CanonicalMessageBundle {
            requests,
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn make_vertex_add_canonical() -> Vec<u8> {
        use crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks;
        let proofs: Vec<Vec<u8>> = vec![vec![0x11u8; 16], vec![0x22u8; 32]];
        crate::hypergraph_intrinsic::VertexAdd {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            data: pack_vertex_add_proof_chunks(&proofs).unwrap(),
            signature: vec![0xCCu8; 114],
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn make_vertex_remove_canonical() -> Vec<u8> {
        crate::hypergraph_intrinsic::VertexRemove {
            domain: vec![0xAAu8; 32],
            data_address: vec![0xBBu8; 32],
            signature: vec![0xCCu8; 114],
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn hypergraph_engine_validate_accepts_valid_vertex_add_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let bundle = make_bundle(vec![make_vertex_add_canonical()]);
        assert!(e.validate_message(1, &[0u8; 32], &bundle).is_ok());
    }

    #[test]
    fn hypergraph_engine_validate_rejects_structurally_invalid_op_in_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        // VertexAdd with empty data field → structural validation fails
        let bad_va = crate::hypergraph_intrinsic::VertexAdd {
            domain: vec![0u8; 32],
            data_address: vec![0u8; 32],
            data: vec![], // empty = invalid
            signature: vec![0u8; 1],
        }
        .to_canonical_bytes()
        .unwrap();
        let bundle = make_bundle(vec![bad_va]);
        assert!(e.validate_message(1, &[0u8; 32], &bundle).is_err());
    }

    #[test]
    fn hypergraph_engine_validate_accepts_single_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let inner = make_vertex_add_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(e.validate_message(1, &[0u8; 32], &req).is_ok());
    }

    #[test]
    fn hypergraph_engine_process_accepts_single_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let inner = make_vertex_add_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        // Single requests are now processed (materialization skipped without state).
        assert!(e.process_message(1, &BigInt::from(1), &[0u8; 32], &req).is_ok());
    }

    #[test]
    fn hypergraph_engine_process_accepts_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let bundle = make_bundle(vec![
            make_vertex_add_canonical(),
            make_vertex_remove_canonical(),
        ]);
        let r = e
            .process_message(1, &BigInt::from(1), &[0u8; 32], &bundle)
            .unwrap();
        assert!(r.messages.is_empty());
    }

    #[test]
    fn hypergraph_engine_lock_extracts_addresses_from_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let bundle = make_bundle(vec![
            make_vertex_add_canonical(),
            make_vertex_remove_canonical(),
        ]);
        let addrs = e.lock(1, &[0u8; 32], &bundle).unwrap();
        // Both vertex ops target the same domain+data_address →
        // should produce addresses (may overlap).
        assert!(!addrs.is_empty());
        for addr in &addrs {
            assert_eq!(addr.len(), 64); // domain(32) + data_address(32)
        }
    }

    #[test]
    fn hypergraph_engine_get_cost_for_vertex_add_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let inner = make_vertex_add_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let cost = e.get_cost(&req).unwrap();
        // 2 proofs × 55 = 110
        assert_eq!(cost, BigInt::from(110));
    }

    #[test]
    fn hypergraph_engine_get_cost_for_vertex_remove_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application);
        let inner = make_vertex_remove_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let cost = e.get_cost(&req).unwrap();
        assert_eq!(cost, BigInt::from(64));
    }
}
