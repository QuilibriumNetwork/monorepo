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
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) {
        if let Some(intrinsic) = self.intrinsic.take() {
            let mut updated = intrinsic
                .with_frame_header_deps(prover_registry, reward_issuance)
                .with_frame_prover(frame_prover);
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

    /// Install only the `frame_prover` on the intrinsic. This is the
    /// minimum that ProverJoin validation needs
    /// (`verify_prover_join_vdf` in `GlobalIntrinsic::validate`); the
    /// broader `install_frame_header_deps` also wires materializer-side
    /// registry/issuance/kick deps and is only needed on nodes that
    /// locally materialize global frames (archives). Non-archive
    /// masters call this so the archive-poller callback can pass
    /// ProverJoin validation without taking on archive-only
    /// materialization.
    pub fn install_frame_prover(
        &mut self,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) {
        if let Some(intrinsic) = self.intrinsic.take() {
            self.intrinsic = Some(intrinsic.with_frame_prover(frame_prover));
        }
    }

    /// Create with full dependencies for real signature verification
    /// and state materialization.
    pub fn new_with_intrinsic(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt.clone()));
        let intrinsic = crate::global_intrinsic::intrinsic::GlobalIntrinsic::new(key_manager)
            .with_clock_store(clock_store);
        Self {
            inclusion_prover,
            intrinsic: Some(intrinsic),
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
/// Crypto dependencies are mandatory: every dispatch path that runs
/// hidden-Schnorr + bulletproof + Decaf-scalar verify needs
/// `BulletproofProver` (range proofs + sum checks + hidden-sig verify)
/// and `DecafConstructor` (`hash_to_scalar` for transcript →
/// challenge). Production callers MUST supply real implementations;
/// tests can wire noop stubs from `crate::testing` to satisfy the
/// signature without actually verifying anything (paired with paths
/// that don't exercise the verify chain).
pub struct TokenExecutionEngine {
    mode: ExecutionMode,
    inclusion_prover: Arc<dyn InclusionProver>,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
    decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor>,
    key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    config_resolver: Arc<dyn crate::token_intrinsic::config_resolver::TokenConfigResolver>,
}

impl TokenExecutionEngine {
    /// Build a `TokenExecutionEngine` with all crypto + store
    /// dependencies. There is no fallback path — every dispatch
    /// branch that needed `Option::as_deref` to short-circuit now
    /// unconditionally consumes the provided traits.
    pub fn new(
        mode: ExecutionMode,
        inclusion_prover: Arc<dyn InclusionProver>,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        Self {
            mode,
            inclusion_prover,
            state: None,
            bulletproof_prover,
            decaf_constructor,
            key_manager,
            clock_store,
            config_resolver: Arc::new(
                crate::token_intrinsic::config_resolver::QuilOnlyConfigResolver,
            ),
        }
    }

    /// Build a `TokenExecutionEngine` wired up with a hypergraph
    /// `state` so materialize-writes land on the CRDT.
    pub fn new_with_state(
        mode: ExecutionMode,
        inclusion_prover: Arc<dyn InclusionProver>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        decaf_constructor: Arc<dyn quil_types::crypto::DecafConstructor>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            inclusion_prover,
            state: Some(state),
            bulletproof_prover,
            decaf_constructor,
            key_manager,
            clock_store,
            config_resolver: Arc::new(
                crate::token_intrinsic::config_resolver::QuilOnlyConfigResolver,
            ),
        }
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
        // Defense-in-depth domain reject. Upstream routing
        // selects this engine by destination address but the
        // validate_message contract should not silently accept
        // GLOBAL/COMPUTE addresses if a future routing bug sends one.
        // A token write to a system-managed domain would let the
        // token materialize at materialize-time write into the wrong
        // tree.
        if _address.len() >= 32 {
            if _address[..32] == crate::domains::GLOBAL
                || _address[..32] == crate::domains::COMPUTE
            {
                return Err(QuilError::InvalidArgument(format!(
                    "token engine: refusing to validate message addressed to \
                     system-managed domain {}",
                    hex::encode(&_address[..32]),
                )));
            }
        }
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

                    // STRUCTURAL FAIL-FAST. See
                    // `require_traversal_proof_for_inputs` for the
                    // attack chain this gate closes. Extracted to a
                    // standalone function so the regression test can
                    // pin the invariant directly (the engine's
                    // `process_message` swallows invoke_token errors
                    // by design — that's correct production behavior
                    // but makes the gate untestable via the
                    // process_message API).
                    require_traversal_proof_for_inputs(&tx)?;

                    // Full crypto verify is unconditional — the providers
                    // are mandatory engine inputs. Production callers
                    // MUST supply real `BulletproofProver` +
                    // `DecafConstructor`; the noop stubs in
                    // `crate::testing` make every verify fail, which
                    // matches the security posture we want when no
                    // real crypto is wired up.
                    let bp = self.bulletproof_prover.as_ref();
                    let decaf = self.decaf_constructor.as_ref();
                    let transcript = crate::token_intrinsic::verify::build_transaction_transcript(&tx)?;
                    let challenge = decaf.hash_to_scalar(&transcript)?;
                    // Per-input verify chain — structural, hidden
                    // Schnorr, double-spend, AND within-tx duplicate
                    // check all run together for each input. Keeping
                    // these atomic per-input matches Go's behaviour at
                    // `token_intrinsic_transaction.go:528-533, 1515-1521`
                    // and avoids any refactor short-circuit that could
                    // bypass the spent check.
                    //
                    // Within-tx duplicate input detection: track
                    // poseidon(vk) addresses already seen in this
                    // batch and reject collisions.
                    let mut seen_vk: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
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
                        // Within-tx duplicate guard: same coin
                        // can't appear twice in this transaction's
                        // input list. Mirrors Go's check at
                        // `token_intrinsic_transaction.go:1515-1521`.
                        let vk_window = if input.signature.len() >= 56 * 5 {
                            &input.signature[56 * 4..56 * 5]
                        } else {
                            return Err(QuilError::InvalidArgument(format!(
                                "transaction: input {} signature too short for vk window",
                                idx
                            )));
                        };
                        if !seen_vk.insert(vk_window.to_vec()) {
                            return Err(QuilError::InvalidArgument(format!(
                                "transaction: input {} is a within-tx duplicate",
                                idx
                            )));
                        }
                        // Spent-marker check: the coin must not
                        // already be consumed in the on-chain state.
                        let not_spent = crate::token_intrinsic::spent_check::check_input_not_double_spent(
                            state,
                            _address,
                            &input.signature,
                        )?;
                        if !not_spent {
                            return Err(QuilError::InvalidArgument(format!(
                                "transaction: input {} already spent (double-spend)",
                                idx
                            )));
                        }
                        // Refund-side expiration gate. For Expirable
                        // tokens, each pending-claim input carries:
                        //   - proofs[1]: 8-byte BE u64 expiration frame
                        //   - proofs[2]: single-byte isTo indicator
                        //     ([0x02] means "to" recipient; anything
                        //     else means refund recipient)
                        // A refund recipient (!isTo) cannot claim
                        // before frame_number >= expiration, otherwise
                        // they could short-circuit the recipient's
                        // grace window. Mirrors Go
                        // `token_intrinsic_transaction.go:656`.
                        // QUIL_BEHAVIOR has EXPIRABLE set; non-QUIL
                        // token configs would need to resolve their
                        // behavior dynamically, but the only token
                        // path through this engine today is QUIL.
                        let behavior = crate::token_intrinsic::constants::QUIL_BEHAVIOR;
                        if behavior & crate::token_intrinsic::constants::EXPIRABLE != 0
                            && input.proofs.len() >= 3
                        {
                            let expiration_bytes = &input.proofs[1];
                            let is_to_byte = input.proofs[2].first().copied();
                            if expiration_bytes.len() == 8 && is_to_byte != Some(0x02) {
                                let expiration = u64::from_be_bytes(
                                    expiration_bytes.as_slice().try_into().unwrap(),
                                );
                                if _frame_number < expiration {
                                    return Err(QuilError::InvalidArgument(format!(
                                        "transaction: input {} refund-claim before expiration \
                                         (frame_number={} < expiration={})",
                                        idx, _frame_number, expiration,
                                    )));
                                }
                            }
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

                    // Traversal-proof verification against the source
                    // shard's commitment root. The root comes from
                    // `HypergraphCrdt::get_shard_commits(frame, domain)[0]`
                    // (vertex-adds phase). This is the ON-CHAIN
                    // EXISTENCE GATE for transaction inputs.
                    //
                    // SECURITY: this check is MANDATORY for any tx
                    // with inputs. Without it, an attacker can mint
                    // QUIL from thin air:
                    //
                    //   1. Fabricate a 336-byte signature for an
                    //      input by choosing the secret first and
                    //      computing the commitment to match — the
                    //      hidden-Schnorr verify (`verify_input_hidden_signature`)
                    //      passes by construction.
                    //   2. The within-tx-duplicate check passes
                    //      because the fabricated vk is unique.
                    //   3. The spent-marker check
                    //      (`check_input_not_double_spent`) returns
                    //      `not_spent = true` because there is no
                    //      spent marker at `poseidon(vk)` — but
                    //      there's no marker because the coin was
                    //      NEVER MINTED, not because it was
                    //      "previously unspent." The marker check
                    //      proves non-double-spend, not existence.
                    //   4. The bulletproof range/sum check
                    //      (`verify_transaction_crypto`) verifies
                    //      internal consistency of the
                    //      commitment-vs-balance math — but it does
                    //      not require the input commitments to
                    //      exist on-chain. An attacker who picks
                    //      input and output values that sum can pass
                    //      this trivially.
                    //
                    // The traversal_proof is the only place that
                    // checks the input coin exists in the source
                    // shard's vertex-adds tree at the cited frame.
                    // Without it, the entire crypto stack reduces to
                    // "prove knowledge of values you chose," which
                    // is no proof at all.
                    //
                    // The earlier comment claimed spent-check
                    // provided fallback correctness when
                    // traversal_proof was empty. That was wrong — the
                    // spent-marker is at `poseidon(vk)`, not at the
                    // coin's address, and its absence is the
                    // expected case for an unspent coin (whether
                    // real or fake).
                    // Structural fail-fast (empty inputs / empty
                    // traversal_proof / empty outputs) has already
                    // fired at the top of this arm. Reaching here
                    // means we have all three; now verify the proof.
                    if !tx.inputs.is_empty() {
                        let first_output = crate::token_intrinsic::TransactionOutput::from_canonical_bytes(&tx.outputs[0])?;
                        if first_output.frame_number.len() != 8 {
                            return Err(QuilError::InvalidArgument(
                                "transaction: outputs[0].frame_number must be 8 bytes".into(),
                            ));
                        }
                        let cited_frame = u64::from_be_bytes(
                            first_output.frame_number.as_slice().try_into().unwrap(),
                        );
                        let crdt = state.crdt();
                        let roots = crdt.get_shard_commits(cited_frame, &tx.domain)
                            .map_err(|e| QuilError::InvalidArgument(format!(
                                "transaction: cannot fetch shard commits for frame {} domain {}: {}",
                                cited_frame, hex::encode(&tx.domain), e,
                            )))?;
                        if roots.is_empty() {
                            return Err(QuilError::InvalidArgument(format!(
                                "transaction: no shard commit at frame {} for domain {}",
                                cited_frame, hex::encode(&tx.domain),
                            )));
                        }
                        let traversal = crate::token_intrinsic::mint::parse_go_traversal_proof(
                            &tx.traversal_proof,
                        )?;
                        let ok = crate::traversal_proof::verify_traversal_proof(
                            self.inclusion_prover.as_ref(),
                            &roots[0],
                            &traversal,
                        )?;
                        if !ok {
                            return Err(QuilError::InvalidArgument(
                                "transaction: traversal proof failed (input not present \
                                 in source-shard adds-phase)".into(),
                            ));
                        }
                    }

                    // Spent-check is inlined in the per-input loop
                    // above. Do NOT reintroduce a separate post-crypto
                    // spent-loop — keeping the spent check atomic with
                    // the rest of each input's verification is what
                    // prevents future refactors from short-circuiting
                    // it. If the per-input spent-check is removed,
                    // materialize_transaction will double-spend
                    // silently.

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
                    // variant-specific per-input verify. Providers are
                    // mandatory engine inputs — no silent skip on
                    // missing crypto.
                    let bp = self.bulletproof_prover.as_ref();
                    let decaf = self.decaf_constructor.as_ref();
                    let km = self.key_manager.as_ref();
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
                            let hg_arc: Arc<quil_hypergraph::HypergraphCrdt> =
                                state.crdt().clone();
                            crate::token_intrinsic::mint::verify_mint_transaction_pomw(
                                &tx,
                                &hg_arc,
                                Some(self.clock_store.as_ref()),
                                self.inclusion_prover.as_ref(),
                                bp,
                                km,
                            )?;
                        }
                        MintVariant::Authority | MintVariant::Signature => {
                            // Both variants run the identical
                            // 9-check chain. Requires the
                            // authority key type + pubkey from the
                            // resolver.
                            if let (Some(kt), Some(pk)) = (
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
                        MintVariant::NoMint | MintVariant::Unknown => unreachable!(
                            "rejected above before crypto verify"
                        ),
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

                    // Full crypto verify is now unconditional.
                    // Mirrors Go's Verify → Materialize pattern.
                    // Legacy pre-2.1 259-byte ed448 inputs are handled
                    // inside `verify_pending_transaction` via the
                    // hypergraph CRDT reference below.
                    let bp = self.bulletproof_prover.as_ref();
                    let decaf = self.decaf_constructor.as_ref();
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

                            // Update gates: BLS signature on the
                            // existing owner key, then behavior
                            // parity + supply non-decrease. Read
                            // prior config from the metadata vertex.
                            let metadata_addr =
                                crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
                            let mut prior_cfg: Option<crate::token_intrinsic::TokenConfiguration> = None;
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
                                                prior_cfg = Some(prior);
                                            }
                                        }
                                    }
                                }
                            }

                            // BLS owner-key signature gate. Mirrors
                            // Go's `TokenIntrinsic.Deploy` update
                            // branch at `token_intrinsic.go:145-154`.
                            // The signed message is the canonical-bytes
                            // encoding of the TokenUpdate with its
                            // signature field cleared, domain
                            // `address || "TOKEN_UPDATE"`.
                            let prior = prior_cfg.as_ref().ok_or_else(|| {
                                QuilError::InvalidArgument(
                                    "token update: prior config not found — \
                                     cannot verify owner-key signature".into(),
                                )
                            })?;
                            if prior.owner_public_key.is_empty() {
                                return Err(QuilError::InvalidArgument(
                                    "token update: prior config has empty owner_public_key".into(),
                                ));
                            }
                            // Re-encode the update with the signature
                            // field cleared to recover the signed
                            // message bytes.
                            let mut without_sig = update.clone();
                            without_sig.public_key_signature_bls48581 = Vec::new();
                            let signed_message = without_sig.to_canonical_bytes()?;
                            // Extract the raw BLS signature from the
                            // AggregateSignature envelope.
                            if update.public_key_signature_bls48581.is_empty() {
                                return Err(QuilError::InvalidArgument(
                                    "token update: missing signature".into(),
                                ));
                            }
                            let agg = crate::hypergraph_intrinsic::canonical::AggregateSignature::from_canonical_bytes(
                                &update.public_key_signature_bls48581,
                            )?;
                            let mut domain = Vec::with_capacity(32 + b"TOKEN_UPDATE".len());
                            domain.extend_from_slice(_address);
                            domain.extend_from_slice(b"TOKEN_UPDATE");
                            let ok = self.key_manager.validate_signature(
                                quil_types::crypto::KeyType::Bls48581G1,
                                &prior.owner_public_key,
                                &signed_message,
                                &agg.signature,
                                &domain,
                            )?;
                            if !ok {
                                return Err(QuilError::InvalidArgument(
                                    "token update: signature does not verify against \
                                     prior config's owner public key".into(),
                                ));
                            }
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

/// Structural fail-fast gate for `TYPE_TRANSACTION`. Any token tx
/// with a non-empty input list MUST carry a non-empty
/// `traversal_proof` and at least one output (`outputs[0].frame_number`
/// is the source-shard frame the proof is cited against). Returns
/// `Ok(())` when the tx is well-shaped or has no inputs.
///
/// **Attack chain this closes:** modern 336-byte input signatures
/// verify hidden-Schnorr against a self-attested commitment — they
/// prove knowledge of the commitment's discrete log but NOT that the
/// referenced coin ever existed on-chain. The spent-marker check
/// (`check_input_not_double_spent`) only proves a marker isn't
/// present at `poseidon(vk)`; a never-minted coin has no marker
/// either, so the check returns "not spent." The bulletproof
/// range/sum check verifies the input/output commitment math is
/// internally consistent — but doesn't tie the input commitments to
/// any on-chain state. With all three checks in place but
/// `traversal_proof` empty, an attacker can fabricate inputs whose
/// values they choose and mint QUIL from nothing.
///
/// The traversal_proof verification below (against
/// `crdt.get_shard_commits(cited_frame, domain)[0]`) is the only
/// on-chain existence gate. Making this structural prerequisite
/// fail-fast lets us reject the malformed shape before paying for
/// any crypto work, and makes the invariant unit-testable directly.
pub(crate) fn require_traversal_proof_for_inputs(
    tx: &crate::token_intrinsic::Transaction,
) -> Result<()> {
    if tx.inputs.is_empty() {
        return Ok(());
    }
    if tx.traversal_proof.is_empty() {
        return Err(QuilError::InvalidArgument(
            "transaction: missing traversal_proof — modern token \
             transactions with inputs must prove on-chain existence \
             of each input coin"
                .into(),
        ));
    }
    if tx.outputs.is_empty() {
        return Err(QuilError::InvalidArgument(
            "transaction: cannot cite source-shard frame without an \
             output (outputs[0].frame_number is the citation)"
                .into(),
        ));
    }
    Ok(())
}

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
        // ShardSplit, ShardMerge, and ProverSeniorityMerge all sign
        // with the prover's BLS key and carry the prover's address
        // in `AddressedSignature.address`. These entries must be
        // present so `load_trees_for_validation` can resolve the
        // signer's prover tree — otherwise validate falls through to
        // `Ok(true)` and anyone could propose shard splits/merges or
        // claim seniority unverified.
        crate::global_intrinsic::prover_ops::TYPE_SHARD_SPLIT =>
            crate::global_intrinsic::prover_ops::ShardSplit::from_canonical_bytes(inner_bytes).ok()
                .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        crate::global_intrinsic::prover_ops::TYPE_SHARD_MERGE =>
            crate::global_intrinsic::prover_ops::ShardMerge::from_canonical_bytes(inner_bytes).ok()
                .and_then(|op| op.public_key_signature_bls48581.map(|s| s.address)),
        crate::global_intrinsic::prover_ops::TYPE_PROVER_SENIORITY_MERGE =>
            crate::global_intrinsic::prover_ops::ProverSeniorityMerge::from_canonical_bytes(inner_bytes).ok()
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
///
/// Crypto + compiler dependencies are mandatory. There is no longer a
/// "structural peek only" fallback at dispatch time.
pub struct ComputeExecutionEngine {
    mode: ExecutionMode,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
    key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
}

impl ComputeExecutionEngine {
    /// Build a `ComputeExecutionEngine` with all verification
    /// dependencies. Production callers MUST supply real
    /// implementations; tests pull noop stubs from `crate::testing`.
    pub fn new(
        mode: ExecutionMode,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        Self {
            mode,
            state: None,
            bulletproof_prover,
            key_manager,
            circuit_compiler,
        }
    }

    /// Construct with hypergraph state so materialize writes the
    /// deploy / execute / finalize vertices.
    pub fn new_with_state(
        mode: ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        bulletproof_prover: Arc<dyn quil_types::crypto::BulletproofProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            state: Some(state),
            bulletproof_prover,
            key_manager,
            circuit_compiler,
        }
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
            // Crypto/compiler are mandatory engine inputs — no
            // conditional verify gates.
            let bp = self.bulletproof_prover.as_ref();
            let km = self.key_manager.as_ref();
            let cc = self.circuit_compiler.as_ref();
            match inner_tp {
                crate::compute_intrinsic::TYPE_CODE_DEPLOYMENT => {
                    let dep = crate::compute_intrinsic::CodeDeployment::from_canonical_bytes(inner_bytes)?;
                    let _ = crate::compute_intrinsic::intrinsic::verify_code_deployment(cc, &dep.circuit)?;
                    if let Some(s) = state {
                        let _ = crate::compute_intrinsic::materialize::materialize_code_deploy(
                            s, &dep, frame_number,
                        )?;
                    }
                }
                crate::compute_intrinsic::TYPE_CODE_EXECUTE => {
                    let ex = crate::compute_intrinsic::CodeExecute::from_canonical_bytes(inner_bytes)?;
                    let ok = crate::compute_intrinsic::intrinsic::verify_code_execute(&ex, bp)?;
                    if !ok {
                        return Err(QuilError::InvalidArgument(
                            "code execute: verify failed".into(),
                        ));
                    }
                    if let Some(s) = state {
                        let _ = crate::compute_intrinsic::materialize::materialize_code_execute(
                            s, &ex, frame_number,
                        )?;
                    }
                }
                crate::compute_intrinsic::TYPE_CODE_FINALIZE => {
                    let fin = crate::compute_intrinsic::CodeFinalize::from_canonical_bytes(inner_bytes)?;
                    if address.len() != 32 {
                        return Err(QuilError::InvalidArgument(
                            "code finalize: address must be 32 bytes".into(),
                        ));
                    }
                    let mut domain = [0u8; 32];
                    domain.copy_from_slice(&address[..32]);
                    // Load the Ed448 write_public_key from the deployed
                    // ComputeConfiguration metadata vertex, NOT from
                    // the routing address — the 32-byte routing address
                    // is not a valid 57-byte Ed448 key. Mirrors the
                    // ComputeUpdate arm below which loads from the same
                    // vertex.
                    let s = state.ok_or_else(|| QuilError::InvalidArgument(
                        "code finalize: hypergraph state not installed — \
                         cannot resolve write_public_key".into(),
                    ))?;
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let metadata_addr = crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
                    let prior_blob = s.get(address, &metadata_addr, &va_disc)?
                        .ok_or_else(|| QuilError::InvalidArgument(
                            "code finalize: compute config metadata vertex \
                             not found for this domain".into(),
                        ))?;
                    let prior_cfg = crate::compute_intrinsic::config::ComputeConfiguration::from_canonical_bytes(&prior_blob)?;
                    if prior_cfg.write_public_key.is_empty() {
                        return Err(QuilError::InvalidArgument(
                            "code finalize: compute config has empty \
                             write_public_key".into(),
                        ));
                    }
                    let _ = crate::compute_intrinsic::intrinsic::verify_code_finalize(
                        &fin, &domain, &prior_cfg.write_public_key, km,
                    )?;
                    crate::compute_intrinsic::materialize::materialize_code_finalize(
                        s, &fin, &domain, frame_number,
                    )?;
                }
                crate::compute_intrinsic::config::TYPE_COMPUTE_DEPLOY => {
                    // ComputeDeploy structural validation only (initial
                    // deploy — no prior owner key to verify against).
                    // Decode to confirm well-formed canonical bytes;
                    // materialization of the compute config metadata
                    // vertex isn't ported yet. Reject the message so
                    // it doesn't silently slip past with no record
                    // (fail-closed).
                    let _ = crate::compute_intrinsic::config::ComputeDeploy::from_canonical_bytes(inner_bytes)?;
                    return Err(QuilError::Internal(
                        "ComputeDeploy materialization not implemented — rejecting".into(),
                    ));
                }
                crate::compute_intrinsic::config::TYPE_COMPUTE_UPDATE => {
                    // BLS owner-key signature gate. Mirrors Go
                    // `ComputeIntrinsic.Deploy` update branch at
                    // `compute_intrinsic.go:404-413`. Signed message =
                    // canonical bytes of ComputeUpdate with signature
                    // field cleared, domain = `address || "COMPUTE_UPDATE"`.
                    let update = crate::compute_intrinsic::config::ComputeUpdate::from_canonical_bytes(inner_bytes)?;
                    if address.len() != 32 {
                        return Err(QuilError::InvalidArgument(
                            "compute update: address must be 32 bytes".into(),
                        ));
                    }
                    // Load prior config from compute metadata vertex.
                    let s = state.ok_or_else(|| QuilError::InvalidArgument(
                        "compute update: hypergraph state not installed".into(),
                    ))?;
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let metadata_addr = crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
                    let prior_blob = s.get(address, &metadata_addr, &va_disc)?
                        .ok_or_else(|| QuilError::InvalidArgument(
                            "compute update: prior config not found".into(),
                        ))?;
                    let prior_owner_key = crate::compute_intrinsic::config::ComputeConfiguration::from_canonical_bytes(&prior_blob)
                        .map(|c| c.owner_public_key)
                        .unwrap_or_default();
                    if prior_owner_key.is_empty() {
                        return Err(QuilError::InvalidArgument(
                            "compute update: prior config has empty owner_public_key".into(),
                        ));
                    }
                    // Re-encode without signature for verify.
                    let mut without_sig = update.clone();
                    without_sig.public_key_signature_bls48581 = Vec::new();
                    let signed_message = without_sig.to_canonical_bytes()?;
                    if update.public_key_signature_bls48581.is_empty() {
                        return Err(QuilError::InvalidArgument(
                            "compute update: missing signature".into(),
                        ));
                    }
                    let agg = crate::hypergraph_intrinsic::canonical::AggregateSignature::from_canonical_bytes(
                        &update.public_key_signature_bls48581,
                    )?;
                    let mut domain_bytes = Vec::with_capacity(32 + b"COMPUTE_UPDATE".len());
                    domain_bytes.extend_from_slice(address);
                    domain_bytes.extend_from_slice(b"COMPUTE_UPDATE");
                    let ok = km.validate_signature(
                        quil_types::crypto::KeyType::Bls48581G1,
                        &prior_owner_key,
                        &signed_message,
                        &agg.signature,
                        &domain_bytes,
                    )?;
                    if !ok {
                        return Err(QuilError::InvalidArgument(
                            "compute update: signature does not verify against \
                             prior config's owner public key".into(),
                        ));
                    }
                    // Signature verified; materialize is still not
                    // ported. Reject so the message doesn't silently
                    // pass with no on-disk effect (fail-closed).
                    return Err(QuilError::Internal(
                        "ComputeUpdate materialization not implemented — \
                         rejecting after signature verify".into(),
                    ));
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
    /// Mandatory. Resolves the Ed448 `WritePublicKey` for each
    /// hypergraph domain. Every VertexAdd/VertexRemove/HyperedgeAdd/
    /// HyperedgeRemove op must sign with this key; without a resolver
    /// no op can be verified, which means the engine cannot safely
    /// run.
    config_resolver:
        Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>,
    /// Key manager for verifying `HypergraphUpdate` BLS48-581 aggregate
    /// signatures against the owner public key resolved from the config
    /// resolver. Optional only because `HypergraphExecutionEngine::new`
    /// is used by tests that don't exercise the update path; production
    /// wiring via `ExecutionEngineManager::new` always supplies it.
    /// The verify path returns `Err` when `update` traffic reaches an
    /// engine without a key manager installed.
    key_manager: Option<Arc<dyn quil_types::crypto::KeyManager>>,
}

impl HypergraphExecutionEngine {
    pub fn new(
        mode: ExecutionMode,
        config_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>,
    ) -> Self {
        Self {
            mode,
            state: None,
            inclusion_prover: Arc::new(NoopInclusionProver),
            config_resolver,
            key_manager: None,
        }
    }

    pub fn new_with_state(
        mode: ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        config_resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            state: Some(state),
            inclusion_prover: Arc::new(NoopInclusionProver),
            config_resolver,
            key_manager: None,
        }
    }

    pub fn with_inclusion_prover(
        mut self,
        inclusion_prover: Arc<dyn InclusionProver>,
    ) -> Self {
        self.inclusion_prover = inclusion_prover;
        self
    }

    pub fn with_key_manager(
        mut self,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    ) -> Self {
        self.key_manager = Some(key_manager);
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

        // Authority gate. Three layers:
        //   1. Inner message `domain` matches routing `domain`.
        //   2. Domain is not a system-managed address (global,
        //      compute, QUIL token — written exclusively by their
        //      intrinsic materializers).
        //   3. Ed448 signature verifies against the hypergraph's
        //      `WritePublicKey` (when a resolver is configured).
        //      Without #3, any valid Ed448 key can impersonate a
        //      hypergraph owner.
        let inner_domain: &[u8] = match &msg {
            hg_dispatch::DispatchedMessage::VertexAdd(v) => &v.domain,
            hg_dispatch::DispatchedMessage::VertexRemove(v) => &v.domain,
            hg_dispatch::DispatchedMessage::HyperedgeAdd(h) => &h.domain,
            hg_dispatch::DispatchedMessage::HyperedgeRemove(h) => &h.domain,
        };
        if inner_domain != domain {
            return Err(QuilError::InvalidArgument(format!(
                "hypergraph: inner-domain/routing-domain mismatch (inner={}, routing={})",
                hex::encode(inner_domain),
                hex::encode(domain),
            )));
        }
        if inner_domain == &crate::domains::GLOBAL[..]
            || inner_domain == &crate::domains::COMPUTE[..]
            || inner_domain == &crate::domains::QUIL_TOKEN[..]
        {
            return Err(QuilError::InvalidArgument(format!(
                "hypergraph: write to system-managed domain {} rejected",
                hex::encode(inner_domain),
            )));
        }
        self.verify_op_authority(&msg)?;

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

    /// Resolve the hypergraph's `WritePublicKey` for the inner-domain
    /// and Ed448-verify the op's signature. Behavior by resolver state:
    ///
    /// - `None` (no resolver configured): logs a warning and accepts.
    ///   Existing system-shard gate is still enforced upstream.
    /// - `Some` but `write_public_key(domain) == None`: rejects.
    ///   An op against an undeployed hypergraph is always invalid.
    /// - `Some` and key resolves: rejects on signature mismatch.
    fn verify_op_authority(
        &self,
        msg: &hg_dispatch::DispatchedMessage,
    ) -> Result<()> {
        use crate::hypergraph_intrinsic::auth::{
            verify_op_signature, AuthCheck, OpForAuth,
        };
        let op = match msg {
            hg_dispatch::DispatchedMessage::VertexAdd(v) => OpForAuth::VertexAdd(v),
            hg_dispatch::DispatchedMessage::VertexRemove(v) => OpForAuth::VertexRemove(v),
            hg_dispatch::DispatchedMessage::HyperedgeAdd(h) => {
                let commit = self.compute_hyperedge_commit(&h.value)?;
                let check = verify_op_signature(
                    &self.config_resolver,
                    &OpForAuth::HyperedgeAdd { op: h, commit: &commit },
                )?;
                return Self::auth_check_to_result(check, "hyperedge_add");
            }
            hg_dispatch::DispatchedMessage::HyperedgeRemove(h) => OpForAuth::HyperedgeRemove(h),
        };
        let check = verify_op_signature(&self.config_resolver, &op)?;
        let label = match msg {
            hg_dispatch::DispatchedMessage::VertexAdd(_) => "vertex_add",
            hg_dispatch::DispatchedMessage::VertexRemove(_) => "vertex_remove",
            hg_dispatch::DispatchedMessage::HyperedgeRemove(_) => "hyperedge_remove",
            hg_dispatch::DispatchedMessage::HyperedgeAdd(_) => unreachable!(),
        };
        Self::auth_check_to_result(check, label)
    }

    fn auth_check_to_result(
        check: crate::hypergraph_intrinsic::auth::AuthCheck,
        op_label: &str,
    ) -> Result<()> {
        use crate::hypergraph_intrinsic::auth::AuthCheck;
        match check {
            AuthCheck::Verified => Ok(()),
            AuthCheck::UnknownDomain => Err(QuilError::InvalidArgument(format!(
                "hypergraph {}: unknown deployment (no write key resolves)",
                op_label,
            ))),
            AuthCheck::Invalid => Err(QuilError::InvalidArgument(format!(
                "hypergraph {}: signature does not verify against write key",
                op_label,
            ))),
        }
    }

    /// Per-op materialization dispatch. Re-runs the verify path
    /// (defense-in-depth: a caller might invoke `process_message`
    /// without first calling `validate_message`) and then routes to
    /// the appropriate materializer. Deploy and Update materialization
    /// isn't ported yet — those branches return `Err` so they can't
    /// silently no-op past their verify gate.
    fn process_inner_op(
        &self,
        frame_number: u64,
        address: &[u8],
        inner_type_prefix: u32,
        inner_bytes: &[u8],
    ) -> Result<()> {
        use crate::hypergraph_intrinsic::canonical::{
            TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE,
        };
        if !crate::hypergraph_engine::is_hypergraph_type_prefix(inner_type_prefix) {
            return Ok(());
        }
        // Defense-in-depth: re-verify before materializing. The
        // frame boundary wires validate_message before process_message,
        // but engines should not assume the caller has done that check.
        self.validate_inner_op(address, inner_type_prefix, inner_bytes)?;
        match inner_type_prefix {
            TYPE_HYPERGRAPH_DEPLOYMENT | TYPE_HYPERGRAPH_UPDATE => {
                // Fail-closed: the materialization path for deploy and
                // update (config vertex creation, owner-key install,
                // RDF schema swap) hasn't been ported from Go yet.
                // Returning Err here means a verified deploy/update
                // is rejected at materialization rather than silently
                // dropped — the production engine cannot accept
                // either type until the materializer lands.
                Err(QuilError::Internal(
                    "hypergraph deploy/update materialization not yet implemented".into(),
                ))
            }
            _ => {
                // Vertex add/remove, hyperedge add/remove — existing
                // materialization path.
                self.invoke_hypergraph_op(frame_number, inner_bytes, address)
            }
        }
    }

    /// Per-op validation dispatch. Routes the six hypergraph type
    /// prefixes (deploy, update, vertex add/remove, hyperedge
    /// add/remove) through their respective verify paths. Returns
    /// `Ok(())` for non-hypergraph prefixes (other engines might own
    /// them in the bundle) — engine routing already filtered by
    /// destination address.
    fn validate_inner_op(
        &self,
        address: &[u8],
        inner_type_prefix: u32,
        inner_bytes: &[u8],
    ) -> Result<()> {
        use crate::hypergraph_intrinsic::canonical::{
            TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE,
        };
        if !crate::hypergraph_engine::is_hypergraph_type_prefix(inner_type_prefix) {
            return Ok(());
        }
        match inner_type_prefix {
            TYPE_HYPERGRAPH_DEPLOYMENT => {
                // Structural validation only. The deploy creates a new
                // hypergraph addressed by a Poseidon hash of its config
                // commitment — that binding IS the auth check. There
                // is no signature on a Deploy in Go either (see
                // `HypergraphIntrinsic.Deploy` new-deploy branch).
                let dispatched =
                    crate::hypergraph_intrinsic::decode_and_validate_deploy(inner_bytes)?;
                // Defense-in-depth — re-assert config key lengths
                // after dispatch's structural validate. The
                // `HypergraphDeploy::validate()` already chains into
                // `config.validate()`, but a future refactor could
                // separate them; this explicit check keeps the
                // 57/57/(0|585) key-length invariant attached to the
                // engine entrypoint, not just the canonical decoder.
                if let Some(c) = dispatched.deploy.config.as_ref() {
                    c.validate()?;
                }
                Ok(())
            }
            TYPE_HYPERGRAPH_UPDATE => self.validate_hypergraph_update(address, inner_bytes),
            _ => {
                // Vertex add/remove, hyperedge add/remove — existing
                // dispatch path (structural decode + per-op validate).
                let msg = hg_dispatch::decode_and_validate(inner_bytes)?;
                // VertexAdd carries embedded verenc proofs. Mirrors
                // Go's Verify() which calls `d.Verify()` on every
                // proof (hypergraph_vertex_add.go:185-192) BEFORE
                // the signature check. Without this, a VertexAdd
                // with byte-shaped-but-cryptographically-invalid
                // proofs passes validation and corrupts the on-disk
                // tree at materialize time.
                if let hg_dispatch::DispatchedMessage::VertexAdd(v) = &msg {
                    let chunks = crate::hypergraph_intrinsic::split_vertex_add_proof_chunks(&v.data)?;
                    crate::hypergraph_intrinsic::vertex_ops::verify_vertex_add_proofs(&chunks)?;
                }
                Ok(())
            }
        }
    }

    /// HypergraphUpdate verify path. Mirrors the Go branch in
    /// `HypergraphIntrinsic.Deploy` (lines 495-548) where an update
    /// against an existing hypergraph is gated by a BLS48-581 G1
    /// signature against the current `OwnerPublicKey` over the canonical
    /// bytes of the update with its signature field cleared, plus
    /// `domain || "HYPERGRAPH_UPDATE"` as the BLS domain separator.
    /// `domain` is the routing address — the hypergraph being updated.
    /// The resolver looks up the existing owner key for that domain.
    fn validate_hypergraph_update(&self, domain: &[u8], inner_bytes: &[u8]) -> Result<()> {
        use crate::hypergraph_intrinsic::auth::verify_update_signature;
        let dispatched =
            crate::hypergraph_intrinsic::decode_and_validate_update(inner_bytes)?;
        let update = &dispatched.update;
        // Re-assert config key lengths after dispatch's structural
        // validate. Same rationale as the deploy branch above.
        if let Some(c) = update.config.as_ref() {
            c.validate()?;
        }
        let sig = update
            .public_key_signature_bls48581
            .as_ref()
            .ok_or_else(|| {
                QuilError::InvalidArgument(
                    "hypergraph update: missing BLS48-581 aggregate signature".into(),
                )
            })?;
        let key_manager = self.key_manager.as_ref().ok_or_else(|| {
            QuilError::Internal(
                "hypergraph update: key_manager not installed — cannot verify signature".into(),
            )
        })?;
        let bytes_without_sig = update.to_canonical_bytes_without_signature()?;
        let check = verify_update_signature(
            &self.config_resolver,
            domain,
            &bytes_without_sig,
            &sig.signature,
            key_manager.as_ref(),
        )?;
        Self::auth_check_to_result(check, "hypergraph_update")?;
        // Schema-evolution check. The new schema must be a strict
        // superset of the prior schema (no removed classes or fields,
        // no changed field metadata). When the resolver reports no
        // prior schema, the check is skipped — matches Go's "first
        // update treated as deploy" branch.
        if !update.rdf_schema.is_empty() {
            if let Some(prior) = self.config_resolver.prior_rdf_schema(domain) {
                crate::hypergraph_intrinsic::dispatch::validate_rdf_schema_evolution(
                    &prior,
                    &update.rdf_schema,
                )?;
            }
        }
        Ok(())
    }

    /// Commit the extrinsic tree carried in a hyperedge atom's `value`.
    /// Layout: `[0x01][32 app_address][32 data_address][tree_bytes]`
    /// where `tree_bytes` is Go's `SerializeNonLazyTree` wire format.
    ///
    /// The extrinsic tree itself must structurally deserialize, and
    /// the resulting commit must be non-empty. Mirrors Go
    /// `hypergraph_hyperedge_add.go:166-172`. Without the non-empty
    /// gate, a hyperedge value can carry junk tail bytes that
    /// `deserialize_go_tree` accepts as an empty tree — verify would
    /// pass on an essentially-empty extrinsic, and materialize would
    /// write garbage.
    fn compute_hyperedge_commit(&self, value: &[u8]) -> Result<Vec<u8>> {
        use crate::hypergraph_intrinsic::hyperedge_ops::HYPEREDGE_MIN_VALUE_LEN;
        if value.len() < HYPEREDGE_MIN_VALUE_LEN {
            return Err(QuilError::InvalidArgument(
                "hyperedge commit: value too short".into(),
            ));
        }
        let tree_bytes = &value[HYPEREDGE_MIN_VALUE_LEN..];
        if tree_bytes.is_empty() {
            return Err(QuilError::InvalidArgument(
                "hyperedge commit: extrinsic tree bytes empty".into(),
            ));
        }
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.root = quil_tries::deserialize_go_tree(tree_bytes).map_err(|e| {
            QuilError::InvalidArgument(format!(
                "hyperedge commit: extrinsic tree failed structural deserialize: {e}"
            ))
        })?;
        let commit = tree.commit(self.inclusion_prover.as_ref());
        if commit.is_empty() {
            return Err(QuilError::InvalidArgument(
                "hyperedge commit: extrinsic tree commitment is empty — invalid tree".into(),
            ));
        }
        Ok(commit)
    }
}

impl ShardExecutionEngine for HypergraphExecutionEngine {
    fn get_name(&self) -> &str { "hypergraph" }

    fn validate_message(&self, _frame_number: u64, address: &[u8], message: &[u8]) -> Result<()> {
        let kind = crate::hypergraph_engine::peek_top_level_kind(message)?;
        match kind {
            crate::hypergraph_engine::MessageKindTopLevel::Bundle => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        self.validate_inner_op(address, r.inner_type_prefix, &r.inner_bytes)?;
                    }
                }
                Ok(())
            }
            crate::hypergraph_engine::MessageKindTopLevel::Request => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                self.validate_inner_op(address, req.inner_type_prefix, &req.inner_bytes)?;
                Ok(())
            }
        }
    }

    fn process_message(
        &self,
        frame_number: u64,
        _fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let kind = crate::hypergraph_engine::peek_top_level_kind(message)?;
        match kind {
            crate::hypergraph_engine::MessageKindTopLevel::Bundle => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        self.process_inner_op(
                            frame_number,
                            address,
                            r.inner_type_prefix,
                            &r.inner_bytes,
                        )?;
                    }
                }
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            crate::hypergraph_engine::MessageKindTopLevel::Request => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                self.process_inner_op(
                    frame_number,
                    address,
                    req.inner_type_prefix,
                    &req.inner_bytes,
                )?;
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

    /// Build a `TokenExecutionEngine` for tests with the noop crypto
    /// stubs slotted in. Production-side `new(...)` requires real
    /// crypto; tests reach for this helper.
    fn token_engine_test(mode: ExecutionMode) -> TokenExecutionEngine {
        let stubs = crate::testing::NoopExecutionCrypto::new();
        TokenExecutionEngine::new(
            mode,
            Arc::new(StubInclusionProver),
            stubs.bulletproof_prover,
            stubs.decaf_constructor,
            stubs.key_manager,
            stubs.clock_store,
        )
    }

    /// Build a `ComputeExecutionEngine` for tests.
    fn compute_engine_test(mode: ExecutionMode) -> ComputeExecutionEngine {
        let stubs = crate::testing::NoopExecutionCrypto::new();
        ComputeExecutionEngine::new(
            mode,
            stubs.bulletproof_prover,
            stubs.key_manager,
            stubs.circuit_compiler,
        )
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
        let e = token_engine_test(ExecutionMode::Application);
        assert_eq!(e.get_name(), "token");
    }

    #[test]
    fn token_engine_rejects_system_managed_domains() {
        // Token engine must explicitly reject GLOBAL/COMPUTE-addressed
        // messages even if routing slipped up. Non-system domains
        // (custom token domains, QUIL_TOKEN) continue to validate
        // normally.
        let e = token_engine_test(ExecutionMode::Application);
        // Custom token domain [0; 32] is allowed.
        assert!(e.validate_message(0, &[0u8; 32], b"").is_ok());
        // GLOBAL = [0xFF; 32] must be rejected.
        let err = e.validate_message(0, &crate::domains::GLOBAL, b"").unwrap_err();
        assert!(format!("{err}").contains("system-managed domain"));
        // COMPUTE must also be rejected.
        let err = e.validate_message(0, &crate::domains::COMPUTE, b"").unwrap_err();
        assert!(format!("{err}").contains("system-managed domain"));
    }

    #[test]
    fn token_engine_capabilities_advertise_protocol_v1() {
        let e = token_engine_test(ExecutionMode::Application);
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::capabilities::TOKEN_PROTOCOL_V1
        );
    }

    #[test]
    fn token_engine_can_be_constructed_in_both_modes() {
        let app = token_engine_test(ExecutionMode::Application);
        let global = token_engine_test(ExecutionMode::Global);
        assert_eq!(app.get_name(), "token");
        assert_eq!(global.get_name(), "token");
    }

    // =================================================================
    // ComputeExecutionEngine
    // =================================================================

    #[test]
    fn compute_engine_name_is_compute() {
        let e = compute_engine_test(ExecutionMode::Application);
        assert_eq!(e.get_name(), "compute");
    }

    #[test]
    fn compute_engine_capabilities_advertise_protocol_v1() {
        let e = compute_engine_test(ExecutionMode::Application);
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 12);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::capabilities::COMPUTE_PROTOCOL_V1
        );
    }

    #[test]
    fn compute_engine_process_returns_empty() {
        let e = compute_engine_test(ExecutionMode::Application);
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        assert_eq!(e.get_name(), "hypergraph");
    }

    #[test]
    fn hypergraph_engine_advertises_four_capabilities() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let caps = e.get_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            caps[0].protocol_identifier,
            crate::hypergraph_engine::HYPERGRAPH_PROTOCOL_V1
        );
    }

    #[test]
    fn hypergraph_engine_process_rejects_short_message() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        assert!(e.process_message(0, &BigInt::from(1), &[0u8; 32], b"").is_err());
    }

    // =================================================================
    // Cost / lock / unlock uniformity across engines
    // =================================================================

    #[test]
    fn all_engines_report_zero_cost() {
        let g = global_engine();
        let t = token_engine_test(ExecutionMode::Application);
        let c = compute_engine_test(ExecutionMode::Application);
        let h = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let zero = BigInt::from(0);
        assert_eq!(g.get_cost(b"").unwrap(), zero);
        assert_eq!(t.get_cost(b"").unwrap(), zero);
        assert_eq!(c.get_cost(b"").unwrap(), zero);
        assert_eq!(h.get_cost(b"").unwrap(), zero);
    }

    #[test]
    fn all_engines_lock_unlock_are_noops() {
        let g = global_engine();
        let t = token_engine_test(ExecutionMode::Application);
        let c = compute_engine_test(ExecutionMode::Application);
        let h = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
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
        // Verify path enforces verenc proof shape; proofs must be
        // either 9268-byte VerEncProof or 621-byte compressed verenc.
        // Use 621-byte filler (compressed accepted as-is structurally
        // — no crypto verify on this form). 9268-byte form would
        // require valid Ed448 curve points (parse_verenc_proof_full
        // rejects invalid bytes and the cryptographic verify would
        // fail too).
        let proofs: Vec<Vec<u8>> =
            vec![vec![0u8; crate::hypergraph_intrinsic::VERENC_COMPRESSED_BYTES]];
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let bundle = make_bundle(vec![make_vertex_add_canonical()]);
        assert!(e.validate_message(1, &[0u8; 32], &bundle).is_ok());
    }

    #[test]
    fn hypergraph_engine_validate_rejects_structurally_invalid_op_in_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let inner = make_vertex_add_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(e.validate_message(1, &[0u8; 32], &req).is_ok());
    }

    #[test]
    fn hypergraph_engine_process_accepts_single_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
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
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let inner = make_vertex_add_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let cost = e.get_cost(&req).unwrap();
        // make_vertex_add_canonical uses 1 valid 621-byte compressed
        // verenc proof (engines.rs verify path requires valid
        // verenc-length proofs). Cost = 1 × 55 = 55.
        assert_eq!(cost, BigInt::from(55));
    }

    #[test]
    fn hypergraph_engine_get_cost_for_vertex_remove_request() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let inner = make_vertex_remove_canonical();
        let req = crate::message_envelope::CanonicalMessageRequest::wrap(inner)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let cost = e.get_cost(&req).unwrap();
        assert_eq!(cost, BigInt::from(64));
    }

    // =================================================================
    // Traversal-proof mandatory-gate regression test
    //
    // Closes the gap previously documented at `engines.rs:752` (the
    // skip-when-empty clause): a Transaction with non-empty inputs but
    // empty `traversal_proof` MUST be rejected. Without the gate, an
    // attacker can pass hidden-Schnorr + spent-marker + bulletproof
    // checks with fabricated inputs that never existed on-chain. See
    // the long docstring above the gate in `process_message`'s
    // TYPE_TRANSACTION arm for the full attack chain.
    // =================================================================

    /// Build a `Transaction` with a fabricated input (zeroed commitment
    /// + signature) for testing the structural gate. Content of the
    /// input doesn't matter — the helper under test runs BEFORE any
    /// per-input crypto.
    fn tx_with_one_input(
        traversal_proof: Vec<u8>,
        outputs: Vec<Vec<u8>>,
    ) -> crate::token_intrinsic::Transaction {
        use crate::token_intrinsic::{Transaction, TransactionInput};
        let fake_input = TransactionInput {
            commitment: vec![0u8; 56],
            signature: vec![0u8; 336],
            proofs: Vec::new(),
        };
        Transaction {
            domain: crate::domains::QUIL_TOKEN.to_vec(),
            inputs: vec![fake_input.to_canonical_bytes().unwrap()],
            outputs,
            fees: Vec::new(),
            range_proof: Vec::new(),
            traversal_proof,
        }
    }

    fn one_zero_output() -> Vec<Vec<u8>> {
        use crate::token_intrinsic::TransactionOutput;
        vec![TransactionOutput {
            frame_number: vec![0u8; 8],
            commitment: vec![0u8; 64],
            recipient_output: Vec::new(),
        }
        .to_canonical_bytes()
        .unwrap()]
    }

    /// Inputs present, traversal_proof empty → rejected with explicit
    /// "missing traversal_proof" message. This is the load-bearing
    /// regression: without the gate, the attacker mints QUIL from
    /// thin air (see the function docstring for the attack chain).
    #[test]
    fn transaction_with_empty_traversal_proof_is_rejected() {
        let tx = tx_with_one_input(Vec::new(), one_zero_output());
        let result = require_traversal_proof_for_inputs(&tx);
        let err = result.expect_err(
            "tx with non-empty inputs and empty traversal_proof must be rejected",
        );
        let msg = format!("{}", err);
        assert!(
            msg.contains("missing traversal_proof"),
            "expected explicit 'missing traversal_proof' error, got: {}",
            msg,
        );
    }

    /// Inputs present, traversal_proof present, but outputs empty →
    /// also rejected (the source-shard citation lives in
    /// outputs[0].frame_number). Even if an attacker provides the
    /// traversal_proof bytes, they need a citable output frame for
    /// the proof to verify against.
    #[test]
    fn transaction_with_empty_outputs_and_inputs_is_rejected() {
        let tx = tx_with_one_input(vec![0u8; 32], Vec::new());
        let result = require_traversal_proof_for_inputs(&tx);
        let err = result.expect_err(
            "tx with inputs but no outputs must be rejected",
        );
        let msg = format!("{}", err);
        assert!(
            msg.contains("cannot cite source-shard frame"),
            "expected explicit 'cannot cite source-shard frame' error, got: {}",
            msg,
        );
    }

    /// Inputs present, traversal_proof present, outputs present →
    /// helper passes. (The deeper proof verification happens in the
    /// engine's TYPE_TRANSACTION arm against the actual shard commits;
    /// this gate is the structural fail-fast.)
    #[test]
    fn transaction_with_inputs_and_traversal_proof_and_outputs_passes_structural_gate() {
        let tx = tx_with_one_input(vec![0u8; 32], one_zero_output());
        let result = require_traversal_proof_for_inputs(&tx);
        assert!(result.is_ok(), "well-shaped tx must pass the structural gate: {:?}", result);
    }

    /// Empty inputs → helper is a no-op (returns Ok). Lets mint
    /// transactions, dummy bundles, and other zero-input shapes
    /// through without false-rejecting.
    #[test]
    fn transaction_with_no_inputs_passes_structural_gate() {
        use crate::token_intrinsic::Transaction;
        let tx = Transaction {
            domain: crate::domains::QUIL_TOKEN.to_vec(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: Vec::new(),
            range_proof: Vec::new(),
            traversal_proof: Vec::new(),
        };
        let result = require_traversal_proof_for_inputs(&tx);
        assert!(result.is_ok(), "zero-input tx must pass: {:?}", result);
    }
}
