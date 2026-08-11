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
    /// minimum needed to verify frame-header attestations
    /// (`verify_frame_header_signature` in `GlobalIntrinsic::validate`);
    /// the broader `install_frame_header_deps` also wires
    /// materializer-side registry/issuance/kick deps and is only needed
    /// on nodes that locally materialize global frames (archives).
    /// Non-archive masters call this so the archive-poller callback can
    /// validate frame headers without taking on archive-only
    /// materialization. (ProverJoin no longer requires a VDF proof.)
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
                            // Invalid global-intrinsic ops (prover join/confirm/
                            // leave/reject/pause/resume/update/kick) are an
                            // expected, high-volume part of normal operation
                            // (stale frame numbers, races, superseded lifecycle
                            // ops) — log at debug, not warn. Other engines keep
                            // their failures at warn.
                            tracing::debug!(
                                "global invoke_step failed for bundle request type=0x{:08x}: {}",
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
                    // Invalid global-intrinsic ops are expected/high-volume; log
                    // at debug (see the bundle path above). Other engines' op
                    // failures stay at warn.
                    tracing::debug!(
                        "global invoke_step failed for single request type=0x{:08x}: {}",
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
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        Self {
            mode,
            inclusion_prover,
            state: None,
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
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self {
            mode,
            inclusion_prover,
            state: Some(state),
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
                // Decaf448 token types are RETIRED (post-PQ flag day): the
                // confidential-value path is now the lattice-CT types (0x0512–
                // 0x0516). decaf448 was never live on mainnet (legacy coins are
                // migrated via the verenc→transparent→shield path), so these
                // types are rejected outright rather than crypto-verified.
                crate::token_engine::TYPE_TRANSACTION
                | crate::token_engine::TYPE_MINT_TRANSACTION
                | crate::token_engine::TYPE_PENDING_TRANSACTION => {
                    return Err(QuilError::InvalidArgument(
                        "decaf448 token type retired; use lattice-CT types (0x0512–0x0516)".into(),
                    ));
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
                    // Retired (decaf448): the confidential-value path is now
                    // the lattice-CT types (0x0512-0x0516). Rejected at validate;
                    // this is a defense-in-depth reject (unreachable in process).
                    return Err(QuilError::InvalidArgument(
                        "decaf448 token type retired; use lattice-CT (0x0512-0x0516)".into(),
                    ));
                }
                crate::token_engine::TYPE_LATTICE_TRANSACTION => {
                    // Post-quantum confidential transaction. `inner_bytes` is a
                    // lattice-CT `TxEnvelope`: verify the folded spend proofs
                    // against the token's committed accumulator root, check the
                    // key-image nullifiers, and balance — then materialize the new
                    // `(P, cv)` coins + key-image markers and refresh the shadow
                    // tree's committed root. (Coexists with the decaf path during
                    // cutover; retiring the decaf providers is a follow-up.)
                    use crate::token_intrinsic::lattice_ct;
                    let env = lattice_ct::decode_tx_envelope(inner_bytes)?;
                    // Bound the consensus-opaque per-output memos + one-time keys
                    // before they are stored verbatim in state (griefing/state-bloat
                    // hardening #5).
                    lattice_ct::check_memos_size(&env.output_memos)?;
                    lattice_ct::check_otks_size(&env.output_otks)?;
                    let np = lattice_ct::production_params();
                    let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                    match lattice_ct::verify_envelope_and_derive_coins(
                        np, state, _address, &env, is_quil,
                    )? {
                        Some((key_images, new_coins)) => {
                            let frame_bytes = _frame_number.to_be_bytes();
                            let result =
                                crate::token_intrinsic::materialize::materialize_lattice_transaction(
                                    _address, &frame_bytes, &new_coins, &key_images,
                                    &env.output_memos,
                                )?;
                            write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                            crate::token_intrinsic::shadow_accumulator::refresh_root(
                                state, _address,
                            )?;
                        }
                        None => {
                            return Err(QuilError::InvalidArgument(
                                "lattice-ct: confidential transaction verification failed".into(),
                            ));
                        }
                    }
                }
                crate::token_engine::TYPE_LATTICE_MINT => {
                    // Post-quantum PoMW mint. `inner_bytes` is a lattice-CT
                    // `MintEnvelope`: verify each input's reward entitlement
                    // (forest membership) + Falcon authorization + confidential
                    // conservation, then materialize the new coins, DECREMENT the
                    // provers' reward balances (soundness), and refresh the shadow
                    // tree. All post-quantum — no decaf, no BLS.
                    use crate::token_intrinsic::lattice_ct;
                    let env = lattice_ct::decode_mint_envelope(inner_bytes)?;
                    // Bound the consensus-opaque per-output memos + one-time keys
                    // (hardening #5).
                    lattice_ct::check_memos_size(&env.output_memos)?;
                    lattice_ct::check_otks_size(&env.output_otks)?;
                    let np = lattice_ct::production_params();
                    let is_quil = _address == &crate::domains::QUIL_TOKEN[..];
                    // Reward-tree root for the cited frame (forest, 32 bytes).
                    let reward_root_vec: Vec<u8> = if is_quil {
                        let frame = self.clock_store.get_global_clock_frame(env.cited_frame)?;
                        let header = frame.header.ok_or_else(|| {
                            QuilError::InvalidArgument("lattice-mint: cited frame has no header".into())
                        })?;
                        header.prover_tree_commitment
                    } else {
                        state
                            .crdt()
                            .get_shard_commits(env.cited_frame, _address)?
                            .into_iter()
                            .next()
                            .ok_or_else(|| {
                                QuilError::InvalidArgument("lattice-mint: shard commit missing".into())
                            })?
                    };
                    let reward_root: [u8; 32] = reward_root_vec.as_slice().try_into().map_err(|_| {
                        QuilError::InvalidArgument(
                            "lattice-mint: reward root not 32 bytes (forest reward tree required)".into(),
                        )
                    })?;
                    // DoS guard: a malformed mint proof must not panic the block
                    // thread (consensus halt) — reject it instead (audit hardening).
                    match lattice_ct::guard_verify(|| {
                        lattice_ct::verify_mint_envelope_and_derive(np, &reward_root, _address, &env)
                    })? {
                        Some((new_coins, decrements)) => {
                            let frame_bytes = _frame_number.to_be_bytes();
                            let result =
                                crate::token_intrinsic::materialize::materialize_lattice_transaction(
                                    _address, &frame_bytes, &new_coins, &[], &env.output_memos,
                                )?;
                            write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                            lattice_ct::apply_reward_decrements(
                                state, _address, _frame_number, &decrements, is_quil,
                            )?;
                            crate::token_intrinsic::shadow_accumulator::refresh_root(state, _address)?;
                        }
                        None => {
                            return Err(QuilError::InvalidArgument(
                                "lattice-mint: mint verification failed".into(),
                            ));
                        }
                    }
                }
                crate::token_engine::TYPE_LATTICE_PENDING => {
                    // Escrow CREATE: spend inputs, lock the value into a pending
                    // vertex (dual Falcon recipients + expiration). No coin yet.
                    use crate::token_intrinsic::lattice_ct;
                    let env = lattice_ct::decode_pending_create(inner_bytes)?;
                    // Bound all consensus-opaque fields stored verbatim in the
                    // escrow vertex before verify (griefing/state-bloat hardening #5).
                    lattice_ct::check_escrow_memo_size(&env.memo)?;
                    lattice_ct::check_memos_size(&env.change_memos)?;
                    lattice_ct::check_otks_size(&env.change_otks)?;
                    lattice_ct::check_recipient_key_size(&env.to_key)?;
                    lattice_ct::check_recipient_key_size(&env.refund_key)?;
                    let np = lattice_ct::production_params();
                    match lattice_ct::guard_verify(|| lattice_ct::verify_lattice_pending_create(
                        np,
                        state,
                        _address,
                        &env.input_spend_proofs,
                        &env.escrow_commitment,
                        &env.escrow_range_proof,
                        &env.change_commitments,
                        &env.change_otks,
                        &env.balance_proof,
                        env.fee,
                    ))? {
                        Some((key_images, cv, change_coins)) => {
                            let frame_bytes = _frame_number.to_be_bytes();
                            let mut result = crate::token_intrinsic::materialize::materialize_lattice_pending(
                                _address, &frame_bytes, &cv, &env.to_key, &env.refund_key,
                                env.expiration, &env.memo, &key_images,
                            )?;
                            // Materialize any change coins back to the sender.
                            if !change_coins.is_empty() {
                                let change = crate::token_intrinsic::materialize::materialize_lattice_transaction(
                                    _address, &frame_bytes, &change_coins, &[], &env.change_memos,
                                )?;
                                result.coins.extend(change.coins);
                            }
                            write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                            crate::token_intrinsic::shadow_accumulator::refresh_root(state, _address)?;
                        }
                        None => {
                            return Err(QuilError::InvalidArgument(
                                "lattice-pending: escrow create verification failed".into(),
                            ));
                        }
                    }
                }
                crate::token_engine::TYPE_LATTICE_PENDING_CLAIM => {
                    // Escrow CLAIM/REFUND: the `to` (or `refund` after expiration)
                    // party claims the escrow into a coin; the escrow is retired.
                    use crate::token_intrinsic::{lattice_ct, materialize, spent_check};
                    let env = lattice_ct::decode_pending_claim(inner_bytes)?;
                    // Bound the consensus-opaque claimed-coin memo + one-time key
                    // (hardening #5).
                    lattice_ct::check_memo_size(&env.output_memo)?;
                    lattice_ct::check_otk_size(&env.output_otk)?;
                    let np = lattice_ct::production_params();

                    // Read the escrow vertex and extract its fields.
                    let blob = state
                        .get(_address, &env.escrow_address, &va_disc)?
                        .ok_or_else(|| QuilError::InvalidArgument("lattice-pending: escrow not found".into()))?;
                    let tree = quil_tries::VectorCommitmentTree {
                        root: quil_tries::deserialize_go_tree(&blob)
                            .map_err(|e| QuilError::Internal(format!("escrow decode: {e}")))?,
                    };
                    let ptype = materialize::pending_type_hash(_address)?;
                    if tree.get(&[0xFFu8; 32]) != Some(&ptype[..]) {
                        return Err(QuilError::InvalidArgument("lattice-pending: not an escrow vertex".into()));
                    }
                    let getf = |k: u8| -> Result<Vec<u8>> {
                        tree.get(&[k << 2])
                            .map(|v| v.to_vec())
                            .ok_or_else(|| QuilError::InvalidArgument("lattice-pending: escrow field missing".into()))
                    };
                    let cv = getf(1)?;
                    let (to_key, refund_key) = (getf(2)?, getf(3)?);
                    let exp_bytes = getf(4)?;
                    let expiration = u64::from_be_bytes(
                        exp_bytes.get(..8).and_then(|s| s.try_into().ok())
                            .ok_or_else(|| QuilError::InvalidArgument("lattice-pending: bad expiration".into()))?,
                    );
                    let recipient_key = if env.is_to {
                        to_key
                    } else {
                        if _frame_number < expiration {
                            return Err(QuilError::InvalidArgument(
                                "lattice-pending: refund before expiration".into(),
                            ));
                        }
                        refund_key
                    };
                    // The escrow must not have been claimed already (nullifier).
                    if !spent_check::check_key_image_not_spent(state, _address, &env.escrow_address)? {
                        return Err(QuilError::InvalidArgument("lattice-pending: escrow already claimed".into()));
                    }

                    match lattice_ct::guard_verify(|| lattice_ct::verify_lattice_pending_claim(
                        np, _address, &cv, &recipient_key, env.is_to, &env.falcon_sig,
                        &env.output_commitment, &env.output_range_proof, &env.value_link_proof,
                    ))? {
                        Some(new_cv) => {
                            let frame_bytes = _frame_number.to_be_bytes();
                            let new_coins = vec![(env.output_otk.clone(), new_cv)];
                            // Carry the claimant's per-output memo so the new coin is
                            // scannable + spendable (empty ⇒ no memo, legacy claim).
                            let memos: Vec<Vec<u8>> = if env.output_memo.is_empty() {
                                Vec::new()
                            } else {
                                vec![env.output_memo.clone()]
                            };
                            // Retire the escrow via a nullifier keyed on its address.
                            let result = materialize::materialize_lattice_transaction(
                                _address, &frame_bytes, &new_coins, &[env.escrow_address.to_vec()], &memos,
                            )?;
                            write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                            crate::token_intrinsic::shadow_accumulator::refresh_root(state, _address)?;
                        }
                        None => {
                            return Err(QuilError::InvalidArgument(
                                "lattice-pending: claim verification failed".into(),
                            ));
                        }
                    }
                }
                crate::token_engine::TYPE_LATTICE_SHIELD => {
                    // One-way shield: spend a legacy TRANSPARENT coin (its Ed448
                    // owner signs) into a lattice private coin; the transparent
                    // entry is nullified. Ed448 survives only here.
                    use crate::token_intrinsic::{lattice_ct, materialize, spent_check};
                    let env = lattice_ct::decode_shield(inner_bytes)?;
                    // Bound the consensus-opaque one-time key (hardening #5); the
                    // shield envelope carries no memo.
                    lattice_ct::check_otk_size(&env.output_otk)?;
                    let np = lattice_ct::production_params();

                    let blob = state
                        .get(_address, &env.transparent_address, &va_disc)?
                        .ok_or_else(|| QuilError::InvalidArgument("shield: transparent coin not found".into()))?;
                    let tree = quil_tries::VectorCommitmentTree {
                        root: quil_tries::deserialize_go_tree(&blob)
                            .map_err(|e| QuilError::Internal(format!("shield decode: {e}")))?,
                    };
                    let ttype = crate::token_intrinsic::legacy_migration::transparent_type_hash(_address)?;
                    if tree.get(&[0xFFu8; 32]) != Some(&ttype[..]) {
                        return Err(QuilError::InvalidArgument("shield: not a transparent coin".into()));
                    }
                    let mut owner_address = [0u8; 32];
                    owner_address.copy_from_slice(
                        tree.get(&[0x00]).and_then(|v| v.get(..32)).ok_or_else(|| {
                            QuilError::InvalidArgument("shield: bad owner field".into())
                        })?,
                    );
                    let mut a16 = [0u8; 16];
                    a16.copy_from_slice(
                        tree.get(&[1u8 << 2]).and_then(|v| v.get(..16)).ok_or_else(|| {
                            QuilError::InvalidArgument("shield: bad amount field".into())
                        })?,
                    );
                    let amount = u128::from_le_bytes(a16);

                    // Not already shielded (nullifier keyed on the transparent addr).
                    if !spent_check::check_key_image_not_spent(state, _address, &env.transparent_address)? {
                        return Err(QuilError::InvalidArgument("shield: coin already shielded".into()));
                    }

                    match lattice_ct::guard_verify(|| lattice_ct::verify_lattice_shield(
                        np, _address, &owner_address, amount, &env.ed448_pubkey, &env.ed448_sig,
                        &env.output_commitment, &env.output_range_proof, &env.balance_proof,
                    ))? {
                        Some(cv) => {
                            let frame_bytes = _frame_number.to_be_bytes();
                            let new_coins = vec![(env.output_otk.clone(), cv)];
                            let result = materialize::materialize_lattice_transaction(
                                _address, &frame_bytes, &new_coins, &[env.transparent_address.to_vec()], &[],
                            )?;
                            write_tx_result(state, _address, &va_disc, _frame_number, &result)?;
                            crate::token_intrinsic::shadow_accumulator::refresh_root(state, _address)?;
                        }
                        None => {
                            return Err(QuilError::InvalidArgument(
                                "shield: verification failed".into(),
                            ));
                        }
                    }
                }
                crate::token_engine::TYPE_MINT_TRANSACTION => {
                    // Retired (decaf448): the confidential-value path is now
                    // the lattice-CT types (0x0512-0x0516). Rejected at validate;
                    // this is a defense-in-depth reject (unreachable in process).
                    return Err(QuilError::InvalidArgument(
                        "decaf448 token type retired; use lattice-CT (0x0512-0x0516)".into(),
                    ));
                }
                crate::token_engine::TYPE_PENDING_TRANSACTION => {
                    // Retired (decaf448): the confidential-value path is now
                    // the lattice-CT types (0x0512-0x0516). Rejected at validate;
                    // this is a defense-in-depth reject (unreachable in process).
                    return Err(QuilError::InvalidArgument(
                        "decaf448 token type retired; use lattice-CT (0x0512-0x0516)".into(),
                    ));
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
                    // A deploy DERIVES a new token domain from its config
                    // (Go token_intrinsic.go deploy branch) — it does NOT
                    // write at the routing `_address`. materialize_token_
                    // deploy_init builds the full metadata vertex (config +
                    // RDF + the 0xff*32 type-domain) at the derived domain
                    // so the manager routes it to the token engine.
                    let deploy = crate::token_intrinsic::TokenDeploy::from_canonical_bytes(inner_bytes)?;
                    if !deploy.config.is_empty() {
                        let cfg = crate::token_intrinsic::TokenConfiguration::from_canonical_bytes(&deploy.config)?;
                        let derived = crate::token_intrinsic::materialize::materialize_token_deploy_init(
                            state,
                            &cfg,
                            _frame_number,
                            self.inclusion_prover.as_ref(),
                        )?;
                        self.config_resolver.invalidate(&derived);
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
                            // Post-quantum owner auth: a single FALCON signature
                            // (no aggregation envelope — the field carries the
                            // Falcon sig bytes directly now).
                            if update.public_key_signature_bls48581.is_empty() {
                                return Err(QuilError::InvalidArgument(
                                    "token update: missing signature".into(),
                                ));
                            }
                            let mut domain = Vec::with_capacity(32 + b"TOKEN_UPDATE".len());
                            domain.extend_from_slice(_address);
                            domain.extend_from_slice(b"TOKEN_UPDATE");
                            let ok = self.key_manager.validate_signature(
                                quil_types::crypto::KeyType::Falcon512,
                                &prior.owner_public_key,
                                &signed_message,
                                &update.public_key_signature_bls48581,
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

        // Run one inner op, rolling its partial changeset writes back on
        // error. invoke_token accumulates `state.set` calls as it goes
        // (spent-markers, output coins, PoMW balance decrements); a
        // failure partway through must not leave those half-applied. We
        // snapshot the changeset length before the call and truncate
        // back to it on `Err`. Errors stay non-fatal (logged, frame
        // continues) — that part of the original behavior is correct.
        let run_one = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            let savepoint = self.state.as_ref().map(|s| s.changeset_len());
            if let Err(e) = invoke_token(inner_bytes, inner_tp) {
                // INFRASTRUCTURE/TRANSIENT failures (Store/Io) are replica-local:
                // swallowing one here would let this node skip an op another node
                // applies → silent state divergence under the same certified
                // digest (audit Finding #4). Propagate them so the outer
                // materializer treats the frame as fatal (retry, don't advance).
                // DETERMINISTIC failures (bad sig/semantics) fail identically on
                // every replica, so they stay non-fatal: roll back + continue.
                if let (Some(s), Some(sp)) = (self.state.as_ref(), savepoint) {
                    s.rollback_to(sp);
                }
                if matches!(e, QuilError::Store(_) | QuilError::Io(_)) {
                    return Err(e);
                }
                eprintln!("[WARN] token invoke_step failed type=0x{:08x}: {}", inner_tp, e);
            }
            Ok(())
        };

        // Persist the frame's accepted token writes into the CRDT. The
        // token engine previously never committed its HypergraphState,
        // so spent-markers and output coins lived only in the in-memory
        // changeset and never reached the CRDT (and thence the on-disk
        // trees via `crdt.commit(frame)`): the spent-set was effectively
        // empty on the next frame, making every spend replayable.
        // Mirrors GlobalExecutionEngine's per-message `state.commit()`.
        let commit_state = || -> Result<()> {
            if let Some(s) = self.state.as_ref() {
                match s.commit() {
                    // Clear the committed changeset. The engine and its
                    // HypergraphState are reused for the node's lifetime,
                    // so leaving committed entries in place would
                    // re-apply every prior message's writes on every
                    // subsequent commit (unbounded growth + redundant
                    // re-adds). The data is now in the CRDT; later reads
                    // (even same-frame, later messages) see it via the
                    // CRDT fallback in `HypergraphState::get`.
                    Ok(()) => s.abort(),
                    // A commit failure is infrastructure (Store/Io): propagate
                    // it as fatal so the frame is retried, not silently advanced
                    // with the writes lost (audit Finding #4).
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        };

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                for req in &bundle.requests {
                    if let Some(r) = req {
                        run_one(&r.inner_bytes, r.inner_type_prefix)?;
                    }
                }
                commit_state()?;
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                run_one(&req.inner_bytes, req.inner_type_prefix)?;
                commit_state()?;
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
    key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
}

impl ComputeExecutionEngine {
    /// Build a `ComputeExecutionEngine`. Proof-of-payment now uses Falcon
    /// (post-quantum) — no bulletproof/decaf dependency.
    pub fn new(
        mode: ExecutionMode,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        Self { mode, state: None, key_manager, circuit_compiler }
    }

    /// Construct with hypergraph state so materialize writes the
    /// deploy / execute / finalize vertices.
    pub fn new_with_state(
        mode: ExecutionMode,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt));
        Self { mode, state: Some(state), key_manager, circuit_compiler }
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
                    let ok = crate::compute_intrinsic::intrinsic::verify_code_execute(&ex)?;
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
                    // Initial deploy: derive the new compute app's domain
                    // and write the full metadata vertex (config + RDF +
                    // COMPUTE_INTRINSIC_DOMAIN type-domain) so the manager
                    // routes the derived domain to the compute engine.
                    // Mirrors Go ComputeIntrinsic.Deploy deploy branch.
                    let deploy = crate::compute_intrinsic::config::ComputeDeploy::from_canonical_bytes(inner_bytes)?;
                    if !deploy.config.is_empty() {
                        let cfg = crate::compute_intrinsic::config::ComputeConfiguration::from_canonical_bytes(&deploy.config)?;
                        let s = state.ok_or_else(|| QuilError::InvalidArgument(
                            "compute deploy: hypergraph state not installed".into(),
                        ))?;
                        // The compute engine has no inclusion_prover field
                        // of its own; commit metadata sub-trees with the
                        // CRDT's prover (same one the frame commit uses).
                        let prover = s.crdt().prover().clone();
                        let _derived = crate::compute_intrinsic::materialize::materialize_compute_deploy_init(
                            s,
                            &cfg,
                            &deploy.rdf_schema,
                            frame_number,
                            prover.as_ref(),
                        )?;
                    }
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
                    // Post-quantum owner auth: a single FALCON signature.
                    let mut domain_bytes = Vec::with_capacity(32 + b"COMPUTE_UPDATE".len());
                    domain_bytes.extend_from_slice(address);
                    domain_bytes.extend_from_slice(b"COMPUTE_UPDATE");
                    let ok = km.validate_signature(
                        quil_types::crypto::KeyType::Falcon512,
                        &prior_owner_key,
                        &signed_message,
                        &update.public_key_signature_bls48581,
                        &domain_bytes,
                    )?;
                    if !ok {
                        return Err(QuilError::InvalidArgument(
                            "compute update: signature does not verify against \
                             prior config's owner public key".into(),
                        ));
                    }
                    // Signature verified — materialize the config/RDF
                    // update into the existing metadata vertex.
                    let cfg = if update.config.is_empty() {
                        None
                    } else {
                        Some(crate::compute_intrinsic::config::ComputeConfiguration::from_canonical_bytes(&update.config)?)
                    };
                    let prover = s.crdt().prover().clone();
                    crate::compute_intrinsic::materialize::materialize_compute_update(
                        s,
                        address,
                        cfg.as_ref(),
                        &update.rdf_schema,
                        frame_number,
                        prover.as_ref(),
                    )?;
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
                // Build the vertex-data tree from the confidential-field chunk
                // list. `v.data` is the wire-encoded list (u16 count + per-field
                // u16 size + bytes); each field is a commit-and-encrypt
                // ConfidentialField stored verbatim under its BE-u64 index.
                let chunks =
                    crate::hypergraph_intrinsic::split_vertex_add_proof_chunks(&v.data)
                        .unwrap_or_default();
                let tree =
                    crate::hypergraph_intrinsic::encrypted_to_vertex_tree(&chunks)?;
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
    /// Existing system-shard gate is still enforced upstream.
    /// - `Some` but `write_public_key(domain) == None`: rejects.
    /// An op against an undeployed hypergraph is always invalid.
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
            TYPE_HYPERGRAPH_DEPLOYMENT => {
                // Derive the new hypergraph app's domain and write the
                // full metadata vertex (config + RDF + HYPERGRAPH_BASE_
                // DOMAIN type-domain) so the manager routes the derived
                // domain to the hypergraph engine. Mirrors Go
                // HypergraphIntrinsic.Deploy deploy branch.
                let dispatched =
                    crate::hypergraph_intrinsic::decode_and_validate_deploy(inner_bytes)?;
                if let (Some(cfg), Some(state)) =
                    (dispatched.deploy.config.as_ref(), self.state.as_ref())
                {
                    let _derived =
                        crate::hypergraph_intrinsic::materialize_hypergraph_deploy_init(
                            state,
                            cfg,
                            &dispatched.deploy.rdf_schema,
                            frame_number,
                            self.inclusion_prover.as_ref(),
                        )?;
                }
                Ok(())
            }
            TYPE_HYPERGRAPH_UPDATE => {
                // The owner-key signature was already verified in
                // validate_inner_op → validate_hypergraph_update (run
                // before this match). Materialize the config/RDF swap
                // into the existing metadata vertex.
                let dispatched =
                    crate::hypergraph_intrinsic::dispatch::decode_and_validate_update(inner_bytes)?;
                if let Some(state) = self.state.as_ref() {
                    crate::hypergraph_intrinsic::materialize_hypergraph_update(
                        state,
                        address,
                        dispatched.update.config.as_ref(),
                        &dispatched.update.rdf_schema,
                        frame_number,
                        self.inclusion_prover.as_ref(),
                    )?;
                }
                Ok(())
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
        // Single source of truth shared with the client's build path: the
        // extrinsic tree is committed with the SHA-256 hash-Merkle prover
        // (`ShaInclusionProver`), NOT KZG — matching how every other
        // vertex/shard commitment is formed now (`quil_tries::vertex_commitment`
        // / `hypergraph_state::tree_content_digest`). The wired
        // `self.inclusion_prover` is a stale KZG leftover; committing with it
        // here would make the client (which has no ceremony SRS) unable to
        // reproduce the signed commitment. This was the ONLY live consensus
        // caller of the wired prover, so delegating to the SHA path removes the
        // last KZG dependency from the hyperedge-add auth path.
        crate::hypergraph_intrinsic::hyperedge_ops::hyperedge_extrinsic_commit(value)
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
        // Process the message's op(s), accumulating writes into the
        // HypergraphState changeset.
        let result: Result<()> = (|| {
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
                }
                crate::hypergraph_engine::MessageKindTopLevel::Request => {
                    let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                    self.process_inner_op(
                        frame_number,
                        address,
                        req.inner_type_prefix,
                        &req.inner_bytes,
                    )?;
                }
            }
            Ok(())
        })();

        // Flush accepted writes to the CRDT (`state.commit()` → `crdt.add_vertex`
        // / `remove_vertex` / `add_hyperedge` / `remove_hyperedge`), then clear
        // the changeset. On ANY error, discard this message's partial changeset —
        // mirrors GlobalExecutionEngine / TokenExecutionEngine's per-message
        // commit/abort. Without this the hypergraph engine's writes (deploy
        // metadata vertices AND vertex/hyperedge data) never reached the CRDT.
        if let Some(state) = self.state.as_ref() {
            match result {
                Ok(()) => {
                    state.commit()?;
                    state.abort();
                }
                Err(e) => {
                    state.abort();
                    return Err(e);
                }
            }
        } else {
            result?;
        }
        Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
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
            stubs.key_manager,
            stubs.clock_store,
        )
    }

    /// Build a `ComputeExecutionEngine` for tests.
    fn compute_engine_test(mode: ExecutionMode) -> ComputeExecutionEngine {
        let stubs = crate::testing::NoopExecutionCrypto::new();
        ComputeExecutionEngine::new(mode, stubs.key_manager, stubs.circuit_compiler)
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
        // The validate path requires each chunk to decode as a well-formed
        // commit-and-encrypt ConfidentialField — seal one to a throwaway reader.
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let field = crate::hypergraph_intrinsic::confidential::seal(
            b"vertex-field",
            &kp.public,
            &[0x11u8; 32],
            &[0x22u8; 12],
        )
        .unwrap();
        let proofs: Vec<Vec<u8>> =
            vec![crate::hypergraph_intrinsic::confidential::encode(&field)];
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
        // make_vertex_add_canonical carries 1 confidential field; the cost
        // model charges per field. Cost = 1 × 55 = 55.
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
