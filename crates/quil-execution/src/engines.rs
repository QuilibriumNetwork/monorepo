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
/// Refuse a token configuration whose mint policy names a classical authority
/// key. Application authority is post-quantum only;
/// checked on deploy and on update, so neither path can install one.
fn check_post_quantum_token_config(config: &crate::token_intrinsic::TokenConfiguration) -> Result<()> {
    if config.mint_strategy.is_empty() {
        return Ok(());
    }
    let strategy = crate::token_intrinsic::config::TokenMintStrategy::from_canonical_bytes(&config.mint_strategy)?;
    crate::token_intrinsic::config_resolver::StaticTokenConfigResolver::check_post_quantum_authority(&strategy)
}

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

/// Execution venue supplied by the manager. Global materialization also routes
/// uncovered applications here; covered applications execute in app mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Global,
    Application,
}

#[path = "engine_fork.rs"]
mod execution_fork;

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

    /// Install the config the unified-tree split reset needs at the flag day: the
    /// archive KEEP-set (records that survive the drop) and the network's QUIL
    /// genesis shard-prefix set (the grid is rebuilt to it). See
    /// [`crate::global_intrinsic::intrinsic::GlobalIntrinsic::maybe_apply_split_reset`].
    /// Archive-materializing nodes only; without it the reset no-ops and the node
    /// syncs the post-reset state.
    pub fn install_split_reset_config(
        &mut self,
        archive_prover_addresses: Arc<std::collections::HashSet<Vec<u8>>>,
        reset_genesis_prefixes: Arc<Vec<Vec<u32>>>,
    ) {
        if let Some(intrinsic) = self.intrinsic.take() {
            self.intrinsic = Some(
                intrinsic
                    .with_archive_prover_addresses(archive_prover_addresses)
                    .with_reset_genesis_prefixes(reset_genesis_prefixes),
            );
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
        shards_store: Option<Arc<dyn quil_types::store::ShardsStore>>,
        shards_db: Option<Arc<dyn quil_types::store::KvDb>>,
    ) -> Self {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(crdt.clone()));
        let mut intrinsic = crate::global_intrinsic::intrinsic::GlobalIntrinsic::new(key_manager)
            .with_clock_store(clock_store);
        // Shard split/merge topology changes only persist/apply when BOTH the
        // shards store and its KvDb are wired (see GlobalIntrinsic::with_shards_*).
        if let Some(s) = shards_store {
            intrinsic = intrinsic.with_shards_store(s);
        }
        if let Some(db) = shards_db {
            intrinsic = intrinsic.with_shards_db(db);
        }
        Self {
            inclusion_prover,
            intrinsic: Some(intrinsic),
            crdt: Some(crdt),
            state: Some(state),
        }
    }

    /// Apply epoch-aligned shard topology changes (split/merge) that have reached
    /// their E+2 effective epoch, ONCE per global frame — decoupled from
    /// `invoke_frame_header` so a staged `PendingShardChange` flips deterministically
    /// at its boundary even when NO app-shard `FrameHeader` is materialized in the
    /// frame. (Field failure mode: `apply_due_shard_changes` was reachable ONLY from
    /// `invoke_frame_header`, so when app-shard header flow to the global chain
    /// stalled, the flip never fired at the due frame and the split re-proposed
    /// forever.) Writes go onto the frame's state changeset; `state.commit()` pushes
    /// them into the in-memory CRDT trees exactly like `process_message`, so the
    /// materializer's `commit_frame` flushes them durably. No-op when the
    /// intrinsic/state is absent or nothing is due.
    pub fn apply_due_shard_changes(&self, frame_number: u64) -> Result<()> {
        if let (Some(intrinsic), Some(state)) = (&self.intrinsic, &self.state) {
            let checkpoint = state.changeset_len();
            let start = std::time::Instant::now();
            let result = (|| {
                intrinsic.apply_due_shard_changes(frame_number, state)?;
                // A cutover reset supersedes any topology applied in this frame.
                intrinsic.maybe_apply_split_reset(frame_number, state)?;
                state.commit()
            })();
            if let Err(error) = result {
                state.rollback_to(checkpoint);
                return Err(error);
            }
            if start.elapsed().as_millis() > 500 {
                tracing::warn!(frame = frame_number, ms = start.elapsed().as_millis() as u64,
                    changeset = state.changeset_len(), "shard maintenance staging is slow");
            }
            // CRDT staging owns both forest and metadata writes until the frame
            // transaction succeeds. The message changeset can now be cleared.
            state.abort();
        }
        Ok(())
    }
}

impl GlobalExecutionEngine {
    /// Credit this global frame's token fees to its prover. Rides the same
    /// pre-commit hook shape as `apply_due_shard_changes`: the credit is staged into the CRDT and the
    /// materializer's `commit_frame` flushes it durably.
    pub fn credit_global_frame_fees(
        &self,
        frame_number: u64,
        prover_public_key: &[u8],
        fee_total: u128,
    ) -> Result<bool> {
        let (Some(ref intrinsic), Some(ref state)) = (&self.intrinsic, &self.state) else {
            return Ok(false);
        };
        let credited =
            intrinsic.credit_global_frame_fees(frame_number, prover_public_key, fee_total, state)?;
        if credited {
            state.commit()?;
            state.abort();
        }
        Ok(credited)
    }
}

impl ShardExecutionEngine for GlobalExecutionEngine {
    fn as_any(&self) -> Option<&dyn std::any::Any> { Some(self) }

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
            if inner_tp == crate::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF {
                let state = self.state.as_ref().ok_or_else(|| QuilError::ExecutionUnavailable(
                    "handoff validation requires authenticated global state".into()))?;
                let submission = crate::global_intrinsic::handoff::CertificateSubmission::from_canonical_bytes(inner_bytes)?;
                crate::global_intrinsic::handoff::verify_submission(state.as_ref(), frame_number, &submission)?;
                return Ok(());
            }
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
                    false => Err(QuilError::InvalidArgument(format!(
                        "global: signature verification failed (op={}, prover_tree={}, alloc_tree={})",
                        crate::global_engine::peek_global_message_kind(inner_bytes)
                            .map(|k| format!("{k:?}"))
                            .unwrap_or_else(|_| "unknown".into()),
                        prover_tree.is_some(),
                        alloc_tree.is_some(),
                    ))),
                }
            } else if let Some(ref intrinsic) = self.intrinsic {
                // Intrinsic present but no state — structural only
                match intrinsic.validate(frame_number, inner_bytes, None, None)? {
                    true => Ok(()),
                    false => Err(QuilError::InvalidArgument(format!(
                        "global: signature verification failed (op={}, no-state)",
                        crate::global_engine::peek_global_message_kind(inner_bytes)
                            .map(|k| format!("{k:?}"))
                            .unwrap_or_else(|_| "unknown".into()),
                    ))),
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

        let checkpoint = self.state.as_ref().map_or(0, |state| state.changeset_len());
        let invoke = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if inner_tp == crate::global_intrinsic::handoff::TYPE_COMMITTEE_HANDOFF
                && (self.intrinsic.is_none() || self.state.is_none())
            {
                return Err(QuilError::ExecutionUnavailable("handoff execution requires authenticated global state".into()));
            }
            if !crate::global_engine::is_global_type_prefix(inner_tp) {
                return Ok(());
            }
            if let (Some(intrinsic), Some(state)) = (&self.intrinsic, &self.state) {
                let step_checkpoint = state.changeset_len();
                if let Err(error) = intrinsic.invoke_step(_frame_number, inner_bytes, state) {
                    return finish_global_step(state, step_checkpoint, inner_tp, error);
                }
            }
            Ok(())
        };
        let result = match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                bundle.requests.iter().flatten().try_for_each(|request|
                    invoke(&request.inner_bytes, request.inner_type_prefix))
            }
            TYPE_MESSAGE_REQUEST => {
                let request = CanonicalMessageRequest::from_canonical_bytes(message)?;
                invoke(&request.inner_bytes, request.inner_type_prefix)
            }
            _ => Err(QuilError::InvalidArgument("global: unsupported message type".into())),
        };
        if let Err(error) = result {
            if let Some(state) = &self.state { state.rollback_to(checkpoint); }
            return Err(error);
        }
        // Staging failure must abort frame processing. Successful publication
        // clears the changeset so later requests do not reapply prior writes.
        let _timing = crate::step_timing::section("stage changes");
        publish_execution_changes(self.state.as_deref(), checkpoint)?;
        Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
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
            | Some(MessageRequestInner::SeniorityMerge(_))
            | Some(MessageRequestInner::CommitteeHandoff(_)) => true,
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
/// Confidential operations require the configured QCT3 policy, state and
/// isolated amount-proof worker. Retired confidential formats are rejected.
pub struct TokenExecutionEngine {
    mode: ExecutionMode,
    #[cfg(feature = "native-proof")]
    token_policy: Option<crate::token_intrinsic::dispatch::TokenPolicy>,
    #[cfg(feature = "native-proof")]
    token_execution: std::sync::Mutex<()>,
    #[cfg(feature = "native-proof")]
    token_worker: Option<quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier>,
    inclusion_prover: Arc<dyn InclusionProver>,
    state: Option<Arc<crate::hypergraph_state::HypergraphState>>,
    key_manager: Arc<dyn quil_types::crypto::KeyManager>,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    config_resolver: Arc<dyn crate::token_intrinsic::config_resolver::TokenConfigResolver>,
}

impl TokenExecutionEngine {
    /// Select the token suite explicitly for this engine. Requires real
    /// state; unintegrated confidential operations reject without old fallback.
    /// Node defaults remain unchanged pending the complete swap/security gates.
    #[cfg(feature = "native-proof")]
    pub fn with_token_proofs(mut self,
        policy: crate::token_intrinsic::dispatch::TokenPolicy) -> Result<Self> {
        if self.state.is_none() {
            return Err(QuilError::InvalidArgument("token engine requires state".into()));
        }
        self.token_policy = Some(policy);
        Ok(self)
    }

    /// Use a locally configured child process for amount proofs.
    /// Share clones of one client across engines to share its admission limit.
    /// Requires the token policy first; worker failure never falls back
    /// to in-process native verification or to the earlier token suite.
    #[cfg(feature = "native-proof")]
    pub fn with_token_worker(mut self,
        worker: quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier,
    ) -> Result<Self> {
        if self.token_policy.is_none() {
            return Err(QuilError::InvalidArgument("token policy must be configured before its worker".into()));
        }
        self.token_worker = Some(worker);
        Ok(self)
    }

    /// Configure both parts together before a manager publishes this engine.
    #[cfg(feature = "native-proof")]
    pub(crate) fn configure_token_worker(
        &mut self,
        policy: crate::token_intrinsic::dispatch::TokenPolicy,
        worker: quil_lattice_ct::confidential::relation::backend::worker_client::WorkerVerifier,
    ) -> Result<()> {
        if self.state.is_none() {
            return Err(QuilError::InvalidArgument("token engine requires state".into()));
        }
        self.token_policy = Some(policy);
        self.token_worker = Some(worker);
        Ok(())
    }

    /// Confidential operations inside canonical bundles: `(address, inner bytes,
    /// type prefix)` for every request the token suite would verify.
    #[cfg(feature = "native-proof")]
    pub fn confidential_operations(bundles: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>, u32)> {
        let mut operations = Vec::new();
        for (address, bytes) in bundles {
            let Ok(bundle) = crate::message_envelope::CanonicalMessageBundle::from_canonical_bytes(bytes) else { continue };
            for request in bundle.requests.into_iter().flatten() {
                if crate::token_intrinsic::dispatch::is_confidential_type(request.inner_type_prefix) {
                    operations.push((address.clone(), request.inner_bytes, request.inner_type_prefix));
                }
            }
        }
        operations
    }

    /// Verify a frame's confidential operations concurrently (up to the
    /// worker's admission slots) so the sequential materialization loop finds
    /// their verdicts cached. Never holds the execution lock; never fails.
    #[cfg(feature = "native-proof")]
    pub fn preverify_bundles(&self, bundles: &[(Vec<u8>, Vec<u8>)]) {
        let (Some(policy), Some(worker)) = (self.token_policy, self.token_worker.as_ref()) else { return };
        let operations = Self::confidential_operations(bundles);
        if operations.is_empty() { return; }
        let parallelism = worker.concurrency().clamp(1, operations.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..parallelism {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((address, bytes, tp)) = operations.get(index) else { break };
                    policy.preverify(worker, address, bytes, *tp);
                });
            }
        });
    }

    /// Confidential operations a proposal may schedule under the verification
    /// budget; unbounded without a configured worker.
    #[cfg(feature = "native-proof")]
    pub fn verification_capacity(&self) -> usize {
        match self.token_worker.as_ref() {
            Some(worker) => crate::token_intrinsic::dispatch::frame_verification_capacity(worker.concurrency()),
            None => usize::MAX,
        }
    }

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
            #[cfg(feature = "native-proof")]
            token_policy: None,
            #[cfg(feature = "native-proof")]
            token_execution: std::sync::Mutex::new(()),
            #[cfg(feature = "native-proof")]
            token_worker: None,
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
            #[cfg(feature = "native-proof")]
            token_policy: None,
            #[cfg(feature = "native-proof")]
            token_execution: std::sync::Mutex::new(()),
            #[cfg(feature = "native-proof")]
            token_worker: None,
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
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
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
            #[cfg(feature = "native-proof")]
            if let Some(policy) = &self.token_policy {
                if crate::token_intrinsic::dispatch::is_confidential_type(inner_tp)
                    || inner_tp == crate::token_intrinsic::constants::TYPE_COIN_DELIVERY
                {
                    policy.check_venue(self.mode, _address, inner_tp)?;
                    return policy.preflight(_address, inner_bytes, inner_tp);
                }
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
                crate::token_engine::TYPE_LATTICE_TRANSACTION
                | crate::token_engine::TYPE_LATTICE_MINT
                | crate::token_engine::TYPE_LATTICE_PENDING
                | crate::token_engine::TYPE_LATTICE_PENDING_CLAIM
                | crate::token_engine::TYPE_LATTICE_SHIELD
                | crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                | crate::token_engine::TYPE_LATTICE_SETTLEMENT => {
                    return Err(QuilError::InvalidArgument("token proof verification is not configured".into()));
                }
                _ => { crate::token_engine::peek_token_message_kind(inner_bytes)?; }
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
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        self.process_message_with_context(
            quil_types::execution::FrameExecutionContext {
                frame_number, finalized_global_frame: None, venue: None, shard: quil_types::execution::ShardPath::WHOLE
            }, fee_multiplier, address, message)
    }

    fn process_message_with_context(
        &self,
        context: quil_types::execution::FrameExecutionContext,
        _fee_multiplier: &BigInt,
        _address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let _frame_number = context.frame_number;
        #[cfg(feature = "native-proof")]
        let _token_guard = if self.token_policy.is_some() {
            Some(self.token_execution.lock().map_err(|_| QuilError::ExecutionUnavailable(
                "token execution lock poisoned".into()))?)
        } else { None };
        if message.len() < 4 {
            return Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() });
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&message[..4]);
        let tp = u32::from_be_bytes(buf);

        let state_checkpoint = self.state.as_ref().map_or(0, |s| s.changeset_len());
        // A payment admitted from the bundle's settlement claim, consumed by
        // the first custom mint of the bundle (a paid mint policy's price).
        #[cfg(feature = "native-proof")]
        let paid_allowance: std::cell::Cell<Option<crate::token_intrinsic::custom_mint::PaidMintAllowance>> =
            std::cell::Cell::new(None);

        let invoke_token = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            if !crate::token_engine::is_token_type_prefix(inner_tp) {
                return Ok(());
            }
            let state = match &self.state {
                Some(s) => s,
                None if matches!(inner_tp,
                    crate::token_engine::TYPE_LATTICE_TRANSACTION
                    | crate::token_engine::TYPE_LATTICE_MINT
                    | crate::token_engine::TYPE_LATTICE_PENDING
                    | crate::token_engine::TYPE_LATTICE_PENDING_CLAIM
                    | crate::token_engine::TYPE_LATTICE_SHIELD
                    | crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                    | crate::token_engine::TYPE_LATTICE_SETTLEMENT) => {
                    return Err(QuilError::InvalidArgument("token proof verification is not configured".into()));
                }
                None => return Ok(()), // other stateless operations skip materialization
            };
            #[cfg(feature = "native-proof")]
            if let Some(policy) = &self.token_policy {
                // An explicit anchor is authoritative: app-shard
                // materialization (workers, archive ingest) passes the
                // frame's certified global anchor, the global materializer
                // passes frame − 1. Only a global-venue caller without one
                // derives it from the frame number. The executing shard is a
                // property of the frame, not of this rebuilt anchor.
                let anchored = quil_types::execution::FrameExecutionContext {
                    frame_number: _frame_number,
                    finalized_global_frame: settlement_global_bound(effective_mode(self.mode, context), context),
                    venue: context.venue, shard: context.shard,
                };
                if inner_tp == crate::token_intrinsic::constants::TYPE_COIN_DELIVERY {
                    policy.check_venue(effective_mode(self.mode, context), _address, inner_tp)?;
                    return policy.dispatch_delivery(state, anchored, self.clock_store.as_ref(), _address, inner_bytes);
                }
                if crate::token_intrinsic::dispatch::is_confidential_type(inner_tp) {
                    // A shard holding part of the application runs these too:
                    // it only verifies and relays, and the global frame decides.
                    // What an operation still needs from local state — a
                    // shield's legacy coin, a custom mint's deployed policy — is
                    // checked where it is read.
                    policy.check_venue(effective_mode(self.mode, context), _address, inner_tp)?;
                    // The fee is priced by the venue where the operation
                    // COMMITS, not by the frame that happens to carry it. An
                    // operation that commits through the global frame is priced
                    // at that frame's vote of 1, which is the quote a wallet is
                    // given (`GetTokenFeeQuote` answers QUIL from the global
                    // snapshot and refuses a global-venue quote whose vote is
                    // not 1); the app shard that verifies and relays it prices
                    // it the same way, by voting 1 for such a bundle
                    // (`materialize_app_shard_requests`). The check stays HERE,
                    // before the relay: nothing re-validates the fee of a
                    // relayed entry at the global commit, which credits the
                    // entry's own `fee`.
                    policy.check_self_paid_fee(_address, inner_bytes, inner_tp, _fee_multiplier)?;
                    // Every operation that consumes or creates coins commits
                    // through the global frame: app shards verify and relay,
                    // the global venue commits inline.
                    let commits = <[u8; 32]>::try_from(_address).is_ok_and(|application|
                        crate::token_intrinsic::spend_entries::commits_globally(&application, inner_tp));
                    if commits {
                        return match effective_mode(self.mode, context) {
                            ExecutionMode::Application => policy.dispatch_for_commit(
                                state, anchored, self.clock_store.as_ref(), _address, inner_bytes, inner_tp,
                                self.token_worker.as_ref(), paid_allowance.take()),
                            ExecutionMode::Global => policy.dispatch_commit_inline(
                                state, anchored, self.clock_store.as_ref(), _address, inner_bytes, inner_tp,
                                self.token_worker.as_ref(), paid_allowance.take()),
                        };
                    }
                    if inner_tp == crate::token_engine::TYPE_LATTICE_MINT {
                        return policy.dispatch_global_mint(state, _frame_number, self.clock_store.as_ref(), _address, inner_bytes, self.token_worker.as_ref());
                    }
                    // Every other confidential operation commits through the
                    // global frame (handled above); nothing stages locally.
                    return Err(QuilError::InvalidArgument("confidential operation has no local execution path".into()));
                }
            }
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
                crate::token_engine::TYPE_LATTICE_TRANSACTION
                | crate::token_engine::TYPE_LATTICE_MINT
                | crate::token_engine::TYPE_LATTICE_PENDING
                | crate::token_engine::TYPE_LATTICE_PENDING_CLAIM
                | crate::token_engine::TYPE_LATTICE_SHIELD
                | crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                | crate::token_engine::TYPE_LATTICE_SETTLEMENT => {
                    return Err(QuilError::InvalidArgument("token proof verification is not configured".into()));
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
                        check_post_quantum_token_config(&cfg)?;
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

                            check_post_quantum_token_config(&new_cfg)?;
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
        // back to it on `Err`. Every rejection propagates; frame callers
        // distinguish deterministic rejection from retryable local failures.
        let run_one = |inner_bytes: &[u8], inner_tp: u32| -> Result<()> {
            let savepoint = self.state.as_ref().map(|s| s.changeset_len());
            finish_token_step(self.state.as_deref(), savepoint, inner_tp,
                invoke_token(inner_bytes, inner_tp))
        };

        // Persist the frame's accepted token writes into the CRDT. The
        // token engine previously never committed its HypergraphState,
        // so spent-markers and output coins lived only in the in-memory
        // changeset and never reached the CRDT (and thence the on-disk
        // trees via `crdt.commit(frame)`): the spent-set was effectively
        // empty on the next frame, making every spend replayable.
        // Mirrors GlobalExecutionEngine's per-message `state.commit()`.
        let commit_state = || publish_execution_changes(self.state.as_deref(), state_checkpoint);

        match tp {
            TYPE_MESSAGE_BUNDLE => {
                let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
                let claim_checkpoint = self.state.as_ref().map(|s| s.changeset_len());
                // Operations on any application other than QUIL carry a QUIL
                // fee. A custom-token bundle that grows state at a nonzero
                // price must open with a settlement claim covering that growth
                // (paid to the executing shard's provers); the claim may also
                // carry a paid mint's price to the token's payment address.
                #[cfg(feature = "native-proof")]
                if self.token_policy.is_some() && _address.len() >= 32 && _address[..32] != crate::domains::QUIL_TOKEN {
                    let growth = bundle.requests.iter().flatten()
                        .try_fold(0u64, |total, r| token_consumer_cost(r).map(|cost| total.saturating_add(cost)))?;
                    let admitted = crate::token_intrinsic::settlement_claim::admit_bundle(
                        &crate::token_intrinsic::settlement_claim::PaymentContext {
                            state: self.state.as_deref(),
                            clock: Some(self.clock_store.as_ref()),
                            global_bound: settlement_global_bound(effective_mode(self.mode, context), context),
                            frame_number: _frame_number,
                            multiplier: _fee_multiplier,
                            shard: context.shard,
                        },
                        _address, &bundle, growth,
                    )?;
                    if let Some(admitted) = admitted.filter(|admitted| admitted.payment > 0) {
                        paid_allowance.set(Some(crate::token_intrinsic::custom_mint::PaidMintAllowance {
                            payment_address: admitted.payment_address,
                            payment: admitted.payment,
                        }));
                    }
                }
                if let Err(error) = run_token_bundle(self.state.as_deref(), &bundle, run_one) {
                    // Also drop the claim's consumption marker.
                    if let (Some(state), Some(checkpoint)) = (self.state.as_deref(), claim_checkpoint) {
                        state.rollback_to(checkpoint);
                    }
                    return Err(error);
                }
                commit_state()?;
                Ok(ProcessMessageResult { messages: Vec::new(), state: Vec::new() })
            }
            TYPE_MESSAGE_REQUEST => {
                let req = CanonicalMessageRequest::from_canonical_bytes(message)?;
                // A lone custom-token request cannot carry a claim, so it is
                // admitted only when it grows no state or the price is zero.
                #[cfg(feature = "native-proof")]
                if self.token_policy.is_some() && _address.len() >= 32 && _address[..32] != crate::domains::QUIL_TOKEN {
                    let growth = token_consumer_cost(&req)?;
                    let single = CanonicalMessageBundle { requests: vec![Some(req.clone())], timestamp: 0 };
                    crate::token_intrinsic::settlement_claim::admit_bundle(
                        &crate::token_intrinsic::settlement_claim::PaymentContext {
                            state: None, clock: None, global_bound: None,
                            frame_number: _frame_number, multiplier: _fee_multiplier,
                            shard: context.shard,
                        },
                        _address, &single, growth,
                    )?;
                }
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
            | Some(MessageRequestInner::TokenOperation(_)),
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
                    crate::token_engine::TYPE_TRANSACTION
                    | crate::token_engine::TYPE_PENDING_TRANSACTION
                    | crate::token_engine::TYPE_MINT_TRANSACTION => {
                        return Err(QuilError::InvalidArgument("retired token operation".into()));
                    }
                    // Confidential operations are priced like every other
                    // primitive: by the bytes of world state their admission
                    // adds (coins, escrow, markers), never by proof size.
                    crate::token_engine::TYPE_LATTICE_TRANSACTION
                    | crate::token_engine::TYPE_LATTICE_MINT
                    | crate::token_engine::TYPE_LATTICE_PENDING
                    | crate::token_engine::TYPE_LATTICE_PENDING_CLAIM
                    | crate::token_engine::TYPE_LATTICE_SHIELD
                    | crate::token_engine::TYPE_LATTICE_MINT_CLAIM
                | crate::token_engine::TYPE_LATTICE_SETTLEMENT => {
                        #[cfg(feature = "confidential-tokens")]
                        {
                            return Ok(BigInt::from(crate::token_intrinsic::cost::state_growth(&req.inner_bytes)?));
                        }
                        #[cfg(not(feature = "confidential-tokens"))]
                        {
                            return Ok(BigInt::from(req.inner_bytes.len() as u64));
                        }
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

/// Write materialized coin and spent marker vertices to the HypergraphState.
/// Roll back an unsuccessful operation before distinguishing a deterministic
/// rejection from a local failure that must abort frame processing.
fn finish_token_step(
    state: Option<&crate::hypergraph_state::HypergraphState>,
    savepoint: Option<usize>,
    inner_tp: u32,
    result: Result<()>,
) -> Result<()> {
    if let Err(e) = result {
        if let (Some(state), Some(savepoint)) = (state, savepoint) {
            state.rollback_to(savepoint);
        }
        let _ = inner_tp;
        return Err(e);
    }
    Ok(())
}

/// Global lifecycle rejections remain per-operation skips. Infrastructure
/// failures must reach the frame caller. Neither may retain partial step writes.
fn finish_global_step(
    state: &crate::hypergraph_state::HypergraphState,
    checkpoint: usize,
    inner_type: u32,
    error: QuilError,
) -> Result<()> {
    state.rollback_to(checkpoint);
    if error.is_execution_unavailable() { return Err(error); }
    tracing::debug!(inner_type, %error, "global operation rejected");
    Ok(())
}

/// Publish the accepted changeset, or discard this attempt's changes
/// before returning a retryable staging failure. Atomic CRDT batch preparation
/// guarantees that an error has not published part of this changeset.
fn publish_execution_changes(
    state: Option<&crate::hypergraph_state::HypergraphState>,
    checkpoint: usize,
) -> Result<()> {
    if let Some(state) = state {
        if let Err(error) = state.commit() {
            state.rollback_to(checkpoint);
            return Err(error);
        }
        // Published data is now readable through the CRDT fallback. Do not
        // accumulate and replay successful changesets on subsequent messages.
        state.abort();
    }
    Ok(())
}

/// Stage a token bundle atomically. No fee producer or earlier operation may
/// survive a later rejection merely because its individual step succeeded.
/// CRDT commit remains the caller's responsibility after all steps succeed.
/// World-state growth (bytes) a request adds to a custom-token application,
/// the unit its QUIL fee is priced in: a confidential operation's staged growth
/// and a deploy or update's configuration. Other requests cost nothing here
/// (a settlement claim's own marker is priced by the claim admission).
#[cfg(feature = "native-proof")]
/// State growth a token request adds beyond what `request_cost` already
/// prices: the staged growth of a confidential operation. Deploys and updates
/// are priced by `request_cost`, which the paying wallet uses too, so they must
/// not be counted again here.
fn token_consumer_cost(request: &CanonicalMessageRequest) -> Result<u64> {
    if crate::token_intrinsic::dispatch::is_confidential_type(request.inner_type_prefix) {
        return crate::token_intrinsic::cost::state_growth(&request.inner_bytes);
    }
    Ok(0)
}

fn run_token_bundle(
    state: Option<&crate::hypergraph_state::HypergraphState>,
    bundle: &CanonicalMessageBundle,
    mut run_one: impl FnMut(&[u8], u32) -> Result<()>,
) -> Result<()> {
    let checkpoint = state.map(|s| s.changeset_len());
    for request in bundle.requests.iter().flatten() {
        if let Err(error) = run_one(&request.inner_bytes, request.inner_type_prefix) {
            if let (Some(state), Some(checkpoint)) = (state, checkpoint) {
                state.rollback_to(checkpoint);
            }
            return Err(error);
        }
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
    /// Canonical global frames, for settlement claims funding compute writes.
    global_clock: Option<Arc<dyn quil_types::store::ClockStore>>,
}

impl TokenExecutionEngine {
    /// The venue this engine executes in.
    pub fn mode(&self) -> ExecutionMode {
        self.mode
    }

    /// Read canonical global frames (reward mint and mint-claim citations)
    /// from `store`. A thread worker's own clock store holds only its app-shard
    /// chain; the master's store holds the global chain.
    pub fn set_global_clock_store(&mut self, store: Arc<dyn quil_types::store::ClockStore>) {
        self.clock_store = store;
    }

    /// Set the venue: application workers execute app-shard frames, whose
    /// claims are bounded by the frame's certified global anchor rather than
    /// by the execution frame number.
    pub fn set_mode(&mut self, mode: ExecutionMode) {
        self.mode = mode;
    }
}

impl ComputeExecutionEngine {
    /// Build a `ComputeExecutionEngine`. Proof-of-payment now uses Falcon
    /// (post-quantum) — no bulletproof/decaf dependency.
    pub fn new(
        mode: ExecutionMode,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        circuit_compiler: Arc<dyn quil_types::execution::CircuitCompiler>,
    ) -> Self {
        Self { mode, state: None, key_manager, circuit_compiler, global_clock: None }
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
        Self { mode, state: Some(state), key_manager, circuit_compiler, global_clock: None }
    }
}

/// The venue a frame executes in: the context's, when it names one, else the
/// engine's configured venue.
#[cfg_attr(not(feature = "native-proof"), allow(dead_code))]
fn effective_mode(own: ExecutionMode, context: quil_types::execution::FrameExecutionContext) -> ExecutionMode {
    match context.venue {
        Some(quil_types::execution::Venue::Global) => ExecutionMode::Global,
        Some(quil_types::execution::Venue::Application) => ExecutionMode::Application,
        None => own,
    }
}

/// Newest global frame a claim (mint, pending or settlement) may cite. An
/// explicit anchor is authoritative: app-shard materialization (workers,
/// archive ingest, including managers built for the global venue) passes the
/// frame's certified global anchor and the global materializer passes frame − 1.
/// Only a global-venue caller without one derives it from the frame number.
fn settlement_global_bound(mode: ExecutionMode, context: quil_types::execution::FrameExecutionContext) -> Option<u64> {
    match (mode, context.finalized_global_frame) {
        (_, Some(anchor)) => Some(anchor),
        (ExecutionMode::Global, None) => context.frame_number.checked_sub(1),
        (ExecutionMode::Application, None) => None,
    }
}

impl ComputeExecutionEngine {
    /// Store holding canonical global frames (settlement claim citations).
    pub fn set_global_clock_store(&mut self, store: Arc<dyn quil_types::store::ClockStore>) {
        self.global_clock = Some(store);
    }
}

impl ShardExecutionEngine for ComputeExecutionEngine {
    fn as_any(&self) -> Option<&dyn std::any::Any> { Some(self) }

    fn get_name(&self) -> &str { "compute" }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn process_message(&self, frame_number: u64, fee_multiplier: &BigInt, address: &[u8], message: &[u8]) -> Result<ProcessMessageResult> {
        self.process_message_with_context(
            quil_types::execution::FrameExecutionContext { frame_number, finalized_global_frame: None, venue: None, shard: quil_types::execution::ShardPath::WHOLE },
            fee_multiplier, address, message,
        )
    }

    /// Admit the message's payment (a settlement claim covering its state
    /// growth), execute it, and commit its writes atomically.
    fn process_message_with_context(
        &self,
        context: quil_types::execution::FrameExecutionContext,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let result = (|| {
            #[cfg(feature = "confidential-tokens")]
            crate::token_intrinsic::settlement_claim::admit_paid_message(
                &crate::token_intrinsic::settlement_claim::PaymentContext {
                    state: self.state.as_deref(),
                    clock: self.global_clock.as_deref(),
                    global_bound: settlement_global_bound(effective_mode(self.mode, context), context),
                    frame_number: context.frame_number,
                    multiplier: fee_multiplier,
                    shard: context.shard,
                },
                address,
                message,
            )?;
            #[cfg(not(feature = "confidential-tokens"))]
            let _ = fee_multiplier;
            self.process_unpaid(context.frame_number, address, message)
        })();
        match (self.state.as_ref(), result) {
            (Some(state), Ok(outcome)) => {
                state.commit()?;
                state.abort();
                Ok(outcome)
            }
            (Some(state), Err(e)) => {
                state.abort();
                Err(e)
            }
            (None, result) => result,
        }
    }

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

impl ComputeExecutionEngine {
    fn process_unpaid(&self, frame_number: u64, address: &[u8], message: &[u8]) -> Result<ProcessMessageResult> {
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
    /// Canonical global frames, for settlement claims funding writes.
    global_clock: Option<Arc<dyn quil_types::store::ClockStore>>,
}

impl HypergraphExecutionEngine {
    /// Store holding canonical global frames (settlement claim citations).
    pub fn set_global_clock_store(&mut self, store: Arc<dyn quil_types::store::ClockStore>) {
        self.global_clock = Some(store);
    }

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
            global_clock: None,
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
            global_clock: None,
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

        // A settlement consumption marker is engine-owned: a vertex write or
        // removal at its address would let the record fund a second bundle.
        if let hg_dispatch::DispatchedMessage::VertexAdd(crate::hypergraph_intrinsic::types::VertexAdd { domain, data_address, .. })
        | hg_dispatch::DispatchedMessage::VertexRemove(crate::hypergraph_intrinsic::types::VertexRemove { domain, data_address, .. }) = &msg
        {
            #[cfg(feature = "confidential-tokens")]
            if state.get(domain, data_address, &va_disc)?
                .is_some_and(|blob| crate::token_intrinsic::settlement_claim::is_consumption_marker(&blob))
            {
                return Err(QuilError::InvalidArgument(
                    "hypergraph: vertex address holds a settlement consumption marker".into(),
                ));
            }
            #[cfg(not(feature = "confidential-tokens"))]
            let _ = (domain, data_address);
        }

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
            verify_op_signature, OpForAuth,
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
    fn as_any(&self) -> Option<&dyn std::any::Any> { Some(self) }

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

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn process_message(
        &self,
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        self.process_message_with_context(
            quil_types::execution::FrameExecutionContext { frame_number, finalized_global_frame: None, venue: None, shard: quil_types::execution::ShardPath::WHOLE },
            fee_multiplier, address, message,
        )
    }

    fn process_message_with_context(
        &self,
        context: quil_types::execution::FrameExecutionContext,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let frame_number = context.frame_number;
        let kind = crate::hypergraph_engine::peek_top_level_kind(message)?;
        // Process the message's op(s), accumulating writes into the
        // HypergraphState changeset.
        let result: Result<()> = (|| {
            // Payment first: a state-growing bundle must open with a
            // settlement claim covering its dynamic cost; the claim's
            // consumption marker joins this message's changeset.
            #[cfg(feature = "confidential-tokens")]
            crate::token_intrinsic::settlement_claim::admit_paid_message(
                &crate::token_intrinsic::settlement_claim::PaymentContext {
                    state: self.state.as_deref(),
                    clock: self.global_clock.as_deref(),
                    global_bound: settlement_global_bound(effective_mode(self.mode, context), context),
                    frame_number,
                    multiplier: fee_multiplier,
                    shard: context.shard,
                },
                address,
                message,
            )?;
            #[cfg(not(feature = "confidential-tokens"))]
            let _ = fee_multiplier;
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

    #[test]
    fn token_backend_failure_rolls_back_and_propagates_instead_of_rejecting() {
        let state = crate::hypergraph_state::HypergraphState::new(Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver))));
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        state.set(&[1; 32], &[2; 32], &disc, 1, vec![3]).unwrap();
        let checkpoint = state.changeset_len();
        for error in [
            QuilError::ExecutionUnavailable("native allocation budget".into()),
            QuilError::Store("read unavailable".into()),
            QuilError::Io(std::io::Error::other("disk unavailable")),
            QuilError::InvalidArgument("invalid proof".into()),
        ] {

            state.set(&[1; 32], &[4; 32], &disc, 1, vec![5]).unwrap();
            let result = finish_token_step(Some(&state), Some(checkpoint),
                crate::token_engine::TYPE_LATTICE_TRANSACTION, Err(error));
            assert!(result.is_err());
            assert_eq!(state.changeset_len(), checkpoint);
            assert_eq!(state.get(&[1; 32], &[2; 32], &disc).unwrap(), Some(vec![3]));
            assert!(state.get(&[1; 32], &[4; 32], &disc).unwrap().is_none());
        }
    }

    #[test]
    fn global_publication_failure_reaches_caller_and_success_clears_changes() {
        use crate::hypergraph_state::{HypergraphState, vertex_adds_discriminator, hyperedge_adds_discriminator};
        use quil_hypergraph::{HypergraphCrdt, testing::MemStore};
        for bundled in [false, true] {
            let store = Arc::new(MemStore::new());
            let crdt = Arc::new(HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver)));
            let state = Arc::new(HypergraphState::new(crdt.clone()));
            let va = vertex_adds_discriminator().unwrap();
            let ha = hyperedge_adds_discriminator().unwrap();
            state.set(&[7; 32], &[8; 32], &va, 1, b"vertex".to_vec()).unwrap();
            state.set(&[7; 32], &[9; 32], &ha, 1, b"edge".to_vec()).unwrap();
            let mut engine = global_engine();
            engine.state = Some(state.clone());
            let inner = make_prover_pause_canonical();
            let message = if bundled { make_bundle(vec![inner]) } else {
                CanonicalMessageRequest::wrap(inner).unwrap().to_canonical_bytes().unwrap()
            };
            store.fail_vertex_reads(Some("removes"));
            assert!(engine.process_message(1, &BigInt::from(0), &domains::GLOBAL, &message)
                .unwrap_err().is_execution_unavailable());
            assert_eq!(state.changeset_len(), 2); // earlier checkpoint retained
            store.fail_vertex_reads(None);
            engine.process_message(1, &BigInt::from(0), &domains::GLOBAL, &message).unwrap();
            assert_eq!(state.changeset_len(), 0);
            crdt.commit(1).unwrap();
            let reopened = HypergraphState::new(Arc::new(HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver))));
            assert_eq!(reopened.get(&[7; 32], &[8; 32], &va).unwrap(), Some(b"vertex".to_vec()));
            assert_eq!(reopened.get(&[7; 32], &[9; 32], &ha).unwrap(), Some(b"edge".to_vec()));
        }
    }

    #[test]
    fn global_step_errors_rollback_and_distinguish_infrastructure() {
        use crate::hypergraph_state::{HypergraphState, vertex_adds_discriminator};
        use quil_hypergraph::{HypergraphCrdt, testing::MemStore};
        let state = HypergraphState::new(Arc::new(HypergraphCrdt::new(Arc::new(MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver))));
        let va = vertex_adds_discriminator().unwrap();
        state.set(&[7; 32], &[8; 32], &va, 1, b"earlier".to_vec()).unwrap();
        let checkpoint = state.changeset_len();
        for unavailable in [false, true] {
            state.set(&[7; 32], &[9; 32], &va, 1, b"partial".to_vec()).unwrap();
            let error = if unavailable { QuilError::Store("temporarily unavailable".into()) }
                else { QuilError::InvalidArgument("rejected operation".into()) };
            let result = finish_global_step(&state, checkpoint, 0, error);
            assert_eq!(result.is_err(), unavailable);
            assert_eq!(state.changeset_len(), checkpoint);
            assert_eq!(state.get(&[7; 32], &[9; 32], &va).unwrap(), None);
        }
    }

    #[test]
    fn failed_token_publication_discards_attempt_before_reexecution() {
        use crate::hypergraph_state::{HypergraphState, vertex_adds_discriminator, hyperedge_adds_discriminator};
        use quil_hypergraph::{HypergraphCrdt, Location, testing::MemStore};
        let store = Arc::new(MemStore::new());
        let crdt = Arc::new(HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        let app = [7; 32]; let prior = [8; 32]; let first = [9; 32]; let second = [10; 32];
        let va = vertex_adds_discriminator().unwrap();
        let ha = hyperedge_adds_discriminator().unwrap();
        state.set(&app, &prior, &va, 1, b"prior".to_vec()).unwrap();
        let checkpoint = state.changeset_len();
        let execute = || {
            assert_eq!(state.get(&app, &first, &va).unwrap(), None);
            assert_eq!(state.get(&app, &second, &ha).unwrap(), None);
            state.set(&app, &first, &va, 1, b"first".to_vec()).unwrap();
            state.set(&app, &second, &ha, 1, b"second".to_vec()).unwrap();
        };
        execute();
        store.fail_vertex_reads(Some("removes"));
        assert!(publish_execution_changes(Some(&state), checkpoint).unwrap_err().is_execution_unavailable());
        assert_eq!(state.changeset_len(), checkpoint);
        store.fail_vertex_reads(None);
        assert_eq!(state.get(&app, &prior, &va).unwrap(), Some(b"prior".to_vec()));
        assert_eq!(crdt.get_vertex_data_checked(&Location { app_address: app, data_address: first }).unwrap(), None);
        execute();
        publish_execution_changes(Some(&state), checkpoint).unwrap();
        assert_eq!(state.changeset_len(), 0);
        crdt.commit(1).unwrap();
        let reopened = HypergraphState::new(Arc::new(HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver))));
        assert_eq!(reopened.get(&app, &prior, &va).unwrap(), Some(b"prior".to_vec()));
        assert_eq!(reopened.get(&app, &first, &va).unwrap(), Some(b"first".to_vec()));
        assert_eq!(reopened.get(&app, &second, &ha).unwrap(), Some(b"second".to_vec()));
    }

    #[test]
    fn token_bundle_rejection_discards_prior_steps_and_stops_execution() {
        let state = crate::hypergraph_state::HypergraphState::new(Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver))));
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        state.set(&[1; 32], &[2; 32], &disc, 1, vec![3]).unwrap();
        let checkpoint = state.changeset_len();
        let request = CanonicalMessageRequest::wrap(crate::token_engine::TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec()).unwrap();
        let bytes = make_bundle(vec![request.inner_bytes.clone(), request.inner_bytes.clone(), request.inner_bytes]);
        let bundle = CanonicalMessageBundle::from_canonical_bytes(&bytes).unwrap();
        for unavailable in [false, true] {
            let mut calls = 0;
            let result = run_token_bundle(Some(&state), &bundle, |_, _| {
                calls += 1;
                state.set(&[1; 32], &[4; 32], &disc, 1, vec![calls])?;
                if calls == 2 {
                    return Err(if unavailable { QuilError::ExecutionUnavailable("worker busy".into()) }
                        else { QuilError::InvalidArgument("operation rejected".into()) });
                }
                Ok(())
            });
            assert_eq!(result.unwrap_err().is_execution_unavailable(), unavailable);
            assert_eq!(calls, 2);
            assert_eq!(state.changeset_len(), checkpoint);
            assert!(state.get(&[1; 32], &[4; 32], &disc).unwrap().is_none());
            assert_eq!(state.get(&[1; 32], &[2; 32], &disc).unwrap(), Some(vec![3]));
        }
    }

    #[test]
    fn token_engine_reports_rejected_operation_to_frame_caller() {
        let state = Arc::new(crate::hypergraph_state::HypergraphState::new(Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver)))));
        let mut engine = token_engine_test(ExecutionMode::Application);
        engine.state = Some(state.clone());
        let mut unsupported = crate::token_engine::TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec();
        unsupported.extend_from_slice(b"QCT3");
        let request = CanonicalMessageRequest::wrap(unsupported.clone()).unwrap().to_canonical_bytes().unwrap();
        for bytes in [request, make_bundle(vec![unsupported])] {
            let error = engine.process_message(1, &BigInt::from(1), &domains::QUIL_TOKEN, &bytes).unwrap_err();
            assert!(!error.is_execution_unavailable());
            assert_eq!(state.changeset_len(), 0);
        }
    }

    #[test]
    fn unconfigured_token_engine_rejects_all_confidential_types_before_decoding() {
        use crate::token_engine::*;
        for (mode, stateful) in [
            (ExecutionMode::Application, false), (ExecutionMode::Application, true),
            (ExecutionMode::Global, false), (ExecutionMode::Global, true)] {
            let state = Arc::new(crate::hypergraph_state::HypergraphState::new(Arc::new(
                quil_hypergraph::HypergraphCrdt::new(
                    Arc::new(quil_hypergraph::testing::MemStore::new()),
                    Arc::new(quil_types::crypto::NoopInclusionProver)))));
            let mut engine = token_engine_test(mode);
            if stateful { engine.state = Some(state.clone()); }
            for tp in [TYPE_LATTICE_TRANSACTION, TYPE_LATTICE_MINT, TYPE_LATTICE_PENDING,
                TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SHIELD, TYPE_LATTICE_MINT_CLAIM] {
                for body in [b"QLCT".as_slice(), b"QCT3".as_slice(), b"".as_slice()] {
                    let mut inner = tp.to_be_bytes().to_vec();
                    inner.extend_from_slice(body);
                    let single = CanonicalMessageRequest::wrap(inner.clone()).unwrap().to_canonical_bytes().unwrap();
                    for message in [single, make_bundle(vec![inner])] {
                        for result in [engine.validate_message(1, &domains::QUIL_TOKEN, &message),
                            engine.process_message(1, &BigInt::from(1), &domains::QUIL_TOKEN, &message).map(|_| ())] {
                            assert!(matches!(result, Err(QuilError::InvalidArgument(ref reason))
                                if reason == "token proof verification is not configured"));
                        }
                        assert_eq!(state.changeset_len(), 0);
                    }
                }
            }
        }
    }

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

    /// A QUIL settlement pays for a hypergraph write end to end: the GLOBAL
    /// record proven at a certified root admits the bundle once, its marker
    /// blocks a replay, and the app's own write key cannot erase the marker.
    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn paid_hypergraph_bundle_consumes_its_settlement_once() {
        use crate::hypergraph_intrinsic::{
            vertex_add_domain_separator, vertex_add_signing_message, vertex_remove_domain_separator,
            vertex_remove_signing_message, HypergraphConfigResolver,
        };
        use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use crate::token_intrinsic::{settlement_claim::*, settlement_record::*};
        use quil_types::crypto::Signer;
        use quil_types::execution::FrameExecutionContext;
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};

        struct Resolver(Vec<u8>);
        impl HypergraphConfigResolver for Resolver {
            fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> { Some(self.0.clone()) }
        }
        let app = [0xAAu8; 32];
        let network = [1u8; 32];
        let signer = quil_crypto::FalconSigner::generate();
        let sign = |separator: Vec<u8>, message: Vec<u8>| signer.sign_with_domain(&[separator, message].concat(), &[]).unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let mut engine = HypergraphExecutionEngine::new_with_state(
            ExecutionMode::Application, crdt.clone(), Arc::new(Resolver(signer.public_key().to_vec())),
        );
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        engine.set_global_clock_store(clock.clone());

        // The consumer write: a signed vertex add, bound by the payer's context.
        let kp = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let field = crate::hypergraph_intrinsic::confidential::seal(b"paid", &kp.public, &[0x11; 32], &[0x22; 12]).unwrap();
        let chunks = vec![crate::hypergraph_intrinsic::confidential::encode(&field)];
        let data_address = vec![0xBBu8; 32];
        let add = crate::hypergraph_intrinsic::VertexAdd {
            domain: app.to_vec(), data_address: data_address.clone(),
            data: crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks(&chunks).unwrap(),
            signature: sign(vertex_add_domain_separator(&app).unwrap(),
                vertex_add_signing_message(&app, &data_address, &chunks).unwrap()),
        }.to_canonical_bytes().unwrap();
        let mut bundle = CanonicalMessageBundle {
            requests: vec![None, Some(CanonicalMessageRequest::wrap(add).unwrap())],
            timestamp: 7,
        };
        let context = bundle_context(&bundle).unwrap();
        let cost = request_cost(bundle.requests[1].as_ref().unwrap()).unwrap() + marker_record().unwrap().len() as u64;
        let settlement = u128::from(cost) * 3;

        // The GLOBAL record, certified at global frame 9.
        let entry = SettlementEntry {
            receipt: [0x5E; 32],
            parameter_context: quil_lattice_ct::confidential::transfer::parameter_context(&network, &crate::domains::QUIL_TOKEN),
            destination: app, context, settlement, payment_address: [0; 32], payment: 0, claimant: [0; 32],
        };
        let blob = create_record(&entry).unwrap();
        let forest = quil_forest::Forest::in_memory();
        let root = forest.commit_shard_phase_raw(b"settlement-test", quil_forest::Phase::VertexAdds, 0,
            [(entry.receipt.to_vec(), quil_tries::vertex_leaf_value(&blob).unwrap())]).unwrap();
        let address = [crate::domains::GLOBAL.to_vec(), entry.receipt.to_vec()].concat();
        let membership = forest.build_vertex_membership_proof(b"settlement-test", quil_forest::Phase::VertexAdds, 0, &address, &blob).unwrap();
        let proof = quil_forest::MembershipProof { inputs: vec![membership] }.to_bytes();
        clock.seed_frame(GlobalFrame {
            header: Some(GlobalFrameHeader { frame_number: 9, prover_tree_commitment: root.to_vec(), ..Default::default() }),
            ..Default::default()
        });
        let claim = SettlementClaim {
            network, application: app, cited_global_frame: 9, global_root: root, receipt: entry.receipt,
            settlement, context, payment_address: [0; 32], payment: 0, forest_proof: proof,
            claimant_key_type: 0, claimant_public_key: Vec::new(), claimant_signature: Vec::new(),
        };
        bundle.requests[0] = Some(CanonicalMessageRequest::wrap(claim.encode().unwrap()).unwrap());
        let bytes = bundle.to_canonical_bytes().unwrap();
        let context_at = |anchor| FrameExecutionContext { frame_number: 10, finalized_global_frame: Some(anchor), venue: None, shard: quil_types::execution::ShardPath::WHOLE };
        let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let view = crate::hypergraph_state::HypergraphState::new(crdt.clone());
        let marker = consumption_marker(&app, &entry.receipt).unwrap();

        // Underpaid at this price, or citing past the anchor: nothing lands.
        assert!(engine.process_message_with_context(context_at(9), &BigInt::from(4), &app, &bytes).is_err());
        assert!(engine.process_message_with_context(context_at(8), &BigInt::from(3), &app, &bytes).is_err());
        assert!(view.get(&app, &marker, &disc).unwrap().is_none());
        // A claim for another destination (same record) is refused.
        let mut other = bundle.clone();
        other.requests[0] = Some(CanonicalMessageRequest::wrap(SettlementClaim { application: [0xAB; 32], ..claim.clone() }.encode().unwrap()).unwrap());
        assert!(engine.process_message_with_context(context_at(9), &BigInt::from(3), &[0xAB; 32], &other.to_canonical_bytes().unwrap()).is_err());

        // Paid: the write and the consumption marker land together.
        engine.process_message_with_context(context_at(9), &BigInt::from(3), &app, &bytes).unwrap();
        assert!(view.get(&app, &data_address, &disc).unwrap().is_some());
        assert!(is_consumption_marker(&view.get(&app, &marker, &disc).unwrap().unwrap()));
        assert_eq!(message_settlement_amount(&bytes), settlement);

        // The record funds one bundle only.
        let replay = engine.process_message_with_context(context_at(9), &BigInt::from(3), &app, &bytes).unwrap_err();
        assert!(replay.to_string().contains("already consumed"), "{replay}");

        // The app's write key cannot remove the marker to reuse the record.
        let remove = crate::hypergraph_intrinsic::VertexRemove {
            domain: app.to_vec(), data_address: marker.to_vec(),
            signature: sign(vertex_remove_domain_separator(&app).unwrap(), vertex_remove_signing_message(&app, &marker).unwrap()),
        }.to_canonical_bytes().unwrap();
        let remove = CanonicalMessageRequest::wrap(remove).unwrap().to_canonical_bytes().unwrap();
        let error = engine.process_message_with_context(context_at(9), &BigInt::from(0), &app, &remove).unwrap_err();
        assert!(error.to_string().contains("consumption marker"), "{error}");
        assert!(is_consumption_marker(&view.get(&app, &marker, &disc).unwrap().unwrap()));

        // A second write, funded by a settlement paid before this bundle
        // existed: its record names the payer's claimant key, and the claim
        // carries that key's signature over the bundle instead of a context.
        let second_address = vec![0xCCu8; 32];
        let second_add = crate::hypergraph_intrinsic::VertexAdd {
            domain: app.to_vec(), data_address: second_address.clone(),
            data: crate::hypergraph_intrinsic::conversions::pack_vertex_add_proof_chunks(&chunks).unwrap(),
            signature: sign(vertex_add_domain_separator(&app).unwrap(),
                vertex_add_signing_message(&app, &second_address, &chunks).unwrap()),
        }.to_canonical_bytes().unwrap();
        let mut second = CanonicalMessageBundle {
            requests: vec![None, Some(CanonicalMessageRequest::wrap(second_add).unwrap())],
            timestamp: 11,
        };
        let second_context = bundle_context(&second).unwrap();
        let claimant = quil_crypto::FalconSigner::generate();
        let claimant_key = claimant.public_key().to_vec();
        let prefunded_entry = SettlementEntry {
            receipt: [0x5F; 32], context: [0; 32],
            claimant: crate::token_intrinsic::settlement_record::claimant_address(
                quil_types::crypto::KeyType::Falcon512 as u32, &claimant_key).unwrap(),
            ..entry
        };
        let blob = create_record(&prefunded_entry).unwrap();
        let root = forest.commit_shard_phase_raw(b"prefunded-test", quil_forest::Phase::VertexAdds, 0,
            [(prefunded_entry.receipt.to_vec(), quil_tries::vertex_leaf_value(&blob).unwrap())]).unwrap();
        let address = [crate::domains::GLOBAL.to_vec(), prefunded_entry.receipt.to_vec()].concat();
        let membership = forest.build_vertex_membership_proof(b"prefunded-test", quil_forest::Phase::VertexAdds, 0, &address, &blob).unwrap();
        clock.seed_frame(GlobalFrame {
            header: Some(GlobalFrameHeader { frame_number: 9, prover_tree_commitment: root.to_vec(), ..Default::default() }),
            ..Default::default()
        });
        let prefunded_proof = quil_forest::MembershipProof { inputs: vec![membership] }.to_bytes();
        let prefunded_claim = |context: &[u8; 32]| SettlementClaim {
            network, application: app, cited_global_frame: 9, global_root: root, receipt: prefunded_entry.receipt,
            settlement, context: [0; 32], payment_address: [0; 32], payment: 0,
            claimant_key_type: quil_types::crypto::KeyType::Falcon512 as u32,
            claimant_public_key: claimant_key.clone(),
            claimant_signature: claimant.sign_with_domain(
                &crate::token_intrinsic::settlement_claim::claimant_message(&network, &app, &prefunded_entry.receipt, context),
                &quil_lattice_ct::confidential::transfer::parameter_context(&network, &app)).unwrap(),
            forest_proof: prefunded_proof.clone(),
        };
        // A signature over another bundle does not authorize this one.
        let mut wrong = second.clone();
        wrong.requests[0] = Some(CanonicalMessageRequest::wrap(prefunded_claim(&context).encode().unwrap()).unwrap());
        let error = engine.process_message_with_context(context_at(9), &BigInt::from(3), &app, &wrong.to_canonical_bytes().unwrap()).unwrap_err();
        assert!(error.to_string().contains("claimant did not authorize"), "{error}");
        second.requests[0] = Some(CanonicalMessageRequest::wrap(prefunded_claim(&second_context).encode().unwrap()).unwrap());
        let second_bytes = second.to_canonical_bytes().unwrap();
        engine.process_message_with_context(context_at(9), &BigInt::from(3), &app, &second_bytes).unwrap();
        assert!(view.get(&app, &second_address, &disc).unwrap().is_some());
        let prefunded_marker = consumption_marker(&app, &prefunded_entry.receipt).unwrap();
        assert!(is_consumption_marker(&view.get(&app, &prefunded_marker, &disc).unwrap().unwrap()));
        // And it funds that one bundle only, like any other settlement.
        let replay = engine.process_message_with_context(context_at(9), &BigInt::from(3), &app, &second_bytes).unwrap_err();
        assert!(replay.to_string().contains("already consumed"), "{replay}");
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
        // Single requests are processed (materialization skipped without state)
        // when free; at a nonzero price the unpaid write is refused.
        assert!(e.process_message(1, &BigInt::from(0), &[0u8; 32], &req).is_ok());
        #[cfg(feature = "confidential-tokens")]
        assert!(e.process_message(1, &BigInt::from(1), &[0u8; 32], &req).unwrap_err().to_string().contains("settlement claim"));
    }

    #[test]
    fn hypergraph_engine_process_accepts_bundle() {
        let e = HypergraphExecutionEngine::new(ExecutionMode::Application, std::sync::Arc::new(crate::testing::NoopHypergraphConfigResolver));
        let bundle = make_bundle(vec![
            make_vertex_add_canonical(),
            make_vertex_remove_canonical(),
        ]);
        let r = e
            .process_message(1, &BigInt::from(0), &[0u8; 32], &bundle)
            .unwrap();
        assert!(r.messages.is_empty());
        #[cfg(feature = "confidential-tokens")]
        assert!(e.process_message(1, &BigInt::from(1), &[0u8; 32], &bundle).is_err());
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

}
