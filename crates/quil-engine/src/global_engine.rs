use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{debug, info, warn};

use quil_types::consensus::{
    DifficultyAdjuster, DynamicFeeManager, EventDistributor, ProverRegistry,
    RewardIssuance, SignerRegistry,
};
use quil_types::crypto::{FrameProver, InclusionProver};
use quil_types::error::{QuilError, Result};
use quil_types::store::{ClockStore, HypergraphStore, ShardsStore};

use quil_execution::ExecutionEngineManager;
use quil_keys::KeyManager;

use crate::consensus_activation::{self, ConsensusActivationParams};
use crate::consensus_glue::ConsensusPublisher;
use crate::consensus_types::GlobalEventLoopHandle;
use crate::frame_materializer::FrameMaterializer;
use crate::message_collector::MessageCollector;
use crate::message_router::{self, MessageRoute};
use crate::worker_allocator::WorkerAllocator;

/// The global consensus engine: orchestrates consensus, execution, storage,
/// and networking for the global frame chain.
pub struct GlobalConsensusEngine {
    // -- Core dependencies --
    pub clock_store: Arc<dyn ClockStore>,
    pub hypergraph_store: Arc<dyn HypergraphStore>,
    pub shards_store: Arc<dyn ShardsStore>,

    // -- Crypto --
    pub frame_prover: Arc<dyn FrameProver>,
    pub inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
    pub key_manager: Arc<dyn KeyManager>,

    // -- Consensus sub-components --
    pub signer_registry: Arc<dyn SignerRegistry>,
    pub prover_registry: Arc<dyn ProverRegistry>,
    pub difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
    pub reward_issuance: Arc<dyn RewardIssuance>,
    pub fee_manager: Arc<dyn DynamicFeeManager>,
    pub event_distributor: Arc<dyn EventDistributor>,

    // -- Execution --
    pub execution_manager: Arc<ExecutionEngineManager>,

    // -- Materializer --
    pub materializer: Option<Arc<FrameMaterializer>>,

    // -- Consensus event loop --
    consensus_handle: Mutex<Option<GlobalEventLoopHandle>>,

    // -- Message collection --
    pub message_collector: Arc<MessageCollector>,

    // -- Worker allocation --
    pub worker_allocator: Option<Arc<WorkerAllocator>>,

    // -- State --
    pub prover_address: Vec<u8>,
    pub last_observed_frame: AtomicU64,
    pub current_difficulty: std::sync::atomic::AtomicU32,
    pub archive_mode: bool,
}

impl GlobalConsensusEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock_store: Arc<dyn ClockStore>,
        hypergraph_store: Arc<dyn HypergraphStore>,
        shards_store: Arc<dyn ShardsStore>,
        frame_prover: Arc<dyn FrameProver>,
        inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
        key_manager: Arc<dyn KeyManager>,
        signer_registry: Arc<dyn SignerRegistry>,
        prover_registry: Arc<dyn ProverRegistry>,
        difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
        reward_issuance: Arc<dyn RewardIssuance>,
        fee_manager: Arc<dyn DynamicFeeManager>,
        event_distributor: Arc<dyn EventDistributor>,
        execution_manager: Arc<ExecutionEngineManager>,
        prover_address: Vec<u8>,
        archive_mode: bool,
    ) -> Self {
        Self {
            clock_store,
            hypergraph_store,
            shards_store,
            frame_prover,
            inclusion_prover,
            key_manager,
            signer_registry,
            prover_registry,
            difficulty_adjuster,
            reward_issuance,
            fee_manager,
            event_distributor,
            execution_manager,
            materializer: None,
            consensus_handle: Mutex::new(None),
            message_collector: Arc::new(MessageCollector::new()),
            worker_allocator: None,
            prover_address,
            last_observed_frame: AtomicU64::new(0),
            current_difficulty: std::sync::atomic::AtomicU32::new(0),
            archive_mode,
        }
    }

    /// Set the frame materializer. Must be called before `on_new_frame`.
    /// The materializer requires a `HypergraphCrdt` which is constructed
    /// externally, so this is wired after `new()`.
    pub fn with_materializer(mut self, materializer: Arc<FrameMaterializer>) -> Self {
        self.materializer = Some(materializer);
        self
    }

    /// Set the worker allocator. Optional -- only needed on nodes that
    /// run shard workers.
    pub fn with_worker_allocator(mut self, allocator: Arc<WorkerAllocator>) -> Self {
        self.worker_allocator = Some(allocator);
        self
    }

    /// Set the message collector (replaces the default empty one).
    pub fn with_message_collector(mut self, collector: Arc<MessageCollector>) -> Self {
        self.message_collector = collector;
        self
    }

    // -----------------------------------------------------------------
    // Consensus lifecycle
    // -----------------------------------------------------------------

    /// Start the consensus event loop. Calls `activate_consensus()`
    /// with this engine's dependencies and stores the returned handle
    /// for message routing.
    ///
    /// # Arguments
    /// * `genesis_frame` - The frame to bootstrap consensus from
    ///   (latest finalized or actual genesis).
    /// * `bls_signer` - BLS48-581 signer for producing votes/timeouts.
    /// * `publisher` - Optional publisher for broadcasting consensus
    ///   messages to the network via BlossomSub.
    ///
    /// Returns the event loop handle. The handle is also stored
    /// internally so that `handle_incoming_message` can route
    /// consensus messages to it.
    pub fn start_consensus_loop(
        &self,
        genesis_frame: quil_types::proto::global::GlobalFrame,
        bls_signer: Box<dyn quil_types::crypto::Signer>,
        publisher: Option<Arc<dyn ConsensusPublisher>>,
    ) -> Result<GlobalEventLoopHandle> {
        // Derive the local BLS public key from the signer.
        let local_bls_pubkey = bls_signer.public_key().to_vec();

        let params = ConsensusActivationParams {
            prover_registry: Arc::clone(&self.prover_registry),
            frame_prover: Arc::clone(&self.frame_prover),
            difficulty_adjuster: Arc::clone(&self.difficulty_adjuster),
            clock_store: Arc::clone(&self.clock_store),
            message_collector: Arc::clone(&self.message_collector),
            local_prover_address: self.prover_address.clone(),
            local_bls_pubkey,
            bls_signer,
            inclusion_prover: Arc::clone(&self.inclusion_prover),
            genesis_frame,
            publisher,
            on_finalized_state: None,
            on_incorporated_state: None,
            on_qc_observed: None,
            config_override: None,
            genesis_qc_override: None,
            kv_db: None,
        };

        let activation = consensus_activation::activate_consensus(params)?;
        let handle = activation.handle;

        // Drive the event loop. NOTE: this uses bare `tokio::spawn` —
        // a panic inside `run_future` will print to stderr and leave
        // this engine's handle pointing at a dead task. Production
        // callers (master_node) should bypass this convenience method
        // and register `activation.run_future` directly with the
        // process supervisor so panics surface as `JoinError`.
        tokio::spawn(activation.run_future);

        // Store for message routing.
        *self.consensus_handle.lock().unwrap() = Some(handle.clone());

        info!("consensus loop started and handle stored");
        Ok(handle)
    }

    /// Get a clone of the consensus handle, if the loop has been started.
    pub fn consensus_handle(&self) -> Option<GlobalEventLoopHandle> {
        self.consensus_handle.lock().unwrap().clone()
    }

    // -----------------------------------------------------------------
    // Frame processing
    // -----------------------------------------------------------------

    /// Called when a new finalized global frame arrives (from the
    /// network or produced locally). This is the main entry point for
    /// frame processing.
    ///
    /// Steps:
    /// 1. Delegates to `FrameMaterializer::materialize` for execution,
    ///    prover root verification, eviction, etc.
    /// 2. Updates `last_observed_frame` and `current_difficulty`.
    /// 3. Triggers worker allocator reconciliation.
    pub fn on_new_frame(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
    ) -> Result<()> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame has no header".into()))?;
        let frame_number = header.frame_number;

        // 1. Materialize through the FrameMaterializer if available.
        if let Some(ref mat) = self.materializer {
            let result = mat.materialize(frame)?;
            info!(
                frame = frame_number,
                processed = result.processed,
                skipped = result.skipped,
                root_ok = result.prover_root_matched,
                "frame materialized via materializer"
            );
        } else {
            // Fallback: process messages directly through execution manager
            // (legacy path for tests or nodes without full materializer).
            let fee_multiplier = num_bigint::BigInt::from(1);
            let mut messages = Vec::new();
            for bundle in &frame.requests {
                let bundle_bytes = prost::Message::encode_to_vec(bundle);
                let address = vec![0xFFu8; 32];
                messages.push((address, bundle_bytes));
            }
            let processed = self.materialize_frame(
                frame_number,
                &fee_multiplier,
                &messages,
            )?;
            debug!(frame = frame_number, processed, "frame materialized (legacy path)");
        }

        // 2. Update observed frame and difficulty.
        self.last_observed_frame.store(frame_number, Ordering::SeqCst);
        self.current_difficulty.store(header.difficulty, Ordering::Relaxed);

        // 3. Reconcile worker allocations.
        if let Some(ref wa) = self.worker_allocator {
            if let Err(e) = wa.on_new_frame(frame_number) {
                warn!(
                    frame = frame_number,
                    error = %e,
                    "worker allocator reconciliation failed"
                );
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    // Message routing
    // -----------------------------------------------------------------

    /// Route an incoming network message to the appropriate handler.
    ///
    /// Uses `message_router::classify_message` to determine the message
    /// type, then dispatches:
    /// - Consensus messages (proposals, QCs, TCs) -> event loop handle
    /// - Prover/shard messages -> message collector (buffered for
    ///   inclusion in the next frame proposal)
    /// - Frame messages -> deserialized and passed to `on_new_frame`
    /// - Bundles -> individual entries extracted and re-routed
    ///
    /// Returns `Ok(())` on successful routing. Unrecognized messages
    /// are logged and dropped (not an error -- the network is noisy).
    pub fn handle_incoming_message(&self, data: &[u8]) -> Result<()> {
        let route = message_router::classify_message(data)?;

        match route {
            MessageRoute::Consensus => {
                self.route_consensus_message(data)
            }
            MessageRoute::GlobalProverOp
            | MessageRoute::ShardManagement
            | MessageRoute::HypergraphOp
            | MessageRoute::AppShardOp => {
                // Buffer for inclusion in the next proposal.
                let rank = self.current_consensus_rank();
                if !self.message_collector.add_message(rank, data.to_vec()) {
                    debug!(
                        route = ?route,
                        "message rejected by collector (duplicate or truncated)"
                    );
                }
                Ok(())
            }
            MessageRoute::Bundle => {
                // A bundle wraps multiple messages. Decode and re-route
                // each inner message individually.
                self.route_bundle(data)
            }
            MessageRoute::Unknown => {
                debug!(
                    prefix = hex::encode(&data[..std::cmp::min(4, data.len())]),
                    "dropping unknown message type"
                );
                Ok(())
            }
        }
    }

    /// Route a consensus-protocol message to the event loop handle.
    ///
    /// Wire-format QCs/TCs (canonical bytes) are decoded and converted
    /// to trait objects via `consensus_wire_adapter`. Proposals and
    /// votes are decoded and submitted through the event loop handle.
    /// Frame-carrying proposals are additionally routed through
    /// `on_new_frame`.
    fn route_consensus_message(&self, data: &[u8]) -> Result<()> {
        // Determine the consensus sub-type from the 4-byte prefix.
        if data.len() < 4 {
            return Err(QuilError::InvalidArgument("consensus message too short".into()));
        }
        let tp = u32::from_be_bytes(data[..4].try_into().unwrap());

        use crate::consensus_wire;
        match tp {
            consensus_wire::QUORUM_CERTIFICATE_TYPE => {
                let guard = self.consensus_handle.lock().unwrap();
                let Some(ref handle) = *guard else {
                    debug!("QC received before loop started, dropping");
                    return Ok(());
                };
                match consensus_wire::QuorumCertificate::from_canonical_bytes(data) {
                    Ok(wire_qc) => {
                        let rank = wire_qc.rank;
                        let trait_qc = wire_qc.into_trait_object();
                        handle.submit_quorum_certificate(trait_qc);
                        debug!(rank, "routed QC to consensus loop");
                    }
                    Err(e) => {
                        debug!(error = %e, "failed to decode QC, dropping");
                    }
                }
            }
            consensus_wire::TIMEOUT_CERTIFICATE_TYPE => {
                let guard = self.consensus_handle.lock().unwrap();
                let Some(ref handle) = *guard else {
                    debug!("TC received before loop started, dropping");
                    return Ok(());
                };
                match consensus_wire::TimeoutCertificate::from_canonical_bytes(data) {
                    Ok(wire_tc) => {
                        let trait_tc = wire_tc.into_trait_object();
                        handle.submit_timeout_certificate(trait_tc);
                        debug!("routed TC to consensus loop");
                    }
                    Err(e) => {
                        debug!(error = %e, "failed to decode TC, dropping");
                    }
                }
            }
            consensus_wire::PROPOSAL_VOTE_TYPE
            | consensus_wire::TIMEOUT_STATE_TYPE => {
                // Votes and timeout-states are collected for the
                // timeout/vote aggregator. Buffer them in the
                // message collector so the leader can include
                // them in proposals.
                let rank = self.current_consensus_rank();
                self.message_collector.add_message(rank, data.to_vec());
            }
            consensus_wire::GLOBAL_PROPOSAL_TYPE
            | consensus_wire::GLOBAL_FRAME_TYPE => {
                // A full frame arriving on the consensus bitmask --
                // this is a proposal that carries a GlobalFrame.
                // Decode it and process as a new frame.
                self.route_frame_from_wire(data)?;
            }
            _ => {
                debug!(tp, "unrecognized consensus sub-type, dropping");
            }
        }
        Ok(())
    }

    /// Decode a GlobalFrame from wire bytes and process via on_new_frame.
    fn route_frame_from_wire(&self, data: &[u8]) -> Result<()> {
        // Skip the 4-byte type prefix and decode as proto GlobalFrame.
        if data.len() <= 4 {
            return Err(QuilError::InvalidArgument("frame message too short".into()));
        }
        let frame: quil_types::proto::global::GlobalFrame =
            prost::Message::decode(&data[4..])
                .map_err(|e| QuilError::InvalidArgument(format!("bad frame proto: {}", e)))?;
        self.on_new_frame(&frame)
    }

    /// Route a bundle by decoding and re-routing each inner message.
    fn route_bundle(&self, data: &[u8]) -> Result<()> {
        use quil_execution::message_envelope::CanonicalMessageBundle;

        match CanonicalMessageBundle::from_canonical_bytes(data) {
            Ok(bundle) => {
                for maybe_req in &bundle.requests {
                    if let Some(ref req) = maybe_req {
                        if let Err(e) = self.handle_incoming_message(&req.inner_bytes) {
                            debug!(error = %e, "bundle inner message routing failed");
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                debug!(error = %e, "failed to decode message bundle");
                Ok(())
            }
        }
    }

    /// The current consensus rank (from the event loop handle, or
    /// approximated from last_observed_frame + 1).
    fn current_consensus_rank(&self) -> u64 {
        // The collector buffers messages by rank. We use
        // last_observed_frame + 1 as a reasonable approximation
        // when the consensus handle isn't available yet.
        self.last_observed_frame.load(Ordering::SeqCst) + 1
    }

    // -----------------------------------------------------------------
    // Legacy direct-execution path
    // -----------------------------------------------------------------

    /// Process all messages in a frame through the execution manager.
    /// Each entry is (address, canonical_message_bytes).
    /// Returns the number of successfully processed messages.
    pub fn materialize_frame(
        &self,
        frame_number: u64,
        fee_multiplier: &num_bigint::BigInt,
        messages: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<usize> {
        let mut processed = 0;
        for (address, message) in messages {
            // Validate before processing. Per-op Verify hooks re-run
            // structural + signature checks; skipping validate would
            // let the materialize path silently accept unsigned /
            // spoofed join/kick/seniority/shard/frame_header messages.
            if let Err(e) = self.execution_manager.validate_message(
                frame_number,
                address,
                message,
            ) {
                warn!(
                    frame = frame_number,
                    error = %e,
                    "rejecting message that failed validation"
                );
                continue;
            }
            match self.execution_manager.process_message(
                frame_number,
                fee_multiplier,
                address,
                message,
            ) {
                Ok(_) => processed += 1,
                Err(e) => {
                    warn!(
                        frame = frame_number,
                        error = %e,
                        "skipping message that failed processing"
                    );
                }
            }
        }
        Ok(processed)
    }
}

/// Standalone function: process a batch of (address, message) pairs
/// through an execution manager. Doesn't need the full
/// GlobalConsensusEngine — useful for testing and replay.
pub fn process_message_batch(
    execution_manager: &ExecutionEngineManager,
    frame_number: u64,
    fee_multiplier: &num_bigint::BigInt,
    messages: &[(Vec<u8>, Vec<u8>)],
) -> quil_types::error::Result<usize> {
    let mut processed = 0;
    for (address, message) in messages {
        // Validate before processing.
        if let Err(e) = execution_manager.validate_message(
            frame_number,
            address,
            message,
        ) {
            tracing::debug!(error = %e, "rejecting message that failed validation");
            continue;
        }
        match execution_manager.process_message(
            frame_number,
            fee_multiplier,
            address,
            message,
        ) {
            Ok(_) => processed += 1,
            Err(e) => {
                tracing::debug!(error = %e, "skipping failed message");
            }
        }
    }
    Ok(processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::message_envelope::{
        CanonicalMessageBundle, CanonicalMessageRequest,
    };
    use quil_hypergraph::testing::MemStore;
    use quil_types::crypto::{InclusionProver, NoopInclusionProver};

    fn build_manager() -> ExecutionEngineManager {
        let inclusion_prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
        let hg_store: Arc<dyn quil_types::store::HypergraphStore> =
            Arc::new(MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            inclusion_prover.clone(),
        ));
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let hg_resolver: Arc<dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver> =
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
        ExecutionEngineManager::new(
            inclusion_prover,
            stubs.key_manager.clone(),
            crdt,
            stubs.bulletproof_prover,
            stubs.decaf_constructor,
            stubs.circuit_compiler,
            stubs.clock_store,
            hg_resolver,
            true,
        )
    }

    #[test]
    fn process_batch_empty_returns_zero() {
        let mgr = build_manager();
        let n = process_message_batch(&mgr, 1, &num_bigint::BigInt::from(1), &[]).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn process_batch_routes_global_prover_pause_bundle() {
        let mgr = build_manager();
        let inner = quil_execution::global_intrinsic::ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 42,
            public_key_signature_bls48581: Some(
                quil_execution::global_intrinsic::AddressedSignature {
                    signature: vec![0xBBu8; 74],
                    address: vec![0xCCu8; 32],
                },
            ),
        }
        .to_canonical_bytes()
        .unwrap();

        let bundle = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(inner).unwrap())],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();

        let global_addr = vec![0xFFu8; 32];
        let n = process_message_batch(
            &mgr, 1, &num_bigint::BigInt::from(1),
            &[(global_addr, bundle)],
        ).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn process_batch_rejects_hypergraph_vertex_add_with_unknown_domain() {
        // With a noop config resolver the hypergraph engine cannot
        // resolve the Ed448 WritePublicKey for the target domain, so
        // verify returns AuthCheck::UnknownDomain and the message is
        // rejected at validate time.
        let mgr = build_manager();
        let inner = quil_execution::hypergraph_intrinsic::VertexAdd {
            domain: vec![0x11u8; 32],
            data_address: vec![0x22u8; 32],
            data: quil_execution::hypergraph_intrinsic::pack_vertex_add_proof_chunks(
                &[vec![0x33u8; 16]],
            ).unwrap(),
            signature: vec![0x44u8; 114],
        }
        .to_canonical_bytes()
        .unwrap();

        let bundle = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(inner).unwrap())],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();

        let hg_addr = vec![0x42u8; 32];
        let n = process_message_batch(
            &mgr, 1, &num_bigint::BigInt::from(1),
            &[(hg_addr, bundle)],
        ).unwrap();
        assert_eq!(n, 0, "expected unverified hypergraph op to be rejected");
    }

    #[test]
    fn process_batch_handles_short_messages_without_panic() {
        let mgr = build_manager();
        let global_addr = vec![0xFFu8; 32];
        // Short messages are treated as no-ops (Ok with empty result)
        // by engines that have an early-return for len < 4.
        let result = process_message_batch(
            &mgr, 1, &num_bigint::BigInt::from(1),
            &[(global_addr, vec![0u8; 2])],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn process_batch_routes_invalid_type_prefix_gracefully() {
        let mgr = build_manager();
        let global_addr = vec![0xFFu8; 32];
        // A message with a valid length but unknown type prefix →
        // the engine will attempt to decode and fail.
        let bad_msg = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let n = process_message_batch(
            &mgr, 1, &num_bigint::BigInt::from(1),
            &[(global_addr, bad_msg)],
        ).unwrap();
        assert_eq!(n, 0); // rejected by engine
    }
}
