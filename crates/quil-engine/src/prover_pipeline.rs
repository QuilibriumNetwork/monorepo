//! End-to-end submission pipeline for prover lifecycle actions.
//!
//! The lifecycle evaluator produces abstract `LifecycleAction`s; this
//! module turns them into signed canonical-bytes messages wrapped in a
//! `MessageBundle` and submits them via a pluggable
//! [`ProverMessageTransport`] (gRPC fan-out + BlossomSub in production,
//! a single in-memory broadcast in tests).
//!
//! Mirrors Go's `publishProverMessage` at
//! `node/consensus/global/global_consensus_engine.go:154-159`.

use std::sync::Arc;

use tracing::{debug, info, warn};

use quil_execution::global_intrinsic::{
    addressed_signature::AddressedSignature,
    prover_filter_ops::ProverLeave,
    prover_join::ProverJoin,
    prover_ops::{ProverConfirm, ProverReject, ShardMerge, ShardSplit},
    sig_with_pop::SignatureWithPop,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_types::crypto::{FrameProver, Signer};
use quil_types::error::{QuilError, Result};

use crate::provers::lifecycle::{LifecycleAction, ProverLifecycle};
use crate::worker::WorkerManager;
use crate::prover_message_transport::ProverMessageTransport;
use crate::message_collector::{MessageCollector, SubmitOutcome};
use crate::current_frame::CurrentFrame;

/// End-to-end submission pipeline for prover lifecycle actions.
///
/// Owns no transport details — the caller injects an
/// [`Arc<dyn ProverMessageTransport>`] that knows how to ship a
/// `CanonicalMessageBundle` on `GLOBAL_PROVER` (production: gRPC
/// fan-out + BlossomSub; tests: in-memory network).
pub struct ProverPipeline {
    pub lifecycle: Arc<ProverLifecycle>,
    pub worker_manager: Arc<dyn WorkerManager>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
    /// Ed448 seeds loaded from `config.engine.multisig_prover_enrollment_paths`
    /// plus the local peer's own Ed448 seed, used to build merge
    /// helpers for `ProverSeniorityMerge`. Each seed signs the local
    /// BLS prover pubkey with the `PROVER_SENIORITY_MERGE` domain so
    /// on-chain materialization can attribute historical seniority
    /// from the old peer keys.
    pub multisig_ed448_seeds: Vec<[u8; 57]>,
    /// Optional delegate address for ProverJoin emissions. Mirrors Go's
    /// `config.Engine.DelegateAddress` at
    /// `node/consensus/global/worker_allocator.go:1483-1490` —
    /// hex-decoded when set, empty `Vec::new()` when unset. Empty is
    /// the default and is functionally equivalent to "delegate ==
    /// prover_address" inside the materializer (the join handler
    /// substitutes `prover_address` when `len(DelegateAddress) != 32`),
    /// but the canonical-bytes wire form differs — preserve byte-level
    /// parity with default Go nodes by leaving this empty unless the
    /// operator explicitly configured a delegate.
    pub delegate_address: Vec<u8>,
    /// Transport used to ship outbound `MessageBundle` bytes on
    /// `GLOBAL_PROVER` and to fetch the latest frame header for VDF
    /// challenge derivation in [`Self::submit_join`].
    pub transport: Arc<dyn ProverMessageTransport>,
    /// Live hypergraph CRDT — read by the storage-attestation confirm hook
    /// (`submit_confirm`) to partition each confirmed shard's committed
    /// subtree into PoRep leaves. Required for data-shard confirmations.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Replica store the confirm hook persists per-leaf SDR replicas into
    /// (keyed by `(epoch, leaf_id)`), so the per-frame producer can later
    /// answer openings. Required for data-shard confirmations.
    pub replica_store: Option<quil_store::replica_store::ReplicaStore>,
    /// Per-shard storage: the hypergraph and replica store of the worker that
    /// holds and attests a shard, when it is not the node's own (a thread
    /// worker opens its own database). Confirmation must encode the same data
    /// into the same replica store the attesting worker proves from, or the
    /// registered leaf roots diverge from its attestations once the shard's
    /// data changes and every storage frame is rejected.
    pub storage_for_filter: Option<std::sync::Arc<
        dyn Fn(&[u8]) -> Option<(std::sync::Arc<quil_hypergraph::HypergraphCrdt>, quil_store::replica_store::ReplicaStore)>
            + Send + Sync,
    >>,
    /// Leaf roots prepared by the standalone (cluster-mode) worker serving a
    /// filter, from its own store: `Ok(None)` when no such worker serves it.
    /// Called from a blocking task. Without it the master encoded from its
    /// own store, which lacks the shard's data, and the worker's attestations
    /// were rejected for leaves it could never prove.
    pub remote_storage_confirm: Option<RemoteStorageConfirm>,
    /// Splits and merges this node has recorded but not applied. A confirm in
    /// the epoch before one applies also registers the shards it creates from
    /// the confirmed ones (see `pre_registration_targets`).
    pub pending_shard_changes: Option<std::sync::Arc<
        dyn Fn() -> Vec<quil_types::store::PendingShardChange> + Send + Sync,
    >>,
    /// Local global-message collector, for LOOPBACK of ops this node generates
    /// for ITSELF (ShardSplit/ShardMerge from the coverage orchestrator, which
    /// runs on the frame producer). A producer must include its own generated op
    /// in the frame it builds; the network publish only reaches OTHER nodes, so
    /// on a single-archive network (no other archive to accept, gossipsub won't
    /// self-loopback) the op would otherwise never land. Loop it into the same
    /// collector the gRPC/gossip ingest feeds. `None` disables loopback (tests).
    pub local_message_collector: Option<Arc<MessageCollector>>,
    /// Current-frame tracker, used to tag looped-back ops with the CONSENSUS RANK
    /// (`effective_rank()`) exactly as the gRPC ingest does (grpc.rs:400) so the
    /// leader's `collect_for_rank` picks them up. `None` disables loopback.
    pub current_frame: Option<Arc<CurrentFrame>>,
}

pub type RemoteStorageConfirm = std::sync::Arc<
    dyn Fn(&[u8], &[Vec<u8>], u64) -> Result<Option<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>>>
        + Send + Sync,
>;

/// Hard ceiling on lifecycle submissions that do NOT perform VDF
/// compute (confirms, rejects, leaves, seniority merge). Each of
/// these is sign + canonicalize + publish; the only legitimately
/// slow piece is the gRPC fan-out, which has its own per-archive
/// timeout in the transport. 30s is well above the worst case but
/// bounds the spawned task so a transport bug, runtime starvation,
/// or stuck publish can't silently wedge a dispatch forever.
const NON_VDF_SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a confirm encodes, per confirmed filter: the filter, from its own
/// storage, then the shards a split or merge applying at `epoch` creates from
/// it (see `pre_registration_targets`). A merge target two confirmed sources
/// share is encoded once, from the first.
fn confirm_encoding_plan(
    filters: &[Vec<u8>],
    changes: &[quil_types::store::PendingShardChange],
    epoch: u64,
) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut claimed: Vec<Vec<u8>> = filters.to_vec();
    filters
        .iter()
        .map(|filter| {
            let targets: Vec<Vec<u8>> = if filter.is_empty() {
                Vec::new()
            } else {
                quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets(
                    changes,
                    std::slice::from_ref(filter),
                    epoch,
                )
                .into_iter()
                .filter(|target| !claimed.contains(target))
                .collect()
            };
            claimed.extend(targets.iter().cloned());
            (filter.clone(), targets)
        })
        .collect()
}

impl ProverPipeline {
    fn dispatch_confirmation(
        self: &Arc<Self>, filters: Vec<Vec<u8>>, frame_number: u64,
        needs_storage: bool, prune_replicas: bool,
    ) {
        let Some(attempt) = self.lifecycle.confirmation_attempts.begin(&filters, frame_number) else {
            tracing::info!(frame = frame_number, filters = filters.len(), needs_storage,
                "confirmation dispatch skipped: an attempt for this filter/epoch is already recorded");
            return;
        };
        tracing::info!(frame = frame_number, filters = filters.len(), needs_storage, prune_replicas,
            "dispatching prover confirmation");
        let me = self.clone();
        tokio::spawn(async move {
            // Limit expensive preparation independently from network timeouts.
            // Keep the reservation inside the blocking task: cancelling its
            // waiter cannot start a second encoder while the first still runs.
            let (roots, attempt) = if needs_storage {
                static ENCODERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
                let Ok(permit) = ENCODERS.acquire().await else { return; };
                let encoder = me.clone();
                let encoded_filters = filters.clone();
                let prepared = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let roots = encoder.storage_confirm_leaf_roots(&encoded_filters, frame_number);
                    (roots, attempt)
                }).await;
                match prepared {
                    Ok((Ok(roots), attempt)) => (roots, attempt),
                    Ok((Err(e), _attempt)) => {
                        warn!(frame = frame_number, %e, "confirmation preparation failed; retrying on next cycle");
                        return;
                    }
                    Err(e) => {
                        warn!(frame = frame_number, %e, "confirmation preparation task failed");
                        return;
                    }
                }
            } else {
                (Vec::new(), attempt)
            };
            match tokio::time::timeout(
                NON_VDF_SUBMIT_TIMEOUT,
                me.submit_confirm(filters, frame_number, roots),
            ).await {
                Ok(Ok(())) => {
                    attempt.published(me.current_frame.as_ref().map(|f| f.effective()).unwrap_or(frame_number));
                    if prune_replicas {
                        if let Some(store) = me.replica_store.as_ref() {
                            // Keep current and next epoch replicas. Publication
                            // alone is not an on-chain registration acknowledgement.
                            let current_epoch = quil_types::consensus::epoch_for_frame(frame_number);
                            if let Err(e) = store.evict_below_epoch(current_epoch) {
                                warn!(frame = frame_number, %e, "replica cleanup failed");
                            }
                        }
                    }
                }
                Ok(Err(e)) => warn!(frame = frame_number, %e, "confirmation submission failed"),
                Err(_) => warn!(frame = frame_number, "confirmation submission timed out"),
            }
        });
    }

    /// Dispatch a lifecycle action. Non-blocking: spawns a tokio task
    /// to handle the (slow) VDF + sign + submit work so the caller's
    /// frame-processing loop continues.
    pub fn dispatch(self: &Arc<Self>, action: LifecycleAction) {
        match action {
            LifecycleAction::Noop => {}
            LifecycleAction::ProposeJoin { filters, worker_ids, frame_number } => {
                let me = self.clone();
                // Guard against overlapping VDF computations — set before
                // spawn so the next evaluate() sees it immediately.
                me.lifecycle.set_proof_in_progress(true);
                // Hard ceiling on the whole submit. VDF compute is
                // `spawn_blocking` and can run 10-20s on a slow box;
                // archive RPC has its own per-call timeout; BlossomSub
                // publish is fast. 90s is well above the legitimate
                // worst case but bounded — if anything in this path
                // ever hangs (transport bug, runtime starvation, etc.)
                // `proof_in_progress` clears so the lifecycle can
                // try again on the next frame instead of being
                // permanently stuck.
                const SUBMIT_JOIN_TIMEOUT: std::time::Duration =
                    std::time::Duration::from_secs(90);
                // TODO
                // Chunk the filters so no single ProverJoin exceeds the
                // decoder's `MAX_FILTERS` (100) / `MAX_PROOF_LEN` (51600 =
                // 100*516) ceiling — a >100-shard node would otherwise emit one
                // over-cap message the archive silently drops at decode. Each
                // chunk is an independent, valid join (one prover key, a subset
                // of shards) that the archive processes additively; `submit_join`
                // marks all `worker_ids` pending on each, which is idempotent.
                // Today there are ~49 shards ⇒ a single chunk, byte-identical to
                // the pre-chunking behaviour. Each chunk gets its own VDF-bounded
                // timeout since chunk N's proofs are independent of chunk N-1's.
                const MAX_FILTERS_PER_JOIN: usize = 100;
                tokio::spawn(async move {
                    let chunks: Vec<Vec<Vec<u8>>> = if filters.is_empty() {
                        vec![Vec::new()]
                    } else {
                        filters
                            .chunks(MAX_FILTERS_PER_JOIN)
                            .map(|c| c.to_vec())
                            .collect()
                    };
                    let chunk_count = chunks.len();
                    for (idx, chunk) in chunks.into_iter().enumerate() {
                        match tokio::time::timeout(
                            SUBMIT_JOIN_TIMEOUT,
                            me.submit_join(chunk, &worker_ids, frame_number),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                warn!(frame = frame_number, chunk = idx, chunk_count, %e, "ProposeJoin submission failed");
                                break;
                            }
                            Err(_) => {
                                warn!(
                                    frame = frame_number,
                                    chunk = idx,
                                    chunk_count,
                                    timeout_s = SUBMIT_JOIN_TIMEOUT.as_secs(),
                                    "ProposeJoin submission timed out — clearing proof_in_progress",
                                );
                                break;
                            }
                        }
                    }
                    me.lifecycle.set_proof_in_progress(false);
                });
            }
            LifecycleAction::ConfirmJoins { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, true, false);
            }
            LifecycleAction::RejectJoins { filters, frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_reject(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "RejectJoins submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "RejectJoins submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ProposeLeave { filters, frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_leave(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeLeave submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ProposeLeave submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ConfirmLeaves { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, false, false);
            }
            LifecycleAction::ReconfirmEpoch { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, true, true);
            }
            LifecycleAction::RejectLeaves { filters, frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_reject(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "RejectLeaves submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "RejectLeaves submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ProposeSeniorityMerge { frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_seniority_merge(frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeSeniorityMerge submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ProposeSeniorityMerge submission timed out",
                            );
                        }
                    }
                });
            }
        }
    }

    fn domain(label: &[u8]) -> Result<[u8; 32]> {
        let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        dp.extend_from_slice(label);
        quil_crypto::poseidon::hash_bytes_to_32(&dp)
    }

    fn bls_signer(&self) -> Result<Box<dyn Signer>> {
        self.key_manager
            .get_signer(quil_types::crypto::KeyType::Falcon512)
            .map_err(|e| QuilError::Internal(format!("no BLS signer: {e}")))
    }

    /// Submit a `ProverJoin` for the given filters. Normally driven
    /// by the lifecycle's `ProposeJoin` action; exposed pub so admin
    /// tooling (`NodeService::request_join`) can force an immediate
    /// submission bypassing the cooldown / readiness gate.
    ///
    /// `worker_ids` is the list of workers that will be pinned to
    /// each filter on success. Pass empty slice for admin submissions
    /// where worker assignment happens after registry confirmation.
    pub async fn submit_join(
        &self,
        filters: Vec<Vec<u8>>,
        worker_ids: &[u32],
        lifecycle_frame: u64,
    ) -> Result<()> {
        info!(
            filter_count = filters.len(),
            lifecycle_frame,
            "building ProverJoin"
        );

        let header = self.transport.latest_global_frame_header().await?;
        let frame_number = header.frame_number;

        // VDF proof-of-sequential-work is no longer required to join.
        // The `proof` field is retained in the wire format (empty here)
        // purely so historical joins still decode; new joins carry none.
        let all_proofs: Vec<u8> = Vec::new();

        // Seniority merge targets: our own + enrolled Ed448 seeds. The join op
        // itself only carries the BLS prover key, so the ONLY way the join can
        // factor in our libp2p peer-id(s)' premainnet seniority is to attach
        // them as merge targets — each Ed448 seed signs our BLS pubkey under
        // the `PROVER_JOIN_MERGE` domain (the same domain `verify_prover_join`
        // checks and `invoke_join` derives peer-ids from). Without this the
        // prover joins at seniority 0 regardless of what its peer-id earned,
        // and only a later `ProverSeniorityMerge` could raise it. A seed whose
        // peer-id has no premainnet seniority contributes 0 — harmless. This is
        // the same seed set used for `submit_seniority_merge` (own key first,
        // then `multisig_prover_enrollment_paths`).
        let merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> = {
            let mut mts =
                Vec::with_capacity(self.multisig_ed448_seeds.len());
            for seed in &self.multisig_ed448_seeds {
                let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
                let helper_signer =
                    quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
                let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                    &helper_signer,
                    &self.bls_pubkey,
                    b"PROVER_JOIN_MERGE",
                )?;
                mts.push(quil_execution::global_intrinsic::SeniorityMerge {
                    signature: helper_sig,
                    key_type: quil_types::crypto::KeyType::Ed448 as u32,
                    prover_public_key: helper_pubkey,
                });
            }
            mts
        };

        // Build + sign. Go signs the full ProverJoin canonical bytes
        // with signature=nil, then fills in the signature:
        // see global_prover_join.go:1074-1079.
        let signer = self.bls_signer()?;
        let unsigned = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: None,
            delegate_address: self.delegate_address.clone(),
            merge_targets: merge_targets.clone(),
            proof: all_proofs.clone(),
        };
        let join_message = unsigned.to_canonical_bytes()?;
        let join_domain = Self::domain(b"PROVER_JOIN")?;
        let signature = signer.sign_with_domain(&join_message, &join_domain)?;
        // Proof of possession: sign own pubkey with it, using BLS48_POP_SK domain.
        let pop_signature = signer.sign_with_domain(&self.bls_pubkey, b"BLS48_POP_SK")?;

        let signed = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature,
                public_key: Some(self.bls_pubkey.clone()),
                pop_signature,
            }),
            delegate_address: self.delegate_address.clone(),
            merge_targets,
            proof: all_proofs,
        };
        let bytes = signed.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            filter_count = filters.len(),
            bytes_len = bytes.len(),
            "submitting ProverJoin"
        );
        crate::metrics::inc_prover_joins_submitted();

        self.publish_prover_message(bytes).await?;

        // Publish succeeded — NOW burn the 4-frame cooldown. Setting
        // this earlier (in lifecycle's evaluate) would waste join
        // opportunities whenever an archive is unreachable or a VDF
        // self-verify fails: the next eligible frame would be gated
        // by a cooldown from a join that never actually reached the
        // network. Matches Go's post-success set at
        // `worker_allocator.go:224`.
        self.lifecycle.record_join_attempt(lifecycle_frame);

        // Persist the pending frame on each worker so reconcile can tell
        // "proposal in flight" from "orphaned". Uses `lifecycle_frame`
        // (not `frame_number`) — the timestamp matches the cooldown
        // timer on WorkerAllocator.
        for &core_id in worker_ids {
            let _ = self.worker_manager.set_pending_filter_frame(core_id, lifecycle_frame);
        }

        Ok(())
    }

    async fn submit_confirm(
        &self,
        filters: Vec<Vec<u8>>,
        frame_number: u64,
        leaf_roots: Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
    ) -> Result<()> {
        // Storage-attestation confirm hook (PoRep): at/after activation,
        // partition each confirmed shard, SDR-encode + persist this prover's
        // per-leaf replicas, and fold the registered leaf roots into the
        // confirm. The signature covers `confirm_signing_message`, which
        // appends the leaf-root set — byte-identical to the legacy
        // concat(filters)||frame message when the set is empty (pre-activation
        // / deps absent), so default Go-parity is preserved.
        let msg = quil_execution::global_intrinsic::prover_verify::confirm_signing_message(
            &filters,
            frame_number,
            &leaf_roots,
        );

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_CONFIRM")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let confirm = ProverConfirm {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
            leaf_roots,
        };
        let bytes = confirm.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), leaf_roots = confirm.leaf_roots.len(),
            leaf_entries = confirm.leaf_roots.iter().map(|g| g.entries.len()).sum::<usize>(),
            "submitting ProverConfirm");
        crate::metrics::inc_prover_confirms_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Partition committed shard data into PoRep leaves, encode and persist the
    /// next epoch's replicas, and return their roots. Preparation errors abort
    /// submission so the lifecycle can retry. Global confirms need no replicas.
    fn storage_confirm_leaf_roots(
        &self,
        filters: &[Vec<u8>],
        frame_number: u64,
    ) -> Result<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>> {
        let (Some(crdt), Some(replica_store)) =
            (self.hypergraph.as_ref(), self.replica_store.as_ref())
        else {
            if filters.iter().all(Vec::is_empty) {
                return Ok(Vec::new());
            }
            return Err(QuilError::Internal("storage confirmation requires hypergraph and replica store".into()));
        };
        // Epoch-aligned: a confirm in epoch E encodes + registers leaf roots for
        // the NEXT epoch E+1 (the `next` slot). The prover encodes ahead so that
        // when it becomes active next epoch it is already proving against an
        // on-chain registration. The per-frame proving path
        // (`storage_vote_openings`) reads replica@CURRENT-epoch, which this same
        // store wrote one epoch earlier — so encode-ahead lines up exactly.
        let epoch = quil_types::consensus::epoch_for_frame(frame_number) + 1;
        // Shards a split or merge applying next epoch creates from a confirmed
        // shard are registered too, encoded from that shard's storage: its
        // holder is on one of them once the change applies.
        let changes = match self.pending_shard_changes.as_ref() {
            Some(pending) if frame_number >= quil_execution::global_intrinsic::leaf_root_registration::pre_registration_frame() => pending(),
            _ => Vec::new(),
        };
        let mut roots = Vec::with_capacity(filters.len());
        for (filter, targets) in confirm_encoding_plan(filters, &changes, epoch) {
            let filter = &filter;
            let worker = if filter.is_empty() {
                None
            } else {
                self.storage_for_filter.as_ref().and_then(|resolve| resolve(filter))
            };
            if worker.is_none() && !filter.is_empty() {
                if let Some(remote) = self.remote_storage_confirm.as_ref() {
                    if let Some(prepared) = remote(filter, &targets, frame_number)? {
                        roots.extend(prepared);
                        continue;
                    }
                }
            }
            let (filter_crdt, filter_replicas) = match worker.as_ref() {
                Some((worker_crdt, worker_replicas)) => (worker_crdt.as_ref(), worker_replicas),
                None => (crdt.as_ref(), replica_store),
            };
            let encoded: Vec<Vec<u8>> = std::iter::once(filter.clone()).chain(targets).collect();
            roots.extend(crate::app_shard_metadata::compute_storage_confirm(
                filter_crdt,
                filter_replicas,
                &encoded,
                &self.prover_address,
                epoch,
                quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                &quil_crypto::sdr::SdrParams::default(),
            )?);
        }
        Ok(roots)

    }

    async fn submit_reject(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go: sign(concat(filters) || u64(frame_number), PROVER_REJECT_domain).
        // See global_prover_reject.go:260-295.
        let mut msg = Vec::new();
        for f in &filters { msg.extend_from_slice(f); }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_REJECT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let reject = ProverReject {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
        };
        let bytes = reject.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), "submitting ProverReject");
        crate::metrics::inc_prover_rejects_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Submit a `ShardSplit` proposal for the given shard → child set.
    /// Go signs `u64_be(frame) || shard_address` under the
    /// `SHARD_SPLIT` domain. See `global_shard_split.go:205-230`.
    pub async fn submit_shard_split(
        &self,
        shard_address: Vec<u8>,
        proposed_shards: Vec<Vec<u8>>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + shard_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&shard_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_SPLIT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let split = ShardSplit {
            shard_address: shard_address.clone(),
            proposed_shards,
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = split.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            shard = hex::encode(&shard_address),
            "submitting ShardSplit"
        );
        crate::metrics::inc_shard_splits_submitted();
        self.publish_prover_message_local_first(bytes).await
    }

    /// Submit a `ShardMerge` proposal for the given shard list →
    /// parent. Go signs `u64_be(frame) || parent_address` under the
    /// `SHARD_MERGE` domain. See `global_shard_merge.go:203-230`.
    pub async fn submit_shard_merge(
        &self,
        shard_addresses: Vec<Vec<u8>>,
        parent_address: Vec<u8>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + parent_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&parent_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_MERGE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let merge = ShardMerge {
            shard_addresses,
            parent_address: parent_address.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = merge.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            parent = hex::encode(&parent_address),
            "submitting ShardMerge"
        );
        crate::metrics::inc_shard_merges_submitted();
        self.publish_prover_message_local_first(bytes).await
    }

    /// Submit a `ProverSeniorityMerge` to raise on-chain seniority.
    /// Mirrors Go's `submitSeniorityMerge` at `worker_allocator.go:1725-1783`
    /// and `ProverSeniorityMerge.Prove` at `global_prover_seniority_merge.go:270-349`.
    async fn submit_seniority_merge(&self, frame_number: u64) -> Result<()> {
        if self.multisig_ed448_seeds.is_empty() {
            return Err(QuilError::Internal(
                "seniority merge: no multisig Ed448 seeds loaded".into(),
            ));
        }

        let merge_domain_tag: &[u8] = b"PROVER_SENIORITY_MERGE";

        // Build one SeniorityMerge record per helper seed.
        let mut merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> =
            Vec::with_capacity(self.multisig_ed448_seeds.len());
        for seed in &self.multisig_ed448_seeds {
            let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
            let helper_signer = quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
            let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                &helper_signer,
                &self.bls_pubkey,
                merge_domain_tag,
            )?;

            merge_targets.push(quil_execution::global_intrinsic::SeniorityMerge {
                signature: helper_sig,
                key_type: quil_types::crypto::KeyType::Ed448 as u32,
                prover_public_key: helper_pubkey,
            });
        }

        // BLS-sign `frame_be || helper_pubkeys_concat` under the
        // PROVER_SENIORITY_MERGE domain.
        let mut message: Vec<u8> = Vec::with_capacity(8 + merge_targets.len() * 57);
        message.extend_from_slice(&frame_number.to_be_bytes());
        for mt in &merge_targets {
            message.extend_from_slice(&mt.prover_public_key);
        }
        let bls_signer = self.bls_signer()?;
        let domain = Self::domain(merge_domain_tag)?;
        let bls_sig = bls_signer.sign_with_domain(&message, &domain)?;

        let merge = quil_execution::global_intrinsic::ProverSeniorityMerge {
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: bls_sig,
                address: self.prover_address.to_vec(),
            }),
            merge_targets,
        };
        let bytes = merge.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            helpers = self.multisig_ed448_seeds.len(),
            "submitting ProverSeniorityMerge"
        );
        self.publish_prover_message(bytes).await
    }

    async fn submit_leave(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go's leave message format differs — length-prefixed:
        //   u32(num_filters) || for each: u32(len) || filter || u64(frame).
        // See global_prover_leave.go:230-245.
        let mut msg = Vec::new();
        msg.extend_from_slice(&(filters.len() as u32).to_be_bytes());
        for f in &filters {
            msg.extend_from_slice(&(f.len() as u32).to_be_bytes());
            msg.extend_from_slice(f);
        }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_LEAVE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let leave = ProverLeave {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = leave.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), "submitting ProverLeave");
        crate::metrics::inc_prover_leaves_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Wrap `inner_bytes` in a `MessageBundle` and hand off to the
    /// configured transport. The transport is responsible for the
    /// gRPC fan-out + pubsub publish (production) or in-memory
    /// broadcast (tests).
    fn build_prover_bundle(&self, inner_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let req = CanonicalMessageRequest::wrap(inner_bytes)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: now_ms,
        };
        bundle.to_canonical_bytes()
    }

    async fn publish_prover_message(&self, inner_bytes: Vec<u8>) -> Result<()> {
        let bundle_bytes = self.build_prover_bundle(inner_bytes)?;
        self.transport.publish_prover_bundle(bundle_bytes).await
    }

    /// Loop a self-generated op into the LOCAL mempool (the same collector the
    /// gRPC/gossip ingest feeds), tagged with the current consensus rank exactly
    /// like the gRPC ingest (grpc.rs:400). Returns true if the op is now in the
    /// local mempool (freshly Accepted, or already present as a Duplicate).
    fn loopback_to_local_mempool(&self, bundle_bytes: &[u8]) -> bool {
        match (&self.local_message_collector, &self.current_frame) {
            (Some(mc), Some(cf)) => matches!(
                mc.add_message_outcome(cf.effective_rank(), bundle_bytes.to_vec()),
                SubmitOutcome::Accepted | SubmitOutcome::Duplicate
            ),
            _ => false,
        }
    }

    /// Publish a self-generated op LOCAL-FIRST: add it to this node's own mempool
    /// (so a frame PRODUCER includes its own op) AND best-effort publish to remote
    /// paths. Succeeds if EITHER path delivered — so a single-archive producer
    /// (where the remote publish has no acceptor and gossipsub won't self-loop)
    /// still submits its op instead of failing with "no archive accepted". Used
    /// for ShardSplit/ShardMerge, which the coverage orchestrator generates on
    /// the frame producer itself.
    async fn publish_prover_message_local_first(&self, inner_bytes: Vec<u8>) -> Result<()> {
        let bundle_bytes = self.build_prover_bundle(inner_bytes)?;
        let looped = self.loopback_to_local_mempool(&bundle_bytes);
        let published = self.transport.publish_prover_bundle(bundle_bytes).await;
        if looped || published.is_ok() {
            if looped {
                debug!("prover op looped back into local mempool (producer self-inclusion)");
            }
            Ok(())
        } else {
            published
        }
    }
}

#[cfg(test)]
mod tests {
    use super::confirm_encoding_plan;
    use quil_types::store::{PendingShardChange, ShardChangeKind};

    fn change(kind: ShardChangeKind, parent: u8, children: &[u8]) -> PendingShardChange {
        PendingShardChange {
            kind,
            parent: vec![parent],
            children: children.iter().map(|c| vec![*c]).collect(),
            effective_epoch: 8,
            proposed_frame: 0,
        }
    }

    #[test]
    fn a_confirm_encodes_the_shards_a_change_creates_from_each_filter_once() {
        let changes = vec![change(ShardChangeKind::Split, 1, &[10, 11]), change(ShardChangeKind::Merge, 2, &[20, 21])];
        assert_eq!(
            confirm_encoding_plan(&[vec![1], vec![20], vec![21], vec![]], &changes, 8),
            vec![
                (vec![1], vec![vec![10], vec![11]]),
                (vec![20], vec![vec![2]]),
                (vec![21], vec![]),
                (vec![], vec![]),
            ],
            "each split child from the parent's storage; a shared merge target once",
        );
        assert_eq!(confirm_encoding_plan(&[vec![1]], &changes, 9), vec![(vec![1], vec![])], "only a change applying next epoch");
    }
}
