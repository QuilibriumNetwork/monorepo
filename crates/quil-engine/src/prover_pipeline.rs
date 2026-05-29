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
}

/// Hard ceiling on lifecycle submissions that do NOT perform VDF
/// compute (confirms, rejects, leaves, seniority merge). Each of
/// these is sign + canonicalize + publish; the only legitimately
/// slow piece is the gRPC fan-out, which has its own per-archive
/// timeout in the transport. 30s is well above the worst case but
/// bounds the spawned task so a transport bug, runtime starvation,
/// or stuck publish can't silently wedge a dispatch forever.
const NON_VDF_SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl ProverPipeline {
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
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
                tokio::spawn(async move {
                    let outcome = tokio::time::timeout(
                        SUBMIT_JOIN_TIMEOUT,
                        me.submit_join(filters, &worker_ids, frame_number),
                    ).await;
                    me.lifecycle.set_proof_in_progress(false);
                    match outcome {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeJoin submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = SUBMIT_JOIN_TIMEOUT.as_secs(),
                                "ProposeJoin submission timed out — clearing proof_in_progress",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ConfirmJoins { filters, frame_number } => {
                let me = self.clone();
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_confirm(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ConfirmJoins submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ConfirmJoins submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::RejectJoins { filters, frame_number } => {
                let me = self.clone();
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
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
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
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
                let me = self.clone();
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_confirm(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ConfirmLeaves submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ConfirmLeaves submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::RejectLeaves { filters, frame_number } => {
                let me = self.clone();
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
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
                // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
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
            .get_signer(quil_types::crypto::KeyType::Bls48581G1)
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
            "building ProverJoin (fetching latest frame for VDF challenge)"
        );

        let header = self.transport.latest_global_frame_header().await?;
        let output = header.output.clone();
        let frame_number = header.frame_number;
        let difficulty = header.difficulty;

        // Compute VDF multi-proof in parallel — one proof per filter.
        let challenge: [u8; 32] = {
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest(&output).into()
        };
        let ids: Vec<Vec<u8>> = filters.iter().enumerate().map(|(i, f)| {
            let mut id = Vec::new();
            id.extend_from_slice(&self.prover_address);
            id.extend_from_slice(f);
            id.extend_from_slice(&(i as u32).to_be_bytes());
            id
        }).collect();

        let num_filters = filters.len();
        let mut handles = Vec::with_capacity(num_filters);
        for i in 0..num_filters {
            let fp = self.frame_prover.clone();
            let all_ids = ids.clone();
            let ch = challenge;
            handles.push(tokio::task::spawn_blocking(move || {
                let refs: Vec<&[u8]> = all_ids.iter().map(|v| v.as_slice()).collect();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fp.calculate_multi_proof(&ch, difficulty, &refs, i as u32)
                }));
                (i, result)
            }));
        }
        let mut results: Vec<Option<Vec<u8>>> = vec![None; num_filters];
        for handle in handles {
            match handle.await {
                Ok((i, Ok(Ok(p)))) => results[i] = Some(p),
                Ok((i, Ok(Err(e)))) => {
                    return Err(QuilError::Internal(format!(
                        "VDF proof {} failed: {}", i, e
                    )));
                }
                Ok((i, Err(_panic))) => {
                    return Err(QuilError::Internal(format!(
                        "VDF proof {} panicked", i
                    )));
                }
                Err(e) => {
                    return Err(QuilError::Internal(format!(
                        "VDF task join error: {}", e
                    )));
                }
            }
        }
        let mut all_proofs = Vec::with_capacity(num_filters * 516);
        for r in results {
            all_proofs.extend_from_slice(&r.unwrap());
        }

        // Self-verify before submitting — catches a class of key/VDF bugs
        // before the message reaches the network.
        {
            let refs_for_verify: Vec<&[u8]> = ids.iter().map(|v| v.as_slice()).collect();
            let solutions: Vec<Vec<u8>> = (0..num_filters)
                .map(|i| all_proofs[i * 516..(i + 1) * 516].to_vec())
                .collect();
            let sol_refs: Vec<&[u8]> = solutions.iter().map(|s| s.as_slice()).collect();
            match self.frame_prover.verify_multi_proof(&challenge, difficulty, &refs_for_verify, &sol_refs) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(QuilError::Internal(
                        "ProverJoin self-verify failed".into(),
                    ));
                }
                Err(e) => {
                    return Err(QuilError::Internal(format!(
                        "ProverJoin self-verify error: {}", e
                    )));
                }
            }
        }

        // Build + sign. Go signs the full ProverJoin canonical bytes
        // with signature=nil, then fills in the signature:
        // see global_prover_join.go:1074-1079.
        let signer = self.bls_signer()?;
        let unsigned = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: None,
            delegate_address: self.delegate_address.clone(),
            merge_targets: vec![],
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
            merge_targets: vec![],
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

    async fn submit_confirm(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go: sign(concat(filters) || u64(frame_number), PROVER_CONFIRM_domain).
        // See global_prover_confirm.go:302-325.
        let mut msg = Vec::new();
        for f in &filters { msg.extend_from_slice(f); }
        msg.extend_from_slice(&frame_number.to_be_bytes());

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
        };
        let bytes = confirm.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), "submitting ProverConfirm");
        crate::metrics::inc_prover_confirms_submitted();
        self.publish_prover_message(bytes).await
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
        self.publish_prover_message(bytes).await
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
        self.publish_prover_message(bytes).await
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
    async fn publish_prover_message(&self, inner_bytes: Vec<u8>) -> Result<()> {
        let req = CanonicalMessageRequest::wrap(inner_bytes)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: now_ms,
        };
        let bundle_bytes = bundle.to_canonical_bytes()?;
        self.transport.publish_prover_bundle(bundle_bytes).await
    }
}
