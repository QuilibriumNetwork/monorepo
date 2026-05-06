//! End-to-end submission pipeline for prover lifecycle actions.
//!
//! The lifecycle evaluator produces abstract `LifecycleAction`s; this
//! module turns them into signed canonical-bytes messages wrapped in a
//! `MessageBundle` and submits them both via gRPC (to known archive
//! endpoints) and BlossomSub GLOBAL_PROVER.
//!
//! Mirrors Go's `publishProverMessage` at
//! `node/consensus/global/global_consensus_engine.go:154-159`.

use std::sync::Arc;

use tracing::{info, warn, debug};

use quil_engine::provers::lifecycle::{LifecycleAction, ProverLifecycle};
use quil_engine::worker::WorkerManager;
use quil_execution::global_intrinsic::{
    addressed_signature::AddressedSignature,
    prover_filter_ops::ProverLeave,
    prover_join::ProverJoin,
    prover_ops::{ProverConfirm, ProverReject, ShardMerge, ShardSplit},
    sig_with_pop::SignatureWithPop,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_rpc::{ArchiveClient, ArchiveEndpointPool};
use quil_types::crypto::{FrameProver, Signer};
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

const GLOBAL_PROVER_BITMASK: &[u8] = &[0x00, 0x00, 0x00];

pub struct ProverPipeline {
    pub lifecycle: Arc<ProverLifecycle>,
    pub worker_manager: Arc<dyn WorkerManager>,
    pub archive_pool: Arc<ArchiveEndpointPool>,
    pub clock_store: Arc<dyn ClockStore>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
    pub ed448_seed: Option<[u8; 57]>,
    pub p2p_handle: quil_p2p::node::P2PHandle,
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
}

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
                tokio::spawn(async move {
                    let result = me.submit_join(filters, &worker_ids, frame_number).await;
                    me.lifecycle.set_proof_in_progress(false);
                    if let Err(e) = result {
                        warn!(frame = frame_number, %e, "ProposeJoin submission failed");
                    }
                });
            }
            LifecycleAction::ConfirmJoins { filters, frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_confirm(filters, frame_number).await {
                        warn!(frame = frame_number, %e, "ConfirmJoins submission failed");
                    }
                });
            }
            LifecycleAction::RejectJoins { filters, frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_reject(filters, frame_number).await {
                        warn!(frame = frame_number, %e, "RejectJoins submission failed");
                    }
                });
            }
            LifecycleAction::ProposeLeave { filters, frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_leave(filters, frame_number).await {
                        warn!(frame = frame_number, %e, "ProposeLeave submission failed");
                    }
                });
            }
            LifecycleAction::ConfirmLeaves { filters, frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_confirm(filters, frame_number).await {
                        warn!(frame = frame_number, %e, "ConfirmLeaves submission failed");
                    }
                });
            }
            LifecycleAction::RejectLeaves { filters, frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_reject(filters, frame_number).await {
                        warn!(frame = frame_number, %e, "RejectLeaves submission failed");
                    }
                });
            }
            LifecycleAction::ProposeSeniorityMerge { frame_number } => {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.submit_seniority_merge(frame_number).await {
                        warn!(frame = frame_number, %e, "ProposeSeniorityMerge submission failed");
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

    /// Fetch the latest frame header directly from an archive so the
    /// ProverJoin's frame_number references current chain state (Go rejects
    /// joins where `frame_number < head - 10`). Falls back to local store
    /// only if no archive is reachable.
    async fn latest_frame(&self) -> Result<(Vec<u8>, u64, u32)> {
        if let Some(seed) = self.ed448_seed {
            if let Some(addr) = self.archive_pool.get_all().await.into_iter().next() {
                if let Ok(mut c) = ArchiveClient::connect_mtls(&addr, &seed).await {
                    if let Ok(f) = c.get_global_frame(0).await {
                        if let Some(h) = f.header.as_ref() {
                            return Ok((h.output.clone(), h.frame_number, h.difficulty));
                        }
                    }
                }
            }
        }
        let f = self.clock_store.get_latest_global_clock_frame()
            .map_err(|e| QuilError::Internal(format!("no local frame: {e}")))?;
        let h = f.header.as_ref()
            .ok_or_else(|| QuilError::Internal("local frame missing header".into()))?;
        Ok((h.output.clone(), h.frame_number, h.difficulty))
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

        let (output, frame_number, difficulty) = self.latest_frame().await?;

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
        quil_engine::metrics::inc_prover_joins_submitted();

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
        quil_engine::metrics::inc_prover_confirms_submitted();
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
        quil_engine::metrics::inc_prover_rejects_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Submit a `ShardSplit` proposal for the given shard. Go signs
    /// `u64_be(frame) || shard_address` under the `SHARD_SPLIT`
    /// domain. See `global_shard_split.go:198-226`.
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
        quil_engine::metrics::inc_shard_splits_submitted();
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
        quil_engine::metrics::inc_shard_merges_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Submit a `ProverSeniorityMerge` to raise on-chain seniority.
    /// Mirrors Go's `submitSeniorityMerge` at `worker_allocator.go:1725-1783`
    /// and `ProverSeniorityMerge.Prove` at `global_prover_seniority_merge.go:270-349`.
    ///
    /// Flow:
    ///   1. Each helper Ed448 key signs the local BLS prover pubkey
    ///      with the `PROVER_SENIORITY_MERGE` domain.
    ///   2. Build `SeniorityMerge` records (key_type=Ed448, pubkey, sig).
    ///   3. BLS-sign `frame_number_be || concat(helper_pubkeys)` with the
    ///      poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_SENIORITY_MERGE")
    ///      domain.
    ///   4. Wrap in `ProverSeniorityMerge` with our addressed BLS sig.
    ///   5. Publish via `publish_prover_message`.
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
            // Ed448 signer from seed; signs the BLS prover pubkey with
            // PROVER_SENIORITY_MERGE as Ed448 context.
            let helper_signer = quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
            let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                &helper_signer,
                &self.bls_pubkey,
                merge_domain_tag,
            )?;

            merge_targets.push(quil_execution::global_intrinsic::SeniorityMerge {
                signature: helper_sig,
                // KeyType::Ed448 = 0 in quil_types::crypto::KeyType.
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
        quil_engine::metrics::inc_prover_leaves_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Wrap in MessageBundle and publish via gRPC to archives (primary path)
    /// plus BlossomSub GLOBAL_PROVER (fallback). Mirrors Go's
    /// `publishProverMessage` behavior.
    ///
    /// Fan-out semantics: gRPC submissions are dispatched to every known
    /// archive endpoint concurrently. The BlossomSub broadcast runs in
    /// parallel with the gRPC fan-out via `tokio::join!`. Returns `Ok`
    /// when *at least one* path succeeded — either an archive accepted
    /// the submission, or the BlossomSub publish was dispatched without
    /// error (an empty mesh still counts as success because BlossomSub
    /// buffers the message for late-joining peers, matching Go). Returns
    /// `Err(QuilError::P2p)` only when *every* archive failed AND the
    /// BlossomSub publish itself failed (channel closed, behaviour
    /// rejected the message, etc.).
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

        // Fan out to archives concurrently. Each closure connects + submits
        // independently so a slow / unreachable archive does not block the
        // others. The closure returns Ok(()) on a successful submit and
        // Err(_) on either connect or submit failure.
        let archive_addrs = if self.ed448_seed.is_some() {
            self.archive_pool.get_all().await
        } else {
            Vec::new()
        };
        let archive_count = archive_addrs.len();

        let grpc_future = {
            let bundle_bytes = bundle_bytes.clone();
            let seed_opt = self.ed448_seed;
            async move {
                if seed_opt.is_none() || archive_addrs.is_empty() {
                    return 0usize;
                }
                let seed = seed_opt.unwrap();
                let bytes = bundle_bytes;
                let submit = move |stream_addr: String, bytes: Vec<u8>| {
                    // `seed` is `[u8; 57]: Copy`, so each invocation gets its
                    // own value moved into the returned future.
                    let seed = seed;
                    async move {
                        match ArchiveClient::connect_mtls(&stream_addr, &seed).await {
                            Ok(mut client) => match client.submit_global_message(bytes).await {
                                Ok(()) => Ok(stream_addr),
                                Err(e) => Err((stream_addr, format!("submit rejected: {e}"))),
                            },
                            Err(e) => Err((stream_addr, format!("connect failed: {e}"))),
                        }
                    }
                };
                fan_out_to_archives(archive_addrs, bytes, submit).await
            }
        };

        // BlossomSub publish runs concurrently with the gRPC fan-out.
        // `P2PHandle::publish` is fallible (channel closed / behaviour
        // rejected the message). An empty mesh / no peers is *not* an
        // error — Go's behaviour also silently buffers in that case.
        let bs_future = self
            .p2p_handle
            .publish(GLOBAL_PROVER_BITMASK.to_vec(), bundle_bytes);

        let (grpc_ok_count, bs_result) = tokio::join!(grpc_future, bs_future);
        let p2p_ok = bs_result.is_ok();
        if let Err(ref e) = bs_result {
            warn!(error = %e, "BlossomSub publish failed for prover message");
        }

        if archive_count > 0 && grpc_ok_count == 0 {
            warn!(
                archive_count,
                "no archive accepted submission — relying on BlossomSub fallback"
            );
        }

        combine_publish_outcome(grpc_ok_count, p2p_ok)
    }
}

/// Combine fan-out outcomes into a final result. Returns `Err` only when
/// every archive failed AND the BlossomSub publish failed. Empty-mesh /
/// no-peer scenarios feed in as `p2p_ok = true` because the swarm
/// successfully accepted the message for buffered redelivery.
fn combine_publish_outcome(archive_ok_count: usize, p2p_ok: bool) -> Result<()> {
    if archive_ok_count == 0 && !p2p_ok {
        return Err(QuilError::P2p(
            "publish_prover_message: all paths failed (no archive accepted, BlossomSub publish failed)".into(),
        ));
    }
    Ok(())
}

/// Fan out a submission to every archive endpoint concurrently.
///
/// `submit` is a closure that takes a single `(stream_addr, payload)` and
/// returns `Ok(stream_addr)` on success or `Err((stream_addr, reason))`.
/// Returns the number of successful submissions.
///
/// Extracted as a free function so unit tests can substitute a closure
/// without needing a real `ArchiveClient` / mTLS handshake.
async fn fan_out_to_archives<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
) -> usize
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String)>>
        + Send
        + 'static,
{
    let mut handles = Vec::with_capacity(archive_addrs.len());
    for addr in archive_addrs {
        // Archive peer-info multiaddrs use the pubsub port (:8336);
        // the gRPC stream service listens on :8340.
        let stream_addr = addr.replace(":8336", ":8340");
        let bytes = bundle_bytes.clone();
        let submit = submit.clone();
        handles.push(tokio::spawn(async move { submit(stream_addr, bytes).await }));
    }
    let mut ok_count = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(addr)) => {
                debug!(%addr, "prover message submitted via gRPC");
                ok_count += 1;
            }
            Ok(Err((addr, reason))) => {
                warn!(%addr, %reason, "gRPC submit failed");
            }
            Err(e) => {
                warn!(error = %e, "gRPC submit task join error");
            }
        }
    }
    ok_count
}

#[cfg(test)]
mod tests {
    use super::fan_out_to_archives;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Verify that fan-out attempts every archive and counts every success.
    #[tokio::test]
    async fn publish_prover_message_fans_out_to_all_archives() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let submit = move |addr: String, _bytes: Vec<u8>| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<String, (String, String)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![0xAA; 16], submit).await;
        assert_eq!(ok, 3, "expected 3 successful submissions");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "expected 3 closure invocations (one per archive)"
        );
    }

    /// Verify partial-failure semantics: when one archive rejects, the
    /// others still succeed and the success count reflects only the good
    /// path.
    #[tokio::test]
    async fn publish_prover_message_falls_back_when_one_archive_fails() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            if addr.starts_with("5.") {
                Err::<String, (String, String)>((addr, "simulated reject".to_string()))
            } else {
                Ok::<String, (String, String)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![0xBB; 16], submit).await;
        assert_eq!(
            ok, 2,
            "expected 2 successes when 1 of 3 archives rejects (rest must still attempt)"
        );
    }

    /// All-fail scenario: every archive errors, so the success count is
    /// zero. Caller treats this as the trigger to log "relying on
    /// BlossomSub fallback".
    #[tokio::test]
    async fn publish_prover_message_all_archives_fail() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String)>((addr, "simulated reject".to_string()))
        };
        let addrs = vec!["1.2.3.4:8336".to_string(), "5.6.7.8:8336".to_string()];
        let ok = fan_out_to_archives(addrs, vec![0xCC; 16], submit).await;
        assert_eq!(ok, 0, "expected 0 successes when every archive fails");
    }

    /// Empty archive list: no submissions attempted, success count zero,
    /// no panics.
    #[tokio::test]
    async fn publish_prover_message_empty_archive_list() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Ok::<String, (String, String)>(addr)
        };
        let ok = fan_out_to_archives(Vec::new(), vec![0xDD; 16], submit).await;
        assert_eq!(ok, 0, "expected 0 successes with no archive endpoints");
    }

    /// When every archive fails AND the BlossomSub publish itself fails,
    /// `publish_prover_message` must surface an error so the caller can
    /// react. This mirrors `publish_prover_message`'s combine-step using
    /// the same outcome-combining helper to avoid having to wire a full
    /// `ProverPipeline` (which has many heavyweight deps unrelated to the
    /// publish-result path under test).
    #[tokio::test]
    async fn publish_prover_message_returns_err_when_all_paths_fail() {
        // Empty archive list means archive_ok_count == 0.
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String)>((addr, "no archive".into()))
        };
        let archive_ok = fan_out_to_archives(Vec::new(), vec![0xEE; 16], submit).await;
        assert_eq!(archive_ok, 0);

        // Simulate a P2P publish failure with the test stub.
        let handle = quil_p2p::node::P2PHandle::for_test(true);
        let p2p_result = handle.publish(vec![0u8; 3], vec![0xEE; 16]).await;
        assert!(p2p_result.is_err(), "stub configured to fail must return Err");
        let p2p_ok = p2p_result.is_ok();

        let combined = super::combine_publish_outcome(archive_ok, p2p_ok);
        assert!(
            combined.is_err(),
            "all-paths-fail must return Err — got {:?}",
            combined
        );
        // And: success on either path keeps the result Ok (empty-mesh /
        // fire-and-forget compatibility — Go semantics).
        let handle_ok = quil_p2p::node::P2PHandle::for_test(false);
        let p2p_result_ok = handle_ok.publish(vec![0u8; 3], vec![0xEE; 16]).await;
        assert!(p2p_result_ok.is_ok(), "stub OK path must return Ok");
        assert!(super::combine_publish_outcome(0, true).is_ok());
        assert!(super::combine_publish_outcome(2, false).is_ok());
    }
}
