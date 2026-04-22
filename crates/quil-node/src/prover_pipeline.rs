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

use tracing::{info, warn};

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
            delegate_address: self.prover_address.to_vec(),
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
            delegate_address: self.prover_address.to_vec(),
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
        info!(
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
        info!(
            frame = frame_number,
            parent = hex::encode(&parent_address),
            "submitting ShardMerge"
        );
        quil_engine::metrics::inc_shard_merges_submitted();
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

        let mut grpc_ok = false;
        if let Some(seed) = self.ed448_seed {
            let addrs = self.archive_pool.get_all().await;
            for addr in &addrs {
                // Archive peer-info multiaddrs use the pubsub port (:8336);
                // the gRPC stream service listens on :8340.
                let stream_addr = addr.replace(":8336", ":8340");
                match ArchiveClient::connect_mtls(&stream_addr, &seed).await {
                    Ok(mut client) => {
                        match client.submit_global_message(bundle_bytes.clone()).await {
                            Ok(()) => {
                                info!(%stream_addr, "prover message submitted via gRPC");
                                grpc_ok = true;
                            }
                            Err(e) => warn!(%stream_addr, %e, "gRPC submit rejected"),
                        }
                    }
                    Err(e) => warn!(%stream_addr, %e, "archive connect failed"),
                }
            }
        }

        // Always broadcast via BlossomSub regardless — if gRPC succeeded this
        // is a redundant relay; if it didn't, this is the only path.
        self.p2p_handle
            .publish(GLOBAL_PROVER_BITMASK.to_vec(), bundle_bytes)
            .await;

        if !grpc_ok && self.ed448_seed.is_some() {
            warn!("no archive accepted submission — relying on BlossomSub fallback");
        }
        Ok(())
    }
}
