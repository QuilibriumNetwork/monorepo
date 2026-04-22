//! Global intrinsic dispatcher. Partial port of
//! `node/execution/intrinsics/global/global_intrinsic.go`.
//!
//! Routes incoming canonical-bytes messages by type prefix to the
//! per-op verify + materialize functions. Holds the KeyManager and
//! a reference to the CRDT for vertex lookups.

use std::sync::Arc;

use sha2::{Sha256, Digest};
use quil_types::crypto::KeyManager;
use quil_types::error::{QuilError, Result};
use quil_types::store::{ClockStore, KvDb, ShardsStore, ShardInfo};

use super::materialize;
use super::prover_filter_ops::{
    ProverLeave, ProverPause, ProverResume,
    TYPE_PROVER_LEAVE, TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME,
};
use super::prover_ops::{
    ProverConfirm, ProverReject,
    TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT,
    TYPE_PROVER_KICK, TYPE_PROVER_UPDATE,
    TYPE_SHARD_SPLIT, TYPE_SHARD_MERGE,
};
use super::prover_join::{ProverJoin, TYPE_PROVER_JOIN};
use super::seniority_merge::TYPE_SENIORITY_MERGE;
use super::frame_header::TYPE_FRAME_HEADER;
use super::verify;
use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{HypergraphState, vertex_adds_discriminator};

/// The global intrinsic: holds dependencies for signature
/// verification and state lookups. Dispatches `validate` and
/// `invoke_step` calls to per-op handlers.
pub struct GlobalIntrinsic {
    key_manager: Arc<dyn KeyManager>,
    _frame_prover: Option<Arc<dyn quil_types::crypto::FrameProver>>,
    clock_store: Option<Arc<dyn ClockStore>>,
    shards_store: Option<Arc<dyn ShardsStore>>,
    /// KvDb backing the shards store, used to create batch transactions
    /// for shard split/merge writes (Go passes nil txn; Rust needs one).
    shards_db: Option<Arc<dyn KvDb>>,
}

impl GlobalIntrinsic {
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self {
            key_manager,
            _frame_prover: None,
            clock_store: None,
            shards_store: None,
            shards_db: None,
        }
    }

    /// Create with VDF frame prover for full ProverJoin verification.
    pub fn new_with_frame_prover(
        key_manager: Arc<dyn KeyManager>,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) -> Self {
        Self {
            key_manager,
            _frame_prover: Some(frame_prover),
            clock_store: None,
            shards_store: None,
            shards_db: None,
        }
    }

    /// Create with all runtime dependencies.
    pub fn new_with_stores(
        key_manager: Arc<dyn KeyManager>,
        frame_prover: Option<Arc<dyn quil_types::crypto::FrameProver>>,
        clock_store: Option<Arc<dyn ClockStore>>,
        shards_store: Option<Arc<dyn ShardsStore>>,
        shards_db: Option<Arc<dyn KvDb>>,
    ) -> Self {
        Self {
            key_manager,
            _frame_prover: frame_prover,
            clock_store,
            shards_store,
            shards_db,
        }
    }

    /// Validate a canonical-bytes global op message. Decodes the
    /// message, dispatches by type prefix, and runs the per-op
    /// structural validation + signature verification (when prover
    /// trees are available).
    ///
    /// `prover_tree` and `allocation_tree` are optional — when `None`,
    /// only structural validation runs (no signature check). The
    /// engine passes these in after loading from the CRDT.
    pub fn validate(
        &self,
        _frame_number: u64,
        input: &[u8],
        prover_tree: Option<&quil_tries::VectorCommitmentTree>,
        allocation_tree: Option<&quil_tries::VectorCommitmentTree>,
    ) -> Result<bool> {
        if input.len() < 4 {
            return Err(QuilError::InvalidArgument(
                "global intrinsic: input too short".into(),
            ));
        }

        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&input[..4]);
        let type_prefix = u32::from_be_bytes(tp_buf);

        match type_prefix {
            TYPE_PROVER_PAUSE => {
                let op = ProverPause::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_pause(
                        &op, pt, allocation_tree, self.key_manager.as_ref(),
                    );
                }
                // Structural-only validation (no tree = no sig check)
                Ok(true)
            }
            TYPE_PROVER_RESUME => {
                let op = ProverResume::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_resume(
                        &op, pt, allocation_tree, self.key_manager.as_ref(),
                    );
                }
                Ok(true)
            }
            TYPE_PROVER_LEAVE => {
                let op = ProverLeave::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_leave(
                        &op, pt, self.key_manager.as_ref(),
                    );
                }
                Ok(true)
            }
            TYPE_PROVER_CONFIRM => {
                let op = ProverConfirm::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_confirm(
                        &op, pt, self.key_manager.as_ref(),
                    );
                }
                Ok(true)
            }
            TYPE_PROVER_REJECT => {
                let op = ProverReject::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_reject(
                        &op, pt, self.key_manager.as_ref(),
                    );
                }
                Ok(true)
            }
            TYPE_PROVER_JOIN => {
                let op = ProverJoin::from_canonical_bytes(input)?;
                let _v = verify::validate_prover_join_structural(&op, _frame_number)?;
                // VDF multi-proof verify if frame_prover + frame data available
                // The caller provides frame_output and frame_difficulty via
                // a separate call to verify_prover_join_vdf when the frame
                // store lookup succeeds.
                Ok(true)
            }
            TYPE_PROVER_UPDATE => {
                let op = super::prover_ops::ProverUpdate::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    return verify::verify_prover_update(
                        &op, pt, self.key_manager.as_ref(),
                    );
                }
                Ok(true)
            }
            TYPE_PROVER_KICK | TYPE_SENIORITY_MERGE
            | TYPE_FRAME_HEADER | TYPE_SHARD_SPLIT | TYPE_SHARD_MERGE => {
                crate::global_engine::peek_global_message_kind(input)?;
                Ok(true)
            }
            _ => Err(QuilError::InvalidArgument(format!(
                "global intrinsic: unknown type prefix 0x{:08x}",
                type_prefix
            ))),
        }
    }

    /// Execute a state transition for a global intrinsic operation.
    ///
    /// Decodes the canonical-bytes input by type prefix, loads the
    /// relevant prover/allocation vertex trees from the HypergraphState,
    /// applies the materialize function, and writes the modified trees
    /// back to the state.
    pub fn invoke_step(
        &self,
        frame_number: u64,
        input: &[u8],
        state: &HypergraphState,
    ) -> Result<()> {
        if input.len() < 4 {
            return Err(QuilError::InvalidArgument(
                "global intrinsic invoke_step: input too short".into(),
            ));
        }

        let mut tp_buf = [0u8; 4];
        tp_buf.copy_from_slice(&input[..4]);
        let type_prefix = u32::from_be_bytes(tp_buf);

        let va_disc = vertex_adds_discriminator()?;

        match type_prefix {
            TYPE_PROVER_PAUSE => {
                let op = ProverPause::from_canonical_bytes(input)?;
                self.invoke_filter_op(frame_number, &op.filter, &op.public_key_signature_bls48581, state, &va_disc, |alloc_tree, fn_| {
                    materialize::materialize_prover_pause(alloc_tree, fn_)
                })
            }
            TYPE_PROVER_RESUME => {
                let op = ProverResume::from_canonical_bytes(input)?;
                self.invoke_filter_op(frame_number, &op.filter, &op.public_key_signature_bls48581, state, &va_disc, |alloc_tree, fn_| {
                    materialize::materialize_prover_resume(alloc_tree, fn_)
                })
            }
            TYPE_PROVER_LEAVE => {
                let op = ProverLeave::from_canonical_bytes(input)?;
                for filter in &op.filters {
                    self.invoke_filter_op(frame_number, filter, &op.public_key_signature_bls48581, state, &va_disc, |alloc_tree, fn_| {
                        materialize::materialize_prover_leave(alloc_tree, fn_)
                    })?;
                }
                Ok(())
            }
            TYPE_PROVER_CONFIRM => {
                let op = ProverConfirm::from_canonical_bytes(input)?;
                // Confirm applies to each filter in the confirm message.
                // Validate timing window (360-720 frames) before materializing.
                for filter in &op.filters {
                    self.invoke_filter_op(frame_number, filter, &op.public_key_signature_bls48581, state, &va_disc, |alloc_tree, fn_| {
                        // Check timing constraints first
                        verify::validate_confirm_timing(fn_, alloc_tree)?;
                        materialize::materialize_prover_confirm(alloc_tree, fn_)
                    })?;
                }
                Ok(())
            }
            TYPE_PROVER_REJECT => {
                let op = ProverReject::from_canonical_bytes(input)?;
                self.invoke_filter_op(frame_number, &op.filter, &op.public_key_signature_bls48581, state, &va_disc, |alloc_tree, fn_| {
                    materialize::materialize_prover_reject(alloc_tree, fn_)
                })
            }
            TYPE_PROVER_JOIN => {
                let op = ProverJoin::from_canonical_bytes(input)?;
                self.invoke_join(frame_number, &op, state, &va_disc)
            }
            TYPE_PROVER_KICK => {
                let op = super::prover_ops::ProverKick::from_canonical_bytes(input)?;
                self.invoke_kick(frame_number, &op, state, &va_disc)
            }
            TYPE_PROVER_UPDATE => {
                let op = super::prover_ops::ProverUpdate::from_canonical_bytes(input)?;
                self.invoke_update(frame_number, &op, state, &va_disc)
            }
            TYPE_SENIORITY_MERGE => {
                let op = super::prover_ops::ProverSeniorityMerge::from_canonical_bytes(input)?;
                self.invoke_seniority_merge(frame_number, &op, state, &va_disc)
            }
            TYPE_FRAME_HEADER => {
                let op = super::frame_header::FrameHeader::from_canonical_bytes(input)?;
                self.invoke_frame_header(frame_number, &op, state, &va_disc)
            }
            TYPE_SHARD_SPLIT => {
                let op = super::prover_ops::ShardSplit::from_canonical_bytes(input)?;
                self.invoke_shard_split(frame_number, &op, state, &va_disc)
            }
            TYPE_SHARD_MERGE => {
                let op = super::prover_ops::ShardMerge::from_canonical_bytes(input)?;
                self.invoke_shard_merge(frame_number, &op, state, &va_disc)
            }
            _ => Err(QuilError::InvalidArgument(format!(
                "global intrinsic invoke_step: unknown type prefix 0x{:08x}",
                type_prefix
            ))),
        }
    }

    /// Common helper for filter-based ops (Pause/Resume/Leave/Confirm/Reject).
    ///
    /// Loads the prover vertex from the CRDT, computes the allocation
    /// address, loads the allocation vertex, applies the mutation via
    /// the provided closure, and writes both vertices back.
    ///
    /// The vertex data in the CRDT is a flat byte blob. The
    /// `VectorCommitmentTree` is reconstructed from the blob by
    /// treating field values at RDF-schema keys. For now, the
    /// changeset stores the raw field mutations as marker entries.
    fn invoke_filter_op(
        &self,
        frame_number: u64,
        filter: &[u8],
        addressed_sig: &Option<super::addressed_signature::AddressedSignature>,
        state: &HypergraphState,
        va_disc: &[u8; 32],
        mutate: impl FnOnce(&mut quil_tries::VectorCommitmentTree, u64) -> Result<()>,
    ) -> Result<()> {
        let prover_address = addressed_sig
            .as_ref()
            .map(|s| s.address.clone())
            .unwrap_or_default();
        if prover_address.len() < 32 {
            return Err(QuilError::InvalidArgument("invoke_step: prover address too short".into()));
        }

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

        // Load prover vertex data from CRDT.
        let prover_data = state.get(domain, &prover_address, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument("invoke_step: prover not found".into()))?;

        // Reconstruct the prover tree from stored data.
        // The CRDT stores field data as a flat blob — we rebuild the tree
        // by parsing field values. For vertices loaded from the synced
        // prover tree (via ensure_prover_tree), the data is a serialized
        // tree node. For now, create a minimal tree and populate from data.
        let prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);

        // Read public key from prover tree
        let pubkey = read_field(&prover_tree, "prover:Prover", "PublicKey")
            .unwrap_or_default();
        if pubkey.is_empty() {
            return Err(QuilError::InvalidArgument("invoke_step: prover has no PublicKey".into()));
        }

        // Compute allocation address
        let alloc_addr = materialize::allocation_address(&pubkey, filter)?;

        // Load allocation vertex
        let alloc_data = state.get(domain, &alloc_addr, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument("invoke_step: allocation not found".into()))?;

        let mut alloc_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&alloc_data);

        // Apply the mutation
        mutate(&mut alloc_tree, frame_number)?;

        // Serialize the modified allocation tree back to blob form.
        let alloc_blob = crate::prover_registry::vertex_tree_to_blob(&alloc_tree);
        state.set(domain, &alloc_addr, va_disc, frame_number, alloc_blob)?;

        // Update prover aggregate status.
        let new_status = read_field(&alloc_tree, "allocation:ProverAllocation", "Status")
            .and_then(|b| b.first().copied())
            .unwrap_or(0);

        let mut prover_tree_mut = prover_tree;
        write_field(&mut prover_tree_mut, "prover:Prover", "Status", &[new_status])?;
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&prover_tree_mut);
        state.set(domain, &prover_address, va_disc, frame_number, prover_blob)?;

        Ok(())
    }

    /// ProverJoin invoke_step: create prover + allocation vertices.
    ///
    /// Validation checks:
    /// - Public key must be present
    /// - Prover must not have been previously kicked (KickFrameNumber != 0)
    /// - Existing active allocations block rejoining (unless expired after 720 frames)
    fn invoke_join(
        &self,
        frame_number: u64,
        op: &ProverJoin,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        let pubkey = op.public_key_signature_bls48581
            .as_ref()
            .and_then(|s| s.public_key.as_ref())
            .cloned()
            .unwrap_or_default();
        if pubkey.is_empty() {
            return Err(QuilError::InvalidArgument("invoke_step join: no public key".into()));
        }

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let prover_address = materialize::prover_address_from_pubkey(&pubkey)?;

        // Check if prover was previously kicked
        if let Ok(Some(existing_data)) = state.get(domain, &prover_address, va_disc) {
            if !existing_data.is_empty() {
                let existing_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&existing_data);
                let kick_frame = read_field(&existing_tree, "prover:Prover", "KickFrameNumber")
                    .unwrap_or_default();
                if kick_frame.len() == 8 {
                    let kf = u64::from_be_bytes(kick_frame.try_into().unwrap());
                    if kf > 0 {
                        return Err(QuilError::InvalidArgument(
                            "invoke_step join: prover has been previously kicked".into(),
                        ));
                    }
                }

                // Check existing allocations aren't still active (Go: lines 990-1069)
                for filter in &op.filters {
                    let alloc_addr = materialize::allocation_address(&pubkey, filter)?;
                    if let Ok(Some(alloc_data)) = state.get(domain, &alloc_addr, va_disc) {
                        if !alloc_data.is_empty() {
                            let alloc_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&alloc_data);
                            let status = read_field(&alloc_tree, "allocation:ProverAllocation", "Status")
                                .and_then(|b| b.first().copied())
                                .unwrap_or(4);
                            // Status 4 (left/kicked) is ok to rejoin
                            if status != 4 {
                                // Check if the allocation has expired (720 frame window)
                                let join_frame = read_field(&alloc_tree, "allocation:ProverAllocation", "JoinFrameNumber")
                                    .unwrap_or_default();
                                if join_frame.len() == 8 {
                                    let jf = u64::from_be_bytes(join_frame.try_into().unwrap());
                                    if frame_number < jf + 720 {
                                        return Err(QuilError::InvalidArgument(format!(
                                            "invoke_step join: allocation still active (status={}, frame_since_join={})",
                                            status, frame_number.saturating_sub(jf)
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let seniority = op.frame_number; // seniority = join frame
        let output = materialize::materialize_prover_join(&pubkey, &op.filters, frame_number, seniority)?;

        // Write prover vertex
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&output.prover_tree);
        state.set(domain, &output.prover_address, va_disc, frame_number, prover_blob)?;

        // Write allocation vertices
        for (alloc_addr, alloc_tree) in &output.allocations {
            let alloc_blob = crate::prover_registry::vertex_tree_to_blob(alloc_tree);
            state.set(domain, alloc_addr, va_disc, frame_number, alloc_blob)?;
        }

        // Write reward vertex
        let reward_addr = materialize::reward_address(&output.prover_address)?;
        let mut reward_tree = quil_tries::VectorCommitmentTree::new();
        materialize::set_reward_balance(&mut reward_tree, &[])?;
        if !op.delegate_address.is_empty() {
            materialize::set_reward_delegate_address(&mut reward_tree, &op.delegate_address)?;
        }
        let reward_blob = crate::prover_registry::vertex_tree_to_blob(&reward_tree);
        state.set(domain, &reward_addr, va_disc, frame_number, reward_blob)?;

        Ok(())
    }

    /// ProverKick invoke_step: kick prover + all allocations.
    /// The kick message contains the kicked prover's public key. We derive
    /// the prover address, load the prover vertex, kick it, and kick all
    /// allocations found via the prover registry.
    fn invoke_kick(
        &self,
        frame_number: u64,
        op: &super::prover_ops::ProverKick,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        let prover_address = materialize::prover_address_from_pubkey(&op.kicked_prover_public_key)?;

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

        // Load and kick prover vertex
        let prover_data = state.get(domain, &prover_address, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument("invoke_step kick: prover not found".into()))?;
        if prover_data.is_empty() {
            return Err(QuilError::InvalidArgument("invoke_step kick: prover has no data".into()));
        }
        let mut prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        materialize::materialize_prover_kick(&mut prover_tree, frame_number)?;
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&prover_tree);
        state.set(domain, &prover_address, va_disc, frame_number, prover_blob)?;

        // Note: To kick all allocations, we'd need to scan the prover's
        // hyperedge for all allocation addresses. For now, the kicked prover
        // status (4) is set on the prover vertex itself. Allocation-level
        // kicks happen during EvictInactiveProvers in the coverage monitor.

        Ok(())
    }

    /// ProverUpdate invoke_step: update DelegateAddress on the reward vertex.
    fn invoke_update(
        &self,
        frame_number: u64,
        op: &super::prover_ops::ProverUpdate,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        let prover_address = op.public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .unwrap_or_default();
        if prover_address.len() < 32 {
            return Err(QuilError::InvalidArgument("invoke_step update: address too short".into()));
        }

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

        // Update DelegateAddress on reward vertex if provided
        if !op.delegate_address.is_empty() {
            let reward_addr = materialize::reward_address(&prover_address)?;
            if let Some(reward_data) = state.get(domain, &reward_addr, va_disc)? {
                if !reward_data.is_empty() {
                    let mut reward_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&reward_data);
                    materialize::set_reward_delegate_address(&mut reward_tree, &op.delegate_address)?;
                    let reward_blob = crate::prover_registry::vertex_tree_to_blob(&reward_tree);
                    state.set(domain, &reward_addr, va_disc, frame_number, reward_blob)?;
                }
            }
        }

        Ok(())
    }

    /// SeniorityMerge invoke_step: merge seniority from old peer keys
    /// into the prover's Seniority field and write spent-merge markers.
    ///
    /// Go equivalent: `ProverSeniorityMerge::Materialize` at
    /// `global_prover_seniority_merge.go:65`.
    ///
    /// Converts Ed448 merge-target public keys to base58 peer ID
    /// strings, looks up their seniority in the ClockStore's peer
    /// seniority map, and passes the max seniority to
    /// `materialize_seniority_merge`. If no ClockStore is configured,
    /// merge_seniority defaults to 0.
    fn invoke_seniority_merge(
        &self,
        frame_number: u64,
        op: &super::prover_ops::ProverSeniorityMerge,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        if op.merge_targets.is_empty() {
            return Err(QuilError::InvalidArgument(
                "invoke_step seniority_merge: no merge targets".into(),
            ));
        }

        let prover_address = op.public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .unwrap_or_default();
        if prover_address.len() < 32 {
            return Err(QuilError::InvalidArgument(
                "invoke_step seniority_merge: address too short".into(),
            ));
        }

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

        // Load prover vertex
        let prover_data = state.get(domain, &prover_address, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument(
                "invoke_step seniority_merge: prover not found".into(),
            ))?;
        if prover_data.is_empty() {
            return Err(QuilError::InvalidArgument(
                "invoke_step seniority_merge: prover has no data".into(),
            ));
        }
        let mut prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);

        // Collect merge target public keys
        let merge_target_pubkeys: Vec<Vec<u8>> = op.merge_targets
            .iter()
            .map(|mt| mt.prover_public_key.clone())
            .collect();

        // Compute merge_seniority from merge targets by converting
        // Ed448 public keys to peer IDs and looking up in the
        // seniority map.
        let merge_seniority: u64 = if let Some(ref clock_store) = self.clock_store {
            // Convert Ed448 keys to base58 peer ID strings
            let peer_ids: Vec<String> = op.merge_targets
                .iter()
                .filter(|mt| mt.key_type == 0 && mt.prover_public_key.len() == 57)
                .map(|mt| ed448_pubkey_to_peer_id_string(&mt.prover_public_key))
                .collect();

            if peer_ids.is_empty() {
                0
            } else {
                // Look up seniority from the clock store (empty filter = global)
                match clock_store.get_peer_seniority_map(&[]) {
                    Ok(seniority_map) => {
                        let mut max_seniority: u64 = 0;
                        for pid in &peer_ids {
                            if let Some(&s) = seniority_map.get(pid) {
                                if s > max_seniority {
                                    max_seniority = s;
                                }
                            }
                        }
                        max_seniority
                    }
                    Err(_) => 0,
                }
            }
        } else {
            0
        };

        let spent_markers = materialize::materialize_seniority_merge(
            &mut prover_tree,
            &prover_address,
            merge_seniority,
            &merge_target_pubkeys,
        )?;

        // Write updated prover vertex
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&prover_tree);
        state.set(domain, &prover_address, va_disc, frame_number, prover_blob)?;

        // Write spent-merge markers
        for (spent_addr, spent_tree) in &spent_markers {
            let spent_blob = crate::prover_registry::vertex_tree_to_blob(spent_tree);
            state.set(domain, spent_addr, va_disc, frame_number, spent_blob)?;
        }

        Ok(())
    }

    /// FrameHeader (ProverShardUpdate) invoke_step: update allocation
    /// LastActiveFrameNumber for participating provers and distribute
    /// rewards.
    ///
    /// Go equivalent: `ProverShardUpdate::Materialize` at
    /// `global_prover_shard_update.go:147`.
    ///
    /// NOTE: The full Go implementation verifies the frame header's BLS
    /// aggregate signature, identifies participating provers by bitmask
    /// index, computes ring assignments, and distributes per-ring
    /// rewards. This requires the frame prover (VDF verifier), BLS
    /// constructor, prover registry, and reward issuance calculator —
    /// none of which have Rust surfaces yet. This is therefore a
    /// structural no-op that acknowledges the message.
    ///
    /// The per-allocation `LastActiveFrameNumber` update is implemented
    /// in `materialize_frame_header_activity` and can be called by the
    /// caller once the participating prover list is resolved.
    fn invoke_frame_header(
        &self,
        _frame_number: u64,
        _op: &super::frame_header::FrameHeader,
        _state: &HypergraphState,
        _va_disc: &[u8; 32],
    ) -> Result<()> {
        // Frame header processing requires:
        // 1. Frame prover to verify the BLS aggregate signature and
        //    extract the participant bitmask.
        // 2. Prover registry to get active provers for the shard.
        // 3. Reward issuance calculator for per-ring reward amounts.
        // 4. Hypergraph metadata for state size / shard count.
        //
        // Until these runtime deps are ported, acknowledge the message
        // without modifying state. The Go engine gates this behind
        // `frameNumber != p.FrameHeader.FrameNumber+1`, so invalid
        // headers are rejected at verify time.
        Ok(())
    }

    /// ShardSplit invoke_step: register new sub-shard addresses.
    ///
    /// Go equivalent: `ShardSplitOp::Materialize` at
    /// `global_shard_split.go:150`.
    ///
    /// Parses the split, then writes each new sub-shard to the
    /// ShardsStore if one is configured. If no ShardsStore is set,
    /// the split is validated but not persisted.
    fn invoke_shard_split(
        &self,
        _frame_number: u64,
        op: &super::prover_ops::ShardSplit,
        _state: &HypergraphState,
        _va_disc: &[u8; 32],
    ) -> Result<()> {
        let output = materialize::materialize_shard_split(
            &op.shard_address,
            &op.proposed_shards,
        )?;

        // Write new sub-shard entries to the shards store.
        if let (Some(ref store), Some(ref db)) = (&self.shards_store, &self.shards_db) {
            let txn = db.new_batch(false)?;
            for (l2, path) in &output.new_shards {
                let shard = ShardInfo {
                    shard_key: l2.clone(),
                    prefix: path.clone(),
                    size: Vec::new(),
                    data_shards: 0,
                    commitment: Vec::new(),
                };
                store.put_app_shard(txn.as_ref(), &shard)?;
            }
            txn.commit()?;
        }

        Ok(())
    }

    /// ShardMerge invoke_step: remove child shard addresses.
    ///
    /// Go equivalent: `ShardMergeOp::Materialize` at
    /// `global_shard_merge.go:158`.
    ///
    /// Parses the merge, then removes each child shard from the
    /// ShardsStore if one is configured. If no ShardsStore is set,
    /// the merge is validated but not persisted.
    fn invoke_shard_merge(
        &self,
        _frame_number: u64,
        op: &super::prover_ops::ShardMerge,
        _state: &HypergraphState,
        _va_disc: &[u8; 32],
    ) -> Result<()> {
        let output = materialize::materialize_shard_merge(
            &op.shard_addresses,
            &op.parent_address,
        )?;

        // Remove child shard entries from the shards store.
        if let (Some(ref store), Some(ref db)) = (&self.shards_store, &self.shards_db) {
            let txn = db.new_batch(false)?;
            for (l2, path) in &output.removed_shards {
                store.delete_app_shard(txn.as_ref(), l2, path)?;
            }
            txn.commit()?;
        }

        Ok(())
    }
}

/// Convert an Ed448 public key (57 bytes) to a base58-encoded libp2p
/// peer ID string. Matches Go's `peer.IDFromPublicKey` for Ed448 keys.
///
/// Process:
/// 1. Protobuf-encode the key: `PublicKey { Type: 4 (Ed448), Data: pubkey }`
/// 2. SHA2-256 hash (key > 42 bytes, so not inlined)
/// 3. Multihash-wrap: `[0x12, 0x20, <32-byte SHA256>]`
/// 4. Base58-encode the 34-byte multihash
fn ed448_pubkey_to_peer_id_string(pubkey: &[u8]) -> String {
    // Step 1: protobuf encode
    let mut proto = Vec::with_capacity(4 + pubkey.len());
    proto.push(0x08); // field 1 tag (varint)
    proto.push(0x04); // value = 4 (Ed448)
    proto.push(0x12); // field 2 tag (length-delimited)
    proto.push(pubkey.len() as u8);
    proto.extend_from_slice(pubkey);

    // Step 2: SHA2-256 hash
    let hash = Sha256::digest(&proto);

    // Step 3: multihash wrap
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12); // SHA2-256 function code
    multihash.push(0x20); // digest length (32)
    multihash.extend_from_slice(&hash);

    // Step 4: base58 encode
    bs58::encode(&multihash).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use quil_types::crypto::KeyType;
    use crate::global_schema::{
        write_field, write_type, TYPE_HASH_PROVER, TYPE_HASH_ALLOCATION,
    };
    use super::super::addressed_signature::AddressedSignature;

    struct AcceptAll;
    impl KeyManager for AcceptAll {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> { Ok(true) }
    }

    struct RejectAll;
    impl KeyManager for RejectAll {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> { Ok(false) }
    }

    fn make_prover_tree() -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "prover:Prover").unwrap();
        write_field(&mut tree, "prover:Prover", "PublicKey", &vec![0xAAu8; 585]).unwrap();
        write_field(&mut tree, "prover:Prover", "Status", &[1u8]).unwrap();
        tree
    }

    fn make_alloc_tree(status: u8) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "allocation:ProverAllocation").unwrap();
        write_field(&mut tree, "allocation:ProverAllocation", "Status", &[status]).unwrap();
        tree
    }

    fn pause_bytes() -> Vec<u8> {
        ProverPause {
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

    #[test]
    fn validate_pause_structural_only() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        assert!(gi.validate(1, &pause_bytes(), None, None).unwrap());
    }

    #[test]
    fn validate_pause_with_trees_and_accept() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let pt = make_prover_tree();
        let at = make_alloc_tree(1); // active
        assert!(gi.validate(1, &pause_bytes(), Some(&pt), Some(&at)).unwrap());
    }

    #[test]
    fn validate_pause_with_trees_and_reject() {
        let gi = GlobalIntrinsic::new(Arc::new(RejectAll));
        let pt = make_prover_tree();
        let at = make_alloc_tree(1);
        assert!(!gi.validate(1, &pause_bytes(), Some(&pt), Some(&at)).unwrap());
    }

    #[test]
    fn validate_pause_wrong_allocation_status() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let pt = make_prover_tree();
        let at = make_alloc_tree(2); // paused, not active
        assert!(gi.validate(1, &pause_bytes(), Some(&pt), Some(&at)).is_err());
    }

    #[test]
    fn validate_join_structural() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let join = crate::global_intrinsic::ProverJoin {
            filters: vec![vec![0x01u8; 32]],
            frame_number: 100,
            public_key_signature_bls48581: Some(
                crate::global_intrinsic::SignatureWithPop {
                    signature: vec![0xAAu8; 74],
                    public_key: Some(vec![0xBBu8; 585]),
                    pop_signature: vec![0xCCu8; 74],
                },
            ),
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![0xDDu8; 516],
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(gi.validate(105, &join, None, None).unwrap());
    }

    #[test]
    fn validate_rejects_unknown_type() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let bad = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(gi.validate(1, &bad, None, None).is_err());
    }

    #[test]
    fn validate_rejects_short_input() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        assert!(gi.validate(1, &[0, 0], None, None).is_err());
    }

    #[test]
    fn validate_confirm_structural_only() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let confirm = crate::global_intrinsic::ProverConfirm {
            filter: vec![],
            frame_number: 500,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
            filters: vec![vec![0xDDu8; 32]],
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(gi.validate(1, &confirm, None, None).unwrap());
    }
}
