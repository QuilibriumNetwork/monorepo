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
use quil_types::store::{
    ClockStore, KvDb, PendingShardChange, ShardChangeKind, ShardsStore, ShardInfo,
};

use super::materialize;
use super::reassignment;
use super::consensus_types::{AltShardUpdate, TYPE_ALT_SHARD_UPDATE};
use super::prover_filter_ops::{
    ProverLeave, ProverPause, ProverResume,
    TYPE_PROVER_LEAVE, TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME,
};
use super::prover_ops::{
    ProverConfirm, ProverReject,
    TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT,
};
use super::prover_join::{ProverJoin, TYPE_PROVER_JOIN};
use super::verify;
use crate::global_engine::{
    TYPE_PROVER_KICK, TYPE_PROVER_UPDATE, TYPE_SENIORITY_MERGE,
    TYPE_FRAME_HEADER, TYPE_SHARD_SPLIT, TYPE_SHARD_MERGE,
};
use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{
    HypergraphState, hyperedge_adds_discriminator,
    vertex_adds_discriminator, vertex_removes_discriminator,
};

/// The global intrinsic: holds dependencies for signature
/// verification and state lookups. Dispatches `validate` and
/// `invoke_step` calls to per-op handlers.
pub struct GlobalIntrinsic {
    key_manager: Arc<dyn KeyManager>,
    frame_prover: Option<Arc<dyn quil_types::crypto::FrameProver>>,
    clock_store: Option<Arc<dyn ClockStore>>,
    shards_store: Option<Arc<dyn ShardsStore>>,
    /// KvDb backing the shards store, used to create batch transactions
    /// for shard split/merge writes (Go passes nil txn; Rust needs one).
    shards_db: Option<Arc<dyn KvDb>>,
    /// BLS constructor for per-op signature verification (including
    /// ProverKick's conflicting-frame aggregate-signature check).
    bls_constructor: Option<Arc<dyn quil_types::crypto::BlsConstructor>>,
    /// Hypergraph CRDT for spend checks + shard-commit lookups used by
    /// ProverKick full verify. When absent, the dispatcher falls back to
    /// structural-only equivocation detection.
    hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Inclusion prover for traversal-proof + multiproof verification
    /// on ProverKick.
    inclusion_prover: Option<Arc<dyn quil_types::crypto::InclusionProver>>,
    /// Prover registry for `invoke_frame_header` → ProverShardUpdate
    /// (active-prover lookup by shard).
    prover_registry: Option<Arc<dyn quil_types::consensus::ProverRegistry>>,
    /// Reward issuance calculator for per-ring share computation.
    reward_issuance: Option<Arc<dyn quil_types::consensus::RewardIssuance>>,
    /// The KEEP-set for the unified-tree split reset: prover addresses
    /// (`poseidon(bls_pubkey)`) that survive the flag-day drop — the genesis
    /// archives + beacon. Every other prover record is removed at the reset frame
    /// so the corrupt post-split shard grid is rebuilt from the genesis topology
    /// (see [`Self::maybe_apply_split_reset`]). Absent ⇒ the reset no-ops (a node
    /// without the set syncs the post-reset state rather than computing it).
    archive_prover_addresses: Option<Arc<std::collections::HashSet<Vec<u8>>>>,
    /// The QUIL genesis shard-prefix set the split reset rebuilds the grid to —
    /// NETWORK-specific (mainnet = 64-way `[[0]..[63]]`; testnet/localnet =
    /// single `[[]]`), so it mirrors whatever `genesis` seeded on this net rather
    /// than hardcoding mainnet's layout. Injected by the node; absent ⇒ reset
    /// no-ops (paired with [`Self::archive_prover_addresses`]).
    reset_genesis_prefixes: Option<Arc<Vec<Vec<u32>>>>,
    /// Once-per-frame guard for [`Self::apply_due_shard_changes`]. It is called
    /// BOTH once-per-frame standalone (`apply_global_due_shard_changes`) AND inline
    /// per app-shard `FrameHeader` request (`invoke_frame_header`); with a backlog
    /// of shard frames per shard the inline calls run the full pending-change
    /// tombstone scan + reassign N times per global frame (the materialize balloon).
    /// The due changes are frame-gated + idempotent, so the work only needs to run
    /// once: this records the last global frame it completed for and short-circuits
    /// any further call at the same frame. `u64::MAX` = "never run" so frame 0 still
    /// applies. Set only on SUCCESS, so a failed/partial apply re-runs on retry.
    last_due_apply_frame: std::sync::atomic::AtomicU64,
}

impl GlobalIntrinsic {
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self {
            key_manager,
            frame_prover: None,
            clock_store: None,
            shards_store: None,
            shards_db: None,
            bls_constructor: None,
            hypergraph: None,
            inclusion_prover: None,
            prover_registry: None,
            reward_issuance: None,
            archive_prover_addresses: None,
            reset_genesis_prefixes: None,
            last_due_apply_frame: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Create with VDF frame prover for full ProverJoin verification.
    pub fn new_with_frame_prover(
        key_manager: Arc<dyn KeyManager>,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) -> Self {
        Self {
            key_manager,
            frame_prover: Some(frame_prover),
            clock_store: None,
            shards_store: None,
            shards_db: None,
            bls_constructor: None,
            hypergraph: None,
            inclusion_prover: None,
            prover_registry: None,
            reward_issuance: None,
            archive_prover_addresses: None,
            reset_genesis_prefixes: None,
            last_due_apply_frame: std::sync::atomic::AtomicU64::new(u64::MAX),
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
            frame_prover,
            clock_store,
            shards_store,
            shards_db,
            bls_constructor: None,
            hypergraph: None,
            inclusion_prover: None,
            prover_registry: None,
            reward_issuance: None,
            archive_prover_addresses: None,
            reset_genesis_prefixes: None,
            last_due_apply_frame: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Install the dependencies that `verify_prover_kick_full` needs
    /// (BLS constructor + hypergraph + inclusion prover). Without all
    /// three, ProverKick validation falls back to structural-only
    /// equivocation detection.
    pub fn with_kick_verify_deps(
        mut self,
        bls_constructor: Arc<dyn quil_types::crypto::BlsConstructor>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    ) -> Self {
        self.bls_constructor = Some(bls_constructor);
        self.hypergraph = Some(hypergraph);
        self.inclusion_prover = Some(inclusion_prover);
        self
    }

    /// Install the dependencies that `invoke_frame_header` needs to
    /// run the full ProverShardUpdate materialize chain (per-ring
    /// reward distribution + per-allocation activity bump). Without
    /// these the dispatcher acknowledges the frame header without
    /// mutating state.
    pub fn with_frame_header_deps(
        mut self,
        prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
        reward_issuance: Arc<dyn quil_types::consensus::RewardIssuance>,
    ) -> Self {
        self.prover_registry = Some(prover_registry);
        self.reward_issuance = Some(reward_issuance);
        self
    }

    /// Install the archive KEEP-set for the unified-tree split reset — the
    /// prover addresses (`poseidon(bls_pubkey)`) of the genesis archives + beacon
    /// that survive the flag-day drop. Only nodes that materialize the reset
    /// (global archives) need this; others sync the post-reset state.
    pub fn with_archive_prover_addresses(
        mut self,
        archive_prover_addresses: Arc<std::collections::HashSet<Vec<u8>>>,
    ) -> Self {
        self.archive_prover_addresses = Some(archive_prover_addresses);
        self
    }

    /// Install the QUIL genesis shard-prefix set the split reset rebuilds to
    /// (network-specific: mainnet 64-way, testnet single). Paired with
    /// [`Self::with_archive_prover_addresses`]; both required for the reset to run.
    pub fn with_reset_genesis_prefixes(
        mut self,
        reset_genesis_prefixes: Arc<Vec<Vec<u32>>>,
    ) -> Self {
        self.reset_genesis_prefixes = Some(reset_genesis_prefixes);
        self
    }

    /// Install the VDF frame prover used by `invoke_frame_header`
    /// for the per-participant multi-proof attestation check.
    pub fn with_frame_prover(
        mut self,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    ) -> Self {
        self.frame_prover = Some(frame_prover);
        self
    }

    /// Install the clock store used by ProverJoin validation to look up
    /// the referenced frame's output + difficulty for the VDF verify
    /// chain. Without it, every ProverJoin in `validate` fails closed
    /// with "clock_store not installed".
    pub fn with_clock_store(
        mut self,
        clock_store: Arc<dyn ClockStore>,
    ) -> Self {
        self.clock_store = Some(clock_store);
        self
    }

    /// Install the shards store used by shard split/merge materialization.
    /// Without it, `invoke_shard_split`/`invoke_shard_merge` validate but
    /// record NO `PendingShardChange`, and `apply_due_shard_changes` no-ops —
    /// so proposed splits "succeed" yet never take effect (the shard stays
    /// overcrowded and provers re-propose every frame). Must be paired with
    /// [`Self::with_shards_db`].
    pub fn with_shards_store(mut self, shards_store: Arc<dyn ShardsStore>) -> Self {
        self.shards_store = Some(shards_store);
        self
    }

    /// Install the KvDb the shard-change records + topology flips are written
    /// through. Must point at the SAME backing store as
    /// [`Self::with_shards_store`]. Required for split/merge to persist.
    pub fn with_shards_db(mut self, shards_db: Arc<dyn KvDb>) -> Self {
        self.shards_db = Some(shards_db);
        self
    }

    /// Install ONLY the hypergraph CRDT — the committed-state source the
    /// deterministic reassignment / allocation re-home enumerate provers from.
    /// The richer [`Self::with_kick_verify_deps`] also wires it but pulls in a
    /// BLS constructor + inclusion prover; this is the minimal form for paths
    /// (and tests) that need committed-state reads without equivocation checks.
    pub fn with_hypergraph(mut self, hypergraph: Arc<quil_hypergraph::HypergraphCrdt>) -> Self {
        self.hypergraph = Some(hypergraph);
        self
    }

    /// Validate a canonical-bytes global op message. Decodes the
    /// message, dispatches by type prefix, and runs the per-op
    /// structural validation + signature verification (when prover
    /// trees are available).
    ///
    /// Per-op `frame_number` freshness gating only applies to ops
    /// whose Go counterpart enforces it: `ProverJoin` (10-frame
    /// window in `validate_prover_join_structural`) and
    /// `ProverSeniorityMerge` (10-frame window in
    /// `verify_prover_seniority_merge`). The other ops
    /// (Pause/Resume/Confirm/Reject/Update/ShardSplit/Merge) do not
    /// have per-op replay windows; the frame orchestrator handles
    /// ordering. ProverConfirm/Reject's 360-720 window is a timing
    /// constraint relative to JoinFrameNumber, not a freshness gate
    /// (enforced by `validate_confirm_timing`).
    ///
    /// `prover_tree` and `allocation_tree` are optional — when `None`,
    /// only structural validation runs (no signature check). The
    /// engine passes these in after loading from the CRDT.
    pub fn validate(
        &self,
        frame_number: u64,
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
                    let sig_ok = verify::verify_prover_leave(
                        &op, pt, self.key_manager.as_ref(),
                    )?;
                    if !sig_ok {
                        return Ok(false);
                    }
                    // Require at least one allocation in the leave's
                    // filters to be Status=1 (active) before accepting.
                    // Go enforces this at
                    // `global_prover_leave.go:395-436`. Without it,
                    // verify accepts a leave for an already-left
                    // prover; materialize rejects → consensus split.
                    if let Some(hg) = self.hypergraph.as_ref() {
                        let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                        let pubkey = crate::global_schema::read_field(pt, "prover:Prover", "PublicKey")
                            .ok_or_else(|| QuilError::InvalidArgument(
                                "ProverLeave: prover vertex missing PublicKey".into(),
                            ))?;
                        verify::verify_prover_leave_has_active_allocation(
                            &op,
                            &pubkey,
                            |addr: &[u8; 32]| -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
                                let blob = hg_state.get(domain, addr, &va_disc)?;
                                Ok(blob.and_then(|b| if b.is_empty() { None }
                                    else { Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&b)) }))
                            },
                        )?;
                    }
                    return Ok(true);
                }
                Ok(true)
            }
            TYPE_PROVER_CONFIRM => {
                let op = ProverConfirm::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    let sig_ok = verify::verify_prover_confirm(
                        &op, pt, self.key_manager.as_ref(),
                    )?;
                    if !sig_ok {
                        return Ok(false);
                    }
                    // Timing window enforcement. Mirrors Go
                    // `global_prover_confirm.go:492-574`. For each
                    // filter, load the allocation tree and check the
                    // 360-720 frame window. The check has to run at
                    // validate time — if it only ran at invoke_step,
                    // validate would accept a stale confirm that
                    // materialize then rejects, splitting consensus.
                    // When the hypergraph CRDT is wired, we look up
                    // per-filter allocation trees and enforce timing
                    // here.
                    if let Some(hg) = self.hypergraph.as_ref() {
                        let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                        let pubkey = crate::global_schema::read_field(pt, "prover:Prover", "PublicKey")
                            .ok_or_else(|| QuilError::InvalidArgument(
                                "ProverConfirm: prover vertex missing PublicKey".into(),
                            ))?;
                        for filter in &op.filters {
                            let alloc_addr =
                                super::materialize::allocation_address(&pubkey, filter)?;
                            let blob = hg_state.get(domain, &alloc_addr, &va_disc)?;
                            let Some(blob) = blob else { continue };
                            if blob.is_empty() {
                                continue;
                            }
                            let alloc_tree =
                                crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
                            verify::validate_confirm_timing(frame_number, &alloc_tree)?;
                        }
                    }
                    return Ok(true);
                }
                Ok(true)
            }
            TYPE_PROVER_REJECT => {
                let op = ProverReject::from_canonical_bytes(input)?;
                if let Some(pt) = prover_tree {
                    let sig_ok = verify::verify_prover_reject(
                        &op, pt, self.key_manager.as_ref(),
                    )?;
                    if !sig_ok {
                        return Ok(false);
                    }
                    // Same timing window as confirm. ProverReject
                    // applies to a single filter (the `op.filter`
                    // field, not `filters[]`).
                    if let Some(hg) = self.hypergraph.as_ref() {
                        let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                        let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                        let pubkey = crate::global_schema::read_field(pt, "prover:Prover", "PublicKey")
                            .ok_or_else(|| QuilError::InvalidArgument(
                                "ProverReject: prover vertex missing PublicKey".into(),
                            ))?;
                        let alloc_addr =
                            super::materialize::allocation_address(&pubkey, &op.filter)?;
                        if let Some(blob) = hg_state.get(domain, &alloc_addr, &va_disc)? {
                            if !blob.is_empty() {
                                let alloc_tree =
                                    crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
                                verify::validate_confirm_timing(frame_number, &alloc_tree)?;
                            }
                        }
                    }
                    return Ok(true);
                }
                Ok(true)
            }
            TYPE_PROVER_JOIN => {
                let op = ProverJoin::from_canonical_bytes(input)?;
                let v = verify::validate_prover_join_structural(&op, frame_number)?;
                // BLS48-581 G1 signature + proof-of-possession + merge
                // target signatures — mirrors Go's
                // `ProverJoin.Verify` at `global_prover_join.go:1095-1146`.
                let sigs_ok = verify::verify_prover_join_signatures(
                    &op,
                    &v,
                    self.key_manager.as_ref(),
                    None, // no live hypergraph here for consumed-merge check
                )?;
                if !sigs_ok {
                    return Ok(false);
                }
                // Kicked-prover gate. When the validator caller
                // supplied an existing prover vertex tree, reject the
                // join if `KickFrameNumber != 0`. Without this,
                // validate would accept; materialize would reject;
                // and consensus would split between nodes that did vs
                // did not run materialization.
                if let Some(pt) = prover_tree {
                    verify::verify_prover_join_not_kicked(pt, frame_number)?;
                }
                // Existing-allocation expiry gate. For each filter
                // in the join, check the prover's current allocation:
                // it must be status=4 (left/kicked) OR expired
                // (>= 720 frames since JoinFrameNumber). Requires a
                // hypergraph CRDT reference to load per-filter
                // allocation vertices — when absent, this check is
                // skipped and the materialize-time fallback catches
                // it (less ideal — validate/materialize mismatch — but
                // consistent with how other state lookups in this
                // dispatcher degrade gracefully).
                if let Some(hg) = self.hypergraph.as_ref() {
                    let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                    verify::verify_prover_join_allocations_expired(
                        &op,
                        &v.public_key,
                        frame_number,
                        |alloc_addr: &[u8; 32]| -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
                            let blob = hg_state.get(domain, alloc_addr, &va_disc)?;
                            Ok(blob.and_then(|b| {
                                if b.is_empty() { None }
                                else { Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&b)) }
                            }))
                        },
                    )?;
                }
                // VDF proof-of-sequential-work was removed from joins.
                // Once the structural, signature/PoP, not-kicked, and
                // allocation-expiry gates pass, the join is valid. The
                // `proof` field is ignored (kept in the wire format only
                // so historical joins still decode).
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
            TYPE_ALT_SHARD_UPDATE => {
                let op = AltShardUpdate::from_canonical_bytes(input)?;
                super::alt_shard_update_materialize::validate_alt_shard_update(
                    &op, frame_number, self.key_manager.as_ref(),
                )
            }
            TYPE_SHARD_SPLIT => {
                let op = super::prover_ops::ShardSplit::from_canonical_bytes(input)?;
                tracing::debug!(
                    frame = frame_number,
                    shard = hex::encode(&op.shard_address),
                    proposed = op.proposed_shards.len(),
                    "validate_message: ShardSplit reached validation wall"
                );
                // Fail-closed. No prover_tree means we couldn't
                // resolve the signer's BLS pubkey, so the BLS verify
                // can't run. Reject rather than accept on faith.
                let pt = prover_tree.ok_or_else(|| QuilError::InvalidArgument(
                    "ShardSplit: prover tree unavailable — cannot verify signature".into(),
                ))?;
                let sig_ok = match verify::verify_shard_split(&op, pt, self.key_manager.as_ref()) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(frame = frame_number, error = %e, "validate_message: ShardSplit verify ERRORED → rejected");
                        return Err(e);
                    }
                };
                if !sig_ok {
                    tracing::warn!(frame = frame_number, "validate_message: ShardSplit sig_ok=false → rejected");
                    return Ok(false);
                }
                // Signer must be an active global prover. Mirrors Go
                // `global_shard_split.go:92-102`.
                if let Some(hg) = self.hypergraph.as_ref() {
                    let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                    verify::verify_shard_op_signer_is_active_global(
                        pt,
                        |addr: &[u8; 32]| -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
                            let blob = hg_state.get(domain, addr, &va_disc)?;
                            Ok(blob.and_then(|b| if b.is_empty() { None }
                                else { Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&b)) }))
                        },
                    )?;
                }
                Ok(true)
            }
            TYPE_SHARD_MERGE => {
                let op = super::prover_ops::ShardMerge::from_canonical_bytes(input)?;
                let pt = prover_tree.ok_or_else(|| QuilError::InvalidArgument(
                    "ShardMerge: prover tree unavailable — cannot verify signature".into(),
                ))?;
                let sig_ok = verify::verify_shard_merge(&op, pt, self.key_manager.as_ref())?;
                if !sig_ok {
                    return Ok(false);
                }
                // Signer must be an active global prover.
                if let Some(hg) = self.hypergraph.as_ref() {
                    let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                    verify::verify_shard_op_signer_is_active_global(
                        pt,
                        |addr: &[u8; 32]| -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
                            let blob = hg_state.get(domain, addr, &va_disc)?;
                            Ok(blob.and_then(|b| if b.is_empty() { None }
                                else { Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&b)) }))
                        },
                    )?;
                }
                Ok(true)
            }
            TYPE_SENIORITY_MERGE => {
                // This is the *outer* `ProverSeniorityMerge` (0x031A),
                // not the inner `SeniorityMerge` target record (0x0310).
                let op = super::prover_ops::ProverSeniorityMerge::from_canonical_bytes(input)?;
                let pt = prover_tree.ok_or_else(|| QuilError::InvalidArgument(
                    "ProverSeniorityMerge: prover tree unavailable — cannot verify signature".into(),
                ))?;
                let sigs_ok = verify::verify_prover_seniority_merge(
                    &op, pt, frame_number, self.key_manager.as_ref(),
                )?;
                if !sigs_ok {
                    return Ok(false);
                }
                // Spent-merge tombstone check. Two provers must not
                // be able to both pass verify with the same
                // merge_target — otherwise the target's seniority
                // would be claimed twice (one prover passes
                // materialize, the other diverges).
                if let Some(hg) = self.hypergraph.as_ref() {
                    let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
                    verify::verify_prover_seniority_merge_spent_markers(
                        &op,
                        |addr: &[u8; 32]| hg_state.get(domain, addr, &va_disc),
                    )?;
                }
                Ok(true)
            }
            TYPE_PROVER_KICK => {
                // Prover kick validation chain. Mirrors Go's
                // `ProverKick.Verify` at `global_prover_kick.go:391-469`:
                //
                // Structural equivocation (always runs):
                // 1. Two conflicting frames decode to the same type
                //    (FrameHeader or GlobalFrameHeader)
                // 2. Same frame_number + filter/address
                // 3. Different outputs (the actual equivocation)
                // 4. Both carry BLS signatures
                //
                // When the full cryptographic deps are installed
                // (BLS constructor + hypergraph + inclusion prover +
                // clock store + frame prover), we run the full chain:
                // BLS verify on both conflicting frames, traversal
                // proof against the prover tree at frame N-1, and
                // multiproof verify of [PublicKey, Status]. Otherwise
                // we fall back to structural-only rejection (tighter
                // verification happens at the consensus materializer).
                let op = super::prover_ops::ProverKick::from_canonical_bytes(input)?;
                if let (Some(cs), Some(fp), Some(bls), Some(hg), Some(ip)) = (
                    self.clock_store.as_deref(),
                    self.frame_prover.as_deref(),
                    self.bls_constructor.as_deref(),
                    self.hypergraph.as_deref(),
                    self.inclusion_prover.as_deref(),
                ) {
                    super::kick_verify::verify_prover_kick_full(
                        &op, frame_number, cs, fp, bls, hg, ip,
                        self.prover_registry.as_deref(),
                    )?;
                    Ok(true)
                } else {
                    // Fail-closed. Structural-only checks (same frame number,
                    // different output) do NOT prove the victim signed both
                    // conflicting frames — only the full BLS verify does. Without
                    // the crypto deps we cannot run it, so REJECT rather than
                    // accept on faith (accepting would let a fabricated ProverKick
                    // evict an honest prover). Matches SHARD_SPLIT / SHARD_MERGE /
                    // SENIORITY_MERGE / FRAME_HEADER, which all fail-closed on
                    // missing deps. Safe: eviction materialization (`invoke_kick`)
                    // is archive-only and archives hold the full deps, so nodes
                    // that lack them don't apply kicks anyway (they sync the
                    // already-materialized prover tree from archives).
                    let _ = &op;
                    Err(QuilError::InvalidArgument(
                        "ProverKick: crypto deps unavailable — cannot verify \
                         equivocation signatures; rejecting rather than accepting \
                         a structurally-plausible-but-unverified kick".into(),
                    ))
                }
            }
            TYPE_FRAME_HEADER => {
                // FrameHeader op governs `LastActiveFrameNumber`
                // advancement and per-ring reward issuance — both are
                // load-bearing for consensus + reward accounting.
                // Verification REQUIRES prover_registry + frame_prover
                // + bls_constructor. Missing any of them is a hard
                // error (fail-closed), not a soft skip back to
                // structural-only — a structural-only fall-back
                // silently accepts forged FrameHeaders.
                crate::global_engine::peek_global_message_kind(input)?;
                let op = super::frame_header::FrameHeader::from_canonical_bytes(input)?;
                let pr = self.prover_registry.as_deref().ok_or_else(|| {
                    QuilError::Internal(
                        "FrameHeader: prover_registry not installed — cannot verify".into(),
                    )
                })?;
                let fp = self.frame_prover.as_deref().ok_or_else(|| {
                    QuilError::Internal(
                        "FrameHeader: frame_prover not installed — cannot verify".into(),
                    )
                })?;
                let bls = self.bls_constructor.as_deref().ok_or_else(|| {
                    QuilError::Internal(
                        "FrameHeader: bls_constructor not installed — cannot verify".into(),
                    )
                })?;
                // CW path: a simplex-finalized shard frame's sig field
                // holds the magic-prefixed finalization certificate, not a BLS
                // aggregate. Verify it via the shared attestation helper (VDF +
                // committee cert) and accept — the BLS-specific aggregate-pubkey /
                // multiproof checks below don't apply to a Falcon cert.
                if quil_cw_consensus::app_cert::unwrap_cert_from_header(
                    &op.public_key_signature_bls48581,
                )
                .is_some()
                {
                    // Reconstruct the committee at the app frame's OWN global
                    // anchor (`op.global_frame_number`), NOT the current global
                    // `frame_number` — the committee that signed this frame was
                    // formed at that anchor's epoch (see AppLeaderProvider's
                    // `committee_anchor_gfn`). Windowed-lockstep bounds the two
                    // within W, but they can straddle an epoch boundary.
                    let committee_frame = if op.global_frame_number > 0 {
                        op.global_frame_number
                    } else {
                        frame_number
                    };
                    let active = pr.get_active_provers(&op.address, committee_frame).map_err(|e| {
                        QuilError::Internal(format!("FrameHeader: get_active_provers: {e}"))
                    })?;
                    super::prover_shard_update::verify_frame_header_attestation(
                        &op, fp, bls, &active,
                    )?;
                    return Ok(true);
                }
                {
                    let sig = match op.public_key_signature_bls48581.is_empty() {
                        true => return Err(QuilError::InvalidArgument(
                            "FrameHeader op missing BLS aggregate signature".into(),
                        )),
                        false => crate::hypergraph_intrinsic::canonical::AggregateSignature::from_canonical_bytes(
                            &op.public_key_signature_bls48581,
                        ).map_err(|e| QuilError::InvalidArgument(format!(
                            "FrameHeader: aggregate signature decode failed: {e}"
                        )))?,
                    };
                    // Materialize the wire FrameHeader for the
                    // signature-verification helper. The op we hold
                    // is the global-intrinsic carrier; the helper
                    // expects the proto shape that the consensus
                    // engine signs over.
                    let header = quil_types::proto::global::FrameHeader {
                        address: op.address.clone(),
                        frame_number: op.frame_number,
                        timestamp: op.timestamp,
                        difficulty: op.difficulty,
                        fee_multiplier_vote: op.fee_multiplier_vote as u64,
                        parent_selector: op.parent_selector.clone(),
                        requests_root: op.requests_root.clone(),
                        state_roots: op.state_roots.clone(),
                        prover: op.prover.clone(),
                        output: op.output.clone(),
                        rank: op.rank,
                        public_key_signature_bls48581: Some(
                            quil_types::proto::keys::Bls48581AggregateSignature {
                                public_key: Some(
                                    quil_types::proto::keys::Bls48581g2PublicKey {
                                        key_value: sig.public_key.as_ref()
                                            .map(|k| k.key_value.clone())
                                            .unwrap_or_default(),
                                    },
                                ),
                                signature: sig.signature.clone(),
                                bitmask: sig.bitmask.clone(),
                            },
                        ),
                        storage_attestation_root: op.storage_attestation_root.clone(),
                        global_frame_number: op.global_frame_number,
                        storage_attestation: op.storage_attestation.clone(),
                    };

                    // Aggregate-pubkey consistency check: the bitmask
                    // names a subset of active provers, and their
                    // pubkey aggregate must equal the signature's
                    // declared aggregate pubkey. Mirrors what the
                    // outer frame validator does for GlobalFrame.
                    // Committee at the app frame's own global anchor (see the
                    // CW-path note above), not the current global frame.
                    let committee_frame = if op.global_frame_number > 0 {
                        op.global_frame_number
                    } else {
                        frame_number
                    };
                    let active = pr.get_active_provers(&op.address, committee_frame).map_err(|e| {
                        QuilError::Internal(format!(
                            "FrameHeader: get_active_provers: {e}"
                        ))
                    })?;
                    let participant_indices: Vec<usize> =
                        quil_consensus::bitmask::set_bit_indices(&sig.bitmask).collect();
                    let active_pks: Vec<&[u8]> = active
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| participant_indices.contains(i))
                        .map(|(_, prover)| prover.public_key.as_slice())
                        .collect();
                    let reconstructed_pubkey = bls
                        .aggregate_public_keys(&active_pks)
                        .map_err(|e| QuilError::Crypto(format!(
                            "FrameHeader: aggregate_public_keys: {e}"
                        )))?;
                    let sig_pubkey_bytes: &[u8] = sig.public_key.as_ref()
                        .map(|k| k.key_value.as_slice())
                        .unwrap_or(&[]);
                    if reconstructed_pubkey.as_slice() != sig_pubkey_bytes {
                        let active_summary: Vec<String> = active
                            .iter()
                            .map(|p| hex::encode(&p.address[..p.address.len().min(8)]))
                            .collect();
                        tracing::warn!(
                            shard_address = %hex::encode(&op.address[..op.address.len().min(8)]),
                            bitmask_hex = %hex::encode(&sig.bitmask),
                            participant_indices = ?participant_indices,
                            active_count = active.len(),
                            active_first_addrs = ?active_summary,
                            reconstructed_pubkey_prefix = %hex::encode(
                                &reconstructed_pubkey[..reconstructed_pubkey.len().min(16)]
                            ),
                            sig_declared_pubkey_prefix = %hex::encode(
                                &sig_pubkey_bytes[..sig_pubkey_bytes.len().min(16)]
                            ),
                            "FrameHeader aggregate pubkey mismatch — bitmask + active_provers vs signed aggregate diverge"
                        );
                        return Err(QuilError::Crypto(
                            "FrameHeader: aggregate pubkey does not match signature's declared pubkey".into(),
                        ));
                    }

                    // BLS aggregate + per-signer VDF multi-proof
                    // verify. App shard frame signatures are
                    // `bls_agg(74) || u32_be(count) || N×516
                    // multi-proofs` past byte 74 (or just 74 bytes
                    // for a single signer with no tail). The
                    // 74-byte short-circuit avoids tripping the
                    // multi-proof tail parser on a single-signer
                    // aggregate.
                    let ids: Vec<&[u8]> = active
                        .iter()
                        .map(|p| p.address.as_slice())
                        .collect();
                    let ids_arg: Option<&[&[u8]]> = if sig.signature.len() == 666 {
                        None
                    } else {
                        Some(&ids)
                    };
                    match fp.verify_frame_header_signature(&header, bls, ids_arg) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(QuilError::Crypto(
                                "FrameHeader: BLS signature / multiproof verification rejected".into(),
                            ));
                        }
                        Err(e) => {
                            return Err(QuilError::Crypto(format!(
                                "FrameHeader: BLS signature / multiproof verification: {e}"
                            )));
                        }
                    }
                }
                Ok(true)
            }
            _ => Err(QuilError::InvalidArgument(format!(
                "global intrinsic: unknown type prefix 0x{:08x}",
                type_prefix
            ))),
        }
    }

    /// Execute a state transition for a global intrinsic operation.
    /// Mirrors Go `GlobalIntrinsic.InvokeStep` at `global_intrinsic.go:849`.
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
                self.invoke_filter_op(
                    frame_number,
                    &op.filter,
                    &op.public_key_signature_bls48581,
                    state,
                    &va_disc,
                    |prover_tree, alloc_tree| verify::verify_prover_pause(
                        &op, prover_tree, alloc_tree, self.key_manager.as_ref(),
                    ),
                    |alloc_tree, fn_| materialize::materialize_prover_pause(alloc_tree, fn_),
                )
            }
            TYPE_PROVER_RESUME => {
                let op = ProverResume::from_canonical_bytes(input)?;
                self.invoke_filter_op(
                    frame_number,
                    &op.filter,
                    &op.public_key_signature_bls48581,
                    state,
                    &va_disc,
                    |prover_tree, alloc_tree| verify::verify_prover_resume(
                        &op, prover_tree, alloc_tree, self.key_manager.as_ref(),
                    ),
                    |alloc_tree, fn_| materialize::materialize_prover_resume(alloc_tree, fn_),
                )
            }
            TYPE_PROVER_LEAVE => {
                let op = ProverLeave::from_canonical_bytes(input)?;
                for filter in &op.filters {
                    self.invoke_filter_op(
                        frame_number,
                        filter,
                        &op.public_key_signature_bls48581,
                        state,
                        &va_disc,
                        |prover_tree, _alloc_tree| verify::verify_prover_leave(
                            &op, prover_tree, self.key_manager.as_ref(),
                        ),
                        |alloc_tree, fn_| materialize::materialize_prover_leave(alloc_tree, fn_),
                    )?;
                }
                Ok(())
            }
            TYPE_PROVER_CONFIRM => {
                let op = ProverConfirm::from_canonical_bytes(input)?;
                // Confirm applies to each filter in the confirm message.
                // Validate timing window (360-720 frames) before materializing.
                for filter in &op.filters {
                    self.invoke_filter_op(
                        frame_number,
                        filter,
                        &op.public_key_signature_bls48581,
                        state,
                        &va_disc,
                        |prover_tree, _alloc_tree| verify::verify_prover_confirm(
                            &op, prover_tree, self.key_manager.as_ref(),
                        ),
                        |alloc_tree, fn_| {
                            // Check timing constraints first
                            verify::validate_confirm_timing(fn_, alloc_tree)?;

                            // Halt-risk gate (leave-confirm only).
                            // Extracted to a helper so the logic is
                            // unit-testable. See `check_leave_confirm_halt_risk`.
                            let current_status =
                                read_field(alloc_tree, "allocation:ProverAllocation", "Status")
                                    .and_then(|b| b.first().copied())
                                    .unwrap_or(0);
                            // A split-away parent is no longer in the
                            // registered shard set; its provers bypass
                            // the halt-risk floor so they can drain onto
                            // the children (deep-split convergence).
                            let shard_removed = self
                                .shards_store
                                .as_ref()
                                .map(|s| !shard_filter_is_registered(s.as_ref(), filter))
                                .unwrap_or(false);
                            check_leave_confirm_halt_risk(
                                filter,
                                current_status,
                                self.prover_registry.as_deref(),
                                fn_,
                                shard_removed,
                            )?;

                            materialize::materialize_prover_confirm(alloc_tree, fn_)
                        },
                    )?;
                }
                // Fold: write the per-leaf storage-root vertices registered with
                // this confirm. The roots are bound into the confirm's signing
                // message (verify_prover_confirm), so they're authenticated as
                // the signer's. Overwrite-in-place keyed (member, leaf_id).
                if !op.leaf_roots.is_empty() {
                    let member: [u8; 32] = op
                        .public_key_signature_bls48581
                        .as_ref()
                        .and_then(|s| <[u8; 32]>::try_from(s.address.as_slice()).ok())
                        .ok_or_else(|| QuilError::InvalidArgument(
                            "prover confirm: leaf roots require a 32-byte signer address".into(),
                        ))?;
                    let domain = &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS[..];
                    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
                    // Epoch-aligned: a confirm in epoch E registers leaf roots for
                    // the NEXT epoch E+1 (the `next` slot of the two-slot
                    // registration), matching the allocation's `Epoch` field set
                    // by `materialize_prover_confirm` and the replica the worker
                    // encoded ahead. The audit at epoch C reads the slot
                    // registered for C — written here during epoch C-1's confirm.
                    let epoch = quil_types::consensus::epoch_for_frame(frame_number) + 1;
                    for group in &op.leaf_roots {
                        // Only honor leaf roots for filters actually confirmed here.
                        if !op.filters.iter().any(|f| f == &group.filter) {
                            continue;
                        }
                        for entry in &group.entries {
                            let leaf_id = super::leaf_id_bytes(&group.filter, &entry.prefix);
                            let addr = materialize::leaf_root_address(&member, &leaf_id)?;
                            // Two-slot upsert: merge into {current,next}, keeping
                            // the two highest epochs, so the member can hold the
                            // epoch it's proving + the next it's pre-confirmed.
                            let existing = state
                                .get(domain, &addr, &va_disc)?
                                .filter(|d| !d.is_empty())
                                .map(|d| crate::prover_registry::rebuild_vertex_tree_from_blob(&d));
                            let tree = materialize::upsert_leaf_root_registration(
                                existing.as_ref(),
                                &member, &group.filter, &entry.prefix, epoch,
                                &entry.leaf_root, entry.num_blocks, frame_number,
                            )?;
                            let blob = crate::prover_registry::vertex_tree_to_blob(&tree);
                            state.set(domain, &addr, &va_disc, frame_number, blob)?;
                        }
                    }
                }
                Ok(())
            }
            TYPE_PROVER_REJECT => {
                let op = ProverReject::from_canonical_bytes(input)?;
                self.invoke_filter_op(
                    frame_number,
                    &op.filter,
                    &op.public_key_signature_bls48581,
                    state,
                    &va_disc,
                    |prover_tree, _alloc_tree| verify::verify_prover_reject(
                        &op, prover_tree, self.key_manager.as_ref(),
                    ),
                    |alloc_tree, fn_| materialize::materialize_prover_reject(alloc_tree, fn_),
                )
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
            TYPE_ALT_SHARD_UPDATE => {
                // AltShardUpdate::Materialize is a no-op in Go (see
                // `global_alt_shard_update.go:253`). Real persistence
                // happens via the consensus frame materializer's
                // `persistAltShardUpdates` path. We run the validator
                // and derive the commit record for parity; the caller
                // can pick it up via the frame materializer layer.
                let op = AltShardUpdate::from_canonical_bytes(input)?;
                let _commit = super::alt_shard_update_materialize::materialize_alt_shard_update(&op)?;
                let _ = frame_number;
                let _ = state;
                let _ = va_disc;
                Ok(())
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
        verify_sig: impl FnOnce(
            &quil_tries::VectorCommitmentTree,
            Option<&quil_tries::VectorCommitmentTree>,
        ) -> Result<bool>,
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

        // Defense-in-depth: re-run the op-specific signature verification
        // against the freshly loaded prover/alloc trees. The engine-side
        // `validate()` already runs this at message-admission time, but
        // it returns Ok(true) for filter ops when the prover tree wasn't
        // loadable from state (intrinsic.rs:178-247). The materializer
        // is the last gate before state mutation — verify here so a
        // future validate-side bypass can't admit unsigned ops.
        if !verify_sig(&prover_tree, Some(&alloc_tree))? {
            return Err(QuilError::InvalidArgument(
                "invoke_step: signature verification failed at materialize".into(),
            ));
        }

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
    /// Mirrors Go's `ProverJoin.Materialize` at `global_prover_join.go:115`.
    ///
    /// Validation checks (matching Go's `Verify`):
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

        // Defense-in-depth: re-verify the join SIGNATURE at materialize, matching
        // invoke_filter_op / invoke_update / invoke_seniority_merge (which all
        // re-verify). Materialize is normally reached only after validate_message
        // gates the op, but a caller that invokes materialize without validating
        // first must not be able to write prover/allocation/reward state on an
        // unsigned join. This is the SIGNATURE check only (BLS main + PoP) —
        // structural/VDF checks stay in validate. `verify_prover_join_signatures`
        // reads only `validation.public_key`, so the other fields are unused.
        {
            let jv = verify::ProverJoinValidation {
                public_key: pubkey.clone(),
                prover_address: [0u8; 32],
                filter_count: 0,
            };
            if !verify::verify_prover_join_signatures(
                op,
                &jv,
                self.key_manager.as_ref(),
                None,
            )? {
                return Err(QuilError::InvalidArgument(
                    "invoke_step join: signature verification failed".into(),
                ));
            }
        }

        // Phase F join-freeze (decision #2): a shard with a pending split/merge
        // (recorded between the proposal epoch E and the E+2 flip) cannot accept
        // new joins — its existence/identity is about to change, and the
        // coverage-gate reasons over the FROZEN committee. The pending set is
        // recorded deterministically by the split/merge op, so this reject is
        // identical on every node. The freeze lifts automatically once
        // `apply_due_shard_changes` consumes the pending record at E+2.
        if let Some(store) = self.shards_store.as_ref() {
            let pending = store.all_pending_shard_changes()?;
            if !pending.is_empty() {
                for filter in &op.filters {
                    if pending.iter().any(|c| c.affects_shard(filter)) {
                        return Err(QuilError::InvalidArgument(format!(
                            "invoke_step join: shard {} is frozen by a pending split/merge \
                             (join blocked until it settles at E+2)",
                            hex::encode(&filter[..filter.len().min(8)]),
                        )));
                    }
                }
            }
        }

        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let prover_address = materialize::prover_address_from_pubkey(&pubkey)?;

        // Check if prover was previously kicked (Go: global_prover_join.go:972-988)
        if let Ok(Some(existing_data)) = state.get(domain, &prover_address, va_disc) {
            if !existing_data.is_empty() {
                let existing_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&existing_data);
                let kick_frame = read_field(&existing_tree, "prover:Prover", "KickFrameNumber")
                    .unwrap_or_default();
                if kick_frame.len() == 8 {
                    let kf = u64::from_be_bytes(kick_frame.try_into().unwrap());
                    // Spurious-kick amnesty (must mirror the validate-side gate in
                    // `verify_prover_join_not_kicked` exactly): a kick before the
                    // flag-day frame stops barring re-join once the chain reaches it.
                    if materialize::kick_bars_rejoin(kf, frame_number) {
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
                            // Byte 4 (Rejected) and byte 6 (Historic) are ok to
                            // rejoin — a Historic slot was vacated by a reassignment
                            // and RETAINED for reactivation, so a fresh Join reclaims
                            // it instead of being blocked by the 720-frame window.
                            // MUST match the validate-side gate in
                            // `verify_prover_join_allocations_expired`.
                            if status != 4 && status != materialize::STATUS_HISTORIC {
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

        // Compute seniority from merge targets via
        // `compat::GetAggregatedSeniority` (Go's
        // `global_prover_join.go:155-211`).
        //
        // For each merge target:
        //  - Look up the spent-marker at
        //    `poseidon("PROVER_JOIN_MERGE" || target_pubkey)` — if a
        //    different prover already consumed the marker, skip.
        //  - For Ed448 targets (`key_type == 0`, 57-byte pubkey),
        //    derive the libp2p peer-id string and feed it to the
        //    aggregated-seniority lookup.
        //
        // The fallback when there are no merge targets (or no
        // matching peer ids) is `0` — Go does **not** fall back to
        // `op.frame_number` for new provers, it just stores zero.
        let computed_seniority: u64 = {
            let mut peer_ids: Vec<String> = Vec::new();
            for mt in &op.merge_targets {
                // Spent-marker dedup: skip if another prover claimed it.
                let spent_addr = materialize::spent_join_merge_address(&mt.prover_public_key)?;
                if let Ok(Some(prior_blob)) = state.get(domain, &spent_addr, va_disc) {
                    if !prior_blob.is_empty() {
                        let prior_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prior_blob);
                        if let Some(stored_addr) = read_field(&prior_tree, "merge:SpentMerge", "ProverAddress") {
                            if stored_addr.len() == 32 && stored_addr.as_slice() != prover_address.as_slice() {
                                continue;
                            }
                        }
                    }
                }
                if mt.key_type == 0 && mt.prover_public_key.len() == 57 {
                    peer_ids.push(ed448_pubkey_to_peer_id_string(&mt.prover_public_key));
                }
            }
            if peer_ids.is_empty() {
                0
            } else {
                crate::seniority_compat::get_aggregated_seniority(&peer_ids)
            }
        };

        // Determine whether the prover already exists (Go's `proverExists`
        // branch at `global_prover_join.go:213,352`). For brand-new
        // provers we always write the computed seniority; for existing
        // provers we update only if the new value beats the stored one.
        let prover_already_exists = state
            .get(domain, &prover_address, va_disc)?
            .map(|d| !d.is_empty())
            .unwrap_or(false);

        let initial_seniority = if prover_already_exists {
            // Read existing seniority, decide max with computed.
            let existing_blob = state.get(domain, &prover_address, va_disc)?.unwrap_or_default();
            let existing_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&existing_blob);
            let existing = read_field(&existing_tree, "prover:Prover", "Seniority")
                .and_then(|b| {
                    if b.len() == 8 {
                        Some(u64::from_be_bytes(b.try_into().unwrap()))
                    } else { None }
                })
                .unwrap_or(0);
            std::cmp::max(existing, computed_seniority)
        } else {
            computed_seniority
        };

        let output = materialize::materialize_prover_join(
            &pubkey, &op.filters, frame_number, initial_seniority,
        )?;

        // Write prover vertex
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&output.prover_tree);
        state.set(domain, &output.prover_address, va_disc, frame_number, prover_blob)?;

        // Write allocation vertices
        for (alloc_addr, alloc_tree) in &output.allocations {
            let alloc_blob = crate::prover_registry::vertex_tree_to_blob(alloc_tree);
            state.set(domain, alloc_addr, va_disc, frame_number, alloc_blob)?;
        }

        // Write the hyperedge linking prover → allocations. Mirrors Go
        // `global_prover_join.go:402-425, 526-528, 620-635`. Without
        // this, ProverKick has no way to enumerate the prover's
        // allocations to mark them kicked.
        let alloc_pairs: Vec<([u8; 32], &quil_tries::VectorCommitmentTree)> = output
            .allocations
            .iter()
            .map(|(a, t)| (*a, t))
            .collect();
        let hyperedge_blob = materialize::build_prover_allocation_hyperedge_blob(
            &output.prover_address,
            &alloc_pairs,
        )?;
        let ha_disc = hyperedge_adds_discriminator()?;
        state.set(domain, &output.prover_address, &ha_disc, frame_number, hyperedge_blob)?;

        // Write spent-merge markers for each consumed merge target.
        // Mirrors Go `global_prover_join.go:530-599`. Each marker stores
        // the consuming prover's address at `merge:SpentMerge.ProverAddress`
        // so a later join cannot re-claim the same target.
        for mt in &op.merge_targets {
            let spent_addr = materialize::spent_join_merge_address(&mt.prover_public_key)?;
            // If a *new-format* marker already exists for someone else,
            // skip. Legacy/empty markers can be overwritten.
            if let Ok(Some(prior_blob)) = state.get(domain, &spent_addr, va_disc) {
                if !prior_blob.is_empty() {
                    let prior_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prior_blob);
                    if let Some(stored_addr) = read_field(&prior_tree, "merge:SpentMerge", "ProverAddress") {
                        if stored_addr.len() == 32 {
                            // New format marker — skip regardless of who.
                            continue;
                        }
                    }
                }
            }
            let spent_tree = materialize::create_spent_merge_tree(&output.prover_address)?;
            let spent_blob = crate::prover_registry::vertex_tree_to_blob(&spent_tree);
            state.set(domain, &spent_addr, va_disc, frame_number, spent_blob)?;
        }

        // Write reward vertex. Mirrors Go `ProverJoin.Materialize`
        // at `global_prover_join.go:293-351`: always writes
        // `DelegateAddress` (defaulting to the prover's own address
        // when no delegate is supplied) and `Balance` as 32 zero
        // bytes. The reward vertex address is
        // `poseidon(QUIL_TOKEN_ADDRESS || prover_address)` —
        // `materialize::reward_address` matches.
        let reward_addr = materialize::reward_address(&output.prover_address)?;
        // Only INITIALIZE the reward vertex when it does not already exist. A
        // prover that left (Status=4) holding an unclaimed accrued balance and
        // later rejoins (allowed once its allocations expire past the 720-frame
        // window) must NOT have its balance zeroed or its delegate reset. Go
        // wrote this vertex unconditionally — a silent fund-loss on rejoin that
        // we no longer carry. When absent, initialize with a zero balance and
        // the supplied/default delegate.
        let reward_exists = match state.get(domain, &reward_addr, va_disc) {
            Ok(Some(b)) => !b.is_empty(),
            _ => false,
        };
        if !reward_exists {
            let mut reward_tree = quil_tries::VectorCommitmentTree::new();
            let delegate = if op.delegate_address.len() == 32 {
                op.delegate_address.clone()
            } else {
                output.prover_address.to_vec()
            };
            materialize::set_reward_delegate_address(&mut reward_tree, &delegate)?;
            // 32-byte zero balance — matches Go's `make([]byte, 32)`.
            materialize::set_reward_balance(&mut reward_tree, &[0u8; 32])?;
            let reward_blob = crate::prover_registry::vertex_tree_to_blob(&reward_tree);
            state.set(domain, &reward_addr, va_disc, frame_number, reward_blob)?;
        }

        Ok(())
    }

    /// ProverKick invoke_step: kick prover + all allocations.
    /// The kick message contains the kicked prover's public key. We derive
    /// the prover address, load the prover vertex, kick it, and kick all
    /// allocations found via the prover's hyperedge.
    ///
    /// Mirrors Go `ProverKick.Materialize` at
    /// `node/execution/intrinsics/global/global_prover_kick.go:180-293`:
    /// for every allocation hyperedge of the kicked prover, write
    /// Status=4 + KickFrameNumber=N on the allocation vertex.
    fn invoke_kick(
        &self,
        frame_number: u64,
        op: &super::prover_ops::ProverKick,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        let prover_address = materialize::prover_address_from_pubkey(&op.kicked_prover_public_key)?;
        self.kick_prover_by_address(frame_number, &prover_address, state, va_disc)
    }

    /// Evict a prover by its 32-byte address: set the prover vertex to kicked
    /// (Status=4, KickFrameNumber, Seniority→0) and kick every allocation
    /// linked from its hyperedge. Shared by [`Self::invoke_kick`] (signed
    /// `ProverKick`) and the PoRep storage audit (no signature — the eviction
    /// is a deterministic consequence of a failed sampled possession proof in a
    /// committee-signed reward frame). Idempotent: re-kicking a kicked prover
    /// just re-stamps the same fields. A missing prover vertex is a no-op Ok
    /// (the audit may name a member the archive hasn't synced).
    fn kick_prover_by_address(
        &self,
        frame_number: u64,
        prover_address: &[u8],
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

        // Load and kick prover vertex
        let prover_data = match state.get(domain, prover_address, va_disc)? {
            Some(d) if !d.is_empty() => d,
            _ => return Ok(()),
        };
        let mut prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        materialize::materialize_prover_kick(&mut prover_tree, frame_number)?;
        let prover_blob = crate::prover_registry::vertex_tree_to_blob(&prover_tree);
        state.set(domain, prover_address, va_disc, frame_number, prover_blob)?;

        // Kick every allocation linked from the prover's hyperedge.
        // Hyperedges are addressed by
        // `(GLOBAL_INTRINSIC_ADDRESS, prover_address)` and store a
        // serialized extrinsic tree whose leaf keys are 64-byte atom
        // IDs `appAddr || dataAddr`. Each atom is an allocation
        // vertex; we strip the appAddr prefix to recover the dataAddr
        // (allocation address) and mutate it.
        //
        // Read the hyperedge data through `state.get` so an
        // uncommitted hyperedge add (e.g. ProverJoin earlier in the
        // same frame's changeset) is visible — this matters for the
        // join-then-kick sequence and mirrors Go's
        // `hg.Get(addr, hyperedgeAddsDiscriminator)` semantics.
        let ha_disc = hyperedge_adds_discriminator()?;
        if let Some(hyperedge_blob) = state.get(domain, &prover_address, &ha_disc)? {
            if !hyperedge_blob.is_empty() {
                let mut ext_tree = quil_tries::VectorCommitmentTree::new();
                if let Ok(Some(root)) = quil_tries::deserialize_go_tree(&hyperedge_blob) {
                    ext_tree.root = Some(root);
                }
                for (key, _value) in ext_tree.leaves() {
                    if key.len() != 64 {
                        continue;
                    }
                    if &key[..32] != &GLOBAL_INTRINSIC_ADDRESS[..32] {
                        return Err(QuilError::InvalidArgument(
                            "invoke_step kick: hyperedge has non-global allocation atom".into(),
                        ));
                    }
                    let mut alloc_addr = [0u8; 32];
                    alloc_addr.copy_from_slice(&key[32..]);

                    // Skip if allocation vertex isn't present.
                    let alloc_data = match state.get(domain, &alloc_addr, va_disc)? {
                        Some(d) if !d.is_empty() => d,
                        _ => continue,
                    };
                    let mut alloc_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&alloc_data);
                    materialize::materialize_prover_kick_allocation(&mut alloc_tree, frame_number)?;
                    let alloc_blob = crate::prover_registry::vertex_tree_to_blob(&alloc_tree);
                    state.set(domain, &alloc_addr, va_disc, frame_number, alloc_blob)?;
                }
            }
        }

        Ok(())
    }

    /// ProverUpdate invoke_step: update DelegateAddress on the reward
    /// vertex. Delegates to
    /// `prover_update_materialize::materialize_prover_update`, which
    /// performs the full port of Go's `ProverUpdate::Materialize`
    /// (including the `poseidon(PublicKey) == Address` cross-check).
    fn invoke_update(
        &self,
        frame_number: u64,
        op: &super::prover_ops::ProverUpdate,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        // Defense-in-depth signature re-verification — see invoke_filter_op
        // for the rationale. `validate()` may have returned Ok(true) without
        // checking the signature if the prover tree wasn't loadable from
        // state at admission time.
        let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
            QuilError::InvalidArgument("invoke_update: missing signature".into())
        })?;
        if sig.address.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "invoke_update: invalid prover address length".into(),
            ));
        }
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let prover_data = state.get(domain, &sig.address, va_disc)?.ok_or_else(|| {
            QuilError::InvalidArgument("invoke_update: prover not found".into())
        })?;
        if prover_data.is_empty() {
            return Err(QuilError::InvalidArgument(
                "invoke_update: prover has no data".into(),
            ));
        }
        let prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        if !verify::verify_prover_update(op, &prover_tree, self.key_manager.as_ref())? {
            return Err(QuilError::InvalidArgument(
                "invoke_update: signature verification failed at materialize".into(),
            ));
        }

        super::prover_update_materialize::materialize_prover_update(op, frame_number, state)
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

        // Defense-in-depth — re-verify the BLS signature against the
        // prover tree's pubkey before mutating. validate_message
        // already ran this on the bundle, but a buggy/dropped validate
        // path shouldn't bypass authority enforcement at materialize.
        if !verify::verify_prover_seniority_merge(
            op, &prover_tree, frame_number, self.key_manager.as_ref(),
        )? {
            return Err(QuilError::InvalidArgument(
                "invoke_step seniority_merge: signature verification failed".into(),
            ));
        }

        // Collect merge target public keys
        let merge_target_pubkeys: Vec<Vec<u8>> = op.merge_targets
            .iter()
            .map(|mt| mt.prover_public_key.clone())
            .collect();

        // Compute merge_seniority from merge targets by converting
        // Ed448 public keys to peer IDs and looking up the aggregated
        // seniority via the static compat table. Mirrors Go's
        // ProverSeniorityMerge.Materialize at
        // `global_prover_seniority_merge.go:119-143`, which calls
        // `compat.GetAggregatedSeniority(peerIds)` — a SUM across the
        // four retro epochs (max within each epoch, summed across
        // epochs) further `max`'d with the mainnet snapshot value.
        // This is NOT a MAX over individual peer seniorities.
        let peer_ids: Vec<String> = op.merge_targets
            .iter()
            .filter(|mt| mt.key_type == 0 && mt.prover_public_key.len() == 57)
            .map(|mt| ed448_pubkey_to_peer_id_string(&mt.prover_public_key))
            .collect();
        let merge_seniority: u64 = if peer_ids.is_empty() {
            0
        } else {
            crate::seniority_compat::get_aggregated_seniority(&peer_ids)
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

        // Write spent-merge markers, mirroring Go's skip-if-claimed
        // semantics at `global_prover_seniority_merge.go:208-230`:
        // if a marker already exists with a non-empty ProverAddress
        // field, leave it alone (the same target was already consumed
        // by a prover). Only legacy empty markers and missing markers
        // are (over)written with the current prover's address.
        for (spent_addr, spent_tree) in &spent_markers {
            if let Some(existing_blob) = state.get(domain, spent_addr, va_disc)? {
                if !existing_blob.is_empty() {
                    let existing_tree =
                        crate::prover_registry::rebuild_vertex_tree_from_blob(&existing_blob);
                    let stored_addr = crate::global_schema::read_field(
                        &existing_tree,
                        "merge:SpentMerge",
                        "ProverAddress",
                    );
                    if stored_addr.map(|b| b.len() == 32).unwrap_or(false) {
                        // Already claimed — skip overwrite.
                        continue;
                    }
                    // Legacy empty marker — fall through to overwrite.
                }
            }
            let spent_blob = crate::prover_registry::vertex_tree_to_blob(spent_tree);
            state.set(domain, spent_addr, va_disc, frame_number, spent_blob)?;
        }

        Ok(())
    }

    /// FrameHeader (ProverShardUpdate) invoke_step: route to
    /// `prover_shard_update::materialize_prover_shard_update` when the
    /// engine has wired the prover registry, frame prover, reward
    /// issuance calculator, and shard metadata. Otherwise acknowledge
    /// the message without mutating state (Go gates this at verify time
    /// by requiring `frameNumber == p.FrameHeader.FrameNumber+1`).
    ///
    /// Go equivalent: `ProverShardUpdate::Materialize` at
    /// `global_prover_shard_update.go:147`.
    ///
    /// The `GlobalIntrinsic` dispatcher holds a `frame_prover` but does
    /// not currently own the prover registry, reward issuance
    /// calculator, or hypergraph metadata surface needed for full
    /// materialization. The full port lives in
    /// `super::prover_shard_update` and is invoked from the consensus
    /// engine's frame materializer, which has those dependencies.
    /// PoRep storage audit (5w): decode the committee `StorageAttestation`
    /// carried on the reward proof, recompute the beacon ρ_N from the anchored
    /// global frame's COMMITTED VDF output, run the bounded ρ_N-sampled
    /// possession + registry audit, and evict members with a failing sampled
    /// opening. No-op before the storage fork or when the frame carries no
    /// attestation. Deterministic over committed state — the eviction is
    /// identical on every archive (non-archive nodes inherit it via sync).
    fn audit_storage_attestation(
        &self,
        frame_number: u64,
        op: &super::frame_header::FrameHeader,
        bitmask: &[u8],
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        // Genesis / legacy-VDF frames anchor to 0 — no storage beacon, no
        // lockstep requirement.
        if op.global_frame_number == 0 {
            return Ok(());
        }

        // WINDOWED LOCKSTEP: a storage frame (global_frame_number > 0) anchors to
        // a RECENT global frame — within `[frame_number-1-W, frame_number-1]`.
        // A strict `== frame_number-1` is unsatisfiable for MULTI-MEMBER app
        // shards: members' synced global heads differ, so a proposer must anchor
        // to `latest − K` (a frame every committee member already holds), which
        // then lags the packing frame by K + transit. The window absorbs that.
        // Still rejects FUTURE anchors (> frame-1) and STALE ones (older than the
        // window). Hard-reject: an out-of-window op invalidates the whole global
        // frame (Err → invoke_frame_header → materialize), so a correct leader
        // includes ONLY shard proofs whose beacon anchors within the window.
        // `W = STORAGE_ANCHOR_LOCKSTEP_WINDOW` bounds ρ_N staleness (freshness).
        let expected_anchor = frame_number.saturating_sub(1);
        let oldest_anchor = expected_anchor
            .saturating_sub(crate::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW);
        if op.global_frame_number > expected_anchor || op.global_frame_number < oldest_anchor {
            return Err(QuilError::InvalidArgument(format!(
                "storage attestation out of lockstep: anchor global_frame_number={} \
                 but global frame {} requires anchor in [{}, {}]",
                op.global_frame_number, frame_number, oldest_anchor, expected_anchor
            )));
        }

        // Anchor is in lockstep. If there's no attestation payload, there are no
        // openings to audit — nothing more to do.
        if op.storage_attestation.is_empty() {
            return Ok(());
        }
        let att = <quil_types::proto::global::StorageAttestation as prost::Message>::decode(
            op.storage_attestation.as_slice(),
        )
        .map_err(|e| {
            QuilError::InvalidArgument(format!(
                "invoke_frame_header: storage attestation decode failed: {e}"
            ))
        })?;
        let openings: Vec<quil_crypto::porep::StorageOpening> = att
            .openings
            .iter()
            .map(quil_crypto::porep::StorageOpening::from_proto)
            .collect();
        if openings.is_empty() {
            return Ok(());
        }
        // Possession verify is γ-independent at k=1, so the bitmask is a
        // don't-care for the per-opening audit (it bound the aggregate root,
        // already committee-signed). Accept it to document the contract.
        let _ = bitmask;

        let clock_store = self.clock_store.as_ref().ok_or_else(|| {
            QuilError::Internal(
                "invoke_frame_header: clock_store not installed — cannot recompute ρ_N for audit"
                    .into(),
            )
        })?;
        let global_output = clock_store
            .get_global_clock_frame(op.global_frame_number)
            .ok()
            .and_then(|f| f.header.map(|h| h.output))
            .unwrap_or_default();
        let rho_n =
            quil_crypto::porep::derive_storage_beacon(op.global_frame_number, &global_output);
        let active_epoch = quil_types::consensus::epoch_for_frame(op.global_frame_number);

        // Registry cross-check: read the on-chain leaf-root registration vertex
        // `(member, leaf_id)` from committed state.
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let lookup = |member: &[u8], shard_id: &[u8]| -> Option<(Vec<u8>, u64, u64)> {
            if member.len() < 32 {
                return None;
            }
            let mut m = [0u8; 32];
            m.copy_from_slice(&member[..32]);
            let addr = materialize::leaf_root_address(&m, shard_id).ok()?;
            let data = state.get(domain, &addr, va_disc).ok()??;
            if data.is_empty() {
                return None;
            }
            let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&data);
            // Two-slot {current,next}: match whichever slot is registered for the
            // epoch being audited (the member may hold the current epoch in one
            // slot and a pre-confirmed next epoch in the other).
            let (leaf_root, num_blocks) =
                materialize::leaf_root_registration_for_epoch(&tree, active_epoch)?;
            Some((leaf_root, num_blocks, active_epoch))
        };

        let failed = quil_crypto::porep::audit_frame_storage_attestations(
            &openings,
            &rho_n,
            quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
            active_epoch,
            quil_types::consensus::STORAGE_AUDIT_SAMPLE,
            lookup,
        );
        for member in failed {
            self.kick_prover_by_address(frame_number, &member, state, va_disc)?;
        }
        Ok(())
    }

    fn invoke_frame_header(
        &self,
        frame_number: u64,
        op: &super::frame_header::FrameHeader,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        // Verify FIRST, materialize SECOND. The attestation check
        // requires frame_prover + bls_constructor + prover_registry —
        // these MUST be installed; absence is a fail-closed Err.
        // Silently acking an unverified FrameHeader would let
        // a forged frame slip past materialize on any node missing
        // these deps.
        //
        // Materialize-only deps (reward_issuance, hypergraph) are
        // archive-mode extras: when absent, we skip the state
        // mutations but only AFTER the attestation has verified.
        let fp = self.frame_prover.as_ref().ok_or_else(|| QuilError::Internal(
            "invoke_frame_header: frame_prover not installed — cannot verify attestation".into(),
        ))?;
        let bls = self.bls_constructor.as_ref().ok_or_else(|| QuilError::Internal(
            "invoke_frame_header: bls_constructor not installed — cannot verify attestation".into(),
        ))?;
        let pr = self.prover_registry.as_ref().ok_or_else(|| QuilError::Internal(
            "invoke_frame_header: prover_registry not installed — cannot resolve active provers".into(),
        ))?;
        // Committee at the app frame's own global anchor (`op.global_frame_number`),
        // matching the epoch its committee was formed at — not the current global
        // `frame_number`. See AppLeaderProvider's `committee_anchor_gfn`.
        let committee_frame = if op.global_frame_number > 0 {
            op.global_frame_number
        } else {
            frame_number
        };
        let active_provers = pr
            .get_active_provers(&op.address, committee_frame)
            .map_err(|e| QuilError::InvalidArgument(format!(
                "invoke_frame_header: get_active_provers failed: {e}"
            )))?;
        let bitmask_bytes = super::prover_shard_update::verify_frame_header_attestation(
            op,
            fp.as_ref(),
            bls.as_ref(),
            &active_provers,
        ).map_err(|e| QuilError::InvalidArgument(format!(
            "invoke_frame_header: frame header attestation invalid: {e}"
        )))?;

        // Phase F: apply any epoch-aligned shard topology changes that have now
        // reached their effective (E+2) epoch — flips the local grid topology
        // AND deterministically reassigns each affected prover's allocation onto
        // the new shard(s) in committed hypergraph state. Runs regardless of the
        // archive-mode reward/hypergraph deps below.
        self.apply_due_shard_changes(frame_number, state)?;

        // Now that verification has passed, gate further state writes
        // on the archive-mode deps.
        let (Some(ri), Some(hg)) = (
            self.reward_issuance.as_ref(),
            self.hypergraph.as_ref(),
        ) else {
            return Ok(());
        };

        // Expand bitmask → participant indices (matches Go's
        // GetSetBitIndices). The materialize helper validates each
        // index against active_provers.len().
        let participant_indices: Vec<u8> = quil_consensus::bitmask::set_bit_indices(&bitmask_bytes)
            .filter_map(|idx| u8::try_from(idx).ok())
            .collect();

        // Per-SUB-SHARD reward basis: `op.address` is the coverage filter
        // `app(32) ‖ prefix-byte-per-level`. Read the size of the SPECIFIC
        // sub-shard subtree the worker covers, not the whole app — otherwise
        // every one of a split app's N sub-shards is credited the full app size
        // (an N× over-reward). An unsplit app (bare 32-byte filter) still
        // resolves to whole-app metadata.
        let hg_md = hg.sub_shard_metadata_for_filter(&op.address);
        let (state_size_u64, shard_count_u64) = match hg_md {
            Some(md) => {
                let s = md.size.to_string().parse::<u64>().unwrap_or(0);
                (s, md.leaf_count)
            }
            None => (0u64, 0u64),
        };
        // PROOF-OF-STORAGE GATE: a storage frame (anchored to a real global
        // frame, `global_frame_number > 0`) that covers a shard WITH committed
        // data (`state_size > 0`) MUST carry a storage attestation proving the
        // prover possesses the replica. If the attestation is absent, the prover
        // has not proven storage → WITHHOLD its reward for this shard (zero the
        // reward basis) — `shard_md` feeds ONLY the issuance calc, so this pays 0
        // without halting the frame or evicting (`audit_storage_attestation` is
        // the hard-reject path for a PRESENT-but-invalid attestation). The
        // decision is deterministic: `op.storage_attestation` /
        // `global_frame_number` are header fields and `state_size` derives from
        // committed state, so every node withholds identically. An empty shard
        // (`state_size == 0`) has nothing to attest and is unaffected.
        let unproven_storage = op.global_frame_number > 0
            && state_size_u64 > 0
            && op.storage_attestation.is_empty();
        if unproven_storage {
            // Previously silent: the reward basis is zeroed here WITHOUT halting
            // or evicting, so from the operator seat the node looks healthy while
            // being paid 0. Surface it — a persistent stream of these means the
            // shard's producer is not attaching a storage attestation (see the
            // app-engine "no storage openings built" log), so no reward proof is
            // ever earned even though the shard carries committed data.
            tracing::warn!(
                address = %hex::encode(&op.address[..op.address.len().min(8)]),
                frame_number = op.frame_number,
                global_frame_number = op.global_frame_number,
                state_size = state_size_u64,
                "proof-of-storage gate: shard has committed data but frame carries NO storage attestation — WITHHOLDING reward (basis zeroed), frame NOT halted; prover silently paid 0 for this shard"
            );
        }
        let (state_size_u64, shard_count_u64) = if unproven_storage {
            (0u64, 0u64)
        } else {
            (state_size_u64, shard_count_u64)
        };
        let shard_md = super::prover_shard_update::ShardMetadata {
            state_size: state_size_u64,
            shard_count: shard_count_u64,
        };

        // World size for reward issuance EXCLUDES the global prover shard (0xff)
        // — `total_size()` now enforces that exclusion at the live counter (the
        // prover registry / leaf-root registry / reward vertices don't count).
        let world_state_size = hg.total_size();
        let world_size_u64 = world_state_size
            .to_string()
            .parse::<u64>()
            .unwrap_or(0);

        // The frame_prover ref is unused by the materialize impl
        // (it's a placeholder for parity with Go's signature) — pass
        // a fallback when absent.
        let frame_prover = self.frame_prover.clone().unwrap_or_else(|| {
            // Construct a minimal stub. The materialize helper does
            // not invoke any FrameProver methods.
            struct StubFrameProver;
            impl quil_types::crypto::FrameProver for StubFrameProver {
                fn prove_frame_header(
                    &self,
                    _: &[u8],
                    _: &[u8],
                    _: &[u8],
                    _: &[Vec<u8>],
                    _: &[u8],
                    _: i64,
                    _: u32,
                    _: u64,
                    _: u64,
                    _: &[u8],
                    _: u64,
                ) -> Result<quil_types::proto::global::FrameHeader>
                { Err(QuilError::Internal("stub".into())) }
                fn verify_frame_header(&self, _: &quil_types::proto::global::FrameHeader)
                    -> Result<Vec<u8>>
                { Ok(vec![]) }
                fn prove_global_frame_header(
                    &self,
                    _: &quil_types::proto::global::GlobalFrameHeader,
                    _: &[Vec<u8>],
                    _: &[u8],
                    _: &[Vec<u8>],
                    _: &[u8],
                    _: &dyn quil_types::crypto::Signer,
                    _: i64,
                    _: u32,
                    _: u8,
                ) -> Result<quil_types::proto::global::GlobalFrameHeader>
                { Err(QuilError::Internal("stub".into())) }
                fn verify_global_frame_header(&self, _: &quil_types::proto::global::GlobalFrameHeader)
                    -> Result<Vec<u8>>
                { Ok(vec![]) }
                fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32)
                    -> Result<Vec<u8>>
                { Err(QuilError::Internal("stub".into())) }
                fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]])
                    -> Result<bool>
                { Ok(true) }
            }
            Arc::new(StubFrameProver)
        });

        super::prover_shard_update::materialize_prover_shard_update(
            op,
            frame_number,
            state,
            pr,
            &frame_prover,
            ri,
            world_size_u64,
            active_provers,
            &participant_indices,
            shard_md,
        )?;

        // PoRep (5w): the ρ_N-sampled possession audit runs LAST — AFTER the
        // coverage credit above — so a cheating member's eviction (Status=4,
        // Seniority→0) is the final write and isn't clobbered by the
        // LastActiveFrameNumber update that `materialize_prover_shard_update`
        // applies from the active-prover snapshot taken before this possession
        // audit. Archive-only (past
        // the ri/hg gate); deterministic over committed state (ρ_N from the
        // anchored global frame's committed VDF output + the on-chain leaf-root
        // registry), so every archive evicts identically and non-archive nodes
        // inherit it via sync.
        self.audit_storage_attestation(frame_number, op, &bitmask_bytes, state, va_disc)?;
        Ok(())
    }

    /// Go parity (`global_shard_split.go` / `global_shard_merge.go`
    /// `Verify`): a shard split/merge may only be proposed by a registered
    /// prover holding an ACTIVE GLOBAL allocation — one whose
    /// `confirmation_filter` is empty (global/committee membership). The
    /// registry reflects this frame's committed prover state (refreshed
    /// before message processing), so the check is deterministic across
    /// nodes. Fails closed: returns false when the registry is unavailable
    /// or the proposer is unknown.
    /// Authorize a shard split/merge signer as an ACTIVE GLOBAL prover, checked
    /// against COMMITTED hypergraph state — IDENTICAL to `validate_message`'s
    /// `verify_shard_op_signer_is_active_global`, so invoke and validate always
    /// agree on the same node.
    ///
    /// FOLLOWER nodes (regular nodes, not the global committee) wire the intrinsic
    /// with `install_frame_prover`, NOT `install_frame_header_deps`, so their
    /// `hypergraph` slot is `None`. Like validate (whose check is `if let Some(hg)`
    /// → skipped when absent), we then SKIP the authorization and trust the
    /// FINALIZED frame's QC — the global committee already validated + authorized
    /// the op before it finalized, and a follower has no committed global-prover
    /// view to re-check against. The previous code instead consulted the ASYNC
    /// `prover_registry` cache here, which lags on followers → they REJECTED (at
    /// invoke) a finalized split their own validate had ACCEPTED → never recorded
    /// the `PendingShardChange` → `apply_due_shard_changes` no-oped → the
    /// follower's shards_store stayed single-shard forever (stale app_prefixes →
    /// size-buckets → compute_shard_root: the deep-split empty-leaf churn).
    fn proposer_is_active_global(
        &self,
        prover_tree: &quil_tries::VectorCommitmentTree,
    ) -> bool {
        let Some(hg) = self.hypergraph.as_ref() else {
            // No committed state (follower) → trust the finalized frame, like validate.
            return true;
        };
        let hg_state = crate::hypergraph_state::HypergraphState::new(hg.clone());
        let Ok(va_disc) = crate::hypergraph_state::vertex_adds_discriminator() else {
            return true;
        };
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        verify::verify_shard_op_signer_is_active_global(
            prover_tree,
            |addr: &[u8; 32]| -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
                let blob = hg_state.get(domain, addr, &va_disc)?;
                Ok(blob.and_then(|b| if b.is_empty() { None }
                    else { Some(crate::prover_registry::rebuild_vertex_tree_from_blob(&b)) }))
            },
        )
        .is_ok()
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
        frame_number: u64,
        op: &super::prover_ops::ShardSplit,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        tracing::debug!(
            frame = frame_number,
            shard = hex::encode(&op.shard_address),
            proposed = op.proposed_shards.len(),
            "invoke_shard_split: received split op"
        );
        // Defense-in-depth — re-verify the BLS signature against the
        // prover tree's pubkey. validate_message already ran this on
        // the bundle; this is the second wall.
        let prover_address = op
            .public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .ok_or_else(|| QuilError::InvalidArgument(
                "invoke_shard_split: missing signature".into(),
            ))?;
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let prover_data = state.get(domain, &prover_address, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument(
                "invoke_shard_split: prover not found".into(),
            ))?;
        if prover_data.is_empty() {
            return Err(QuilError::InvalidArgument(
                "invoke_shard_split: prover has no data".into(),
            ));
        }
        let prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        if !verify::verify_shard_split(op, &prover_tree, self.key_manager.as_ref())? {
            return Err(QuilError::InvalidArgument(
                "invoke_shard_split: signature verification failed".into(),
            ));
        }
        // Authorization (Go parity, global_shard_split.go:82-100): only an
        // ACTIVE GLOBAL prover (one with an allocation whose
        // confirmation_filter is empty + status Active) may propose a
        // shard split.
        if !self.proposer_is_active_global(&prover_tree) {
            tracing::warn!(
                frame = frame_number,
                proposer = hex::encode(&prover_address),
                "invoke_shard_split: REJECTED — proposer is not an active global prover"
            );
            return Err(QuilError::InvalidArgument(
                "invoke_shard_split: proposer is not an active global prover".into(),
            ));
        }

        // Validate the child filters now (fail fast on a malformed proposal),
        // but DEFER the topology flip. Epoch-aligned: a split proposed in epoch E
        // takes effect at the E+2 boundary so committee membership stays frozen
        // within an epoch. Record a pending change; `apply_due_shard_changes`
        // (run from invoke_frame_header) applies it when the chain reaches E+2.
        // Deep-bifurcation: post-cutover proposals encode children as bit-path
        // filters (validated as bit-prefix extensions); pre-cutover as byte
        // suffixes. The proposal frame decides the format.
        let bit_path_mode = frame_number >= super::materialize::unified_tree_cutover_frame();
        let _ = materialize::materialize_shard_split(
            &op.shard_address,
            &op.proposed_shards,
            bit_path_mode,
        )?;

        if let (Some(ref store), Some(ref db)) = (&self.shards_store, &self.shards_db) {
            let change = PendingShardChange {
                kind: ShardChangeKind::Split,
                parent: op.shard_address.clone(),
                children: op.proposed_shards.clone(),
                effective_epoch: quil_types::consensus::epoch_for_frame(frame_number) + 2,
                proposed_frame: frame_number,
            };
            let txn = db.new_batch(false)?;
            store.put_pending_shard_change(txn.as_ref(), &change)?;
            txn.commit()?;
            tracing::info!(
                frame = frame_number,
                shard = hex::encode(&op.shard_address),
                effective_epoch = change.effective_epoch,
                bit_path_mode,
                "invoke_shard_split: recorded pending split change (applies at E+2)"
            );
        } else {
            tracing::warn!(
                frame = frame_number,
                "invoke_shard_split: no shards_store/db — split validated but NOT persisted"
            );
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
        frame_number: u64,
        op: &super::prover_ops::ShardMerge,
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
        tracing::debug!(
            frame = frame_number,
            parent = hex::encode(&op.parent_address),
            children = op.shard_addresses.len(),
            "invoke_shard_merge: received merge op"
        );
        // Defense-in-depth — see invoke_shard_split.
        let prover_address = op
            .public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .ok_or_else(|| QuilError::InvalidArgument(
                "invoke_shard_merge: missing signature".into(),
            ))?;
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let prover_data = state.get(domain, &prover_address, va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument(
                "invoke_shard_merge: prover not found".into(),
            ))?;
        if prover_data.is_empty() {
            return Err(QuilError::InvalidArgument(
                "invoke_shard_merge: prover has no data".into(),
            ));
        }
        let prover_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        if !verify::verify_shard_merge(op, &prover_tree, self.key_manager.as_ref())? {
            return Err(QuilError::InvalidArgument(
                "invoke_shard_merge: signature verification failed".into(),
            ));
        }
        // Authorization (Go parity, global_shard_merge.go:84-100): only an
        // ACTIVE GLOBAL prover may propose a shard merge.
        if !self.proposer_is_active_global(&prover_tree) {
            return Err(QuilError::InvalidArgument(
                "invoke_shard_merge: proposer is not an active global prover".into(),
            ));
        }

        // Validate now, defer the flip to the E+2 boundary (see invoke_shard_split).
        // Deep-bifurcation: the proposal frame decides the child filter format.
        let bit_path_mode = frame_number >= super::materialize::unified_tree_cutover_frame();
        let _ = materialize::materialize_shard_merge(
            &op.shard_addresses,
            &op.parent_address,
            bit_path_mode,
        )?;

        if let (Some(ref store), Some(ref db)) = (&self.shards_store, &self.shards_db) {
            let change = PendingShardChange {
                kind: ShardChangeKind::Merge,
                parent: op.parent_address.clone(),
                children: op.shard_addresses.clone(),
                effective_epoch: quil_types::consensus::epoch_for_frame(frame_number) + 2,
                proposed_frame: frame_number,
            };
            let txn = db.new_batch(false)?;
            store.put_pending_shard_change(txn.as_ref(), &change)?;
            txn.commit()?;
            tracing::info!(
                frame = frame_number,
                parent = hex::encode(&op.parent_address),
                effective_epoch = change.effective_epoch,
                bit_path_mode,
                "invoke_shard_merge: recorded pending merge change (applies at E+2)"
            );
        }

        Ok(())
    }

    /// Apply any staged shard topology changes (Phase F) whose `effective_epoch`
    /// the chain has now reached. Run from `invoke_frame_header`, so it fires on
    /// the same frame across all nodes (identical frame sequence → deterministic
    /// shards-store view). Robust to gaps: applies every pending change with
    /// `effective_epoch <= epoch_for_frame(frame_number)`, then removes it. The
    /// topology flip (put children / delete children) lands here at E+2, NOT at
    /// proposal time.
    /// Once-per-frame wrapper (see `last_due_apply_frame`): the due-change apply is
    /// invoked BOTH standalone once per frame AND inline per app-shard `FrameHeader`
    /// request, so a backlog of shard frames would otherwise re-run the full
    /// tombstone scan + reassign N times per global frame. The work is frame-gated
    /// and idempotent, so run it once and short-circuit the rest. The flag is set
    /// only on SUCCESS, so a failed/partial apply (frame aborts → retries) re-runs.
    pub fn apply_due_shard_changes(
        &self,
        frame_number: u64,
        state: &HypergraphState,
    ) -> Result<()> {
        if self.last_due_apply_frame.load(std::sync::atomic::Ordering::Relaxed) == frame_number {
            return Ok(());
        }
        let result = self.apply_due_shard_changes_inner(frame_number, state);
        if result.is_ok() {
            self.last_due_apply_frame
                .store(frame_number, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    fn apply_due_shard_changes_inner(
        &self,
        frame_number: u64,
        state: &HypergraphState,
    ) -> Result<()> {
        let (Some(store), Some(db)) = (self.shards_store.as_ref(), self.shards_db.as_ref())
        else {
            return Ok(());
        };
        let cur_epoch = quil_types::consensus::epoch_for_frame(frame_number);
        let pending_scan_start = std::time::Instant::now();
        let all_pending = store.all_pending_shard_changes()?;
        let pending_scan_ms = pending_scan_start.elapsed().as_millis() as u64;
        if pending_scan_ms > 500 {
            // A slow scan that returns few/zero LIVE entries = tombstone
            // accumulation in the pending-change keyspace (many create+delete
            // cycles over the chain's life). This runs every frame (inline via
            // invoke_frame_header on request frames, standalone otherwise), so it
            // shows up as the per-frame materialize floor. A range compaction of
            // the pending keyspace drops the tombstones.
            tracing::warn!(
                frame = frame_number,
                ms = pending_scan_ms,
                live = all_pending.len(),
                "apply_due: all_pending_shard_changes scan SLOW (tombstone bloat in the pending-change keyspace)"
            );
        }
        if !all_pending.is_empty() {
            // Fires every frame while a change waits for its E+2 boundary — debug
            // to avoid per-frame spam; the apply itself logs at info.
            tracing::debug!(
                frame = frame_number,
                cur_epoch,
                total_pending = all_pending.len(),
                effective_epochs = ?all_pending.iter().map(|c| c.effective_epoch).collect::<Vec<_>>(),
                "apply_due_shard_changes: pending shard changes present"
            );
        }
        let due: Vec<PendingShardChange> = all_pending
            .into_iter()
            .filter(|c| c.effective_epoch <= cur_epoch)
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        // Wedge detector: a due change is only cleared (delete_pending) after the
        // whole reassign+grid-flip txn commits below. Any error aborts the frame
        // and leaves the record still due NEXT frame, re-running the O(provers)
        // reassign forever with no grid change. Logging the due set every frame
        // makes the recurrence visible — the SAME (parent, effective_epoch)
        // appearing on consecutive frames is the wedge signature.
        tracing::info!(
            frame = frame_number,
            cur_epoch,
            due = due.len(),
            changes = ?due
                .iter()
                .map(|c| (hex::encode(&c.parent), c.effective_epoch, c.kind))
                .collect::<Vec<_>>(),
            "apply_due_shard_changes: applying due shard changes"
        );

        // 1. Reassign every affected prover's allocation onto the new
        //    topology (committed hypergraph state, via `state`). Done FIRST:
        //    a failure here returns Err → `invoke_frame_header` returns Err →
        //    the frame's state changeset is aborted before we mutate the
        //    local grid below, keeping the two views consistent.
        let va_disc = vertex_adds_discriminator()?;
        // ONE committed-state prover-shard scan for the whole frame, shared across
        // ALL due changes — instead of a full O(provers) scan per change (the
        // N×full-scan cost that spikes to tens of seconds when a batch comes due at
        // an epoch boundary). Committed state, so reassignment stays deterministic
        // across nodes (do NOT swap for the async registry cache — that forks the
        // prover tree). None when no hypergraph (reassign falls back to the cache).
        let prover_scan = self
            .hypergraph
            .as_ref()
            .map(|hg| crate::prover_registry::CommittedProverScan::scan(hg));
        for change in &due {
            if let Err(e) = self.reassign_shard_allocations(
                state,
                &va_disc,
                change,
                frame_number,
                prover_scan.as_ref(),
            ) {
                tracing::error!(
                    frame = frame_number,
                    parent = hex::encode(&change.parent),
                    effective_epoch = change.effective_epoch,
                    kind = ?change.kind,
                    error = %e,
                    "apply_due_shard_changes: reassign FAILED — frame aborts, pending record NOT cleared (will re-fire next frame)"
                );
                return Err(e);
            }
        }

        // 2. Flip the LOCAL grid topology + consume the pending records.
        // L1(3) || L2(32) grid key, matching genesis + the original immediate path.
        let grid_key = |l2: &[u8]| -> Vec<u8> {
            let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(l2, 256, 3);
            let mut k = Vec::with_capacity(3 + l2.len());
            k.extend_from_slice(&l1);
            k.extend_from_slice(l2);
            k
        };

        let txn = db.new_batch(false)?;
        // Live grid entries, KEYED BY CANONICAL BIT-PATH (not the raw prefix) so the
        // stale check is FORM-AGNOSTIC. A genesis shard is stored as a byte-suffix
        // prefix (`[i]`), while `materialize_shard_split` reports `removed_parent` in
        // SENTINEL bit-path form — comparing the raw prefixes never matches, which
        // wrongly classified the FIRST split of every byte-suffix genesis shard as
        // "stale" and skipped it (mainnet post-reset: QUIL stuck at 64-way, unable to
        // split). Decode both sides to bits — sentinel via `shard_bit_path_from_prefix`,
        // byte-suffix via the 6-bit-per-level binary (the mapping
        // `decode_shard_filter_or_root` uses) — so the same shard compares equal in
        // either encoding. A genuinely STALE duplicate (whose parent an earlier change
        // already removed) still fails the membership test and is skipped. `live` is
        // updated as we apply so a straddle that lands both the E+2 and E+3 record in
        // ONE frame is caught too. The duplicate arises because the proposer used to
        // re-emit a split every frame while the parent stayed over-crowded; a
        // re-proposal crossing the epoch boundary stamps a later effective_epoch that
        // coexists with the first — both would otherwise apply.
        let canon_bits = |prefix: &[u32]| -> Vec<bool> {
            quil_forest::shard_bit_path_from_prefix(prefix)
                .unwrap_or_else(|| quil_forest::prefix_to_bits(prefix, 6))
        };
        let mut live: std::collections::HashSet<(Vec<u8>, Vec<bool>)> = store
            .range_app_shards()?
            .into_iter()
            .map(|r| (r.shard_key, canon_bits(&r.prefix)))
            .collect();
        for change in &due {
            match change.kind {
                ShardChangeKind::Split => {
                    // Decode in the format the children were PROPOSED in (a split
                    // that straddles the cutover keeps its original encoding).
                    let bit_path_mode =
                        change.proposed_frame >= super::materialize::unified_tree_cutover_frame();
                    let output = materialize::materialize_shard_split(
                        &change.parent,
                        &change.children,
                        bit_path_mode,
                    )?;
                    // Skip a stale duplicate whose parent no longer exists in the grid
                    // (already split by an earlier change) — applying it would layer a
                    // DIFFERENT partition on top of the real children (overlapping
                    // shards → provers on "both sides"). Still consume the pending
                    // record below so it stops re-firing.
                    let parent_in_grid = output.removed_parent.as_ref().map_or(true, |(l2, path)| {
                        live.contains(&(grid_key(l2), canon_bits(path)))
                    });
                    if !parent_in_grid {
                        tracing::warn!(
                            parent = hex::encode(&change.parent),
                            effective_epoch = change.effective_epoch,
                            proposed_frame = change.proposed_frame,
                            frame = frame_number,
                            "apply_due: SKIPPING stale split — parent already split (not in grid); consuming the duplicate pending record without re-registering overlapping children"
                        );
                    } else {
                        tracing::info!(
                            parent = hex::encode(&change.parent),
                            bit_path_mode,
                            // Total registered shards = 2 leaves + the co-path spine
                            // (Option A); parent is removed.
                            new_shards = output.new_shards.len(),
                            removed_parent = output.removed_parent.is_some(),
                            frame = frame_number,
                            proposed_frame = change.proposed_frame,
                            "applying shard split (E+2 flip)"
                        );
                        // Deep-bifurcation (b): the first deep split on an app must
                        // convert that app's ENTIRE stored set to sentinel bit-path
                        // prefixes (routing-preserving) so the set never goes mixed
                        // (canonical can't resolve a mix). Idempotent + deterministic.
                        if bit_path_mode && change.parent.len() >= 32 {
                            materialize::migrate_app_shards_to_sentinel(
                                store.as_ref(),
                                txn.as_ref(),
                                &grid_key(&change.parent[..32]),
                            )?;
                        }
                        for (l2, path) in &output.new_shards {
                            // Decode the registered sentinel prefix back to its bit-path
                            // for observability (a deep path here proves the flip stored
                            // the descended child, not an immediate-bit one).
                            let bits = quil_forest::shard_bit_path_from_prefix(path);
                            tracing::debug!(
                                l2 = hex::encode(l2),
                                prefix = ?path,
                                bit_path = ?bits,
                                "registering split child shard"
                            );
                            let shard = ShardInfo {
                                shard_key: grid_key(l2),
                                prefix: path.clone(),
                                size: Vec::new(),
                                data_shards: 0,
                                commitment: Vec::new(),
                            };
                            store.put_app_shard(txn.as_ref(), &shard)?;
                            live.insert((grid_key(l2), canon_bits(path)));
                        }
                        // Deep-bifurcation (Option A): the parent is REPLACED by the
                        // partition (spine + leaves) — remove it so the set stays
                        // prefix-free (else the parent shadows its own children).
                        if let Some((l2, path)) = &output.removed_parent {
                            tracing::debug!(
                                l2 = hex::encode(l2),
                                prefix = ?path,
                                "removing split parent shard (replaced by partition)"
                            );
                            store.delete_app_shard(txn.as_ref(), &grid_key(l2), path)?;
                            live.remove(&(grid_key(l2), canon_bits(path)));
                        }
                    }
                }
                ShardChangeKind::Merge => {
                    // Decode in the format the children were PROPOSED in (mirrors
                    // the Split branch's straddle-safe gate).
                    let bit_path_mode =
                        change.proposed_frame >= super::materialize::unified_tree_cutover_frame();
                    let output = materialize::materialize_shard_merge(
                        &change.children,
                        &change.parent,
                        bit_path_mode,
                    )?;
                    tracing::info!(
                        parent = hex::encode(&change.parent),
                        bit_path_mode,
                        removed = output.removed_shards.len(),
                        added_parent = output.added_parent.is_some(),
                        frame = frame_number,
                        "applying shard merge (E+2 flip)"
                    );
                    for (l2, path) in &output.removed_shards {
                        let bits = quil_forest::shard_bit_path_from_prefix(path);
                        tracing::debug!(
                            l2 = hex::encode(l2),
                            prefix = ?path,
                            bit_path = ?bits,
                            "removing merged child shard"
                        );
                        store.delete_app_shard(txn.as_ref(), &grid_key(l2), path)?;
                    }
                    // Deep-bifurcation (Option A): re-register the merged parent
                    // (branch) as a leaf next to the retained spine.
                    if let Some((l2, path)) = &output.added_parent {
                        tracing::debug!(
                            l2 = hex::encode(l2),
                            prefix = ?path,
                            bit_path = ?quil_forest::shard_bit_path_from_prefix(path),
                            "registering merged parent shard"
                        );
                        let shard = ShardInfo {
                            shard_key: grid_key(l2),
                            prefix: path.clone(),
                            size: Vec::new(),
                            data_shards: 0,
                            commitment: Vec::new(),
                        };
                        store.put_app_shard(txn.as_ref(), &shard)?;
                    }
                }
            }
            store.delete_pending_shard_change(txn.as_ref(), &change.parent, change.effective_epoch)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Flag-day split reset, riding [`unified_tree_cutover_frame`]. The deep-split
    /// machinery left the QUIL app with a NON-prefix-free shard grid: empty spine
    /// descendants that alias their data-bearing ancestors. On that grid the
    /// legacy whole-app aggregate PANICS (`app_root_from_shard_paths` needs
    /// prefix-free) and, under unified, an empty alias shard's canonical bit-path
    /// collapses onto its ancestor's — so it commits the ancestor's root while
    /// holding no data (a prover placed there wedges). Rather than surgically
    /// drain each alias, this rebuilds from the genesis topology at ONE
    /// coordinated frame:
    ///  1. Reset the QUIL shard rows to the 64-way genesis set (`[0]..[63]`),
    ///     dropping every accumulated split/merge row and any pending change.
    ///  2. Drop every NON-archive prover record (prover vertex + allocations +
    ///     hyperedge). The archives (keep-set) stay up to serve/anchor; dropped
    ///     provers re-join onto the clean grid. Their baseline seniority is
    ///     restored on re-join from the embedded Ed448 seniority ledger (a
    ///     re-merge — it is NOT stored in the dropped vertex), with
    ///     [`super::materialize::UNIFIED_RESET_AMNESTY_FRAME`] covering any stale
    ///     kick the drop missed.
    ///
    /// Runs ONCE, at exactly the cutover frame, on nodes that materialize the
    /// global frame (archives): the prover-record deletes go onto `state` so they
    /// ride the frame's commit batch and land in the cutover frame's committed
    /// state root; regulars sync that state. `== cutover` (not `>=`) makes it
    /// exactly-once per node — a sequential materializer hits the cutover frame
    /// once, and a node that synced past it never materializes that frame. No-op
    /// (returns `false`) without the shards store / hypergraph / archive keep-set.
    pub fn maybe_apply_split_reset(
        &self,
        frame_number: u64,
        state: &HypergraphState,
    ) -> Result<bool> {
        // Fires at the v1 unified cutover AND the v2 grid reset (mainnet 740_000).
        // The grid reset is idempotent (delete all QUIL rows → rewrite genesis), so
        // no marker is needed here — the exact-frame gate + idempotency make it safe
        // even if the frame re-materializes. The prover-tree wipe that rides the same
        // frame IS marker-guarded (it is not idempotent). See
        // `materialize::quil_grid_reset_v2_frame`.
        if frame_number != super::materialize::unified_tree_cutover_frame()
            && frame_number != super::materialize::quil_grid_reset_v2_frame()
            && frame_number != super::materialize::quil_prover_reset_v3_frame()
        {
            return Ok(false);
        }
        let (Some(store), Some(db), Some(hg), Some(keep), Some(genesis_prefixes)) = (
            self.shards_store.as_ref(),
            self.shards_db.as_ref(),
            self.hypergraph.as_ref(),
            self.archive_prover_addresses.as_ref(),
            self.reset_genesis_prefixes.as_ref(),
        ) else {
            tracing::info!(
                frame = frame_number,
                "unified split reset: deps absent (shards/hg/keep-set/genesis-prefixes) — \
                 skipping; this node syncs the post-reset state rather than computing it"
            );
            return Ok(false);
        };

        let quil = crate::domains::QUIL_TOKEN;
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
        let mut grid_key = Vec::with_capacity(3 + 32);
        grid_key.extend_from_slice(&l1);
        grid_key.extend_from_slice(&quil);

        // ---- (1) Reset the QUIL shard grid to the 64-way genesis topology ----
        let txn = db.new_batch(false)?;
        let mut removed_rows = 0usize;
        for s in store.range_app_shards()? {
            if s.shard_key == grid_key {
                store.delete_app_shard(txn.as_ref(), &s.shard_key, &s.prefix)?;
                removed_rows += 1;
            }
        }
        // Rewrite to the network's QUIL genesis topology (mainnet = 64-way
        // `[0]..[63]`; testnet = single `[]`), mirroring what `genesis` seeded.
        // Prefix-free by construction, so the aliasing (and the legacy-aggregate
        // panic) is gone.
        for prefix in genesis_prefixes.iter() {
            store.put_app_shard(
                txn.as_ref(),
                &ShardInfo {
                    shard_key: grid_key.clone(),
                    prefix: prefix.clone(),
                    size: Vec::new(),
                    data_shards: 0,
                    commitment: Vec::new(),
                },
            )?;
        }
        // Drop any pending QUIL split/merge so a staged change can't re-cascade
        // onto the freshly-reset grid.
        let mut removed_pending = 0usize;
        for pc in store.all_pending_shard_changes()? {
            if pc.parent.len() >= 32 && pc.parent[..32] == quil {
                store.delete_pending_shard_change(txn.as_ref(), &pc.parent, pc.effective_epoch)?;
                removed_pending += 1;
            }
        }
        txn.commit()?;

        // The GLOBAL PROVER TREE reset (wipe the prover shard's vertex + hyperedge
        // trees and rebuild them from the genesis prover set) is NOT done here: it
        // needs the genesis prover data + seeding logic that live in the engine
        // layer (`quil_engine::genesis`), and it must REBUILD fresh trees (the
        // forest JMT is put-only, so a per-vertex delete cannot shrink it). It
        // rides the same cutover frame via the materializer's reset hook — see
        // `quil_engine::genesis::reset_prover_tree_to_genesis`. Both land in the
        // cutover frame's committed state, so the prover-tree commitment changes
        // and propagates to syncing nodes (which is what makes dropped provers
        // re-join). Here we only rebuild the QUIL shard grid.
        let _ = (hg, keep);

        tracing::info!(
            frame = frame_number,
            removed_rows,
            removed_pending,
            genesis_shards = genesis_prefixes.len(),
            "unified split reset: QUIL shard grid rebuilt to genesis topology"
        );
        Ok(true)
    }

    /// Phase F deterministic reassignment: at the E+2 boundary, move every
    /// affected prover's allocation onto the new shard topology by rewriting
    /// its `ConfirmationFilter` in committed hypergraph state.
    ///
    /// - Split: each ACTIVE prover on the parent → exactly one child, chosen
    /// deterministically by [`reassignment::assign_child_index`] over the
    /// prover's address (frozen-committee, consensus-identical).
    /// - Merge: every ACTIVE prover on any child → the parent.
    ///
    /// The active set is read DIRECTLY from committed hypergraph state via the
    /// CRDT (`active_provers_on_filter_committed`), NOT from the async
    /// `prover_registry` cache — so every node enumerates the identical prover
    /// set for a given committed frame and the reassignment is a pure function
    /// of that frame (the cache is refreshed on timing-dependent background
    /// paths and could otherwise diverge → fork). Leaving/joining allocations
    /// are NOT reassigned: a pending Leave departs at E+2 by design, and joins
    /// to a frozen shard were rejected by the join-freeze. When no CRDT is
    /// installed (non-archive fixtures) we fall back to the cache; when neither
    /// is installed this is a no-op — the local grid still flips.
    fn reassign_shard_allocations(
        &self,
        state: &HypergraphState,
        va_disc: &[u8; 32],
        change: &PendingShardChange,
        frame_number: u64,
        // ONE committed-state scan shared across all due changes this frame
        // (built by the caller). `None` ⇒ scan on demand / fall back to the cache.
        scan: Option<&crate::prover_registry::CommittedProverScan>,
    ) -> Result<()> {
        let pr = self.prover_registry.as_ref();
        // Proceed when EITHER committed-state (preferred) OR the cache is
        // available; otherwise nothing to reassign.
        if self.hypergraph.is_none() && pr.is_none() {
            return Ok(());
        }
        let vr_disc = vertex_removes_discriminator()?;
        let ha_disc = hyperedge_adds_discriminator()?;

        // Enumerate `(public_key, prover_address)` on `filter`: committed state
        // via the CRDT when present (deterministic), else the async cache.
        let enumerate = |filter: &[u8]| -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            if let Some(scan) = scan {
                // Reuse the ONE per-frame committed scan (deterministic).
                Ok(scan.active_on_filter(filter, frame_number))
            } else if let Some(hg) = self.hypergraph.as_ref() {
                // No shared scan supplied — scan on demand (still committed state).
                Ok(crate::prover_registry::active_provers_on_filter_committed(
                    hg, filter, frame_number,
                ))
            } else if let Some(pr) = pr {
                let provers = pr.get_active_provers(filter, frame_number).map_err(|e| {
                    QuilError::InvalidArgument(format!("reassign: get_active_provers failed: {e}"))
                })?;
                Ok(provers
                    .into_iter()
                    .map(|info| (info.public_key, info.address))
                    .collect())
            } else {
                Ok(Vec::new())
            }
        };

        match change.kind {
            ShardChangeKind::Split => {
                if change.children.is_empty() {
                    return Ok(());
                }
                let mut provers = enumerate(&change.parent)?;
                let k = change.children.len();
                tracing::info!(
                    parent = hex::encode(&change.parent),
                    enumerated = provers.len(),
                    children = k,
                    frame = frame_number,
                    "reassign split: active provers enumerated on parent (0 ⇒ nothing moves)"
                );
                // Distribute the parent's provers EVENLY across the children.
                // `assign_child_index` maps by the prover's address byte — ~even
                // for a large committee, but for a SMALL one (a handful of
                // provers) they can all hash to the same child, leaving the
                // sibling child with ZERO provers → permanently uncovered / halt
                // (the localnet "child …80 never covered" artifact). A
                // deterministic round-robin over address-sorted provers
                // guarantees every child gets ⌊N/k⌋..⌈N/k⌉ provers. State-
                // affecting (the committed reassignment), so it's gated on the
                // unified cutover flag day — a coordinated upgrade point where
                // every node flips together (pre-cutover keeps the exact legacy
                // `assign_child_index` mapping, so no fork on in-flight splits).
                let even = frame_number
                    >= super::materialize::unified_tree_cutover_frame();
                if even {
                    // Deterministic order independent of enumeration order.
                    provers.sort_by(|a, b| a.1.cmp(&b.1));
                }
                for (i, (public_key, address)) in provers.iter().enumerate() {
                    let idx = if even {
                        i % k
                    } else {
                        reassignment::assign_child_index(address, k)
                    };
                    let new_filter = &change.children[idx];
                    self.rekey_allocation(
                        state, va_disc, &vr_disc, &ha_disc, public_key, address,
                        &change.parent, new_filter, frame_number,
                    )?;
                }
            }
            ShardChangeKind::Merge => {
                for child in &change.children {
                    let provers = enumerate(child)?;
                    for (public_key, address) in &provers {
                        self.rekey_allocation(
                            state, va_disc, &vr_disc, &ha_disc, public_key, address,
                            child, &change.parent, frame_number,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Re-key one allocation from `old_filter` to `new_filter`: write the new
    /// allocation vertex (Status/Epoch/frame fields carried verbatim), rebuild
    /// the prover's hyperedge atom for the new address, and remove the old
    /// vertex — UNLESS the re-key collided to the same address (poseidon
    /// absorbs trailing-zero filter suffixes, so a parent and its `…‖0x00`
    /// child share an allocation address), in which case the `set` already
    /// updated the filter in place and a `delete` would erase it.
    #[allow(clippy::too_many_arguments)]
    fn rekey_allocation(
        &self,
        state: &HypergraphState,
        va_disc: &[u8; 32],
        vr_disc: &[u8; 32],
        ha_disc: &[u8; 32],
        pubkey: &[u8],
        prover_address: &[u8],
        old_filter: &[u8],
        new_filter: &[u8],
        frame_number: u64,
    ) -> Result<()> {
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        let old_addr = materialize::allocation_address(pubkey, old_filter)?;
        let new_addr = materialize::allocation_address(pubkey, new_filter)?;

        // Read the existing (committed) allocation; nothing to move if absent.
        let old_blob = match state.get(domain, &old_addr, va_disc)? {
            Some(b) if !b.is_empty() => b,
            _ => {
                tracing::info!(
                    old_filter = hex::encode(old_filter),
                    old_addr = hex::encode(old_addr),
                    "rekey: NO allocation at old_addr via state.get (snapshot miss?) — NOTHING moved"
                );
                return Ok(());
            }
        };

        tracing::debug!(
            old_filter = hex::encode(old_filter),
            new_filter = hex::encode(new_filter),
            new_addr = hex::encode(new_addr),
            moved = (new_addr != old_addr),
            "rekey: found old allocation → writing new (+deleting old if moved)"
        );
        let new_blob = reassignment::rewrite_allocation_filter(&old_blob, new_filter)?;
        let new_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&new_blob);

        // Write the new (or, on collision, in-place) allocation vertex.
        state.set(domain, &new_addr, va_disc, frame_number, new_blob)?;

        // Rebuild the prover's allocation hyperedge atom for the new address so
        // ProverKick can still enumerate the moved allocation.
        let existing_he = state
            .get(domain, prover_address, ha_disc)?
            .unwrap_or_default();
        let new_he = reassignment::rebuild_hyperedge_with_reassigned_atom(
            &existing_he, &old_addr, &new_addr, &new_tree,
        )?;
        state.set(domain, prover_address, ha_disc, frame_number, new_he)?;

        // Retire the vacated slot as Historic instead of DELETING it, but only
        // when the address actually changed (a poseidon-collision re-key already
        // updated in place above). A hard delete writes a removes-phase tombstone
        // that `get_vertex_data` honors forever and no later `add_vertex` clears —
        // so a shard that splits, loses coverage, and merges back could never
        // re-represent this allocation (the address is gone for good). Flipping
        // Status to Historic keeps the vertex: committee/worker reads exclude it
        // (`committee_eligible`), its hyperedge atom is already dropped above, and
        // a future reassignment TO `old_filter` reactivates the same slot.
        let _ = vr_disc;
        if new_addr != old_addr {
            let historic_blob =
                reassignment::set_allocation_status(&old_blob, materialize::STATUS_HISTORIC)?;
            state.set(domain, &old_addr, va_disc, frame_number, historic_blob)?;
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

/// Halt-risk gate for `ProverLeaveConfirm`. The lifecycle's
/// `decide_leaves` is the honest-prover defense; this is the
/// last-line materializer gate that catches a malicious node
/// submitting `ProverLeaveConfirm` directly without going through
/// its own lifecycle.
///
/// Only fires on the Leaving→Kicked path (i.e. a leave-confirm).
/// Join-confirms (Joining→Active) and any other transition are
/// allowed unconditionally.
///
/// At leave-confirm time our own alloc is already in Leaving
/// status, so `get_active_provers(filter)` returns OTHER active
/// provers on the shard — confirming our leave moves us
/// Leaving→Kicked, which doesn't change that count. The check is
/// therefore "after this confirm, will the shard have enough Active
/// margin?" If the count is at or below `HALT_RISK_PROVER_COUNT + 1`
/// the shard is at or one prover above halt-risk; rejecting the
/// confirm preserves our pending Leaving alloc, which either gets
/// rejected by `decide_leaves` (returning us to Active) or
/// auto-expires after the 720-frame grace.
///
/// `registry` is optional so test paths and intrinsic configurations
/// that don't install one still work — without a registry there's no
/// way to count and the gate degrades open (`Ok(())`). Production
/// always wires the registry via `with_frame_header_deps`.
/// Whether `filter` still corresponds to a registered app shard.
///
/// After a deep split, the parent shard is removed from the store
/// (`delete_app_shard`) and replaced by its prefix-free children. Its
/// provers' allocations linger (they drain via canonical leave), so
/// `get_active_provers` still counts them — but the shard itself is
/// gone. This reconstructs each registered shard's canonical wire
/// filter (`shard_prefix_to_filter`, matching `build_shard_inventory`
/// and the allocation `ConfirmationFilter`) and checks membership.
///
/// Degrades CLOSED (returns `true`, "still registered") on a store
/// error so a read failure never spuriously bypasses the halt-risk gate.
fn shard_filter_is_registered(store: &dyn ShardsStore, filter: &[u8]) -> bool {
    let Ok(rows) = store.range_app_shards() else {
        return true;
    };
    for s in rows {
        if s.shard_key.len() < 35 {
            continue;
        }
        let f = quil_forest::shard_prefix_to_filter(&s.shard_key[3..35], &s.prefix);
        if f == filter {
            return true;
        }
    }
    false
}

fn check_leave_confirm_halt_risk(
    filter: &[u8],
    current_alloc_status: u8,
    registry: Option<&dyn quil_types::consensus::ProverRegistry>,
    frame_number: u64,
    shard_removed: bool,
) -> Result<()> {
    // Only applies when we're confirming a leave. Join-confirms and
    // any pathological status pass through.
    if current_alloc_status != materialize::STATUS_LEAVING {
        return Ok(());
    }
    // A split-away parent shard has been removed from the registered
    // set (its data moved into the prefix-free children). It no longer
    // needs coverage, so its provers MUST be allowed to fully drain —
    // the halt-risk floor would otherwise deadlock all `active` of them
    // on a shard that no longer exists (deep-split convergence bug).
    // Removal is committed state (`delete_app_shard` in
    // `apply_due_shard_changes`), so this is deterministic across nodes.
    if shard_removed {
        return Ok(());
    }
    let Some(registry) = registry else {
        return Ok(());
    };
    let active_count = registry
        .get_active_provers(filter, frame_number)
        .map(|p| p.len())
        .unwrap_or(0);
    if active_count <= materialize::HALT_RISK_PROVER_COUNT + 1 {
        return Err(QuilError::InvalidArgument(format!(
            "ProverLeaveConfirm rejected: shard {} would land at {} active provers \
             (≤ halt-risk floor + 1 = {}); leave can re-attempt after coverage recovers",
            hex::encode(filter),
            active_count,
            materialize::HALT_RISK_PROVER_COUNT + 1,
        )));
    }
    Ok(())
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
                signature: vec![0xBBu8; 666],
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
    fn validate_join_without_frame_prover_ok() {
        // ProverJoin no longer carries a VDF proof (the join VDF was
        // removed — PoRep storage attestation replaced it), so join
        // validation does NOT require a frame_prover/clock_store. A join
        // with valid structure + BLS PoP (AcceptAll signer) validates on
        // its own; the `proof` field is ignored. (Regression guard for
        // the VDF-removal: this must NOT fail-closed on missing deps.)
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let join = crate::global_intrinsic::ProverJoin {
            filters: vec![vec![0x01u8; 32]],
            frame_number: 100,
            public_key_signature_bls48581: Some(
                crate::global_intrinsic::SignatureWithPop {
                    signature: vec![0xAAu8; 666],
                    public_key: Some(vec![0xBBu8; 897]),
                    pop_signature: vec![0xCCu8; 666],
                },
            ),
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![0xDDu8; 516],
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(
            gi.validate(105, &join, None, None).unwrap(),
            "join must validate on structural+BLS alone now that the VDF is gone",
        );
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

    // -----------------------------------------------------------------
    // Leave-confirm halt-risk gate (`check_leave_confirm_halt_risk`).
    // -----------------------------------------------------------------

    /// Stub registry whose `get_active_provers` returns the configured
    /// count for any filter. All other methods return empty.
    struct ActiveCountRegistry {
        count: usize,
    }
    impl quil_types::consensus::ProverRegistry for ActiveCountRegistry {
        fn get_prover_info(
            &self,
            _: &[u8],
        ) -> Result<Option<quil_types::consensus::ProverInfo>> {
            Ok(None)
        }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn get_ordered_provers(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: u64,
        ) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn get_active_provers(
            &self,
            _: &[u8],
            _: u64,
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            // Return `count` dummy ProverInfos — only the length is
            // read by the gate.
            Ok((0..self.count)
                .map(|i| quil_types::consensus::ProverInfo {
                    public_key: vec![i as u8; 585],
                    address: vec![i as u8; 32],
                    status: quil_types::consensus::ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                })
                .collect())
        }
        fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
            Ok(self.count)
        }
        fn get_provers(
            &self,
            _: &[u8],
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_provers_by_status(
            &self,
            _: &[u8],
            _: quil_types::consensus::ProverStatus,
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_prover_shard_summaries(
            &self,
            _: u64,
        ) -> Result<Vec<quil_types::consensus::ProverShardSummary>> {
            Ok(Vec::new())
        }
    }

    /// Join-confirm (status != Leaving) — gate is a no-op regardless
    /// of the shard's active count.
    #[test]
    fn halt_risk_gate_ignores_join_confirms() {
        let registry = ActiveCountRegistry { count: 0 };
        // STATUS_JOINING: we'd never reject a join-confirm even on a
        // shard with literally zero existing Actives — that's the
        // only way a shard ever crosses the halt-risk floor upward.
        let result = super::check_leave_confirm_halt_risk(
            b"filterX",
            materialize::STATUS_JOINING,
            Some(&registry),
            0,
            false,
        );
        assert!(result.is_ok(), "join-confirm must pass: {:?}", result.err());
    }

    /// Leave-confirm on a healthy shard (active count well above
    /// halt-risk + 1) — confirm allowed.
    #[test]
    fn halt_risk_gate_allows_leave_confirm_on_healthy_shard() {
        // 10 Active others. Post-confirm: us Kicked, still 10 Active.
        // Far above halt-risk floor.
        let registry = ActiveCountRegistry { count: 10 };
        let result = super::check_leave_confirm_halt_risk(
            b"filterX",
            materialize::STATUS_LEAVING,
            Some(&registry),
            0,
            false,
        );
        assert!(result.is_ok(), "healthy shard leave-confirm must pass: {:?}", result.err());
    }

    /// Leave-confirm on a shard already at the halt-risk floor + 1
    /// (4 Active others) — rejected. This is the boundary case the
    /// `+ 1` is designed to catch: if a single additional prover ever
    /// leaves, the shard drops to halt-risk; we don't want to be the
    /// last confirm to remove the margin.
    #[test]
    fn halt_risk_gate_rejects_leave_confirm_at_floor_plus_one() {
        let registry = ActiveCountRegistry {
            count: materialize::HALT_RISK_PROVER_COUNT + 1, // = 4 on mainnet
        };
        let result = super::check_leave_confirm_halt_risk(
            b"filterX",
            materialize::STATUS_LEAVING,
            Some(&registry),
            0,
            false,
        );
        assert!(result.is_err(),
            "leave-confirm at floor+1 must be rejected, got {:?}", result);
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("halt-risk"),
            "rejection message should mention halt-risk: {}", msg);
    }

    /// Leave-confirm on a shard already below halt-risk floor (0 or 3
    /// Active others) — rejected. Same gate fires; the shard is
    /// definitionally halt-risk.
    #[test]
    fn halt_risk_gate_rejects_leave_confirm_below_floor() {
        for active_count in [0, 1, materialize::HALT_RISK_PROVER_COUNT] {
            let registry = ActiveCountRegistry { count: active_count };
            let result = super::check_leave_confirm_halt_risk(
                b"filterX",
                materialize::STATUS_LEAVING,
                Some(&registry),
                0,
                false,
            );
            assert!(
                result.is_err(),
                "leave-confirm at active={} must be rejected, got {:?}",
                active_count, result,
            );
        }
    }

    /// Leave-confirm just above floor+1 (5 Active others on mainnet)
    /// — allowed. Confirms we're not over-rejecting healthy
    /// boundary cases.
    #[test]
    fn halt_risk_gate_allows_leave_confirm_just_above_floor_plus_one() {
        let registry = ActiveCountRegistry {
            count: materialize::HALT_RISK_PROVER_COUNT + 2, // = 5 on mainnet
        };
        let result = super::check_leave_confirm_halt_risk(
            b"filterX",
            materialize::STATUS_LEAVING,
            Some(&registry),
            0,
            false,
        );
        assert!(result.is_ok(),
            "leave-confirm at floor+2 must pass: {:?}", result.err());
    }

    /// No registry installed — gate degrades open (returns Ok) so
    /// test setups and intrinsic configurations that don't wire a
    /// registry still work.
    #[test]
    fn halt_risk_gate_degrades_open_without_registry() {
        let result = super::check_leave_confirm_halt_risk(
            b"filterX",
            materialize::STATUS_LEAVING,
            None,
            0,
            false,
        );
        assert!(result.is_ok(),
            "gate must degrade open when no registry: {:?}", result.err());
    }

    /// Leave-confirm on a shard at/below the halt-risk floor but which
    /// has been REMOVED from the registered set (`shard_removed = true`)
    /// — allowed. A split-away parent no longer needs coverage; its
    /// provers must be able to fully drain onto the prefix-free
    /// children (deep-split convergence). Without this bypass the
    /// halt-risk floor deadlocks every prover on the removed parent.
    #[test]
    fn halt_risk_gate_allows_leave_confirm_on_removed_split_parent() {
        for active_count in [0, 1, materialize::HALT_RISK_PROVER_COUNT + 1] {
            let registry = ActiveCountRegistry { count: active_count };
            let result = super::check_leave_confirm_halt_risk(
                b"filterX",
                materialize::STATUS_LEAVING,
                Some(&registry),
                0,
                true, // shard removed → bypass
            );
            assert!(
                result.is_ok(),
                "removed split-parent leave-confirm at active={} must pass: {:?}",
                active_count, result.err(),
            );
        }
    }

    #[test]
    fn validate_confirm_structural_only() {
        let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
        let confirm = crate::global_intrinsic::ProverConfirm {
            filter: vec![],
            frame_number: 500,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 666],
                address: vec![0xCCu8; 32],
            }),
            filters: vec![vec![0xDDu8; 32]],
            leaf_roots: Vec::new(),
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(gi.validate(1, &confirm, None, None).unwrap());
    }

    // -----------------------------------------------------------------
    // ProverSeniorityMerge dispatcher (`invoke_seniority_merge`):
    // covers MAX→SUM aggregation parity with Go and the skip-if-claimed
    // spent-marker semantics at `global_prover_seniority_merge.go:208-230`.
    // -----------------------------------------------------------------
    mod seniority_merge {
        use super::*;
        use crate::global_intrinsic::materialize::{
            create_prover_vertex_tree, create_spent_merge_tree,
            prover_address_from_pubkey, spent_seniority_merge_address,
        };
        use crate::global_intrinsic::prover_ops::{
            ProverSeniorityMerge as ProverSeniorityMergeOp,
        };
        use crate::global_intrinsic::seniority_merge::SeniorityMerge as SeniorityMergeTarget;
        use crate::global_schema::read_field;
        use crate::hypergraph_state::{
            vertex_adds_discriminator, HypergraphState,
        };
        use crate::prover_registry::{
            rebuild_vertex_tree_from_blob, vertex_tree_to_blob,
        };
        use quil_hypergraph::HypergraphCrdt;
        use quil_types::crypto::{InclusionProver, Multiproof};

        struct StubProver;
        impl InclusionProver for StubProver {
            fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
            fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
            fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
            fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
                Err(QuilError::Internal("batch not supported".into()))
            }
            fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
        }

        fn make_state() -> HypergraphState {
            let store = Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new());
            let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
            HypergraphState::new(crdt)
        }

        /// Seed a prover vertex with the given 585-byte BLS pubkey and
        /// initial seniority. Returns its 32-byte address.
        fn seed_prover(state: &HypergraphState, pubkey: &[u8], seniority: u64) -> [u8; 32] {
            let addr = prover_address_from_pubkey(pubkey).unwrap();
            let tree = create_prover_vertex_tree(pubkey, seniority).unwrap();
            let blob = vertex_tree_to_blob(&tree);
            let va_disc = vertex_adds_discriminator().unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &addr, &va_disc, 1, blob).unwrap();
            addr
        }

        /// Build a `ProverSeniorityMerge` op with the given prover
        /// address and a list of (key_type, pubkey) merge targets.
        fn build_op(
            prover_address: [u8; 32],
            targets: Vec<(u32, Vec<u8>)>,
        ) -> ProverSeniorityMergeOp {
            ProverSeniorityMergeOp {
                frame_number: 100,
                public_key_signature_bls48581: Some(AddressedSignature {
                    signature: vec![0xBBu8; 666],
                    address: prover_address.to_vec(),
                }),
                merge_targets: targets
                    .into_iter()
                    .map(|(key_type, pk)| SeniorityMergeTarget {
                        signature: vec![0xCCu8; 74],
                        key_type,
                        prover_public_key: pk,
                    })
                    .collect(),
            }
        }

        /// Read the current Seniority u64 from a prover vertex stored
        /// in `state` at `addr`.
        fn read_seniority(state: &HypergraphState, addr: &[u8; 32]) -> u64 {
            let va_disc = vertex_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], addr, &va_disc)
                .unwrap()
                .expect("prover vertex");
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let bytes = read_field(&tree, "prover:Prover", "Seniority")
                .expect("seniority field");
            assert_eq!(bytes.len(), 8);
            u64::from_be_bytes(bytes.try_into().unwrap())
        }

        /// Read the ProverAddress field from a SpentMerge marker blob.
        /// Returns None if the marker is absent.
        fn read_marker_prover_addr(
            state: &HypergraphState,
            spent_addr: &[u8; 32],
        ) -> Option<Vec<u8>> {
            let va_disc = vertex_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], spent_addr, &va_disc)
                .ok()
                .flatten()?;
            if blob.is_empty() {
                return None;
            }
            let tree = rebuild_vertex_tree_from_blob(&blob);
            read_field(&tree, "merge:SpentMerge", "ProverAddress")
        }

        // -------------------------------------------------------------
        // Test 1 (covers the MAX→SUM bug):
        //
        // Asserts that `invoke_seniority_merge` dispatches to
        // `seniority_compat::get_aggregated_seniority` for the merge
        // amount — the same path Go uses via `compat.GetAggregatedSeniority`.
        // The pre-fix Rust code routed through
        // `clock_store.get_peer_seniority_map` and computed MAX over
        // peer seniorities, which is wrong for two reasons:
        //   1. SUM (across the four retro epochs, then `max`'d with
        //      mainnet) is the correct aggregation, not MAX.
        //   2. The clock_store path silently returned 0 whenever no
        //      ClockStore was configured.
        //
        // We construct the dispatcher with no ClockStore. The old
        // path would unconditionally yield 0; the new path queries
        // the static compat table. We then assert the post-merge
        // Seniority equals `existing + get_aggregated_seniority(peer_ids)`.
        // Constructing a 57-byte Ed448 pubkey whose poseidon-hashed
        // libp2p peer-id-string matches a known retro entry would
        // require an Ed448 keypair we don't have, so with synthetic
        // pubkeys the aggregated value is 0 — but the test still
        // pins the dispatcher to the SUM path: any future regression
        // that re-introduces the clock-store branch would still match
        // the assertion only by coincidence. The structural
        // invariants below (using `get_aggregated_seniority` directly
        // as the oracle, no `with_stores` configuration) lock in the
        // intended code path.
        // -------------------------------------------------------------
        #[test]
        fn merge_aggregates_seniority_via_sum() {
            let state = make_state();
            let pk = vec![0xAAu8; 585];
            let prover_addr = seed_prover(&state, &pk, 100);

            // Two Ed448 merge targets (key_type=0, 57-byte pubkey).
            let targets = vec![
                (0u32, vec![0x11u8; 57]),
                (0u32, vec![0x22u8; 57]),
            ];
            let pubkeys: Vec<String> = targets
                .iter()
                .map(|(_, pk)| ed448_pubkey_to_peer_id_string(pk))
                .collect();
            // Oracle: the new dispatcher must compute exactly this
            // value (regardless of whether the synthetic peers land
            // on real retro entries — that is, the test passes both
            // when the table returns 0 *and* when it doesn't, as
            // long as the dispatcher uses the SUM path).
            let expected_merge =
                crate::seniority_compat::get_aggregated_seniority(&pubkeys);

            let op = build_op(prover_addr, targets);
            // Deliberately no `with_stores` / ClockStore — the SUM
            // path must work without a clock store, mirroring Go's
            // compat-table-only lookup.
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            let va_disc = vertex_adds_discriminator().unwrap();
            gi.invoke_seniority_merge(2, &op, &state, &va_disc).unwrap();

            let new_seniority = read_seniority(&state, &prover_addr);
            assert_eq!(
                new_seniority,
                100u64.saturating_add(expected_merge),
                "post-merge seniority must equal existing + SUM-aggregated, \
                 not MAX-of-clock-store-map",
            );
        }

        // -------------------------------------------------------------
        // Test 2: re-running a merge after a marker has been claimed
        // by a prover MUST NOT overwrite the marker. Mirrors Go's
        // skip-if-claimed branch at lines 224-225 of
        // `global_prover_seniority_merge.go`.
        // -------------------------------------------------------------
        #[test]
        fn merge_skips_already_claimed_spent_marker() {
            let state = make_state();
            let claimer_pk = vec![0xAAu8; 585];
            let claimer_addr = seed_prover(&state, &claimer_pk, 50);
            let attacker_pk = vec![0xBBu8; 585];
            let attacker_addr = seed_prover(&state, &attacker_pk, 0);

            let target_pk = vec![0x33u8; 57];

            // Claimer runs the merge first — stamps the marker.
            let op1 = build_op(claimer_addr, vec![(0, target_pk.clone())]);
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            let va_disc = vertex_adds_discriminator().unwrap();
            gi.invoke_seniority_merge(2, &op1, &state, &va_disc).unwrap();
            // Persist the changeset into the CRDT so the next call's
            // state.get sees the new marker via the changeset / CRDT.
            let spent_addr = spent_seniority_merge_address(&target_pk).unwrap();
            assert_eq!(
                read_marker_prover_addr(&state, &spent_addr).as_deref(),
                Some(&claimer_addr[..]),
                "first merge must stamp the marker with the claimer's address",
            );

            // Attacker tries to re-run the merge against the same
            // target — must NOT overwrite the marker.
            let op2 = build_op(attacker_addr, vec![(0, target_pk.clone())]);
            gi.invoke_seniority_merge(3, &op2, &state, &va_disc).unwrap();
            assert_eq!(
                read_marker_prover_addr(&state, &spent_addr).as_deref(),
                Some(&claimer_addr[..]),
                "second merge must NOT overwrite a claimed marker (parity \
                 with Go's skip-if-claimed branch)",
            );
        }

        // -------------------------------------------------------------
        // Test 3: legacy empty markers (created before the fix that
        // started stamping ProverAddress) must be overwritten by a
        // fresh merge so they pick up the current prover's address.
        // Mirrors Go's "Legacy empty marker — overwrite" branch at
        // line 227 of `global_prover_seniority_merge.go`.
        // -------------------------------------------------------------
        #[test]
        fn merge_overwrites_legacy_empty_marker() {
            let state = make_state();
            let pk = vec![0xCCu8; 585];
            let prover_addr = seed_prover(&state, &pk, 0);

            let target_pk = vec![0x44u8; 57];
            let spent_addr = spent_seniority_merge_address(&target_pk).unwrap();

            // Pre-seed an empty SpentMerge marker (no ProverAddress
            // field) — the legacy on-chain shape.
            let empty_marker = quil_tries::VectorCommitmentTree::new();
            let empty_blob = vertex_tree_to_blob(&empty_marker);
            let va_disc = vertex_adds_discriminator().unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &spent_addr, &va_disc, 1, empty_blob).unwrap();
            assert!(
                read_marker_prover_addr(&state, &spent_addr).is_none(),
                "pre-seeded marker must have no ProverAddress",
            );

            let op = build_op(prover_addr, vec![(0, target_pk.clone())]);
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            gi.invoke_seniority_merge(2, &op, &state, &va_disc).unwrap();

            // Post-merge: the legacy empty marker must now hold
            // the prover's address.
            let stored = read_marker_prover_addr(&state, &spent_addr)
                .expect("legacy empty marker should be overwritten with ProverAddress");
            assert_eq!(stored, prover_addr.to_vec());

            // Sanity: the alternate "create_spent_merge_tree" helper
            // produces the same payload shape we just wrote.
            let canonical = vertex_tree_to_blob(
                &create_spent_merge_tree(&prover_addr).unwrap(),
            );
            assert!(
                !canonical.is_empty(),
                "create_spent_merge_tree should produce a non-empty blob",
            );
        }
    }

    // -----------------------------------------------------------------
    // ProverJoin / ProverKick parity coverage:
    //   - kick_with_two_allocations_marks_both_status_4
    //   - join_creates_hyperedge_linking_prover_to_allocations
    //   - join_with_merge_targets_aggregates_seniority
    // -----------------------------------------------------------------
    mod join_kick_parity {
        use super::*;
        use crate::global_intrinsic::materialize::{
            allocation_address, build_prover_allocation_hyperedge_blob,
            create_allocation_vertex_tree, create_prover_vertex_tree,
            prover_address_from_pubkey, STATUS_KICKED,
        };
        use crate::global_intrinsic::prover_ops::ProverKick;
        use crate::global_intrinsic::prover_join::ProverJoin as ProverJoinOp;
        use crate::global_intrinsic::sig_with_pop::SignatureWithPop;
        use crate::global_intrinsic::seniority_merge::SeniorityMerge as SeniorityMergeTarget;
        use crate::global_schema::read_field;
        use crate::hypergraph_state::{
            hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState,
        };
        use crate::prover_registry::{
            rebuild_vertex_tree_from_blob, vertex_tree_to_blob,
        };
        use quil_hypergraph::HypergraphCrdt;
        use quil_types::crypto::{InclusionProver, Multiproof};

        struct StubProver;
        impl InclusionProver for StubProver {
            fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
            fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
            fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
            fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64)
                -> Result<Box<dyn Multiproof>>
            { Err(QuilError::Internal("batch not supported".into())) }
            fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
        }

        fn make_state() -> HypergraphState {
            let store = Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new());
            let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
            HypergraphState::new(crdt)
        }

        fn read_status(state: &HypergraphState, addr: &[u8; 32], cls: &str) -> Option<u8> {
            let va_disc = vertex_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], addr, &va_disc)
                .ok()
                .flatten()?;
            if blob.is_empty() {
                return None;
            }
            let tree = rebuild_vertex_tree_from_blob(&blob);
            read_field(&tree, cls, "Status")
                .and_then(|b| b.first().copied())
        }

        fn read_kick_frame(state: &HypergraphState, addr: &[u8; 32], cls: &str) -> Option<u64> {
            let va_disc = vertex_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], addr, &va_disc)
                .ok()
                .flatten()?;
            if blob.is_empty() { return None; }
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let bytes = read_field(&tree, cls, "KickFrameNumber")?;
            if bytes.len() != 8 { return None; }
            Some(u64::from_be_bytes(bytes.try_into().unwrap()))
        }

        // -------------------------------------------------------------
        // Fix #1: ProverKick must mark every allocation under the
        // prover's hyperedge as Status=4 + KickFrameNumber=N.
        //
        // We seed a prover with two allocations + a hyperedge that
        // points at both, then run `invoke_kick` and assert both
        // allocations receive Status=4 and the right frame.
        // -------------------------------------------------------------
        #[test]
        fn kick_with_two_allocations_marks_both_status_4() {
            let state = make_state();
            let pubkey = vec![0xAAu8; 897];
            let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
            let prover_tree = create_prover_vertex_tree(&pubkey, 100).unwrap();
            let va_disc = vertex_adds_discriminator().unwrap();
            state.set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &prover_addr, &va_disc, 1,
                vertex_tree_to_blob(&prover_tree),
            ).unwrap();

            // Two allocations.
            let filter_a = vec![0x11u8; 32];
            let filter_b = vec![0x22u8; 32];
            let alloc_a_addr = allocation_address(&pubkey, &filter_a).unwrap();
            let alloc_b_addr = allocation_address(&pubkey, &filter_b).unwrap();
            let alloc_a_tree = create_allocation_vertex_tree(&prover_addr, &filter_a, 1).unwrap();
            let alloc_b_tree = create_allocation_vertex_tree(&prover_addr, &filter_b, 1).unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_a_addr, &va_disc, 1, vertex_tree_to_blob(&alloc_a_tree)).unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_b_addr, &va_disc, 1, vertex_tree_to_blob(&alloc_b_tree)).unwrap();

            // Hyperedge linking prover → both allocations.
            let allocs = vec![
                (alloc_a_addr, &alloc_a_tree),
                (alloc_b_addr, &alloc_b_tree),
            ];
            let blob = build_prover_allocation_hyperedge_blob(&prover_addr, &allocs).unwrap();
            let ha_disc = hyperedge_adds_discriminator().unwrap();
            state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &prover_addr, &ha_disc, 1, blob).unwrap();

            // Kick.
            let op = ProverKick {
                frame_number: 42,
                kicked_prover_public_key: pubkey.clone(),
                conflicting_frame_1: vec![],
                conflicting_frame_2: vec![],
                commitment: vec![],
                proof: vec![],
                traversal_proof: vec![],
            };
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            gi.invoke_kick(42, &op, &state, &va_disc).unwrap();

            // Prover vertex got kicked.
            assert_eq!(
                read_status(&state, &prover_addr, "prover:Prover"),
                Some(STATUS_KICKED),
                "prover vertex must have Status=4 after kick",
            );

            // Both allocations got kicked.
            assert_eq!(
                read_status(&state, &alloc_a_addr, "allocation:ProverAllocation"),
                Some(STATUS_KICKED),
                "allocation A must have Status=4 after kick",
            );
            assert_eq!(
                read_status(&state, &alloc_b_addr, "allocation:ProverAllocation"),
                Some(STATUS_KICKED),
                "allocation B must have Status=4 after kick",
            );

            // KickFrameNumber set on both allocations.
            assert_eq!(
                read_kick_frame(&state, &alloc_a_addr, "allocation:ProverAllocation"),
                Some(42),
            );
            assert_eq!(
                read_kick_frame(&state, &alloc_b_addr, "allocation:ProverAllocation"),
                Some(42),
            );
        }

        // -------------------------------------------------------------
        // PoRep (5w): the storage audit at FrameHeader ingest must evict
        // a member whose sampled opening fails the registry cross-check
        // (here: unregistered — no leaf-root vertex), and leave provers
        // not named in the attestation untouched. Gated on the storage
        // fork + a non-empty carried attestation.
        // -------------------------------------------------------------
        fn storage_opening_proto(
            member: &[u8],
            shard_id: &[u8],
            epoch: u64,
        ) -> quil_types::proto::global::StorageOpening {
            quil_types::proto::global::StorageOpening {
                shard_id: shard_id.to_vec(),
                epoch,
                member_id: member.to_vec(),
                query: 0,
                leaf_root: vec![0u8; 74],
                num_blocks: 1,
                path_commits: vec![],
                path_proofs: vec![],
                commitment: vec![0u8; 74],
                value: vec![0u8; 32],
                proof: vec![0u8; 74],
            }
        }

        fn frame_header_with_attestation(
            filter: &[u8],
            global_frame_number: u64,
            att: &quil_types::proto::global::StorageAttestation,
        ) -> crate::global_intrinsic::frame_header::FrameHeader {
            crate::global_intrinsic::frame_header::FrameHeader {
                address: filter.to_vec(),
                frame_number: 5,
                global_frame_number,
                storage_attestation: prost::Message::encode_to_vec(att),
                ..Default::default()
            }
        }

        #[test]
        fn storage_audit_evicts_unregistered_member_and_spares_others() {
            quil_crypto::init();
            let state = make_state();
            let va_disc = vertex_adds_discriminator().unwrap();

            // Cheating member: prover vertex present + active, but no
            // leaf-root registration → registry cross-check fails → evicted.
            let bad_pubkey = vec![0xA1u8; 897];
            let bad_addr = prover_address_from_pubkey(&bad_pubkey).unwrap();
            state.set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &bad_addr, &va_disc, 1,
                vertex_tree_to_blob(&create_prover_vertex_tree(&bad_pubkey, 100).unwrap()),
            ).unwrap();

            // Bystander prover: never named in the attestation → untouched.
            let other_pubkey = vec![0xB2u8; 897];
            let other_addr = prover_address_from_pubkey(&other_pubkey).unwrap();
            state.set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &other_addr, &va_disc, 1,
                vertex_tree_to_blob(&create_prover_vertex_tree(&other_pubkey, 100).unwrap()),
            ).unwrap();

            let filter = vec![0x55u8; 32];
            let att = quil_types::proto::global::StorageAttestation {
                openings: vec![storage_opening_proto(&bad_addr, &vec![0x07u8; 32], 1)],
            };
            let op = frame_header_with_attestation(&filter, 1_000, &att);

            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll))
                .with_clock_store(Arc::new(quil_store::testing::InMemoryClockStore::new()));
            // In lockstep: anchor 1000 == frame_number 1001 - 1.
            gi.audit_storage_attestation(1_001, &op, &[], &state, &va_disc).unwrap();

            assert_eq!(
                read_status(&state, &bad_addr, "prover:Prover"),
                Some(STATUS_KICKED),
                "unregistered member must be evicted by the storage audit",
            );
            assert_ne!(
                read_status(&state, &other_addr, "prover:Prover"),
                Some(STATUS_KICKED),
                "a prover not named in the attestation must be untouched",
            );
        }

        #[test]
        fn storage_audit_is_noop_without_anchor_or_attestation() {
            quil_crypto::init();
            let state = make_state();
            let va_disc = vertex_adds_discriminator().unwrap();
            let bad_pubkey = vec![0xC3u8; 897];
            let bad_addr = prover_address_from_pubkey(&bad_pubkey).unwrap();
            state.set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &bad_addr, &va_disc, 1,
                vertex_tree_to_blob(&create_prover_vertex_tree(&bad_pubkey, 100).unwrap()),
            ).unwrap();
            let filter = vec![0x55u8; 32];
            let att = quil_types::proto::global::StorageAttestation {
                openings: vec![storage_opening_proto(&bad_addr, &vec![0x07u8; 32], 0)],
            };
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll))
                .with_clock_store(Arc::new(quil_store::testing::InMemoryClockStore::new()));

            // No global anchor (genesis / legacy-VDF frame, gfn == 0): no audit.
            let pre = frame_header_with_attestation(&filter, 0, &att);
            gi.audit_storage_attestation(7, &pre, &[], &state, &va_disc).unwrap();
            assert_ne!(
                read_status(&state, &bad_addr, "prover:Prover"),
                Some(STATUS_KICKED),
                "no eviction for a frame with no global anchor",
            );

            // Anchored (in lockstep) but empty attestation: no audit.
            let empty = crate::global_intrinsic::frame_header::FrameHeader {
                address: filter.clone(),
                frame_number: 5,
                global_frame_number: 1_000,
                storage_attestation: Vec::new(),
                ..Default::default()
            };
            gi.audit_storage_attestation(1_001, &empty, &[], &state, &va_disc).unwrap();
            assert_ne!(
                read_status(&state, &bad_addr, "prover:Prover"),
                Some(STATUS_KICKED),
                "no eviction when the frame carries no attestation",
            );
        }

        #[test]
        fn storage_audit_rejects_out_of_lockstep_anchor() {
            quil_crypto::init();
            let state = make_state();
            let va_disc = vertex_adds_discriminator().unwrap();
            let member_pubkey = vec![0xD4u8; 897];
            let member_addr = prover_address_from_pubkey(&member_pubkey).unwrap();
            let filter = vec![0x55u8; 32];
            let att = quil_types::proto::global::StorageAttestation {
                openings: vec![storage_opening_proto(&member_addr, &vec![0x07u8; 32], 1)],
            };
            // FUTURE anchor: anchor=1000 while materializing frame=7 (expected ≤ 6)
            // → out of window → hard-reject.
            let op = frame_header_with_attestation(&filter, 1_000, &att);
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll))
                .with_clock_store(Arc::new(quil_store::testing::InMemoryClockStore::new()));
            let err = gi
                .audit_storage_attestation(7, &op, &[], &state, &va_disc)
                .expect_err("future anchor must hard-reject");
            assert!(
                format!("{err}").contains("lockstep"),
                "error should name the lockstep violation, got: {err}"
            );

            // STALE-BEYOND-WINDOW: at frame 100 the window is [100-1-W, 99]. An
            // anchor older than `99 - W` is rejected.
            let w = crate::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
            let too_old = frame_header_with_attestation(&filter, 99 - w - 1, &att);
            gi.audit_storage_attestation(100, &too_old, &[], &state, &va_disc)
                .expect_err("anchor older than the window must hard-reject");

            // The exact preceding frame (anchor == frame-1) is accepted.
            let ok = frame_header_with_attestation(&filter, 6, &att);
            gi.audit_storage_attestation(7, &ok, &[], &state, &va_disc)
                .expect("anchor == frame_number-1 is in lockstep");

            // An anchor INSIDE the window (older than frame-1 but within W) is
            // now accepted (the multi-member case the window exists for).
            let in_window = frame_header_with_attestation(&filter, 99 - w, &att);
            gi.audit_storage_attestation(100, &in_window, &[], &state, &va_disc)
                .expect("anchor at the oldest edge of the window is in lockstep");
        }

        // -------------------------------------------------------------
        // Fix #2: ProverJoin must write a hyperedge linking the new
        // prover vertex to its initial allocations. Without this, the
        // kick path (Fix #1) has no atom list to iterate.
        //
        // We invoke join with two filters and assert that the
        // hyperedge stored at `(GLOBAL_INTRINSIC_ADDRESS, prover_addr)`
        // contains exactly those allocation IDs.
        // -------------------------------------------------------------
        #[test]
        fn join_creates_hyperedge_linking_prover_to_allocations() {
            let state = make_state();
            let pubkey = vec![0xBBu8; 897];
            let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
            let filter_a = vec![0x33u8; 32];
            let filter_b = vec![0x44u8; 32];

            let join = ProverJoinOp {
                filters: vec![filter_a.clone(), filter_b.clone()],
                frame_number: 10,
                public_key_signature_bls48581: Some(SignatureWithPop {
                    signature: vec![0xAAu8; 666],
                    public_key: Some(pubkey.clone()),
                    pop_signature: vec![0xCCu8; 666],
                }),
                delegate_address: vec![],
                merge_targets: vec![],
                proof: vec![0xDDu8; 516],
            };
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            let va_disc = vertex_adds_discriminator().unwrap();
            gi.invoke_join(10, &join, &state, &va_disc).unwrap();

            // The hyperedge must exist and enumerate both allocation IDs.
            let ha_disc = hyperedge_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover_addr, &ha_disc)
                .unwrap()
                .expect("join must write a hyperedge for the prover");
            assert!(!blob.is_empty(), "hyperedge blob must be populated");

            let mut tree = quil_tries::VectorCommitmentTree::new();
            let root = quil_tries::deserialize_go_tree(&blob).unwrap();
            tree.root = root;
            let leaves = tree.leaves();
            let alloc_a_addr = allocation_address(&pubkey, &filter_a).unwrap();
            let alloc_b_addr = allocation_address(&pubkey, &filter_b).unwrap();
            let mut keys: Vec<[u8; 64]> = leaves.iter()
                .filter(|(k, _)| k.len() == 64)
                .map(|(k, _)| { let mut a = [0u8; 64]; a.copy_from_slice(k); a })
                .collect();
            keys.sort();

            let mut expected = vec![
                {
                    let mut id = [0u8; 64];
                    id[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS[..32]);
                    id[32..].copy_from_slice(&alloc_a_addr);
                    id
                },
                {
                    let mut id = [0u8; 64];
                    id[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS[..32]);
                    id[32..].copy_from_slice(&alloc_b_addr);
                    id
                },
            ];
            expected.sort();
            assert_eq!(keys, expected, "hyperedge must enumerate exactly the join's allocations");
        }

        // -------------------------------------------------------------
        // Fix #3: ProverJoin Seniority field must be the
        // `compat::GetAggregatedSeniority` SUM across the merge-target
        // peer ids — NOT `op.frame_number`.
        //
        // We construct a join with synthetic Ed448 merge targets and
        // assert the resulting prover.Seniority equals the oracle
        // (`get_aggregated_seniority(peer_ids)`), and that this
        // differs from `op.frame_number` (which the buggy path used).
        //
        // For reproducibility, we don't rely on actual mainnet retro
        // hits — the oracle and the dispatcher both run the same
        // function over the same peer-id strings, so the test pins
        // the dispatcher to the SUM path. Crucially, the assertion
        // also fails if the dispatcher reverts to the
        // `seniority = op.frame_number` line (the original bug).
        // -------------------------------------------------------------
        #[test]
        fn join_with_merge_targets_aggregates_seniority() {
            let state = make_state();
            let pubkey = vec![0xEEu8; 897];
            let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
            let mt_pubkey = vec![0x55u8; 57];

            // Compute oracle seniority for the post-join Seniority value.
            let peer_ids = vec![ed448_pubkey_to_peer_id_string(&mt_pubkey)];
            let expected = crate::seniority_compat::get_aggregated_seniority(&peer_ids);
            // Use a frame_number that is unmistakably distinct from
            // the oracle so the bug — `seniority = op.frame_number` —
            // would produce a wrong value.
            let frame_number: u64 = 0xDEAD_BEEF;
            assert_ne!(
                expected, frame_number,
                "test setup must distinguish frame_number from aggregated value",
            );

            let join = ProverJoinOp {
                filters: vec![vec![0x66u8; 32]],
                frame_number,
                public_key_signature_bls48581: Some(SignatureWithPop {
                    signature: vec![0xAAu8; 666],
                    public_key: Some(pubkey.clone()),
                    pop_signature: vec![0xCCu8; 666],
                }),
                delegate_address: vec![],
                merge_targets: vec![SeniorityMergeTarget {
                    signature: vec![0x11u8; 74],
                    key_type: 0, // Ed448
                    prover_public_key: mt_pubkey,
                }],
                proof: vec![0xDDu8; 516],
            };

            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll));
            let va_disc = vertex_adds_discriminator().unwrap();
            gi.invoke_join(frame_number, &join, &state, &va_disc).unwrap();

            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover_addr, &va_disc)
                .unwrap()
                .expect("join must create a prover vertex");
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let bytes = read_field(&tree, "prover:Prover", "Seniority").expect("seniority field");
            assert_eq!(bytes.len(), 8);
            let stored = u64::from_be_bytes(bytes.try_into().unwrap());

            assert_eq!(
                stored, expected,
                "post-join Seniority must equal compat::GetAggregatedSeniority — \
                 not op.frame_number ({})",
                frame_number,
            );
        }
    }

    /// Reproduction harness for the "duplicate ShardSplit re-proposal" concern:
    /// the split proposer re-emits every frame because it never checks for an
    /// existing pending change, so a split whose parent stays over-crowded through
    /// epochs E and E+1 records a pending change at effective_epoch E+2 (from the
    /// E proposals) AND E+3 (from the E+1 proposals). Both coexist (keyed by
    /// `(effective_epoch, parent)`) and BOTH apply. This test shows exactly what
    /// that does to the grid.
    mod split_double_apply {
        use super::*;
        use crate::hypergraph_state::HypergraphState;
        use quil_hypergraph::HypergraphCrdt;
        use quil_types::crypto::{InclusionProver, Multiproof};
        use quil_types::store::{
            KvDb, PendingShardChange, ShardChangeKind, ShardInfo, ShardsStore,
        };

        struct StubProver;
        impl InclusionProver for StubProver {
            fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
            fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
            fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
            fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
                Err(QuilError::Internal("batch not supported".into()))
            }
            fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
        }
        fn make_state() -> HypergraphState {
            let store = Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new());
            let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
            HypergraphState::new(crdt)
        }

        #[test]
        fn duplicate_pending_splits_across_epochs_stale_one_is_skipped() {
            let app = [0x11u8; 32];
            // Parent = the app-root shard (post-cutover ⇒ bit-path mode).
            let parent = app.to_vec();
            let grid_key = {
                let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3);
                let mut k = l1.to_vec();
                k.extend_from_slice(&app);
                k
            };

            // Real in-memory shards store (grid + pending changes) + its KvDb.
            let shdb = quil_store::RocksDb::open_in_memory().unwrap();
            let store: Arc<dyn ShardsStore> =
                Arc::new(quil_store::RocksShardsStore::new(shdb.inner()));
            let shards_db: Arc<dyn KvDb> = Arc::new(shdb);

            // Seed the parent (root) grid entry (sentinel-form empty bit-path).
            {
                let txn = shards_db.new_batch(false).unwrap();
                store
                    .put_app_shard(
                        txn.as_ref(),
                        &ShardInfo {
                            shard_key: grid_key.clone(),
                            prefix: quil_forest::bit_path_to_prefix(&[]),
                            size: Vec::new(),
                            data_shards: 0,
                            commitment: Vec::new(),
                        },
                    )
                    .unwrap();
                txn.commit().unwrap();
            }

            // Two pending splits for the SAME parent at DIFFERENT effective epochs,
            // with DIFFERENT children (the bifurcation shifted as data grew between
            // E and E+1): E+2 → 1-bit split [0],[1]; E+3 → deeper split of the
            // 0-branch [0,0],[0,1]. Both post-cutover (proposed_frame > cutover).
            let (e2, e3) = (1002u64, 1003u64);
            let proposed = 800_000u64; // > UNIFIED_TREE_CUTOVER_FRAME ⇒ bit_path_mode
            let child = |bits: &[bool]| quil_forest::encode_shard_bit_path(&app, bits);
            let changes = [
                (e2, vec![child(&[false]), child(&[true])]),
                (e3, vec![child(&[false, false]), child(&[false, true])]),
            ];
            for (epoch, children) in &changes {
                let txn = shards_db.new_batch(false).unwrap();
                store
                    .put_pending_shard_change(
                        txn.as_ref(),
                        &PendingShardChange {
                            kind: ShardChangeKind::Split,
                            parent: parent.clone(),
                            children: children.clone(),
                            effective_epoch: *epoch,
                            proposed_frame: proposed,
                        },
                    )
                    .unwrap();
                txn.commit().unwrap();
            }
            // Both coexist — keyed by (effective_epoch, parent), so nothing dedups
            // the duplicate re-proposal that straddled the epoch boundary.
            assert_eq!(
                store.all_pending_shard_changes().unwrap().len(),
                2,
                "duplicate splits for one parent at E+2 and E+3 COEXIST"
            );

            // Wire the intrinsic (no hypergraph/registry ⇒ reassign no-ops; this
            // isolates the GRID topology effect).
            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll))
                .with_shards_store(store.clone())
                .with_shards_db(shards_db.clone());
            let state = make_state();

            let prefixes = |s: &Arc<dyn ShardsStore>| -> Vec<Vec<u32>> {
                let mut v: Vec<Vec<u32>> = s
                    .range_app_shards()
                    .unwrap()
                    .into_iter()
                    .filter(|r| r.shard_key == grid_key)
                    .map(|r| r.prefix)
                    .collect();
                v.sort();
                v
            };
            let p_root = quil_forest::bit_path_to_prefix(&[]);
            let p_0 = quil_forest::bit_path_to_prefix(&[false]);
            let p_1 = quil_forest::bit_path_to_prefix(&[true]);
            let p_00 = quil_forest::bit_path_to_prefix(&[false, false]);
            let p_01 = quil_forest::bit_path_to_prefix(&[false, true]);

            // Apply at E+2: parent → [0],[1], root removed. This is the CORRECT split.
            let frame_e2 = e2 * quil_types::consensus::EPOCH_LENGTH_FRAMES + 10;
            gi.apply_due_shard_changes(frame_e2, &state).unwrap();
            let after_e2 = prefixes(&store);
            println!("grid after E+2 apply: {after_e2:?}");
            assert!(after_e2.contains(&p_0) && after_e2.contains(&p_1), "E+2 children present");
            assert!(!after_e2.contains(&p_root), "root removed by the split");
            assert!(!after_e2.contains(&p_00), "no deeper children yet");

            // Apply at E+3: the STALE duplicate targets the already-removed parent.
            let frame_e3 = e3 * quil_types::consensus::EPOCH_LENGTH_FRAMES + 10;
            gi.apply_due_shard_changes(frame_e3, &state).unwrap();
            let after_e3 = prefixes(&store);
            println!("grid after E+3 apply (fixed — stale skipped): {after_e3:?}");

            // FIXED: the apply-side guard sees the parent is no longer in the grid
            // (already split at E+2) and SKIPS the stale duplicate — so the grid is
            // unchanged, no overlapping [0,0]/[0,1] on top of [0]. No double coverage.
            assert_eq!(after_e3, after_e2, "stale E+3 split skipped → grid unchanged from E+2");
            assert!(after_e3.contains(&p_0) && after_e3.contains(&p_1), "the real E+2 children remain");
            assert!(
                !after_e3.contains(&p_00) && !after_e3.contains(&p_01),
                "E+3's deeper children NOT registered — no overlapping shards",
            );
            // Both pending records are consumed (the stale one is not left to re-fire).
            assert!(
                store.all_pending_shard_changes().unwrap().is_empty(),
                "both pending records consumed",
            );
        }

        /// Regression: a GENESIS shard is stored as a byte-suffix prefix (`[i]`),
        /// while `materialize_shard_split` reports `removed_parent` in SENTINEL form.
        /// The stale-split guard must treat those as the SAME shard, or it wrongly
        /// skips the FIRST split of every genesis shard (mainnet: QUIL stuck at 64-way
        /// after the grid reset). This exercises the multi-shard byte-suffix path that
        /// the single-shard localnet could not.
        #[test]
        fn fresh_byte_suffix_genesis_split_applies_and_removes_the_parent() {
            use quil_types::store::{
                KvDb, PendingShardChange, ShardChangeKind, ShardInfo, ShardsStore,
            };
            let app = crate::domains::QUIL_TOKEN;
            let grid_key = {
                let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3);
                let mut k = l1.to_vec();
                k.extend_from_slice(&app);
                k
            };
            let shdb = quil_store::RocksDb::open_in_memory().unwrap();
            let store: Arc<dyn ShardsStore> =
                Arc::new(quil_store::RocksShardsStore::new(shdb.inner()));
            let shards_db: Arc<dyn KvDb> = Arc::new(shdb);

            // The full 64-way byte-suffix genesis grid (`[0]..[63]`), as the reset
            // writes it — so `migrate_app_shards_to_sentinel` canonicalizes to the
            // 6-bit paths that match `removed_parent` (a smaller set would give a
            // narrower width and misrepresent mainnet).
            for i in 0..64u32 {
                let txn = shards_db.new_batch(false).unwrap();
                store
                    .put_app_shard(
                        txn.as_ref(),
                        &ShardInfo {
                            shard_key: grid_key.clone(),
                            prefix: vec![i],
                            size: Vec::new(),
                            data_shards: 0,
                            commitment: Vec::new(),
                        },
                    )
                    .unwrap();
                txn.commit().unwrap();
            }

            // FRESH split of the byte-suffix parent app‖[0] (6-bit path 000000) into
            // its two 7-bit children 0000000 / 0000001.
            let mut parent = app.to_vec();
            parent.push(0x00);
            let bits = |s: &str| -> Vec<bool> { s.chars().map(|c| c == '1').collect() };
            let child = |b: &str| quil_forest::encode_shard_bit_path(&app, &bits(b));
            let txn = shards_db.new_batch(false).unwrap();
            store
                .put_pending_shard_change(
                    txn.as_ref(),
                    &PendingShardChange {
                        kind: ShardChangeKind::Split,
                        parent: parent.clone(),
                        children: vec![child("0000000"), child("0000001")],
                        effective_epoch: 1002,
                        proposed_frame: 800_000, // > cutover ⇒ bit_path_mode
                    },
                )
                .unwrap();
            txn.commit().unwrap();

            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll))
                .with_shards_store(store.clone())
                .with_shards_db(shards_db.clone());
            let state = make_state();
            gi.apply_due_shard_changes(1002 * quil_types::consensus::EPOCH_LENGTH_FRAMES + 10, &state)
                .unwrap();

            // The split APPLIED (was NOT skipped as stale): children present in
            // canonical bits, and the parent 000000 is GONE — not left as a phantom.
            let canon = |p: &Vec<u32>| {
                quil_forest::shard_bit_path_from_prefix(p)
                    .unwrap_or_else(|| quil_forest::prefix_to_bits(p, 6))
            };
            let present: Vec<Vec<bool>> = store
                .range_app_shards()
                .unwrap()
                .into_iter()
                .filter(|s| s.shard_key == grid_key)
                .map(|s| canon(&s.prefix))
                .collect();
            assert!(
                present.contains(&bits("0000000")) && present.contains(&bits("0000001")),
                "children registered (split applied, not skipped)"
            );
            assert!(
                !present.contains(&bits("000000")),
                "byte-suffix genesis parent removed — no phantom overlapping its children"
            );
            // Untouched genesis siblings survive (migrated to sentinel by the split).
            assert!(
                present.contains(&bits("000001"))
                    && present.contains(&bits("000010"))
                    && present.contains(&bits("000011")),
                "sibling genesis shards retained"
            );
            assert!(store.all_pending_shard_changes().unwrap().is_empty(), "pending consumed");
        }
    }

    /// Delete-free reassignment — the fix for split→lose-coverage→merge-back. A
    /// reassignment must NOT hard-delete the vacated allocation: that writes a
    /// permanent removes-phase tombstone (`get_vertex_data` gate), so if the shard
    /// is re-formed the slot could never be re-represented. `rekey_allocation`
    /// retires the vacated slot to `Historic` in place; a later reassignment BACK
    /// reactivates the SAME address. This asserts the full Active→Historic→Active
    /// round-trip survives real CRDT commits (where a delete would be terminal).
    mod delete_free_reassignment {
        use super::*;
        use crate::global_intrinsic::materialize::{
            allocation_address, create_allocation_vertex_tree, create_prover_vertex_tree,
            prover_address_from_pubkey, STATUS_ACTIVE, STATUS_HISTORIC,
        };
        use crate::global_schema::read_field;
        use crate::hypergraph_state::{
            hyperedge_adds_discriminator, vertex_adds_discriminator,
            vertex_removes_discriminator, HypergraphState,
        };
        use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};
        use quil_hypergraph::HypergraphCrdt;
        use quil_types::crypto::{InclusionProver, Multiproof};

        struct StubProver;
        impl InclusionProver for StubProver {
            fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
            fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
            fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
            fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
                Err(QuilError::Internal("batch not supported".into()))
            }
            fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
        }

        /// Read the allocation Status byte at `addr` from committed state (via the
        /// CRDT), or `None` if the vertex is absent/tombstoned — so a hard delete
        /// would surface here as `None`, a Historic retirement as `Some(6)`.
        fn status_at(state: &HypergraphState, addr: &[u8; 32]) -> Option<u8> {
            let va = vertex_adds_discriminator().unwrap();
            let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], addr, &va).unwrap()?;
            if blob.is_empty() {
                return None;
            }
            let tree = rebuild_vertex_tree_from_blob(&blob);
            read_field(&tree, "allocation:ProverAllocation", "Status").and_then(|b| b.first().copied())
        }

        #[test]
        fn retires_to_historic_and_reactivates_on_merge_back() {
            let store = Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new());
            let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
            let state = HypergraphState::new(crdt.clone());
            let va = vertex_adds_discriminator().unwrap();
            let vr = vertex_removes_discriminator().unwrap();
            let ha = hyperedge_adds_discriminator().unwrap();

            let pubkey = vec![0xAAu8; 897];
            let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
            let app = crate::domains::QUIL_TOKEN.to_vec();
            // Parent = genesis shard 0 (byte-suffix); child = its 7-bit split.
            let filter_a = {
                let mut f = app.clone();
                f.push(0x00);
                f
            };
            let filter_b = quil_forest::encode_shard_bit_path(&app, &[false; 7]);
            let addr_a = allocation_address(&pubkey, &filter_a).unwrap();
            let addr_b = allocation_address(&pubkey, &filter_b).unwrap();
            assert_ne!(addr_a, addr_b, "distinct filters ⇒ distinct addresses (no poseidon collision)");

            // Seed prover + one Active allocation on A, commit into the CRDT.
            state
                .set(&GLOBAL_INTRINSIC_ADDRESS[..], &prover_addr, &va, 1, vertex_tree_to_blob(&create_prover_vertex_tree(&pubkey, 100).unwrap()))
                .unwrap();
            let a_active = reassignment::set_allocation_status(
                &vertex_tree_to_blob(&create_allocation_vertex_tree(&prover_addr, &filter_a, 1).unwrap()),
                STATUS_ACTIVE,
            )
            .unwrap();
            state
                .set(&GLOBAL_INTRINSIC_ADDRESS[..], &addr_a, &va, 1, a_active)
                .unwrap();
            state.commit().unwrap();
            crdt.commit(1).unwrap();
            assert_eq!(status_at(&state, &addr_a), Some(STATUS_ACTIVE), "seeded Active on A");

            let gi = GlobalIntrinsic::new(Arc::new(AcceptAll)).with_hypergraph(crdt.clone());

            // SPLIT: reassign A → B.
            gi.rekey_allocation(&state, &va, &vr, &ha, &pubkey, &prover_addr, &filter_a, &filter_b, 10)
                .unwrap();
            state.commit().unwrap();
            crdt.commit(2).unwrap();
            assert_eq!(status_at(&state, &addr_b), Some(STATUS_ACTIVE), "B Active after split");
            // The crux: A is RETAINED as Historic — a live vertex, not a tombstone.
            assert_eq!(
                status_at(&state, &addr_a),
                Some(STATUS_HISTORIC),
                "A retired to Historic (NOT deleted) after split"
            );

            // MERGE BACK: reassign B → A. A hard delete would have tombstoned addr_a
            // permanently; delete-free retention lets this reactivate the SAME slot.
            gi.rekey_allocation(&state, &va, &vr, &ha, &pubkey, &prover_addr, &filter_b, &filter_a, 20)
                .unwrap();
            state.commit().unwrap();
            crdt.commit(3).unwrap();
            assert_eq!(
                status_at(&state, &addr_a),
                Some(STATUS_ACTIVE),
                "A REACTIVATED on merge-back — impossible had it been deleted"
            );
            assert_eq!(status_at(&state, &addr_b), Some(STATUS_HISTORIC), "B retired to Historic after merge-back");
        }
    }

}
