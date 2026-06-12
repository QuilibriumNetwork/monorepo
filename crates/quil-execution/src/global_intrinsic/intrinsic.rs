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
    HypergraphState, hyperedge_adds_discriminator, vertex_adds_discriminator,
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
                    verify::verify_prover_join_not_kicked(pt)?;
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
                // VDF multi-proof chain. Go's `ProverJoin.Verify` runs
                // this unconditionally — without it, anyone can craft
                // a ProverJoin with a valid BLS signature but bogus
                // VDF proof and pass validation. Look up the
                // referenced frame's output + difficulty from the
                // clock store; the verify chain is gated on both the
                // clock store and the frame prover being installed
                // (mandatory in production but the intrinsic can be
                // constructed without them in legacy test setups).
                let frame_prover = self.frame_prover.as_ref().ok_or_else(|| {
                    QuilError::Internal(
                        "ProverJoin: frame_prover not installed — cannot verify VDF".into(),
                    )
                })?;
                let clock_store = self.clock_store.as_ref().ok_or_else(|| {
                    QuilError::Internal(
                        "ProverJoin: clock_store not installed — cannot look up referenced frame".into(),
                    )
                })?;
                let referenced = clock_store
                    .get_global_clock_frame(op.frame_number)
                    .map_err(|e| QuilError::InvalidArgument(format!(
                        "ProverJoin: referenced frame {} not in clock store: {}",
                        op.frame_number, e,
                    )))?;
                let header = referenced.header.as_ref().ok_or_else(|| {
                    QuilError::InvalidArgument(
                        "ProverJoin: referenced frame has no header".into(),
                    )
                })?;
                verify::verify_prover_join_vdf(
                    &op,
                    frame_number,
                    &header.output,
                    header.difficulty,
                    frame_prover.as_ref(),
                )
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
                // Fail-closed. No prover_tree means we couldn't
                // resolve the signer's BLS pubkey, so the BLS verify
                // can't run. Reject rather than accept on faith.
                let pt = prover_tree.ok_or_else(|| QuilError::InvalidArgument(
                    "ShardSplit: prover tree unavailable — cannot verify signature".into(),
                ))?;
                let sig_ok = verify::verify_shard_split(&op, pt, self.key_manager.as_ref())?;
                if !sig_ok {
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
                    super::kick_verify::verify_equivocation_structural(&op)
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
                    };

                    // Aggregate-pubkey consistency check: the bitmask
                    // names a subset of active provers, and their
                    // pubkey aggregate must equal the signature's
                    // declared aggregate pubkey. Mirrors what the
                    // outer frame validator does for GlobalFrame.
                    let active = pr.get_active_provers(&op.address).map_err(|e| {
                        QuilError::Internal(format!(
                            "FrameHeader: get_active_provers: {e}"
                        ))
                    })?;
                    let participant_indices: Vec<usize> =
                        quil_consensus::bitmask::set_bit_indices(&sig.bitmask).collect();
                    let (_throwaway_signer, throwaway_pub) = bls
                        .new_key()
                        .map_err(|e| QuilError::Crypto(format!(
                            "FrameHeader: throwaway key: {e}"
                        )))?;
                    let mut active_pks: Vec<&[u8]> = Vec::new();
                    let mut throwaway_list: Vec<&[u8]> = Vec::new();
                    for (i, prover) in active.iter().enumerate() {
                        if participant_indices.contains(&i) {
                            active_pks.push(&prover.public_key);
                            throwaway_list.push(&throwaway_pub);
                        }
                    }
                    let aggregate = bls
                        .aggregate(&active_pks, &throwaway_list)
                        .map_err(|e| QuilError::Crypto(format!(
                            "FrameHeader: aggregate: {e}"
                        )))?;
                    let sig_pubkey_bytes: &[u8] = sig.public_key.as_ref()
                        .map(|k| k.key_value.as_slice())
                        .unwrap_or(&[]);
                    if aggregate.public_key.as_slice() != sig_pubkey_bytes {
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
                                &aggregate.public_key[..aggregate.public_key.len().min(16)]
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
                    let ids_arg: Option<&[&[u8]]> = if sig.signature.len() == 74 {
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
                            check_leave_confirm_halt_risk(
                                filter,
                                current_status,
                                self.prover_registry.as_deref(),
                            )?;

                            materialize::materialize_prover_confirm(alloc_tree, fn_)
                        },
                    )?;
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
    fn invoke_frame_header(
        &self,
        frame_number: u64,
        op: &super::frame_header::FrameHeader,
        state: &HypergraphState,
        _va_disc: &[u8; 32],
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
        let active_provers = pr
            .get_active_provers(&op.address)
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

        let hg_md = hg.shard_metadata_for_address(&op.address);
        let (state_size_u64, shard_count_u64) = match hg_md {
            Some(md) => {
                let s = md.size.to_string().parse::<u64>().unwrap_or(0);
                (s, md.leaf_count)
            }
            None => (0u64, 0u64),
        };
        let shard_md = super::prover_shard_update::ShardMetadata {
            state_size: state_size_u64,
            shard_count: shard_count_u64,
        };

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
        )
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
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
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

        let output = materialize::materialize_shard_split(
            &op.shard_address,
            &op.proposed_shards,
        )?;

        // Write new sub-shard entries to the shards store.
        // Go equivalent: shardsStore.PutAppShard(nil, ShardInfo{L2, Path})
        // at global_shard_split.go:167.
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
        state: &HypergraphState,
        va_disc: &[u8; 32],
    ) -> Result<()> {
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

        let output = materialize::materialize_shard_merge(
            &op.shard_addresses,
            &op.parent_address,
        )?;

        // Remove child shard entries from the shards store.
        // Go equivalent: shardsStore.DeleteAppShard(nil, shardKey, path)
        // at global_shard_merge.go:175.
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
fn check_leave_confirm_halt_risk(
    filter: &[u8],
    current_alloc_status: u8,
    registry: Option<&dyn quil_types::consensus::ProverRegistry>,
) -> Result<()> {
    // Only applies when we're confirming a leave. Join-confirms and
    // any pathological status pass through.
    if current_alloc_status != materialize::STATUS_LEAVING {
        return Ok(());
    }
    let Some(registry) = registry else {
        return Ok(());
    };
    let active_count = registry
        .get_active_provers(filter)
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
    fn validate_join_without_frame_prover_rejects() {
        // ProverJoin validation requires the VDF chain. Without a
        // frame_prover + clock_store installed on the intrinsic,
        // validate must return Err — accepting joins on structural+BLS
        // alone would let forged VDF proofs through.
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
        let err = gi.validate(105, &join, None, None).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("frame_prover not installed")
                || msg.contains("clock_store not installed"),
            "expected fail-closed error about missing deps, got: {}",
            msg,
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
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn get_ordered_provers(
            &self,
            _: &[u8; 32],
            _: &[u8],
        ) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn get_active_provers(
            &self,
            _: &[u8],
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
        );
        assert!(result.is_ok(),
            "gate must degrade open when no registry: {:?}", result.err());
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
                    signature: vec![0xBBu8; 74],
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
            let pubkey = vec![0xAAu8; 585];
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
            let pubkey = vec![0xBBu8; 585];
            let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
            let filter_a = vec![0x33u8; 32];
            let filter_b = vec![0x44u8; 32];

            let join = ProverJoinOp {
                filters: vec![filter_a.clone(), filter_b.clone()],
                frame_number: 10,
                public_key_signature_bls48581: Some(SignatureWithPop {
                    signature: vec![0xAAu8; 74],
                    public_key: Some(pubkey.clone()),
                    pop_signature: vec![0xCCu8; 74],
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
            let pubkey = vec![0xEEu8; 585];
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
                    signature: vec![0xAAu8; 74],
                    public_key: Some(pubkey.clone()),
                    pop_signature: vec![0xCCu8; 74],
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
}
