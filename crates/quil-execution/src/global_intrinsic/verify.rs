//! Prover op verify implementations. These wire together the signing
//! message construction, domain hash, state lookups, and BLS signature
//! verification into complete verify paths.
//!
//! Each verify function takes:
//! - The decoded canonical-bytes op struct
//! - A `VectorCommitmentTree` for the prover vertex (loaded externally)
//! - A `VectorCommitmentTree` for the allocation vertex (loaded externally)
//! - A `&dyn KeyManager` for signature verification
//!
//! The calling code (the global intrinsic dispatcher) is responsible for
//! loading the vertex trees from the hypergraph CRDT. This module only
//! does the pure verification logic.

use std::sync::atomic::{AtomicU64, Ordering};

use quil_types::crypto::{KeyManager, KeyType};
use quil_types::error::{QuilError, Result};

use crate::global_schema::{read_field, read_type};
use super::prover_filter_ops::{ProverLeave, ProverPause, ProverResume};
use super::prover_join::ProverJoin;
use super::prover_ops::{ProverConfirm, ProverReject};
use super::prover_verify;
use super::materialize::prover_address_from_pubkey;

/// Minimum frames after a join/leave before a Confirm can be applied.
/// Mainnet uses 360 (`global_prover_confirm.go:507`); testnet/devnet
/// override to a smaller value via [`set_confirm_window_frames`] so a
/// 4-node smoke test doesn't have to wait an hour for joins to settle.
pub static MIN_CONFIRM_FRAMES: AtomicU64 = AtomicU64::new(360);
/// Maximum frames after a join/leave before a Confirm is rejected as
/// expired. Default 720; clamped to `>= MIN_CONFIRM_FRAMES + 1` by the
/// setter so a misconfiguration can't produce an empty window.
pub static MAX_CONFIRM_FRAMES: AtomicU64 = AtomicU64::new(720);

/// Override the confirm-timing window. Call once at startup before
/// any frames are processed; the values are read on every confirm
/// without further locking. Passing `min == 0` keeps mainnet defaults.
pub fn set_confirm_window_frames(min: u64, max: u64) {
    if min == 0 {
        return;
    }
    let max = max.max(min + 1);
    MIN_CONFIRM_FRAMES.store(min, Ordering::Relaxed);
    MAX_CONFIRM_FRAMES.store(max, Ordering::Relaxed);
}

/// Verify a `ProverPause` operation.
///
/// Go equivalent: `ProverPause::Verify` at
/// `global_prover_pause.go:324`.
///
/// Steps:
/// 1. Check the prover vertex exists and is a Prover type
/// 2. Read the prover's public key from the vertex tree
/// 3. Compute the allocation address and check it exists with status=1 (active)
/// 4. Build the signing message and domain hash
/// 5. Verify the BLS48-581 G1 signature
pub fn verify_prover_pause(
    op: &ProverPause,
    prover_tree: &quil_tries::VectorCommitmentTree,
    allocation_tree: Option<&quil_tries::VectorCommitmentTree>,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    // 1. Check vertex type
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover pause: prover vertex has no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument(format!(
            "verify prover pause: expected prover:Prover, got {}",
            vertex_type
        )));
    }

    // 2. Read public key
    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover pause: no PublicKey in prover vertex".into())
    })?;

    // 3. Check allocation status = 1 (active)
    if let Some(alloc_tree) = allocation_tree {
        let status_bytes = read_field(alloc_tree, "allocation:ProverAllocation", "Status");
        let status = status_bytes.as_ref().and_then(|b| b.first().copied()).unwrap_or(0);
        if status != 1 {
            return Err(QuilError::InvalidArgument(format!(
                "verify prover pause: allocation status is {} (expected 1=active)",
                status
            )));
        }
    }

    // 4. Build signing message and domain
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover pause: missing signature".into())
    })?;

    let message = prover_verify::single_filter_signing_message(&op.filter, op.frame_number);
    let domain = prover_verify::prover_pause_domain()?;

    // 5. Verify BLS48-581 G1 signature
    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

/// Verify a `ProverResume` operation. Same shape as pause.
pub fn verify_prover_resume(
    op: &ProverResume,
    prover_tree: &quil_tries::VectorCommitmentTree,
    allocation_tree: Option<&quil_tries::VectorCommitmentTree>,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover resume: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument("verify prover resume: wrong type".into()));
    }

    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover resume: no PublicKey".into())
    })?;

    // Check allocation status = 2 (paused) for resume
    if let Some(alloc_tree) = allocation_tree {
        let status = read_field(alloc_tree, "allocation:ProverAllocation", "Status")
            .and_then(|b| b.first().copied())
            .unwrap_or(0);
        if status != 2 {
            return Err(QuilError::InvalidArgument(format!(
                "verify prover resume: allocation status is {} (expected 2=paused)",
                status
            )));
        }
    }

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover resume: missing signature".into())
    })?;

    let message = prover_verify::single_filter_signing_message(&op.filter, op.frame_number);
    let domain = prover_verify::prover_resume_domain()?;

    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

/// ProverLeave active-allocation gate. Mirrors Go
/// `global_prover_leave.go:395-436`. Without this, a leave for a
/// prover that is already left/kicked passes verify but fails
/// materialize — splitting consensus between nodes that run
/// materialize and those that don't.
///
/// `lookup_alloc` returns the per-filter allocation tree (None if no
/// vertex exists). At least one allocation in the leave's filters
/// must be Status=1 (active) for the leave to be accepted.
pub fn verify_prover_leave_has_active_allocation<F>(
    op: &ProverLeave,
    pubkey: &[u8],
    mut lookup_alloc: F,
) -> Result<()>
where
    F: FnMut(&[u8; 32]) -> Result<Option<quil_tries::VectorCommitmentTree>>,
{
    const STATUS_ACTIVE: u8 = 1;
    for filter in &op.filters {
        let alloc_addr = super::materialize::allocation_address(pubkey, filter)?;
        let Some(alloc_tree) = lookup_alloc(&alloc_addr)? else {
            continue;
        };
        let status = read_field(&alloc_tree, "allocation:ProverAllocation", "Status")
            .and_then(|b| b.first().copied())
            .unwrap_or(4);
        if status == STATUS_ACTIVE {
            return Ok(());
        }
    }
    Err(QuilError::InvalidArgument(
        "ProverLeave verify: no active allocations found for any of the requested filters".into(),
    ))
}

/// Verify a `ProverLeave` operation.
pub fn verify_prover_leave(
    op: &ProverLeave,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover leave: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument("verify prover leave: wrong type".into()));
    }

    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover leave: no PublicKey".into())
    })?;

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover leave: missing signature".into())
    })?;

    let message = prover_verify::multi_filter_signing_message(&op.filters, op.frame_number);
    let domain = prover_verify::prover_leave_domain()?;

    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

// =====================================================================
// ProverJoin structural validation
// =====================================================================

/// VDF proof size per filter (516 bytes per filter).
pub const PROOF_CHUNK_SIZE: usize = 516;
/// Minimum filter length in bytes.
pub const MIN_FILTER_LEN: usize = 32;
/// Maximum frames a join request can be older than current frame.
pub const JOIN_FRESHNESS_WINDOW: u64 = 10;

/// Structural validation for ProverJoin — checks everything that
/// doesn't require external dependencies (frame store, VDF prover).
///
/// Checks:
/// 1. All filters are >= 32 bytes
/// 2. Proof size == 516 * len(filters)
/// 3. frame_number + 10 >= current_frame (not too stale)
/// 4. Signature-with-PoP is present
/// 5. Public key in signature is non-empty
/// 6. Prover address derivation succeeds
pub fn validate_prover_join_structural(
    op: &ProverJoin,
    current_frame_number: u64,
) -> Result<ProverJoinValidation> {
    // 1. Filter sizes
    for (i, filter) in op.filters.iter().enumerate() {
        if filter.len() < MIN_FILTER_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "prover join: filter {} is {} bytes (min {})",
                i,
                filter.len(),
                MIN_FILTER_LEN
            )));
        }
    }

    // 2. Proof size
    let expected_proof_size = PROOF_CHUNK_SIZE * op.filters.len();
    if op.proof.len() != expected_proof_size {
        return Err(QuilError::InvalidArgument(format!(
            "prover join: proof size {} != expected {} (516 * {} filters)",
            op.proof.len(),
            expected_proof_size,
            op.filters.len()
        )));
    }

    // 3. Freshness
    if op.frame_number + JOIN_FRESHNESS_WINDOW < current_frame_number {
        return Err(QuilError::InvalidArgument(format!(
            "prover join: request frame {} is too old (current {})",
            op.frame_number, current_frame_number
        )));
    }

    // 4. Signature present
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover join: missing signature with PoP".into())
    })?;

    // 5. Public key non-empty
    let public_key = sig.public_key.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover join: signature has no public key".into())
    })?;
    if public_key.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover join: empty public key".into(),
        ));
    }

    // 6. Derive prover address
    let prover_address = prover_address_from_pubkey(public_key)?;

    Ok(ProverJoinValidation {
        public_key: public_key.clone(),
        prover_address,
        filter_count: op.filters.len(),
    })
}

/// Full ProverJoin verification including VDF multi-proof.
///
/// Requires:
/// - `frame_output`: the VDF output of the frame referenced by `op.frame_number`
/// - `frame_difficulty`: the difficulty of that frame
/// - `frame_prover`: the VDF prover for multi-proof verification
///
/// This is the complete verify path that Go's `ProverJoin.Verify` runs.
pub fn verify_prover_join_vdf(
    op: &ProverJoin,
    current_frame_number: u64,
    frame_output: &[u8],
    frame_difficulty: u32,
    frame_prover: &dyn quil_types::crypto::FrameProver,
) -> Result<bool> {
    // 1. Structural validation
    let validation = validate_prover_join_structural(op, current_frame_number)?;

    // 2. Compute challenge from frame output (Go: sha3.Sum256)
    use sha3::Digest;
    let challenge: [u8; 32] = sha3::Sha3_256::digest(frame_output).into();

    // 3. Build ID list: for each filter, id = prover_address || filter || index_be
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(op.filters.len());
    for (idx, filter) in op.filters.iter().enumerate() {
        let mut id = Vec::with_capacity(32 + filter.len() + 4);
        id.extend_from_slice(&validation.prover_address);
        id.extend_from_slice(filter);
        id.extend_from_slice(&(idx as u32).to_be_bytes());
        ids.push(id);
    }

    // 4. Split proof into 516-byte chunks
    let mut solutions: Vec<Vec<u8>> = Vec::with_capacity(op.filters.len());
    for i in 0..op.filters.len() {
        solutions.push(op.proof[i * PROOF_CHUNK_SIZE..(i + 1) * PROOF_CHUNK_SIZE].to_vec());
    }

    // 5. Verify VDF multi-proof
    let id_refs: Vec<&[u8]> = ids.iter().map(|id| id.as_slice()).collect();
    let sol_refs: Vec<&[u8]> = solutions.iter().map(|s| s.as_slice()).collect();

    frame_prover.verify_multi_proof(
        &challenge,
        frame_difficulty,
        &id_refs,
        &sol_refs,
    )
}

/// Output of structural validation — carries the derived values
/// forward so the caller doesn't need to recompute them.
pub struct ProverJoinValidation {
    /// The BLS48-581 public key from the signature.
    pub public_key: Vec<u8>,
    /// The 32-byte prover address derived from the public key.
    pub prover_address: [u8; 32],
    /// Number of filters (= number of allocations to create).
    pub filter_count: usize,
}

/// Verify the BLS signatures on a `ProverJoin`. Mirrors Go's
/// `ProverJoin.Verify` at `global_prover_join.go:1095-1146`. Structural
/// validation is assumed to have already passed — the caller supplies
/// the resulting `ProverJoinValidation`.
///
/// Checks:
/// 1. BLS sig over `concat(filters) || frame_number_be_u64` with domain
///    `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_JOIN")`.
/// 2. Proof-of-possession: BLS sig over pubkey with ASCII domain
///    `"BLS48_POP_SK"` (Go uses the domain bytes literally, not a
///    poseidon hash — matches `global_prover_join.go:1093`).
/// 3. Each merge target's signature over pubkey with Ed448 context
///    `"PROVER_JOIN_MERGE"` (skipped for already-consumed targets).
///
/// Go skips merge-sig verification when the merge's spent-vertex
/// already exists in the hypergraph (replay guard). This port takes
/// `consumed_merge_check` as an optional closure — callers with a live
/// hypergraph can pass one; otherwise all non-empty merges are verified.
pub fn verify_prover_join_signatures(
    op: &ProverJoin,
    validation: &ProverJoinValidation,
    key_manager: &dyn KeyManager,
    consumed_merge_check: Option<&dyn Fn(&[u8]) -> bool>,
) -> Result<bool> {
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover join verify: missing signature".into())
    })?;

    // 1. Main join signature.
    //
    // Go signs the full canonical-bytes of the ProverJoin with
    // `PublicKeySignatureBls48581 = nil` — NOT just
    // `concat(filters) || frame_be_u64`. See
    // `node/execution/intrinsics/global/global_prover_join.go:1074-1102`:
    //
    //     joinClone := p.ToProtobuf()
    //     joinClone.PublicKeySignatureBls48581 = nil
    //     joinMessage, err := joinClone.ToCanonicalBytes()
    //     ...
    //     keyManager.ValidateSignature(.., joinMessage, sig, domain)
    //
    // Signing `concat(filters) || frame_be_u64` (the previous Rust
    // impl) would reject every Go-signed join in production.
    let join_domain = super::prover_verify::prover_join_domain()?;
    let mut clone = op.clone();
    clone.public_key_signature_bls48581 = None;
    let join_message = clone.to_canonical_bytes()?;
    let ok = key_manager.validate_signature(
        KeyType::Bls48581G1,
        &validation.public_key,
        &join_message,
        &sig.signature,
        &join_domain,
    )?;
    if !ok {
        return Ok(false);
    }

    // 2. Proof of possession: sig over pubkey itself with the literal
    //    domain bytes "BLS48_POP_SK" (no poseidon wrapping in Go).
    const POP_DOMAIN: &[u8] = b"BLS48_POP_SK";
    let ok = key_manager.validate_signature(
        KeyType::Bls48581G1,
        &validation.public_key,
        &validation.public_key,
        &sig.pop_signature,
        POP_DOMAIN,
    )?;
    if !ok {
        return Ok(false);
    }

    // 3. Merge target signatures — each signs the local BLS pubkey
    //    with an Ed448 (or other) key under the "PROVER_JOIN_MERGE"
    //    domain. Skip targets whose spent-vertex already exists.
    const MERGE_DOMAIN: &[u8] = b"PROVER_JOIN_MERGE";
    for mt in &op.merge_targets {
        if let Some(check) = consumed_merge_check {
            if check(&mt.prover_public_key) {
                continue;
            }
        }
        let key_type = match mt.key_type {
            0 => KeyType::Ed448,
            1 => KeyType::X448,
            2 => KeyType::Bls48581G1,
            3 => KeyType::Bls48581G2,
            4 => KeyType::Decaf448,
            other => {
                return Err(QuilError::InvalidArgument(format!(
                    "prover join verify: merge target has unknown key_type {}",
                    other
                )));
            }
        };
        let ok = key_manager.validate_signature(
            key_type,
            &mt.prover_public_key,
            &validation.public_key,
            &mt.signature,
            MERGE_DOMAIN,
        )?;
        if !ok {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Active-global-prover gate for ShardSplit / ShardMerge. Mirrors Go
/// `global_shard_split.go:92-102` (and the matching
/// `global_shard_merge.go` lines). The signer must be a registered
/// prover AND have at least one allocation with empty
/// ConfirmationFilter (the global filter) at Status=ACTIVE (=1).
/// Revoked / paused / kicked provers can otherwise produce
/// signature-valid splits/merges that pass verify but should fail at
/// materialize.
///
/// The prover-tree existence already gates "registered" — the
/// `verify_addressed_bls` helper rejects with `prover vertex not
/// found`. This helper layers on the active-status check.
pub fn verify_shard_op_signer_is_active_global<F>(
    prover_tree: &quil_tries::VectorCommitmentTree,
    mut lookup_alloc: F,
) -> Result<()>
where
    F: FnMut(&[u8; 32]) -> Result<Option<quil_tries::VectorCommitmentTree>>,
{
    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument(
            "verify shard op: prover vertex missing PublicKey".into(),
        )
    })?;
    let global_filter: Vec<u8> = Vec::new();
    let alloc_addr = super::materialize::allocation_address(&pubkey, &global_filter)?;
    let Some(alloc_tree) = lookup_alloc(&alloc_addr)? else {
        return Err(QuilError::InvalidArgument(
            "verify shard op: signer has no global allocation — not an active global prover"
                .into(),
        ));
    };
    let status = read_field(&alloc_tree, "allocation:ProverAllocation", "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(4);
    const STATUS_ACTIVE: u8 = 1;
    if status != STATUS_ACTIVE {
        return Err(QuilError::InvalidArgument(format!(
            "verify shard op: signer's global allocation is not active (status={})",
            status,
        )));
    }
    Ok(())
}

/// ProverSeniorityMerge spent-merge deduplication gate. Mirrors Go
/// `global_prover_seniority_merge.go:476-540`. For each merge target,
/// look up two tombstone vertices in the global domain:
///
///   - `spent_seniority_merge_address(target_pubkey)` —
///     PROVER_SENIORITY_MERGE was already consumed.
///   - `spent_join_merge_address(target_pubkey)` —
///     PROVER_JOIN_MERGE consumed the same target during a
///     ProverJoin's merge_targets list.
///
/// Finding EITHER marker means the merge target has already been
/// claimed by some prover; allowing the current op would split the
/// target's seniority between two provers. Without this gate, two
/// provers could both pass verify with the same merge_target, both
/// pass into a frame, then materialize would reject one — splitting
/// consensus on which prover ends up with the seniority.
///
/// `lookup_tombstone` is invoked for each target's spent address. The
/// caller threads state through it. Returning `Ok(Some(_))` means
/// "marker exists"; `Ok(None)` means "fresh, may merge".
pub fn verify_prover_seniority_merge_spent_markers<F>(
    op: &super::prover_ops::ProverSeniorityMerge,
    mut lookup_tombstone: F,
) -> Result<()>
where
    F: FnMut(&[u8; 32]) -> Result<Option<Vec<u8>>>,
{
    for mt in &op.merge_targets {
        let join_marker = super::materialize::spent_join_merge_address(&mt.prover_public_key)?;
        if lookup_tombstone(&join_marker)?.is_some() {
            return Err(QuilError::InvalidArgument(
                "ProverSeniorityMerge verify: merge target already consumed by \
                 a prior ProverJoin (PROVER_JOIN_MERGE tombstone)".into(),
            ));
        }
        let seniority_marker =
            super::materialize::spent_seniority_merge_address(&mt.prover_public_key)?;
        if lookup_tombstone(&seniority_marker)?.is_some() {
            return Err(QuilError::InvalidArgument(
                "ProverSeniorityMerge verify: merge target already consumed by \
                 a prior ProverSeniorityMerge (PROVER_SENIORITY_MERGE tombstone)".into(),
            ));
        }
    }
    Ok(())
}

/// ProverJoin kicked-prover gate. Mirrors Go
/// `global_prover_join.go:972-988`: if the existing prover vertex has
/// a non-zero `KickFrameNumber`, the join must be rejected. A
/// previously-kicked prover cannot rejoin with the same public key
/// (otherwise eviction-for-malice has no teeth).
///
/// Without this gate at verify time, a kicked prover's join would
/// pass BLS+VDF validation, only to be rejected at materialize on
/// nodes that ran materialization — splitting consensus between
/// validators that did and did not run materialize.
pub fn verify_prover_join_not_kicked(
    prover_tree: &quil_tries::VectorCommitmentTree,
) -> Result<()> {
    let kf_bytes =
        read_field(prover_tree, "allocation:ProverAllocation", "KickFrameNumber")
            .or_else(|| read_field(prover_tree, "prover:Prover", "KickFrameNumber"));
    let Some(kf_bytes) = kf_bytes else {
        return Ok(());
    };
    if kf_bytes.len() != 8 {
        return Ok(());
    }
    let kf = u64::from_be_bytes(kf_bytes.try_into().unwrap());
    if kf != 0 {
        return Err(QuilError::InvalidArgument(format!(
            "ProverJoin verify: prover has been previously kicked \
             (KickFrameNumber={})",
            kf,
        )));
    }
    Ok(())
}

/// ProverJoin existing-allocation expiry gate. Mirrors Go
/// `global_prover_join.go:990-1069`. For each filter in the join, the
/// prover's existing allocation (if any) must be either status=4
/// (left/kicked) OR expired (`frame_number >= JoinFrameNumber + 720`).
/// Otherwise the prover is trying to claim coverage on a shard they
/// are already on, which would double-count their PoMW.
///
/// `lookup_alloc` is the per-allocation tree loader the caller
/// supplies — it lets this helper stay free of state-store coupling.
/// Pass `Ok(None)` for filters with no existing allocation vertex.
pub fn verify_prover_join_allocations_expired<F>(
    op: &ProverJoin,
    pubkey: &[u8],
    frame_number: u64,
    mut lookup_alloc: F,
) -> Result<()>
where
    F: FnMut(&[u8; 32]) -> Result<Option<quil_tries::VectorCommitmentTree>>,
{
    for filter in &op.filters {
        let alloc_addr = super::materialize::allocation_address(pubkey, filter)?;
        let Some(alloc_tree) = lookup_alloc(&alloc_addr)? else {
            continue;
        };
        let status = read_field(&alloc_tree, "allocation:ProverAllocation", "Status")
            .and_then(|b| b.first().copied())
            .unwrap_or(4);
        if status == 4 {
            continue;
        }
        let jf_bytes = read_field(&alloc_tree, "allocation:ProverAllocation", "JoinFrameNumber")
            .ok_or_else(|| QuilError::InvalidArgument(format!(
                "ProverJoin verify: existing allocation for filter is active \
                 (status={}) with no JoinFrameNumber — refusing to rejoin",
                status,
            )))?;
        if jf_bytes.len() != 8 {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin verify: existing allocation has malformed \
                 JoinFrameNumber ({} bytes)",
                jf_bytes.len(),
            )));
        }
        let jf = u64::from_be_bytes(jf_bytes.try_into().unwrap());
        const REJOIN_WINDOW: u64 = 720;
        if frame_number < jf.saturating_add(REJOIN_WINDOW) {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin verify: existing allocation still active \
                 (status={}, frames_since_join={})",
                status,
                frame_number.saturating_sub(jf),
            )));
        }
    }
    Ok(())
}

/// Verify a `ProverUpdate` operation. The signing message is just the
/// delegate_address; the domain is PROVER_UPDATE (but Go actually
/// uses an empty domain for updates — the signature covers just the
/// delegate address bytes with the addressed-signature's address as
/// context).
pub fn verify_prover_update(
    op: &super::prover_ops::ProverUpdate,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover update: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument("verify prover update: wrong type".into()));
    }

    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover update: no PublicKey".into())
    })?;

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover update: missing signature".into())
    })?;

    // Address-binding cross-check. Mirrors Go
    // `global_prover_update.go:364-375`: derive
    // `poseidon(pubkey_from_tree)` and assert it equals the address
    // declared by the op's signature. Without this, the prover tree
    // could be looked up by ONE address, but the signature could
    // claim a DIFFERENT address — bypassing per-prover authority.
    if sig.address.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "verify prover update: signature.address must be 32 bytes, got {}",
            sig.address.len(),
        )));
    }
    let derived_addr = prover_address_from_pubkey(&pubkey)?;
    if derived_addr.as_slice() != sig.address.as_slice() {
        return Ok(false);
    }

    // ProverUpdate signing message is just the delegate_address.
    // Domain matches Go's `global_prover_update.go:378` —
    // `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_UPDATE")`.
    let message = &op.delegate_address;
    let domain = super::prover_update_materialize::prover_update_domain()?;

    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        message,
        &sig.signature,
        &domain,
    )
}

/// Verify a `ProverConfirm` operation. Same BLS signature check as
/// the filter ops, but uses multi-filter signing message and the
/// PROVER_CONFIRM domain.
pub fn verify_prover_confirm(
    op: &ProverConfirm,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover confirm: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument("verify prover confirm: wrong type".into()));
    }

    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover confirm: no PublicKey".into())
    })?;

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover confirm: missing signature".into())
    })?;

    let message = prover_verify::multi_filter_signing_message(&op.filters, op.frame_number);
    let domain = prover_verify::prover_confirm_domain()?;

    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

/// Validate ProverConfirm timing constraints. Called during invoke_step
/// with the allocation tree loaded. Mirrors Go's frame window checks in
/// `global_prover_confirm.go:492-574`.
///
/// - Join confirm (status=0): must wait 360-720 frames after JoinFrameNumber
/// - Leave confirm (status=3): must wait 360-720 frames after LeaveFrameNumber
pub fn validate_confirm_timing(
    frame_number: u64,
    allocation_tree: &quil_tries::VectorCommitmentTree,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";
    let status = crate::global_schema::read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(255);

    match status {
        0 => {
            // Joining — check JoinFrameNumber timing
            let join_frame_bytes = crate::global_schema::read_field(
                allocation_tree, cls, "JoinFrameNumber",
            ).unwrap_or_default();
            if join_frame_bytes.len() != 8 {
                return Err(QuilError::InvalidArgument(
                    "confirm: missing JoinFrameNumber".into(),
                ));
            }
            let mut join_frame = u64::from_be_bytes(join_frame_bytes.try_into().unwrap());

            // Tier-5 #11: 2.1 transition window. Joins between
            // 244100..255840 must wait until frame 255840 to confirm.
            // Once frame 255840 hits, those joins immediately become
            // eligible (they all "catch up" at once). Joins ≥ 255840
            // fall through to the normal 360..720 window. Mirrors Go's
            // `global_prover_confirm.go:507-546`.
            const TRANSITION_END: u64 =
                crate::token_intrinsic::constants::FRAME_2_1_EXTENDED_ENROLL_END;
            const TRANSITION_BEGIN: u64 = 244_100;
            if join_frame >= TRANSITION_BEGIN && join_frame < TRANSITION_END {
                if frame_number < TRANSITION_END {
                    return Err(QuilError::InvalidArgument(
                        "confirm: cannot confirm before frame 255840 (2.1 enrollment window)"
                            .into(),
                    ));
                }
                // Clamp join_frame so the resulting window starts at
                // (TRANSITION_END - 360). For joins newer than the
                // floor, leave them alone so they get the full 360.
                if join_frame < TRANSITION_END - 360 {
                    join_frame = TRANSITION_END - 360;
                }
            }

            // Joins ≥ (TRANSITION_END - 360) OR ≤ 244100 follow the
            // normal MIN..MAX window (360..720 on mainnet; configurable
            // for testnet via `set_confirm_window_frames`). Joins inside
            // the transition band were either rejected above or
            // clamped.
            if join_frame >= TRANSITION_END - 360 || join_frame <= TRANSITION_BEGIN {
                let min = MIN_CONFIRM_FRAMES.load(Ordering::Relaxed);
                let max = MAX_CONFIRM_FRAMES.load(Ordering::Relaxed);
                let frames_since = frame_number.saturating_sub(join_frame);
                if frames_since < min {
                    return Err(QuilError::InvalidArgument(format!(
                        "confirm: must wait {} frames after join (only {} elapsed)",
                        min, frames_since
                    )));
                }
                if frames_since > max {
                    return Err(QuilError::InvalidArgument(format!(
                        "confirm: join confirmation window expired ({} frames, {} elapsed)",
                        max, frames_since
                    )));
                }
            }
            Ok(())
        }
        3 => {
            // Leaving — check LeaveFrameNumber timing
            let leave_frame_bytes = crate::global_schema::read_field(
                allocation_tree, cls, "LeaveFrameNumber",
            ).unwrap_or_default();
            if leave_frame_bytes.len() != 8 {
                return Err(QuilError::InvalidArgument(
                    "confirm: missing LeaveFrameNumber".into(),
                ));
            }
            let leave_frame = u64::from_be_bytes(leave_frame_bytes.try_into().unwrap());
            let frames_since = frame_number.saturating_sub(leave_frame);
            let min = MIN_CONFIRM_FRAMES.load(Ordering::Relaxed);
            let max = MAX_CONFIRM_FRAMES.load(Ordering::Relaxed);
            if frames_since < min {
                return Err(QuilError::InvalidArgument(format!(
                    "confirm: must wait {} frames after leave (only {} elapsed)",
                    min, frames_since
                )));
            }
            if frames_since > max {
                return Err(QuilError::InvalidArgument(format!(
                    "confirm: leave confirmation window expired ({} frames, {} elapsed)",
                    max, frames_since
                )));
            }
            Ok(())
        }
        _ => Err(QuilError::InvalidArgument(format!(
            "confirm: invalid allocation status {} (expected 0=joining or 3=leaving)",
            status
        ))),
    }
}

/// Verify a `ProverReject` operation.
pub fn verify_prover_reject(
    op: &ProverReject,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("verify prover reject: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument("verify prover reject: wrong type".into()));
    }

    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("verify prover reject: no PublicKey".into())
    })?;

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("verify prover reject: missing signature".into())
    })?;

    let message = prover_verify::multi_filter_signing_message(&op.filters, op.frame_number);
    let domain = prover_verify::prover_reject_domain()?;

    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

// =====================================================================
// ShardSplit / ShardMerge / ProverSeniorityMerge verify
// =====================================================================
//
// These three ops share the AddressedSignature → prover_tree pubkey
// lookup pattern used by ProverUpdate/Confirm/Reject. Prior to these
// helpers, the dispatcher in `intrinsic.rs` routed all three through
// `peek_global_message_kind` which only validated the type prefix —
// leaving their BLS signatures unverified and allowing consensus
// bypass (forged shard rebalancing, forged seniority merges).

/// Compute `poseidon(GLOBAL_INTRINSIC_ADDRESS || tag)`.
fn intrinsic_domain(tag: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + tag.len());
    preimage.extend_from_slice(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS);
    preimage.extend_from_slice(tag);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Shared pattern: recover pubkey from `prover_tree`, check address
/// binding `poseidon(pubkey) == sig.address`, then BLS-verify under
/// the given message + domain. Returns `Ok(false)` on any check
/// failure (not `Err`) so the dispatcher rejects the op uniformly.
fn verify_addressed_bls(
    sig_address: &[u8],
    signature: &[u8],
    prover_tree: &quil_tries::VectorCommitmentTree,
    message: &[u8],
    domain: &[u8; 32],
    key_manager: &dyn KeyManager,
    op_name: &str,
) -> Result<bool> {
    if sig_address.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "{op_name}: signature address must be 32 bytes, got {}",
            sig_address.len()
        )));
    }
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument(format!("{op_name}: no type hash"))
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument(format!(
            "{op_name}: expected prover:Prover, got {vertex_type}"
        )));
    }
    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey")
        .ok_or_else(|| {
            QuilError::InvalidArgument(format!("{op_name}: no PublicKey"))
        })?;
    // Address binding: poseidon(pubkey) == sig.address. Without this
    // check, a malicious message could claim signer_address=A but sign
    // with the private key of signer B, and BLS-verify would succeed
    // against B's registered pubkey.
    let addr = prover_address_from_pubkey(&pubkey)?;
    if addr.as_slice() != sig_address {
        return Ok(false);
    }
    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        message,
        signature,
        domain,
    )
}

/// Verify a `ShardSplit` op. Mirrors Go's `ShardSplitOp.Verify` at
/// `global_shard_split.go:53-133`:
///   - shard_address 32–63 bytes
///   - proposed_shards has 2–8 entries, each of parent_len+1 or
///     parent_len+2 and prefixed by shard_address
///   - BLS sig over `frame_be_u64 || shard_address` with domain
///     `poseidon(GLOBAL_INTRINSIC_ADDRESS || "SHARD_SPLIT")`
pub fn verify_shard_split(
    op: &super::prover_ops::ShardSplit,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    if op.shard_address.len() < 32 || op.shard_address.len() > 63 {
        return Err(QuilError::InvalidArgument(format!(
            "shard split: shard_address must be 32-63 bytes, got {}",
            op.shard_address.len()
        )));
    }
    if op.proposed_shards.len() < 2 || op.proposed_shards.len() > 8 {
        return Err(QuilError::InvalidArgument(format!(
            "shard split: proposed_shards must have 2-8 entries, got {}",
            op.proposed_shards.len()
        )));
    }
    let parent_len = op.shard_address.len();
    for shard in &op.proposed_shards {
        if shard.len() != parent_len + 1 && shard.len() != parent_len + 2 {
            return Err(QuilError::InvalidArgument(format!(
                "shard split: proposed shard length {} invalid for parent length {}",
                shard.len(),
                parent_len
            )));
        }
        if !shard.starts_with(&op.shard_address) {
            return Err(QuilError::InvalidArgument(
                "shard split: proposed shard must share parent prefix".into(),
            ));
        }
    }

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("shard split: missing signature".into())
    })?;

    let mut message = Vec::with_capacity(8 + op.shard_address.len());
    message.extend_from_slice(&op.frame_number.to_be_bytes());
    message.extend_from_slice(&op.shard_address);

    let domain = intrinsic_domain(b"SHARD_SPLIT")?;

    verify_addressed_bls(
        &sig.address,
        &sig.signature,
        prover_tree,
        &message,
        &domain,
        key_manager,
        "shard split",
    )
}

/// Verify a `ShardMerge` op. Mirrors Go's `ShardMergeOp.Verify` at
/// `global_shard_merge.go:51-125`:
///   - parent_address 32 bytes
///   - shard_addresses has 2–8 entries, each parent_len+1 or parent_len+2
///     and each prefixed by parent_address
///   - BLS sig over `frame_be_u64 || parent_address` with domain
///     `poseidon(GLOBAL_INTRINSIC_ADDRESS || "SHARD_MERGE")`
pub fn verify_shard_merge(
    op: &super::prover_ops::ShardMerge,
    prover_tree: &quil_tries::VectorCommitmentTree,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    if op.parent_address.len() < 32 || op.parent_address.len() > 63 {
        return Err(QuilError::InvalidArgument(format!(
            "shard merge: parent_address must be 32-63 bytes, got {}",
            op.parent_address.len()
        )));
    }
    if op.shard_addresses.len() < 2 || op.shard_addresses.len() > 8 {
        return Err(QuilError::InvalidArgument(format!(
            "shard merge: shard_addresses must have 2-8 entries, got {}",
            op.shard_addresses.len()
        )));
    }
    let parent_len = op.parent_address.len();
    for shard in &op.shard_addresses {
        if shard.len() != parent_len + 1 && shard.len() != parent_len + 2 {
            return Err(QuilError::InvalidArgument(format!(
                "shard merge: child shard length {} invalid for parent length {}",
                shard.len(),
                parent_len
            )));
        }
        if !shard.starts_with(&op.parent_address) {
            return Err(QuilError::InvalidArgument(
                "shard merge: child shard must share parent prefix".into(),
            ));
        }
    }

    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("shard merge: missing signature".into())
    })?;

    let mut message = Vec::with_capacity(8 + op.parent_address.len());
    message.extend_from_slice(&op.frame_number.to_be_bytes());
    message.extend_from_slice(&op.parent_address);

    let domain = intrinsic_domain(b"SHARD_MERGE")?;

    verify_addressed_bls(
        &sig.address,
        &sig.signature,
        prover_tree,
        &message,
        &domain,
        key_manager,
        "shard merge",
    )
}

/// Verify a `ProverSeniorityMerge` op. Partial port of Go's
/// `ProverSeniorityMerge.Verify` at
/// `global_prover_seniority_merge.go:391-618`.
///
/// Checks:
///   - addressed signature present, address 32 bytes
///   - 10-frame freshness: `op.frame_number + 10 >= current_frame_number`
///   - each merge-target signs `pubKeyBytes` with its own `key_type` under
///     the literal ASCII domain `"PROVER_SENIORITY_MERGE"`
///   - main BLS sig over `frame_be_u64 || concat(helper_pubkeys)` under
///     domain `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_SENIORITY_MERGE")`
///   - address-binding: `poseidon(pubKeyBytes) == sig.address`
///
/// NOT checked here (requires hypergraph state the dispatcher doesn't
/// have): spent-merge tombstones, `mergeSeniority > existingSeniority`
/// via the compat table. Those run in the materialize path.
pub fn verify_prover_seniority_merge(
    op: &super::prover_ops::ProverSeniorityMerge,
    prover_tree: &quil_tries::VectorCommitmentTree,
    current_frame_number: u64,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    if op.merge_targets.is_empty() {
        return Err(QuilError::InvalidArgument(
            "prover seniority merge: no merge targets".into(),
        ));
    }
    let sig = op.public_key_signature_bls48581.as_ref().ok_or_else(|| {
        QuilError::InvalidArgument("prover seniority merge: missing signature".into())
    })?;
    if sig.address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "prover seniority merge: invalid address length".into(),
        ));
    }
    // Freshness: 10-frame window matching Go's `p.FrameNumber+10 < frameNumber`.
    if op.frame_number + 10 < current_frame_number {
        return Err(QuilError::InvalidArgument(
            "prover seniority merge: outdated request".into(),
        ));
    }

    // Read the registered pubkey and verify address binding. Mirrors
    // Go's `poseidon(pubKeyBytes) == sig.Address` check at :447-457.
    let vertex_type = read_type(prover_tree).ok_or_else(|| {
        QuilError::InvalidArgument("prover seniority merge: no type hash".into())
    })?;
    if vertex_type != "prover:Prover" {
        return Err(QuilError::InvalidArgument(format!(
            "prover seniority merge: expected prover:Prover, got {vertex_type}"
        )));
    }
    let pubkey = read_field(prover_tree, "prover:Prover", "PublicKey").ok_or_else(|| {
        QuilError::InvalidArgument("prover seniority merge: no PublicKey".into())
    })?;
    let addr = prover_address_from_pubkey(&pubkey)?;
    if addr.as_slice() != sig.address.as_slice() {
        return Ok(false);
    }

    // Each merge target signs `pubkey` with its own key under the
    // literal ASCII domain — mirrors Go's :462-468.
    const MERGE_TARGET_DOMAIN: &[u8] = b"PROVER_SENIORITY_MERGE";
    for mt in &op.merge_targets {
        let key_type = match mt.key_type {
            0 => KeyType::Ed448,
            1 => KeyType::X448,
            2 => KeyType::Bls48581G1,
            3 => KeyType::Bls48581G2,
            4 => KeyType::Decaf448,
            other => {
                return Err(QuilError::InvalidArgument(format!(
                    "prover seniority merge: merge target has unknown key_type {other}"
                )));
            }
        };
        let ok = key_manager.validate_signature(
            key_type,
            &mt.prover_public_key,
            &pubkey,
            &mt.signature,
            MERGE_TARGET_DOMAIN,
        )?;
        if !ok {
            return Ok(false);
        }
    }

    // Main BLS sig over `frame_be || concat(helper_pubkeys)` under
    // the poseidon-wrapped domain.
    let mut message = Vec::with_capacity(8);
    message.extend_from_slice(&op.frame_number.to_be_bytes());
    for mt in &op.merge_targets {
        message.extend_from_slice(&mt.prover_public_key);
    }
    let domain = intrinsic_domain(b"PROVER_SENIORITY_MERGE")?;
    key_manager.validate_signature(
        KeyType::Bls48581G1,
        &pubkey,
        &message,
        &sig.signature,
        &domain,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use crate::global_schema::{TYPE_HASH_PROVER, TYPE_HASH_ALLOCATION};
    use super::super::addressed_signature::AddressedSignature;

    // Stub key manager that always accepts/rejects
    struct AcceptKeyManager;
    impl KeyManager for AcceptKeyManager {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(true)
        }
    }

    struct RejectKeyManager;
    impl KeyManager for RejectKeyManager {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(false)
        }
    }

    fn make_prover_tree() -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        // Type hash at [0xFF; 32]
        tree.insert(&[0xFFu8; 32], &TYPE_HASH_PROVER, &[], &BigInt::from(32)).unwrap();
        // PublicKey at order 0 → key 0x00
        tree.insert(&[0x00], &vec![0xAAu8; 585], &[], &BigInt::from(585)).unwrap();
        // Status at order 1 → key 0x04
        tree.insert(&[0x04], &[1u8], &[], &BigInt::from(1)).unwrap();
        tree
    }

    fn make_allocation_tree(status: u8) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xFFu8; 32], &TYPE_HASH_ALLOCATION, &[], &BigInt::from(32)).unwrap();
        // Status at order 1 → key 0x04
        tree.insert(&[0x04], &[status], &[], &BigInt::from(1)).unwrap();
        tree
    }

    fn sample_pause() -> ProverPause {
        ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 42,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        }
    }

    // -----------------------------------------------------------------
    // verify_prover_pause
    // -----------------------------------------------------------------

    #[test]
    fn pause_verify_accepts_with_accept_key_manager() {
        let prover_tree = make_prover_tree();
        let alloc_tree = make_allocation_tree(1); // active
        let result = verify_prover_pause(
            &sample_pause(),
            &prover_tree,
            Some(&alloc_tree),
            &AcceptKeyManager,
        );
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn pause_verify_rejects_with_reject_key_manager() {
        let prover_tree = make_prover_tree();
        let alloc_tree = make_allocation_tree(1);
        let result = verify_prover_pause(
            &sample_pause(),
            &prover_tree,
            Some(&alloc_tree),
            &RejectKeyManager,
        );
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn pause_verify_rejects_non_active_allocation() {
        let prover_tree = make_prover_tree();
        let alloc_tree = make_allocation_tree(2); // paused, not active
        let result = verify_prover_pause(
            &sample_pause(),
            &prover_tree,
            Some(&alloc_tree),
            &AcceptKeyManager,
        );
        assert!(result.is_err());
    }

    #[test]
    fn pause_verify_rejects_missing_signature() {
        let prover_tree = make_prover_tree();
        let mut op = sample_pause();
        op.public_key_signature_bls48581 = None;
        let result = verify_prover_pause(&op, &prover_tree, None, &AcceptKeyManager);
        assert!(result.is_err());
    }

    #[test]
    fn pause_verify_rejects_wrong_vertex_type() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xFFu8; 32], &TYPE_HASH_ALLOCATION, &[], &BigInt::from(32)).unwrap();
        tree.insert(&[0x00], &vec![0xAAu8; 585], &[], &BigInt::from(585)).unwrap();
        let result = verify_prover_pause(&sample_pause(), &tree, None, &AcceptKeyManager);
        assert!(result.is_err());
    }

    #[test]
    fn pause_verify_rejects_missing_pubkey() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xFFu8; 32], &TYPE_HASH_PROVER, &[], &BigInt::from(32)).unwrap();
        // No pubkey inserted
        let result = verify_prover_pause(&sample_pause(), &tree, None, &AcceptKeyManager);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // verify_prover_resume
    // -----------------------------------------------------------------

    #[test]
    fn resume_verify_accepts_paused_allocation() {
        let prover_tree = make_prover_tree();
        let alloc_tree = make_allocation_tree(2); // paused
        let op = ProverResume {
            filter: vec![0xAAu8; 32],
            frame_number: 43,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        assert!(verify_prover_resume(&op, &prover_tree, Some(&alloc_tree), &AcceptKeyManager).unwrap());
    }

    #[test]
    fn resume_verify_rejects_active_allocation() {
        let prover_tree = make_prover_tree();
        let alloc_tree = make_allocation_tree(1); // active, not paused
        let op = ProverResume {
            filter: vec![0xAAu8; 32],
            frame_number: 43,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        assert!(verify_prover_resume(&op, &prover_tree, Some(&alloc_tree), &AcceptKeyManager).is_err());
    }

    // -----------------------------------------------------------------
    // verify_prover_leave
    // -----------------------------------------------------------------

    #[test]
    fn leave_verify_accepts_with_accept_key_manager() {
        let prover_tree = make_prover_tree();
        let op = ProverLeave {
            filters: vec![vec![0xAAu8; 32]],
            frame_number: 100,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        assert!(verify_prover_leave(&op, &prover_tree, &AcceptKeyManager).unwrap());
    }

    #[test]
    fn leave_verify_rejects_with_reject_key_manager() {
        let prover_tree = make_prover_tree();
        let op = ProverLeave {
            filters: vec![vec![0xAAu8; 32]],
            frame_number: 100,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
        };
        assert!(!verify_prover_leave(&op, &prover_tree, &RejectKeyManager).unwrap());
    }

    // -----------------------------------------------------------------
    // verify_prover_confirm
    // -----------------------------------------------------------------

    fn sample_confirm() -> ProverConfirm {
        ProverConfirm {
            filter: vec![],
            frame_number: 500,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
            filters: vec![vec![0xDDu8; 32]],
        }
    }

    #[test]
    fn confirm_verify_accepts_with_accept_key_manager() {
        let prover_tree = make_prover_tree();
        assert!(verify_prover_confirm(&sample_confirm(), &prover_tree, &AcceptKeyManager).unwrap());
    }

    #[test]
    fn confirm_verify_rejects_with_reject_key_manager() {
        let prover_tree = make_prover_tree();
        assert!(!verify_prover_confirm(&sample_confirm(), &prover_tree, &RejectKeyManager).unwrap());
    }

    #[test]
    fn confirm_verify_rejects_missing_signature() {
        let prover_tree = make_prover_tree();
        let mut op = sample_confirm();
        op.public_key_signature_bls48581 = None;
        assert!(verify_prover_confirm(&op, &prover_tree, &AcceptKeyManager).is_err());
    }

    // -----------------------------------------------------------------
    // verify_prover_reject
    // -----------------------------------------------------------------

    fn sample_reject() -> ProverReject {
        ProverReject {
            filter: vec![],
            frame_number: 600,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 74],
                address: vec![0xCCu8; 32],
            }),
            filters: vec![vec![0xEEu8; 32]],
        }
    }

    #[test]
    fn reject_verify_accepts_with_accept_key_manager() {
        let prover_tree = make_prover_tree();
        assert!(verify_prover_reject(&sample_reject(), &prover_tree, &AcceptKeyManager).unwrap());
    }

    #[test]
    fn reject_verify_rejects_with_reject_key_manager() {
        let prover_tree = make_prover_tree();
        assert!(!verify_prover_reject(&sample_reject(), &prover_tree, &RejectKeyManager).unwrap());
    }

    // -----------------------------------------------------------------
    // validate_prover_join_structural
    // -----------------------------------------------------------------

    use super::super::sig_with_pop::SignatureWithPop;

    fn sample_join(filters: Vec<Vec<u8>>) -> ProverJoin {
        let proof_size = PROOF_CHUNK_SIZE * filters.len();
        ProverJoin {
            filters,
            frame_number: 100,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature: vec![0xAAu8; 74],
                public_key: Some(vec![0xBBu8; 585]),
                pop_signature: vec![0xCCu8; 74],
            }),
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![0xDDu8; proof_size],
        }
    }

    #[test]
    fn join_structural_accepts_valid_join() {
        let op = sample_join(vec![vec![0x01u8; 32], vec![0x02u8; 48]]);
        let result = validate_prover_join_structural(&op, 105);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.public_key.len(), 585);
        assert_eq!(v.prover_address.len(), 32);
        assert_eq!(v.filter_count, 2);
    }

    #[test]
    fn join_structural_rejects_short_filter() {
        let op = sample_join(vec![vec![0x01u8; 31]]); // 31 < 32
        assert!(validate_prover_join_structural(&op, 105).is_err());
    }

    #[test]
    fn join_structural_rejects_wrong_proof_size() {
        let mut op = sample_join(vec![vec![0x01u8; 32]]);
        op.proof = vec![0u8; 100]; // should be 516
        assert!(validate_prover_join_structural(&op, 105).is_err());
    }

    #[test]
    fn join_structural_rejects_stale_request() {
        let op = sample_join(vec![vec![0x01u8; 32]]);
        // op.frame_number=100, current=111 → 100+10=110 < 111 → stale
        assert!(validate_prover_join_structural(&op, 111).is_err());
    }

    #[test]
    fn join_structural_accepts_at_freshness_boundary() {
        let op = sample_join(vec![vec![0x01u8; 32]]);
        // op.frame_number=100, current=110 → 100+10=110 >= 110 → ok
        assert!(validate_prover_join_structural(&op, 110).is_ok());
    }

    #[test]
    fn join_structural_rejects_missing_signature() {
        let mut op = sample_join(vec![vec![0x01u8; 32]]);
        op.public_key_signature_bls48581 = None;
        assert!(validate_prover_join_structural(&op, 105).is_err());
    }

    #[test]
    fn join_structural_rejects_missing_public_key() {
        let mut op = sample_join(vec![vec![0x01u8; 32]]);
        op.public_key_signature_bls48581.as_mut().unwrap().public_key = None;
        assert!(validate_prover_join_structural(&op, 105).is_err());
    }

    #[test]
    fn join_structural_prover_address_is_deterministic() {
        let op = sample_join(vec![vec![0x01u8; 32]]);
        let v1 = validate_prover_join_structural(&op, 105).unwrap();
        let v2 = validate_prover_join_structural(&op, 105).unwrap();
        assert_eq!(v1.prover_address, v2.prover_address);
    }

    #[test]
    fn join_structural_empty_filters_with_empty_proof() {
        let op = ProverJoin {
            filters: vec![],
            frame_number: 100,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature: vec![0xAAu8; 74],
                public_key: Some(vec![0xBBu8; 585]),
                pop_signature: vec![0xCCu8; 74],
            }),
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![], // 0 filters → 0 proof
        };
        let v = validate_prover_join_structural(&op, 105).unwrap();
        assert_eq!(v.filter_count, 0);
    }

    // -----------------------------------------------------------------
    // verify_prover_join_vdf — regression for test #548
    //
    // Builds a real VDF multi-proof with the signer-side algorithm
    // (SHA3-256 challenge over frame_output, matching Go's
    // `sha3.Sum256` and Rust's prover_pipeline) and feeds it through
    // the actual verifier. Pins the cross-implementation hash
    // agreement; would have caught the original sha2/sha3 mismatch.
    // -----------------------------------------------------------------

    #[test]
    fn verify_prover_join_vdf_accepts_real_proof() {
        use quil_types::crypto::FrameProver;

        let frame_prover = quil_crypto::WesolowskiFrameProver::new(2048);
        let difficulty: u32 = 200;
        let frame_output: &[u8] = b"deadbeef-test-frame-output";
        let filters: Vec<Vec<u8>> = vec![vec![0x01u8; 32], vec![0x02u8; 48]];

        let stub = sample_join(filters.clone());
        let prover_address = validate_prover_join_structural(&stub, 105)
            .unwrap()
            .prover_address;

        use sha3::Digest as _;
        let challenge: [u8; 32] = sha3::Sha3_256::digest(frame_output).into();

        let ids: Vec<Vec<u8>> = filters
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let mut id = Vec::with_capacity(32 + f.len() + 4);
                id.extend_from_slice(&prover_address);
                id.extend_from_slice(f);
                id.extend_from_slice(&(i as u32).to_be_bytes());
                id
            })
            .collect();
        let id_refs: Vec<&[u8]> = ids.iter().map(|v| v.as_slice()).collect();

        let mut proof = Vec::with_capacity(filters.len() * PROOF_CHUNK_SIZE);
        for i in 0..filters.len() {
            let chunk = frame_prover
                .calculate_multi_proof(&challenge, difficulty, &id_refs, i as u32)
                .unwrap();
            assert_eq!(chunk.len(), PROOF_CHUNK_SIZE);
            proof.extend_from_slice(&chunk);
        }

        let op = ProverJoin { proof, ..stub };

        let ok = verify_prover_join_vdf(&op, 105, frame_output, difficulty, &frame_prover)
            .expect("verify_prover_join_vdf returned an error");
        assert!(ok, "real ProverJoin proof must verify (regression testfor #548)");
    }

    // -----------------------------------------------------------------
    // Tier-5 #11: 2.1 transition window in validate_confirm_timing
    // -----------------------------------------------------------------

    fn make_alloc_tree_with_join_frame(status: u8, join_frame: u64)
        -> quil_tries::VectorCommitmentTree
    {
        // ConfirmationFilter at order 2 → key 0x08; JoinFrameNumber at order 4 → key 0x10.
        // Use schema-driven keys to be safe.
        let mut tree = make_allocation_tree(status);
        let cls = "allocation:ProverAllocation";
        let join_key = crate::global_schema::field_key(cls, "JoinFrameNumber").unwrap();
        tree.insert(&join_key, &join_frame.to_be_bytes(), &[], &BigInt::from(8)).unwrap();
        tree
    }

    /// Joins inside the 2.1 transition window (244100..255840) cannot
    /// confirm before frame 255840.
    #[test]
    fn confirm_timing_blocks_transition_window_before_255840() {
        let alloc = make_alloc_tree_with_join_frame(0, 244_500);
        // frame_number < 255840 → must error.
        let res = validate_confirm_timing(255_000, &alloc);
        assert!(res.is_err(), "must reject confirm before 255840");
    }

    /// Joins inside the transition window get clamped at frame 255840
    /// so they all confirm immediately once the cutover frame hits.
    #[test]
    fn confirm_timing_admits_transition_window_at_255840() {
        // Join in the middle of the band; once frame_number hits
        // 255840, the clamped join_frame becomes 255840-360, so
        // frames_since == 360 → allowed.
        let alloc = make_alloc_tree_with_join_frame(0, 244_200);
        let res = validate_confirm_timing(255_840, &alloc);
        assert!(res.is_ok(), "must admit transition-window join at 255840: {res:?}");
    }

    /// Pre-transition joins (< 244100) follow the normal 360..720 window.
    #[test]
    fn confirm_timing_normal_window_pre_transition() {
        let alloc = make_alloc_tree_with_join_frame(0, 200_000);

        // Too early.
        assert!(validate_confirm_timing(200_300, &alloc).is_err());
        // In the window.
        assert!(validate_confirm_timing(200_400, &alloc).is_ok());
        // Past the window.
        assert!(validate_confirm_timing(200_800, &alloc).is_err());
    }

    /// Joins after the cutover (≥ 255840) follow the normal 360..720
    /// window — the transition logic does not affect them.
    #[test]
    fn confirm_timing_normal_window_post_transition() {
        let alloc = make_alloc_tree_with_join_frame(0, 256_000);

        // Too early.
        assert!(validate_confirm_timing(256_200, &alloc).is_err());
        // In the window (frames_since = 360).
        assert!(validate_confirm_timing(256_360, &alloc).is_ok());
        // Past 720 frames.
        assert!(validate_confirm_timing(256_721, &alloc).is_err());
    }
}
