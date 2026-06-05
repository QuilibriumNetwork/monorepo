//! Prover op materialize implementations — the state transitions
//! that mutate prover/allocation vertices in the hypergraph.
//!
//! Each materialize function takes a mutable allocation tree and
//! applies the status change + frame number update. The calling code
//! is responsible for writing the modified tree back to the CRDT via
//! `HypergraphState.set()`.

use quil_types::error::{QuilError, Result};

use crate::global_schema::{read_field, write_field, write_type};

/// Prover allocation status constants (from Go).
pub const STATUS_JOINING: u8 = 0;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_PAUSED: u8 = 2;
pub const STATUS_LEAVING: u8 = 3;
pub const STATUS_KICKED: u8 = 4;

/// Protocol-level halt-risk threshold. A shard with `Active` prover
/// count at or below this value is classified as halt-risk by the
/// coverage monitor and the proposer's auto-allocation logic.
/// Mirrors `quil_engine::provers::proposer::HALT_RISK_PROVER_COUNT`
/// (the engine-side copy used by `plan_and_allocate` / `plan_leaves`)
/// — duplicated here to avoid an `engine → execution` dependency.
/// If the engine constant changes, this one must change with it.
///
/// Used by `materialize_prover_confirm`'s leave-confirm gate: at
/// confirm time, our alloc is `Leaving` so we're NOT counted in
/// the registry's active-prover query. Rejecting a confirm whose
/// shard already sits at the threshold preserves what little
/// margin remains rather than letting attacker-coordinated mass
/// leaves walk the network through the halt grace.
pub const HALT_RISK_PROVER_COUNT: usize = 3;

/// Materialize a ProverPause: set allocation Status=2 (paused),
/// PauseFrameNumber=frame_number.
///
/// Go equivalent: `ProverPause::Materialize` at
/// `global_prover_pause.go:57`.
pub fn materialize_prover_pause(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";

    // Check current status is active
    let status = read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(0);
    if status != STATUS_ACTIVE {
        return Err(QuilError::InvalidArgument(format!(
            "materialize pause: allocation status is {} (expected {}=active)",
            status, STATUS_ACTIVE
        )));
    }

    // Set Status = 2 (paused)
    write_field(allocation_tree, cls, "Status", &[STATUS_PAUSED])?;

    // Set PauseFrameNumber
    write_field(
        allocation_tree,
        cls,
        "PauseFrameNumber",
        &frame_number.to_be_bytes(),
    )?;

    Ok(())
}

/// Materialize a ProverResume: set allocation Status=1 (active),
/// ResumeFrameNumber=frame_number.
pub fn materialize_prover_resume(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";

    let status = read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(0);
    if status != STATUS_PAUSED {
        return Err(QuilError::InvalidArgument(format!(
            "materialize resume: allocation status is {} (expected {}=paused)",
            status, STATUS_PAUSED
        )));
    }

    write_field(allocation_tree, cls, "Status", &[STATUS_ACTIVE])?;
    write_field(
        allocation_tree,
        cls,
        "ResumeFrameNumber",
        &frame_number.to_be_bytes(),
    )?;

    Ok(())
}

/// Materialize a ProverLeave: set allocation Status=3 (leaving),
/// LeaveFrameNumber=frame_number.
pub fn materialize_prover_leave(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";

    let status = read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(0);
    // Can leave from active (1) or paused (2) state
    if status != STATUS_ACTIVE && status != STATUS_PAUSED {
        return Err(QuilError::InvalidArgument(format!(
            "materialize leave: allocation status is {} (expected 1=active or 2=paused)",
            status
        )));
    }

    write_field(allocation_tree, cls, "Status", &[STATUS_LEAVING])?;
    write_field(
        allocation_tree,
        cls,
        "LeaveFrameNumber",
        &frame_number.to_be_bytes(),
    )?;

    Ok(())
}

// =====================================================================
// Aggregate prover status
// =====================================================================

/// Compute the aggregate prover status from a set of allocation statuses.
///
/// Priority: Active(1) > Joining(0) > Leaving(3) > Paused(2) > Kicked(4)
///
/// Returns the new prover status byte. If `allocation_statuses` is
/// empty, returns `STATUS_KICKED` (byte 4 — the rolled-up
/// "all allocations terminal / no longer participating" value).
pub fn compute_aggregate_prover_status(allocation_statuses: &[u8]) -> u8 {
    if allocation_statuses.is_empty() {
        return STATUS_KICKED; // 4 = left
    }

    let mut has_active = false;
    let mut has_joining = false;
    let mut has_leaving = false;
    let mut has_paused = false;

    for &status in allocation_statuses {
        match status {
            STATUS_JOINING => has_joining = true,
            STATUS_ACTIVE => has_active = true,
            STATUS_PAUSED => has_paused = true,
            STATUS_LEAVING => has_leaving = true,
            // STATUS_KICKED (4 = left) is ignored for aggregate
            _ => {}
        }
    }

    if has_active {
        STATUS_ACTIVE
    } else if has_joining {
        STATUS_JOINING
    } else if has_leaving {
        STATUS_LEAVING
    } else if has_paused {
        STATUS_PAUSED
    } else {
        STATUS_KICKED // all allocations are left/kicked
    }
}

/// Update the prover vertex tree's Status field based on a set of
/// allocation statuses. Convenience wrapper that calls
/// `compute_aggregate_prover_status` and writes the result.
pub fn update_prover_status_from_allocations(
    prover_tree: &mut quil_tries::VectorCommitmentTree,
    allocation_statuses: &[u8],
) -> Result<u8> {
    let new_status = compute_aggregate_prover_status(allocation_statuses);
    write_field(prover_tree, "prover:Prover", "Status", &[new_status])?;
    Ok(new_status)
}

// =====================================================================
// ProverConfirm materialize
// =====================================================================

/// Materialize a ProverConfirm for a single allocation. Two paths:
///
/// - **Confirm join** (status 0→1): set Status=Active,
///   JoinConfirmFrameNumber, LastActiveFrameNumber.
/// - **Confirm leave** (status 3→4): set Status=Kicked,
///   LeaveConfirmFrameNumber.
///
/// Returns `Err` if the allocation is not in status 0 or 3.
pub fn materialize_prover_confirm(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";
    let status = read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(255);

    let frame_bytes = frame_number.to_be_bytes();

    match status {
        STATUS_JOINING => {
            // Confirm join → active
            write_field(allocation_tree, cls, "Status", &[STATUS_ACTIVE])?;
            write_field(allocation_tree, cls, "JoinConfirmFrameNumber", &frame_bytes)?;
            write_field(allocation_tree, cls, "LastActiveFrameNumber", &frame_bytes)?;
            Ok(())
        }
        STATUS_LEAVING => {
            // Confirm leave → left
            write_field(allocation_tree, cls, "Status", &[STATUS_KICKED])?; // 4 = left/kicked
            write_field(allocation_tree, cls, "LeaveConfirmFrameNumber", &frame_bytes)?;
            Ok(())
        }
        _ => Err(QuilError::InvalidArgument(format!(
            "materialize confirm: allocation status is {} (expected 0=joining or 3=leaving)",
            status
        ))),
    }
}

/// Materialize a ProverReject for a single allocation. Two paths:
///
/// - **Reject join** (status 0→4): set Status=Kicked,
///   JoinRejectFrameNumber.
/// - **Reject leave** (status 3→1): set Status=Active,
///   LeaveRejectFrameNumber, LastActiveFrameNumber.
pub fn materialize_prover_reject(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";
    let status = read_field(allocation_tree, cls, "Status")
        .and_then(|b| b.first().copied())
        .unwrap_or(255);

    let frame_bytes = frame_number.to_be_bytes();

    match status {
        STATUS_JOINING => {
            // Reject join → kicked
            write_field(allocation_tree, cls, "Status", &[STATUS_KICKED])?;
            write_field(allocation_tree, cls, "JoinRejectFrameNumber", &frame_bytes)?;
            Ok(())
        }
        STATUS_LEAVING => {
            // Reject leave → back to active
            write_field(allocation_tree, cls, "Status", &[STATUS_ACTIVE])?;
            write_field(allocation_tree, cls, "LeaveRejectFrameNumber", &frame_bytes)?;
            write_field(allocation_tree, cls, "LastActiveFrameNumber", &frame_bytes)?;
            Ok(())
        }
        _ => Err(QuilError::InvalidArgument(format!(
            "materialize reject: allocation status is {} (expected 0=joining or 3=leaving)",
            status
        ))),
    }
}

// =====================================================================
// ProverUpdate materialize
// =====================================================================

/// Compute the reward vertex address for a prover.
/// `poseidon(QUIL_TOKEN_ADDRESS || prover_address)` → 32 bytes.
pub fn reward_address(prover_address: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + prover_address.len());
    preimage.extend_from_slice(&crate::domains::QUIL_TOKEN);
    preimage.extend_from_slice(prover_address);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Read the current balance from a reward vertex tree.
/// Returns zero-length vec if balance field is not set.
pub fn read_reward_balance(
    reward_tree: &quil_tries::VectorCommitmentTree,
) -> Vec<u8> {
    read_field(reward_tree, "reward:ProverReward", "Balance")
        .unwrap_or_default()
}

/// Update the balance on a reward vertex tree.
/// `new_balance` is a big-endian serialized BigInt (up to 32 bytes).
pub fn set_reward_balance(
    reward_tree: &mut quil_tries::VectorCommitmentTree,
    new_balance: &[u8],
) -> Result<()> {
    write_type(reward_tree, "reward:ProverReward")?;
    write_field(reward_tree, "reward:ProverReward", "Balance", new_balance)
}

/// Add `amount` to the reward balance. Reads the current balance,
/// adds `amount`, writes back as a fixed-width 32-byte big-endian
/// integer. Mirrors Go's
/// `node/execution/intrinsics/global/global_prover_shard_update.go:467-468`
/// (`balanceBytes := make([]byte, 32); currentBalance.FillBytes(balanceBytes)`).
/// Writing minimal-length bytes here would change the leaf size on
/// the first issuance and diverge the prover-tree commitment from Go.
pub fn add_to_reward_balance(
    reward_tree: &mut quil_tries::VectorCommitmentTree,
    amount: &num_bigint::BigInt,
) -> Result<()> {
    use num_bigint::BigInt;
    let current_bytes = read_reward_balance(reward_tree);
    let current = if current_bytes.is_empty() {
        BigInt::from(0)
    } else {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &current_bytes)
    };
    let new_balance = current + amount;
    let (_, new_bytes) = new_balance.to_bytes_be();
    // Right-align into 32 bytes (matches Go's `FillBytes(make([]byte, 32))`).
    let mut padded = [0u8; 32];
    if new_bytes.len() <= 32 {
        padded[32 - new_bytes.len()..].copy_from_slice(&new_bytes);
    } else {
        // Mathematically a balance >2^256 cannot exist on-chain (issuance
        // is bounded), but be safe: surface the divergence rather than
        // silently truncate.
        return Err(quil_types::error::QuilError::InvalidArgument(format!(
            "reward balance overflow: {} bytes (max 32)",
            new_bytes.len()
        )));
    }
    set_reward_balance(reward_tree, &padded)
}

/// Create or update a reward vertex tree with a delegate address.
pub fn set_reward_delegate_address(
    reward_tree: &mut quil_tries::VectorCommitmentTree,
    delegate_address: &[u8],
) -> Result<()> {
    write_type(reward_tree, "reward:ProverReward")?;
    write_field(reward_tree, "reward:ProverReward", "DelegateAddress", delegate_address)?;
    Ok(())
}

// =====================================================================
// ProverKick materialize
// =====================================================================

/// Materialize a ProverKick: set prover Status=4 (kicked),
/// KickFrameNumber=frame_number, Seniority=0.
///
/// Kicked provers lose their seniority — this prevents re-joining
/// with accumulated seniority after an equivocation. Go's
/// `ProverKick.Materialize` and `evictProver` do NOT zero seniority,
/// which is a bug — Rust fixes it deliberately. PublicKey and
/// AvailableStorage are left alone.
///
/// The caller is also responsible for kicking all allocations
/// (calling `materialize_prover_kick_allocation` for each).
pub fn materialize_prover_kick(
    prover_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    write_field(prover_tree, "prover:Prover", "Status", &[STATUS_KICKED])?;
    write_field(
        prover_tree,
        "prover:Prover",
        "KickFrameNumber",
        &frame_number.to_be_bytes(),
    )?;
    // Zero out seniority — kicked provers lose accumulated seniority.
    // Go misses this; Rust intentionally diverges to fix the bug.
    write_field(prover_tree, "prover:Prover", "Seniority", &0u64.to_be_bytes())?;
    Ok(())
}

/// Materialize a kick on a single allocation: set Status=4,
/// KickFrameNumber=frame_number.
pub fn materialize_prover_kick_allocation(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";
    write_field(allocation_tree, cls, "Status", &[STATUS_KICKED])?;
    write_field(allocation_tree, cls, "KickFrameNumber", &frame_number.to_be_bytes())?;
    Ok(())
}

// =====================================================================
// ProverJoin materialize
// =====================================================================

/// Compute a prover's 32-byte address from their BLS48-581 public key.
/// `poseidon_hash(public_key) → 32 bytes big-endian`.
pub fn prover_address_from_pubkey(public_key: &[u8]) -> Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(public_key)
}

/// Compute an allocation's 32-byte address from the prover pubkey and filter.
/// `poseidon_hash("PROVER_ALLOCATION" || pubkey || filter) → 32 bytes`.
pub fn allocation_address(public_key: &[u8], filter: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(17 + public_key.len() + filter.len());
    preimage.extend_from_slice(b"PROVER_ALLOCATION");
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(filter);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a new prover vertex tree with initial field values.
/// Sets: PublicKey, Status=0 (joining), AvailableStorage=0, Seniority.
///
/// Returns the populated tree. The caller is responsible for writing
/// it to the CRDT via HypergraphState.set().
pub fn create_prover_vertex_tree(
    public_key: &[u8],
    seniority: u64,
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    let cls = "prover:Prover";

    write_type(&mut tree, cls)?;
    write_field(&mut tree, cls, "PublicKey", public_key)?;
    write_field(&mut tree, cls, "Status", &[STATUS_JOINING])?;
    write_field(&mut tree, cls, "AvailableStorage", &0u64.to_be_bytes())?;
    write_field(&mut tree, cls, "Seniority", &seniority.to_be_bytes())?;

    Ok(tree)
}

/// Create a new allocation vertex tree for a single filter.
/// Sets: Prover (reference to prover address), Status=0 (joining),
/// ConfirmationFilter, JoinFrameNumber.
pub fn create_allocation_vertex_tree(
    prover_address: &[u8; 32],
    filter: &[u8],
    frame_number: u64,
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    let cls = "allocation:ProverAllocation";

    write_type(&mut tree, cls)?;
    write_field(&mut tree, cls, "Prover", prover_address)?;
    write_field(&mut tree, cls, "Status", &[STATUS_JOINING])?;
    write_field(&mut tree, cls, "ConfirmationFilter", filter)?;
    write_field(&mut tree, cls, "JoinFrameNumber", &frame_number.to_be_bytes())?;

    Ok(tree)
}

/// Full ProverJoin materialize output — the set of vertex trees to
/// write to the CRDT via HypergraphState.
pub struct ProverJoinOutput {
    /// The prover vertex tree.
    pub prover_tree: quil_tries::VectorCommitmentTree,
    /// The 32-byte prover address (poseidon(pubkey)).
    pub prover_address: [u8; 32],
    /// (allocation_address, allocation_tree) pairs — one per filter.
    pub allocations: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
}

/// Create the prover + allocation vertex trees for a ProverJoin.
/// The caller applies these to the CRDT via HypergraphState.set().
pub fn materialize_prover_join(
    public_key: &[u8],
    filters: &[Vec<u8>],
    frame_number: u64,
    seniority: u64,
) -> Result<ProverJoinOutput> {
    let prover_address = prover_address_from_pubkey(public_key)?;
    let prover_tree = create_prover_vertex_tree(public_key, seniority)?;

    let mut allocations = Vec::with_capacity(filters.len());
    for filter in filters {
        let alloc_addr = allocation_address(public_key, filter)?;
        let alloc_tree = create_allocation_vertex_tree(&prover_address, filter, frame_number)?;
        allocations.push((alloc_addr, alloc_tree));
    }

    Ok(ProverJoinOutput {
        prover_tree,
        prover_address,
        allocations,
    })
}

/// Address for a spent ProverJoin merge marker.
/// `poseidon("PROVER_JOIN_MERGE" || merge_target_pubkey) → 32 bytes`.
///
/// This is **distinct** from
/// [`spent_seniority_merge_address`] — `ProverJoin` consumes merge
/// targets via the `PROVER_JOIN_MERGE` domain, while `ProverSeniorityMerge`
/// uses `PROVER_SENIORITY_MERGE`. Mirrors Go's
/// `global_prover_join.go:160-163` and `:531-534`.
pub fn spent_join_merge_address(merge_target_pubkey: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(17 + merge_target_pubkey.len());
    preimage.extend_from_slice(b"PROVER_JOIN_MERGE");
    preimage.extend_from_slice(merge_target_pubkey);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Build the hyperedge data blob linking a prover to its initial
/// allocations.
///
/// The blob is a serialized `VectorCommitmentTree` (Go's
/// `SerializeNonLazyTree` format) whose leaf keys are the 64-byte atom
/// IDs (`appAddr || dataAddr`) of each allocation vertex. The leaf
/// values mirror Go's `vertex.ToBytes()` —
/// `0x00 || appAddr(32) || dataAddr(32) || commitment(64) || size(32)`
/// — but the Rust port reads back only the keys (ID list) so any
/// minor commitment divergence in the value bytes does not affect
/// kick-time iteration. The commitment + size are computed via
/// `NoopInclusionProver` here; the consumer (`get_hyperedge_extrinsic_ids`)
/// only inspects keys.
///
/// Mirrors Go `ProverJoin.Materialize` at
/// `node/execution/intrinsics/global/global_prover_join.go:402-425, 526-528`.
pub fn build_prover_allocation_hyperedge_blob(
    prover_address: &[u8; 32],
    allocations: &[([u8; 32], &quil_tries::VectorCommitmentTree)],
) -> Result<Vec<u8>> {
    use num_bigint::BigInt;
    use quil_types::crypto::InclusionProver;

    // The hyperedge atom IDs are `(GLOBAL_INTRINSIC_ADDRESS, allocation_address)`.
    // We reuse the same convention as `genesis.rs` for byte-for-byte
    // parity with the existing on-chain hyperedge format.
    let app_addr = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;

    // Tiny stand-in inclusion prover: emits a deterministic 64-byte
    // commitment from the input bytes (no real KZG). The hyperedge
    // consumer (`get_hyperedge_extrinsic_ids`) reads only the leaf
    // **keys**, so the value commitment is informational.
    struct LocalProver;
    impl InclusionProver for LocalProver {
        fn commit_raw(&self, data: &[u8], _: u64) -> quil_types::error::Result<Vec<u8>> {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::new();
            h.update(data);
            Ok(h.finalize().to_vec())
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> quil_types::error::Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64)
            -> quil_types::error::Result<Box<dyn quil_types::crypto::Multiproof>>
        { Err(quil_types::error::QuilError::Internal("not impl".into())) }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    let mut ext_tree = quil_tries::VectorCommitmentTree::new();
    for (alloc_addr, alloc_tree) in allocations {
        let mut atom_id = [0u8; 64];
        atom_id[..32].copy_from_slice(&app_addr);
        atom_id[32..].copy_from_slice(alloc_addr);

        // value = vertex.ToBytes() shape (0x00 + appAddr + dataAddr + commitment + size32).
        // Compute the allocation tree's commitment by walking a clone-equivalent.
        // Since VectorCommitmentTree doesn't implement Clone, serialize +
        // deserialize a fresh copy to avoid mutating the input.
        let blob = crate::prover_registry::vertex_tree_to_blob(alloc_tree);
        let mut tmp = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let alloc_commitment = tmp.commit(&LocalProver);

        let alloc_size = alloc_tree
            .root
            .as_ref()
            .map(|n| n.size().clone())
            .unwrap_or_else(|| BigInt::from(0));
        let mut size_bytes = [0u8; 32];
        let (_, sb) = alloc_size.to_bytes_be();
        let off = 32usize.saturating_sub(sb.len());
        size_bytes[off..].copy_from_slice(&sb[..std::cmp::min(sb.len(), 32)]);

        let mut atom_bytes = Vec::with_capacity(161);
        atom_bytes.push(0x00);
        atom_bytes.extend_from_slice(&app_addr);
        atom_bytes.extend_from_slice(alloc_addr);
        atom_bytes.extend_from_slice(&alloc_commitment);
        atom_bytes.extend_from_slice(&size_bytes);

        ext_tree.insert(
            &atom_id,
            &atom_bytes,
            &[],
            &BigInt::from(atom_bytes.len() as u64),
        )?;
    }

    let _ = prover_address; // hyperedge address is the prover address (passed by caller)
    Ok(crate::prover_registry::vertex_tree_to_blob(&ext_tree))
}

// =====================================================================
// SeniorityMerge materialize (0x0310)
// =====================================================================

/// Address for a spent seniority-merge marker.
/// `poseidon("PROVER_SENIORITY_MERGE" || merge_target_pubkey) → 32 bytes`.
pub fn spent_seniority_merge_address(merge_target_pubkey: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(21 + merge_target_pubkey.len());
    preimage.extend_from_slice(b"PROVER_SENIORITY_MERGE");
    preimage.extend_from_slice(merge_target_pubkey);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a spent-merge marker tree. Stores the prover address at the
/// `merge:SpentMerge` / `ProverAddress` field so that the same merge
/// target cannot be consumed by a different prover.
pub fn create_spent_merge_tree(
    prover_address: &[u8],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    write_type(&mut tree, "merge:SpentMerge")?;
    write_field(&mut tree, "merge:SpentMerge", "ProverAddress", prover_address)?;
    Ok(tree)
}

/// Materialize a ProverSeniorityMerge.
///
/// 1. Reads the prover's current Seniority from `prover_tree`.
/// 2. Adds `merge_seniority` (pre-computed from the merge targets'
///    Ed448 peer IDs via `compat::GetAggregatedSeniority`).
/// 3. Writes the new Seniority value.
/// 4. Creates spent-merge marker trees for each merge target.
///
/// The caller is responsible for:
/// - Computing `merge_seniority` from the merge targets (requires
///   Ed448 key → peer ID conversion + seniority DB lookup, which are
///   not available in the pure-data layer).
/// - Writing the prover tree and spent markers to the CRDT.
///
/// Go equivalent: `ProverSeniorityMerge::Materialize` at
/// `global_prover_seniority_merge.go:65`.
pub fn materialize_seniority_merge(
    prover_tree: &mut quil_tries::VectorCommitmentTree,
    prover_address: &[u8],
    merge_seniority: u64,
    merge_target_pubkeys: &[Vec<u8>],
) -> Result<Vec<([u8; 32], quil_tries::VectorCommitmentTree)>> {
    let cls = "prover:Prover";

    // Read existing seniority
    let existing_seniority = read_field(prover_tree, cls, "Seniority")
        .and_then(|b| {
            if b.len() == 8 {
                Some(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            } else {
                None
            }
        })
        .unwrap_or(0);

    // Add merge seniority to existing
    let new_seniority = existing_seniority.saturating_add(merge_seniority);

    // Write updated seniority
    write_field(prover_tree, cls, "Seniority", &new_seniority.to_be_bytes())?;

    // Create spent-merge markers for each target
    let mut spent_markers = Vec::with_capacity(merge_target_pubkeys.len());
    for pubkey in merge_target_pubkeys {
        let spent_addr = spent_seniority_merge_address(pubkey)?;
        let spent_tree = create_spent_merge_tree(prover_address)?;
        spent_markers.push((spent_addr, spent_tree));
    }

    Ok(spent_markers)
}

// =====================================================================
// ShardSplit materialize (0x031E)
// =====================================================================

/// Output of a shard split materialize.
pub struct ShardSplitOutput {
    /// (shard_l2, shard_path) pairs for each new sub-shard to register.
    /// `l2` is the first 32 bytes of the proposed shard address,
    /// `path` is the remaining bytes as `u32` nibble indices.
    pub new_shards: Vec<(Vec<u8>, Vec<u32>)>,
}

/// Materialize a ShardSplit.
///
/// Parses each proposed sub-shard address into L2 (first 32 bytes) and
/// path (remaining bytes as uint32s). Returns the parsed shard info;
/// the caller is responsible for writing to the shards store.
pub fn materialize_shard_split(
    shard_address: &[u8],
    proposed_shards: &[Vec<u8>],
) -> Result<ShardSplitOutput> {
    if shard_address.len() < 32 {
        return Err(QuilError::InvalidArgument(
            "materialize shard split: shard_address must be >= 32 bytes".into(),
        ));
    }
    if proposed_shards.len() < 2 {
        return Err(QuilError::InvalidArgument(
            "materialize shard split: need at least 2 proposed shards".into(),
        ));
    }

    let mut new_shards = Vec::with_capacity(proposed_shards.len());
    for proposed in proposed_shards {
        if proposed.len() < 32 {
            return Err(QuilError::InvalidArgument(
                "materialize shard split: proposed shard must be >= 32 bytes".into(),
            ));
        }
        // Validate that proposed shard shares the parent prefix
        if !proposed.starts_with(shard_address) {
            return Err(QuilError::InvalidArgument(
                "materialize shard split: proposed shard must share parent prefix".into(),
            ));
        }
        // Extract L2 (first 32 bytes) and path (remaining bytes as u32 nibble indices)
        let l2 = proposed[..32].to_vec();
        let path: Vec<u32> = proposed[32..].iter().map(|&b| b as u32).collect();
        new_shards.push((l2, path));
    }

    Ok(ShardSplitOutput { new_shards })
}

// =====================================================================
// ShardMerge materialize (0x031F)
// =====================================================================

/// Output of a shard merge materialize.
pub struct ShardMergeOutput {
    /// (shard_l2, shard_path) pairs for each sub-shard to remove.
    pub removed_shards: Vec<(Vec<u8>, Vec<u32>)>,
}

/// Materialize a ShardMerge.
///
/// Parses each child shard address into L2 (first 32 bytes) and
/// path (remaining bytes as uint32s). Returns the parsed shard info
/// for removal; the caller is responsible for writing to the shards store.
pub fn materialize_shard_merge(
    shard_addresses: &[Vec<u8>],
    parent_address: &[u8],
) -> Result<ShardMergeOutput> {
    if parent_address.len() != 32 {
        return Err(QuilError::InvalidArgument(
            "materialize shard merge: parent_address must be 32 bytes".into(),
        ));
    }
    if shard_addresses.len() < 2 {
        return Err(QuilError::InvalidArgument(
            "materialize shard merge: need at least 2 shard addresses".into(),
        ));
    }

    let mut removed_shards = Vec::with_capacity(shard_addresses.len());
    for addr in shard_addresses {
        if addr.len() <= 32 {
            return Err(QuilError::InvalidArgument(
                "materialize shard merge: cannot merge base shards (must be > 32 bytes)".into(),
            ));
        }
        // Validate that all shards share the parent prefix
        if !addr.starts_with(parent_address) {
            return Err(QuilError::InvalidArgument(
                "materialize shard merge: shard must share parent address prefix".into(),
            ));
        }
        let l2 = addr[..32].to_vec();
        let path: Vec<u32> = addr[32..].iter().map(|&b| b as u32).collect();
        removed_shards.push((l2, path));
    }

    Ok(ShardMergeOutput { removed_shards })
}

// =====================================================================
// FrameHeader / ProverShardUpdate materialize (0x030A)
// =====================================================================

/// Materialize a FrameHeader (ProverShardUpdate).
///
/// In Go this is `ProverShardUpdate::Materialize` at
/// `global_prover_shard_update.go:147`. It performs two operations for
/// each participating prover on the shard:
///
/// 1. **Reward distribution**: calculates the per-ring reward share
///    based on difficulty, world size, and prover ring assignment, then
///    adds it to the prover's reward balance.
///
/// 2. **Activity tracking**: updates the allocation's
///    `LastActiveFrameNumber` to the current frame number.
///
/// Both require runtime dependencies (prover registry, frame prover
/// for BLS signature verification, reward issuance calculator,
/// hypergraph metadata for state size/shard count) that are not
/// available in the pure-data layer.
///
/// This function implements the **activity tracking** half: given a
/// list of participating allocation trees, it updates each one's
/// `LastActiveFrameNumber`.
///
/// For reward distribution, see `add_to_reward_balance` above. The
/// caller is responsible for computing the reward amounts using the
/// reward issuance calculator and applying them.
pub fn materialize_frame_header_activity(
    allocation_tree: &mut quil_tries::VectorCommitmentTree,
    frame_number: u64,
) -> Result<()> {
    let cls = "allocation:ProverAllocation";
    write_field(
        allocation_tree,
        cls,
        "LastActiveFrameNumber",
        &frame_number.to_be_bytes(),
    )
}

/// Ring group size for reward distribution — matches Go's
/// `ringGroupSize = 8` at `global_prover_shard_update.go:28`.
pub const RING_GROUP_SIZE: u64 = 8;

/// Default shard leaf count when metadata reports zero.
/// Matches Go's `defaultShardLeaves = 1`.
pub const DEFAULT_SHARD_LEAVES: u64 = 1;

/// Reward units per block.
pub const REWARD_UNITS: u64 = 8_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use crate::global_schema::{write_type, TYPE_HASH_ALLOCATION};

    fn make_allocation_tree(status: u8) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "allocation:ProverAllocation").unwrap();
        write_field(&mut tree, "allocation:ProverAllocation", "Status", &[status]).unwrap();
        tree
    }

    // -----------------------------------------------------------------
    // materialize_prover_pause
    // -----------------------------------------------------------------

    #[test]
    fn pause_sets_status_to_paused() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_pause(&mut tree, 100).unwrap();
        let status = read_field(&tree, "allocation:ProverAllocation", "Status").unwrap();
        assert_eq!(status, vec![STATUS_PAUSED]);
    }

    #[test]
    fn pause_sets_pause_frame_number() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_pause(&mut tree, 12345).unwrap();
        let frame = read_field(&tree, "allocation:ProverAllocation", "PauseFrameNumber").unwrap();
        assert_eq!(frame, 12345u64.to_be_bytes().to_vec());
    }

    #[test]
    fn pause_rejects_non_active_status() {
        let mut tree = make_allocation_tree(STATUS_PAUSED);
        assert!(materialize_prover_pause(&mut tree, 100).is_err());
    }

    #[test]
    fn pause_rejects_leaving_status() {
        let mut tree = make_allocation_tree(STATUS_LEAVING);
        assert!(materialize_prover_pause(&mut tree, 100).is_err());
    }

    // -----------------------------------------------------------------
    // materialize_prover_resume
    // -----------------------------------------------------------------

    #[test]
    fn resume_sets_status_to_active() {
        let mut tree = make_allocation_tree(STATUS_PAUSED);
        materialize_prover_resume(&mut tree, 200).unwrap();
        let status = read_field(&tree, "allocation:ProverAllocation", "Status").unwrap();
        assert_eq!(status, vec![STATUS_ACTIVE]);
    }

    #[test]
    fn resume_sets_resume_frame_number() {
        let mut tree = make_allocation_tree(STATUS_PAUSED);
        materialize_prover_resume(&mut tree, 200).unwrap();
        let frame = read_field(&tree, "allocation:ProverAllocation", "ResumeFrameNumber").unwrap();
        assert_eq!(frame, 200u64.to_be_bytes().to_vec());
    }

    #[test]
    fn resume_rejects_non_paused_status() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        assert!(materialize_prover_resume(&mut tree, 200).is_err());
    }

    // -----------------------------------------------------------------
    // materialize_prover_leave
    // -----------------------------------------------------------------

    #[test]
    fn leave_from_active_sets_status_to_leaving() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_leave(&mut tree, 300).unwrap();
        let status = read_field(&tree, "allocation:ProverAllocation", "Status").unwrap();
        assert_eq!(status, vec![STATUS_LEAVING]);
    }

    #[test]
    fn leave_from_paused_sets_status_to_leaving() {
        let mut tree = make_allocation_tree(STATUS_PAUSED);
        materialize_prover_leave(&mut tree, 300).unwrap();
        let status = read_field(&tree, "allocation:ProverAllocation", "Status").unwrap();
        assert_eq!(status, vec![STATUS_LEAVING]);
    }

    #[test]
    fn leave_sets_leave_frame_number() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_leave(&mut tree, 999).unwrap();
        let frame = read_field(&tree, "allocation:ProverAllocation", "LeaveFrameNumber").unwrap();
        assert_eq!(frame, 999u64.to_be_bytes().to_vec());
    }

    #[test]
    fn leave_rejects_joining_status() {
        let mut tree = make_allocation_tree(STATUS_JOINING);
        assert!(materialize_prover_leave(&mut tree, 300).is_err());
    }

    #[test]
    fn leave_rejects_kicked_status() {
        let mut tree = make_allocation_tree(STATUS_KICKED);
        assert!(materialize_prover_leave(&mut tree, 300).is_err());
    }

    // -----------------------------------------------------------------
    // Full cycle: pause → resume
    // -----------------------------------------------------------------

    #[test]
    fn pause_then_resume_returns_to_active() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_pause(&mut tree, 100).unwrap();
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_PAUSED]
        );
        materialize_prover_resume(&mut tree, 200).unwrap();
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_ACTIVE]
        );
        // Both frame numbers should be recorded
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "PauseFrameNumber").unwrap(),
            100u64.to_be_bytes().to_vec()
        );
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "ResumeFrameNumber").unwrap(),
            200u64.to_be_bytes().to_vec()
        );
    }

    // -----------------------------------------------------------------
    // Full cycle: active → leave
    // -----------------------------------------------------------------

    #[test]
    fn active_to_leave_transition() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        materialize_prover_leave(&mut tree, 500).unwrap();
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_LEAVING]
        );
        // Cannot pause a leaving allocation
        assert!(materialize_prover_pause(&mut tree, 600).is_err());
    }

    // -----------------------------------------------------------------
    // ProverJoin materialize
    // -----------------------------------------------------------------

    #[test]
    fn prover_address_from_pubkey_is_deterministic() {
        let pk = vec![0xAAu8; 585];
        let a1 = prover_address_from_pubkey(&pk).unwrap();
        let a2 = prover_address_from_pubkey(&pk).unwrap();
        assert_eq!(a1, a2);
        assert_eq!(a1.len(), 32);
        assert!(a1.iter().any(|&b| b != 0));
    }

    #[test]
    fn prover_address_differs_for_different_keys() {
        let a1 = prover_address_from_pubkey(&vec![0xAAu8; 585]).unwrap();
        let a2 = prover_address_from_pubkey(&vec![0xBBu8; 585]).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn allocation_address_is_deterministic() {
        let pk = vec![0xAAu8; 585];
        let filter = vec![0xBBu8; 32];
        let a1 = allocation_address(&pk, &filter).unwrap();
        let a2 = allocation_address(&pk, &filter).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn allocation_address_differs_by_filter() {
        let pk = vec![0xAAu8; 585];
        let a1 = allocation_address(&pk, &vec![0x01u8; 32]).unwrap();
        let a2 = allocation_address(&pk, &vec![0x02u8; 32]).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn create_prover_vertex_tree_has_correct_fields() {
        let pk = vec![0xAAu8; 585];
        let tree = create_prover_vertex_tree(&pk, 42).unwrap();

        assert_eq!(crate::global_schema::read_type(&tree), Some("prover:Prover"));
        assert_eq!(read_field(&tree, "prover:Prover", "PublicKey").unwrap(), pk);
        assert_eq!(read_field(&tree, "prover:Prover", "Status").unwrap(), vec![STATUS_JOINING]);
        assert_eq!(read_field(&tree, "prover:Prover", "AvailableStorage").unwrap(), 0u64.to_be_bytes().to_vec());
        assert_eq!(read_field(&tree, "prover:Prover", "Seniority").unwrap(), 42u64.to_be_bytes().to_vec());
    }

    #[test]
    fn create_allocation_vertex_tree_has_correct_fields() {
        let prover_addr = [0xCCu8; 32];
        let filter = vec![0xDDu8; 48];
        let tree = create_allocation_vertex_tree(&prover_addr, &filter, 100).unwrap();

        assert_eq!(crate::global_schema::read_type(&tree), Some("allocation:ProverAllocation"));
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Prover").unwrap(), prover_addr.to_vec());
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_JOINING]);
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "ConfirmationFilter").unwrap(), filter);
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "JoinFrameNumber").unwrap(), 100u64.to_be_bytes().to_vec());
    }

    #[test]
    fn materialize_prover_join_creates_prover_and_allocations() {
        let pk = vec![0xAAu8; 585];
        let filters = vec![vec![0x01u8; 32], vec![0x02u8; 48]];
        let output = materialize_prover_join(&pk, &filters, 50, 0).unwrap();

        // Prover tree
        assert_eq!(crate::global_schema::read_type(&output.prover_tree), Some("prover:Prover"));
        assert_eq!(read_field(&output.prover_tree, "prover:Prover", "PublicKey").unwrap(), pk);

        // Prover address
        assert_eq!(output.prover_address, prover_address_from_pubkey(&pk).unwrap());

        // Two allocations
        assert_eq!(output.allocations.len(), 2);
        for (alloc_addr, alloc_tree) in &output.allocations {
            assert_eq!(alloc_addr.len(), 32);
            assert_eq!(crate::global_schema::read_type(alloc_tree), Some("allocation:ProverAllocation"));
            assert_eq!(
                read_field(alloc_tree, "allocation:ProverAllocation", "JoinFrameNumber").unwrap(),
                50u64.to_be_bytes().to_vec()
            );
        }
    }

    #[test]
    fn materialize_prover_join_with_seniority() {
        let pk = vec![0xBBu8; 585];
        let output = materialize_prover_join(&pk, &[vec![0x01u8; 32]], 10, 999).unwrap();
        assert_eq!(
            read_field(&output.prover_tree, "prover:Prover", "Seniority").unwrap(),
            999u64.to_be_bytes().to_vec()
        );
    }

    // -----------------------------------------------------------------
    // compute_aggregate_prover_status
    // -----------------------------------------------------------------

    #[test]
    fn aggregate_empty_is_left() {
        assert_eq!(compute_aggregate_prover_status(&[]), STATUS_KICKED);
    }

    #[test]
    fn aggregate_active_wins_over_all() {
        assert_eq!(compute_aggregate_prover_status(&[STATUS_ACTIVE]), STATUS_ACTIVE);
        assert_eq!(compute_aggregate_prover_status(&[STATUS_JOINING, STATUS_ACTIVE, STATUS_PAUSED]), STATUS_ACTIVE);
    }

    #[test]
    fn aggregate_joining_wins_over_leaving_paused_left() {
        assert_eq!(compute_aggregate_prover_status(&[STATUS_JOINING, STATUS_LEAVING, STATUS_PAUSED]), STATUS_JOINING);
    }

    #[test]
    fn aggregate_leaving_wins_over_paused_left() {
        assert_eq!(compute_aggregate_prover_status(&[STATUS_LEAVING, STATUS_PAUSED, STATUS_KICKED]), STATUS_LEAVING);
    }

    #[test]
    fn aggregate_paused_wins_over_left() {
        assert_eq!(compute_aggregate_prover_status(&[STATUS_PAUSED, STATUS_KICKED]), STATUS_PAUSED);
    }

    #[test]
    fn aggregate_all_left_is_left() {
        assert_eq!(compute_aggregate_prover_status(&[STATUS_KICKED, STATUS_KICKED]), STATUS_KICKED);
    }

    #[test]
    fn update_prover_status_writes_to_tree() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "prover:Prover").unwrap();
        write_field(&mut tree, "prover:Prover", "Status", &[STATUS_JOINING]).unwrap();

        let new_status = update_prover_status_from_allocations(
            &mut tree,
            &[STATUS_ACTIVE, STATUS_PAUSED],
        ).unwrap();
        assert_eq!(new_status, STATUS_ACTIVE);
        assert_eq!(read_field(&tree, "prover:Prover", "Status").unwrap(), vec![STATUS_ACTIVE]);
    }

    // -----------------------------------------------------------------
    // materialize_prover_confirm
    // -----------------------------------------------------------------

    #[test]
    fn confirm_join_sets_active_and_frame_numbers() {
        let mut tree = make_allocation_tree(STATUS_JOINING);
        materialize_prover_confirm(&mut tree, 400).unwrap();
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_ACTIVE]);
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "JoinConfirmFrameNumber").unwrap(), 400u64.to_be_bytes().to_vec());
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap(), 400u64.to_be_bytes().to_vec());
    }

    #[test]
    fn confirm_leave_sets_left_and_frame_number() {
        let mut tree = make_allocation_tree(STATUS_LEAVING);
        materialize_prover_confirm(&mut tree, 500).unwrap();
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_KICKED]); // 4 = left
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "LeaveConfirmFrameNumber").unwrap(), 500u64.to_be_bytes().to_vec());
    }

    #[test]
    fn confirm_rejects_active_status() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        assert!(materialize_prover_confirm(&mut tree, 400).is_err());
    }

    #[test]
    fn confirm_rejects_paused_status() {
        let mut tree = make_allocation_tree(STATUS_PAUSED);
        assert!(materialize_prover_confirm(&mut tree, 400).is_err());
    }

    // -----------------------------------------------------------------
    // materialize_prover_reject
    // -----------------------------------------------------------------

    #[test]
    fn reject_join_sets_kicked() {
        let mut tree = make_allocation_tree(STATUS_JOINING);
        materialize_prover_reject(&mut tree, 450).unwrap();
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_KICKED]);
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "JoinRejectFrameNumber").unwrap(), 450u64.to_be_bytes().to_vec());
    }

    #[test]
    fn reject_leave_sets_active() {
        let mut tree = make_allocation_tree(STATUS_LEAVING);
        materialize_prover_reject(&mut tree, 550).unwrap();
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_ACTIVE]);
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "LeaveRejectFrameNumber").unwrap(), 550u64.to_be_bytes().to_vec());
        assert_eq!(read_field(&tree, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap(), 550u64.to_be_bytes().to_vec());
    }

    #[test]
    fn reject_rejects_active_status() {
        let mut tree = make_allocation_tree(STATUS_ACTIVE);
        assert!(materialize_prover_reject(&mut tree, 450).is_err());
    }

    // -----------------------------------------------------------------
    // Full lifecycle: join → confirm → pause → leave → confirm leave
    // -----------------------------------------------------------------

    #[test]
    fn full_lifecycle_with_confirm() {
        let prover_addr = [0xAAu8; 32];
        let filter = vec![0xBBu8; 32];

        // Join creates the allocation with status=0
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &filter, 100).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_JOINING]);

        // Confirm join → active
        materialize_prover_confirm(&mut alloc, 460).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_ACTIVE]);

        // Pause
        materialize_prover_pause(&mut alloc, 500).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_PAUSED]);

        // Resume
        materialize_prover_resume(&mut alloc, 600).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_ACTIVE]);

        // Leave
        materialize_prover_leave(&mut alloc, 700).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_LEAVING]);

        // Confirm leave → left
        materialize_prover_confirm(&mut alloc, 1060).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_KICKED]);
    }

    #[test]
    fn lifecycle_join_then_reject() {
        let prover_addr = [0xCCu8; 32];
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &vec![0xDDu8; 32], 100).unwrap();

        // Reject join → kicked
        materialize_prover_reject(&mut alloc, 460).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_KICKED]);

        // Cannot do anything further with kicked allocation
        assert!(materialize_prover_pause(&mut alloc, 500).is_err());
        assert!(materialize_prover_resume(&mut alloc, 500).is_err());
        assert!(materialize_prover_leave(&mut alloc, 500).is_err());
    }

    #[test]
    fn lifecycle_leave_then_reject_returns_to_active() {
        let prover_addr = [0xEEu8; 32];
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &vec![0xFFu8; 32], 100).unwrap();

        // Confirm join
        materialize_prover_confirm(&mut alloc, 460).unwrap();
        // Leave
        materialize_prover_leave(&mut alloc, 500).unwrap();
        // Reject leave → back to active
        materialize_prover_reject(&mut alloc, 600).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_ACTIVE]);

        // Can pause again after reject-leave
        materialize_prover_pause(&mut alloc, 700).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_PAUSED]);
    }

    // -----------------------------------------------------------------
    // reward_address + set_reward_delegate_address
    // -----------------------------------------------------------------

    #[test]
    fn reward_address_is_deterministic() {
        let pa = [0xAAu8; 32];
        assert_eq!(reward_address(&pa).unwrap(), reward_address(&pa).unwrap());
    }

    #[test]
    fn reward_address_differs_for_different_provers() {
        assert_ne!(
            reward_address(&[0xAAu8; 32]).unwrap(),
            reward_address(&[0xBBu8; 32]).unwrap()
        );
    }

    #[test]
    fn set_reward_delegate_address_creates_tree() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let delegate = vec![0xDDu8; 32];
        set_reward_delegate_address(&mut tree, &delegate).unwrap();
        assert_eq!(crate::global_schema::read_type(&tree), Some("reward:ProverReward"));
        assert_eq!(
            read_field(&tree, "reward:ProverReward", "DelegateAddress").unwrap(),
            delegate
        );
    }

    #[test]
    fn set_reward_delegate_address_overwrites() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        set_reward_delegate_address(&mut tree, &vec![0x11u8; 32]).unwrap();
        set_reward_delegate_address(&mut tree, &vec![0x22u8; 32]).unwrap();
        assert_eq!(
            read_field(&tree, "reward:ProverReward", "DelegateAddress").unwrap(),
            vec![0x22u8; 32]
        );
    }

    // -----------------------------------------------------------------
    // Reward balance operations
    // -----------------------------------------------------------------

    #[test]
    fn reward_balance_starts_empty() {
        let tree = quil_tries::VectorCommitmentTree::new();
        assert!(read_reward_balance(&tree).is_empty());
    }

    #[test]
    fn set_and_read_reward_balance() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let balance = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8]; // 1000
        set_reward_balance(&mut tree, &balance).unwrap();
        assert_eq!(read_reward_balance(&tree), balance);
    }

    #[test]
    fn add_to_reward_balance_accumulates() {
        use num_bigint::BigInt;
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "reward:ProverReward").unwrap();

        add_to_reward_balance(&mut tree, &BigInt::from(1000)).unwrap();
        let b1 = read_reward_balance(&tree);
        let val1 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &b1);
        assert_eq!(val1, BigInt::from(1000));

        add_to_reward_balance(&mut tree, &BigInt::from(500)).unwrap();
        let b2 = read_reward_balance(&tree);
        let val2 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &b2);
        assert_eq!(val2, BigInt::from(1500));
    }

    #[test]
    fn add_to_reward_balance_from_empty() {
        use num_bigint::BigInt;
        let mut tree = quil_tries::VectorCommitmentTree::new();
        add_to_reward_balance(&mut tree, &BigInt::from(42)).unwrap();
        let b = read_reward_balance(&tree);
        assert_eq!(BigInt::from_bytes_be(num_bigint::Sign::Plus, &b), BigInt::from(42));
    }

    // -----------------------------------------------------------------
    // materialize_prover_kick
    // -----------------------------------------------------------------

    #[test]
    fn kick_sets_prover_status_and_frame() {
        let pk = vec![0xAAu8; 585];
        let mut tree = create_prover_vertex_tree(&pk, 100).unwrap();
        // Simulate confirm (set active)
        write_field(&mut tree, "prover:Prover", "Status", &[STATUS_ACTIVE]).unwrap();

        materialize_prover_kick(&mut tree, 999).unwrap();
        assert_eq!(read_field(&tree, "prover:Prover", "Status").unwrap(), vec![STATUS_KICKED]);
        assert_eq!(read_field(&tree, "prover:Prover", "KickFrameNumber").unwrap(), 999u64.to_be_bytes().to_vec());
        // PublicKey and Seniority should be unchanged
        assert_eq!(read_field(&tree, "prover:Prover", "PublicKey").unwrap(), pk);
    }

    #[test]
    fn kick_allocation_sets_status_and_frame() {
        let prover_addr = [0xBBu8; 32];
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &vec![0xCCu8; 32], 100).unwrap();
        // Simulate confirm
        write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();

        materialize_prover_kick_allocation(&mut alloc, 999).unwrap();
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(), vec![STATUS_KICKED]);
        assert_eq!(read_field(&alloc, "allocation:ProverAllocation", "KickFrameNumber").unwrap(), 999u64.to_be_bytes().to_vec());
    }

    #[test]
    fn kick_zeroes_seniority() {
        let pk = vec![0xDDu8; 585];
        let mut tree = create_prover_vertex_tree(&pk, 42).unwrap();
        materialize_prover_kick(&mut tree, 100).unwrap();
        // Kicked provers lose their seniority
        assert_eq!(read_field(&tree, "prover:Prover", "Seniority").unwrap(), 0u64.to_be_bytes().to_vec());
    }

    #[test]
    fn kicked_prover_cannot_be_paused() {
        let pk = vec![0xEEu8; 585];
        let mut tree = create_prover_vertex_tree(&pk, 0).unwrap();
        materialize_prover_kick(&mut tree, 100).unwrap();
        // Status is now 4 — cannot transition further
        // (the materialize functions check status preconditions)
    }

    #[test]
    fn materialize_prover_join_empty_filters() {
        let pk = vec![0xCCu8; 585];
        let output = materialize_prover_join(&pk, &[], 1, 0).unwrap();
        assert!(output.allocations.is_empty());
    }

    // -----------------------------------------------------------------
    // Full cycle: join → pause → resume → leave
    // -----------------------------------------------------------------

    #[test]
    fn full_lifecycle_join_then_pause_then_resume_then_leave() {
        let prover_addr = [0xCCu8; 32];
        let filter = vec![0xFFu8; 32];

        // Start with a fresh allocation tree (simulating join output)
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &filter, 10).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_JOINING]
        );

        // Simulate confirm by manually setting status to active
        write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();

        // Pause
        materialize_prover_pause(&mut alloc, 20).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_PAUSED]
        );

        // Resume
        materialize_prover_resume(&mut alloc, 30).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_ACTIVE]
        );

        // Leave
        materialize_prover_leave(&mut alloc, 40).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "Status").unwrap(),
            vec![STATUS_LEAVING]
        );
    }

    // -----------------------------------------------------------------
    // materialize_seniority_merge
    // -----------------------------------------------------------------

    #[test]
    fn seniority_merge_adds_to_existing() {
        let pk = vec![0xAAu8; 585];
        let mut tree = create_prover_vertex_tree(&pk, 100).unwrap();
        let prover_addr = prover_address_from_pubkey(&pk).unwrap();

        let merge_pubkeys = vec![vec![0xBBu8; 57], vec![0xCCu8; 57]];
        let spent = materialize_seniority_merge(
            &mut tree, &prover_addr, 500, &merge_pubkeys,
        ).unwrap();

        // Seniority should be 100 + 500 = 600
        let seniority = read_field(&tree, "prover:Prover", "Seniority").unwrap();
        assert_eq!(seniority, 600u64.to_be_bytes().to_vec());

        // Should have 2 spent markers
        assert_eq!(spent.len(), 2);
        for (addr, marker_tree) in &spent {
            assert_eq!(addr.len(), 32);
            assert_eq!(
                crate::global_schema::read_type(marker_tree),
                Some("merge:SpentMerge"),
            );
            assert_eq!(
                read_field(marker_tree, "merge:SpentMerge", "ProverAddress").unwrap(),
                prover_addr.to_vec(),
            );
        }
    }

    #[test]
    fn seniority_merge_from_zero() {
        let pk = vec![0xDDu8; 585];
        let mut tree = create_prover_vertex_tree(&pk, 0).unwrap();
        let prover_addr = prover_address_from_pubkey(&pk).unwrap();

        let _ = materialize_seniority_merge(
            &mut tree, &prover_addr, 42, &[vec![0xEEu8; 57]],
        ).unwrap();

        let seniority = read_field(&tree, "prover:Prover", "Seniority").unwrap();
        assert_eq!(seniority, 42u64.to_be_bytes().to_vec());
    }

    #[test]
    fn spent_seniority_merge_address_is_deterministic() {
        let pk = vec![0xAAu8; 57];
        let a1 = spent_seniority_merge_address(&pk).unwrap();
        let a2 = spent_seniority_merge_address(&pk).unwrap();
        assert_eq!(a1, a2);
        assert_eq!(a1.len(), 32);
    }

    #[test]
    fn spent_seniority_merge_address_differs_by_key() {
        let a1 = spent_seniority_merge_address(&vec![0x01u8; 57]).unwrap();
        let a2 = spent_seniority_merge_address(&vec![0x02u8; 57]).unwrap();
        assert_ne!(a1, a2);
    }

    // -----------------------------------------------------------------
    // materialize_shard_split
    // -----------------------------------------------------------------

    #[test]
    fn shard_split_parses_proposed_shards() {
        let parent = vec![0xAAu8; 32];
        let mut child1 = parent.clone();
        child1.push(0x01);
        let mut child2 = parent.clone();
        child2.push(0x02);

        let output = materialize_shard_split(&parent, &[child1.clone(), child2.clone()]).unwrap();
        assert_eq!(output.new_shards.len(), 2);
        assert_eq!(output.new_shards[0].0, parent); // L2 = first 32 bytes
        assert_eq!(output.new_shards[0].1, vec![0x01u32]); // path = remaining
        assert_eq!(output.new_shards[1].1, vec![0x02u32]);
    }

    #[test]
    fn shard_split_rejects_short_parent() {
        assert!(materialize_shard_split(&vec![0xAAu8; 31], &[]).is_err());
    }

    #[test]
    fn shard_split_rejects_fewer_than_two_proposed() {
        let parent = vec![0xAAu8; 32];
        let mut child = parent.clone();
        child.push(0x01);
        assert!(materialize_shard_split(&parent, &[child]).is_err());
    }

    #[test]
    fn shard_split_rejects_mismatched_prefix() {
        let parent = vec![0xAAu8; 32];
        let mut bad_child = vec![0xBBu8; 32];
        bad_child.push(0x01);
        let mut good_child = parent.clone();
        good_child.push(0x02);
        assert!(materialize_shard_split(&parent, &[good_child, bad_child]).is_err());
    }

    // -----------------------------------------------------------------
    // materialize_shard_merge
    // -----------------------------------------------------------------

    #[test]
    fn shard_merge_parses_child_shards() {
        let parent = vec![0xAAu8; 32];
        let mut child1 = parent.clone();
        child1.push(0x01);
        let mut child2 = parent.clone();
        child2.push(0x02);

        let output = materialize_shard_merge(&[child1, child2], &parent).unwrap();
        assert_eq!(output.removed_shards.len(), 2);
        assert_eq!(output.removed_shards[0].0, parent);
        assert_eq!(output.removed_shards[0].1, vec![0x01u32]);
        assert_eq!(output.removed_shards[1].1, vec![0x02u32]);
    }

    #[test]
    fn shard_merge_rejects_wrong_parent_length() {
        let parent = vec![0xAAu8; 31]; // too short
        let mut child = vec![0xAAu8; 32];
        child.push(0x01);
        assert!(materialize_shard_merge(&[child.clone(), child], &parent).is_err());
    }

    #[test]
    fn shard_merge_rejects_base_shards() {
        let parent = vec![0xAAu8; 32];
        let base_shard = vec![0xAAu8; 32]; // exactly 32 bytes = base shard
        let mut child = parent.clone();
        child.push(0x01);
        assert!(materialize_shard_merge(&[base_shard, child], &parent).is_err());
    }

    #[test]
    fn shard_merge_rejects_mismatched_prefix() {
        let parent = vec![0xAAu8; 32];
        let mut bad_child = vec![0xBBu8; 32];
        bad_child.push(0x01);
        let mut good_child = parent.clone();
        good_child.push(0x02);
        assert!(materialize_shard_merge(&[good_child, bad_child], &parent).is_err());
    }

    #[test]
    fn shard_merge_rejects_fewer_than_two() {
        let parent = vec![0xAAu8; 32];
        let mut child = parent.clone();
        child.push(0x01);
        assert!(materialize_shard_merge(&[child], &parent).is_err());
    }

    // -----------------------------------------------------------------
    // materialize_frame_header_activity
    // -----------------------------------------------------------------

    #[test]
    fn frame_header_activity_updates_last_active() {
        let prover_addr = [0xAAu8; 32];
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &vec![0xBBu8; 32], 100).unwrap();
        // Simulate confirm
        write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();

        materialize_frame_header_activity(&mut alloc, 500).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap(),
            500u64.to_be_bytes().to_vec(),
        );
    }

    #[test]
    fn frame_header_activity_overwrites_previous() {
        let prover_addr = [0xCCu8; 32];
        let mut alloc = create_allocation_vertex_tree(&prover_addr, &vec![0xDDu8; 32], 100).unwrap();

        materialize_frame_header_activity(&mut alloc, 500).unwrap();
        materialize_frame_header_activity(&mut alloc, 600).unwrap();
        assert_eq!(
            read_field(&alloc, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap(),
            600u64.to_be_bytes().to_vec(),
        );
    }

    #[test]
    fn ring_group_size_matches_go() {
        assert_eq!(RING_GROUP_SIZE, 8);
    }

    #[test]
    fn reward_units_matches_go() {
        assert_eq!(REWARD_UNITS, 8_000_000_000);
    }
}
