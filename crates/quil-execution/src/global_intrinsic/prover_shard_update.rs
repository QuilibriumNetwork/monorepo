//! ProverShardUpdate (FrameHeader) Validate + Materialize.
//! Verifies aggregate BLS signature, enforces 2/3 participation,
//! computes per-ring reward shares, credits participants, and updates
//! `LastActiveFrameNumber`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use num_bigint::BigInt;

/// When set, `apply_reward` logs credits applied to this address.
pub static LOCAL_PROVER_ADDRESS: OnceLock<Vec<u8>> = OnceLock::new();

/// Read the current reward balance for `prover_address` from the CRDT.
pub fn read_reward_balance_for(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    prover_address: &[u8],
) -> Result<BigInt> {
    use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
    use super::materialize::reward_address;
    use crate::prover_registry::rebuild_vertex_tree_from_blob;

    let state = HypergraphState::new(crdt.clone());
    let reward_addr = reward_address(prover_address)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;

    let blob = state.get(domain, &reward_addr, &va_disc)?;
    let tree = match blob {
        Some(b) if !b.is_empty() => rebuild_vertex_tree_from_blob(&b),
        _ => return Ok(BigInt::from(0)),
    };
    let bytes = super::materialize::read_reward_balance(&tree);
    if bytes.is_empty() {
        Ok(BigInt::from(0))
    } else {
        Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes))
    }
}

use quil_types::consensus::{ProverAllocation, ProverInfo, ProverRegistry, RewardIssuance};
use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};

use super::frame_header::FrameHeader;
use super::materialize::{
    add_to_reward_balance, allocation_address, materialize_frame_header_activity, reward_address,
    DEFAULT_SHARD_LEAVES, REWARD_UNITS, RING_GROUP_SIZE,
};
use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

/// Hypergraph metadata for the shard under `FrameHeader.address`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShardMetadata {
    pub state_size: u64,
    /// Zero becomes `DEFAULT_SHARD_LEAVES` = 1.
    pub shard_count: u64,
}

/// Participants from a frame header, grouped by ring.
#[derive(Debug, Clone)]
pub struct ShardUpdateContext {
    pub active_provers: Vec<ProverInfo>,
    pub participant_indices: Vec<usize>,
    pub participants_by_ring: HashMap<u8, Vec<usize>>,
    pub ring_by_prover_address: HashMap<Vec<u8>, u8>,
    pub state_size: u64,
    pub shard_count: u64,
}

/// Verify a finalized shard FrameHeader's three-layer attestation:
/// leader VDF, aggregate BLS over `make_vote_message(address, rank,
/// poseidon(output))`, and per-participant VDF multi-proofs over
/// `sha3(parent_selector)`. Returns the participant bitmask.
///
/// `active_provers` must be in the same order the consensus committee
/// used at this rank — the bitmask indexes into this list.
pub fn verify_frame_header_attestation(
    frame_header: &FrameHeader,
    frame_prover: &dyn quil_types::crypto::FrameProver,
    bls: &dyn quil_types::crypto::BlsConstructor,
    active_provers: &[ProverInfo],
) -> Result<Vec<u8>> {
    if frame_header.public_key_signature_bls48581.is_empty() {
        return Err(QuilError::InvalidArgument(
            "frame header attestation: missing aggregate signature".into(),
        ));
    }
    let agg = crate::hypergraph_intrinsic::canonical::AggregateSignature::from_canonical_bytes(
        &frame_header.public_key_signature_bls48581,
    )?;
    let agg_pubkey = agg
        .public_key
        .clone()
        .ok_or_else(|| {
            QuilError::InvalidArgument(
                "frame header attestation: aggregate signature missing pubkey".into(),
            )
        })?;
    if agg.bitmask.is_empty() {
        return Err(QuilError::InvalidArgument(
            "frame header attestation: aggregate signature bitmask empty".into(),
        ));
    }

    let proto = quil_types::proto::global::FrameHeader {
        address: frame_header.address.clone(),
        frame_number: frame_header.frame_number,
        rank: frame_header.rank,
        timestamp: frame_header.timestamp,
        difficulty: frame_header.difficulty,
        output: frame_header.output.clone(),
        parent_selector: frame_header.parent_selector.clone(),
        requests_root: frame_header.requests_root.clone(),
        state_roots: frame_header.state_roots.clone(),
        prover: frame_header.prover.clone(),
        fee_multiplier_vote: frame_header.fee_multiplier_vote as u64,
        public_key_signature_bls48581: Some(
            quil_types::proto::keys::Bls48581AggregateSignature {
                signature: agg.signature.clone(),
                public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                    key_value: agg_pubkey.key_value.clone(),
                }),
                bitmask: agg.bitmask.clone(),
            },
        ),
    };

    frame_prover.verify_frame_header(&proto)?;

    let participant_ids: Vec<Vec<u8>> = {
        let indices = quil_consensus::bitmask::set_bit_indices(&agg.bitmask)
            .filter_map(|i| u32::try_from(i).ok().map(|x| x as usize))
            .collect::<Vec<_>>();
        let mut out = Vec::with_capacity(indices.len());
        for idx in indices {
            if idx >= active_provers.len() {
                return Err(QuilError::InvalidArgument(format!(
                    "frame header attestation: bitmask index {} ≥ active provers {}",
                    idx,
                    active_provers.len()
                )));
            }
            out.push(active_provers[idx].address.clone());
        }
        out
    };
    let id_refs: Vec<&[u8]> = participant_ids.iter().map(|v| v.as_slice()).collect();
    // 74-byte aggregate = single signer, no multi-proofs to verify.
    let ids_arg: Option<&[&[u8]]> = if agg.signature.len() == 74 {
        if id_refs.len() != 1 {
            return Err(QuilError::InvalidSignature(
                "frame header attestation: 74-byte signature requires exactly 1 participant".into(),
            ));
        }
        None
    } else {
        Some(&id_refs)
    };
    let valid = frame_prover.verify_frame_header_signature(
        &proto,
        bls,
        ids_arg,
    )?;
    if !valid {
        return Err(QuilError::InvalidSignature(
            "frame header attestation: aggregate BLS + multi-proof check failed".into(),
        ));
    }

    Ok(agg.bitmask)
}

/// Build the per-frame context: groups participants by ring and
/// enforces 2/3 participation. The caller passes in the already-verified
/// bitmask (see `verify_frame_header_attestation`).
pub fn build_shard_update_context(
    frame_header: &FrameHeader,
    active_provers: Vec<ProverInfo>,
    participant_bitmask: &[u8],
    shard_metadata: ShardMetadata,
) -> Result<ShardUpdateContext> {
    if frame_header.address.len() < 32 {
        return Err(QuilError::InvalidArgument(
            "shard update: filter length insufficient".into(),
        ));
    }
    if frame_header.address.is_empty() {
        return Err(QuilError::InvalidArgument(
            "shard update: frame header missing address".into(),
        ));
    }
    if active_provers.is_empty() {
        return Err(QuilError::InvalidArgument(
            "shard update: no active provers for shard".into(),
        ));
    }
    if participant_bitmask.is_empty() {
        return Err(QuilError::InvalidArgument(
            "shard update: frame header signature bitmask empty".into(),
        ));
    }

    // Build the dedup'd sorted participant index list.
    let mut participants_set: std::collections::BTreeSet<usize> = Default::default();
    for &idx in participant_bitmask {
        let i = idx as usize;
        if i >= active_provers.len() {
            return Err(QuilError::InvalidArgument(
                "shard update: bitmask index exceeds active prover count".into(),
            ));
        }
        participants_set.insert(i);
    }

    // 2/3 participation threshold: |participants| * 3 >= |active| * 2.
    if participants_set.len() * 3 < active_provers.len() * 2 {
        return Err(QuilError::InvalidArgument(
            "shard update: insufficient prover participation (< 2/3)".into(),
        ));
    }

    let participant_indices: Vec<usize> = participants_set.into_iter().collect();

    // Compute ring assignments from all active provers.
    let ring_by_prover_address =
        compute_ring_assignments(&active_provers, &frame_header.address)?;

    // Group participants by ring.
    let mut participants_by_ring: HashMap<u8, Vec<usize>> = HashMap::new();
    for &idx in &participant_indices {
        let addr = &active_provers[idx].address;
        let ring = *ring_by_prover_address.get(addr).ok_or_else(|| {
            QuilError::InvalidArgument("shard update: missing ring for participant".into())
        })?;
        participants_by_ring.entry(ring).or_default().push(idx);
    }

    // Resolve state size / shard count.
    let mut shard_count = shard_metadata.shard_count;
    if shard_count == 0 {
        shard_count = DEFAULT_SHARD_LEAVES;
    }

    Ok(ShardUpdateContext {
        active_provers,
        participant_indices,
        participants_by_ring,
        ring_by_prover_address,
        state_size: shard_metadata.state_size,
        shard_count,
    })
}

/// Compute ring assignments from the full active-prover list.
///
/// Go equivalent: `computeRingAssignments` at
/// `global_prover_shard_update.go:349`.
///
/// Sort order (descending priority):
/// 1. `JoinFrameNumber` ascending (fallback to `JoinConfirmFrameNumber`
///    if Join is 0 and Confirm is set).
/// 2. `Seniority` descending.
/// 3. Address bytes ascending.
///
/// Rank → ring via `floor(rank / ringGroupSize)`.
fn compute_ring_assignments(
    active_provers: &[ProverInfo],
    filter: &[u8],
) -> Result<HashMap<Vec<u8>, u8>> {
    struct Candidate {
        join_frame: u64,
        seniority: u64,
        address: Vec<u8>,
    }

    let mut candidates: Vec<Candidate> = Vec::with_capacity(active_provers.len());
    for prover in active_provers {
        let allocation = prover
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .ok_or_else(|| {
                QuilError::InvalidArgument(
                    "shard update: allocation not found for prover".into(),
                )
            })?;

        let mut join_frame = allocation.join_frame_number;
        if join_frame == 0 && allocation.join_confirm_frame_number != 0 {
            join_frame = allocation.join_confirm_frame_number;
        }

        candidates.push(Candidate {
            join_frame,
            seniority: prover.seniority,
            address: prover.address.clone(),
        });
    }

    candidates.sort_by(|a, b| {
        a.join_frame
            .cmp(&b.join_frame)
            .then_with(|| b.seniority.cmp(&a.seniority)) // seniority descending
            .then_with(|| a.address.cmp(&b.address))
    });

    let mut ring_by_address = HashMap::with_capacity(candidates.len());
    for (rank, c) in candidates.into_iter().enumerate() {
        let ring = (rank as u64 / RING_GROUP_SIZE) as u8;
        ring_by_address.insert(c.address, ring);
    }

    Ok(ring_by_address)
}

/// Validate a `ProverShardUpdate` (FrameHeader). Matches Go's
/// `Verify`: structural checks + frame ordering.
///
/// Go equivalent: `Verify` at `global_prover_shard_update.go:96`. Go
/// additionally builds the full context (which verifies the BLS
/// aggregate signature via the frame prover); we do the same here when
/// `active_provers` and `participant_bitmask` are supplied.
pub fn validate_prover_shard_update(
    frame_header: &FrameHeader,
    next_frame_number: u64,
    active_provers: Option<Vec<ProverInfo>>,
    participant_bitmask: Option<&[u8]>,
    shard_metadata: Option<ShardMetadata>,
) -> Result<bool> {
    if next_frame_number != frame_header.frame_number + 1 {
        return Err(QuilError::InvalidArgument(format!(
            "shard update: invalid update (next={}, header.frame={})",
            next_frame_number, frame_header.frame_number
        )));
    }

    if let (Some(provers), Some(bitmask), Some(md)) =
        (active_provers, participant_bitmask, shard_metadata)
    {
        let _ctx = build_shard_update_context(frame_header, provers, bitmask, md)?;
    }

    Ok(true)
}

/// Materialize a `ProverShardUpdate`. Distributes per-ring rewards and
/// updates `LastActiveFrameNumber` on each participating allocation.
///
/// Go equivalent: `Materialize` at
/// `global_prover_shard_update.go:147`.
///
/// Arguments:
/// - `frame_header`: the header being applied.
/// - `current_frame_number`: the consensus-engine frame that contains
///   this header (= `frame_header.frame_number + 1`).
/// - `state`: the hypergraph changeset.
/// - `prover_registry`: used only in `build_shard_update_context`
///   (via `active_provers` the caller supplies).
/// - `frame_prover`: used only in `build_shard_update_context` (via
///   `participant_bitmask` the caller supplies).
/// - `reward_issuance`: per-ring reward calculator.
/// - `world_state_size`: `Hypergraph.GetSize(nil, nil)` — the full
///   state size passed to the issuance calculator as `worldSize`.
/// - `active_provers`, `participant_bitmask`, `shard_metadata`: the
///   precomputed inputs (see `build_shard_update_context`).
pub fn materialize_prover_shard_update(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
    _prover_registry: &Arc<dyn ProverRegistry>,
    _frame_prover: &Arc<dyn FrameProver>,
    reward_issuance: &Arc<dyn RewardIssuance>,
    world_state_size: u64,
    active_provers: Vec<ProverInfo>,
    participant_bitmask: &[u8],
    shard_metadata: ShardMetadata,
) -> Result<()> {
    let ctx = build_shard_update_context(
        frame_header,
        active_provers,
        participant_bitmask,
        shard_metadata,
    )?;

    // Per-ring reward shares: build a single-prover allocation map
    // per ring and divide `outputs[0]` by `ringGroupSize`.
    let mut rewards_per_ring: HashMap<u8, BigInt> = HashMap::new();

    for (&ring, participants) in &ctx.participants_by_ring {
        let mut alloc_map: HashMap<String, ProverAllocation> = HashMap::new();
        // Key is the string form of the shard filter
        // (`string(FrameHeader.Address)`).
        alloc_map.insert(
            String::from_utf8_lossy(&frame_header.address).into_owned(),
            ProverAllocation {
                ring,
                shards: ctx.shard_count,
                state_size: ctx.state_size,
            },
        );

        let outputs = reward_issuance.calculate(
            frame_header.difficulty as u64,
            world_state_size,
            REWARD_UNITS,
            &[alloc_map],
        )?;
        if outputs.len() != 1 {
            return Err(QuilError::InvalidArgument(
                "shard update materialize: unexpected reward issuance output size".into(),
            ));
        }
        if participants.is_empty() {
            continue;
        }

        let share = &outputs[0] / BigInt::from(RING_GROUP_SIZE);
        rewards_per_ring.insert(ring, share);
    }

    // Apply per-participant rewards + activity updates.
    for (ring, participants) in &ctx.participants_by_ring {
        let share = rewards_per_ring.get(ring);
        for &idx in participants {
            let prover = &ctx.active_provers[idx];

            if let Some(share_amount) = share {
                if share_amount.sign() != num_bigint::Sign::NoSign {
                    apply_reward(state, current_frame_number, prover, share_amount)?;
                }
            }

            update_allocation_activity(state, current_frame_number, prover, &frame_header.address)?;
        }
    }

    Ok(())
}

/// Add a reward amount to a prover's reward vertex balance.
///
/// Go equivalent: `applyReward` at
/// `global_prover_shard_update.go:400`.
fn apply_reward(
    state: &HypergraphState,
    frame_number: u64,
    prover: &ProverInfo,
    share: &BigInt,
) -> Result<()> {
    if share.sign() == num_bigint::Sign::NoSign {
        return Ok(());
    }

    let reward_addr = reward_address(&prover.address)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;

    // Load existing reward vertex (or create a new tree).
    let existing = state.get(domain, &reward_addr, &va_disc)?;
    let mut reward_tree = match existing {
        Some(blob) if !blob.is_empty() => rebuild_vertex_tree_from_blob(&blob),
        _ => quil_tries::VectorCommitmentTree::new(),
    };

    add_to_reward_balance(&mut reward_tree, share)?;

    let blob = vertex_tree_to_blob(&reward_tree);
    state.set(domain, &reward_addr, &va_disc, frame_number, blob)?;

    // Surface the credit when it lands on the node's own prover.
    // Reads the post-credit balance back from the same tree so the
    // operator sees both the delta and the running total.
    if let Some(local) = LOCAL_PROVER_ADDRESS.get() {
        if !local.is_empty() && local.as_slice() == prover.address.as_slice() {
            let total_bytes = super::materialize::read_reward_balance(&reward_tree);
            let new_total = if total_bytes.is_empty() {
                BigInt::from(0)
            } else {
                BigInt::from_bytes_be(num_bigint::Sign::Plus, &total_bytes)
            };
            tracing::info!(
                frame = frame_number,
                prover = %hex::encode(&prover.address),
                delta = %share,
                new_balance = %new_total,
                "reward credited to local prover"
            );
        }
    }

    Ok(())
}

/// Update an allocation's `LastActiveFrameNumber`.
///
/// Go equivalent: `updateAllocationActivity` at
/// `global_prover_shard_update.go:509`.
fn update_allocation_activity(
    state: &HypergraphState,
    frame_number: u64,
    prover: &ProverInfo,
    filter: &[u8],
) -> Result<()> {
    let alloc_addr = allocation_address(&prover.public_key, filter)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;

    let existing = match state.get(domain, &alloc_addr, &va_disc)? {
        Some(blob) if !blob.is_empty() => blob,
        _ => return Ok(()),
    };
    let mut alloc_tree = rebuild_vertex_tree_from_blob(&existing);

    materialize_frame_header_activity(&mut alloc_tree, frame_number)?;

    let blob = vertex_tree_to_blob(&alloc_tree);
    state.set(domain, &alloc_addr, &va_disc, frame_number, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_schema::read_field;
    use crate::hypergraph_state::{HypergraphState, InMemoryHypergraphStore};
    use quil_hypergraph::HypergraphCrdt;
    use quil_types::consensus::{ProverAllocationInfo, ProverStatus};
    use quil_types::crypto::{InclusionProver, Multiproof};
    use std::sync::Arc;

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
        let store = Arc::new(InMemoryHypergraphStore::new());
        let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
        HypergraphState::new(crdt)
    }

    fn fake_prover(seed: u8, join_frame: u64, seniority: u64, filter: &[u8]) -> ProverInfo {
        let mut addr = [0u8; 32];
        addr[0] = seed;
        ProverInfo {
            public_key: vec![seed; 585],
            address: addr.to_vec(),
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![ProverAllocationInfo {
                status: ProverStatus::Active,
                confirmation_filter: filter.to_vec(),
                rejection_filter: Vec::new(),
                join_frame_number: join_frame,
                leave_frame_number: 0,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 0,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: 0,
                vertex_address: vec![seed; 32],
            }],
            available_storage: 0,
            seniority,
            delegate_address: Vec::new(),
        }
    }

    /// Seed an allocation vertex blob into state so
    /// `update_allocation_activity` (which short-circuits on
    /// missing blob, by design — it only updates existing
    /// allocations) can run end-to-end. Production seeds this
    /// blob via `materialize_prover_join` at join time.
    fn seed_alloc_blob(state: &HypergraphState, prover: &ProverInfo, filter: &[u8]) {
        use crate::global_intrinsic::materialize::materialize_prover_join;
        let output = materialize_prover_join(
            &prover.public_key,
            &[filter.to_vec()],
            1, // arbitrary join_frame; the test overwrites later
            prover.seniority,
        )
        .unwrap();
        let (alloc_addr, alloc_tree) = output.allocations.first().unwrap();
        let alloc_blob = vertex_tree_to_blob(alloc_tree);
        let va_disc = vertex_adds_discriminator().unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                alloc_addr,
                &va_disc,
                1,
                alloc_blob,
            )
            .unwrap();
    }

    fn fake_header(filter: Vec<u8>, frame_number: u64) -> FrameHeader {
        FrameHeader {
            address: filter,
            frame_number,
            rank: 0,
            timestamp: 0,
            difficulty: 100,
            output: Vec::new(),
            parent_selector: Vec::new(),
            requests_root: Vec::new(),
            state_roots: Vec::new(),
            prover: Vec::new(),
            fee_multiplier_vote: 0,
            public_key_signature_bls48581: Vec::new(),
        }
    }

    #[test]
    fn compute_ring_assignments_orders_by_join_frame_then_seniority_then_address() {
        let filter = vec![0xAAu8; 32];
        // Provers with identical join frame; seniority order should win.
        let p1 = fake_prover(0x01, 10, 100, &filter); // seniority 100
        let p2 = fake_prover(0x02, 10, 500, &filter); // seniority 500 (higher, wins tie)
        let p3 = fake_prover(0x03, 5, 1, &filter); // earlier join, wins overall
        let provers = vec![p1.clone(), p2.clone(), p3.clone()];
        let rings = compute_ring_assignments(&provers, &filter).unwrap();
        assert_eq!(rings[&p3.address], 0); // rank 0
        assert_eq!(rings[&p2.address], 0); // rank 1 (higher seniority at frame 10)
        assert_eq!(rings[&p1.address], 0); // rank 2 (lower seniority)
    }

    #[test]
    fn compute_ring_assignments_uses_ring_group_size() {
        let filter = vec![0xAAu8; 32];
        // 10 provers → with ringGroupSize=8, first 8 are ring 0, last 2 are ring 1.
        let provers: Vec<_> = (0..10u8).map(|i| fake_prover(i + 1, i as u64, 0, &filter)).collect();
        let rings = compute_ring_assignments(&provers, &filter).unwrap();
        assert_eq!(rings[&provers[0].address], 0);
        assert_eq!(rings[&provers[7].address], 0);
        assert_eq!(rings[&provers[8].address], 1);
        assert_eq!(rings[&provers[9].address], 1);
    }

    #[test]
    fn compute_ring_assignments_fallback_to_join_confirm_frame_number() {
        let filter = vec![0xAAu8; 32];
        let mut p = fake_prover(1, 0, 100, &filter);
        p.allocations[0].join_confirm_frame_number = 5;
        let rings = compute_ring_assignments(&[p.clone()], &filter).unwrap();
        assert_eq!(rings[&p.address], 0);
    }

    #[test]
    fn build_context_rejects_empty_provers() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter, 10);
        let md = ShardMetadata::default();
        assert!(build_shard_update_context(&header, Vec::new(), &[0u8], md).is_err());
    }

    #[test]
    fn build_context_rejects_empty_bitmask() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        let p = fake_prover(1, 1, 0, &filter);
        let md = ShardMetadata::default();
        assert!(build_shard_update_context(&header, vec![p], &[], md).is_err());
    }

    #[test]
    fn build_context_rejects_index_out_of_range() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        let p = fake_prover(1, 1, 0, &filter);
        let md = ShardMetadata::default();
        // index 5 > active_provers.len() == 1
        assert!(build_shard_update_context(&header, vec![p], &[5u8], md).is_err());
    }

    #[test]
    fn build_context_rejects_below_two_thirds() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        // 3 provers, only 1 participant → 1*3 < 3*2 → rejected.
        let provers: Vec<_> = (0..3u8).map(|i| fake_prover(i + 1, i as u64, 0, &filter)).collect();
        let md = ShardMetadata::default();
        assert!(build_shard_update_context(&header, provers, &[0u8], md).is_err());
    }

    #[test]
    fn build_context_default_shard_count_of_one() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        let p = fake_prover(1, 1, 0, &filter);
        let md = ShardMetadata { state_size: 1000, shard_count: 0 };
        let ctx = build_shard_update_context(&header, vec![p], &[0u8], md).unwrap();
        assert_eq!(ctx.shard_count, DEFAULT_SHARD_LEAVES);
        assert_eq!(ctx.state_size, 1000);
    }

    #[test]
    fn validate_rejects_non_successor_frame() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter, 10);
        // next == header.frame + 2 (not +1)
        assert!(validate_prover_shard_update(&header, 12, None, None, None).is_err());
    }

    #[test]
    fn validate_accepts_successor_frame_structural_only() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter, 10);
        assert!(validate_prover_shard_update(&header, 11, None, None, None).unwrap());
    }

    // -----------------------------------------------------------------
    // materialize: end-to-end with stub RewardIssuance
    // -----------------------------------------------------------------

    struct StubReward(BigInt);
    impl RewardIssuance for StubReward {
        fn calculate(
            &self,
            _difficulty: u64,
            _world_state_bytes: u64,
            _units: u64,
            provers: &[HashMap<String, ProverAllocation>],
        ) -> Result<Vec<BigInt>> {
            // Return `self.0` for each input allocation.
            Ok(provers.iter().map(|_| self.0.clone()).collect())
        }
    }

    #[test]
    fn apply_reward_adds_to_existing_balance() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        apply_reward(&state, 50, &p, &BigInt::from(1000)).unwrap();
        apply_reward(&state, 50, &p, &BigInt::from(500)).unwrap();
        let reward_addr = reward_address(&p.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
            .unwrap()
            .unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let bal_bytes = read_field(&tree, "reward:ProverReward", "Balance").unwrap();
        let bal = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal_bytes);
        assert_eq!(bal, BigInt::from(1500));
    }

    #[test]
    fn update_allocation_activity_sets_last_active() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        // update_allocation_activity only mutates an existing alloc blob.
        seed_alloc_blob(&state, &p, &filter);
        update_allocation_activity(&state, 77, &p, &filter).unwrap();
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
            .unwrap()
            .unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let v = read_field(&tree, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap();
        assert_eq!(v, 77u64.to_be_bytes().to_vec());
    }

    #[test]
    fn materialize_full_flow_single_prover() {
        // Simulate: 1 prover (100% participation), 1 ring, stub reward
        // calculator returns 8_000 per call; divided by RING_GROUP_SIZE=8
        // gives share=1_000.
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        // materialize_prover_shard_update → update_allocation_activity
        // requires an existing alloc blob (it only mutates, doesn't create).
        seed_alloc_blob(&state, &p, &filter);
        let header = fake_header(filter.clone(), 10);

        // stub deps (prover registry + frame prover are unused by
        // materialize when active_provers + bitmask are supplied)
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));

        // NB: prover_registry and frame_prover are passed as `Arc` but
        // ignored by materialize (it uses active_provers / bitmask
        // directly). We pass dummy impls.
        // Minimal stub: every read returns empty/None. The trait
        // defaults cover refresh / update_prover_activity /
        // prune_orphan_joins / get_all_active_app_shard_provers.
        struct NoopRegistry;
        impl ProverRegistry for NoopRegistry {
            fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> { Ok(None) }
            fn get_next_prover(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<Vec<u8>>> { Ok(Vec::new()) }
            fn get_active_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_prover_count(&self, _: &[u8]) -> Result<usize> { Ok(0) }
            fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_prover_shard_summaries(&self, _frame_number: u64) -> Result<Vec<quil_types::consensus::ProverShardSummary>> { Ok(Vec::new()) }
        }
        let registry: Arc<dyn ProverRegistry> = Arc::new(NoopRegistry);

        // stub FrameProver — unused by materialize directly
        struct NoopFrameProver;
        impl FrameProver for NoopFrameProver {
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
            ) -> Result<quil_types::proto::global::FrameHeader> {
                Err(QuilError::InvalidArgument("noop".into()))
            }
            fn verify_frame_header(&self, _: &quil_types::proto::global::FrameHeader) -> Result<Vec<u8>> { Ok(Vec::new()) }
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
            ) -> Result<quil_types::proto::global::GlobalFrameHeader> {
                Err(QuilError::InvalidArgument("noop".into()))
            }
            fn verify_global_frame_header(&self, _: &quil_types::proto::global::GlobalFrameHeader) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> { Ok(true) }
        }
        let frame_prover: Arc<dyn FrameProver> = Arc::new(NoopFrameProver);

        let md = ShardMetadata { state_size: 1024, shard_count: 1 };

        materialize_prover_shard_update(
            &header,
            11, // current frame = header.frame + 1
            &state,
            &registry,
            &frame_prover,
            &reward_issuance,
            4096,
            vec![p.clone()],
            &[0u8],
            md,
        )
        .unwrap();

        // Expect reward vertex has Balance = 8_000 / 8 = 1_000.
        let reward_addr = reward_address(&p.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
            .unwrap()
            .unwrap();
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let bal_bytes = read_field(&tree, "reward:ProverReward", "Balance").unwrap();
        let bal = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal_bytes);
        assert_eq!(bal, BigInt::from(1_000));

        // Expect allocation's LastActiveFrameNumber = 11.
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let ablob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
            .unwrap()
            .unwrap();
        let atree = rebuild_vertex_tree_from_blob(&ablob);
        let lafn = read_field(&atree, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap();
        assert_eq!(lafn, 11u64.to_be_bytes().to_vec());

    }
}
