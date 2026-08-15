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
    add_to_reward_balance, allocation_address, materialize_frame_header_activity,
    prover_address_from_pubkey, reward_address, DEFAULT_SHARD_LEAVES, REWARD_UNITS, RING_GROUP_SIZE,
};
use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
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
    pub state_size: u64,
    pub shard_count: u64,
}

/// Recompute a genesis / no-global-anchor app-shard frame's output and require
/// it to match the header.
///
/// App-shard frames carry NO VDF: the producer (`AppLeaderProvider`) stamps
/// `porep::deterministic_app_frame_output` on every frame it makes. A frame
/// anchored to a real global frame binds ρ_N to that anchor; a genesis /
/// pre-global-chain frame (`global_frame_number == 0`) uses the ZERO-ANCHOR
/// beacon, since there is no global VDF output to bind freshness to. This is the
/// same check `quil_engine::frame_validator::BlsAppFrameValidator` runs on the
/// no-anchor branch — it replaces the legacy Wesolowski verify, which can no
/// longer succeed now that nothing solves a VDF for an app frame.
fn verify_genesis_app_frame_output(frame_header: &FrameHeader) -> Result<()> {
    let rho_n = quil_crypto::porep::derive_storage_beacon(0, &[]);
    let expected = quil_crypto::porep::deterministic_app_frame_output(
        &frame_header.parent_selector,
        &frame_header.requests_root,
        &frame_header.state_roots,
        &rho_n,
        frame_header.frame_number,
        frame_header.rank,
        &frame_header.prover,
        frame_header.difficulty,
        frame_header.fee_multiplier_vote as u64,
        frame_header.timestamp,
        &frame_header.storage_attestation_root,
    );
    if expected != frame_header.output {
        return Err(QuilError::Crypto(
            "frame header attestation: genesis app-shard frame output does not match \
             the deterministic digest"
                .into(),
        ));
    }
    Ok(())
}

/// Verify a finalized shard FrameHeader's three-layer attestation:
/// leader proof-of-frame (deterministic output digest), aggregate BLS over
/// `make_vote_message(address, rank, poseidon(output))`, and per-participant
/// VDF multi-proofs over `sha3(parent_selector)`. Returns the participant
/// bitmask.
///
/// `active_provers` must be in the same order the consensus committee
/// used at this rank — the bitmask indexes into this list.
pub fn verify_frame_header_attestation(
    frame_header: &FrameHeader,
    frame_prover: &dyn quil_types::crypto::FrameProver,
    bls: &dyn quil_types::crypto::BlsConstructor,
    active_provers: &[ProverInfo],
) -> Result<Vec<u8>> {
    // CW path: a commonware-simplex-finalized shard frame carries no
    // BLS aggregate — its `public_key_signature_bls48581` field holds the
    // magic-prefixed simplex FINALIZATION certificate instead. Verify it against
    // the shard committee (the active provers' Falcon keys) + the frame's VDF,
    // and read the participant set (signers) off the cert.
    if let Some(cert_bytes) =
        quil_cw_consensus::app_cert::unwrap_cert_from_header(&frame_header.public_key_signature_bls48581)
    {
        // Output integrity. A frame anchored to a real global frame
        // (`global_frame_number > 0`) is a storage frame whose `output` is the
        // deterministic ρ_N-bound value (`deterministic_app_frame_output`); its
        // integrity comes from the CW finalization cert (which signs
        // `poseidon(output)`, verified below against the committee) plus the ρ_N
        // storage-attestation audit (`audit_storage_attestation`) the caller runs
        // after this. A genesis/no-chain frame (== 0) has no anchor to audit
        // against, so recompute its zero-anchor digest here (mirroring
        // `frame_validator.rs`).
        if frame_header.global_frame_number == 0 {
            verify_genesis_app_frame_output(frame_header)?;
        }

        // Verify the finalization cert against the shard committee. Namespace =
        // b"appshard" ++ app_address; the app address is the header address.
        let mut namespace = b"appshard".to_vec();
        namespace.extend_from_slice(&frame_header.address);
        let committee_pubkeys: Vec<Vec<u8>> =
            active_provers.iter().map(|p| p.public_key.clone()).collect();
        let output_digest = quil_crypto::poseidon::hash_bytes_to_32(&frame_header.output)
            .map_err(|e| QuilError::Crypto(format!("cw cert: poseidon(output): {e}")))?;
        let signer_pubkeys = quil_cw_consensus::app_cert::verify_finalization(
            cert_bytes,
            &committee_pubkeys,
            &namespace,
            output_digest,
        )
        .ok_or_else(|| {
            QuilError::InvalidSignature(
                "frame header attestation: CW finalization cert invalid / below quorum".into(),
            )
        })?;

        // Build the participant bitmask: index of each signer in the active set.
        let mut bitmask: Vec<u8> = Vec::new();
        for pk in &signer_pubkeys {
            if let Some(idx) = active_provers.iter().position(|p| &p.public_key == pk) {
                quil_consensus::bitmask::set_bit(&mut bitmask, idx);
            }
        }
        return Ok(bitmask);
    }

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
        storage_attestation_root: frame_header.storage_attestation_root.clone(),
        global_frame_number: frame_header.global_frame_number,
        storage_attestation: frame_header.storage_attestation.clone(),
    };

    // Same gate as the CW path above: a storage frame (`global_frame_number > 0`)
    // has its output covered by the attestation audit, while a genesis/no-anchor
    // frame (== 0) is checked here against its deterministic zero-anchor digest.
    if frame_header.global_frame_number == 0 {
        verify_genesis_app_frame_output(frame_header)?;
    }

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
    // Pass the FULL active committee — the deterministic universe the
    // multiproof's challenge prime `b` is bound to. `verify_frame_header_signature`
    // re-derives the PRESENT signer subset from the header bitmask and verifies
    // only their proofs against the committee-bound `b`. Requiring full
    // attendance was the bug: a BFT committee can't know who is absent until
    // the vote threshold is in. (`participant_ids` above already bounds-checked
    // every bitmask index against the committee.) See
    // `vdf::wesolowski_verify_multi_sparse`.
    let committee_refs: Vec<&[u8]> =
        active_provers.iter().map(|p| p.address.as_slice()).collect();
    // 666-byte signature = single signer, no multi-proofs to verify.
    let ids_arg: Option<&[&[u8]]> = if agg.signature.len() == 666 {
        if participant_ids.len() != 1 {
            return Err(QuilError::InvalidSignature(
                "frame header attestation: 666-byte signature requires exactly 1 participant".into(),
            ));
        }
        None
    } else {
        Some(&committee_refs)
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

    // Group participants by their LOCKED ring — the value STORED on each
    // allocation at confirmation (and only recomputed on a membership change).
    // We deliberately do NOT re-sort by live seniority here: that read the
    // node-local, async-refreshed prover cache, whose per-frame-changing
    // seniority made the sort node-dependent and forked the prover-tree root.
    // The stored ring is committed state, identical on every node → deterministic.
    let mut participants_by_ring: HashMap<u8, Vec<usize>> = HashMap::new();
    for &idx in &participant_indices {
        let prover = &active_provers[idx];
        let ring = prover
            .allocations
            .iter()
            .find(|a| a.confirmation_filter == frame_header.address)
            .map(|a| a.ring)
            .ok_or_else(|| {
                QuilError::InvalidArgument(
                    "shard update: missing allocation/ring for participant".into(),
                )
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
/// if Join is 0 and Confirm is set).
/// 2. `Seniority` descending.
/// 3. Address bytes ascending.
///
/// Rank → ring via `floor(rank / ringGroupSize)`.
// Ported ahead of the ring-assignment rollout; the shard-update path still
// takes ring numbers off the wire.
#[allow(dead_code)]
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
/// this header (= `frame_header.frame_number + 1`).
/// - `state`: the hypergraph changeset.
/// - `prover_registry`: used only in `build_shard_update_context`
/// (via `active_provers` the caller supplies).
/// - `frame_prover`: used only in `build_shard_update_context` (via
/// `participant_bitmask` the caller supplies).
/// - `reward_issuance`: per-ring reward calculator.
/// - `world_state_size`: `Hypergraph.GetSize(nil, nil)` — the full
/// state size passed to the issuance calculator as `worldSize`.
/// - `active_provers`, `participant_bitmask`, `shard_metadata`: the
/// precomputed inputs (see `build_shard_update_context`).
/// Recompute + persist the shard's per-allocation reward ring from the current
/// active committee, using a STABLE ordering: `JoinFrameNumber` ascending, then
/// address ascending — both IMMUTABLE committed fields. Rank → `ring =
/// floor(rank / RING_GROUP_SIZE)`.
///
/// Because the ordering keys never change for a given prover, the assignment is
/// byte-identical on every node and shifts ONLY when the active SET changes.
/// Membership changes (join-confirm, leave-confirm, kick) are epoch-aligned
/// (they take effect at the E+2 boundary via `effective_status`), so the ring is
/// effectively frozen within an epoch and RECOMPACTED at a boundary — e.g. a
/// ring-0 prover leaving shifts every survivor below it up one rank. This is the
/// behaviour the `Ring` schema field documents, and deliberately does NOT sort
/// by live seniority (whose per-frame drift is what forked the prover-tree root
/// before the ring was stored).
///
/// The active SET is the caller's `active_provers` — the SAME
/// `get_active_provers` result the frame-header attestation already trusts as
/// consistent-with-committed across nodes, so it cannot fork. In-memory rings
/// are patched so THIS frame's distribution uses the fresh values, and changed
/// rings are written back to committed state (unchanged ones are skipped, so
/// there is no version churn within an epoch).
fn recompute_shard_rings(
    state: &HypergraphState,
    filter: &[u8],
    active_provers: &mut [ProverInfo],
    frame_number: u64,
) -> Result<()> {
    if active_provers.is_empty() {
        return Ok(());
    }
    let join_frame = |p: &ProverInfo| -> u64 {
        p.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.join_frame_number)
            .unwrap_or(0)
    };
    let mut order: Vec<usize> = (0..active_provers.len()).collect();
    order.sort_by(|&i, &j| {
        join_frame(&active_provers[i])
            .cmp(&join_frame(&active_provers[j]))
            .then_with(|| active_provers[i].address.cmp(&active_provers[j].address))
    });

    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    for (rank, &idx) in order.iter().enumerate() {
        let ring = (rank as u64 / RING_GROUP_SIZE) as u8;
        let pubkey = active_provers[idx].public_key.clone();
        let Some(alloc) = active_provers[idx]
            .allocations
            .iter_mut()
            .find(|a| a.confirmation_filter == filter)
        else {
            continue;
        };
        // Stable within the epoch: the set (hence the rank) is unchanged, so the
        // cached ring already matches — nothing to write.
        if alloc.ring == ring {
            continue;
        }
        alloc.ring = ring; // fresh value for this frame's reward distribution
        let alloc_addr = allocation_address(&pubkey, filter)?;
        if let Some(blob) = state.get(domain, &alloc_addr, &va_disc)? {
            let mut tree = rebuild_vertex_tree_from_blob(&blob);
            write_field(&mut tree, "allocation:ProverAllocation", "Ring", &[ring])?;
            state.set(domain, &alloc_addr, &va_disc, frame_number, vertex_tree_to_blob(&tree))?;
        }
    }
    Ok(())
}

pub fn materialize_prover_shard_update(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
    _prover_registry: &Arc<dyn ProverRegistry>,
    _frame_prover: &Arc<dyn FrameProver>,
    reward_issuance: &Arc<dyn RewardIssuance>,
    world_state_size: u64,
    mut active_provers: Vec<ProverInfo>,
    participant_bitmask: &[u8],
    shard_metadata: ShardMetadata,
) -> Result<()> {
    // Epoch-aligned ring (re)assignment: recompute from the current active
    // committee before rewards are distributed, recompacting on any membership
    // change and persisting the result. See `recompute_shard_rings`.
    recompute_shard_rings(
        state,
        &frame_header.address,
        &mut active_provers,
        current_frame_number,
    )?;

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
    let mut credited_provers = 0usize;
    let mut total_reward = BigInt::from(0);
    for (ring, participants) in &ctx.participants_by_ring {
        let share = rewards_per_ring.get(ring);
        for &idx in participants {
            let prover = &ctx.active_provers[idx];

            if let Some(share_amount) = share {
                if share_amount.sign() != num_bigint::Sign::NoSign
                    && apply_reward(
                        state,
                        current_frame_number,
                        prover,
                        &frame_header.address,
                        share_amount,
                    )?
                {
                    credited_provers += 1;
                    total_reward += share_amount;
                }
            }

            update_allocation_activity(state, current_frame_number, prover, &frame_header.address)?;
        }
    }

    // Per-shard-frame reward-accrual signal. Unlike the worker-side "reward
    // balance updated by sync" (which only fires on an occasional prover-tree
    // sync that happens to change the balance — sparse + lumpy, a poor proxy for
    // whether a shard is actually earning), this logs on EVERY reward
    // distribution, deterministically, from the committed count of provers
    // credited + the total issued for this shard frame. A zero-credit frame is
    // logged too (participants present but nothing credited ⇒ withheld basis /
    // idempotent re-materialize / non-Active committee), so a reward STALL is
    // visible per frame instead of silent. `participants` is the committee size
    // that was eligible, so `credited < participants` flags a partial payout.
    let participants: usize = ctx.participants_by_ring.values().map(|p| p.len()).sum();
    tracing::info!(
        shard = %hex::encode(&frame_header.address[..frame_header.address.len().min(8)]),
        frame = current_frame_number,
        credited_provers,
        participants,
        total_reward = %total_reward,
        "shard reward distribution",
    );

    Ok(())
}

/// Add a reward amount to a prover's reward vertex balance.
///
/// Go equivalent: `applyReward` at
/// `global_prover_shard_update.go:400`.
/// Returns `true` if the balance was actually credited, `false` if the credit
/// was a no-op (zero share, or the idempotency guard already credited this
/// (frame, shard)). Callers use this for an accurate per-frame reward-accrual
/// count. `filter` is the shard's confirmation filter (`FrameHeader.address`).
fn apply_reward(
    state: &HypergraphState,
    frame_number: u64,
    prover: &ProverInfo,
    filter: &[u8],
    share: &BigInt,
) -> Result<bool> {
    if share.sign() == num_bigint::Sign::NoSign {
        return Ok(false);
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

    // Idempotency guard. Reward crediting is ADDITIVE and NOT nonce-protected
    // like token spends, and the global frame is applied by TWO paths on an
    // archive — the serial materializer AND the archive poller's
    // `process_global_frame`. Without a guard the balance is credited once per
    // path (and again on any re-materialize), and because the paths commit at
    // different times the prover-tree root as-of-frame-N depends on interleaving
    // → a timing-dependent fork. Presence-checked: a fresh reward vertex has no
    // `LastRewardFrameNumber`, so it is creditable at any frame (incl. 0).
    // (frame, SHARD)-keyed idempotency guard (Go parity: Go's `applyReward` takes
    // the shard filter and has no frame guard). A prover allocated to more than
    // one shard accrues EACH shard's reward at the same global frame; the
    // archive's SECOND materialization of the same (frame, shard) still skips.
    // `RewardedShardsBlob` holds the filters already credited at
    // `LastRewardFrameNumber`, reset when the frame advances.
    let cls = "reward:ProverReward";
    let last_reward_frame = read_field(&reward_tree, cls, "LastRewardFrameNumber")
        .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()).map(u64::from_be_bytes));
    match last_reward_frame {
        // Strictly older frame re-materialized — already fully credited.
        Some(last) if frame_number < last => return Ok(false),
        // Same frame — credit only shards not yet credited this frame.
        Some(last) if frame_number == last => {
            let mut shards = decode_rewarded_shards(&reward_tree, cls);
            if shards.iter().any(|s| s.as_slice() == filter) {
                return Ok(false);
            }
            add_to_reward_balance(&mut reward_tree, share)?;
            shards.push(filter.to_vec());
            shards.sort();
            encode_rewarded_shards(&mut reward_tree, cls, &shards)?;
            // LastRewardFrameNumber is already == frame_number; leave it.
        }
        // New (higher) frame, or a fresh vertex — credit and reset the set.
        _ => {
            add_to_reward_balance(&mut reward_tree, share)?;
            write_field(&mut reward_tree, cls, "LastRewardFrameNumber", &frame_number.to_be_bytes())?;
            encode_rewarded_shards(&mut reward_tree, cls, &[filter.to_vec()])?;
        }
    }

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

    Ok(true)
}

/// Decode the `RewardedShardsBlob` field → the shard filters already credited at
/// `LastRewardFrameNumber`. Format: repeated `u16 BE len ‖ filter`, sorted.
/// Absent field or a malformed tail yields the (partial) set parsed so far.
fn decode_rewarded_shards(
    tree: &quil_tries::VectorCommitmentTree,
    cls: &str,
) -> Vec<Vec<u8>> {
    let Some(blob) = read_field(tree, cls, "RewardedShardsBlob") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= blob.len() {
        let len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
        i += 2;
        if i + len > blob.len() {
            break; // malformed tail — stop
        }
        out.push(blob[i..i + len].to_vec());
        i += len;
    }
    out
}

/// Encode a SORTED shard-filter set into the `RewardedShardsBlob` field
/// (`u16 BE len ‖ filter` each). Caller sorts for a deterministic commitment.
fn encode_rewarded_shards(
    tree: &mut quil_tries::VectorCommitmentTree,
    cls: &str,
    shards: &[Vec<u8>],
) -> Result<()> {
    let mut blob = Vec::new();
    for s in shards {
        blob.extend_from_slice(&(s.len() as u16).to_be_bytes());
        blob.extend_from_slice(s);
    }
    write_field(tree, cls, "RewardedShardsBlob", &blob)
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
    state.set(domain, &alloc_addr, &va_disc, frame_number, blob)?;

    // Accrue seniority for this active frame. Called for every participating
    // prover in every ring each frame (right beside `apply_reward`), so an
    // active prover gains `SENIORITY_PER_ACTIVE_FRAME` for every frame it is
    // active. Idempotent per prover per frame (see `accrue_active_seniority`),
    // so a multi-shard prover (one call per allocation) or a re-materialized
    // frame accrues at most once.
    accrue_active_seniority(state, &prover.public_key, frame_number)?;

    Ok(())
}

/// Seniority a prover accrues for each frame it is active.
pub const SENIORITY_PER_ACTIVE_FRAME: u64 = 10;

/// Add `SENIORITY_PER_ACTIVE_FRAME` to a prover's `Seniority` for the current
/// active frame, keyed for idempotency on a `LastSeniorityFrameNumber` field of
/// the prover vertex.
///
/// Seniority is CONSENSUS state (it feeds the `Σseniority·2/3` voting threshold
/// and the committed prover-tree root), so this mutation must be deterministic
/// and applied identically on every node. It is:
///   * per-prover / per-frame idempotent — `frame_number <= last` short-circuits,
///     so multiple allocations of the same prover in one frame, and any
///     re-materialization of a frame, accrue at most once;
///   * gap-safe — a FIXED grant (not `10 * elapsed`), and it only fires on
///     frames the prover is actually active (a participant in a shard update),
///     so inactive frames contribute nothing;
///   * monotonic — an out-of-order replay of an older frame is skipped.
///
/// FLAG-DAY: this changes the prover-tree state root over time (and adds the
/// `LastSeniorityFrameNumber` field), so all nodes must run it together.
fn accrue_active_seniority(
    state: &HypergraphState,
    public_key: &[u8],
    frame_number: u64,
) -> Result<()> {
    let prover_addr = prover_address_from_pubkey(public_key)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;

    // Only accrue for a prover that actually has a vertex (has joined).
    let existing = match state.get(domain, &prover_addr, &va_disc)? {
        Some(blob) if !blob.is_empty() => blob,
        _ => return Ok(()),
    };
    let mut prover_tree = rebuild_vertex_tree_from_blob(&existing);
    let cls = "prover:Prover";

    let last = read_prover_u64(&prover_tree, cls, "LastSeniorityFrameNumber");
    if frame_number <= last {
        return Ok(()); // already accrued for this frame (idempotent)
    }

    let seniority = read_prover_u64(&prover_tree, cls, "Seniority");
    let new_seniority = seniority.saturating_add(SENIORITY_PER_ACTIVE_FRAME);
    write_field(&mut prover_tree, cls, "Seniority", &new_seniority.to_be_bytes())?;
    write_field(
        &mut prover_tree,
        cls,
        "LastSeniorityFrameNumber",
        &frame_number.to_be_bytes(),
    )?;

    let blob = vertex_tree_to_blob(&prover_tree);
    state.set(domain, &prover_addr, &va_disc, frame_number, blob)
}

/// Read an 8-byte big-endian u64 field from a vertex tree, defaulting to 0.
fn read_prover_u64(tree: &quil_tries::VectorCommitmentTree, cls: &str, name: &str) -> u64 {
    read_field(tree, cls, name)
        .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()))
        .map(u64::from_be_bytes)
        .unwrap_or(0)
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
                epoch: 0,
                ring: 0,
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
            storage_attestation_root: Vec::new(),
            global_frame_number: 0,
            storage_attestation: Vec::new(),
        }
    }

    #[test]
    fn accrue_active_seniority_is_fixed_10_per_frame_idempotent_and_monotonic() {
        use crate::global_intrinsic::materialize::materialize_prover_join;
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let prover = fake_prover(0x07, 1, 0, &filter); // initial seniority 0

        // Seed the PROVER vertex (materialize_prover_join writes prover:Prover
        // with the given seniority).
        let output = materialize_prover_join(&prover.public_key, &[filter.clone()], 1, 0).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &output.prover_address,
                &va_disc,
                1,
                vertex_tree_to_blob(&output.prover_tree),
            )
            .unwrap();

        let read = |field: &str| -> u64 {
            let blob = state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &output.prover_address, &va_disc)
                .unwrap()
                .unwrap();
            read_prover_u64(&rebuild_vertex_tree_from_blob(&blob), "prover:Prover", field)
        };

        // First active frame → +10.
        accrue_active_seniority(&state, &prover.public_key, 100).unwrap();
        assert_eq!(read("Seniority"), 10);
        assert_eq!(read("LastSeniorityFrameNumber"), 100);

        // Same frame again (multi-shard prover / re-materialization) → idempotent.
        accrue_active_seniority(&state, &prover.public_key, 100).unwrap();
        assert_eq!(read("Seniority"), 10, "same-frame re-accrual must be a no-op");

        // Next active frame → +10 more.
        accrue_active_seniority(&state, &prover.public_key, 101).unwrap();
        assert_eq!(read("Seniority"), 20);
        assert_eq!(read("LastSeniorityFrameNumber"), 101);

        // Out-of-order replay of an OLDER frame → monotonic skip.
        accrue_active_seniority(&state, &prover.public_key, 50).unwrap();
        assert_eq!(read("Seniority"), 20, "older-frame replay must not accrue");
        assert_eq!(read("LastSeniorityFrameNumber"), 101);

        // A prover with no vertex (never joined) is a silent no-op.
        accrue_active_seniority(&state, &vec![0xEEu8; 585], 100).unwrap();
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
        let reward_addr = reward_address(&p.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let read_bal = || {
            let blob = state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
                .unwrap()
                .unwrap();
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let bal_bytes = read_field(&tree, "reward:ProverReward", "Balance").unwrap();
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal_bytes)
        };

        // Legacy path (frames < the fork frame). Credits accumulate ACROSS frames.
        let shard = [0xAAu8; 32];
        apply_reward(&state, 50, &p, &shard, &BigInt::from(1000)).unwrap();
        apply_reward(&state, 51, &p, &shard, &BigInt::from(500)).unwrap();
        assert_eq!(read_bal(), BigInt::from(1500));

        // Per-frame IDEMPOTENT: a second credit at an already-credited frame
        // (the double-processing case: materializer + archive poller) is a no-op.
        apply_reward(&state, 51, &p, &shard, &BigInt::from(999)).unwrap();
        assert_eq!(read_bal(), BigInt::from(1500), "reward must not double-credit a frame");
    }

    #[test]
    fn multi_shard_reward_per_frame_shard_guard() {
        let read_bal = |state: &HypergraphState, p: &ProverInfo| -> BigInt {
            let reward_addr = reward_address(&p.address).unwrap();
            let va_disc = vertex_adds_discriminator().unwrap();
            let blob = state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
                .unwrap()
                .unwrap();
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let bal = read_field(&tree, "reward:ProverReward", "Balance").unwrap();
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bal)
        };
        let shard_a = vec![0x01u8; 32];
        let shard_b = vec![0x02u8; 32];

        let state = make_state();
        let p = fake_prover(1, 1, 0, &shard_a);

        // A prover on TWO shards accrues BOTH at the same global frame.
        assert!(apply_reward(&state, 100, &p, &shard_a, &BigInt::from(1000)).unwrap());
        assert!(
            apply_reward(&state, 100, &p, &shard_b, &BigInt::from(500)).unwrap(),
            "different shard at same frame MUST credit"
        );
        assert_eq!(read_bal(&state, &p), BigInt::from(1500), "both shards accrue");

        // Dual-path re-materialize of the SAME (frame, shard) is idempotent.
        assert!(!apply_reward(&state, 100, &p, &shard_a, &BigInt::from(999)).unwrap());
        assert!(!apply_reward(&state, 100, &p, &shard_b, &BigInt::from(999)).unwrap());
        assert_eq!(read_bal(&state, &p), BigInt::from(1500), "same (frame,shard) no double-credit");

        // A strictly older frame re-materialized is skipped (already credited).
        assert!(!apply_reward(&state, 99, &p, &shard_a, &BigInt::from(777)).unwrap());
        assert_eq!(read_bal(&state, &p), BigInt::from(1500), "older frame skipped");

        // The NEXT frame resets the per-frame set — the same shard credits again.
        assert!(apply_reward(&state, 101, &p, &shard_a, &BigInt::from(200)).unwrap());
        assert_eq!(read_bal(&state, &p), BigInt::from(1700), "new frame credits again");
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
            fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> { Ok(Vec::new()) }
            fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
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
                _: &[u8],
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
                _: &[Vec<u8>],
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

    // ---- Gap coverage (audit 2026-06-28): partial-ring reward distribution.

    fn noop_registry() -> Arc<dyn ProverRegistry> {
        struct R;
        impl ProverRegistry for R {
            fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> { Ok(None) }
            fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> { Ok(Vec::new()) }
            fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_prover_count(&self, _: &[u8]) -> Result<usize> { Ok(0) }
            fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> { Ok(Vec::new()) }
            fn get_prover_shard_summaries(&self, _: u64) -> Result<Vec<quil_types::consensus::ProverShardSummary>> { Ok(Vec::new()) }
        }
        Arc::new(R)
    }
    fn noop_frame_prover() -> Arc<dyn FrameProver> {
        struct F;
        impl FrameProver for F {
            fn prove_frame_header(&self, _: &[u8], _: &[u8], _: &[u8], _: &[Vec<u8>], _: &[u8], _: i64, _: u32, _: u64, _: u64, _: &[u8], _: u64) -> Result<quil_types::proto::global::FrameHeader> { Err(QuilError::InvalidArgument("noop".into())) }
            fn verify_frame_header(&self, _: &quil_types::proto::global::FrameHeader) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn prove_global_frame_header(&self, _: &quil_types::proto::global::GlobalFrameHeader, _: &[Vec<u8>], _: &[u8], _: &[Vec<u8>], _: &[u8], _: &dyn quil_types::crypto::Signer, _: i64, _: u32, _: u8) -> Result<quil_types::proto::global::GlobalFrameHeader> { Err(QuilError::InvalidArgument("noop".into())) }
            fn verify_global_frame_header(&self, _: &quil_types::proto::global::GlobalFrameHeader) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> { Ok(Vec::new()) }
            fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> { Ok(true) }
        }
        Arc::new(F)
    }
    fn reward_balance(state: &HypergraphState, prover: &ProverInfo) -> BigInt {
        let reward_addr = reward_address(&prover.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        match state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc).unwrap() {
            Some(blob) => {
                let tree = rebuild_vertex_tree_from_blob(&blob);
                let b = read_field(&tree, "reward:ProverReward", "Balance").unwrap_or_default();
                BigInt::from_bytes_be(num_bigint::Sign::Plus, &b)
            }
            None => BigInt::from(0),
        }
    }

    /// A ring with N < RING_GROUP_SIZE participants pays each member
    /// `outputs[0] / RING_GROUP_SIZE`, so the ring mints only N/8 of the full
    /// ring reward — the empty slots are NOT minted. Intended per-slot economic
    /// model (reward tracks participation). Pinned here; VERIFY vs Go before altering.
    #[test]
    fn partial_ring_pays_each_an_eighth_and_undermints() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        // 6 active provers, distinct join frames → ranks 0..5 → all in ring 0
        // (6 < RING_GROUP_SIZE=8). Full participation (bitmask 0b00111111).
        let provers: Vec<ProverInfo> =
            (1u8..=6).map(|s| fake_prover(s, s as u64, 0, &filter)).collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata { state_size: 1024, shard_count: 1 };

        materialize_prover_shard_update(
            &header, 11, &state, &noop_registry(), &noop_frame_prover(),
            &reward_issuance, 4096, provers.clone(),
            &[0, 1, 2, 3, 4, 5], // participant INDICES (full attendance: all 6)
            md,
        )
        .unwrap();

        // Each of the 6 members gets exactly 8_000 / 8 = 1_000; total minted is
        // 6_000 (= 6/8 of the full 8_000 ring reward) — the 2 vacant slots'
        // 2_000 is NOT minted.
        let mut total = BigInt::from(0);
        for p in &provers {
            let bal = reward_balance(&state, p);
            assert_eq!(bal, BigInt::from(1_000), "each ring member gets outputs[0]/8");
            total += bal;
        }
        assert_eq!(total, BigInt::from(6_000), "partial ring under-mints to N/8");
    }

    /// A zero reward share (integer division rounds to 0 / StubReward 0) writes
    /// NO reward vertex, but `LastActiveFrameNumber` is still bumped — activity
    /// and reward are decoupled.
    #[test]
    fn zero_reward_share_skips_vertex_but_bumps_activity() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        seed_alloc_blob(&state, &p, &filter);
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(0)));
        let md = ShardMetadata { state_size: 1024, shard_count: 1 };

        materialize_prover_shard_update(
            &header, 11, &state, &noop_registry(), &noop_frame_prover(),
            &reward_issuance, 4096, vec![p.clone()], &[0u8], md,
        )
        .unwrap();

        // No reward vertex written (share == 0).
        let reward_addr = reward_address(&p.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        assert!(
            state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc).unwrap().is_none(),
            "zero share must not write a reward vertex"
        );
        // But activity still bumped.
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let atree = rebuild_vertex_tree_from_blob(
            &state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc).unwrap().unwrap(),
        );
        assert_eq!(
            read_field(&atree, "allocation:ProverAllocation", "LastActiveFrameNumber").unwrap(),
            11u64.to_be_bytes().to_vec()
        );
    }

    /// Reward is credited to the prover's OWN reward vertex, never redirected to
    /// its `delegate_address` (the delegate is distribution metadata only).
    /// Guards against a "pay the delegate" regression (consensus fork).
    #[test]
    fn reward_credits_prover_vertex_not_delegate() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let mut p = fake_prover(1, 1, 0, &filter);
        let delegate = vec![0xDDu8; 32];
        p.delegate_address = delegate.clone();
        seed_alloc_blob(&state, &p, &filter);
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata { state_size: 1024, shard_count: 1 };

        materialize_prover_shard_update(
            &header, 11, &state, &noop_registry(), &noop_frame_prover(),
            &reward_issuance, 4096, vec![p.clone()], &[0u8], md,
        )
        .unwrap();

        // Prover's own reward vertex got the credit.
        assert_eq!(reward_balance(&state, &p), BigInt::from(1_000));
        // The delegate address has NO reward vertex.
        let va_disc = vertex_adds_discriminator().unwrap();
        let delegate_reward = reward_address(&delegate).unwrap();
        assert!(
            state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &delegate_reward, &va_disc).unwrap().is_none(),
            "delegate must not receive a direct reward credit"
        );
    }

    /// Two rings credit DISTINCT per-ring shares. A ring-aware stub returns
    /// `8000 >> ring` (ring 0 → 8000, ring 1 → 4000); each member is paid
    /// `that / 8`, so ring-0 members get 1000 and the ring-1 member gets 500.
    #[test]
    fn two_rings_credit_distinct_shares() {
        // Ring-aware reward stub: value depends on the allocation's ring.
        struct RingStub;
        impl RewardIssuance for RingStub {
            fn calculate(
                &self, _: u64, _: u64, _: u64,
                provers: &[HashMap<String, ProverAllocation>],
            ) -> Result<Vec<BigInt>> {
                let ring = provers.first().and_then(|m| m.values().next()).map(|a| a.ring).unwrap_or(0);
                Ok(provers.iter().map(|_| BigInt::from(8_000u64 >> ring)).collect())
            }
        }
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        // 9 provers, ranks 0..8 → ring 0 (ranks 0-7) + ring 1 (rank 8). Ring is
        // now the STORED per-allocation value (set at confirmation); materialize
        // reads it rather than re-sorting by seniority. Assign by rank here.
        let mut provers: Vec<ProverInfo> =
            (1u8..=9).map(|s| fake_prover(s, s as u64, 0, &filter)).collect();
        for (i, p) in provers.iter_mut().enumerate() {
            if let Some(alloc) = p.allocations.iter_mut().find(|a| a.confirmation_filter == filter) {
                alloc.ring = (i / RING_GROUP_SIZE as usize) as u8;
            }
        }
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(RingStub);
        let md = ShardMetadata { state_size: 1024, shard_count: 1 };
        let indices: Vec<u8> = (0u8..9).collect();

        materialize_prover_shard_update(
            &header, 11, &state, &noop_registry(), &noop_frame_prover(),
            &reward_issuance, 4096, provers.clone(), &indices, md,
        )
        .unwrap();

        // First 8 (ring 0) get 1000; the 9th (ring 1) gets 500.
        for p in &provers[..8] {
            assert_eq!(reward_balance(&state, p), BigInt::from(1_000), "ring-0 member share");
        }
        assert_eq!(reward_balance(&state, &provers[8]), BigInt::from(500), "ring-1 member share");
    }

    /// The participant index list binds to POSITION in `active_provers`: index 0
    /// and 2 are credited, index 1 (skipped) is not — a reorder would
    /// misattribute rewards, so this guards the consensus determinism.
    #[test]
    fn participant_indices_bind_to_active_prover_position() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let provers: Vec<ProverInfo> =
            (1u8..=3).map(|s| fake_prover(s, s as u64, 0, &filter)).collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata { state_size: 1024, shard_count: 1 };

        // Participants = positions 0 and 2 (skip position 1). 2 of 3 ≥ 2/3.
        materialize_prover_shard_update(
            &header, 11, &state, &noop_registry(), &noop_frame_prover(),
            &reward_issuance, 4096, provers.clone(), &[0, 2], md,
        )
        .unwrap();

        assert_eq!(reward_balance(&state, &provers[0]), BigInt::from(1_000), "index 0 credited");
        assert_eq!(reward_balance(&state, &provers[1]), BigInt::from(0), "index 1 (skipped) not credited");
        assert_eq!(reward_balance(&state, &provers[2]), BigInt::from(1_000), "index 2 credited");
    }

    // =================================================================
    // HIGH-2: durable atomic materialization cursor + crash-gap
    // re-materialize (no double-mint / no under-mint).
    //
    // These tests exercise the REAL materialize order, because the defect
    // lives in that order's interaction with the same-frame commit cache:
    //   1. crdt.commit(N) [pre-reward: caches frame-N root]
    //   2. apply_reward(N) + state.commit [drains reward INTO the CRDT tree
    //                                       → the global-intrinsic tree is
    //                                       now DIRTY, but its frame-N root is
    //                                       already cached]
    //   3. crdt.commit_with_global_cursor(N) [cursor batch — MUST also flush
    //                                           the dirty reward nodes, or the
    //                                           cursor certifies rewards that
    //                                           only reach disk in a LATER,
    //                                           cursor-free commit → under-mint]
    // Durability is asserted by RELOADING a fresh CRDT from the SAME store
    // (models a restart), NOT by reading the live in-memory tree.
    // =================================================================

    /// InclusionProver that returns 74-byte commitments, so a non-empty
    /// shard's committed root is a REAL (non-placeholder) value. This is
    /// what makes the idempotency guard's cache-hit path fire in step 3
    /// (`len != 64`) — exactly as production KZG roots do. The 64-byte
    /// `StubProver` would never reach that path, so it can't reproduce the
    /// cache-hit-dirty defect.
    struct Prover74;
    impl InclusionProver for Prover74 {
        fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            data.hash(&mut h);
            let mut out = vec![0u8; 74];
            out[..8].copy_from_slice(&h.finish().to_be_bytes());
            Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 74]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("batch not supported".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    /// Materialize one frame in the REAL order (pre-reward commit → apply
    /// additive reward → drain into the tree → cursor commit). Mirrors
    /// `FrameMaterializer::materialize`'s commit sequence for a single
    /// reward-bearing frame.
    fn materialize_reward_frame(
        state: &HypergraphState,
        crdt: &quil_hypergraph::HypergraphCrdt,
        cursor_key: &[u8],
        frame_n: u64,
        prover: &ProverInfo,
        share: &BigInt,
    ) {
        crdt.commit(frame_n).unwrap(); // 1. pre-reward root (caches frame-N)
        apply_reward(state, frame_n, prover, &[0xBBu8; 32], share).unwrap(); // 2. additive mint
        state.commit().unwrap(); //           drain reward → CRDT tree (dirty)
        crdt.commit_with_global_cursor(frame_n, cursor_key).unwrap(); // 3. cursor
    }

    /// Seed TWO reward leaves (`p` and `q`) at frame 0 and commit with the
    /// cursor, so the global-intrinsic vertex_adds root is a real 74-byte
    /// BRANCH commitment for every subsequent frame. This is essential: a
    /// single-leaf tree's root is the leaf's 64-byte hash, which the
    /// idempotency guard treats as a placeholder (`len == 64`) and never
    /// caches — so with one leaf the cache-hit-dirty path (the defect) is
    /// never reached. Two leaves force a branch whose root comes from the
    /// prover (74 bytes), exactly like production KZG roots. Returns the
    /// committed shard keys for the reload probe.
    fn seed_two_leaf_baseline(
        state: &HypergraphState,
        crdt: &quil_hypergraph::HypergraphCrdt,
        cursor_key: &[u8],
        p: &ProverInfo,
        q: &ProverInfo,
        share: &BigInt,
    ) -> Vec<quil_types::store::ShardKey> {
        apply_reward(state, 0, p, &[0xBBu8; 32], share).unwrap();
        apply_reward(state, 0, q, &[0xBBu8; 32], share).unwrap();
        state.commit().unwrap();
        crdt.commit_with_global_cursor(0, cursor_key).unwrap();
        crdt.commit(0).unwrap().keys().cloned().collect()
    }

    /// The global cursor is written ATOMICALLY inside the CRDT commit batch
    /// (one `db.write`, cross-store readable) and ONLY by
    /// `commit_with_global_cursor` — a plain `commit` never touches it.
    #[test]
    fn global_cursor_written_atomically_and_cross_store_readable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let inner = db.inner();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
        let clock = quil_store::RocksClockStore::new(inner);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(hg_store, Arc::new(StubProver)));
        let key = quil_store::encoding::global_materialized_cursor_key();

        // Absent on a fresh store.
        assert_eq!(clock.get_global_materialized_cursor(), None);

        // A PLAIN commit must NOT write the global cursor.
        crdt.commit(7).unwrap();
        assert_eq!(
            clock.get_global_materialized_cursor(),
            None,
            "plain commit must never stage the global cursor"
        );

        // commit_with_global_cursor writes cursor == frame, atomically, and
        // the value is visible through the clock store on the shared DB.
        crdt.commit_with_global_cursor(8, &key).unwrap();
        assert_eq!(clock.get_global_materialized_cursor(), Some(8));

        // Advancing to the next frame overwrites the single global key.
        crdt.commit_with_global_cursor(9, &key).unwrap();
        assert_eq!(clock.get_global_materialized_cursor(), Some(9));
    }

    /// `recompute_shard_rings` ranks by (join-frame, address) — a STABLE
    /// immutable ordering — and RECOMPACTS when the active set shrinks: a ring-0
    /// prover leaving shifts every survivor below it up one rank, so an ex-ring-1
    /// prover can drop to ring 0.
    #[test]
    fn shard_rings_rank_by_join_frame_and_recompact_on_leave() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let ring_of = |p: &ProverInfo| {
            p.allocations.iter().find(|a| a.confirmation_filter == filter).unwrap().ring
        };

        // 10 active provers, join frames 10,20,…,100 (distinct, ascending by
        // seed; addresses also ascend by seed) → ranks 0..9.
        let mut provers: Vec<ProverInfo> =
            (1u8..=10).map(|s| fake_prover(s, (s as u64) * 10, 0, &filter)).collect();
        recompute_shard_rings(&state, &filter, &mut provers, 1000).unwrap();
        // ranks 0..7 → ring 0; ranks 8,9 → ring 1 (RING_GROUP_SIZE = 8).
        for p in &provers[..8] {
            assert_eq!(ring_of(p), 0);
        }
        assert_eq!(ring_of(&provers[8]), 1);
        assert_eq!(ring_of(&provers[9]), 1);

        // The earliest joiner (rank 0, ring 0) leaves. Recompute over the 9
        // survivors → ranks 0..8. The ex-rank-8 prover (seed 9) moves to rank 7
        // → RECOMPACTS from ring 1 down to ring 0; only the last stays ring 1.
        provers.remove(0);
        recompute_shard_rings(&state, &filter, &mut provers, 1100).unwrap();
        for p in &provers[..8] {
            assert_eq!(ring_of(p), 0, "survivor recompacted to ring 0");
        }
        assert_eq!(ring_of(&provers[8]), 1);
        assert_eq!(provers.iter().filter(|p| ring_of(p) == 1).count(), 1, "one ring-1 after leave");
    }

    /// THE critical test: frame N's reward-tree NODES must land durably in
    /// the SAME `db.write` as `cursor = N`. Reproduces the exact production
    /// order — a pre-reward `commit(N)` caches frame N's (real, 74-byte)
    /// global-intrinsic root, then the reward mutates that same tree, then
    /// `commit_with_global_cursor(N)` runs. The same-frame cache would
    /// otherwise let the guard skip the DIRTY reward tree, leaving the reward
    /// to reach disk only in a later cursor-free commit (under-mint on crash).
    ///
    /// FAILS on the pre-fix code (reload sees 1·share), PASSES after the fix
    /// (reload sees 2·share).
    #[test]
    fn cursor_commit_flushes_dirty_reward_nodes_atomically() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let inner = db.inner();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
        let clock = quil_store::RocksClockStore::new(inner.clone());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(hg_store, Arc::new(Prover74)));
        let state = HypergraphState::new(crdt.clone());
        let key = quil_store::encoding::global_materialized_cursor_key();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        let q = fake_prover(2, 2, 0, &filter);
        let share = BigInt::from(1_000);

        // Read a prover's reward balance from a FRESH CRDT over the SAME db —
        // i.e. only what is DURABLE in the store (models a restart).
        let reload = |shard_keys: &Vec<quil_types::store::ShardKey>| -> BigInt {
            let s = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
            let c = Arc::new(quil_hypergraph::HypergraphCrdt::new(s, Arc::new(Prover74)));
            for sk in shard_keys {
                c.ensure_all_phase_trees(sk);
            }
            reward_balance(&HypergraphState::new(c), &p)
        };

        // Baseline frame 0: two reward leaves → the global-intrinsic root is a
        // real 74-byte branch, so frame 1's pre-reward commit caches a "real"
        // root and the cache-hit-dirty guard path fires.
        let shard_keys = seed_two_leaf_baseline(&state, &crdt, &key, &p, &q, &share);
        assert_eq!(reload(&shard_keys), share.clone(), "baseline reward durable");

        // Frame 1 in the REAL order (pre-reward commit caches the root; the
        // reward then dirties the same tree; the cursor commit follows).
        materialize_reward_frame(&state, &crdt, &key, 1, &p, &share);

        // A restart must read 2·share (frames 0 AND 1). Pre-fix, the cache-hit
        // guard skipped the dirty reward tree in the cursor batch, so only the
        // baseline reached disk here (1·share) and this assertion FAILS.
        assert_eq!(
            reload(&shard_keys),
            BigInt::from(2) * &share,
            "frame N's reward MUST be durable in the same atomic batch as cursor=N"
        );
        assert_eq!(clock.get_global_materialized_cursor(), Some(1));
    }

    /// Crash-gap re-materialize, faithful order + durable read-back. Reward
    /// minting is additive with no per-frame idempotency, so re-running a
    /// committed frame double-mints. Model: frames 0,1 materialized
    /// (durable cursor=1), then head H=3 with frames 2,3 uncommitted. On
    /// restart, seed from the durable cursor and re-materialize
    /// `[cursor+1..=H]`. The DURABLE balance must equal the single-pass total
    /// (frames 0,1,2,3 each minted once), NOT doubled, and cursor == H.
    #[test]
    fn crash_gap_re_materialize_no_double_mint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let inner = db.inner();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
        let clock = quil_store::RocksClockStore::new(inner.clone());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(hg_store, Arc::new(Prover74)));
        let state = HypergraphState::new(crdt.clone());
        let key = quil_store::encoding::global_materialized_cursor_key();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        let q = fake_prover(2, 2, 0, &filter);
        let share = BigInt::from(1_000);

        let reload = |shard_keys: &Vec<quil_types::store::ShardKey>| -> BigInt {
            let s = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
            let c = Arc::new(quil_hypergraph::HypergraphCrdt::new(s, Arc::new(Prover74)));
            for sk in shard_keys {
                c.ensure_all_phase_trees(sk);
            }
            reward_balance(&HypergraphState::new(c), &p)
        };

        // --- Pre-crash: baseline (frame 0: p+q leaves, cursor=0) then frame 1
        // fully materialized (real order). p's durable balance = 2·share
        // (frames 0,1); cursor=1. ---
        let shard_keys = seed_two_leaf_baseline(&state, &crdt, &key, &p, &q, &share);
        materialize_reward_frame(&state, &crdt, &key, 1, &p, &share);
        assert_eq!(clock.get_global_materialized_cursor(), Some(1));
        assert_eq!(reload(&shard_keys), BigInt::from(2) * &share, "frames 0,1 durable");

        // --- Crash: head H=3, frames 2,3 uncommitted; in-memory cursor lost. ---
        let head: u64 = 3;

        // --- Restart: seed from the durable cursor (=1), re-materialize
        // [cursor+1..=H] with the idempotency gate. Because the DURABLE cursor
        // correctly excludes frame 1, the gap is [2,3] — frame 1 is NEVER
        // re-run (had the cursor been lost → 0, we'd re-run [1..3] → 4·share
        // for those + double-count frame 1). ---
        let durable = clock.get_global_materialized_cursor().unwrap_or(0);
        assert_eq!(durable, 1);
        let mut last = durable; // == FrameMaterializer::seed_cursor(durable)
        for n in (durable + 1)..=head {
            if n <= last {
                continue; // gate: never re-run a frame at/below the cursor
            }
            materialize_reward_frame(&state, &crdt, &key, n, &p, &share);
            last = n;
        }

        // Durable balance = frames 0,1,2,3 each minted exactly ONCE = 4·share.
        // A regression (lost/lagging cursor re-running frame 1) shows 5·share.
        assert_eq!(
            reload(&shard_keys),
            BigInt::from(4) * &share,
            "gap re-materialize must not double-mint the already-committed frame"
        );
        assert_eq!(clock.get_global_materialized_cursor(), Some(3), "cursor advanced to head");
        assert_eq!(last, 3);
    }

    /// With the cursor already at the head, feeding a frame at or below it is
    /// a gate no-op — no reward is re-minted (durable balance unchanged).
    #[test]
    fn no_re_run_at_or_below_cursor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let inner = db.inner();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
        let clock = quil_store::RocksClockStore::new(inner.clone());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(hg_store, Arc::new(Prover74)));
        let state = HypergraphState::new(crdt.clone());
        let key = quil_store::encoding::global_materialized_cursor_key();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        let q = fake_prover(2, 2, 0, &filter);
        let share = BigInt::from(1_000);

        let reload = |shard_keys: &Vec<quil_types::store::ShardKey>| -> BigInt {
            let s = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
            let c = Arc::new(quil_hypergraph::HypergraphCrdt::new(s, Arc::new(Prover74)));
            for sk in shard_keys {
                c.ensure_all_phase_trees(sk);
            }
            reward_balance(&HypergraphState::new(c), &p)
        };

        // Baseline (frame 0, cursor=0) then materialize frames 1..=3 →
        // p durable = 4·share (frames 0,1,2,3), cursor 3.
        let shard_keys = seed_two_leaf_baseline(&state, &crdt, &key, &p, &q, &share);
        let mut last = 0u64;
        for n in 1..=3u64 {
            materialize_reward_frame(&state, &crdt, &key, n, &p, &share);
            last = n;
        }
        assert_eq!(reload(&shard_keys), BigInt::from(4) * &share);
        assert_eq!(clock.get_global_materialized_cursor(), Some(3));

        // Re-feed frames 2 and 3 (both <= cursor 3): the gate skips them, so
        // NO reward is applied and the durable balance stays put.
        for n in [2u64, 3u64] {
            if n <= last {
                continue;
            }
            materialize_reward_frame(&state, &crdt, &key, n, &p, &share);
            last = n;
        }
        assert_eq!(
            reload(&shard_keys),
            BigInt::from(4) * &share,
            "frames at/below the cursor must not re-mint"
        );
        assert_eq!(clock.get_global_materialized_cursor(), Some(3));
    }
}
