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
    use super::materialize::reward_address;
    use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
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
    prover_address_from_pubkey, reward_address, DEFAULT_SHARD_LEAVES, REWARD_UNITS,
    RING_GROUP_SIZE,
};
use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

/// A frame anchored in a hash-proof epoch (decided 2026-10-21): GLOBAL holds
/// each participant's issuance share in its storage seat
/// (`storage_seat`) until its epoch proof settles it, and chains the
/// proposer's openings root there.
#[derive(Debug, Clone, Default)]
pub struct StorageFrame {
    /// The epoch the frame is anchored in.
    pub epoch: u64,
    /// The proposer's commitment, when it made one GLOBAL chains.
    pub commitment: Option<StorageCommitment>,
    /// Members whose seat closed an epoch with committed roots it never
    /// proved: the caller kicks them.
    pub kicks: Vec<Vec<u8>>,
}

/// A frame's openings root as GLOBAL chains it
/// (`storage_seat::decode_commitment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageCommitment {
    pub root: [u8; 32],
    /// The GLOBAL frame whose beacon chose the openings.
    pub beacon: u64,
    /// That frame's storage beacon.
    pub rho_n: Vec<u8>,
}

/// Hypergraph metadata for the shard under `FrameHeader.address`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShardMetadata {
    pub state_size: u64,
    /// Zero becomes `DEFAULT_SHARD_LEAVES` = 1.
    pub shard_count: u64,
}

/// The lowest difficulty GLOBAL prices issuance at under the anchored
/// issuance rules: the first of the square-root generation
/// ([`crate::pricing::pomw_generation`] one). GLOBAL's own difficulty never
/// falls below 50,000, so it binds only a header without an anchor.
pub const ISSUANCE_MIN_DIFFICULTY: u64 = 10_000;

/// How GLOBAL prices and credits one shard header
/// ([`materialize_prover_shard_update_with_fees`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderIssuance {
    /// The difficulty issuance is priced at.
    pub difficulty: u64,
    /// Whether the header earns issuance, fees and activity. From the
    /// anchored issuance epoch a header at or below its session's executed
    /// tip does not: GLOBAL already credited that frame.
    pub credit: bool,
}

impl HeaderIssuance {
    /// The rule before [`quil_types::consensus::anchored_issuance_active`]:
    /// the difficulty the shard's leader wrote into the header, credited.
    pub fn claimed(frame_header: &FrameHeader) -> Self {
        Self {
            difficulty: u64::from(frame_header.difficulty),
            credit: true,
        }
    }
}

/// The difficulty GLOBAL prices a header's issuance at under the anchored
/// issuance rules: that of the GLOBAL frame it anchors to
/// (`anchor_difficulty`, from GLOBAL's own clock), or for a header without
/// an anchor its own, and never below [`ISSUANCE_MIN_DIFFICULTY`]. App voters
/// only bind the header's difficulty into its output and never compare it
/// with GLOBAL's, so the leader's value cannot price issuance.
pub fn anchored_issuance_difficulty(
    frame_header: &FrameHeader,
    anchor_difficulty: Option<u32>,
) -> u64 {
    u64::from(anchor_difficulty.unwrap_or(frame_header.difficulty)).max(ISSUANCE_MIN_DIFFICULTY)
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

/// Recompute an app-shard frame's deterministic output from its header fields
/// and require it to match `output`.
///
/// App-shard frames carry NO VDF: the producer (`AppLeaderProvider`) stamps
/// `porep::deterministic_app_frame_output` on every frame it makes, binding the
/// header fields downstream code consumes (fee total, settlement relay,
/// storage-attestation root, ...). The committee certificate signs only
/// `poseidon(output)`, so without this recomputation a relayer could alter
/// those fields of a certified header. A frame anchored to a real global frame
/// binds ρ_N to `anchor_output` (that global frame's output, resolved by the
/// caller from its own clock store); a genesis / pre-global-chain frame
/// (`global_frame_number == 0`) uses the zero-anchor beacon and ignores it.
pub fn verify_app_frame_output(frame_header: &FrameHeader, anchor_output: &[u8]) -> Result<()> {
    let rho_n = if frame_header.global_frame_number == 0 {
        quil_crypto::porep::derive_storage_beacon(0, &[])
    } else {
        quil_crypto::porep::derive_storage_beacon(frame_header.global_frame_number, anchor_output)
    };
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
        frame_header.fee_total_value(),
        &frame_header.settlements,
        &frame_header.accumulator,
        &frame_header.spends,
    );
    if expected != frame_header.output {
        return Err(QuilError::Crypto(
            "frame header attestation: app-shard frame output does not match the \
             deterministic digest of its header fields"
                .into(),
        ));
    }
    Ok(())
}

fn verify_genesis_app_frame_output(frame_header: &FrameHeader) -> Result<()> {
    verify_app_frame_output(frame_header, &[])
}

/// Structural check of a header's settlement relay: canonical, inside the
/// header's window, and carried only by a QUIL token shard.
pub fn verify_settlement_relay(
    frame_header: &FrameHeader,
) -> Result<
    Vec<(
        u64,
        Vec<crate::token_intrinsic::settlement_record::SettlementEntry>,
    )>,
> {
    if frame_header.settlements.is_empty() {
        return Ok(Vec::new());
    }
    if frame_header.address.len() < 32 || frame_header.address[..32] != crate::domains::QUIL_TOKEN {
        return Err(QuilError::InvalidArgument(
            "frame header: only QUIL token shards relay settlements".into(),
        ));
    }
    crate::token_intrinsic::settlement_record::decode_relay(
        frame_header.frame_number,
        &frame_header.settlements,
    )
}

/// Write the GLOBAL settlement record of every relayed entry not yet recorded.
/// Idempotent: a header re-carries its window, so most entries are repeats.
/// From the committed-credit frame (`settlement_record::committed_credit_frame`)
/// the relay is only checked: the global commit writes a record together with
/// the spend that carries it, so a settlement whose spend is rejected, or never
/// committed, records nothing. Returns the number of records written.
pub fn materialize_settlement_records(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
) -> Result<usize> {
    use crate::token_intrinsic::settlement_record;
    let frames = verify_settlement_relay(frame_header)?;
    if frames.is_empty() || current_frame_number >= settlement_record::committed_credit_frame() {
        return Ok(0);
    }
    let va_disc = vertex_adds_discriminator()?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let mut written = 0usize;
    for (_, entries) in &frames {
        for entry in entries {
            if state
                .get(domain, &entry.receipt, &va_disc)?
                .is_some_and(|b| !b.is_empty())
            {
                continue;
            }
            state.set(
                domain,
                &entry.receipt,
                &va_disc,
                current_frame_number,
                settlement_record::create_record(entry)?,
            )?;
            written += 1;
        }
    }
    if written > 0 {
        tracing::info!(
            shard = %hex::encode(&frame_header.address),
            shard_frame = frame_header.frame_number,
            frame = current_frame_number,
            written,
            "settlement records written",
        );
    }
    Ok(written)
}

/// Resolve the authorized historical committee before global admission and
/// execution. Registry membership changes do not change a session's quorum.
/// Prover metadata is still required for reward/ring attribution; missing
/// metadata stops execution instead of shrinking the authorized committee.
pub fn verify_frame_header_in_state(
    state: &HypergraphState,
    frame_header: &FrameHeader,
    frame_prover: &dyn quil_types::crypto::FrameProver,
    bls: &dyn quil_types::crypto::BlsConstructor,
    registry: &dyn ProverRegistry,
    legacy_committee_frame: u64,
    global_frame: u64,
) -> Result<(Vec<ProverInfo>, Vec<u8>)> {
    verify_frame_header_session(
        state,
        frame_header,
        frame_prover,
        bls,
        registry,
        legacy_committee_frame,
        global_frame,
    )
    .map(|(members, bitmask, _)| (members, bitmask))
}

/// [`verify_frame_header_in_state`], also naming the authorized session that
/// certified the frame (`None` for a legacy committee). Members are in the
/// session's order. `global_frame` is the GLOBAL frame admitting or executing
/// the header (see [`frames::refuse_legacy_after_flag_day`]).
///
/// [`frames::refuse_legacy_after_flag_day`]: super::handoff::frames::refuse_legacy_after_flag_day
pub fn verify_frame_header_session(
    state: &HypergraphState,
    frame_header: &FrameHeader,
    frame_prover: &dyn quil_types::crypto::FrameProver,
    bls: &dyn quil_types::crypto::BlsConstructor,
    registry: &dyn ProverRegistry,
    legacy_committee_frame: u64,
    global_frame: u64,
) -> Result<(Vec<ProverInfo>, Vec<u8>, Option<[u8; 32]>)> {
    use super::handoff::frames::{self, FrameClaim};
    state.require_full_domain_coverage(&GLOBAL_INTRINSIC_ADDRESS)?;
    if let Some(bytes) = quil_cw_consensus::app_cert::unwrap_cert_from_header(
        &frame_header.public_key_signature_bls48581,
    ) {
        let claim = FrameClaim {
            filter: &frame_header.address,
            frame: frame_header.frame_number,
            view: frame_header.rank,
            parent: &frame_header.parent_selector,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&frame_header.output)?,
        };
        if let Some(verified) = frames::verify(state, &claim, bytes)? {
            if frame_header.global_frame_number == 0 {
                verify_genesis_app_frame_output(frame_header)?;
            }
            let mut members = Vec::with_capacity(verified.session.members.len());
            for key in &verified.session.members {
                let address = prover_address_from_pubkey(key)?;
                let mut info = registry.get_prover_info(&address)?.ok_or_else(|| {
                    QuilError::ExecutionUnavailable(
                        "authorized session member metadata unavailable".into(),
                    )
                })?;
                // The session names the member by key and the certificate was
                // verified against it; the registry row only supplies reward
                // and ring attribution. A row whose key or address disagrees
                // (e.g. an empty key for an authorized member) is corrected
                // from the session rather than allowed to stop every node's
                // materialization.
                if info.public_key != *key || info.address != address {
                    tracing::warn!(
                        shard = %hex::encode(&frame_header.address),
                        member = %hex::encode(&address[..8]),
                        registry_key = %hex::encode(&info.public_key[..info.public_key.len().min(8)]),
                        registry_address = %hex::encode(&info.address[..info.address.len().min(8)]),
                        "authorized session member metadata disagrees with the registry; using the session's identity",
                    );
                    info.public_key = key.clone();
                    info.address = address.to_vec();
                }
                members.push(info);
            }
            let mut bitmask = Vec::new();
            for key in &verified.certificate.signers {
                let index = verified.session.members.binary_search(key).map_err(|_| {
                    QuilError::InvalidSignature(
                        "certificate signer outside authorized session".into(),
                    )
                })?;
                quil_consensus::bitmask::set_bit(&mut bitmask, index);
            }
            return Ok((members, bitmask, Some(verified.session.id()?)));
        }
        frames::refuse_legacy_after_flag_day(global_frame)?;
    } else {
        frames::refuse_legacy_after_flag_day(global_frame)?;
        frames::require_legacy_allowed(state, &frame_header.address, frame_header.frame_number)?;
    }
    let active = registry.get_active_provers(&frame_header.address, legacy_committee_frame)?;
    let bitmask = verify_frame_header_attestation(frame_header, frame_prover, bls, &active)?;
    Ok((active, bitmask, None))
}

/// Verify a legacy, unregistered shard FrameHeader's three-layer attestation:
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
    // the shard committee (the active provers' Falcon keys) and output digest,
    // and read the participant set (signers) off the cert.
    if let Some(cert_bytes) = quil_cw_consensus::app_cert::unwrap_cert_from_header(
        &frame_header.public_key_signature_bls48581,
    ) {
        // Positive generations require authenticated global session lookup.
        // They must never verify merely because the current keys happen to fit.
        if quil_cw_consensus::app_cert::unverified_finalization_epoch(cert_bytes) != Some(0) {
            return Err(QuilError::InvalidSignature(
                "app session certificate requires global authorization".into(),
            ));
        }
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
        let committee_pubkeys: Vec<Vec<u8>> = active_provers
            .iter()
            .map(|p| p.public_key.clone())
            .collect();
        let output_digest = quil_crypto::poseidon::hash_bytes_to_32(&frame_header.output)
            .map_err(|e| QuilError::Crypto(format!("cw cert: poseidon(output): {e}")))?;
        let verified = quil_cw_consensus::app_cert::verify_finalization_details(
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
        if verified.finalization.proposal.round.view().get() != frame_header.rank {
            return Err(QuilError::InvalidSignature(
                "app header rank differs from certified view".into(),
            ));
        }

        // Build the participant bitmask: index of each signer in the active set.
        let mut bitmask: Vec<u8> = Vec::new();
        for pk in &verified.signers {
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
    let agg_pubkey = agg.public_key.clone().ok_or_else(|| {
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
        public_key_signature_bls48581: Some(quil_types::proto::keys::Bls48581AggregateSignature {
            signature: agg.signature.clone(),
            public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                key_value: agg_pubkey.key_value.clone(),
            }),
            bitmask: agg.bitmask.clone(),
        }),
        storage_attestation_root: frame_header.storage_attestation_root.clone(),
        global_frame_number: frame_header.global_frame_number,
        storage_attestation: frame_header.storage_attestation.clone(),
        fee_total: frame_header.fee_total.clone(),
        settlements: frame_header.settlements.clone(),
        accumulator: frame_header.accumulator.clone(),
        spends: frame_header.spends.clone(),
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
    let committee_refs: Vec<&[u8]> = active_provers
        .iter()
        .map(|p| p.address.as_slice())
        .collect();
    // 666-byte signature = single signer, no multi-proofs to verify.
    let ids_arg: Option<&[&[u8]]> = if agg.signature.len() == 666 {
        if participant_ids.len() != 1 {
            return Err(QuilError::InvalidSignature(
                "frame header attestation: 666-byte signature requires exactly 1 participant"
                    .into(),
            ));
        }
        None
    } else {
        Some(&committee_refs)
    };
    let valid = frame_prover.verify_frame_header_signature(&proto, bls, ids_arg)?;
    if !valid {
        return Err(QuilError::InvalidSignature(
            "frame header attestation: aggregate BLS + multi-proof check failed".into(),
        ));
    }

    Ok(agg.bitmask)
}

/// Build the per-frame context: groups participants by ring and enforces 2/3
/// participation. The caller expands the verified bitmap into `usize` indices;
/// the committee may contain more than 256 members.
pub fn build_shard_update_context(
    frame_header: &FrameHeader,
    active_provers: Vec<ProverInfo>,
    participant_bitmask: &[usize],
    shard_metadata: ShardMetadata,
) -> Result<ShardUpdateContext> {
    build_shard_update_context_with_rings(
        frame_header,
        active_provers,
        participant_bitmask,
        shard_metadata,
        None,
    )
}

/// [`build_shard_update_context`] with each member's ring given by position
/// (a session's snapshot, [`session_member_rings`]) instead of read from its
/// allocation at the frame's filter, which a later topology change removes.
fn build_shard_update_context_with_rings(
    frame_header: &FrameHeader,
    active_provers: Vec<ProverInfo>,
    participant_bitmask: &[usize],
    shard_metadata: ShardMetadata,
    rings: Option<&[u8]>,
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
        let i = idx;
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
        let ring = match rings {
            Some(rings) => rings.get(idx).copied(),
            None => prover
                .allocations
                .iter()
                .find(|a| a.confirmation_filter == frame_header.address)
                .map(|a| a.ring),
        }
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
                QuilError::InvalidArgument("shard update: allocation not found for prover".into())
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
    participant_bitmask: Option<&[usize]>,
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
    let order = quil_types::reward_ring::reward_member_order(
        &active_provers.iter().collect::<Vec<_>>(),
        filter,
    );

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
            state.set(
                domain,
                &alloc_addr,
                &va_disc,
                frame_number,
                vertex_tree_to_blob(&tree),
            )?;
        }
    }
    Ok(())
}

/// Set each prover's ring on `filter` to the one its committed allocation
/// records.
fn committed_rings(
    state: &HypergraphState,
    filter: &[u8],
    active_provers: &mut [ProverInfo],
) -> Result<()> {
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    for prover in active_provers.iter_mut() {
        let address = allocation_address(&prover.public_key, filter)?;
        let ring = state
            .get(domain, &address, &va_disc)?
            .map(|blob| rebuild_vertex_tree_from_blob(&blob))
            .and_then(|tree| {
                crate::global_schema::read_field(&tree, "allocation:ProverAllocation", "Ring")
            })
            .and_then(|bytes| bytes.first().copied())
            .unwrap_or(0);
        if let Some(allocation) = prover
            .allocations
            .iter_mut()
            .find(|a| a.confirmation_filter == filter)
        {
            allocation.ring = ring;
        }
    }
    Ok(())
}

/// The rings of an authorized session's members, in member order: recorded
/// at the session's first rewarded frame, then read back for every later one.
///
/// Reading each member's allocation at reward time instead (the legacy rule)
/// failed once a split or merge moved the member ("missing allocation/ring"),
/// withholding the whole frame's reward from every participant, and paid a
/// frame certified before a succession at the successor's ranks. The first
/// computation ranks exactly as [`recompute_shard_rings`] does — join frame at
/// the filter, then address — with a member that holds no allocation there
/// ranked by address alone.
fn session_member_rings(
    state: &HypergraphState,
    session: &[u8; 32],
    filter: &[u8],
    members: &[ProverInfo],
    frame_number: u64,
) -> Result<Vec<u8>> {
    if let Some(rings) = super::handoff::session_rings(state, session)? {
        if rings.len() != members.len() {
            return Err(QuilError::Store(
                "session ring snapshot does not match its members".into(),
            ));
        }
        return Ok(rings);
    }
    let join_frame = |p: &ProverInfo| -> u64 {
        p.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.join_frame_number)
            .unwrap_or(0)
    };
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by(|&i, &j| {
        join_frame(&members[i])
            .cmp(&join_frame(&members[j]))
            .then_with(|| members[i].address.cmp(&members[j].address))
    });
    let mut rings = vec![0u8; members.len()];
    for (rank, &idx) in order.iter().enumerate() {
        rings[idx] = (rank as u64 / RING_GROUP_SIZE) as u8;
    }
    super::handoff::record_session_rings(state, frame_number, session, &rings)?;
    Ok(rings)
}

pub fn materialize_prover_shard_update(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
    prover_registry: &Arc<dyn ProverRegistry>,
    frame_prover: &Arc<dyn FrameProver>,
    reward_issuance: &Arc<dyn RewardIssuance>,
    world_state_size: u64,
    active_provers: Vec<ProverInfo>,
    participant_bitmask: &[usize],
    shard_metadata: ShardMetadata,
) -> Result<()> {
    materialize_prover_shard_update_with_fees(
        frame_header,
        current_frame_number,
        state,
        prover_registry,
        frame_prover,
        reward_issuance,
        world_state_size,
        active_provers,
        participant_bitmask,
        shard_metadata,
        0,
        None,
        None,
        HeaderIssuance::claimed(frame_header),
    )
}

/// [`materialize_prover_shard_update`], also crediting `committed_fees`: the
/// fees of the confidential operations this header relayed that the global
/// commit accepted. They are paid to the relaying shard's provers exactly like
/// its own fee total — and only on commit, so verifying an operation the
/// global frame then rejects earns nothing.
///
/// `session` names the authorized session that certified the frame; its
/// members are rewarded at the session's recorded rings
/// ([`session_member_rings`]) and no allocation's ring is rewritten. A legacy
/// committee (`None`) keeps the per-allocation rings.
///
/// `storage` marks a frame anchored in a hash-proof epoch: each participant's
/// issuance share is held in its storage seat instead of paid
/// ([`hold_storage_shares`]); fees are still paid at once. From the unsealed
/// issuance epoch (`quil_types::consensus::unsealed_issuance_active`) a
/// participant without a sealed registration for the shard and epoch is paid
/// its share at once instead of nothing.
///
/// `issuance` prices the frame's issuance and says whether it is credited at
/// all ([`HeaderIssuance`]); a frame not credited only resolves its rings.
#[allow(clippy::too_many_arguments)]
pub fn materialize_prover_shard_update_with_fees(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
    _prover_registry: &Arc<dyn ProverRegistry>,
    _frame_prover: &Arc<dyn FrameProver>,
    reward_issuance: &Arc<dyn RewardIssuance>,
    world_state_size: u64,
    mut active_provers: Vec<ProverInfo>,
    participant_bitmask: &[usize],
    shard_metadata: ShardMetadata,
    committed_fees: u128,
    session: Option<[u8; 32]>,
    storage: Option<&mut StorageFrame>,
    issuance: HeaderIssuance,
) -> Result<()> {
    let session_rings = match &session {
        Some(session) => Some(session_member_rings(
            state,
            session,
            &frame_header.address,
            &active_provers,
            current_frame_number,
        )?),
        None if super::prover_rings::governs(current_frame_number) => {
            // Rings are never assigned during issuance: a registry committee
            // is rewarded at the rings its allocations record (committed
            // state, not the registry cache the caller's provers came from).
            committed_rings(state, &frame_header.address, &mut active_provers)?;
            None
        }
        None => {
            // Epoch-aligned ring (re)assignment: recompute from the current
            // active committee before rewards are distributed, recompacting on
            // any membership change and persisting the result. See
            // `recompute_shard_rings`. Frames before the seniority ring rule
            // keep this behavior so their replay is unchanged.
            recompute_shard_rings(
                state,
                &frame_header.address,
                &mut active_provers,
                current_frame_number,
            )?;
            None
        }
    };

    let ctx = build_shard_update_context_with_rings(
        frame_header,
        active_provers,
        participant_bitmask,
        shard_metadata,
        session_rings.as_deref(),
    )?;
    if !issuance.credit {
        tracing::info!(
            shard = %hex::encode(&frame_header.address),
            shard_frame = frame_header.frame_number,
            frame = current_frame_number,
            "shard header at or below its session's executed tip: GLOBAL already \
             credited this frame, so it earns no issuance, fees or activity again",
        );
        return Ok(());
    }

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
            issuance.difficulty,
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

    // Fees collected by the shard's previous frame (fees are paid to the
    // provers of the shard, never burned). Split equally among
    // this frame's participants; the remainder goes to the frame's prover when
    // it is a participant, else to the first participant.
    let fee_total = BigInt::from(frame_header.fee_total_value()) + BigInt::from(committed_fees);
    let participant_count: usize = ctx.participants_by_ring.values().map(|p| p.len()).sum();
    let (fee_share, fee_remainder) =
        if participant_count > 0 && fee_total.sign() != num_bigint::Sign::NoSign {
            let count = BigInt::from(participant_count as u64);
            (&fee_total / &count, &fee_total % &count)
        } else {
            (BigInt::from(0), BigInt::from(0))
        };
    let remainder_receiver: Option<usize> = if participant_count > 0 {
        let mut ordered: Vec<usize> = ctx
            .participants_by_ring
            .values()
            .flatten()
            .copied()
            .collect();
        ordered.sort_unstable();
        ordered
            .iter()
            .copied()
            .find(|&idx| ctx.active_provers[idx].address == frame_header.prover)
            .or(ordered.first().copied())
    } else {
        None
    };

    // Hash-proof epochs: issuance shares are held per seat, fees paid below.
    // From the unsealed issuance epoch a participant without a sealed
    // registration is paid its share at once, as before the hash epoch.
    let pay_unsealed = quil_types::consensus::unsealed_issuance_active(current_frame_number);
    let held = match storage {
        Some(storage) => Some(hold_storage_shares(
            frame_header,
            current_frame_number,
            state,
            &ctx,
            &rewards_per_ring,
            storage,
        )?),
        None => None,
    };

    // Apply per-participant rewards + activity updates.
    let mut credited_provers = 0usize;
    let mut total_reward = BigInt::from(0);
    let mut unsealed_paid = 0usize;
    for (ring, participants) in &ctx.participants_by_ring {
        let share = rewards_per_ring.get(ring);
        for &idx in participants {
            let prover = &ctx.active_provers[idx];

            let issued = share.cloned().unwrap_or_else(|| BigInt::from(0));
            let sealed = matches!(&held, Some(held) if held.sealed.contains(&idx));
            let unsealed = pay_unsealed && held.is_some() && !sealed;
            let unsealed_share = unsealed && issued.sign() != num_bigint::Sign::NoSign;
            let mut amount = match &held {
                Some(_) if !unsealed => BigInt::from(0),
                _ => issued,
            };
            amount += &fee_share;
            if remainder_receiver == Some(idx) {
                amount += &fee_remainder;
            }
            if amount.sign() != num_bigint::Sign::NoSign
                && apply_reward(
                    state,
                    current_frame_number,
                    prover,
                    &frame_header.address,
                    &amount,
                )?
            {
                credited_provers += 1;
                total_reward += &amount;
                if unsealed_share {
                    unsealed_paid += 1;
                }
            }

            update_allocation_activity(state, current_frame_number, prover, &frame_header.address)?;
        }
    }
    let present: std::collections::HashSet<usize> =
        ctx.participant_indices.iter().copied().collect();
    record_committee_absence(
        state,
        current_frame_number,
        frame_header,
        &ctx.active_provers,
        &present,
    )?;

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
    let HeldShares {
        provers: held_provers,
        total: held_total,
        ..
    } = held.unwrap_or_default();
    tracing::info!(
        shard = %hex::encode(&frame_header.address),
        frame = current_frame_number,
        credited_provers,
        participants,
        total_reward = %total_reward,
        fee_total = %fee_total,
        held_provers,
        held_total = %held_total,
        unsealed_paid,
        "shard reward distribution",
    );

    Ok(())
}

/// Hash-proof epochs (decided 2026-10-21): chain the proposer's openings root
/// into its seat, then hold each participant's issuance share in its seat and
/// count the frame toward the proposals expected of it. Only a member with a
/// sealed registration for the shard and epoch earns a share; settlement pays
/// it in proportion to the expected proposals it published with a root
/// (`storage_seat::SeatSlot::release`). A seat's first root of an epoch
/// queues it for the epoch's expiry sweep. Each seat touched first closes an
/// epoch whose settlement window ended; one that closes with committed roots
/// never proved kicks its member (`storage.kicks`), before the storage kick
/// suspension epoch only (`storage_seat::Seat::expire`). Returns how many
/// participants had shares held, their total, and which participants hold a
/// sealed registration ([`HeldShares`]).
fn hold_storage_shares(
    frame_header: &FrameHeader,
    current_frame_number: u64,
    state: &HypergraphState,
    ctx: &ShardUpdateContext,
    rewards_per_ring: &HashMap<u8, BigInt>,
    storage: &mut StorageFrame,
) -> Result<HeldShares> {
    use super::storage_seat;
    let filter = &frame_header.address;
    let epoch = storage.epoch;
    let touch = |address: &[u8],
                 storage: &mut StorageFrame,
                 f: &mut dyn FnMut(&mut storage_seat::Seat) -> bool|
     -> Result<bool> {
        let Ok(member) = <[u8; 32]>::try_from(address) else {
            return Ok(false);
        };
        let Some(mut seat) = storage_seat::read(state, &member, filter)? else {
            return Ok(false);
        };
        let before = seat.clone();
        if seat.expire(current_frame_number) && !storage.kicks.iter().any(|k| k == address) {
            storage.kicks.push(address.to_vec());
        }
        let changed = f(&mut seat);
        if seat != before {
            storage_seat::write(state, current_frame_number, &seat)?;
        }
        Ok(changed)
    };

    // The proposer's commitment. Every root GLOBAL executes is chained,
    // drained ones too (`commit_drained_storage`), with the GLOBAL frame
    // executing it; settlement counts those within the response window of
    // their beacons (`storage_seat::SeatSlot::response_times`).
    if let Some(commitment) = storage.commitment.clone() {
        let first = touch(&frame_header.prover, storage, &mut |seat| {
            seat.commit(
                epoch,
                frame_header.frame_number,
                commitment.beacon,
                current_frame_number,
                &commitment.rho_n,
                &commitment.root,
            ) && seat.first_commitment(epoch)
        })?;
        if first {
            let seat = storage_seat::seat_address(&frame_header.prover, filter)?;
            storage_seat::enqueue_expiry(state, current_frame_number, epoch, &seat)?;
        }
    }

    let committee = ctx.active_provers.len();
    let mut held = HeldShares::default();
    let none = BigInt::from(0);
    for (ring, participants) in &ctx.participants_by_ring {
        let share = rewards_per_ring.get(ring).unwrap_or(&none);
        for &idx in participants {
            let prover = &ctx.active_provers[idx];
            let mut sealed = false;
            if touch(&prover.address, storage, &mut |seat| {
                sealed = seat.sealed_for(epoch);
                seat.hold(
                    epoch,
                    current_frame_number,
                    frame_header.frame_number,
                    share,
                    committee,
                )
            })? {
                held.provers += 1;
                held.total += share;
            }
            if sealed {
                held.sealed.insert(idx);
            }
        }
    }
    Ok(held)
}

/// What [`hold_storage_shares`] held of a hash-proof frame's issuance.
#[derive(Debug, Default)]
struct HeldShares {
    /// Participants whose shares were held in this call.
    provers: usize,
    /// Their total.
    total: BigInt,
    /// Participants, by committee index, with a sealed registration for the
    /// shard and epoch: their share is held in the seat, never paid at once,
    /// even when this call held nothing for them (a frame applied again).
    sealed: std::collections::HashSet<usize>,
}

/// Pay a storage seat's held rewards to `member` when its epoch proof
/// settles them (`storage_epoch_proof`). The seat's outcome, written in the
/// same frame, keeps it to once.
pub fn credit_storage_settlement(
    state: &HypergraphState,
    frame_number: u64,
    member: &[u8; 32],
    amount: &BigInt,
) -> Result<()> {
    if amount.sign() != num_bigint::Sign::Plus {
        return Ok(());
    }
    let reward_addr = reward_address(member)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    let mut reward_tree = match state.get(domain, &reward_addr, &va_disc)? {
        Some(blob) if !blob.is_empty() => rebuild_vertex_tree_from_blob(&blob),
        _ => quil_tries::VectorCommitmentTree::new(),
    };
    add_to_reward_balance(&mut reward_tree, amount)?;
    state.set(
        domain,
        &reward_addr,
        &va_disc,
        frame_number,
        vertex_tree_to_blob(&reward_tree),
    )?;
    if LOCAL_PROVER_ADDRESS
        .get()
        .is_some_and(|local| local.as_slice() == member)
    {
        tracing::info!(frame = frame_number, prover = %hex::encode(member), delta = %amount,
            "storage rewards released to local prover");
    }
    Ok(())
}

/// Credit the fees of a frame executed in the GLOBAL venue (reward mints,
/// uncovered-shard operations run at the global level) to the global frame's
/// prover (fees are paid to the prover of the affected shard, never burned).
/// Same `apply_reward` path and `(frame, filter)` idempotency guard as the
/// PoMW share, with the global intrinsic address as the filter so a shard
/// credit at the same frame is unaffected. Returns
/// whether a credit was applied (`false` for a zero total or a repeat).
pub fn credit_global_frame_fees(
    state: &HypergraphState,
    frame_number: u64,
    prover_address: &[u8],
    fee_total: u128,
) -> Result<bool> {
    if fee_total == 0 || prover_address.is_empty() {
        return Ok(false);
    }
    let prover = ProverInfo {
        public_key: Vec::new(),
        address: prover_address.to_vec(),
        status: quil_types::consensus::ProverStatus::Active,
        kick_frame_number: 0,
        allocations: Vec::new(),
        available_storage: 0,
        seniority: 0,
        delegate_address: Vec::new(),
    };
    let credited = apply_reward(
        state,
        frame_number,
        &prover,
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &BigInt::from(fee_total),
    )?;
    tracing::info!(
        frame = frame_number,
        prover = %hex::encode(&prover_address[..prover_address.len().min(8)]),
        fee_total,
        credited,
        "global frame fee credit",
    );
    Ok(credited)
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
    let last_reward_frame = read_field(&reward_tree, cls, "LastRewardFrameNumber").and_then(|b| {
        b.get(..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
    });
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
            write_field(
                &mut reward_tree,
                cls,
                "LastRewardFrameNumber",
                &frame_number.to_be_bytes(),
            )?;
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
fn decode_rewarded_shards(tree: &quil_tries::VectorCommitmentTree, cls: &str) -> Vec<Vec<u8>> {
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

/// Update an allocation's `LastActiveFrameNumber`, and from
/// `SIGNED_FRAME_ACTIVATION_FRAME` its `LastSignedFrameNumber`: the caller
/// passes the signers of an app frame this GLOBAL frame includes.
///
/// Go equivalent: `updateAllocationActivity` at
/// `global_prover_shard_update.go:509`.
fn update_allocation_activity(
    state: &HypergraphState,
    frame_number: u64,
    prover: &ProverInfo,
    filter: &[u8],
) -> Result<()> {
    update_allocation_activity_from(
        state,
        frame_number,
        prover,
        filter,
        quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
    )
}

/// [`update_allocation_activity`] recording `LastSignedFrameNumber` from
/// `signed_frame_activation`, so tests can activate it. Below it, the vertex
/// is written exactly as before the field existed.
fn update_allocation_activity_from(
    state: &HypergraphState,
    frame_number: u64,
    prover: &ProverInfo,
    filter: &[u8],
    signed_frame_activation: u64,
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
    if frame_number >= signed_frame_activation {
        write_field(
            &mut alloc_tree,
            "allocation:ProverAllocation",
            "LastSignedFrameNumber",
            &frame_number.to_be_bytes(),
        )?;
    }

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

/// Count which members of `committee` missed this included app frame, for
/// the seniority absence penalty (#976, rule 3: disappearance). A member is present when its index
/// is in `present`, the signers of the frame's certificate
/// (`FrameHeader.public_key_signature_bls48581`: the authorized session's
/// certificate signers, or the legacy aggregate's participant bitmask, whose
/// members each also carry the frame's VDF multi-proof), or when it produced
/// the frame (`FrameHeader.prover`). A present member's `AbsentFrameCount`
/// returns to zero; an absent member's grows by one per app frame, keyed by
/// `LastAbsentFrameNumber` so a re-materialized header counts once. Past
/// `ABSENCE_PENALTY_GRACE_FRAMES` each further absent frame costs
/// `ABSENCE_PENALTY_PER_FRAME` seniority; the epoch-boundary registry pass
/// evicts at `ABSENCE_EVICTION_FRAMES`.
///
/// Only frames the committee produced count, so a committee that produces
/// none (no quorum, GLOBAL or archives down) accrues no absence for anyone.
/// Reads and writes nothing before the penalty epoch.
fn record_committee_absence(
    state: &HypergraphState,
    current_frame_number: u64,
    frame_header: &FrameHeader,
    committee: &[ProverInfo],
    present: &std::collections::HashSet<usize>,
) -> Result<()> {
    use quil_types::consensus::{
        epoch_for_frame, seniority_penalties_at, ABSENCE_PENALTY_GRACE_FRAMES,
        ABSENCE_PENALTY_PER_FRAME,
    };
    if !seniority_penalties_at(epoch_for_frame(current_frame_number)) {
        return Ok(());
    }
    let cls = "allocation:ProverAllocation";
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    let app_frame = frame_header.frame_number;
    for (idx, member) in committee.iter().enumerate() {
        let alloc_addr = allocation_address(&member.public_key, &frame_header.address)?;
        let Some(blob) = state
            .get(domain, &alloc_addr, &va_disc)?
            .filter(|b| !b.is_empty())
        else {
            continue;
        };
        let mut tree = rebuild_vertex_tree_from_blob(&blob);
        let count = read_prover_u64(&tree, cls, "AbsentFrameCount");
        if present.contains(&idx) || member.address == frame_header.prover {
            if count > 0 {
                write_field(&mut tree, cls, "AbsentFrameCount", &0u64.to_be_bytes())?;
                state.set(
                    domain,
                    &alloc_addr,
                    &va_disc,
                    current_frame_number,
                    vertex_tree_to_blob(&tree),
                )?;
                if count > ABSENCE_PENALTY_GRACE_FRAMES {
                    tracing::debug!(
                        shard = %hex::encode(&frame_header.address),
                        prover = %hex::encode(&member.address[..member.address.len().min(8)]),
                        frame = current_frame_number, app_frame, missed = count,
                        "seniority absence penalty ended: the member signed or produced a frame again",
                    );
                }
            }
            continue;
        }
        if app_frame <= read_prover_u64(&tree, cls, "LastAbsentFrameNumber") {
            continue; // this app frame was already counted
        }
        let count = count + 1;
        write_field(&mut tree, cls, "AbsentFrameCount", &count.to_be_bytes())?;
        write_field(
            &mut tree,
            cls,
            "LastAbsentFrameNumber",
            &app_frame.to_be_bytes(),
        )?;
        state.set(
            domain,
            &alloc_addr,
            &va_disc,
            current_frame_number,
            vertex_tree_to_blob(&tree),
        )?;
        if count <= ABSENCE_PENALTY_GRACE_FRAMES {
            continue;
        }
        charge_absence(
            state,
            &member.public_key,
            current_frame_number,
            ABSENCE_PENALTY_PER_FRAME,
        )?;
        crate::seniority_penalty_log::record(
            current_frame_number,
            crate::seniority_penalty_log::PenaltyRule::Absence,
            &member.address,
            &frame_header.address,
            ABSENCE_PENALTY_PER_FRAME,
            app_frame,
        );
    }
    Ok(())
}

/// Subtract `amount` from the prover's `Seniority`, saturating at zero, and
/// add what it subtracted to the prover's `SeniorityPenalty`.
fn charge_absence(
    state: &HypergraphState,
    public_key: &[u8],
    frame_number: u64,
    amount: u64,
) -> Result<()> {
    let prover_addr = prover_address_from_pubkey(public_key)?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    let Some(blob) = state
        .get(domain, &prover_addr, &va_disc)?
        .filter(|b| !b.is_empty())
    else {
        return Ok(());
    };
    let mut tree = rebuild_vertex_tree_from_blob(&blob);
    let seniority = read_prover_u64(&tree, "prover:Prover", "Seniority");
    let charged = seniority.min(amount);
    write_field(
        &mut tree,
        "prover:Prover",
        "Seniority",
        &(seniority - charged).to_be_bytes(),
    )?;
    super::seniority_succession::record_seniority_penalty(&mut tree, charged)?;
    state.set(
        domain,
        &prover_addr,
        &va_disc,
        frame_number,
        vertex_tree_to_blob(&tree),
    )
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
    write_field(
        &mut prover_tree,
        cls,
        "Seniority",
        &new_seniority.to_be_bytes(),
    )?;
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
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> {
            Ok(vec![0u8; 64])
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
        ) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("batch not supported".into()))
        }
        fn verify_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
            _: &[u8],
            _: &[u8],
        ) -> bool {
            true
        }
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
                last_signed_frame_number: 0,
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
            fee_total: Vec::new(),
            settlements: Vec::new(),
            accumulator: Vec::new(),
            spends: Vec::new(),
        }
    }

    fn relay_entry(receipt: u8) -> crate::token_intrinsic::settlement_record::SettlementEntry {
        crate::token_intrinsic::settlement_record::SettlementEntry {
            receipt: [receipt; 32],
            parameter_context: [2; 32],
            destination: [3; 32],
            context: [4; 32],
            settlement: 50,
            payment_address: [0; 32],
            payment: 0,
            claimant: [0; 32],
        }
    }

    fn stamp_output(header: &mut FrameHeader, anchor_output: &[u8]) {
        let rho_n =
            quil_crypto::porep::derive_storage_beacon(header.global_frame_number, anchor_output);
        header.output = quil_crypto::porep::deterministic_app_frame_output(
            &header.parent_selector,
            &header.requests_root,
            &header.state_roots,
            &rho_n,
            header.frame_number,
            header.rank,
            &header.prover,
            header.difficulty,
            header.fee_multiplier_vote as u64,
            header.timestamp,
            &header.storage_attestation_root,
            header.fee_total_value(),
            &header.settlements,
            &header.accumulator,
            &header.spends,
        );
    }

    #[test]
    fn relayed_header_fields_must_reproduce_the_certified_output() {
        use crate::token_intrinsic::settlement_record::encode_relay;
        let anchor = vec![0x5Au8; 516];
        let mut header = fake_header(crate::domains::QUIL_TOKEN.to_vec(), 40);
        header.global_frame_number = 900;
        header.fee_total = super::super::frame_header::fee_total_field(77);
        header.settlements = encode_relay(&[(20, vec![relay_entry(1)])]).unwrap();
        stamp_output(&mut header, &anchor);
        verify_app_frame_output(&header, &anchor).unwrap();
        // A relayer cannot inject or drop settlement entries, change the fee
        // total, or swap the anchor beacon under the same certified output.
        let mut injected = header.clone();
        injected.settlements = encode_relay(&[(20, vec![relay_entry(1), relay_entry(2)])]).unwrap();
        assert!(verify_app_frame_output(&injected, &anchor).is_err());
        let mut dropped = header.clone();
        dropped.settlements.clear();
        assert!(verify_app_frame_output(&dropped, &anchor).is_err());
        let mut fee = header.clone();
        fee.fee_total = super::super::frame_header::fee_total_field(78);
        assert!(verify_app_frame_output(&fee, &anchor).is_err());
        assert!(verify_app_frame_output(&header, &[0x5Bu8; 516]).is_err());
    }

    #[test]
    fn settlement_records_are_written_once_and_only_from_quil_shards() {
        use crate::token_intrinsic::settlement_record::{create_record, encode_relay};
        let state = make_state();
        let va_disc = vertex_adds_discriminator().unwrap();
        let mut filter = crate::domains::QUIL_TOKEN.to_vec();
        filter.push(0x03); // a split QUIL sub-shard
        let mut header = fake_header(filter, 40);
        header.settlements =
            encode_relay(&[(9, vec![relay_entry(1)]), (39, vec![relay_entry(2)])]).unwrap();
        assert_eq!(
            materialize_settlement_records(&header, 1_000, &state).unwrap(),
            2
        );
        let record = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &[1; 32], &va_disc)
            .unwrap()
            .unwrap();
        assert_eq!(record, create_record(&relay_entry(1)).unwrap());
        // The next header re-carries the window: nothing new is written.
        let mut next = header.clone();
        next.frame_number = 41;
        next.settlements = encode_relay(&[
            (9, vec![relay_entry(1)]),
            (39, vec![relay_entry(2)]),
            (40, vec![relay_entry(3)]),
        ])
        .unwrap();
        assert_eq!(
            materialize_settlement_records(&next, 1_001, &state).unwrap(),
            1
        );
        // Outside the carrying header's window.
        let mut stale = header.clone();
        stale.frame_number = 42;
        assert!(materialize_settlement_records(&stale, 1_002, &state).is_err());
        // Another application's shard cannot relay settlements.
        let mut other = header.clone();
        other.address = vec![0xAA; 32];
        assert!(verify_settlement_relay(&other).is_err());
        assert!(materialize_settlement_records(&other, 1_003, &state).is_err());
        other.settlements.clear();
        assert_eq!(
            materialize_settlement_records(&other, 1_003, &state).unwrap(),
            0
        );
    }

    /// A settlement spending `image`, executed at QUIL shard frame 39 and
    /// carrying the settlement of `receipt`.
    #[cfg(feature = "confidential-tokens")]
    fn settling_spend(
        tx: u8,
        image: u8,
        receipt: u8,
    ) -> crate::token_intrinsic::global_commit::SpendEntry {
        crate::token_intrinsic::global_commit::SpendEntry {
            kind: crate::token_engine::TYPE_LATTICE_SETTLEMENT,
            tx_id: [tx; 32],
            source_frame: 39,
            context: [8; 32],
            root_digest: None,
            consumptions: vec![[image; 32]],
            outputs: Vec::new(),
            escrow_create: None,
            escrow_claim: None,
            fee: 5,
            settlement: Some(relay_entry(receipt)),
        }
    }

    /// QUIL shard header 40 relaying `spends` from frame 39, with the
    /// settlements they carry plus `unspent`, settlements of no relayed spend.
    #[cfg(feature = "confidential-tokens")]
    fn settling_header(
        spends: &[crate::token_intrinsic::global_commit::SpendEntry],
        unspent: &[u8],
    ) -> FrameHeader {
        let mut settlements: Vec<_> = spends.iter().filter_map(|s| s.settlement).collect();
        settlements.extend(unspent.iter().map(|receipt| relay_entry(*receipt)));
        settlements.sort();
        settlements.dedup();
        let mut header = fake_header(crate::domains::QUIL_TOKEN.to_vec(), 40);
        header.settlements =
            crate::token_intrinsic::settlement_record::encode_relay(&[(39, settlements)]).unwrap();
        let relayed: Vec<Vec<u8>> = spends.iter().map(|s| s.encode().unwrap()).collect();
        header.spends =
            crate::token_intrinsic::spend_relay::encode_relay(&[(39, relayed)]).unwrap();
        header
    }

    /// What GLOBAL does with a certified QUIL shard header, in its order:
    /// the settlement relay, then the spend relay. Returns the credited fees.
    #[cfg(feature = "confidential-tokens")]
    fn settle(header: &FrameHeader, frame: u64, state: &HypergraphState) -> u128 {
        materialize_settlement_records(header, frame, state).unwrap();
        crate::token_intrinsic::global_commit::materialize_relay(
            state,
            frame,
            &header.address,
            header.frame_number,
            &header.spends,
        )
        .unwrap()
    }

    #[cfg(feature = "confidential-tokens")]
    fn settlement_record_of(state: &HypergraphState, receipt: u8) -> Option<Vec<u8>> {
        let va_disc = vertex_adds_discriminator().unwrap();
        state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &[receipt; 32], &va_disc)
            .unwrap()
            .filter(|blob| !blob.is_empty())
    }

    /// From the committed-credit frame a relayed settlement is recorded only
    /// with its committed spend: not for a double spend, a spend citing a
    /// root the application never had, or a settlement no spend carries.
    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn settlement_records_follow_only_committed_spends_from_the_activation_frame() {
        use crate::token_intrinsic::settlement_record::{
            create_record, set_committed_credit_frame_for_thread,
        };
        let honest = settling_spend(1, 20, 1);
        let double = settling_spend(2, 20, 2);
        let mut unrooted = settling_spend(3, 21, 3);
        unrooted.root_digest = Some([9; 32]);
        let header = settling_header(&[honest, double, unrooted], &[4]);

        set_committed_credit_frame_for_thread(Some(1_001));
        let before = make_state();
        assert_eq!(settle(&header, 1_000, &before), 5);
        for receipt in 1..=4 {
            assert!(settlement_record_of(&before, receipt).is_some());
        }

        set_committed_credit_frame_for_thread(Some(1_000));
        let after = make_state();
        assert_eq!(settle(&header, 1_000, &after), 5, "only the honest spend");
        assert_eq!(
            settlement_record_of(&after, 1),
            Some(create_record(&relay_entry(1)).unwrap()),
            "an honest settlement is recorded exactly as before"
        );
        assert_eq!(
            settlement_record_of(&after, 1),
            settlement_record_of(&before, 1)
        );
        for receipt in 2..=4 {
            assert!(
                settlement_record_of(&after, receipt).is_none(),
                "receipt {receipt} has no committed spend"
            );
        }
        // The next header re-carries the window: nothing changes.
        let mut next = header.clone();
        next.frame_number = 41;
        assert_eq!(settle(&next, 1_001, &after), 0);
        for receipt in 2..=4 {
            assert!(settlement_record_of(&after, receipt).is_none());
        }
        set_committed_credit_frame_for_thread(None);
    }

    /// A settlement relayed twice, or spent again under another operation
    /// id, is recorded and credited once.
    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn a_duplicated_settlement_is_recorded_and_credited_once() {
        use crate::token_intrinsic::settlement_record::set_committed_credit_frame_for_thread;
        set_committed_credit_frame_for_thread(Some(1_000));
        let state = make_state();
        let spend = settling_spend(1, 20, 1);
        let header = settling_header(&[spend.clone(), spend.clone()], &[]);
        assert_eq!(settle(&header, 1_000, &state), 5);
        let recorded = settlement_record_of(&state, 1).unwrap();
        // Re-carried, and re-encoded under another operation id.
        let mut next = settling_header(&[spend, settling_spend(2, 20, 1)], &[]);
        next.frame_number = 41;
        assert_eq!(settle(&next, 1_001, &state), 0);
        assert_eq!(settlement_record_of(&state, 1), Some(recorded));
        set_committed_credit_frame_for_thread(None);
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
                .get(
                    &GLOBAL_INTRINSIC_ADDRESS[..],
                    &output.prover_address,
                    &va_disc,
                )
                .unwrap()
                .unwrap();
            read_prover_u64(
                &rebuild_vertex_tree_from_blob(&blob),
                "prover:Prover",
                field,
            )
        };

        // First active frame → +10.
        accrue_active_seniority(&state, &prover.public_key, 100).unwrap();
        assert_eq!(read("Seniority"), 10);
        assert_eq!(read("LastSeniorityFrameNumber"), 100);

        // Same frame again (multi-shard prover / re-materialization) → idempotent.
        accrue_active_seniority(&state, &prover.public_key, 100).unwrap();
        assert_eq!(
            read("Seniority"),
            10,
            "same-frame re-accrual must be a no-op"
        );

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
        let provers: Vec<_> = (0..10u8)
            .map(|i| fake_prover(i + 1, i as u64, 0, &filter))
            .collect();
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
        assert!(build_shard_update_context(&header, Vec::new(), &[0usize], md).is_err());
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
        assert!(build_shard_update_context(&header, vec![p], &[5usize], md).is_err());
    }

    #[test]
    fn build_context_rejects_below_two_thirds() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        // 3 provers, only 1 participant → 1*3 < 3*2 → rejected.
        let provers: Vec<_> = (0..3u8)
            .map(|i| fake_prover(i + 1, i as u64, 0, &filter))
            .collect();
        let md = ShardMetadata::default();
        assert!(build_shard_update_context(&header, provers, &[0usize], md).is_err());
    }

    #[test]
    fn build_context_default_shard_count_of_one() {
        let filter = vec![0xAAu8; 32];
        let header = fake_header(filter.clone(), 10);
        let p = fake_prover(1, 1, 0, &filter);
        let md = ShardMetadata {
            state_size: 1000,
            shard_count: 0,
        };
        let ctx = build_shard_update_context(&header, vec![p], &[0usize], md).unwrap();
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
        assert_eq!(
            read_bal(),
            BigInt::from(1500),
            "reward must not double-credit a frame"
        );
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
        assert_eq!(
            read_bal(&state, &p),
            BigInt::from(1500),
            "both shards accrue"
        );

        // Dual-path re-materialize of the SAME (frame, shard) is idempotent.
        assert!(!apply_reward(&state, 100, &p, &shard_a, &BigInt::from(999)).unwrap());
        assert!(!apply_reward(&state, 100, &p, &shard_b, &BigInt::from(999)).unwrap());
        assert_eq!(
            read_bal(&state, &p),
            BigInt::from(1500),
            "same (frame,shard) no double-credit"
        );

        // A strictly older frame re-materialized is skipped (already credited).
        assert!(!apply_reward(&state, 99, &p, &shard_a, &BigInt::from(777)).unwrap());
        assert_eq!(
            read_bal(&state, &p),
            BigInt::from(1500),
            "older frame skipped"
        );

        // The NEXT frame resets the per-frame set — the same shard credits again.
        assert!(apply_reward(&state, 101, &p, &shard_a, &BigInt::from(200)).unwrap());
        assert_eq!(
            read_bal(&state, &p),
            BigInt::from(1700),
            "new frame credits again"
        );
    }

    /// Cost of one participant's activity update and its parts, for
    /// shard-header execution time (mainnet: ~9 ms per participant).
    #[test]
    #[ignore = "measurement"]
    fn measure_participant_activity_update() {
        let filter = vec![0xAAu8; 35];
        let state = make_state();
        let mut prover = fake_prover(1, 1, 0, &filter);
        prover.public_key = vec![7u8; 897];
        seed_alloc_blob(&state, &prover, &filter);
        let n = 200u32;
        let time = |what: &str, f: &mut dyn FnMut()| {
            let started = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            eprintln!("{what}: {:?} each", started.elapsed() / n);
        };
        time("allocation_address", &mut || {
            allocation_address(&prover.public_key, &filter).unwrap();
        });
        let alloc_addr = allocation_address(&prover.public_key, &filter).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
            .unwrap()
            .unwrap();
        time("rebuild tree", &mut || {
            rebuild_vertex_tree_from_blob(&blob);
        });
        let tree = rebuild_vertex_tree_from_blob(&blob);
        time("serialize tree", &mut || {
            vertex_tree_to_blob(&tree);
        });
        let mut frame = 100u64;
        time("state.set", &mut || {
            frame += 1;
            state
                .set(
                    &GLOBAL_INTRINSIC_ADDRESS[..],
                    &alloc_addr,
                    &va_disc,
                    frame,
                    blob.clone(),
                )
                .unwrap();
        });
        time("update_allocation_activity", &mut || {
            frame += 1;
            update_allocation_activity(&state, frame, &prover, &filter).unwrap();
        });
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
        let v = read_field(
            &tree,
            "allocation:ProverAllocation",
            "LastActiveFrameNumber",
        )
        .unwrap();
        assert_eq!(v, 77u64.to_be_bytes().to_vec());
    }

    /// The allocation blob `update_allocation_activity` stores, and the blob
    /// of the seeded allocation with `edit` applied, for one update at `frame`
    /// with the signed frame recorded from `activation`.
    fn activity_blobs(
        frame: u64,
        activation: u64,
        edit: impl Fn(&mut quil_tries::VectorCommitmentTree),
    ) -> (Vec<u8>, Vec<u8>) {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        seed_alloc_blob(&state, &p, &filter);
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let read = || {
            state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
                .unwrap()
                .unwrap()
        };
        let mut expected = rebuild_vertex_tree_from_blob(&read());
        edit(&mut expected);
        update_allocation_activity_from(&state, frame, &p, &filter, activation).unwrap();
        (read(), vertex_tree_to_blob(&expected))
    }

    #[test]
    fn update_allocation_activity_writes_only_last_active_below_signed_frame_activation() {
        // Below the activation the allocation vertex is byte-identical to the
        // one written before `LastSignedFrameNumber` existed: LastActive only.
        let last_active_only = |tree: &mut quil_tries::VectorCommitmentTree| {
            materialize_frame_header_activity(tree, 77).unwrap();
        };
        for activation in [78, quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME] {
            let (written, expected) = activity_blobs(77, activation, last_active_only);
            assert_eq!(written, expected, "activation {activation}");
            let tree = rebuild_vertex_tree_from_blob(&written);
            let last_signed = read_field(
                &tree,
                "allocation:ProverAllocation",
                "LastSignedFrameNumber",
            );
            assert_eq!(last_signed, None);
        }
        // The production path uses the disabled default.
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        seed_alloc_blob(&state, &p, &filter);
        update_allocation_activity(&state, 77, &p, &filter).unwrap();
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
            .unwrap();
        assert_eq!(blob.unwrap(), activity_blobs(77, 78, last_active_only).1);
    }

    #[test]
    fn update_allocation_activity_sets_last_signed_from_signed_frame_activation() {
        // At and after the activation, one vertex write records both fields.
        for (frame, activation) in [(77u64, 77u64), (78, 77)] {
            let (written, expected) = activity_blobs(frame, activation, |tree| {
                materialize_frame_header_activity(tree, frame).unwrap();
                write_field(
                    tree,
                    "allocation:ProverAllocation",
                    "LastSignedFrameNumber",
                    &frame.to_be_bytes(),
                )
                .unwrap();
            });
            assert_eq!(written, expected, "frame {frame}");
            let tree = rebuild_vertex_tree_from_blob(&written);
            for field in ["LastActiveFrameNumber", "LastSignedFrameNumber"] {
                assert_eq!(
                    read_field(&tree, "allocation:ProverAllocation", field),
                    Some(frame.to_be_bytes().to_vec()),
                    "{field} at frame {frame}"
                );
            }
        }
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
            fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> {
                Ok(None)
            }
            fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> {
                Ok(Vec::new())
            }
            fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
                Ok(0)
            }
            fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_prover_shard_summaries(
                &self,
                _frame_number: u64,
            ) -> Result<Vec<quil_types::consensus::ProverShardSummary>> {
                Ok(Vec::new())
            }
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
            fn prove_global_frame_header(
                &self,
                _: &quil_types::proto::global::GlobalFrameHeader,
                _: &[Vec<u8>],
                _: &[u8],
                _: &[Vec<u8>],
                _: &[u8],
                _: u64,
                _: &dyn quil_types::crypto::Signer,
                _: i64,
                _: u32,
                _: u8,
            ) -> Result<quil_types::proto::global::GlobalFrameHeader> {
                Err(QuilError::InvalidArgument("noop".into()))
            }
            fn verify_global_frame_header(
                &self,
                _: &quil_types::proto::global::GlobalFrameHeader,
            ) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn calculate_multi_proof(
                &self,
                _: &[u8; 32],
                _: u32,
                _: &[&[u8]],
                _: u32,
            ) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn verify_multi_proof(
                &self,
                _: &[u8; 32],
                _: u32,
                _: &[&[u8]],
                _: &[&[u8]],
            ) -> Result<bool> {
                Ok(true)
            }
        }
        let frame_prover: Arc<dyn FrameProver> = Arc::new(NoopFrameProver);

        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        materialize_prover_shard_update(
            &header,
            11, // current frame = header.frame + 1
            &state,
            &registry,
            &frame_prover,
            &reward_issuance,
            4096,
            vec![p.clone()],
            &[0usize],
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
        let lafn = read_field(
            &atree,
            "allocation:ProverAllocation",
            "LastActiveFrameNumber",
        )
        .unwrap();
        assert_eq!(lafn, 11u64.to_be_bytes().to_vec());
    }

    // ---- Partial-ring reward distribution.

    fn noop_registry() -> Arc<dyn ProverRegistry> {
        struct R;
        impl ProverRegistry for R {
            fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> {
                Ok(None)
            }
            fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> {
                Ok(Vec::new())
            }
            fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
                Ok(0)
            }
            fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> {
                Ok(Vec::new())
            }
            fn get_prover_shard_summaries(
                &self,
                _: u64,
            ) -> Result<Vec<quil_types::consensus::ProverShardSummary>> {
                Ok(Vec::new())
            }
        }
        Arc::new(R)
    }
    fn noop_frame_prover() -> Arc<dyn FrameProver> {
        struct F;
        impl FrameProver for F {
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
            fn prove_global_frame_header(
                &self,
                _: &quil_types::proto::global::GlobalFrameHeader,
                _: &[Vec<u8>],
                _: &[u8],
                _: &[Vec<u8>],
                _: &[u8],
                _: u64,
                _: &dyn quil_types::crypto::Signer,
                _: i64,
                _: u32,
                _: u8,
            ) -> Result<quil_types::proto::global::GlobalFrameHeader> {
                Err(QuilError::InvalidArgument("noop".into()))
            }
            fn verify_global_frame_header(
                &self,
                _: &quil_types::proto::global::GlobalFrameHeader,
            ) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn calculate_multi_proof(
                &self,
                _: &[u8; 32],
                _: u32,
                _: &[&[u8]],
                _: u32,
            ) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn verify_multi_proof(
                &self,
                _: &[u8; 32],
                _: u32,
                _: &[&[u8]],
                _: &[&[u8]],
            ) -> Result<bool> {
                Ok(true)
            }
        }
        Arc::new(F)
    }
    fn reward_balance(state: &HypergraphState, prover: &ProverInfo) -> BigInt {
        let reward_addr = reward_address(&prover.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        match state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
            .unwrap()
        {
            Some(blob) => {
                let tree = rebuild_vertex_tree_from_blob(&blob);
                let b = read_field(&tree, "reward:ProverReward", "Balance").unwrap_or_default();
                BigInt::from_bytes_be(num_bigint::Sign::Plus, &b)
            }
            None => BigInt::from(0),
        }
    }

    /// The previous frame's `fee_total` is paid to the frame's participants on
    /// top of the PoMW share: equal split, remainder to the frame's prover,
    /// under the same per-(frame, shard) idempotency guard.
    #[test]
    fn shard_update_pays_fee_total_to_participants() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let provers: Vec<ProverInfo> = (1u8..=3)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let mut header = fake_header(filter.clone(), 10);
        // 1_000 split three ways: 333 each, remainder 1 to the frame prover.
        header.fee_total = super::super::frame_header::fee_total_to_bytes(1_000);
        header.prover = provers[1].address.clone();
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &[0, 1, 2],
            md,
        )
        .unwrap();

        assert_eq!(
            reward_balance(&state, &provers[0]),
            BigInt::from(1_000 + 333)
        );
        assert_eq!(
            reward_balance(&state, &provers[1]),
            BigInt::from(1_000 + 334)
        );
        assert_eq!(
            reward_balance(&state, &provers[2]),
            BigInt::from(1_000 + 333)
        );

        // Re-materializing the same (frame, shard) credits nothing more.
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };
        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &[0, 1, 2],
            md,
        )
        .unwrap();
        assert_eq!(reward_balance(&state, &provers[1]), BigInt::from(1_334));

        // A frame prover that did not participate: the remainder goes to the
        // lowest-index participant instead.
        let mut header2 = fake_header(filter.clone(), 12);
        header2.fee_total = super::super::frame_header::fee_total_to_bytes(5);
        header2.prover = vec![0x99u8; 32];
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };
        materialize_prover_shard_update(
            &header2,
            13,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &[1, 2],
            md,
        )
        .unwrap();
        assert_eq!(
            reward_balance(&state, &provers[0]),
            BigInt::from(1_333),
            "non-participant unchanged"
        );
        assert_eq!(
            reward_balance(&state, &provers[1]),
            BigInt::from(1_334 + 1_000 + 3)
        );
        assert_eq!(
            reward_balance(&state, &provers[2]),
            BigInt::from(1_333 + 1_000 + 2)
        );
    }

    /// Records the difficulty each issuance calculation was priced at.
    struct DifficultyProbe(std::sync::Mutex<Vec<u64>>);
    impl RewardIssuance for DifficultyProbe {
        fn calculate(
            &self,
            difficulty: u64,
            _world_state_bytes: u64,
            _units: u64,
            provers: &[HashMap<String, ProverAllocation>],
        ) -> Result<Vec<BigInt>> {
            self.0.lock().unwrap().push(difficulty);
            Ok(provers.iter().map(|_| BigInt::from(8_000)).collect())
        }
    }

    /// Under the anchored issuance rules a leader's difficulty below the
    /// square-root generation (about 32 times the issuance at a 1 TiB world)
    /// prices nothing: GLOBAL prices the anchor's difficulty. An honest
    /// header, whose leader wrote GLOBAL's latest difficulty, keeps exactly
    /// the issuance it had, since issuance depends on difficulty only through
    /// its generation.
    #[test]
    fn anchored_issuance_ignores_the_leaders_difficulty() {
        let world = 1u64 << 40;
        let basis = |difficulty| crate::pricing::pomw_basis(difficulty, world, REWARD_UNITS);
        let mut inflated = fake_header(vec![0xABu8; 32], 10);
        inflated.difficulty = 1;
        inflated.global_frame_number = 900;
        let mut honest = inflated.clone();
        honest.difficulty = 150_000;

        assert_eq!(
            anchored_issuance_difficulty(&inflated, Some(160_000)),
            160_000
        );
        assert_eq!(
            basis(anchored_issuance_difficulty(&inflated, Some(160_000))),
            basis(u64::from(honest.difficulty)),
            "an inflated claim earns what an honest one does"
        );
        assert!(
            basis(HeaderIssuance::claimed(&inflated).difficulty)
                > basis(150_000) * BigInt::from(30),
            "the leader's claim alone prices over 30 times the issuance"
        );
        assert_eq!(
            basis(anchored_issuance_difficulty(&honest, Some(160_000))),
            basis(HeaderIssuance::claimed(&honest).difficulty),
            "an honest header's issuance is unchanged"
        );

        // A header without an anchor keeps its own difficulty, floored at
        // the square-root generation.
        inflated.global_frame_number = 0;
        honest.global_frame_number = 0;
        assert_eq!(
            anchored_issuance_difficulty(&inflated, None),
            ISSUANCE_MIN_DIFFICULTY
        );
        assert_eq!(anchored_issuance_difficulty(&honest, None), 150_000);
        assert_eq!(crate::pricing::pomw_generation(ISSUANCE_MIN_DIFFICULTY), 1);
        assert_eq!(
            crate::pricing::pomw_generation(ISSUANCE_MIN_DIFFICULTY - 1),
            0
        );
    }

    /// The materializer prices issuance at the difficulty it is given, and a
    /// header it is told not to credit earns no issuance, fees or activity.
    #[test]
    fn a_header_not_credited_earns_nothing() {
        let state = make_state();
        let filter = vec![0xACu8; 32];
        let provers: Vec<ProverInfo> = (1u8..=3)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let mut header = fake_header(filter.clone(), 10);
        header.difficulty = 1;
        header.fee_total = super::super::frame_header::fee_total_to_bytes(900);
        let probe = Arc::new(DifficultyProbe(std::sync::Mutex::new(Vec::new())));
        let reward_issuance: Arc<dyn RewardIssuance> = probe.clone();
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };
        let last_active = |p: &ProverInfo| {
            let address = allocation_address(&p.public_key, &filter).unwrap();
            let blob = state
                .get(
                    &GLOBAL_INTRINSIC_ADDRESS[..],
                    &address,
                    &vertex_adds_discriminator().unwrap(),
                )
                .unwrap()
                .unwrap();
            read_prover_u64(
                &rebuild_vertex_tree_from_blob(&blob),
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
            )
        };
        let materialize = |frame: u64, issuance: HeaderIssuance| {
            materialize_prover_shard_update_with_fees(
                &header,
                frame,
                &state,
                &noop_registry(),
                &noop_frame_prover(),
                &reward_issuance,
                4096,
                provers.clone(),
                &[0, 1, 2],
                md,
                0,
                None,
                None,
                issuance,
            )
            .unwrap()
        };

        materialize(
            11,
            HeaderIssuance {
                difficulty: 160_000,
                credit: true,
            },
        );
        assert_eq!(*probe.0.lock().unwrap(), vec![160_000]);
        let credited = reward_balance(&state, &provers[0]);
        assert_eq!(credited, BigInt::from(1_000 + 300));
        assert_eq!(last_active(&provers[0]), 11);

        // The same header again in a later GLOBAL frame.
        materialize(
            12,
            HeaderIssuance {
                difficulty: 160_000,
                credit: false,
            },
        );
        assert_eq!(probe.0.lock().unwrap().len(), 1, "not priced");
        assert_eq!(reward_balance(&state, &provers[0]), credited);
        assert_eq!(last_active(&provers[0]), 11, "activity not refreshed");

        // Before the epoch the leader's difficulty prices it, every time.
        materialize(13, HeaderIssuance::claimed(&header));
        assert_eq!(*probe.0.lock().unwrap(), vec![160_000, 1]);
        assert_eq!(reward_balance(&state, &provers[0]), BigInt::from(2 * 1_300));
    }

    /// Hash-proof epochs (decided 2026-10-21): a participant's issuance share
    /// is held in its storage seat, and only with a sealed registration; each
    /// frame counts toward the proposals expected of it, and a proposer's
    /// root is chained into its seat; fees are paid at once.
    #[test]
    fn a_hash_epoch_frame_holds_issuance_in_sealed_seats_and_pays_fees() {
        use super::super::storage_seat::{self, Seat};
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let provers: Vec<ProverInfo> = (1u8..=3)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let epoch = 7;
        let member = |p: &ProverInfo| <[u8; 32]>::try_from(p.address.as_slice()).unwrap();
        // The first two hold sealed registrations, the third none.
        for p in &provers[..2] {
            let mut seat = Seat::new(member(p), filter.clone());
            seat.register(epoch, &[vec![]], 10);
            assert!(seat.seal(epoch, 11));
            storage_seat::write(&state, 11, &seat).unwrap();
        }
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let rho_n = vec![5u8; 32];
        let distribute = |header: &FrameHeader, frame: u64| {
            let commitment = storage_seat::decode_commitment(&header.storage_attestation_root).map(
                |(root, beacon)| StorageCommitment {
                    root,
                    beacon,
                    rho_n: rho_n.clone(),
                },
            );
            let mut storage = StorageFrame {
                epoch,
                commitment,
                kicks: Vec::new(),
            };
            materialize_prover_shard_update_with_fees(
                header,
                frame,
                &state,
                &noop_registry(),
                &noop_frame_prover(),
                &reward_issuance,
                4096,
                provers.clone(),
                &[0, 1, 2],
                ShardMetadata {
                    state_size: 1024,
                    shard_count: 1,
                },
                0,
                None,
                Some(&mut storage),
                HeaderIssuance::claimed(header),
            )
            .unwrap();
            storage.kicks
        };
        let pending = |p: &ProverInfo| {
            storage_seat::read(&state, &member(p), &filter)
                .unwrap()
                .map(|seat| seat.slot(epoch).unwrap().pending_amount())
        };

        let mut header = fake_header(filter.clone(), 10);
        header.fee_total = super::super::frame_header::fee_total_to_bytes(300);
        header.prover = provers[1].address.clone();
        assert!(distribute(&header, 100).is_empty());
        for p in &provers {
            assert_eq!(
                reward_balance(&state, p),
                BigInt::from(100),
                "fees only, at once"
            );
        }
        assert_eq!(pending(&provers[0]), Some(BigInt::from(1_000)));
        assert_eq!(pending(&provers[1]), Some(BigInt::from(1_000)));
        assert_eq!(
            pending(&provers[2]),
            None,
            "no sealed registration, no share"
        );
        let slot = |p: &ProverInfo| {
            storage_seat::read(&state, &member(p), &filter)
                .unwrap()
                .unwrap()
                .slot(epoch)
                .cloned()
                .unwrap()
        };
        assert_eq!(
            (slot(&provers[1]).frames, slot(&provers[1]).expected),
            (0, storage_seat::PROPOSAL / 3),
            "its own frame committed no root: a proposal expected, none published"
        );

        let mut header = fake_header(filter.clone(), 11);
        header.prover = provers[1].address.clone();
        header.storage_attestation_root = storage_seat::encode_commitment(&[0x11; 32], 98);
        distribute(&header, 101);
        assert_eq!(pending(&provers[0]), Some(BigInt::from(2_000)));
        assert_eq!(pending(&provers[1]), Some(BigInt::from(2_000)));
        let committed = slot(&provers[1]);
        assert_eq!(
            (
                committed.frames,
                committed.accumulator,
                committed.chained.clone()
            ),
            (
                1,
                storage_seat::chain([(11, rho_n.as_slice(), &[0x11u8; 32])]),
                vec![storage_seat::Chained {
                    frame: 11,
                    beacon: 98,
                    executed: 101
                }]
            )
        );
        assert_eq!(committed.expected, 2 * (storage_seat::PROPOSAL / 3));
        distribute(&header, 101);
        assert_eq!(
            pending(&provers[1]),
            Some(BigInt::from(2_000)),
            "the same frame applied again"
        );
        assert_eq!(slot(&provers[1]), committed);
    }

    /// Suspend storage kicks from `epoch` on this thread; `None` restores
    /// the process setting.
    fn suspend_storage_kicks(epoch: Option<u64>) {
        quil_types::consensus::set_storage_kick_suspension_epoch_for_thread(epoch);
    }

    /// The frame path: a participant whose seat closes an epoch with a root
    /// it never proved is kicked (`storage.kicks`) by a GLOBAL frame before
    /// the storage kick suspension epoch, and not by its first frame. Its
    /// held share stays unpaid either way.
    #[test]
    fn from_the_suspension_epoch_the_frame_path_withholds_without_a_kick() {
        use super::super::storage_seat::{self, Seat};
        let length = quil_types::consensus::epoch_length_frames();
        let (epoch, suspension) = (5, 8);
        let flag = suspension * length;
        for (frame, kicked) in [(flag - 1, true), (flag, false)] {
            suspend_storage_kicks(Some(suspension));
            let state = make_state();
            let filter = vec![0xA9u8; 32];
            let provers: Vec<ProverInfo> = (1u8..=2)
                .map(|s| fake_prover(s, s as u64, 0, &filter))
                .collect();
            for p in &provers {
                seed_alloc_blob(&state, p, &filter);
            }
            let member = <[u8; 32]>::try_from(provers[0].address.as_slice()).unwrap();
            let mut seat = Seat::new(member, filter.clone());
            seat.register(epoch, &[vec![]], 10);
            assert!(seat.seal(epoch, 11));
            assert!(seat.hold(epoch, 12, 40, &BigInt::from(1_000), 2));
            assert!(seat.commit(epoch, 40, 11, 12, &[1; 32], &[2; 32]));
            storage_seat::write(&state, 12, &seat).unwrap();

            let reward_issuance: Arc<dyn RewardIssuance> =
                Arc::new(StubReward(BigInt::from(8_000)));
            let mut storage = StorageFrame {
                epoch: quil_types::consensus::epoch_for_frame(frame),
                commitment: None,
                kicks: Vec::new(),
            };
            let header = fake_header(filter.clone(), 60);
            materialize_prover_shard_update_with_fees(
                &header,
                frame,
                &state,
                &noop_registry(),
                &noop_frame_prover(),
                &reward_issuance,
                4096,
                provers.clone(),
                &[0, 1],
                ShardMetadata {
                    state_size: 1024,
                    shard_count: 1,
                },
                0,
                None,
                Some(&mut storage),
                HeaderIssuance::claimed(&header),
            )
            .unwrap();
            let expected: Vec<Vec<u8>> = if kicked {
                vec![member.to_vec()]
            } else {
                Vec::new()
            };
            assert_eq!(
                storage.kicks, expected,
                "GLOBAL frame {frame} (suspension from {flag}): a seat expiring from the \
                 suspension epoch kicked its member on the frame path"
            );
            let slot = storage_seat::read(&state, &member, &filter)
                .unwrap()
                .unwrap()
                .slot(epoch)
                .cloned()
                .unwrap();
            assert_eq!(slot.outcome, storage_seat::Outcome::Expired(frame));
            assert_eq!(slot.pending_amount(), BigInt::from(1_000), "withheld");
        }
        suspend_storage_kicks(None);
    }

    /// Distribute `header` to all of `provers` as an app frame anchored in
    /// hash-proof epoch `epoch` and executed in GLOBAL frame `frame`, with an
    /// issuance share of 1,000 per participant and no openings root.
    fn distribute_hash_epoch_frame(
        state: &HypergraphState,
        provers: &[ProverInfo],
        header: &FrameHeader,
        frame: u64,
        epoch: u64,
    ) {
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let participants: Vec<usize> = (0..provers.len()).collect();
        let mut storage = StorageFrame {
            epoch,
            commitment: None,
            kicks: Vec::new(),
        };
        materialize_prover_shard_update_with_fees(
            header,
            frame,
            state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.to_vec(),
            &participants,
            ShardMetadata {
                state_size: 1024,
                shard_count: 1,
            },
            0,
            None,
            Some(&mut storage),
            HeaderIssuance::claimed(header),
        )
        .unwrap();
    }

    /// Give `p` a seat on `filter` registered for `epoch`, sealed or not.
    fn give_seat(state: &HypergraphState, p: &ProverInfo, filter: &[u8], epoch: u64, seal: bool) {
        use super::super::storage_seat::{self, Seat};
        let member = <[u8; 32]>::try_from(p.address.as_slice()).unwrap();
        let mut seat = Seat::new(member, filter.to_vec());
        seat.register(epoch, &[vec![]], 10);
        if seal {
            assert!(seat.seal(epoch, 11));
        }
        storage_seat::write(state, 11, &seat).unwrap();
    }

    /// What `p`'s seat on `filter` holds for `epoch`; `None` without a seat.
    fn held_share(
        state: &HypergraphState,
        p: &ProverInfo,
        filter: &[u8],
        epoch: u64,
    ) -> Option<BigInt> {
        let member = <[u8; 32]>::try_from(p.address.as_slice()).unwrap();
        super::super::storage_seat::read(state, &member, filter)
            .unwrap()
            .and_then(|seat| seat.slot(epoch).map(|slot| slot.pending_amount()))
    }

    /// Start (or stop) the unsealed issuance rule from epoch 0 on this thread.
    fn pay_unsealed_issuance(on: bool) {
        quil_types::consensus::set_unsealed_issuance_epoch_for_thread(on.then_some(0));
    }

    /// Hash-proof epochs under the unsealed issuance rule: a participant
    /// without a sealed registration for the shard and epoch (no seat, or a
    /// registration its labelling never sealed) is paid its issuance share
    /// at once with its fees, while a sealed member's share is still held in
    /// its seat. Without the rule the former earned fees only, which is what
    /// almost every mainnet participant earned from epoch 1314.
    #[test]
    fn an_unsealed_participant_is_paid_its_hash_epoch_issuance_share() {
        pay_unsealed_issuance(true);
        let state = make_state();
        let filter = vec![0xA7u8; 32];
        let provers: Vec<ProverInfo> = (1u8..=3)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let epoch = 7;
        give_seat(&state, &provers[0], &filter, epoch, true);
        give_seat(&state, &provers[2], &filter, epoch, false);
        let mut header = fake_header(filter.clone(), 10);
        header.fee_total = super::super::frame_header::fee_total_to_bytes(300);
        header.prover = provers[0].address.clone();

        distribute_hash_epoch_frame(&state, &provers, &header, 100, epoch);

        for p in &provers[1..] {
            assert_eq!(
                reward_balance(&state, p),
                BigInt::from(1_000 + 100),
                "a participant without a sealed registration must earn its issuance share \
                 with its fees, not its fees only"
            );
        }
        assert_eq!(
            reward_balance(&state, &provers[0]),
            BigInt::from(100),
            "a sealed member is paid its fees at once"
        );
        assert_eq!(
            held_share(&state, &provers[0], &filter, epoch),
            Some(BigInt::from(1_000)),
            "and its share is held in its seat"
        );
        assert_eq!(
            held_share(&state, &provers[2], &filter, epoch),
            Some(BigInt::from(0)),
            "an unsealed registration holds nothing"
        );
        pay_unsealed_issuance(false);
    }

    /// The unsealed issuance rule starts at its epoch, by the GLOBAL frame
    /// executing the header: before it an unsealed participant earns nothing
    /// of a hash-proof frame's issuance. Under it a sealed member's share is
    /// still only held, never also paid, and a frame applied again in the
    /// same GLOBAL frame pays no one twice.
    #[test]
    fn unsealed_issuance_starts_at_its_epoch_and_leaves_sealed_seats_held() {
        let length = quil_types::consensus::epoch_length_frames();
        quil_types::consensus::set_unsealed_issuance_epoch_for_thread(Some(1));
        let state = make_state();
        let filter = vec![0xA8u8; 32];
        let provers: Vec<ProverInfo> = (1u8..=2)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let epoch = 7;
        give_seat(&state, &provers[0], &filter, epoch, true);
        let (sealed, unsealed) = (&provers[0], &provers[1]);

        let header = fake_header(filter.clone(), 10);
        distribute_hash_epoch_frame(&state, &provers, &header, length - 1, epoch);
        assert_eq!(
            reward_balance(&state, unsealed),
            BigInt::from(0),
            "before the rule's epoch"
        );
        assert_eq!(
            held_share(&state, sealed, &filter, epoch),
            Some(BigInt::from(1_000))
        );

        let header = fake_header(filter.clone(), 11);
        distribute_hash_epoch_frame(&state, &provers, &header, length, epoch);
        assert_eq!(reward_balance(&state, unsealed), BigInt::from(1_000));
        assert_eq!(
            reward_balance(&state, sealed),
            BigInt::from(0),
            "a sealed member's share is never paid at once"
        );
        assert_eq!(
            held_share(&state, sealed, &filter, epoch),
            Some(BigInt::from(2_000))
        );

        distribute_hash_epoch_frame(&state, &provers, &header, length, epoch);
        assert_eq!(
            reward_balance(&state, unsealed),
            BigInt::from(1_000),
            "the same frame applied again pays nothing again"
        );
        assert_eq!(reward_balance(&state, sealed), BigInt::from(0));
        assert_eq!(
            held_share(&state, sealed, &filter, epoch),
            Some(BigInt::from(2_000))
        );
        quil_types::consensus::set_unsealed_issuance_epoch_for_thread(None);
    }

    /// Global-venue fees go to the global frame's prover under the global
    /// filter, independent of a shard credit at the same frame.
    #[test]
    fn global_frame_fees_credit_the_global_prover() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let p = fake_prover(1, 1, 0, &filter);
        assert!(!credit_global_frame_fees(&state, 20, &p.address, 0).unwrap());
        assert!(credit_global_frame_fees(&state, 20, &p.address, 700).unwrap());
        assert_eq!(reward_balance(&state, &p), BigInt::from(700));
        // Repeat at the same frame is idempotent.
        assert!(!credit_global_frame_fees(&state, 20, &p.address, 700).unwrap());
        assert_eq!(reward_balance(&state, &p), BigInt::from(700));
        // A shard credit at the same frame still lands (different filter).
        assert!(apply_reward(&state, 20, &p, &filter, &BigInt::from(50)).unwrap());
        assert_eq!(reward_balance(&state, &p), BigInt::from(750));
        // Later frame accrues again.
        assert!(credit_global_frame_fees(&state, 21, &p.address, 1).unwrap());
        assert_eq!(reward_balance(&state, &p), BigInt::from(751));
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
        let provers: Vec<ProverInfo> = (1u8..=6)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
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
            assert_eq!(
                bal,
                BigInt::from(1_000),
                "each ring member gets outputs[0]/8"
            );
            total += bal;
        }
        assert_eq!(
            total,
            BigInt::from(6_000),
            "partial ring under-mints to N/8"
        );
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
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            vec![p.clone()],
            &[0usize],
            md,
        )
        .unwrap();

        // No reward vertex written (share == 0).
        let reward_addr = reward_address(&p.address).unwrap();
        let va_disc = vertex_adds_discriminator().unwrap();
        assert!(
            state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &reward_addr, &va_disc)
                .unwrap()
                .is_none(),
            "zero share must not write a reward vertex"
        );
        // But activity still bumped.
        let alloc_addr = allocation_address(&p.public_key, &filter).unwrap();
        let atree = rebuild_vertex_tree_from_blob(
            &state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc_addr, &va_disc)
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            read_field(
                &atree,
                "allocation:ProverAllocation",
                "LastActiveFrameNumber"
            )
            .unwrap(),
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
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            vec![p.clone()],
            &[0usize],
            md,
        )
        .unwrap();

        // Prover's own reward vertex got the credit.
        assert_eq!(reward_balance(&state, &p), BigInt::from(1_000));
        // The delegate address has NO reward vertex.
        let va_disc = vertex_adds_discriminator().unwrap();
        let delegate_reward = reward_address(&delegate).unwrap();
        assert!(
            state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &delegate_reward, &va_disc)
                .unwrap()
                .is_none(),
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
                &self,
                _: u64,
                _: u64,
                _: u64,
                provers: &[HashMap<String, ProverAllocation>],
            ) -> Result<Vec<BigInt>> {
                let ring = provers
                    .first()
                    .and_then(|m| m.values().next())
                    .map(|a| a.ring)
                    .unwrap_or(0);
                Ok(provers
                    .iter()
                    .map(|_| BigInt::from(8_000u64 >> ring))
                    .collect())
            }
        }
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        // 9 provers, ranks 0..8 → ring 0 (ranks 0-7) + ring 1 (rank 8). Ring is
        // now the STORED per-allocation value (set at confirmation); materialize
        // reads it rather than re-sorting by seniority. Assign by rank here.
        let mut provers: Vec<ProverInfo> = (1u8..=9)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for (i, p) in provers.iter_mut().enumerate() {
            if let Some(alloc) = p
                .allocations
                .iter_mut()
                .find(|a| a.confirmation_filter == filter)
            {
                alloc.ring = (i / RING_GROUP_SIZE as usize) as u8;
            }
        }
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(RingStub);
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };
        let indices: Vec<usize> = (0..9).collect();

        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &indices,
            md,
        )
        .unwrap();

        // First 8 (ring 0) get 1000; the 9th (ring 1) gets 500.
        for p in &provers[..8] {
            assert_eq!(
                reward_balance(&state, p),
                BigInt::from(1_000),
                "ring-0 member share"
            );
        }
        assert_eq!(
            reward_balance(&state, &provers[8]),
            BigInt::from(500),
            "ring-1 member share"
        );
    }

    #[test]
    fn signer_indices_above_255_retain_their_fee_share_and_activity() {
        let state = make_state();
        let filter = vec![0xA9; 32];
        let provers: Vec<_> = (0..300usize)
            .map(|i| {
                let mut prover = fake_prover(1, i as u64 + 1, 0, &filter);
                prover.public_key[..8].copy_from_slice(&(i as u64).to_be_bytes());
                prover.address = prover_address_from_pubkey(&prover.public_key)
                    .unwrap()
                    .to_vec();
                prover.allocations[0].ring = (i / RING_GROUP_SIZE as usize) as u8;
                prover
            })
            .collect();
        for prover in &provers {
            seed_alloc_blob(&state, prover, &filter);
        }
        let mut header = fake_header(filter.clone(), 10);
        // 240 certified signers (indices 60..299) each receive one fee unit.
        header.fee_total = super::super::frame_header::fee_total_field(240);
        let mut bitmap = Vec::new();
        for i in 60..300 {
            quil_consensus::bitmask::set_bit(&mut bitmap, i);
        }
        let indices: Vec<usize> = quil_consensus::bitmask::set_bit_indices(&bitmap).collect();
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(0)));
        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &indices,
            ShardMetadata {
                state_size: 1024,
                shard_count: 1,
            },
        )
        .unwrap();
        let discriminator = vertex_adds_discriminator().unwrap();
        for (i, prover) in provers.iter().enumerate() {
            assert_eq!(
                reward_balance(&state, prover),
                BigInt::from(u8::from(i >= 60)),
                "fee for member {i}"
            );
            let address = allocation_address(&prover.public_key, &filter).unwrap();
            let blob = state
                .get(&GLOBAL_INTRINSIC_ADDRESS, &address, &discriminator)
                .unwrap()
                .unwrap();
            let tree = rebuild_vertex_tree_from_blob(&blob);
            let last_active = read_field(
                &tree,
                "allocation:ProverAllocation",
                "LastActiveFrameNumber",
            );
            assert_eq!(
                last_active,
                if i >= 60 {
                    Some(11u64.to_be_bytes().to_vec())
                } else {
                    None
                },
                "activity for member {i}"
            );
        }
        let context =
            build_shard_update_context(&header, provers, &indices, ShardMetadata::default())
                .unwrap();
        assert_eq!(context.participant_indices.len(), 240);
        assert_eq!(context.participant_indices.last(), Some(&299));
    }

    /// The participant index list binds to POSITION in `active_provers`: index 0
    /// and 2 are credited, index 1 (skipped) is not — a reorder would
    /// misattribute rewards, so this guards the consensus determinism.
    #[test]
    fn participant_indices_bind_to_active_prover_position() {
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let provers: Vec<ProverInfo> = (1u8..=3)
            .map(|s| fake_prover(s, s as u64, 0, &filter))
            .collect();
        for p in &provers {
            seed_alloc_blob(&state, p, &filter);
        }
        let header = fake_header(filter.clone(), 10);
        let reward_issuance: Arc<dyn RewardIssuance> = Arc::new(StubReward(BigInt::from(8_000)));
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };

        // Participants = positions 0 and 2 (skip position 1). 2 of 3 ≥ 2/3.
        materialize_prover_shard_update(
            &header,
            11,
            &state,
            &noop_registry(),
            &noop_frame_prover(),
            &reward_issuance,
            4096,
            provers.clone(),
            &[0, 2],
            md,
        )
        .unwrap();

        assert_eq!(
            reward_balance(&state, &provers[0]),
            BigInt::from(1_000),
            "index 0 credited"
        );
        assert_eq!(
            reward_balance(&state, &provers[1]),
            BigInt::from(0),
            "index 1 (skipped) not credited"
        );
        assert_eq!(
            reward_balance(&state, &provers[2]),
            BigInt::from(1_000),
            "index 2 credited"
        );
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
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
            Ok(vec![0u8; 74])
        }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
            Ok(true)
        }
        fn prove_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
        ) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("batch not supported".into()))
        }
        fn verify_multiple(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
            _: &[u64],
            _: u64,
            _: &[u8],
            _: &[u8],
        ) -> bool {
            true
        }
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
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            Arc::new(StubProver),
        ));
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
            p.allocations
                .iter()
                .find(|a| a.confirmation_filter == filter)
                .unwrap()
                .ring
        };

        // 10 active provers, join frames 10,20,…,100 (distinct, ascending by
        // seed; addresses also ascend by seed) → ranks 0..9.
        let mut provers: Vec<ProverInfo> = (1u8..=10)
            .map(|s| fake_prover(s, (s as u64) * 10, 0, &filter))
            .collect();
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
        assert_eq!(
            provers.iter().filter(|p| ring_of(p) == 1).count(),
            1,
            "one ring-1 after leave"
        );
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
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            Arc::new(Prover74),
        ));
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
        assert_eq!(
            reload(&shard_keys),
            share.clone(),
            "baseline reward durable"
        );

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
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            Arc::new(Prover74),
        ));
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
        assert_eq!(
            reload(&shard_keys),
            BigInt::from(2) * &share,
            "frames 0,1 durable"
        );

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
        assert_eq!(
            clock.get_global_materialized_cursor(),
            Some(3),
            "cursor advanced to head"
        );
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
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store,
            Arc::new(Prover74),
        ));
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

    /// A frame certified by an authorized session is rewarded at the rings
    /// recorded at the session's first rewarded frame. Before, each member's
    /// ring was read from its allocation at the frame's filter, so once a
    /// split or merge moved the members the whole update failed and no
    /// participant was paid.
    #[test]
    fn a_session_frame_keeps_its_rings_after_its_members_move() {
        use quil_types::crypto::Signer as _;
        struct RingStub;
        impl RewardIssuance for RingStub {
            fn calculate(
                &self,
                _: u64,
                _: u64,
                _: u64,
                provers: &[HashMap<String, ProverAllocation>],
            ) -> Result<Vec<BigInt>> {
                let ring = provers
                    .first()
                    .and_then(|m| m.values().next())
                    .map(|a| a.ring)
                    .unwrap_or(0);
                Ok(provers
                    .iter()
                    .map(|_| BigInt::from(8_000u64 >> ring))
                    .collect())
            }
        }
        let state = make_state();
        let filter = vec![0xAAu8; 32];
        let mut keys: Vec<Vec<u8>> = (0..9)
            .map(|_| quil_crypto::FalconSigner::generate().public_key().to_vec())
            .collect();
        keys.sort();
        let session = quil_cw_consensus::handoff::Session {
            chain_id: [0x11; 32],
            filter: filter.clone(),
            generation: 1,
            genesis: [0x33; 32],
            base_frame: 0,
            authorization: [0x22; 32],
            members: keys.clone(),
        };
        super::super::handoff::initialize(&state, 1, &session).unwrap();
        let id = session.id().unwrap();
        // Members in session order; the first-ordered key joined last, so it
        // alone ranks ninth (ring 1).
        let mut members: Vec<ProverInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let mut prover = fake_prover(
                    i as u8 + 1,
                    if i == 0 { 900 } else { 100 + i as u64 },
                    0,
                    &filter,
                );
                prover.public_key = key.clone();
                prover.address = prover_address_from_pubkey(key).unwrap().to_vec();
                prover
            })
            .collect();
        for prover in &members {
            seed_alloc_blob(&state, prover, &filter);
        }
        let issuance: Arc<dyn RewardIssuance> = Arc::new(RingStub);
        let md = ShardMetadata {
            state_size: 1024,
            shard_count: 1,
        };
        let everyone: Vec<usize> = (0..9).collect();
        let reward = |header_frame: u64, members: Vec<ProverInfo>, session: Option<[u8; 32]>| {
            let header = fake_header(filter.clone(), header_frame);
            materialize_prover_shard_update_with_fees(
                &header,
                header_frame + 1,
                &state,
                &noop_registry(),
                &noop_frame_prover(),
                &issuance,
                4096,
                members,
                &everyone,
                md,
                0,
                session,
                None,
                HeaderIssuance::claimed(&header),
            )
        };

        reward(10, members.clone(), Some(id)).unwrap();
        let mut rings = vec![0u8; 9];
        rings[0] = 1;
        assert_eq!(
            super::super::handoff::session_rings(&state, &id).unwrap(),
            Some(rings.clone())
        );
        assert_eq!(reward_balance(&state, &members[0]), BigInt::from(500));
        assert_eq!(reward_balance(&state, &members[1]), BigInt::from(1_000));

        // A split moves every member's allocation to a child filter.
        for prover in &mut members {
            prover.allocations[0].confirmation_filter = vec![0xAB; 34];
        }
        assert!(
            reward(11, members.clone(), None).is_err(),
            "the per-allocation rule fails once the members have moved",
        );
        reward(12, members.clone(), Some(id)).unwrap();
        assert_eq!(reward_balance(&state, &members[0]), BigInt::from(1_000));
        assert_eq!(reward_balance(&state, &members[1]), BigInt::from(2_000));
        assert_eq!(
            super::super::handoff::session_rings(&state, &id).unwrap(),
            Some(rings.clone())
        );
        assert!(
            super::super::handoff::record_session_rings(&state, 13, &id, &[0; 9]).is_err(),
            "a recorded snapshot is never replaced"
        );
    }

    // --- Seniority absence penalty (#976) ---------------------------------

    /// Committee members with prover vertices (seniority `seniority`) and
    /// allocations on `filter`.
    fn absence_committee(
        state: &HypergraphState,
        seeds: &[u8],
        filter: &[u8],
        seniority: u64,
    ) -> Vec<ProverInfo> {
        use crate::global_intrinsic::materialize::materialize_prover_join;
        let va_disc = vertex_adds_discriminator().unwrap();
        seeds
            .iter()
            .map(|&seed| {
                let mut prover = fake_prover(seed, 1, seniority, filter);
                let output =
                    materialize_prover_join(&prover.public_key, &[filter.to_vec()], 1, seniority)
                        .unwrap();
                prover.address = output.prover_address.to_vec();
                state
                    .set(
                        &GLOBAL_INTRINSIC_ADDRESS[..],
                        &output.prover_address,
                        &va_disc,
                        1,
                        vertex_tree_to_blob(&output.prover_tree),
                    )
                    .unwrap();
                seed_alloc_blob(state, &prover, filter);
                prover
            })
            .collect()
    }

    fn missed(state: &HypergraphState, prover: &ProverInfo, filter: &[u8]) -> u64 {
        let va_disc = vertex_adds_discriminator().unwrap();
        let address = allocation_address(&prover.public_key, filter).unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va_disc)
            .unwrap()
            .unwrap();
        read_prover_u64(
            &rebuild_vertex_tree_from_blob(&blob),
            "allocation:ProverAllocation",
            "AbsentFrameCount",
        )
    }

    fn seniority_of(state: &HypergraphState, prover: &ProverInfo) -> u64 {
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover.address, &va_disc)
            .unwrap()
            .unwrap();
        read_prover_u64(
            &rebuild_vertex_tree_from_blob(&blob),
            "prover:Prover",
            "Seniority",
        )
    }

    fn penalty_of(state: &HypergraphState, prover: &ProverInfo) -> u64 {
        let va_disc = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover.address, &va_disc)
            .unwrap()
            .unwrap();
        read_prover_u64(
            &rebuild_vertex_tree_from_blob(&blob),
            "prover:Prover",
            "SeniorityPenalty",
        )
    }

    /// Include app frame `app_frame` of `filter`, produced by `committee[0]`
    /// and signed by the members at `signers`, in GLOBAL frame `global`.
    fn include_frame(
        state: &HypergraphState,
        committee: &[ProverInfo],
        filter: &[u8],
        app_frame: u64,
        global: u64,
        signers: &[usize],
    ) {
        let mut header = fake_header(filter.to_vec(), app_frame);
        header.prover = committee[0].address.clone();
        let present = signers.iter().copied().collect();
        record_committee_absence(state, global, &header, committee, &present).unwrap();
    }

    /// A member that misses 721 consecutive frames its committee produced is
    /// charged for the 721st and each one after, once per frame.
    #[test]
    fn a_member_missing_721_produced_frames_is_charged() {
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(0));
        let state = make_state();
        let filter = vec![0xB1u8; 32];
        let committee = absence_committee(&state, &[1, 2], &filter, 1_000);
        for n in 1..=720 {
            include_frame(&state, &committee, &filter, n, 1_000 + n, &[0]);
        }
        assert_eq!(missed(&state, &committee[1], &filter), 720);
        assert_eq!(
            seniority_of(&state, &committee[1]),
            1_000,
            "the grace costs nothing"
        );
        include_frame(&state, &committee, &filter, 721, 1_721, &[0]);
        assert_eq!(missed(&state, &committee[1], &filter), 721);
        assert_eq!(seniority_of(&state, &committee[1]), 990);
        // A re-materialized header counts once.
        include_frame(&state, &committee, &filter, 721, 1_721, &[0]);
        assert_eq!(seniority_of(&state, &committee[1]), 990);
        include_frame(&state, &committee, &filter, 722, 1_722, &[0]);
        assert_eq!(seniority_of(&state, &committee[1]), 980);
        assert_eq!(
            penalty_of(&state, &committee[1]),
            20,
            "the charges are recorded"
        );
        // The producer, present in every frame, accrued no absence.
        assert_eq!(missed(&state, &committee[0], &filter), 0);
        assert_eq!(seniority_of(&state, &committee[0]), 1_000);
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    }

    /// Absence counts frames the committee produced, not GLOBAL time: a
    /// committee that produces nothing (no quorum, GLOBAL or archives down)
    /// accrues no absence for any member, however many GLOBAL frames pass,
    /// while another shard's committee keeps producing.
    #[test]
    fn a_committee_that_produces_no_frame_accrues_no_absence() {
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(0));
        let state = make_state();
        let producing = vec![0xB2u8; 32];
        let halted = vec![0xB3u8; 32];
        let busy = absence_committee(&state, &[3, 4], &producing, 1_000);
        let stalled = absence_committee(&state, &[5, 6, 7, 8], &halted, 1_000);
        for n in 1..=800 {
            include_frame(&state, &busy, &producing, n, 10 * n, &[0, 1]);
        }
        for member in &stalled {
            assert_eq!(missed(&state, member, &halted), 0);
            assert_eq!(seniority_of(&state, member), 1_000);
        }
        // One frame after 8,000 GLOBAL frames of silence counts as one.
        include_frame(&state, &stalled, &halted, 1, 9_000, &[0, 1, 2]);
        assert_eq!(missed(&state, &stalled[3], &halted), 1);
        assert_eq!(seniority_of(&state, &stalled[3]), 1_000);
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    }

    /// Signing one frame inside the window resets the count.
    #[test]
    fn signing_one_frame_resets_the_absence_count() {
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(0));
        let state = make_state();
        let filter = vec![0xB4u8; 32];
        let committee = absence_committee(&state, &[9, 10], &filter, 1_000);
        for n in 1..=700 {
            include_frame(&state, &committee, &filter, n, 1_000 + n, &[0]);
        }
        include_frame(&state, &committee, &filter, 701, 1_701, &[0, 1]);
        assert_eq!(missed(&state, &committee[1], &filter), 0);
        for n in 702..=1_401 {
            include_frame(&state, &committee, &filter, n, 1_000 + n, &[0]);
        }
        assert_eq!(missed(&state, &committee[1], &filter), 700);
        assert_eq!(
            seniority_of(&state, &committee[1]),
            1_000,
            "1,400 missed frames, but never 721 in a row"
        );
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    }

    /// Before the penalty epoch nothing is read or written: the allocation
    /// and prover vertices stay byte for byte as they were.
    #[test]
    fn absence_is_not_counted_before_the_penalty_epoch() {
        for epoch in [None, Some(5)] {
            quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(epoch);
            let state = make_state();
            let filter = vec![0xB5u8; 32];
            let committee = absence_committee(&state, &[11, 12], &filter, 1_000);
            let va_disc = vertex_adds_discriminator().unwrap();
            let alloc = allocation_address(&committee[1].public_key, &filter).unwrap();
            let blobs = |state: &HypergraphState| {
                (
                    state
                        .get(&GLOBAL_INTRINSIC_ADDRESS[..], &alloc, &va_disc)
                        .unwrap(),
                    state
                        .get(
                            &GLOBAL_INTRINSIC_ADDRESS[..],
                            &committee[1].address,
                            &va_disc,
                        )
                        .unwrap(),
                )
            };
            let before = blobs(&state);
            // Epoch 5 starts at GLOBAL frame 3,600: every frame here is earlier.
            for n in 1..=800 {
                include_frame(&state, &committee, &filter, n, 2_000 + n, &[0]);
            }
            assert_eq!(blobs(&state), before, "epoch {epoch:?}");
        }
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    }

    /// A relayed settlement becomes a GLOBAL record only with the committed
    /// spend that carries it: a spend the global commit rejects (a repeated
    /// consumption, a root outside the application's history) and a
    /// settlement no relayed spend carries leave no record. Runs at the
    /// committed-credit frame, set the way a test network sets it; a build
    /// without that rule ignores the setting.
    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn reproduces_unbacked_settlement_records() {
        use crate::token_intrinsic::global_commit::{materialize_relay, SpendEntry};
        use crate::token_intrinsic::{settlement_record, spend_relay};
        const FRAME: u64 = 1 << 40;
        std::env::set_var("QUIL_COMMITTED_CREDIT_FRAME", FRAME.to_string());
        let spend = |tx: u8, image: u8, receipt: u8| SpendEntry {
            kind: crate::token_engine::TYPE_LATTICE_SETTLEMENT,
            tx_id: [tx; 32],
            source_frame: 39,
            context: [8; 32],
            root_digest: None,
            consumptions: vec![[image; 32]],
            outputs: Vec::new(),
            escrow_create: None,
            escrow_claim: None,
            fee: 5,
            settlement: Some(relay_entry(receipt)),
        };
        let honest = spend(1, 20, 1);
        let repeated = spend(2, 20, 2);
        let mut unrooted = spend(3, 21, 3);
        unrooted.root_digest = Some([9; 32]);
        let relayed: Vec<Vec<u8>> = [honest, repeated, unrooted]
            .iter()
            .map(|s| s.encode().unwrap())
            .collect();
        // Receipt 4 is relayed with no spend carrying it.
        let settlements: Vec<_> = (1..=4).map(relay_entry).collect();
        let mut header = fake_header(crate::domains::QUIL_TOKEN.to_vec(), 40);
        header.settlements = settlement_record::encode_relay(&[(39, settlements)]).unwrap();
        header.spends = spend_relay::encode_relay(&[(39, relayed)]).unwrap();

        // GLOBAL's order for a certified QUIL shard header.
        let state = make_state();
        materialize_settlement_records(&header, FRAME, &state).unwrap();
        let fees = materialize_relay(
            &state,
            FRAME,
            &header.address,
            header.frame_number,
            &header.spends,
        )
        .unwrap();
        assert_eq!(fees, 5, "only the first spend of the coin commits");

        let va_disc = vertex_adds_discriminator().unwrap();
        let record = |receipt: u8| {
            state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], &[receipt; 32], &va_disc)
                .unwrap()
                .filter(|blob| !blob.is_empty())
        };
        assert_eq!(
            record(1),
            Some(settlement_record::create_record(&relay_entry(1)).unwrap()),
            "the committed spend's settlement is recorded"
        );
        for receipt in 2..=4 {
            assert!(
                record(receipt).is_none(),
                "settlement record written for a rejected or absent spend \
                 (receipt {receipt}): claimable credit without a committed spend"
            );
        }
    }
}
