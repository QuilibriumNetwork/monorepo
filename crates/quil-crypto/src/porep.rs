//! Per-frame storage-attestation verification.
//!
//! Thin consensus-level wrapper over [`bls48581::aggregate_verify_openings`]
//! that supplies the two pieces the raw batch verifier deliberately leaves to
//! the caller — the **challenge derivation** and the **Fiat-Shamir transcript**
//! — which together make the batch both sound and non-replayable:
//!
//! - Each opening's evaluation-domain index is **recomputed by the verifier**
//!   from the frame's global-VDF output `ρ_N` and the member id
//!   ([`derive_challenge_index`]); it is never trusted from the wire. So a
//!   prover cannot open at a self-chosen easy point, and a proof produced for
//!   frame `N` cannot be replayed at frame `N+1`: a different `ρ_N` yields a
//!   different index, and the carried proof no longer matches.
//! - The random-linear-combination scalar `γ` is bound to the **entire**
//!   transcript — frame number, `ρ_N`, the committee bitmask, and every
//!   `(member, query, commitment, index, value, proof)` — so the prover cannot
//!   adapt proofs after seeing `γ` (the standard small-exponents-batch
//!   requirement that, if violated, makes the aggregate forgeable).
//!
//! The challenge selects an evaluation-domain index within the challenged
//! leaf's polynomial (sector = one ≤1 GB logical-shard leaf; per the storage
//! design the leaf and intra-leaf block are also `ρ_N`-selected, layered the
//! same way — this module pins the index binding and the transcript, which are
//! the soundness-critical pieces).

use quil_types::proto::global;
use sha3::{Digest, Sha3_256};

/// Domain-separation tag for the per-(member,query) challenge index.
const DST_CHALLENGE: &[u8] = b"quil/porep/challenge/v1";
/// Domain-separation tag for the aggregation scalar `γ`.
const DST_GAMMA: &[u8] = b"quil/porep/agg-gamma/v1";
/// Domain-separation tag for the FrameHeader `storage_attestation_root`.
/// Domain-separation tag for the per-frame storage beacon `ρ_N`.
const DST_BEACON: &[u8] = b"quil/porep/beacon/v1";

const DST_AUDIT: &[u8] = b"quil/porep/audit/v1";

const DST_FRAME_OUTPUT: &[u8] = b"quil/porep/frame-output/v1";

/// Derive the per-frame storage beacon `ρ_N = SHA3(DST ‖ global_frame_number ‖
/// global_output)`. The shard frame commits `global_frame_number` in its VDF
/// challenge and the verifier loads `global_frame[global_frame_number].output`
/// (the global VDF output) — an unpredictable, lockstep-shared value all shards
/// in a frame challenge against. Binding the global frame number prevents a
/// producer from re-deriving a stale beacon under a different anchor.
pub fn derive_storage_beacon(global_frame_number: u64, global_output: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(DST_BEACON);
    h.update(global_frame_number.to_be_bytes());
    h.update((global_output.len() as u32).to_be_bytes());
    h.update(global_output);
    h.finalize().to_vec()
}

/// Deterministic per-frame storage-audit selector — the cost-vs-scale
/// decoupling from the PoRep design (`porep-shard-attestation-design`).
/// A leaf `id` (its `leaf_id` / opening `shard_id`) is AUDITED in the
/// frame whose beacon is `rho_n` iff `H(DST_AUDIT || rho_n || id)` —
/// read as a big-endian fraction of `2^64` from its first 8 bytes — is
/// below `sample_num / sample_den`.
///
/// Because `rho_n` is the global VDF output (unpredictable until it
/// lands), the audited set is unpredictable per frame, so a member must
/// hold its replica EVERY frame regardless of whether it is checked this
/// frame — that is what preserves the storage guarantee while only a
/// bounded sample is verified per frame. The expected sample rate is
/// `sample_num / sample_den`; `sample_num == 0` audits nothing,
/// `sample_num >= sample_den` (or `sample_den == 0`) audits everything.
pub fn is_audited(rho_n: &[u8], id: &[u8], sample_num: u64, sample_den: u64) -> bool {
    if sample_num == 0 {
        return false;
    }
    if sample_den == 0 || sample_num >= sample_den {
        return true;
    }
    let mut h = Sha3_256::new();
    h.update(DST_AUDIT);
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update((id.len() as u32).to_be_bytes());
    h.update(id);
    let digest = h.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[..8]);
    let h_u64 = u64::from_be_bytes(first8);
    // h_u64 / 2^64 < num/den  ⟺  h_u64 * den < num * 2^64  (u128, no overflow:
    // both sides < 2^128 since num,den,h_u64 < 2^64).
    (h_u64 as u128) * (sample_den as u128) < (sample_num as u128) << 64
}

/// Deterministic app-shard frame `output` at/after the storage-attestation fork,
/// REPLACING the Wesolowski VDF output. Binds the frame's committed content + the
/// global beacon `rho_n` so the frame identity (`poseidon(output)`) is fixed by
/// consensus state AND unpredictable until the previous global VDF output lands
/// (lockstep freshness — ≤1 app-shard frame per global period). Returned as 516
/// bytes to preserve the legacy output layout (first 32 = the binding digest,
/// remainder zero), so `poseidon(output)` and `output[..516]` parent derivations
/// are unchanged downstream. Producer and verifier MUST call this identically;
/// `rho_n = derive_storage_beacon(global_frame_number, global_output)`.
///
/// `rank` (the consensus view) is bound in so a re-proposal of the same
/// `frame_number` at a higher rank after a timeout yields a DISTINCT identity —
/// without it, the VDF-free output collides across re-proposals and the
/// consensus forks tree rejects the second as a parent-level conflict.
pub fn deterministic_app_frame_output(
    parent_selector: &[u8],
    requests_root: &[u8],
    state_roots: &[Vec<u8>],
    rho_n: &[u8],
    frame_number: u64,
    rank: u64,
    prover: &[u8],
) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(DST_FRAME_OUTPUT);
    h.update((parent_selector.len() as u32).to_be_bytes());
    h.update(parent_selector);
    h.update((requests_root.len() as u32).to_be_bytes());
    h.update(requests_root);
    h.update((state_roots.len() as u32).to_be_bytes());
    for r in state_roots {
        h.update((r.len() as u32).to_be_bytes());
        h.update(r);
    }
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update(frame_number.to_be_bytes());
    h.update(rank.to_be_bytes());
    h.update((prover.len() as u32).to_be_bytes());
    h.update(prover);
    let digest = h.finalize();
    let mut out = vec![0u8; 516];
    out[..32].copy_from_slice(&digest);
    out
}

/// Canonical per-opening identifier for audit selection — binds the shard, the
/// member, and the query so each distinct opening is sampled independently.
fn opening_audit_id(o: &StorageOpening) -> Vec<u8> {
    let mut v = Vec::with_capacity(o.shard_id.len() + o.member_id.len() + 12);
    v.extend_from_slice(&(o.shard_id.len() as u32).to_be_bytes());
    v.extend_from_slice(&o.shard_id);
    v.extend_from_slice(&(o.member_id.len() as u32).to_be_bytes());
    v.extend_from_slice(&o.member_id);
    v.extend_from_slice(&o.query.to_be_bytes());
    v
}

/// Global-frame SAMPLED storage audit (the cost-vs-scale core). Given ALL the
/// storage openings carried by a global frame's app-shard attestations,
/// deterministically select ≈ `sample_size` of them from the beacon `rho_n`
/// (unpredictable until the previous global VDF output lands — so every member
/// must hold its replica regardless of whether it's checked this frame), then
/// verify ONLY that sample: each sampled opening must (a) be registered by its
/// member for the active epoch (`lookup` returns the registered
/// `(leaf_root, num_blocks, epoch)`), and (b) be a valid possession+path opening.
/// Returns the DISTINCT `member_id`s with at least one failing sampled opening —
/// the eviction candidates. Cost is bounded by `sample_size`, independent of the
/// total population.
///
/// Possession is checked per opening (so culprits are identifiable); each is
/// γ-independent at k=1, so frame/bitmask are don't-cares and a single `rho_n`
/// (the global frame's beacon) drives every challenge.
pub fn audit_frame_storage_attestations<F>(
    openings: &[StorageOpening],
    rho_n: &[u8],
    poly_size: u64,
    active_epoch: u64,
    sample_size: u64,
    lookup: F,
) -> Vec<Vec<u8>>
where
    F: Fn(&[u8], &[u8]) -> Option<(Vec<u8>, u64, u64)>,
{
    use std::collections::HashSet;
    let total = openings.len() as u64;
    let mut failed: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for o in openings {
        let id = opening_audit_id(o);
        if !is_audited(rho_n, &id, sample_size, total) {
            continue;
        }
        // (a) registry cross-check (cheap, no pairing).
        let registry_ok = match lookup(&o.member_id, &o.shard_id) {
            Some((leaf_root, num_blocks, epoch)) => {
                epoch == active_epoch
                    && o.epoch == active_epoch
                    && leaf_root == o.leaf_root
                    && num_blocks == o.num_blocks
            }
            None => false,
        };
        // (b) possession + path (skip if registry already failed).
        let ok = registry_ok
            && verify_storage_attestation(std::slice::from_ref(o), 0, rho_n, &[], poly_size);
        if !ok && seen.insert(o.member_id.clone()) {
            failed.push(o.member_id.clone());
        }
    }
    failed
}

/// Filter `ids` to the subset audited this frame (see [`is_audited`]).
pub fn select_audited<'a>(
    rho_n: &[u8],
    ids: &'a [Vec<u8>],
    sample_num: u64,
    sample_den: u64,
) -> Vec<&'a [u8]> {
    ids.iter()
        .filter(|id| is_audited(rho_n, id, sample_num, sample_den))
        .map(|v| v.as_slice())
        .collect()
}

/// One member's possession opening for one challenge query in a frame.
///
/// The evaluation point (domain index) is intentionally **not** carried: it is
/// derived from `(ρ_N, member_id, query)` by the verifier, so the prover has no
/// freedom over which point it opens.
#[derive(Clone, Debug)]
pub struct StorageOpening {
    /// The shard this opening attests to. Bound into the challenge + transcript
    /// so a possession proof for one shard cannot be replayed as another's
    /// (a member may cover leaves in more than one shard).
    pub shard_id: Vec<u8>,
    /// The replication epoch (the SDR re-encode generation). Bound so an opening
    /// cannot be replayed across an epoch boundary, even during the re-encode
    /// transition window.
    pub epoch: u64,
    /// The prover's identity (binds the challenge + prevents cross-member replay).
    pub member_id: Vec<u8>,
    /// Query index `0..q` for this member (which of its challenged leaves).
    pub query: u32,
    /// The registered leaf commitment — the **KZG root** of the leaf's
    /// vector-commitment tree (`sdr::commit_leaf`). The verifier confirms the
    /// opened block chains up to this root, and the consensus layer confirms it
    /// matches the member's registered leaf.
    pub leaf_root: Vec<u8>,
    /// Number of blocks in the leaf — needed to derive the `ρ_N`-bound block
    /// index and the number of authentication-path levels.
    pub num_blocks: u64,
    /// Authentication-path parent node commitments C_1..C_L (`C_L == leaf_root`),
    /// bottom→top, binding `commitment` to `leaf_root`. Empty for a single-block
    /// leaf. See [`crate::sdr::leaf_path`].
    pub path_commits: Vec<Vec<u8>>,
    /// KZG opening proofs π_1..π_L for the path; π_ℓ opens C_ℓ at the level-ℓ
    /// child index to the field-reduced commitment of the level below.
    pub path_proofs: Vec<Vec<u8>>,
    /// `C_k`: the **challenged block's** KZG commitment (compressed G1) — the
    /// commitment the possession opening below is against, and the bottom of the
    /// authentication path.
    pub commitment: Vec<u8>,
    /// `y_k`: the claimed evaluation at the derived point (scalar bytes).
    pub value: Vec<u8>,
    /// `π_k`: the KZG opening proof (compressed G1).
    pub proof: Vec<u8>,
}

impl StorageOpening {
    /// Wire (proto) form for carrying the opening in an [`global::StorageAttestation`].
    pub fn to_proto(&self) -> global::StorageOpening {
        global::StorageOpening {
            shard_id: self.shard_id.clone(),
            epoch: self.epoch,
            member_id: self.member_id.clone(),
            query: self.query,
            leaf_root: self.leaf_root.clone(),
            num_blocks: self.num_blocks,
            path_commits: self.path_commits.clone(),
            path_proofs: self.path_proofs.clone(),
            commitment: self.commitment.clone(),
            value: self.value.clone(),
            proof: self.proof.clone(),
        }
    }

    /// Parse from the wire (proto) form.
    pub fn from_proto(p: &global::StorageOpening) -> StorageOpening {
        StorageOpening {
            shard_id: p.shard_id.clone(),
            epoch: p.epoch,
            member_id: p.member_id.clone(),
            query: p.query,
            leaf_root: p.leaf_root.clone(),
            num_blocks: p.num_blocks,
            path_commits: p.path_commits.clone(),
            path_proofs: p.path_proofs.clone(),
            commitment: p.commitment.clone(),
            value: p.value.clone(),
            proof: p.proof.clone(),
        }
    }
}

/// Frame-level verify over the wire (proto) attestation: recompute the
/// committee-signed `root` from the carried openings and re-verify possession
/// 100%, exactly as [`verify_frame_storage_attestation`] but taking the proto
/// `StorageAttestation` a frame carries. `root` is the header's
/// `storage_attestation_root`. Returns `true` iff the openings hash to `root`
/// AND every opening is a valid possession proof against its registered leaf.
pub fn verify_frame_storage_attestation_proto(
    root: &[u8],
    attestation: &global::StorageAttestation,
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
) -> bool {
    let openings: Vec<StorageOpening> =
        attestation.openings.iter().map(StorageOpening::from_proto).collect();
    verify_frame_storage_attestation(root, &openings, frame_number, rho_n, bitmask, poly_size)
}

/// Full storage-attestation acceptance check for a frame, including the
/// registry cross-check. On top of [`verify_frame_storage_attestation_proto`]
/// (root binding + possession batch), this enforces that every opening is
/// against a leaf the member actually **registered** for the **current epoch**:
///
/// - `lookup(member_id, leaf_id)` returns the member's registered
///   `(leaf_root, num_blocks, epoch)` for that leaf, or `None`. `leaf_id` is the
///   opening's `shard_id` (which the producer sets to `leaf_id_bytes(filter,
///   prefix)`), so a member can only open leaves it registered.
/// - The registered `leaf_root` and `num_blocks` must match the opening (a
///   prover can't open a self-chosen junk leaf), and both the registered and
///   the opening's `epoch` must equal `active_epoch` (a stale-epoch root —
///   never re-registered this epoch — is rejected, matching the epoch-bound
///   allocation semantics).
///
/// Returns `true` iff all cross-checks pass AND the possession batch verifies.
pub fn verify_frame_storage_attestation_registered<F>(
    root: &[u8],
    attestation: &global::StorageAttestation,
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
    active_epoch: u64,
    lookup: F,
) -> bool
where
    F: Fn(&[u8], &[u8]) -> Option<(Vec<u8>, u64, u64)>,
{
    for o in &attestation.openings {
        if o.epoch != active_epoch {
            return false;
        }
        match lookup(&o.member_id, &o.shard_id) {
            Some((reg_root, reg_blocks, reg_epoch)) => {
                if reg_epoch != active_epoch
                    || reg_root != o.leaf_root
                    || reg_blocks != o.num_blocks
                {
                    return false;
                }
            }
            // Opened a leaf the member never registered → reject.
            None => return false,
        }
    }
    verify_frame_storage_attestation_proto(root, attestation, frame_number, rho_n, bitmask, poly_size)
}

/// Producer counterpart to the verifier: open one member's challenged leaf for
/// one query, given its stored `replica` and the leaf's [`sdr::LeafCommitment`].
/// Derives the `(block, point)` challenge from `rho_n` (so the prover has no
/// freedom), opens the challenged block, and attaches the authentication path to
/// the leaf root. `leaf_id = leaf_id_bytes(filter, prefix)` becomes the
/// opening's `shard_id` — the contract the registry cross-check relies on.
/// Requires `bls48581::init()`.
#[allow(clippy::too_many_arguments)]
pub fn build_storage_opening(
    replica: &[u8],
    leaf: &crate::sdr::LeafCommitment,
    leaf_id: &[u8],
    epoch: u64,
    member_id: &[u8],
    query: u32,
    rho_n: &[u8],
    poly_size: u64,
) -> StorageOpening {
    const MB: usize = 73;
    const NB: usize = 32;
    let num_blocks = leaf.block_commitments().len() as u64;
    let block = derive_block_index(rho_n, leaf_id, epoch, member_id, query, num_blocks);
    let point = derive_challenge_index(rho_n, leaf_id, epoch, member_id, query, poly_size);

    let block_bytes = poly_size as usize * NB;
    let off = block as usize * block_bytes;
    let end = (off + block_bytes).min(replica.len());
    let full = crate::sdr::pack_block(&replica[off..end], poly_size);
    let proof = bls48581::prove_raw_full(&full, point, poly_size);
    let value = full[point as usize * MB..point as usize * MB + MB].to_vec();
    let path = crate::sdr::leaf_path(leaf, block);

    StorageOpening {
        shard_id: leaf_id.to_vec(),
        epoch,
        member_id: member_id.to_vec(),
        query,
        leaf_root: leaf.root.clone(),
        num_blocks,
        path_commits: path.node_commits,
        path_proofs: path.proofs,
        commitment: leaf.block_commitments()[block as usize].clone(),
        value,
        proof,
    }
}

/// Assemble the carried [`global::StorageAttestation`] and its committee-signed
/// `storage_attestation_root` from a set of openings, for a frame producer /
/// aggregator. The root is what the committee signs into the header; the
/// attestation is what travels with the frame.
pub fn build_frame_storage_attestation(
    openings: &[StorageOpening],
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
) -> (global::StorageAttestation, Vec<u8>) {
    let root = compute_storage_attestation_root(openings, frame_number, rho_n, bitmask, poly_size);
    let attestation = global::StorageAttestation {
        openings: openings.iter().map(StorageOpening::to_proto).collect(),
    };
    (attestation, root)
}

/// Derive the `ρ_N`-bound evaluation-domain index for
/// `(shard, epoch, member, query)`.
///
/// Unpredictable until `ρ_N` (the global-frame VDF output) is revealed, so a
/// prover can neither precompute the opening nor reuse last frame's. Bound to
/// `shard_id` + `epoch` + `member_id` so a proof is non-replayable across
/// shards, epochs, and members (each gets a distinct challenge point).
pub fn derive_challenge_index(
    rho_n: &[u8],
    shard_id: &[u8],
    epoch: u64,
    member_id: &[u8],
    query: u32,
    poly_size: u64,
) -> u64 {
    debug_assert!(poly_size > 0);
    let mut h = Sha3_256::new();
    h.update(DST_CHALLENGE);
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update((shard_id.len() as u32).to_be_bytes());
    h.update(shard_id);
    h.update(epoch.to_be_bytes());
    h.update((member_id.len() as u32).to_be_bytes());
    h.update(member_id);
    h.update(query.to_be_bytes());
    h.update(poly_size.to_be_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b) % poly_size.max(1)
}

/// Derive the `ρ_N`-bound BLOCK index within a member's leaf (which ≤256-element
/// block of the leaf tree is challenged this frame). Distinct domain tag from
/// the in-block point so the two are independent.
pub fn derive_block_index(
    rho_n: &[u8],
    shard_id: &[u8],
    epoch: u64,
    member_id: &[u8],
    query: u32,
    num_blocks: u64,
) -> u64 {
    let mut h = Sha3_256::new();
    h.update(DST_CHALLENGE);
    h.update(b"block");
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update((shard_id.len() as u32).to_be_bytes());
    h.update(shard_id);
    h.update(epoch.to_be_bytes());
    h.update((member_id.len() as u32).to_be_bytes());
    h.update(member_id);
    h.update(query.to_be_bytes());
    h.update(num_blocks.to_be_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b) % num_blocks.max(1)
}

/// `γ = SHA3(DST ‖ frame ‖ ρ_N ‖ bitmask ‖ ∀k (canonical order): id ‖ query ‖
/// index ‖ C ‖ y ‖ π)`. Every field is length-prefixed. `idx_openings` must
/// already be in canonical order.
fn fiat_shamir_gamma(
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    idx_openings: &[(&StorageOpening, u64, u64)],
) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(DST_GAMMA);
    update_frame_transcript(&mut h, frame_number, rho_n, bitmask, idx_openings);
    h.finalize().to_vec()
}

/// Derive each opening's `ρ_N`-bound `(block, point)` indices (never trusting the
/// wire) and sort into the canonical order both prover and verifier agree on.
/// Shared by the batch verifier, the FS scalar, and the attestation root so all
/// three commit to identical bytes.
fn canonical_indexed<'a>(
    openings: &'a [StorageOpening],
    rho_n: &[u8],
    poly_size: u64,
) -> Vec<(&'a StorageOpening, u64, u64)> {
    let mut v: Vec<(&'a StorageOpening, u64, u64)> = openings
        .iter()
        .map(|o| {
            let block =
                derive_block_index(rho_n, &o.shard_id, o.epoch, &o.member_id, o.query, o.num_blocks);
            let point =
                derive_challenge_index(rho_n, &o.shard_id, o.epoch, &o.member_id, o.query, poly_size);
            (o, block, point)
        })
        .collect();
    v.sort_by(|a, b| {
        a.0.shard_id
            .cmp(&b.0.shard_id)
            .then(a.0.epoch.cmp(&b.0.epoch))
            .then(a.0.member_id.cmp(&b.0.member_id))
            .then(a.0.query.cmp(&b.0.query))
    });
    v
}

/// Absorb `frame ‖ ρ_N ‖ bitmask ‖ ∀k (id ‖ epoch ‖ member ‖ query ‖ leaf_root ‖
/// num_blocks ‖ block ‖ point ‖ C ‖ y ‖ π)` into `h`, all length-prefixed.
fn update_frame_transcript(
    h: &mut Sha3_256,
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    idx_openings: &[(&StorageOpening, u64, u64)],
) {
    h.update(frame_number.to_be_bytes());
    h.update((rho_n.len() as u32).to_be_bytes());
    h.update(rho_n);
    h.update((bitmask.len() as u32).to_be_bytes());
    h.update(bitmask);
    h.update((idx_openings.len() as u32).to_be_bytes());
    for (o, block, point) in idx_openings {
        h.update((o.shard_id.len() as u32).to_be_bytes());
        h.update(&o.shard_id);
        h.update(o.epoch.to_be_bytes());
        h.update((o.member_id.len() as u32).to_be_bytes());
        h.update(&o.member_id);
        h.update(o.query.to_be_bytes());
        h.update((o.leaf_root.len() as u32).to_be_bytes());
        h.update(&o.leaf_root);
        h.update(o.num_blocks.to_be_bytes());
        h.update(block.to_be_bytes());
        h.update(point.to_be_bytes());
        h.update((o.commitment.len() as u32).to_be_bytes());
        h.update(&o.commitment);
        h.update((o.value.len() as u32).to_be_bytes());
        h.update(&o.value);
        h.update((o.proof.len() as u32).to_be_bytes());
        h.update(&o.proof);
        // Bind the authentication path (parent commitments + proofs).
        h.update((o.path_commits.len() as u32).to_be_bytes());
        for c in &o.path_commits {
            h.update((c.len() as u32).to_be_bytes());
            h.update(c);
        }
        for p in &o.path_proofs {
            h.update((p.len() as u32).to_be_bytes());
            h.update(p);
        }
    }
}

/// The committee's `storage_attestation_root` for the FrameHeader: the 74-byte
/// **aggregate proof point** `A = Σ_k γ^k · π_k` over the canonical opening set
/// (a compressed BLS48-581 G1 element), where `γ` is the Fiat-Shamir challenge
/// over the full opening transcript. It IS the frame's aggregate possession
/// proof and binds the openings (changing any opening changes `γ` ⇒ changes
/// `A`), so the committee signature over the header authenticates exactly this
/// opening set, and the global validator can recompute + check it before
/// re-verifying possession. Lives in the same pairing framework as the openings
/// — NOT a hash. Returns an empty vec for an empty opening set (a frame with no
/// attested openings; the caller enforces the participation quorum separately).
pub fn compute_storage_attestation_root(
    openings: &[StorageOpening],
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
) -> Vec<u8> {
    let idx = canonical_indexed(openings, rho_n, poly_size);
    if idx.is_empty() {
        return Vec::new();
    }
    let gamma = fiat_shamir_gamma(frame_number, rho_n, bitmask, &idx);
    // Fold the proofs in the SAME canonical order the batch verifier uses.
    let proofs: Vec<Vec<u8>> = idx.iter().map(|(o, _, _)| o.proof.clone()).collect();
    bls48581::aggregate_proof_point(&proofs, &gamma).unwrap_or_default()
}

/// Verify a frame's storage attestation in one aggregate pairing check.
///
/// Recomputes each opening's index from `ρ_N` (never trusting the wire), binds
/// `γ` to the full transcript, and delegates the batch math to
/// [`bls48581::aggregate_verify_openings`]. Returns `true` iff every opening is
/// a valid KZG opening of its committed leaf at its `ρ_N`-derived point.
///
/// `bitmask` is the committee/participant bitmask carried in the frame (folded
/// into `γ` so the attested set is bound). `poly_size` is the evaluation-domain
/// size of a leaf polynomial (a supported root-of-unity domain).
pub fn verify_storage_attestation(
    openings: &[StorageOpening],
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
) -> bool {
    if openings.is_empty() {
        // No openings to satisfy this frame; the caller enforces the
        // participation quorum separately.
        return true;
    }
    if poly_size == 0 {
        return false;
    }

    // Derive each (block, point) challenge from ρ_N (not from the wire) and
    // canonicalize.
    let idx_openings = canonical_indexed(openings, rho_n, poly_size);
    let gamma = fiat_shamir_gamma(frame_number, rho_n, bitmask, &idx_openings);

    // Flatten every opening into a single KZG batch: one possession opening of
    // the challenged block at the ρ_N point, PLUS the authentication-path
    // openings binding that block up to the registered leaf root. Every opening
    // (block + internal nodes) shares the same domain `poly_size`, so the whole
    // `point → block → … → root` chain verifies in one aggregate pairing check.
    let mut commitments: Vec<Vec<u8>> = Vec::new();
    let mut indices: Vec<u64> = Vec::new();
    let mut values: Vec<Vec<u8>> = Vec::new();
    let mut proofs: Vec<Vec<u8>> = Vec::new();

    for (o, block, point) in &idx_openings {
        // (a) Possession: C_0 (the block commitment) opens at the derived point.
        commitments.push(o.commitment.clone());
        indices.push(*point);
        values.push(o.value.clone());
        proofs.push(o.proof.clone());

        // (b) Authentication path: the chain of node commitments must have the
        //     exact length the leaf shape dictates, and end at the registered
        //     root, so a prover can neither shorten the path nor swap the root.
        let levels = crate::sdr::leaf_levels(o.num_blocks, poly_size);
        if o.path_commits.len() != levels || o.path_proofs.len() != levels {
            return false;
        }
        if levels == 0 {
            // Single-block leaf: the block commitment IS the root.
            if o.commitment != o.leaf_root {
                return false;
            }
            continue;
        }
        if o.path_commits[levels - 1] != o.leaf_root {
            return false;
        }
        // Each level ℓ: parent C_{ℓ+1} opens at the level-ℓ child index to the
        // field-reduced commitment of the level below (C_0 = block commitment).
        let poly = poly_size as usize;
        let mut idx = *block as usize;
        for lvl in 0..levels {
            let child_idx = idx % poly;
            let below = if lvl == 0 { &o.commitment } else { &o.path_commits[lvl - 1] };
            // The parent holds the field-reduced child commitment in the low 32
            // bytes of a full-width (73-byte) scalar — matching `node_poly`'s
            // packing exactly, so the verifier reconstructs the opened value.
            let mut value = vec![0u8; 73];
            value[41..].copy_from_slice(&crate::sdr::commit_to_scalar(below));
            commitments.push(o.path_commits[lvl].clone());
            indices.push(child_idx as u64);
            values.push(value);
            proofs.push(o.path_proofs[lvl].clone());
            idx /= poly;
        }
    }

    bls48581::aggregate_verify_openings(
        &commitments,
        &indices,
        &values,
        &proofs,
        poly_size,
        &gamma,
    )
}

/// Full frame-level check for a global validator: the supplied `openings` must
/// (a) hash to the committee-signed `root` carried in the shard FrameHeader —
/// proving the committee attested *these* openings — and (b) re-verify
/// possession 100% via [`verify_storage_attestation`]. The global validators
/// do NOT trust the committee's word that the openings are valid; the root only
/// binds *which* openings were attested, the batch re-check proves they hold.
pub fn verify_frame_storage_attestation(
    root: &[u8],
    openings: &[StorageOpening],
    frame_number: u64,
    rho_n: &[u8],
    bitmask: &[u8],
    poly_size: u64,
) -> bool {
    let recomputed = compute_storage_attestation_root(openings, frame_number, rho_n, bitmask, poly_size);
    if root != recomputed.as_slice() {
        return false;
    }
    verify_storage_attestation(openings, frame_number, rho_n, bitmask, poly_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes per BLS48-581 scalar in the full-width encoding.
    const MB: usize = 73;
    /// Bytes per replica node.
    const NB: usize = 32;

    const SHARD: &[u8] = b"shardA";
    const EPOCH: u64 = 7;
    /// Blocks per leaf in the tests (>1 so the Merkle path is exercised).
    const NUM_BLOCKS: u64 = 4;

    /// A deterministic, per-`seed` replica leaf of `num_blocks · block_poly_size`
    /// 32-byte nodes. Each node is kept well under the curve order.
    fn replica_bytes(seed: u8, num_blocks: u64, block_poly_size: u64) -> Vec<u8> {
        let nodes = (num_blocks * block_poly_size) as usize;
        let mut r = vec![0u8; nodes * NB];
        for i in 0..nodes {
            r[i * NB + NB - 1] = seed ^ (i as u8);
            r[i * NB + NB - 2] = ((i >> 8) as u8) ^ seed;
            r[i * NB + NB - 3] = (i as u8).wrapping_mul(31).wrapping_add(seed);
        }
        r
    }

    /// Build one member's opening: commit the whole leaf as a Merkle tree of
    /// block KZG commitments, then open the ρ_N-derived block at its ρ_N-derived
    /// point, attaching the path that binds that block to the leaf root.
    fn make_opening(
        seed: u8,
        shard_id: &[u8],
        epoch: u64,
        member_id: &[u8],
        query: u32,
        rho_n: &[u8],
        num_blocks: u64,
        block_poly_size: u64,
    ) -> StorageOpening {
        let replica = replica_bytes(seed, num_blocks, block_poly_size);
        let leaf = crate::sdr::commit_leaf(&replica, block_poly_size);

        let block =
            derive_block_index(rho_n, shard_id, epoch, member_id, query, num_blocks);
        let point =
            derive_challenge_index(rho_n, shard_id, epoch, member_id, query, block_poly_size);

        // Re-pack exactly the challenged block to open it for possession.
        let block_bytes = block_poly_size as usize * NB;
        let off = block as usize * block_bytes;
        let end = (off + block_bytes).min(replica.len());
        let full = crate::sdr::pack_block(&replica[off..end], block_poly_size);
        let proof = bls48581::prove_raw_full(&full, point, block_poly_size);
        let value = full[point as usize * MB..point as usize * MB + MB].to_vec();

        let path = crate::sdr::leaf_path(&leaf, block);
        StorageOpening {
            shard_id: shard_id.to_vec(),
            epoch,
            member_id: member_id.to_vec(),
            query,
            leaf_root: leaf.root.clone(),
            num_blocks,
            path_commits: path.node_commits,
            path_proofs: path.proofs,
            commitment: leaf.block_commitments()[block as usize].clone(),
            value,
            proof,
        }
    }

    fn build_attestation(rho_n: &[u8], poly_size: u64) -> Vec<StorageOpening> {
        // 3 members (distinct leaves), 2 queries each = 6 openings.
        let mut out = Vec::new();
        for (m, id) in [b"m0".as_slice(), b"m1", b"m2"].iter().enumerate() {
            for q in 0..2u32 {
                out.push(make_opening(
                    0x20 + m as u8, SHARD, EPOCH, id, q, rho_n, NUM_BLOCKS, poly_size,
                ));
            }
        }
        out
    }

    #[test]
    fn golden_attestation_verifies() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        let openings = build_attestation(&rho_n, poly_size);
        assert!(
            verify_storage_attestation(&openings, 100, &rho_n, &bitmask, poly_size),
            "honest attestation must verify"
        );
    }

    #[test]
    fn attestation_root_is_74_byte_g1_aggregate() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        let openings = build_attestation(&rho_n, poly_size);
        assert!(!openings.is_empty());
        let root = compute_storage_attestation_root(&openings, 100, &rho_n, &bitmask, poly_size);
        // The root is the aggregate proof point — a compressed BLS48-581 G1
        // element, NOT a 32-byte hash.
        assert_eq!(root.len(), 74, "root must be a 74-byte compressed G1 element");
        // An empty opening set has no aggregate → empty root.
        assert!(
            compute_storage_attestation_root(&[], 100, &rho_n, &bitmask, poly_size).is_empty()
        );
    }

    #[test]
    fn cross_frame_replay_is_rejected() {
        bls48581::init();
        let poly_size = 16u64;
        let bitmask = [0x07u8];

        // Attestation produced for frame N with ρ_N.
        let rho_n: [u8; 32] = [0xA1; 32];
        let openings = build_attestation(&rho_n, poly_size);
        assert!(
            verify_storage_attestation(&openings, 100, &rho_n, &bitmask, poly_size),
            "fresh attestation must verify under its own frame"
        );

        // Replaying the SAME openings under frame N+1 with a fresh ρ_{N+1} must
        // fail: the re-derived challenge indices differ, so the carried proofs
        // no longer open at the new points.
        let rho_n1: [u8; 32] = [0xB2; 32];
        assert!(
            !verify_storage_attestation(&openings, 101, &rho_n1, &bitmask, poly_size),
            "frame-N proofs must NOT replay under frame N+1's ρ"
        );
    }

    #[test]
    fn tampered_value_and_proof_rejected() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        let mut openings = build_attestation(&rho_n, poly_size);

        let mut bad_v = openings.clone();
        bad_v[2].value[0] ^= 0x01;
        assert!(
            !verify_storage_attestation(&bad_v, 100, &rho_n, &bitmask, poly_size),
            "tampered value rejected"
        );

        openings[4].proof[1] ^= 0x01;
        assert!(
            !verify_storage_attestation(&openings, 100, &rho_n, &bitmask, poly_size),
            "tampered proof rejected"
        );
    }

    #[test]
    fn self_chosen_point_rejected() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        let id = b"prover".as_slice();

        // The verifier derives BOTH the block and the point from ρ_N; the prover
        // honestly commits its leaf but opens the correct block at a different,
        // self-chosen point.
        let block = derive_block_index(&rho_n, SHARD, EPOCH, id, 0, NUM_BLOCKS);
        let derived = derive_challenge_index(&rho_n, SHARD, EPOCH, id, 0, poly_size);
        let chosen = if derived == 0 { 1u64 } else { 0u64 };
        assert_ne!(chosen, derived, "test setup: chosen point must differ from derived");

        let replica = replica_bytes(0x99, NUM_BLOCKS, poly_size);
        let leaf = crate::sdr::commit_leaf(&replica, poly_size);
        let block_bytes = poly_size as usize * NB;
        let off = block as usize * block_bytes;
        let full = crate::sdr::pack_block(&replica[off..off + block_bytes], poly_size);
        let proof = bls48581::prove_raw_full(&full, chosen, poly_size);
        let value = full[chosen as usize * MB..chosen as usize * MB + MB].to_vec();
        let path = crate::sdr::leaf_path(&leaf, block);
        let o = StorageOpening {
            shard_id: SHARD.to_vec(),
            epoch: EPOCH,
            member_id: id.to_vec(),
            query: 0,
            leaf_root: leaf.root.clone(),
            num_blocks: NUM_BLOCKS,
            path_commits: path.node_commits,
            path_proofs: path.proofs,
            commitment: leaf.block_commitments()[block as usize].clone(),
            value,
            proof,
        };
        // The verifier re-derives `derived` ≠ `chosen`, so the proof opens at the
        // wrong point → rejected. A prover cannot choose its own challenge point.
        assert!(
            !verify_storage_attestation(&[o], 100, &rho_n, &bitmask, poly_size),
            "opening at a self-chosen point ≠ the ρ_N-derived index must be rejected"
        );
    }

    #[test]
    fn cross_shard_replay_is_rejected() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        // An opening built for shard A (its challenge index derived with shard=A).
        let o = make_opening(0x33, b"shardA", EPOCH, b"m0", 0, &rho_n, NUM_BLOCKS, poly_size);
        // Re-label it as shard B: the verifier re-derives the index with shard=B,
        // which differs, so the proof (built for shard A's index) no longer opens.
        let mut relabelled = o.clone();
        relabelled.shard_id = b"shardB".to_vec();
        assert!(
            !verify_storage_attestation(&[relabelled], 100, &rho_n, &bitmask, poly_size),
            "a shard-A proof must NOT replay as a shard-B attestation"
        );
    }

    #[test]
    fn cross_epoch_replay_is_rejected() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        // An opening built for epoch 7.
        let o = make_opening(0x44, SHARD, 7, b"m0", 0, &rho_n, NUM_BLOCKS, poly_size);
        // Re-label it as epoch 8: re-derived index differs → proof no longer opens.
        let mut relabelled = o.clone();
        relabelled.epoch = 8;
        assert!(
            !verify_storage_attestation(&[relabelled], 100, &rho_n, &bitmask, poly_size),
            "an epoch-7 proof must NOT replay under epoch 8"
        );
    }

    #[test]
    fn frame_root_binds_openings_and_roundtrips() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let bitmask = [0x07u8];
        let frame = 100u64;
        let openings = build_attestation(&rho_n, poly_size);

        // The committee computes the root and (notionally) signs the frame; the
        // global validator re-checks root + re-verifies possession.
        let root = compute_storage_attestation_root(&openings, frame, &rho_n, &bitmask, poly_size);
        assert!(
            verify_frame_storage_attestation(&root, &openings, frame, &rho_n, &bitmask, poly_size),
            "honest frame attestation must verify against its committee root"
        );

        // The root is order-independent (canonical sort): a shuffled opening list
        // yields the same root, so any committee member computes the same value.
        let mut shuffled = openings.clone();
        shuffled.reverse();
        assert_eq!(
            compute_storage_attestation_root(&shuffled, frame, &rho_n, &bitmask, poly_size),
            root,
            "root must be independent of opening order"
        );

        // Tampering any opening changes the root → recompute mismatch → reject,
        // AND would fail possession re-verify even if the root were forced.
        let mut bad = openings.clone();
        bad[3].value[0] ^= 0x01;
        assert_ne!(
            compute_storage_attestation_root(&bad, frame, &rho_n, &bitmask, poly_size),
            root,
            "tampering an opening must change the root"
        );
        assert!(
            !verify_frame_storage_attestation(&root, &bad, frame, &rho_n, &bitmask, poly_size),
            "openings not matching the committee root must be rejected"
        );

        // A wrong/forged root is rejected even for honest openings.
        let wrong = [0u8; 32];
        assert!(
            !verify_frame_storage_attestation(&wrong, &openings, frame, &rho_n, &bitmask, poly_size),
            "a root that doesn't commit the openings must be rejected"
        );
    }

    /// The KZG authentication path must be load-bearing: a prover that opens a
    /// *valid* block (correct KZG possession opening) but at the *wrong* block
    /// index — or with a stale/forged path — must be rejected because that
    /// block's commitment no longer authenticates under the registered root.
    #[test]
    fn leaf_path_binds_block_to_root() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xC3u8; 32];
        let bitmask = [0x01u8];
        let id = b"m0".as_slice();

        // Honest leaf + honest opening of the ρ_N-derived block verifies.
        let good = make_opening(0x55, SHARD, EPOCH, id, 0, &rho_n, NUM_BLOCKS, poly_size);
        assert!(
            verify_storage_attestation(&[good.clone()], 100, &rho_n, &bitmask, poly_size),
            "honest multi-block leaf opening must verify"
        );

        // Build a perfectly valid KZG possession opening of a DIFFERENT block of
        // the same leaf, with that block's commitment + honest path. The verifier
        // re-derives the challenged block from ρ_N and checks the path at THAT
        // position, so this block's path no longer opens → rejected.
        let derived_block = derive_block_index(&rho_n, SHARD, EPOCH, id, 0, NUM_BLOCKS);
        let other_block = (derived_block + 1) % NUM_BLOCKS;
        assert_ne!(other_block, derived_block);
        let replica = replica_bytes(0x55, NUM_BLOCKS, poly_size);
        let leaf = crate::sdr::commit_leaf(&replica, poly_size);
        let block_bytes = poly_size as usize * NB;
        let off = other_block as usize * block_bytes;
        let full = crate::sdr::pack_block(&replica[off..off + block_bytes], poly_size);
        let point =
            derive_challenge_index(&rho_n, SHARD, EPOCH, id, 0, poly_size);
        let proof = bls48581::prove_raw_full(&full, point, poly_size);
        let value = full[point as usize * MB..point as usize * MB + MB].to_vec();
        let other_path = crate::sdr::leaf_path(&leaf, other_block);
        let wrong_block = StorageOpening {
            shard_id: SHARD.to_vec(),
            epoch: EPOCH,
            member_id: id.to_vec(),
            query: 0,
            leaf_root: leaf.root.clone(),
            num_blocks: NUM_BLOCKS,
            path_commits: other_path.node_commits,
            path_proofs: other_path.proofs,
            commitment: leaf.block_commitments()[other_block as usize].clone(),
            value,
            proof,
        };
        assert!(
            !verify_storage_attestation(&[wrong_block], 100, &rho_n, &bitmask, poly_size),
            "a valid opening of the wrong block must fail the path→root binding"
        );

        // Tampering a path proof (with the correct block) also fails.
        let mut bad_path = good.clone();
        bad_path.path_proofs[0][1] ^= 0x01;
        assert!(
            !verify_storage_attestation(&[bad_path], 100, &rho_n, &bitmask, poly_size),
            "a tampered authentication path must fail the root binding"
        );

        // Swapping in a foreign root (with otherwise honest openings) fails: the
        // top of the path no longer equals the claimed leaf_root.
        let mut wrong_root = good.clone();
        wrong_root.leaf_root = vec![0u8; good.leaf_root.len()];
        assert!(
            !verify_storage_attestation(&[wrong_root], 100, &rho_n, &bitmask, poly_size),
            "a path that doesn't terminate at leaf_root must be rejected"
        );
    }

    /// The proto build/verify glue round-trips and binds the carried openings to
    /// the header root exactly like the in-memory path.
    #[test]
    fn proto_attestation_roundtrips_and_verifies() {
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0x5Eu8; 32];
        let bitmask = [0x07u8];
        let frame = 4242u64;
        let openings = build_attestation(&rho_n, poly_size);

        // Producer side: assemble the carried attestation + signed root.
        let (attestation, root) =
            build_frame_storage_attestation(&openings, frame, &rho_n, &bitmask, poly_size);
        assert_eq!(
            root,
            compute_storage_attestation_root(&openings, frame, &rho_n, &bitmask, poly_size),
            "built root must match the canonical root"
        );

        // Per-opening proto round-trip is lossless.
        for o in &openings {
            let back = StorageOpening::from_proto(&o.to_proto());
            assert_eq!(back.commitment, o.commitment);
            assert_eq!(back.path_commits, o.path_commits);
            assert_eq!(back.path_proofs, o.path_proofs);
            assert_eq!(back.leaf_root, o.leaf_root);
            assert_eq!(back.num_blocks, o.num_blocks);
        }

        // Verifier side: the global validator re-derives the root from the wire
        // openings and re-verifies possession.
        assert!(
            verify_frame_storage_attestation_proto(&root, &attestation, frame, &rho_n, &bitmask, poly_size),
            "wire attestation must verify against its header root"
        );
        // A wrong root is rejected.
        assert!(
            !verify_frame_storage_attestation_proto(&[0u8; 32], &attestation, frame, &rho_n, &bitmask, poly_size),
            "wire attestation must not verify against a mismatched root"
        );
        // A dropped opening changes the root → rejected.
        let mut short = attestation.clone();
        short.openings.pop();
        assert!(
            !verify_frame_storage_attestation_proto(&root, &short, frame, &rho_n, &bitmask, poly_size),
            "dropping a carried opening must break the root binding"
        );
    }

    #[test]
    fn beacon_is_deterministic_and_bound() {
        let out = vec![0xABu8; 516];
        let a = derive_storage_beacon(42, &out);
        assert_eq!(a, derive_storage_beacon(42, &out), "deterministic");
        assert_ne!(a, derive_storage_beacon(43, &out), "binds global frame number");
        let mut out2 = out.clone();
        out2[0] ^= 1;
        assert_ne!(a, derive_storage_beacon(42, &out2), "binds global output");
    }

    #[test]
    fn producer_openings_verify_end_to_end() {
        use std::collections::HashMap;
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0x77u8; 32];
        let bitmask = [0x03u8];
        let frame = 5u64;
        let epoch = 3u64;
        let params = crate::sdr::SdrParams::default();

        let mut openings = Vec::new();
        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for (m, id) in [b"m0".as_slice(), b"m1"].iter().enumerate() {
            // Opaque per-member leaf id (the engine sets this to
            // leaf_id_bytes(filter, prefix); crypto treats it as bytes).
            let leaf_id = vec![0xA0 + m as u8; 9];
            // 4 blocks of leaf data (4 · poly_size · 32 bytes).
            let nodes = 4 * poly_size as usize;
            let leaf_data: Vec<u8> = (0..nodes * 32)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(m as u8))
                .collect();

            let (replica, leaf) = crate::sdr::build_leaf_replica(
                &leaf_data, id, &leaf_id, epoch, poly_size, &params,
            );
            reg.insert(
                (id.to_vec(), leaf_id.clone()),
                (leaf.root.clone(), leaf.block_commitments().len() as u64, epoch),
            );
            for q in 0..2u32 {
                openings.push(build_storage_opening(
                    &replica, &leaf, &leaf_id, epoch, id, q, &rho_n, poly_size,
                ));
            }
        }

        let (attestation, root) =
            build_frame_storage_attestation(&openings, frame, &rho_n, &bitmask, poly_size);
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();
        assert!(
            verify_frame_storage_attestation_registered(
                &root, &attestation, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "producer-built replica + openings must verify against the registry"
        );
    }

    #[test]
    fn registered_verify_accepts_and_rejects() {
        use std::collections::HashMap;
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0x9Eu8; 32];
        let bitmask = [0x07u8];
        let frame = 7000u64;
        let active_epoch = EPOCH; // build_attestation stamps openings with EPOCH

        let openings = build_attestation(&rho_n, poly_size);
        let (attestation, root) =
            build_frame_storage_attestation(&openings, frame, &rho_n, &bitmask, poly_size);

        // Registry map: (member_id, shard_id=leaf_id) → (leaf_root, num_blocks, epoch).
        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for o in &openings {
            reg.insert(
                (o.member_id.clone(), o.shard_id.clone()),
                (o.leaf_root.clone(), o.num_blocks, o.epoch),
            );
        }
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();

        // Honest: registered, current epoch, matching roots → accept.
        assert!(verify_frame_storage_attestation_registered(
            &root, &attestation, frame, &rho_n, &bitmask, poly_size, active_epoch, good,
        ));

        // Unregistered leaf (lookup always None) → reject.
        assert!(!verify_frame_storage_attestation_registered(
            &root, &attestation, frame, &rho_n, &bitmask, poly_size, active_epoch,
            |_m: &[u8], _l: &[u8]| None,
        ));

        // Stale epoch (active epoch advanced; opening still at EPOCH) → reject.
        assert!(!verify_frame_storage_attestation_registered(
            &root, &attestation, frame, &rho_n, &bitmask, poly_size, active_epoch + 1,
            |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned(),
        ));

        // Registered leaf_root differs from the opening's → reject (junk-leaf swap).
        let wrong = |m: &[u8], l: &[u8]| {
            reg.get(&(m.to_vec(), l.to_vec()))
                .map(|(_r, b, e)| (vec![0u8; 74], *b, *e))
        };
        assert!(!verify_frame_storage_attestation_registered(
            &root, &attestation, frame, &rho_n, &bitmask, poly_size, active_epoch, wrong,
        ));
    }

    #[test]
    fn deterministic_frame_output_layout_and_binding() {
        let parent = [0x11u8; 32];
        let rr = [0x22u8; 64];
        let srs = vec![vec![0x33u8; 64], vec![0x44u8; 64]];
        let rho = [0x55u8; 32];
        let prover = [0x66u8; 32];
        let a = deterministic_app_frame_output(&parent, &rr, &srs, &rho, 7, 0, &prover);
        // 516-byte layout: 32-byte digest then zeros (so poseidon(output) +
        // output[..516] parent derivations are unchanged downstream).
        assert_eq!(a.len(), 516);
        assert!(a[..32].iter().any(|&b| b != 0), "digest must be non-zero");
        assert!(a[32..].iter().all(|&b| b == 0), "tail must be zero-padded");
        // Deterministic.
        assert_eq!(a, deterministic_app_frame_output(&parent, &rr, &srs, &rho, 7, 0, &prover));
        // Binds every input: a different beacon, frame, rank, or content changes it.
        let rho2 = [0x56u8; 32];
        assert_ne!(a, deterministic_app_frame_output(&parent, &rr, &srs, &rho2, 7, 0, &prover));
        assert_ne!(a, deterministic_app_frame_output(&parent, &rr, &srs, &rho, 8, 0, &prover));
        assert_ne!(a, deterministic_app_frame_output(&parent, &rr, &srs, &rho, 7, 1, &prover));
        assert_ne!(a, deterministic_app_frame_output(&parent, &[0x23u8; 64], &srs, &rho, 7, 0, &prover));
    }

    #[test]
    fn frame_audit_flags_unregistered_and_tampered() {
        use std::collections::HashMap;
        bls48581::init();
        let poly_size = 16u64;
        let rho_n = [0xA1u8; 32];
        let openings = build_attestation(&rho_n, poly_size);
        let epoch = openings[0].epoch;

        // Registry derived from the honest openings.
        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for o in &openings {
            reg.insert(
                (o.member_id.clone(), o.shard_id.clone()),
                (o.leaf_root.clone(), o.num_blocks, epoch),
            );
        }
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();

        // Audit everything (sample ≥ total): all honest + registered → no failures.
        let failed =
            audit_frame_storage_attestations(&openings, &rho_n, poly_size, epoch, u64::MAX, &good);
        assert!(failed.is_empty(), "honest registered openings must pass: {failed:?}");

        // A member whose leaf isn't registered for this epoch is flagged.
        let good_no_m1 = |m: &[u8], l: &[u8]| {
            if m == b"m1" { None } else { reg.get(&(m.to_vec(), l.to_vec())).cloned() }
        };
        let failed = audit_frame_storage_attestations(
            &openings, &rho_n, poly_size, epoch, u64::MAX, &good_no_m1,
        );
        assert_eq!(failed, vec![b"m1".to_vec()]);

        // A tampered possession (wrong evaluation value) is flagged.
        let mut tampered = openings.clone();
        for o in tampered.iter_mut() {
            if o.member_id == b"m2" {
                o.value = vec![0xFFu8; o.value.len()];
            }
        }
        let failed =
            audit_frame_storage_attestations(&tampered, &rho_n, poly_size, epoch, u64::MAX, &good);
        assert!(failed.contains(&b"m2".to_vec()), "tampered possession must flag m2");
    }

    #[test]
    fn audit_selector_edges_and_determinism() {
        let rho = [0x11u8; 32];
        let id = b"leaf-xyz";
        // num == 0 → never audited; num >= den → always audited.
        assert!(!is_audited(&rho, id, 0, 1000));
        assert!(is_audited(&rho, id, 1000, 1000));
        assert!(is_audited(&rho, id, 2000, 1000));
        assert!(is_audited(&rho, id, 5, 0)); // den==0 → audit all
        // Deterministic for fixed inputs.
        let a = is_audited(&rho, id, 500, 1000);
        let b = is_audited(&rho, id, 500, 1000);
        assert_eq!(a, b);
    }

    #[test]
    fn audit_selector_is_beacon_dependent_and_roughly_rated() {
        // 4000 distinct leaf ids; ~25% target sample rate.
        let ids: Vec<Vec<u8>> =
            (0u32..4000).map(|i| i.to_be_bytes().to_vec()).collect();
        let rho_a = [0x22u8; 32];
        let rho_b = [0x33u8; 32];

        let sel_a = select_audited(&rho_a, &ids, 1, 4);
        let sel_b = select_audited(&rho_b, &ids, 1, 4);

        // Roughly the target rate (25% of 4000 = 1000; wide tolerance for a
        // statistical hash split).
        assert!(
            (700..1300).contains(&sel_a.len()),
            "sample rate off: {} audited of 4000 at 1/4",
            sel_a.len()
        );

        // Beacon-dependent: a different ρ_N audits a substantially different
        // set (the unpredictability the storage guarantee relies on).
        use std::collections::HashSet;
        let set_a: HashSet<&[u8]> = sel_a.iter().copied().collect();
        let overlap = sel_b.iter().filter(|id| set_a.contains(*id)).count();
        assert!(
            overlap < sel_b.len(),
            "different beacons must not select an identical audited set"
        );
    }
}
