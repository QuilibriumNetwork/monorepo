//! Node-side verification for the coefficient-packed ZK range proof — the first
//! step of adopting [`quil_lattice_ct::labrador_ct`]'s compressed confidential
//! range proof into the token intrinsic.
//!
//! The transaction's `range_proof` bytes are a VERSIONED envelope
//! ([`quil_lattice_ct::wire::decode_range_versioned`]): a 1-byte tag selects the
//! legacy [`RangeProofRq`](quil_lattice_ct::range_rq::RangeProofRq) or the new
//! packed ZK proof, so the two can never be confused (fail-closed on an unknown
//! tag). This module verifies the packed variant: it rebuilds the public
//! statement from the network's packed key, the transaction-supplied
//! bit-commitment `c_b`, and the range width, then runs the crate's
//! [`verify_range_zk`]. Verifying is the consensus-critical direction; the prover
//! side lives in the wallet.
//!
//! This module also hosts the node entry points for the full-width (fw) amortized
//! money path (mint/transfer/escrow): one IPA proof per transaction covering the
//! per-limb output ranges and the carry-chain balance, with each input pinned to
//! its spend-proof `c_prime`.

use quil_lattice_ct::labrador_ct::balance_zk::{combined_commitment, verify_balance};
use quil_lattice_ct::labrador_ct::packed::PackedRangeStatement;
use quil_lattice_ct::labrador_ct::verify_range_zk;
use quil_lattice_ct::module::{RingCommitKey, RingCommitment};
use quil_lattice_ct::wire::{decode_packed_balance, decode_range_versioned, RangeProofKind};
use quil_types::error::{QuilError, Result};

/// Verify a versioned `range_proof` envelope that carries the PACKED ZK proof,
/// against the public statement `(packed_key, c_b, n_bits)`.
///
/// Fail-closed: an unknown/absent version tag, a malformed payload, or a
/// commitment-shape mismatch all return `Ok(false)` or `Err` — never a silent
/// accept. A LEGACY-tagged envelope is rejected here (the caller routes legacy to
/// the existing `verify_range_rq` path); pass only envelopes intended as packed.
pub fn verify_packed_range(
    packed_key: &RingCommitKey,
    c_b: &RingCommitment,
    n_bits: usize,
    envelope: &[u8],
) -> Result<bool> {
    let kind = decode_range_versioned(envelope)
        .map_err(|_| QuilError::InvalidArgument("packed range: malformed envelope".into()))?;
    let proof = match kind {
        RangeProofKind::PackedZk(p) => p,
        RangeProofKind::Legacy(_) => {
            return Err(QuilError::InvalidArgument("packed range: legacy proof on packed path".into()));
        }
    };
    // The bit commitment must have the shape this key produces (t2 is one ring
    // element — the packed message). Reject a malformed c_b rather than panic.
    if c_b.t2.0.len() != 1 {
        return Ok(false);
    }
    let stmt = PackedRangeStatement {
        key: packed_key.clone(),
        c_b: c_b.clone(),
        n_bits,
    };
    Ok(verify_range_zk(&stmt, &proof))
}

/// Verify a COMPLETE packed confidential transaction on the consensus path:
/// every OUTPUT is range-proved (`v ∈ [0, 2^{n_bits})`, no negative/overflow
/// amounts) and the transaction BALANCES (`Σin v = Σout v + fee`). The packed
/// `c_b`s ARE the amount commitments (value `= ⟪g,b⟫`, homomorphic), so no
/// separate value commitment or value-binding is needed.
///
/// Fail-closed throughout: malformed bytes, wrong shot count, non-canonical
/// coefficients, or any failed check → `Ok(false)` / `Err`.
#[allow(clippy::too_many_arguments)]
pub fn verify_packed_transaction(
    packed_key: &RingCommitKey,
    in_commitments: &[RingCommitment],
    out_commitments: &[RingCommitment],
    out_range_envelopes: &[Vec<u8>],
    balance_bytes: &[u8],
    fee: u64,
    n_bits: usize,
) -> Result<bool> {
    if out_range_envelopes.len() != out_commitments.len() {
        return Ok(false);
    }
    // 1. Range-prove every output (non-negative, bounded ⇒ no output inflates).
    for (c_b, env) in out_commitments.iter().zip(out_range_envelopes) {
        if !verify_packed_range(packed_key, c_b, n_bits, env)? {
            return Ok(false);
        }
    }
    // 2. Balance: Σin v = Σout v + fee over the homomorphic combined commitment.
    let d = combined_commitment(in_commitments, out_commitments);
    let bal = decode_packed_balance(balance_bytes)
        .map_err(|_| QuilError::InvalidArgument("packed tx: malformed balance proof".into()))?;
    Ok(verify_balance(packed_key, &d, fee, n_bits, &bal))
}

/// A built packed transaction's wire pieces (the wallet fills the `TxEnvelope`
/// byte fields with these).
pub struct BuiltPackedTx {
    /// `output_commitments[i]` = wire-encoded packed `c_b` for output i.
    pub output_commitments: Vec<Vec<u8>>,
    /// `output_range_proofs[i]` = versioned range-proof envelope for output i.
    pub output_range_proofs: Vec<Vec<u8>>,
    /// `balance_proof` = version-tagged packed balance proof (`Σin=Σout+fee`).
    pub balance_proof: Vec<u8>,
}

/// Version tag on the balance-proof bytes selecting the PACKED balance path.
pub const BALANCE_V_PACKED: u8 = 2;

/// WALLET PROVER: build a packed confidential transaction. `inputs`/`outputs` are
/// `(amount, randomness)` for the packed bit commitments this wallet controls
/// (`amount < q`, i.e. ≤ ~36-bit per commitment — full-width uses per-limb packed
/// commitments, a mechanical extension). Range-proves every output and proves the
/// balance `Σin = Σout + fee`. Returns the wire pieces + the input commitments
/// (which the on-chain coins already carry, recomputed here for the balance `D`).
pub fn prove_packed_transaction(
    packed_key: &RingCommitKey,
    inputs: &[(u64, quil_lattice_ct::module::PolyVec)],
    outputs: &[(u64, quil_lattice_ct::module::PolyVec)],
    fee: u64,
    n_bits: usize,
    seed: u64,
) -> Result<(BuiltPackedTx, Vec<RingCommitment>)> {
    use quil_lattice_ct::labrador_ct::balance_zk::{combined_commitment, prove_balance};
    use quil_lattice_ct::labrador_ct::packed::{PackedRangeStatement, PackedRangeWitness};
    use quil_lattice_ct::labrador_ct::prove_range_zk;
    use quil_lattice_ct::module::PolyVec;
    use quil_lattice_ct::rq::Poly;
    use quil_lattice_ct::wire::{encode_commitment, encode_packed_balance, encode_range_versioned_packed_zk};

    let bits_of = |v: u64| -> Poly {
        let mut b = Poly::zero();
        for i in 0..n_bits {
            b.c[i] = (v >> i) & 1;
        }
        b
    };
    let commit = |v: u64, r: &PolyVec| -> (RingCommitment, Poly) {
        let b = bits_of(v);
        (packed_key.commit(&PolyVec(vec![b.clone()]), r), b)
    };

    // Input commitments (recomputed) + their bit polys for the balance.
    let mut in_commits = Vec::with_capacity(inputs.len());
    let mut in_bits = Vec::with_capacity(inputs.len());
    for (v, r) in inputs {
        let (c, b) = commit(*v, r);
        in_commits.push(c);
        in_bits.push((b, r.clone()));
    }
    // Outputs: commitments + range proofs.
    let mut out_commits = Vec::with_capacity(outputs.len());
    let mut out_commit_bytes = Vec::with_capacity(outputs.len());
    let mut out_range = Vec::with_capacity(outputs.len());
    let mut out_bits = Vec::with_capacity(outputs.len());
    for (i, (v, r)) in outputs.iter().enumerate() {
        let (c, b) = commit(*v, r);
        let stmt = PackedRangeStatement { key: packed_key.clone(), c_b: c.clone(), n_bits };
        let wit = PackedRangeWitness { bit_poly: b.clone(), r_b: r.clone() };
        let rp = prove_range_zk(&stmt, &wit, seed ^ (0x9E1 + i as u64))
            .ok_or_else(|| QuilError::InvalidArgument("packed tx: range prove failed".into()))?;
        out_commit_bytes.push(encode_commitment(&c));
        out_range.push(encode_range_versioned_packed_zk(&rp));
        out_commits.push(c);
        out_bits.push((b, r.clone()));
    }

    // Balance: B = Σin b − Σout b, R = Σin r − Σout r.
    let mut big_b = Poly::zero();
    let mut big_r = PolyVec::zero(packed_key.a1.cols);
    for (b, r) in &in_bits {
        big_b = big_b.add(b);
        big_r = big_r.add(r);
    }
    for (b, r) in &out_bits {
        big_b = big_b.sub(b);
        big_r = big_r.add(&PolyVec(r.0.iter().map(|p| p.neg()).collect()));
    }
    let d = combined_commitment(&in_commits, &out_commits);
    let bal = prove_balance(packed_key, &d, &big_b, &big_r, fee, n_bits, seed ^ 0xBA1)
        .ok_or_else(|| QuilError::InvalidArgument("packed tx: balance prove failed".into()))?;
    let mut balance_proof = vec![BALANCE_V_PACKED];
    balance_proof.extend(encode_packed_balance(&bal));

    Ok((
        BuiltPackedTx { output_commitments: out_commit_bytes, output_range_proofs: out_range, balance_proof },
        in_commits,
    ))
}

/// NODE VERIFY dispatch from the raw `TxEnvelope` byte fields: decode packed
/// commitments + range envelopes + the version-tagged balance proof, then run
/// [`verify_packed_transaction`]. The `input_commitments` are the on-chain coins
/// being spent (wire-encoded packed `c_b`).
pub fn verify_packed_transaction_bytes(
    packed_key: &RingCommitKey,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    output_range_proofs: &[Vec<u8>],
    balance_proof: &[u8],
    fee: u64,
    n_bits: usize,
) -> Result<bool> {
    use quil_lattice_ct::wire::decode_commitment;
    let (&tag, bal_body) = balance_proof
        .split_first()
        .ok_or_else(|| QuilError::InvalidArgument("packed tx: empty balance proof".into()))?;
    if tag != BALANCE_V_PACKED {
        return Ok(false); // not a packed-tagged balance proof
    }
    let dec = |cs: &[Vec<u8>]| -> Result<Vec<RingCommitment>> {
        cs.iter()
            .map(|b| decode_commitment(b).map_err(|_| QuilError::InvalidArgument("packed tx: bad commitment".into())))
            .collect()
    };
    let in_c = dec(input_commitments)?;
    let out_c = dec(output_commitments)?;
    verify_packed_transaction(packed_key, &in_c, &out_c, output_range_proofs, bal_body, fee, n_bits)
}

/// FULL-WIDTH packed ranges: for each base-2⁸ limb of an amount, a packed `c_b`
/// range-proved (`limb ∈ [0,2^{n_bits})`) AND value-linked to that limb's slice
/// of the amount's limb commitment. This replaces the per-limb `range_rq` in the
/// full-width limb balance — the carry-chain balance itself stays unchanged, so
/// 64/128-bit amounts get the packed proofs per limb (each limb `< q`).
pub struct PackedLimbRanges {
    /// per-limb `(c_b_bytes, range_envelope, value_link_bytes)`.
    pub limbs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

/// Tag on a packed per-output range blob (rides `output_range_proofs[i]`).
pub const RANGE_V_PACKED_LIMBS: u8 = 3;

/// Serialize `PackedLimbRanges` as `[tag] ‖ n ‖ (len‖c_b, len‖range, len‖link)×n`.
pub fn encode_packed_limb_ranges(p: &PackedLimbRanges) -> Vec<u8> {
    let mut out = vec![RANGE_V_PACKED_LIMBS];
    out.extend((p.limbs.len() as u32).to_le_bytes());
    for (cb, rng, lnk) in &p.limbs {
        for part in [cb, rng, lnk] {
            out.extend((part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
    }
    out
}

/// Decode a packed per-output range blob (fail-closed).
pub fn decode_packed_limb_ranges(b: &[u8]) -> Result<PackedLimbRanges> {
    let err = || QuilError::InvalidArgument("packed limb ranges: malformed".into());
    let (&tag, mut rest) = b.split_first().ok_or_else(err)?;
    if tag != RANGE_V_PACKED_LIMBS {
        return Err(err());
    }
    let take_u32 = |r: &mut &[u8]| -> Result<usize> {
        if r.len() < 4 {
            return Err(err());
        }
        let (h, t) = r.split_at(4);
        *r = t;
        Ok(u32::from_le_bytes(h.try_into().unwrap()) as usize)
    };
    let take = |r: &mut &[u8]| -> Result<Vec<u8>> {
        let n = take_u32(r)?;
        if r.len() < n {
            return Err(err());
        }
        let (h, t) = r.split_at(n);
        *r = t;
        Ok(h.to_vec())
    };
    let n = take_u32(&mut rest)?;
    let mut limbs = Vec::with_capacity(n);
    for _ in 0..n {
        limbs.push((take(&mut rest)?, take(&mut rest)?, take(&mut rest)?));
    }
    if !rest.is_empty() {
        return Err(err());
    }
    Ok(PackedLimbRanges { limbs })
}

/// Whether `output_range_proofs` carry the packed per-limb ranges (vs legacy/empty).
pub fn is_packed_output_ranges(output_range_proofs: &[Vec<u8>]) -> bool {
    output_range_proofs.first().map(|b| b.first() == Some(&RANGE_V_PACKED_LIMBS)).unwrap_or(false)
}

/// Tag marking the FULL-WIDTH amortized money path: the output coins are fw coins
/// and the single IPA proof (carried in `balance_proof`) covers ranges + balance.
pub const RANGE_V_FULLWIDTH: u8 = 4;
/// The `output_range_proofs` marker a full-width tx carries (a single tag; the real
/// proof rides `balance_proof`).
pub fn fw_output_ranges_marker() -> Vec<Vec<u8>> {
    vec![vec![RANGE_V_FULLWIDTH]]
}
/// Whether `output_range_proofs` mark the full-width amortized path.
pub fn is_fw_output_ranges(output_range_proofs: &[Vec<u8>]) -> bool {
    output_range_proofs.first().map(|b| b.first() == Some(&RANGE_V_FULLWIDTH)).unwrap_or(false)
}

// ── SUPERSEDED — single-value amortized IPA range/tx proof ───────────────────
//
// These node entry points wrap the single-value amortized proof
// (`commit_multi_range`/`commit_multi_tx` + `*_multi_range_ipa_zk`), which commits
// each amount as ONE ≤~36-bit coefficient value and so covers only sub-2³⁵ amounts.
// The `fullwidth` path (full u128 per-limb coins) replaced them and is the only
// money path wired into the node. The underlying crate provers are FORCED TO FAIL,
// so these inherit that: the `prove_*` functions return `Err` and the `verify_*`
// functions return `Ok(false)`. Kept for lineage; their tests are `#[ignore]`d.

/// Fixed network CRS seed for the amortized multi-range commitment key.
pub const AMORTIZED_RANGE_SEED: u64 = 0x5175_4C41_4D5A_3100; // "QuLAMZ1\0"

/// WALLET: build the amortized IPA range proof for a tx's output amounts. Returns
/// the wire-encoded shared commitment `c_b` and the proof.
pub fn prove_amortized_output_ranges(
    out_amounts: &[u64],
    n_bits: usize,
    seed: u64,
) -> Result<(Vec<u8>, quil_lattice_ct::labrador::FullCtZkIpaProof)> {
    use quil_lattice_ct::labrador_ct::packed::{commit_multi_range, prove_multi_range_ipa_zk};
    use quil_lattice_ct::wire::encode_commitment;
    let (stmt, wit) = commit_multi_range(n_bits, out_amounts, AMORTIZED_RANGE_SEED, seed);
    let proof = prove_multi_range_ipa_zk(&stmt, &wit, seed ^ 0xA111)
        .ok_or_else(|| QuilError::InvalidArgument("amortized range prove failed".into()))?;
    Ok((encode_commitment(&stmt.c_b), proof))
}

/// NODE: verify the amortized IPA range proof for `m` outputs, reconstructing the
/// commitment key from the FIXED network CRS (not trusting the sent statement).
pub fn verify_amortized_output_ranges(
    m: usize,
    n_bits: usize,
    c_b_bytes: &[u8],
    proof: &quil_lattice_ct::labrador::FullCtZkIpaProof,
) -> Result<bool> {
    use quil_lattice_ct::labrador_ct::packed::{verify_multi_range_ipa_zk, MultiRangeStatement};
    use quil_lattice_ct::wire::decode_commitment;
    let key = RingCommitKey::production(m, AMORTIZED_RANGE_SEED);
    let c_b = decode_commitment(c_b_bytes)
        .map_err(|_| QuilError::InvalidArgument("amortized range: malformed commitment".into()))?;
    let stmt = MultiRangeStatement { key, c_b, m, n_bits, n_in: 0, fee: 0 };
    Ok(verify_multi_range_ipa_zk(&stmt, proof))
}

/// WALLET: build ONE amortized IPA proof covering BOTH the ranges (all inputs +
/// outputs are binary/bounded) AND the balance (`Σin − Σout = fee`). The inputs'
/// bit_polys are committed in the shared `c_b`; membership of the input coins is a
/// SEPARATE proof (the spend proofs), as today.
pub fn prove_amortized_tx(
    in_amounts: &[u64],
    out_amounts: &[u64],
    fee: u64,
    n_bits: usize,
    seed: u64,
) -> Result<(Vec<u8>, quil_lattice_ct::labrador::FullCtZkIpaProof)> {
    use quil_lattice_ct::labrador_ct::packed::{commit_multi_tx, prove_multi_range_ipa_zk};
    use quil_lattice_ct::wire::encode_commitment;
    let (stmt, wit) = commit_multi_tx(n_bits, in_amounts, out_amounts, fee, AMORTIZED_RANGE_SEED, seed);
    let proof = prove_multi_range_ipa_zk(&stmt, &wit, seed ^ 0xB222)
        .ok_or_else(|| QuilError::InvalidArgument("amortized tx prove failed (unbalanced or out of range?)".into()))?;
    Ok((encode_commitment(&stmt.c_b), proof))
}

/// WALLET: like [`prove_amortized_tx`] but returns the tx BYTES `(c_b, proof)` —
/// the proof serialized as it rides the transaction.
pub fn prove_amortized_tx_bytes(
    in_amounts: &[u64],
    out_amounts: &[u64],
    fee: u64,
    n_bits: usize,
    seed: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (c_b, proof) = prove_amortized_tx(in_amounts, out_amounts, fee, n_bits, seed)?;
    Ok((c_b, quil_lattice_ct::wire::encode_full_ct_zk_ipa_compact(&proof)))
}

/// NODE: verify an amortized full-TX proof from its serialized BYTES (fail-closed
/// on a malformed proof).
pub fn verify_amortized_tx_bytes(
    m_in: usize,
    m_out: usize,
    fee: u64,
    n_bits: usize,
    c_b_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<bool> {
    let proof = quil_lattice_ct::wire::decode_full_ct_zk_ipa_compact(proof_bytes)
        .map_err(|_| QuilError::InvalidArgument("amortized tx: malformed proof bytes".into()))?;
    verify_amortized_tx(m_in, m_out, fee, n_bits, c_b_bytes, &proof)
}

/// NODE: verify an amortized full-TX proof (ranges + balance) for `m_in` inputs and
/// `m_out` outputs at fee `fee`, reconstructing the key from the fixed network CRS.
pub fn verify_amortized_tx(
    m_in: usize,
    m_out: usize,
    fee: u64,
    n_bits: usize,
    c_b_bytes: &[u8],
    proof: &quil_lattice_ct::labrador::FullCtZkIpaProof,
) -> Result<bool> {
    use quil_lattice_ct::labrador_ct::packed::{verify_multi_range_ipa_zk, MultiRangeStatement};
    use quil_lattice_ct::wire::decode_commitment;
    let m = m_in + m_out;
    let key = RingCommitKey::production(m, AMORTIZED_RANGE_SEED);
    let c_b = decode_commitment(c_b_bytes)
        .map_err(|_| QuilError::InvalidArgument("amortized tx: malformed commitment".into()))?;
    let stmt = MultiRangeStatement { key, c_b, m, n_bits, n_in: m_in, fee };
    Ok(verify_multi_range_ipa_zk(&stmt, proof))
}

// ── FULL-WIDTH (u128) amortized money path — the fw coin ─────────────────────
// A fw coin `cv = value_key.commit([bit-polys]; r)` — committed under the NETWORK
// value_key so it is spendable via the (message-agnostic) membership relation. One
// IPA proof covers per-limb ranges + carry-chain balance. Node entry points below
// reconstruct the statement from on-chain coin commitments + the PUBLIC amounts.

/// Full-width limb count (u128 = 16 base-2^8 limbs), the network coin width.
pub const FW_N_LIMBS: usize = quil_lattice_ct::value_link::VALUE_LIMBS;

/// WALLET: build a full-width MINT — a public `mint_amount` conserved into hidden
/// output coins (under `value_key`). Returns the per-output coin commitments + proof.
pub fn prove_fw_mint(
    value_key: &RingCommitKey,
    mint_amount: u128,
    out_amounts: &[u128],
    seed: u64,
) -> Result<(Vec<Vec<u8>>, quil_lattice_ct::labrador::FullCtZkIpaProof)> {
    use quil_lattice_ct::labrador_ct::fullwidth::{commit_fw_mint, prove_fw_tx_ipa_zk};
    use quil_lattice_ct::wire::encode_commitment;
    let (stmt, wit, coins) = commit_fw_mint(FW_N_LIMBS, mint_amount, out_amounts, value_key, seed);
    let proof = prove_fw_tx_ipa_zk(&stmt, &wit, seed ^ 0xF117)
        .ok_or_else(|| QuilError::InvalidArgument("fw mint prove failed (over-mint or out of range?)".into()))?;
    let coin_bytes = coins.iter().map(encode_commitment).collect();
    Ok((coin_bytes, proof))
}

/// NODE: verify a full-width MINT proof — `Σ output coins = mint_amount` (conservation
/// + per-limb ranges), under the network `value_key`.
pub fn verify_fw_mint(
    value_key: &RingCommitKey,
    mint_amount: u128,
    out_coins: &[RingCommitment],
    proof: &quil_lattice_ct::labrador::FullCtZkIpaProof,
) -> Result<bool> {
    use quil_lattice_ct::labrador_ct::fullwidth::{stack_coins, verify_fw_tx_ipa_zk, FwTxStatement};
    let c_b = stack_coins(out_coins);
    let stmt = FwTxStatement { key: value_key.clone(), c_b, m: out_coins.len(), n_in: 0, n_limbs: FW_N_LIMBS, fee: 0, pub_in: mint_amount };
    Ok(verify_fw_tx_ipa_zk(&stmt, proof))
}

/// NODE: verify a full-width MINT from SERIALIZED bytes (fail-closed on malformed).
pub fn verify_fw_mint_bytes(
    value_key: &RingCommitKey,
    mint_amount: u128,
    out_coin_bytes: &[Vec<u8>],
    proof_bytes: &[u8],
) -> Result<bool> {
    use quil_lattice_ct::wire::{decode_commitment, decode_full_ct_zk_ipa_compact};
    let out_coins: std::result::Result<Vec<RingCommitment>, _> =
        out_coin_bytes.iter().map(|b| decode_commitment(b)).collect();
    let out_coins = out_coins.map_err(|_| QuilError::InvalidArgument("fw mint: malformed coin commitment".into()))?;
    let proof = decode_full_ct_zk_ipa_compact(proof_bytes)
        .map_err(|_| QuilError::InvalidArgument("fw mint: malformed proof bytes".into()))?;
    verify_fw_mint(value_key, mint_amount, &out_coins, &proof)
}

/// WALLET: `prove_fw_mint` returning the proof BYTES (compact codec) alongside the
/// per-output coin commitments — the form a mint tx carries.
pub fn prove_fw_mint_bytes(
    value_key: &RingCommitKey,
    mint_amount: u128,
    out_amounts: &[u128],
    seed: u64,
) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let (coins, proof) = prove_fw_mint(value_key, mint_amount, out_amounts, seed)?;
    Ok((coins, quil_lattice_ct::wire::encode_full_ct_zk_ipa_compact(&proof)))
}

/// WALLET/TEST: build a full-width TRANSFER — hidden inputs (each with a `c_prime`
/// under `value_key`) into hidden fw output coins. Returns the output coin bytes,
/// the input `c_prime` bytes (as the spend proofs would carry), and the proof bytes.
/// In production the `c_prime`s + their randomness come from the spend proofs; this
/// self-generates them for the wallet/test path.
pub fn prove_fw_transfer_bytes(
    value_key: &RingCommitKey,
    in_amounts: &[u128],
    out_amounts: &[u128],
    fee: u128,
    seed: u64,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<u8>)> {
    use quil_lattice_ct::labrador_ct::fullwidth::{commit_fw_transfer, prove_fw_transfer_ipa_zk};
    use quil_lattice_ct::wire::encode_commitment;
    // Uniform fw: coins and c_primes are BOTH `value_key.commit(bit-polys)`.
    let (stmt, wit, out_coins) = commit_fw_transfer(FW_N_LIMBS, in_amounts, out_amounts, fee, value_key, value_key, seed);
    let proof = prove_fw_transfer_ipa_zk(&stmt, &wit, seed ^ 0xF227)
        .ok_or_else(|| QuilError::InvalidArgument("fw transfer prove failed (unbalanced?)".into()))?;
    let out_bytes = out_coins.iter().map(encode_commitment).collect();
    let cprime_bytes = stmt.c_primes.iter().map(encode_commitment).collect();
    Ok((out_bytes, cprime_bytes, quil_lattice_ct::wire::encode_full_ct_zk_ipa_compact(&proof)))
}

/// NODE: verify a full-width TRANSFER — output ranges + balance, with each input's
/// value PINNED to its spend-proof `c_prime` (under `value_key`). The output coins
/// stack to the amortized `c_b`; `c_primes` come from the spend proofs.
pub fn verify_fw_transfer(
    value_key: &RingCommitKey,
    out_coins: &[RingCommitment],
    c_primes: &[RingCommitment],
    fee: u128,
    proof: &quil_lattice_ct::labrador::FullCtZkIpaProof,
) -> Result<bool> {
    use quil_lattice_ct::labrador_ct::fullwidth::{stack_coins, verify_fw_transfer_ipa_zk, FwTransferStatement};
    let stmt = FwTransferStatement {
        coin_key: value_key.clone(),
        value_key: value_key.clone(),
        c_b: stack_coins(out_coins),
        c_primes: c_primes.to_vec(),
        n_in: c_primes.len(),
        n_out: out_coins.len(),
        n_limbs: FW_N_LIMBS,
        fee,
    };
    Ok(verify_fw_transfer_ipa_zk(&stmt, proof))
}

/// NODE: verify a full-width TRANSFER from SERIALIZED bytes (fail-closed).
pub fn verify_fw_transfer_bytes(
    value_key: &RingCommitKey,
    out_coin_bytes: &[Vec<u8>],
    cprime_bytes: &[Vec<u8>],
    fee: u128,
    proof_bytes: &[u8],
) -> Result<bool> {
    use quil_lattice_ct::wire::{decode_commitment, decode_full_ct_zk_ipa_compact};
    let dec = |bs: &[Vec<u8>]| -> Result<Vec<RingCommitment>> {
        bs.iter()
            .map(|b| decode_commitment(b).map_err(|_| QuilError::InvalidArgument("fw transfer: malformed commitment".into())))
            .collect()
    };
    let out_coins = dec(out_coin_bytes)?;
    let c_primes = dec(cprime_bytes)?;
    let proof = decode_full_ct_zk_ipa_compact(proof_bytes)
        .map_err(|_| QuilError::InvalidArgument("fw transfer: malformed proof bytes".into()))?;
    verify_fw_transfer(value_key, &out_coins, &c_primes, fee, &proof)
}

/// NODE: verify the packed per-limb ranges for EVERY output against its
/// (limb) amount commitment. Used alongside the limb carry-chain balance.
pub fn verify_packed_output_ranges(
    packed_key: &RingCommitKey,
    limb_value_key: &RingCommitKey,
    output_commitments: &[RingCommitment],
    output_range_proofs: &[Vec<u8>],
    n_bits: usize,
) -> Result<bool> {
    if output_range_proofs.len() != output_commitments.len() {
        return Ok(false);
    }
    for (out_c, blob) in output_commitments.iter().zip(output_range_proofs) {
        let ranges = decode_packed_limb_ranges(blob)?;
        if !verify_packed_limb_ranges(packed_key, limb_value_key, out_c, &ranges, n_bits)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The limb-`j` value-commitment slice of a `ℓ=VALUE_LIMBS` amount commitment:
/// `(t1, [t2[j]])` — a valid `ℓ=1` commitment to `limb_j` under the limb value key.
fn limb_slice(c: &RingCommitment, j: usize) -> RingCommitment {
    RingCommitment { t1: c.t1.clone(), t2: quil_lattice_ct::module::PolyVec(vec![c.t2.0[j].clone()]) }
}

/// WALLET: build the per-limb packed ranges + value-links for one amount. `out_c`
/// is the amount's `ℓ=VALUE_LIMBS` commitment `= limb_value_key.commit(limbs; r)`.
#[allow(clippy::too_many_arguments)]
pub fn prove_packed_limb_ranges(
    packed_key: &RingCommitKey,
    limb_value_key: &RingCommitKey,
    out_c: &RingCommitment,
    amount: u128,
    r: &quil_lattice_ct::module::PolyVec,
    n_limbs: usize,
    n_bits: usize,
    seed: u64,
) -> Result<PackedLimbRanges> {
    use quil_lattice_ct::labrador_ct::packed::{PackedRangeStatement, PackedRangeWitness};
    use quil_lattice_ct::labrador_ct::prove_range_zk;
    use quil_lattice_ct::limb_balance::limbs_of;
    use quil_lattice_ct::module::PolyVec;
    use quil_lattice_ct::rq::Poly;
    use quil_lattice_ct::wire::{encode_commitment, encode_range_versioned_packed_zk, encode_value_link};

    let limbs = limbs_of(amount, n_limbs);
    let mut out = Vec::with_capacity(n_limbs);
    for (j, &limb) in limbs.iter().enumerate() {
        let mut b = Poly::zero();
        for i in 0..n_bits {
            b.c[i] = (limb >> i) & 1;
        }
        let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed ^ (0x11B0 + j as u64));
        let r_b = PolyVec::sample_short(packed_key.a1.cols, quil_lattice_ct::module::ETA, &mut prg);
        let c_b = packed_key.commit(&PolyVec(vec![b.clone()]), &r_b);
        // range proof.
        let stmt = PackedRangeStatement { key: packed_key.clone(), c_b: c_b.clone(), n_bits };
        let wit = PackedRangeWitness { bit_poly: b.clone(), r_b: r_b.clone() };
        let rp = prove_range_zk(&stmt, &wit, seed ^ (0x22C0 + j as u64))
            .ok_or_else(|| QuilError::InvalidArgument("packed limb: range prove failed".into()))?;
        // value-link to the limb slice (value = limb, randomness = r shared across limbs).
        let c_v = limb_slice(out_c, j);
        let link = quil_lattice_ct::labrador_ct::balance_zk::prove_value_link(
            packed_key, limb_value_key, &c_b, &c_v, &b, &r_b, limb, r, n_bits, seed ^ (0x33D0 + j as u64),
        )
        .ok_or_else(|| QuilError::InvalidArgument("packed limb: value-link prove failed".into()))?;
        out.push((encode_commitment(&c_b), encode_range_versioned_packed_zk(&rp), encode_value_link(&link)));
    }
    Ok(PackedLimbRanges { limbs: out })
}

/// NODE: verify the per-limb packed ranges + value-links for one amount's limb
/// commitment `out_c`. Each limb is range-proved (non-negative, bounded ⇒ no
/// inflation) AND provably equals the amount's committed limb — so the existing
/// carry-chain balance over `out_c` still binds the real values.
pub fn verify_packed_limb_ranges(
    packed_key: &RingCommitKey,
    limb_value_key: &RingCommitKey,
    out_c: &RingCommitment,
    ranges: &PackedLimbRanges,
    n_bits: usize,
) -> Result<bool> {
    use quil_lattice_ct::wire::decode_commitment;
    if ranges.limbs.len() != out_c.t2.0.len() {
        return Ok(false);
    }
    for (j, (c_b_bytes, range_env, link_bytes)) in ranges.limbs.iter().enumerate() {
        let c_b = decode_commitment(c_b_bytes)
            .map_err(|_| QuilError::InvalidArgument("packed limb: bad c_b".into()))?;
        // (1) range: limb ∈ [0, 2^{n_bits}).
        if !verify_packed_range(packed_key, &c_b, n_bits, range_env)? {
            return Ok(false);
        }
        // (2) value-link: c_b commits the SAME value as the amount's limb slice.
        let c_v = limb_slice(out_c, j);
        if !verify_packed_spend_input(packed_key, limb_value_key, &c_b, &c_v, n_bits, link_bytes)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// PACKED SPEND INPUT: bind a packed `c_b` pseudo-input to a spent coin's scalar
/// value commitment `c_v` (under the value key), proving they commit the SAME
/// value (`⟪g,b⟫ = v`). This is the bridge that lets the limb-committed
/// accumulator feed the packed balance without rewriting membership: the spend
/// proof (membership + key image) stays as-is; the packed pseudo-input is
/// value-linked to the revealed coin commitment. Fail-closed.
pub fn verify_packed_spend_input(
    packed_key: &RingCommitKey,
    value_key: &RingCommitKey,
    c_b: &RingCommitment,
    c_v: &RingCommitment,
    n_bits: usize,
    link_bytes: &[u8],
) -> Result<bool> {
    use quil_lattice_ct::labrador_ct::balance_zk::verify_value_link;
    use quil_lattice_ct::wire::decode_value_link;
    let link = decode_value_link(link_bytes)
        .map_err(|_| QuilError::InvalidArgument("packed spend: malformed value-link".into()))?;
    if c_b.t2.0.len() != 1 || c_v.t2.0.len() != 1 {
        return Ok(false);
    }
    Ok(verify_value_link(packed_key, value_key, c_b, c_v, n_bits, &link))
}

/// WALLET: build a packed spend input — a packed `c_b` for the coin's value plus
/// the value-link proof binding it to the coin's scalar value commitment `c_v`.
pub fn prove_packed_spend_input(
    packed_key: &RingCommitKey,
    value_key: &RingCommitKey,
    value: u64,
    r_b: &quil_lattice_ct::module::PolyVec,
    c_v: &RingCommitment,
    r_v: &quil_lattice_ct::module::PolyVec,
    n_bits: usize,
    seed: u64,
) -> Result<(RingCommitment, Vec<u8>)> {
    use quil_lattice_ct::labrador_ct::balance_zk::prove_value_link;
    use quil_lattice_ct::module::PolyVec;
    use quil_lattice_ct::rq::Poly;
    use quil_lattice_ct::wire::encode_value_link;
    let mut b = Poly::zero();
    for i in 0..n_bits {
        b.c[i] = (value >> i) & 1;
    }
    let c_b = packed_key.commit(&PolyVec(vec![b.clone()]), r_b);
    let link = prove_value_link(packed_key, value_key, &c_b, c_v, &b, r_b, value, r_v, n_bits, seed)
        .ok_or_else(|| QuilError::InvalidArgument("packed spend: value-link prove failed".into()))?;
    Ok((c_b, encode_value_link(&link)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::labrador_ct::packed::commit_packed;
    use quil_lattice_ct::labrador_ct::prove_range_zk;
    use quil_lattice_ct::wire::encode_range_versioned_packed_zk;

    #[test]
    #[ignore = "superseded by `fullwidth`; underlying prover forced to fail"]
    fn amortized_tx_serialized_bytes_roundtrip() {
        // The full node path over SERIALIZED bytes: wallet proves → encodes → the tx
        // carries the bytes → node decodes + verifies. Balanced verifies; a truncated
        // proof and a wrong fee reject; re-encoding a decoded proof is byte-stable.
        let n_bits = 16;
        let (c_b, proof_bytes) = prove_amortized_tx_bytes(&[100u64, 50], &[120u64, 25], 5, n_bits, 0xD5B1).expect("prove");
        assert!(verify_amortized_tx_bytes(2, 2, 5, n_bits, &c_b, &proof_bytes).unwrap(), "serialized balanced tx verifies");
        // Truncated proof ⇒ malformed ⇒ reject (Err → treated as fail-closed).
        assert!(verify_amortized_tx_bytes(2, 2, 5, n_bits, &c_b, &proof_bytes[..proof_bytes.len() - 40]).is_err(), "truncated proof is malformed");
        // Wrong fee ⇒ reject.
        assert!(!verify_amortized_tx_bytes(2, 2, 6, n_bits, &c_b, &proof_bytes).unwrap_or(false), "wrong fee rejects");
        // Decode/re-encode is byte-stable.
        let decoded = quil_lattice_ct::wire::decode_full_ct_zk_ipa_compact(&proof_bytes).unwrap();
        assert_eq!(quil_lattice_ct::wire::encode_full_ct_zk_ipa_compact(&decoded), proof_bytes, "round-trip byte-stable");
        println!("SERIALIZED amortized tx proof = {} KB", proof_bytes.len() / 1024);
    }

    #[test]
    fn fw_mint_node_serialized_roundtrip() {
        // FULL-WIDTH MINT node path over SERIALIZED bytes: wallet proves a public
        // mint conserved into hidden fw coins → the node decodes the coins + proof and
        // verifies conservation. Honest verifies; wrong claimed mint amount, a tampered
        // coin, and a truncated proof all reject (fail-closed).
        let mint = 1_000_000u128;
        let outs = [600_000u128, 400_000u128];
        let vk = RingCommitKey::production(FW_N_LIMBS, 0xABCD);
        let (coin_bytes, proof_bytes) = prove_fw_mint_bytes(&vk, mint, &outs, 0xF117).expect("prove fw mint");
        assert!(verify_fw_mint_bytes(&vk, mint, &coin_bytes, &proof_bytes).unwrap(), "fw mint conserving 1_000_000 verifies");
        // Wrong claimed mint amount ⇒ balance target mismatch ⇒ reject.
        assert!(!verify_fw_mint_bytes(&vk, mint + 1, &coin_bytes, &proof_bytes).unwrap_or(false), "wrong mint amount rejects");
        // Tampered output coin ⇒ reject.
        let mut bad = coin_bytes.clone();
        let last = bad.len() - 1;
        *bad[0].last_mut().unwrap() ^= 0x01;
        let _ = last;
        assert!(!verify_fw_mint_bytes(&vk, mint, &bad, &proof_bytes).unwrap_or(false), "tampered coin rejects");
        // Truncated proof ⇒ malformed ⇒ Err (fail-closed).
        assert!(verify_fw_mint_bytes(&vk, mint, &coin_bytes, &proof_bytes[..proof_bytes.len() - 40]).is_err(), "truncated proof is malformed");
        println!("FW MINT serialized proof = {} KB ({} coins)", proof_bytes.len() / 1024, coin_bytes.len());

        // SHIELD shape: a SINGLE output coin conserving the whole public amount
        // (m=1 — the shield/1-output-mint case). Honest verifies; wrong amount rejects.
        let (sc, sp) = prove_fw_mint_bytes(&vk, 250_000u128, &[250_000u128], 0x5111).expect("prove 1-out fw mint");
        assert_eq!(sc.len(), 1);
        assert!(verify_fw_mint_bytes(&vk, 250_000u128, &sc, &sp).unwrap(), "single-output fw conservation verifies");
        assert!(!verify_fw_mint_bytes(&vk, 250_001u128, &sc, &sp).unwrap_or(false), "single-output wrong amount rejects");
    }

    #[test]
    #[ignore = "superseded by `fullwidth`; underlying prover forced to fail"]
    fn amortized_tx_balance_node_roundtrip() {
        // NODE: one amortized IPA proof covering ranges + BALANCE. Balanced tx
        // (Σin = Σout + fee) verifies; a wrong claimed fee and a corrupted
        // commitment reject.
        let n_bits = 16;
        let in_amounts = [100u64, 50];
        let out_amounts = [120u64, 25];
        let fee = 5u64; // 150 = 145 + 5
        let (c_b, proof) = prove_amortized_tx(&in_amounts, &out_amounts, fee, n_bits, 0xC5A1).expect("prove balanced tx");
        assert!(verify_amortized_tx(in_amounts.len(), out_amounts.len(), fee, n_bits, &c_b, &proof).unwrap(), "balanced tx verifies");

        // Wrong claimed fee ⇒ balance target mismatch ⇒ reject.
        assert!(!verify_amortized_tx(in_amounts.len(), out_amounts.len(), fee + 1, n_bits, &c_b, &proof).unwrap_or(false), "wrong fee rejects");
        // Corrupted shared commitment ⇒ reject.
        let mut c_bad = c_b.clone();
        c_bad[5] ^= 1;
        assert!(!verify_amortized_tx(in_amounts.len(), out_amounts.len(), fee, n_bits, &c_bad, &proof).unwrap_or(false), "corrupted commitment rejects");
    }

    #[test]
    #[ignore = "superseded by `fullwidth`; underlying prover forced to fail"]
    fn amortized_output_ranges_node_roundtrip() {
        // NODE integration: the amortized IPA range proof for a tx's outputs. The
        // wallet proves all output ranges in ONE witness-free ZK proof; the node
        // reconstructs the commitment key from the fixed CRS and verifies. Honest
        // verifies; a corrupted shared commitment and an out-of-range amount reject.
        let n_bits = 16;
        let amounts = [5u64, 42, 1000, 7];
        let (c_b, proof) = prove_amortized_output_ranges(&amounts, n_bits, 0xA33F).expect("prove");
        assert!(verify_amortized_output_ranges(amounts.len(), n_bits, &c_b, &proof).unwrap(), "honest amortized ranges verify");

        // Corrupted shared commitment ⇒ reject.
        let mut c_bad = c_b.clone();
        c_bad[5] ^= 1;
        assert!(!verify_amortized_output_ranges(amounts.len(), n_bits, &c_bad, &proof).unwrap_or(false), "corrupted commitment rejects");

        // Wrong output count ⇒ wrong network key + relation ⇒ reject.
        assert!(!verify_amortized_output_ranges(amounts.len() + 1, n_bits, &c_b, &proof).unwrap_or(false), "wrong output count rejects");
    }

    #[test]
    fn node_verifies_packed_range_from_versioned_envelope() {
        // Prover (wallet) side: commit a value, prove, wrap in the versioned
        // envelope exactly as it would ride in the tx `range_proof` bytes.
        let n_bits = 64;
        let (stmt, wit) = commit_packed(n_bits, 0x1234_5678u64, 5);
        let proof = prove_range_zk(&stmt, &wit, 9).unwrap();
        let envelope = encode_range_versioned_packed_zk(&proof);

        // Node side: rebuild the statement from the SAME packed key + the tx's c_b.
        assert!(
            verify_packed_range(&stmt.key, &stmt.c_b, n_bits, &envelope).unwrap(),
            "node must verify the packed range proof from the envelope"
        );

        // Wrong commitment → reject (binds its c_b).
        let (other, _w) = commit_packed(n_bits, 0x1234_5679u64, 6);
        assert!(!verify_packed_range(&stmt.key, &other.c_b, n_bits, &envelope).unwrap());
    }

    #[test]
    fn node_fails_closed_on_bad_envelope() {
        let (stmt, wit) = commit_packed(64, 1u64, 7);
        let proof = prove_range_zk(&stmt, &wit, 3).unwrap();
        let mut env = encode_range_versioned_packed_zk(&proof);
        // Corrupt the version tag → malformed envelope error.
        env[0] = 0xFF;
        assert!(verify_packed_range(&stmt.key, &stmt.c_b, 64, &env).is_err());
        // A legacy-tagged (v1) envelope is rejected on the packed path.
        let legacy = vec![quil_lattice_ct::wire::RANGE_PROOF_V_LEGACY];
        assert!(verify_packed_range(&stmt.key, &stmt.c_b, 64, &legacy).is_err());
    }

    #[test]
    fn packed_limb_ranges_wire_round_trips_and_output_verify() {
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::limb_balance::{limbs_of, RANGE_BITS};
        use quil_lattice_ct::module::{PolyVec, RingCommitment, ETA};
        use quil_lattice_ct::rq::Poly;
        use quil_lattice_ct::value_link::VALUE_LIMBS;

        let np = crate::token_intrinsic::lattice_ct::NetworkParams::production();
        let packed_key = np.packed_key();
        let limb_vkey = np.limb_range_key().value_key();
        let (n_bits, n_limbs) = (RANGE_BITS, VALUE_LIMBS);
        let amount: u128 = 0x0055_66AA_BB01;
        let mut prg = SplitMix64::new(3);
        let r = PolyVec::sample_short(limb_vkey.a1.cols, ETA, &mut prg);
        let t1 = limb_vkey.a1.matvec(&r);
        let av_r = limb_vkey.a2.matvec(&r).0[0].clone();
        let t2: Vec<Poly> = limbs_of(amount, n_limbs)
            .iter()
            .map(|&l| {
                let mut c = Poly::zero();
                c.c[0] = l % Poly::Q;
                av_r.add(&c)
            })
            .collect();
        let out_c = RingCommitment { t1, t2: PolyVec(t2) };
        let ranges = prove_packed_limb_ranges(packed_key, &limb_vkey, &out_c, amount, &r, n_limbs, n_bits, 5).unwrap();

        // Wire round-trip + the per-output verifier (one output).
        let blob = encode_packed_limb_ranges(&ranges);
        assert!(is_packed_output_ranges(std::slice::from_ref(&blob)));
        let back = decode_packed_limb_ranges(&blob).unwrap();
        assert_eq!(encode_packed_limb_ranges(&back), blob);
        assert!(verify_packed_output_ranges(packed_key, &limb_vkey, &[out_c.clone()], &[blob.clone()], n_bits).unwrap());
        // Truncated blob → fail-closed.
        assert!(decode_packed_limb_ranges(&blob[..blob.len() - 20]).is_err());
    }

    #[test]
    fn measure_packed_vs_legacy_range_proof_sizes() {
        // HONEST size check: is the full-width packed range proof actually smaller
        // than the legacy range_rq it replaces? Print both.
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::limb_balance::{limbs_of, RANGE_BITS};
        use quil_lattice_ct::module::{PolyVec, RingCommitment, ETA};
        use quil_lattice_ct::range_rq::{prove_range_rq, RingRangeKey};
        use quil_lattice_ct::rq::Poly;
        use quil_lattice_ct::value_link::VALUE_LIMBS;

        let np = crate::token_intrinsic::lattice_ct::NetworkParams::production();
        let packed_key = np.packed_key();
        let limb_vkey = np.limb_range_key().value_key();
        let amount: u128 = 0x00A1_B2C3_D4E5_F601;
        let mut prg = SplitMix64::new(9);
        let r = PolyVec::sample_short(limb_vkey.a1.cols, ETA, &mut prg);
        let t1 = limb_vkey.a1.matvec(&r);
        let av_r = limb_vkey.a2.matvec(&r).0[0].clone();
        let t2: Vec<Poly> = limbs_of(amount, VALUE_LIMBS)
            .iter()
            .map(|&l| { let mut c = Poly::zero(); c.c[0] = l % Poly::Q; av_r.add(&c) })
            .collect();
        let out_c = RingCommitment { t1, t2: PolyVec(t2) };

        // Packed: per-output blob (16 limbs × range + value-link).
        let packed = prove_packed_limb_ranges(packed_key, &limb_vkey, &out_c, amount, &r, VALUE_LIMBS, RANGE_BITS, 5).unwrap();
        let packed_bytes = encode_packed_limb_ranges(&packed).len();

        // Legacy: range_rq per limb (16 of them).
        let rk = RingRangeKey::production(RANGE_BITS, 7);
        let mut legacy_bytes = 0usize;
        for (j, &limb) in limbs_of(amount, VALUE_LIMBS).iter().enumerate() {
            let mut prg2 = SplitMix64::new(100 + j as u64);
            let rr = PolyVec::sample_short(limb_vkey.a1.cols, ETA, &mut prg2);
            let mut m = Poly::zero(); m.c[0] = limb % Poly::Q;
            let cv = rk.value_key().commit(&PolyVec(vec![m]), &rr);
            let rp = prove_range_rq(&rk, &cv, limb, &rr, ETA, 1 << 17, 3).unwrap();
            legacy_bytes += quil_lattice_ct::wire::encode_range(&rp).len();
        }
        println!(
            "RANGE SIZE per output ({} limbs): packed={} KB  legacy_range_rq={} KB  ratio={:.2}x",
            VALUE_LIMBS,
            packed_bytes / 1024,
            legacy_bytes / 1024,
            packed_bytes as f64 / legacy_bytes as f64
        );
    }

    #[test]
    fn full_width_packed_limb_ranges_verify() {
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::limb_balance::{limbs_of, RANGE_BITS};
        use quil_lattice_ct::module::{PolyVec, RingCommitment, ETA};
        use quil_lattice_ct::rq::Poly;
        use quil_lattice_ct::value_link::VALUE_LIMBS;

        // Keys: packed + the limb value key (ℓ=1) the amount limbs commit under.
        let np = crate::token_intrinsic::lattice_ct::NetworkParams::production();
        let packed_key = np.packed_key();
        let limb_vkey = np.limb_range_key().value_key();
        let n_bits = RANGE_BITS;
        let n_limbs = VALUE_LIMBS;

        // A full-width (multi-limb) amount, committed as ℓ=VALUE_LIMBS.
        let amount: u128 = 0x00A1_B2C3_D4E5_F601;
        let mut prg = SplitMix64::new(7);
        let r = PolyVec::sample_short(limb_vkey.a1.cols, ETA, &mut prg);
        let t1 = limb_vkey.a1.matvec(&r);
        let av_r = limb_vkey.a2.matvec(&r).0[0].clone(); // a2_val·r
        let limbs = limbs_of(amount, n_limbs);
        let t2: Vec<Poly> = limbs
            .iter()
            .map(|&limb| {
                let mut c = Poly::zero();
                c.c[0] = limb % Poly::Q;
                av_r.add(&c)
            })
            .collect();
        let out_c = RingCommitment { t1, t2: PolyVec(t2) };

        // Wallet builds per-limb packed ranges + value-links; node verifies.
        let ranges = prove_packed_limb_ranges(packed_key, &limb_vkey, &out_c, amount, &r, n_limbs, n_bits, 42).unwrap();
        assert!(
            verify_packed_limb_ranges(packed_key, &limb_vkey, &out_c, &ranges, n_bits).unwrap(),
            "full-width per-limb packed ranges + value-links must verify"
        );

        // Tamper one limb's amount commitment → its value-link must fail.
        let mut bad = out_c.clone();
        bad.t2.0[0] = bad.t2.0[0].add(&Poly::one());
        assert!(!verify_packed_limb_ranges(packed_key, &limb_vkey, &bad, &ranges, n_bits).unwrap());
    }

    #[test]
    fn packed_spend_input_binds_to_onchain_coin() {
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::module::{PolyVec, RingCommitKey, ETA};
        use quil_lattice_ct::rq::Poly;

        let n_bits = 32;
        let packed_key = RingCommitKey::production(1, 0x9ACC_0003);
        let value_key = RingCommitKey::production(1, 0x7A17); // the accumulator's value key
        let value = 4242u64;
        let mk_r = |t: u64| {
            let mut prg = SplitMix64::new(t);
            PolyVec::sample_short(9, ETA, &mut prg)
        };
        let (r_b, r_v) = (mk_r(1), mk_r(2));
        // The on-chain coin's scalar value commitment (value in c[0]).
        let mut vp = Poly::zero();
        vp.c[0] = value % Poly::Q;
        let c_v = value_key.commit(&PolyVec(vec![vp]), &r_v);

        // Wallet builds the packed spend input; node verifies the bind.
        let (c_b, link) = prove_packed_spend_input(&packed_key, &value_key, value, &r_b, &c_v, &r_v, n_bits, 9).unwrap();
        assert!(verify_packed_spend_input(&packed_key, &value_key, &c_b, &c_v, n_bits, &link).unwrap());

        // A packed c_b for a DIFFERENT value must not bind to this coin.
        let (c_b2, link2) = prove_packed_spend_input(&packed_key, &value_key, value + 1, &r_b, &c_v, &r_v, n_bits, 10)
            .map(|(c, l)| (c, l))
            .unwrap_or_else(|_| (c_b.clone(), link.clone()));
        assert!(!verify_packed_spend_input(&packed_key, &value_key, &c_b2, &c_v, n_bits, &link2).unwrap());
    }

    #[test]
    fn wallet_builds_and_node_verifies_from_wire_bytes() {
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::module::{PolyVec, RingCommitKey, ETA};
        use quil_lattice_ct::wire::encode_commitment;

        let n_bits = 32; // ≤36-bit amounts (single-commitment packed)
        let key = RingCommitKey::production(1, 0x9ACC_0002);
        let rand = |tag: u64| {
            let mut prg = SplitMix64::new(tag);
            PolyVec::sample_short(9, ETA, &mut prg)
        };
        // Inputs 1000 + 2500; outputs 3000 + 400; fee 100 (balanced).
        let inputs = vec![(1000u64, rand(1)), (2500u64, rand(2))];
        let outputs = vec![(3000u64, rand(3)), (400u64, rand(4))];
        let fee = 100u64;

        // Wallet builds the tx pieces.
        let (built, in_commits) = prove_packed_transaction(&key, &inputs, &outputs, fee, n_bits, 42).unwrap();
        let in_commit_bytes: Vec<Vec<u8>> = in_commits.iter().map(encode_commitment).collect();

        // Node verifies straight from the wire byte fields (as a TxEnvelope carries).
        assert!(
            verify_packed_transaction_bytes(
                &key,
                &in_commit_bytes,
                &built.output_commitments,
                &built.output_range_proofs,
                &built.balance_proof,
                fee,
                n_bits,
            )
            .unwrap(),
            "wallet-built packed tx must verify on the node from wire bytes"
        );
        // Claiming a smaller fee (inflation) must reject.
        assert!(!verify_packed_transaction_bytes(
            &key,
            &in_commit_bytes,
            &built.output_commitments,
            &built.output_range_proofs,
            &built.balance_proof,
            fee - 1,
            n_bits,
        )
        .unwrap());
    }

    #[test]
    fn node_verifies_complete_packed_transaction() {
        use quil_lattice_ct::arith::SplitMix64;
        use quil_lattice_ct::labrador_ct::balance_zk::{combined_commitment, prove_balance};
        use quil_lattice_ct::labrador_ct::packed::{PackedRangeStatement, PackedRangeWitness};
        use quil_lattice_ct::labrador_ct::prove_range_zk;
        use quil_lattice_ct::module::{PolyVec, ETA};
        use quil_lattice_ct::rq::Poly;
        use quil_lattice_ct::wire::{encode_packed_balance, encode_range_versioned_packed_zk};

        let n_bits = 64;
        // One shared packed key (the network parameter).
        let key = quil_lattice_ct::module::RingCommitKey::production(1, 0x9ACC_0001);
        let commit = |v: u64, tag: u64| {
            let mut prg = SplitMix64::new(tag);
            let r = PolyVec::sample_short(9, ETA, &mut prg);
            let mut b = Poly::zero();
            for i in 0..n_bits {
                b.c[i] = (v >> i) & 1;
            }
            let c = key.commit(&PolyVec(vec![b.clone()]), &r);
            (c, b, r)
        };
        // Inputs 300 + 500; output 750; fee 50 → balanced.
        let (ci1, b1, r1) = commit(300, 1);
        let (ci2, b2, r2) = commit(500, 2);
        let (co1, bo1, ro1) = commit(750, 3);
        let fee = 50u64;

        // Wallet: range-prove the output, prove balance.
        let stmt = PackedRangeStatement { key: key.clone(), c_b: co1.clone(), n_bits };
        let wit = PackedRangeWitness { bit_poly: bo1.clone(), r_b: ro1.clone() };
        let range_env = encode_range_versioned_packed_zk(&prove_range_zk(&stmt, &wit, 11).unwrap());

        let d = combined_commitment(&[ci1.clone(), ci2.clone()], &[co1.clone()]);
        let big_b = b1.add(&b2).sub(&bo1);
        let neg_ro1 = PolyVec(ro1.0.iter().map(|p| p.neg()).collect());
        let big_r = r1.add(&r2).add(&neg_ro1);
        let bal = encode_packed_balance(&prove_balance(&key, &d, &big_b, &big_r, fee, n_bits, 13).unwrap());

        // Node consensus verify: range + balance.
        assert!(
            verify_packed_transaction(&key, &[ci1.clone(), ci2.clone()], &[co1.clone()], &[range_env.clone()], &bal, fee, n_bits).unwrap(),
            "a balanced, in-range packed transaction must verify on the node"
        );
        // Inflated fee claim → balance rejects.
        assert!(!verify_packed_transaction(&key, &[ci1, ci2], &[co1], &[range_env], &bal, fee + 1, n_bits).unwrap());
    }
}
