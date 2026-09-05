//! Post-quantum confidential-transaction verify path — the replacement for the
//! decaf448 crypto (`bulletproofs` range/sum + hidden-Schnorr spend +
//! `verenc` memo) in the token intrinsic.
//!
//! This wires [`quil_lattice_ct`] (the estimator-validated ring-form BDLOP
//! cryptosystem) into the money path. The transaction data model is unchanged —
//! `commitment`, `signature`, `range_proof` are the same opaque `Vec<u8>`
//! containers as before; only their *interpretation* changes:
//!
//! | decaf448 (old) | lattice-CT (new)                         |
//! |--------------------------------------|------------------------------------------|
//! | Pedersen commitment (56 B point) | [`RingCommitment`] (BDLOP, M-SIS/M-LWE)  |
//! | bulletproof range proof | per-output [`RangeProofRq`]              |
//! | bulletproof sum-check (Σin=Σout+fee) | balance [`verify_linear_rq`] |
//! | hidden-Schnorr input signature | linkable ring sig [`ring_rq::verify`]    |
//! | `CoinBalance`/`Mask` (view-key ECDH) | sntrup761 KEM memo (recipient-side) |
//!
//! The consensus verify checks **range** (no out-of-range / overflow outputs),
//! **balance** (declared amounts conserve, no inflation), **ring signature**
//! (spend authority + anonymity), and yields the **key image** (double-spend
//! nullifier). The amount memo / stealth one-time key are recipient-side (wallet
//! opens them off the consensus path — see [`quil_lattice_ct::memo`] /
//! [`quil_lattice_ct::stealth`]); consensus carries them as opaque bytes.
//!
//! # Amount balance and input binding
//!
//! Two properties the earlier decaf448 design left open are both closed here:
//!
//! 1. **Full-width amounts.** Values are committed as 16 base-`2^8` limbs
//! ([`quil_lattice_ct::value_link::VALUE_LIMBS`]) and balance is proven PER
//! limb with an explicit range-proven carry chain (top carry pinned to 0), so
//! every committed value stays `< q` and there is no modular-wrap / overflow
//! mint — full 128-bit amounts. See [`verify_transaction_crypto`].
//! 2. **Real-input ↔ pseudo-output binding.** [`verify_pseudo_output_binding`]
//! proves the pseudo-input commits the same amount as the real on-chain coin
//! (`C_real − C_pseudo` opens to 0), so a false declared input amount is
//! rejected.

use quil_lattice_ct::limb_balance::{
    limbs_of, prove_limb_balance_bound, verify_limb_balance, LimbBalanceProof,
};
use quil_lattice_ct::linear_rq::verify_linear_rq;
use quil_lattice_ct::membership::{verify_membership, verify_spend, MembershipParams};
use quil_lattice_ct::value_link::{ValueLinkParams, VALUE_LIMBS};
use quil_lattice_ct::module::{PolyMatrix, PolyVec, RingCommitKey, RingCommitment, ETA};
use quil_lattice_ct::range_rq::{verify_range_rq, RingRangeKey};
use quil_lattice_ct::ring_rq::{verify as ring_verify, RingSigKeyRq};
use quil_lattice_ct::rq::Poly;
use quil_lattice_ct::sigma_rq::{verify_ring_opening, RingOpeningProof, RingSigmaParams};
use quil_lattice_ct::wire;
use quil_types::error::{QuilError, Result};

use crate::hypergraph_state::HypergraphState;
use super::{shadow_accumulator, spent_check};

/// Message type prefix for a post-quantum confidential (lattice-CT) transaction —
/// its `inner_bytes` is a [`TxEnvelope`]. Distinct from the decaf
/// `TYPE_TRANSACTION` (`0x0509`) so both paths coexist.
pub const TYPE_LATTICE_TRANSACTION: u32 = 0x0512;

/// Message type prefix for a post-quantum (lattice/Falcon) MINT transaction — its
/// `inner_bytes` is a [`MintEnvelope`].
pub const TYPE_LATTICE_MINT: u32 = 0x0513;

/// Message type prefix for a lattice escrow CREATE — `inner_bytes` is a
/// [`PendingCreateEnvelope`].
pub const TYPE_LATTICE_PENDING: u32 = 0x0514;
/// Message type prefix for a lattice escrow CLAIM/REFUND — `inner_bytes` is a
/// [`PendingClaimEnvelope`].
pub const TYPE_LATTICE_PENDING_CLAIM: u32 = 0x0515;

/// Message type prefix for a legacy transparent-coin SHIELD (one-way spend into a
/// lattice private coin) — `inner_bytes` is a [`ShieldEnvelope`].
pub const TYPE_LATTICE_SHIELD: u32 = 0x0516;

/// Amount width in bits. Bounded so the single-coefficient value encoding is
/// sound AND the aggregate `(2·MAX_IO)·2^AMOUNT_BITS + fee` stays `< q≈2^28` (the
/// overflow-safety invariant enforced in `verify_transaction_crypto`): with
/// `MAX_IO=100`, `2·100·2^20 ≈ 2^27.6 < q`. Full 128-bit amounts need the
/// limb-embedded / dual-modulus balance (see module docs).
pub const AMOUNT_BITS: usize = 20;

/// Amount width for the coefficient-PACKED confidential path (single-commitment,
/// so `< q ≈ 2^36`; wider amounts use the full-width limb path). The packed
/// value `v = ⟪g,b⟩` must not wrap `q`, so this stays comfortably below 36.
pub const PACKED_TX_BITS: usize = 32;

/// Ring-Σ masking bound `B` — the same `2^17` the proofs are parameterized at.
const MASK_BOUND: i64 = 1 << 17;

/// Nothing-up-my-sleeve seeds for the network-wide public parameters. Public
/// key material is a seed on the wire (Dilithium-style matrix expansion).
const RANGE_KEY_SEED: u64 = 0x5175_4c43_5254_5631; // "QuLCRTV1"
const SIG_KEY_SEED: u64 = 0x5175_4c43_5349_4731; // "QuLCSIG1"

/// Nothing-up-my-sleeve seed for the full-width limb range key.
const LIMB_RANGE_KEY_SEED: u64 = 0x5175_4c43_4c4d_4231; // "QuLCLMB1"

/// Nothing-up-my-sleeve seed for the PACKED (coefficient-packed) range key.
const PACKED_RANGE_KEY_SEED: u64 = 0x5175_4c50_4143_4b31; // "QuLPACK1"

/// Network-wide public parameters for the lattice-CT money path.
pub struct NetworkParams {
    range_key: RingRangeKey,
    limb_range_key: RingRangeKey,
    /// Coefficient-packed bit-commitment key (`ℓ=1`) for the ZK packed range proof
    /// ([`quil_lattice_ct::labrador_ct`]). Bits live in the coefficients of one
    /// message ring element, committed under this key.
    packed_key: RingCommitKey,
}

impl NetworkParams {
    /// Production parameters at [`AMOUNT_BITS`].
    pub fn production() -> Self {
        Self::with_bits(AMOUNT_BITS)
    }
    /// With an explicit amount width (tests use a small width for speed). The
    /// full-width limb range key is fixed at [`quil_lattice_ct::limb_balance::RANGE_BITS`].
    pub fn with_bits(n_bits: usize) -> Self {
        NetworkParams {
            range_key: RingRangeKey::production(n_bits, RANGE_KEY_SEED),
            limb_range_key: RingRangeKey::production(
                quil_lattice_ct::limb_balance::RANGE_BITS,
                LIMB_RANGE_KEY_SEED,
            ),
            packed_key: RingCommitKey::production(1, PACKED_RANGE_KEY_SEED),
        }
    }
    /// The coefficient-packed bit-commitment key for ZK packed range proofs.
    pub fn packed_key(&self) -> &RingCommitKey {
        &self.packed_key
    }
    /// The full-width limb range/commit key (the Gap-2 balance rides on this).
    pub fn limb_range_key(&self) -> &RingRangeKey {
        &self.limb_range_key
    }
    /// The value-commitment key (`ℓ = VALUE_LIMBS`, full-width). A coin's value is
    /// one vector-message commitment holding the amount's 16 base-`2^8` limbs; its
    /// per-limb *slices* `(t1, t2[j])` are valid `ℓ=1` commitments under the LIMB
    /// range key (the broadcast `A2` rows all equal that key's value row), so the
    /// carry-chain balance ([`quil_lattice_ct::limb_balance`]) rides on those
    /// slices without re-committing. `cv = H_B(C)` compresses the whole stack.
    pub fn value_key(&self) -> RingCommitKey {
        let base = self.limb_range_key.value_key(); // ℓ=1: (A1, a2_val)
        let a2_row = base.a2.m[0].clone();
        RingCommitKey {
            a1: base.a1.clone(),
            a2: PolyMatrix { rows: VALUE_LIMBS, cols: base.a2.cols, m: vec![a2_row; VALUE_LIMBS] },
            ell: VALUE_LIMBS,
        }
    }
    /// The linkable-ring-signature key for an anonymity set of `n_ring` members.
    pub fn sig_key(&self, n_ring: usize) -> RingSigKeyRq {
        RingSigKeyRq::production(n_ring, SIG_KEY_SEED)
    }
    /// The range-proof key.
    pub fn range_key(&self) -> &RingRangeKey {
        &self.range_key
    }
    /// Membership (accumulator) parameters for a coin-set of depth `depth`
    /// (`≤ 2^depth` coins). Proof size/time grow with depth — the anonymity-set
    /// vs cost tradeoff; the shadow-tree depth must match.
    pub fn membership_params(&self, depth: usize) -> MembershipParams {
        MembershipParams::production(depth)
    }
    /// Value-linking parameters keyed to THIS network's value key, so the coin's
    /// `C`, the spend's `C'`, the range proofs, and the balance all agree.
    pub fn value_link_params(&self) -> ValueLinkParams {
        ValueLinkParams::with_vkey(self.value_key())
    }
}

/// Coin-set accumulator depth (`≤ 2^ACC_DEPTH` coins). The SIS shadow-tree the
/// node maintains must use this depth.
///
/// **PERF (measured, RELEASE):** membership-proof *generation* is ~linear in
/// depth (~0.65 s/level, chain phase dominant): depth 8 ≈ 5.8 s, 16 ≈ 11.4 s,
/// 24 ≈ 18.5 s, **32 ≈ 22 s** per spend proof. (An earlier "440 s" figure was a
/// DEBUG-build artifact — always benchmark this in release.) 22 s for a
/// full-`2^32`-set private spend is acceptable as a one-time wallet cost;
/// reducible via public-param caching (chain_keys/matrix expansion ≈ 3 s of the
/// 22 s is deterministic setup) or a shallower depth. See
/// [`crate::token_intrinsic::coin_accumulator`].
pub const ACC_DEPTH: usize = 32;

/// The process-wide production [`NetworkParams`], built once (the keys are a
/// deterministic seed-expansion, so rebuilding per transaction is pure waste).
pub fn production_params() -> &'static NetworkParams {
    static PARAMS: std::sync::OnceLock<NetworkParams> = std::sync::OnceLock::new();
    PARAMS.get_or_init(NetworkParams::production)
}

/// A public amount (fee / target) as a constant-poly message.
fn const_poly(v: u128) -> Poly {
    let mut p = Poly::zero();
    p.c[0] = (v % Poly::Q as u128) as u64;
    p
}

fn decode_commit(b: &[u8]) -> Result<RingCommitment> {
    wire::decode_commitment(b)
        .map_err(|e| QuilError::InvalidArgument(format!("lattice-ct: commitment decode: {e:?}")))
}

/// The amount's base-`2^8` limbs as an `ℓ = VALUE_LIMBS` commitment message.
fn limbs_msg(amount: u128) -> PolyVec {
    PolyVec(limbs_of(amount, VALUE_LIMBS).iter().map(|&l| const_poly(l as u128)).collect())
}

/// The UNIFORM fw coin message: each base-2^8 limb as an 8-bit BIT-POLY (bits in
/// coeffs 0..7). An fw coin is `value_key.commit(bitpoly_msg(amount); r)`; its value
/// is `Σ_l 2^{8l}·⟪g8, bit_l⟫`.
fn bitpoly_msg(amount: u128) -> PolyVec {
    PolyVec(
        limbs_of(amount, VALUE_LIMBS)
            .iter()
            .map(|&l| {
                let mut p = quil_lattice_ct::rq::Poly::zero();
                for i in 0..8 {
                    p.c[i] = (l >> i) & 1;
                }
                p
            })
            .collect(),
    )
}

/// Commit a full-width `amount` under the `ℓ = VALUE_LIMBS` value key.
fn commit_amount(vkey: &RingCommitKey, amount: u128, r: &PolyVec) -> RingCommitment {
    vkey.commit(&limbs_msg(amount), r)
}

/// Ring-coin memo (writer side): mask `(amount, r_out)` with the shared secret
/// `ss`. Unlike [`quil_lattice_ct::memo::encrypt_memo`] (which carries a scalar
/// `&[i128]` blinding for the *scalar* commitment), a lattice coin's `cv` is a
/// **ring** commitment, so the memo must carry the full `PolyVec` output
/// randomness the recipient needs to recompute `cv`.
///
/// Layout (before masking): `amount(16 LE) ‖ wire::encode_polyvec(r_out)`.
pub fn encrypt_ring_memo(ss: &[u8], amount: u128, r_out: &PolyVec) -> Vec<u8> {
    let mut plain = Vec::with_capacity(16);
    plain.extend_from_slice(&amount.to_le_bytes());
    plain.extend_from_slice(&wire::encode_polyvec(r_out));
    let ks = quil_lattice_ct::memo::keystream(ss, b"ring-memo", plain.len());
    quil_lattice_ct::memo::xor(&plain, &ks)
}

/// Ring-coin memo (recipient side): recover `(amount, r_out)` and confirm they
/// recompute the coin's committed `cv` (`compress(commit(limbs(amount), r_out))
/// == coin_cv`). Returns `None` on a garbled memo, wrong `ss`, or a mismatch —
/// the coin is then not spendable by this recipient.
pub fn open_ring_memo(
    np: &NetworkParams,
    ss: &[u8],
    coin_cv: &[u8],
    memo: &[u8],
) -> Option<(u128, PolyVec)> {
    if memo.len() < 16 {
        return None;
    }
    let ks = quil_lattice_ct::memo::keystream(ss, b"ring-memo", memo.len());
    let plain = quil_lattice_ct::memo::xor(memo, &ks);
    let amount = u128::from_le_bytes(plain.get(..16)?.try_into().ok()?);
    let r_out = wire::decode_polyvec(plain.get(16..)?).ok()?;

    // Recompute cv and match. An fw coin is `value_key.commit(bitpoly_msg(amount); r)`;
    // try that first, then fall back to the legacy limb-value form (`commit_amount`) so
    // both forms scan.
    let vkey = np.value_key();
    let vlink = np.value_link_params();
    let c_fw = vkey.commit(&bitpoly_msg(amount), &r_out);
    if wire::encode_polyvec(&vlink.compress(&c_fw)) == coin_cv {
        return Some((amount, r_out));
    }
    let c_legacy = commit_amount(&vkey, amount, &r_out);
    if wire::encode_polyvec(&vlink.compress(&c_legacy)) == coin_cv {
        return Some((amount, r_out));
    }
    None
}

/// Slice one `ℓ = VALUE_LIMBS` value commitment into its `VALUE_LIMBS` virtual
/// `ℓ=1` per-limb commitments `(t1, t2[j])` — the form the carry-chain balance
/// consumes. All share `t1` (the amount's single randomness), which is sound: the
/// per-limb linear openings only require *some* opening randomness, and binding
/// comes from `t1 = A1·r` (see [`NetworkParams::value_key`]).
fn virtual_limbs(c: &RingCommitment) -> Result<Vec<RingCommitment>> {
    if c.t2.0.len() != VALUE_LIMBS {
        return Err(QuilError::InvalidArgument(format!(
            "lattice-ct: value commitment has {} message polys, expected {VALUE_LIMBS}",
            c.t2.0.len()
        )));
    }
    Ok((0..VALUE_LIMBS)
        .map(|j| RingCommitment { t1: c.t1.clone(), t2: PolyVec(vec![c.t2.0[j].clone()]) })
        .collect())
}

// =====================================================================
// Range + balance
// =====================================================================

/// Verify the range proofs on every output and the balance relation
/// `Σ inputs = Σ outputs + fee` (fee omitted when `include_fee` is false — e.g.
/// non-QUIL domains and mints).
///
/// `output_commitments[i]` is the wire-encoded value commitment the range proof
/// `output_range_proofs[i]` binds; `input_commitments` are the (pseudo-)input
/// value commitments; `balance_proof` is one encoded ring-Σ opening.
pub fn verify_transaction_crypto(
    np: &NetworkParams,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    balance_proof: &[u8],
    fee: u128,
    include_fee: bool,
) -> Result<bool> {
    verify_transaction_crypto_ext(np, input_commitments, output_commitments, balance_proof, fee, include_fee, false)
}

/// `verify_transaction_crypto` with `range_free`: when `true` the limb balance's
/// built-in output range_rq is not expected (the caller verified the packed
/// per-limb ranges instead).
#[allow(clippy::too_many_arguments)]
pub fn verify_transaction_crypto_ext(
    np: &NetworkParams,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    balance_proof: &[u8],
    fee: u128,
    include_fee: bool,
    range_free: bool,
) -> Result<bool> {
    // Full-width: each commitment is one ℓ=VALUE_LIMBS vector-message
    // commitment; slice it into virtual per-limb commitments and run the
    // carry-chain balance, which also range-proves every OUTPUT limb (non-negative
    // ⇒ no inflation) and pins the top carry to 0 (Σin = Σout + fee over ℤ). No
    // value ever exceeds `q`, so there is no overflow-mint and no amount ceiling.
    let fee_amt = if include_fee { fee } else { 0 };
    let to_virtual = |cs: &[Vec<u8>]| -> Result<Vec<Vec<RingCommitment>>> {
        cs.iter().map(|b| virtual_limbs(&decode_commit(b)?)).collect()
    };
    let in_virtual = to_virtual(input_commitments)?;
    let out_virtual = to_virtual(output_commitments)?;
    let proof: LimbBalanceProof = wire::decode_limb_balance(balance_proof).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: limb-balance decode: {e:?}"))
    })?;
    Ok(quil_lattice_ct::limb_balance::verify_limb_balance_ext(
        np.limb_range_key(),
        &in_virtual,
        &out_virtual,
        fee_amt,
        VALUE_LIMBS,
        &proof,
        range_free,
    ))
}

// =====================================================================
// Mint conservation — Σ outputs = mint_amount (no spent inputs)
// =====================================================================

/// The public "virtual input" commitment to a minted `amount`: `Commit(amount; 0)
/// = (0, amount)`. Modeling the authorized mint amount as a zero-randomness input
/// lets the mint reuse the transfer balance check: `virtual − Σ outputs = 0`
/// proves `Σ outputs = amount` (no new value beyond the authorized mint).
pub fn mint_virtual_input(amount: u128) -> RingCommitment {
    // Commit(amount; 0) = (A1·0, limbs + A2·0) = (0, limbs), ℓ=VALUE_LIMBS.
    RingCommitment {
        t1: PolyVec::zero(quil_lattice_ct::params::SIS_RANK_KAPPA),
        t2: limbs_msg(amount),
    }
}

/// Build the coefficient-PACKED per-limb range proofs for a set of output
/// commitments (one blob per output). Shared by the transfer, mint, and shield
/// builders so all three emit the packed-only format. `out_rand[i]` is the
/// randomness `output_commitments[i]` was committed with.
pub(crate) fn packed_output_range_blobs(
    np: &NetworkParams,
    output_commitments: &[Vec<u8>],
    out_amounts: &[u128],
    out_rand: &[PolyVec],
    seed: u64,
) -> Result<Vec<Vec<u8>>> {
    let packed_key = np.packed_key();
    let limb_vkey = np.limb_range_key().value_key();
    output_commitments
        .iter()
        .enumerate()
        .map(|(i, cb)| -> Result<Vec<u8>> {
            let out_c = decode_commit(cb)?;
            let ranges = super::packed_range::prove_packed_limb_ranges(
                packed_key,
                &limb_vkey,
                &out_c,
                out_amounts[i],
                &out_rand[i],
                VALUE_LIMBS,
                quil_lattice_ct::limb_balance::RANGE_BITS,
                seed ^ (0x7000 + i as u64),
            )?;
            Ok(super::packed_range::encode_packed_limb_ranges(&ranges))
        })
        .collect()
}

/// Verify a mint's confidential conservation: every output is in range and the
/// outputs sum **exactly** to the authorized `mint_amount` (no over-mint). The
/// caller separately verifies the mint *authorization* (who may mint this).
/// Decode a full-width amortized IPA proof from its `balance_proof` bytes
/// (compact codec), fail-closed on malformed input.
fn decode_fw_proof(bytes: &[u8]) -> Result<quil_lattice_ct::labrador::FullCtZkIpaProof> {
    quil_lattice_ct::wire::decode_full_ct_zk_ipa_compact(bytes)
        .map_err(|_| QuilError::InvalidArgument("full-width: malformed IPA proof bytes".into()))
}

pub fn verify_mint_crypto(
    np: &NetworkParams,
    mint_amount: u128,
    output_commitments: &[Vec<u8>],
    output_range_proofs: &[Vec<u8>],
    balance_proof: &[u8],
) -> Result<bool> {
    // FULL-WIDTH amortized path: one IPA proof (in `balance_proof`) covers per-limb
    // ranges + conservation `Σ output coins = mint_amount`; the outputs ARE fw coins.
    if super::packed_range::is_fw_output_ranges(output_range_proofs) {
        let out_coins: std::result::Result<Vec<RingCommitment>, _> =
            output_commitments.iter().map(|b| decode_commit(b)).collect();
        return super::packed_range::verify_fw_mint(&np.value_key(), mint_amount, &out_coins?, &decode_fw_proof(balance_proof)?);
    }
    // PACKED-only: every mint output carries coefficient-packed per-limb range
    // proofs (non-negativity), value-linked to its commitment; the limb balance is
    // range_free. The non-packed `range_rq` mint format is not accepted.
    if !super::packed_range::is_packed_output_ranges(output_range_proofs) {
        return Ok(false);
    }
    let out_c: std::result::Result<Vec<RingCommitment>, _> =
        output_commitments.iter().map(|b| decode_commit(b)).collect();
    let out_c = out_c?;
    let limb_vkey = np.limb_range_key().value_key();
    if !super::packed_range::verify_packed_output_ranges(
        np.packed_key(), &limb_vkey, &out_c, output_range_proofs,
        quil_lattice_ct::limb_balance::RANGE_BITS,
    )? {
        return Ok(false);
    }
    let vin = wire::encode_commitment(&mint_virtual_input(mint_amount));
    // virtual(+1) − outputs(−1) = 0 ⇔  Σ outputs = mint_amount (range_free balance).
    verify_transaction_crypto_ext(np, &[vin], output_commitments, balance_proof, 0, false, true)
}

// =====================================================================
// Mint authorization — post-quantum (Falcon) replacing BLS + decaf Schnorr
// =====================================================================

/// The message a mint authorization signs: the claimed `value` (public) bound to
/// the transaction challenge `mu` (which commits the outputs). Binding to `mu`
/// replaces the decaf per-input "hidden Schnorr" that tied the authorization to
/// the specific outputs — so an authorization can't be redirected.
pub fn mint_auth_message(claimed_value: u128, mu: &[u8]) -> Vec<u8> {
    let mut msg = claimed_value.to_le_bytes().to_vec();
    msg.extend_from_slice(mu);
    msg
}

/// Verify the reward entitlement behind a PoMW mint: prove (via forest JMT
/// membership — hash-based, post-quantum) that a `reward:ProverReward` vertex
/// exists at `(prover_root_domain ‖ leaf_owner_address)` binding
/// `DelegateAddress == owner_prover_address` and `Balance == claimed_value`, and
/// that the Falcon signer is that owner (`poseidon(falcon_pubkey) == owner`). This
/// is the same forest check the decaf PoMW path uses — only the authorization
/// *signature* changes (to Falcon, see [`verify_mint_auth_signature`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_mint_reward_membership(
    reward_root: &[u8; 32],
    forest_proof: &[u8],
    prover_root_domain: &[u8; 32],
    leaf_owner_address: &[u8; 32],
    owner_prover_address: &[u8],
    falcon_pubkey: &[u8],
    claimed_value: u128,
) -> Result<bool> {
    let deleg_key = crate::global_schema::field_key("reward:ProverReward", "DelegateAddress")
        .ok_or_else(|| QuilError::Internal("mint: reward DelegateAddress key missing".into()))?;
    let balance_key = crate::global_schema::field_key("reward:ProverReward", "Balance")
        .ok_or_else(|| QuilError::Internal("mint: reward Balance key missing".into()))?;
    let mut value_padded = [0u8; 32];
    value_padded[16..].copy_from_slice(&claimed_value.to_be_bytes());
    let expected = vec![
        (deleg_key, owner_prover_address.to_vec()),
        (balance_key, value_padded.to_vec()),
    ];

    let mp = quil_forest::MembershipProof::from_bytes(forest_proof)
        .map_err(|e| QuilError::InvalidArgument(format!("mint: forest proof decode: {e}")))?;
    let vertex = match mp.inputs.first() {
        Some(v) => v,
        None => return Ok(false),
    };
    let mut vertex_id = [0u8; 64];
    vertex_id[..32].copy_from_slice(prover_root_domain);
    vertex_id[32..].copy_from_slice(leaf_owner_address);
    if vertex.vertex_address != vertex_id {
        return Ok(false);
    }
    if quil_forest::verify_vertex_membership(reward_root, vertex, &expected).is_err() {
        return Ok(false);
    }
    // Spend authority: the Falcon signer is the reward owner (self or delegate).
    let signer_addr = quil_crypto::poseidon::hash_bytes_to_32(falcon_pubkey)?;
    Ok(signer_addr.as_slice() == owner_prover_address)
}

/// Verify a mint authorization **Falcon (FN-DSA-512)** signature — the
/// post-quantum replacement for the BLS48-581 authority/PoMW signature. The
/// caller separately checks that `falcon_pubkey` is the authorized minter (an
/// authority key, or — for PoMW — `poseidon(pubkey)` matches the reward vertex's
/// delegate address, proven by forest membership).
pub fn verify_mint_auth_signature(
    falcon_pubkey: &[u8],
    signature: &[u8],
    claimed_value: u128,
    mu: &[u8],
    domain: &[u8],
) -> bool {
    quil_crypto::falcon_verify(
        falcon_pubkey,
        signature,
        &mint_auth_message(claimed_value, mu),
        domain,
    )
}

/// A PoMW mint input — an authorization to create `value` new tokens, backed by
/// an on-chain reward balance. Post-quantum throughout: forest membership + a
/// Falcon signature (no decaf, no BLS).
pub struct LatticeMintInput {
    pub value: u128,
    pub owner_prover_address: Vec<u8>,
    pub falcon_pubkey: Vec<u8>,
    pub falcon_sig: Vec<u8>,
    pub forest_proof: Vec<u8>,
}

/// Verify a **fully post-quantum** PoMW mint: each input's reward entitlement
/// (forest membership) + Falcon authorization signature bound to the outputs, and
/// the confidential conservation `Σ outputs = Σ input values`. Returns the total
/// minted (for the reward-balance decrement at materialize) on success.
///
/// `reward_root` is resolved by the caller (the global clock frame's prover-tree
/// commitment for QUIL, or the domain's shard commit otherwise).
pub fn verify_lattice_pomw_mint(
    np: &NetworkParams,
    reward_root: &[u8; 32],
    domain: &[u8],
    inputs: &[LatticeMintInput],
    output_commitments: &[Vec<u8>],
    output_range_proofs: &[Vec<u8>],
    balance_proof: &[u8],
) -> Result<Option<u128>> {
    // Public minted total = Σ input values (each authorized against its reward).
    let mut total: u128 = 0;
    for inp in inputs {
        total = total
            .checked_add(inp.value)
            .ok_or_else(|| QuilError::InvalidArgument("mint: value sum overflow".into()))?;
    }
    // The authorization signatures bind to this challenge (which commits outputs).
    let mu = tx_challenge(domain, output_commitments, total);

    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for inp in inputs {
        // A reward can be claimed once per mint (owner uniqueness within the tx).
        if !seen.insert(&inp.owner_prover_address) {
            return Ok(None);
        }
        let (prover_root_domain, leaf_owner) =
            super::mint::derive_pomw_addressing(domain, &inp.owner_prover_address)?;
        if !verify_mint_reward_membership(
            reward_root,
            &inp.forest_proof,
            &prover_root_domain,
            &leaf_owner,
            &inp.owner_prover_address,
            &inp.falcon_pubkey,
            inp.value,
        )? {
            return Ok(None);
        }
        if !verify_mint_auth_signature(&inp.falcon_pubkey, &inp.falcon_sig, inp.value, &mu, domain) {
            return Ok(None);
        }
    }

    // Confidential conservation: outputs sum to the authorized total.
    if !verify_mint_crypto(np, total, output_commitments, output_range_proofs, balance_proof)? {
        return Ok(None);
    }
    Ok(Some(total))
}

// =====================================================================
// Legacy shield: one-way spend of a TRANSPARENT legacy coin → lattice coin
// =====================================================================

/// A legacy transparent-coin shield on the wire.
pub struct ShieldEnvelope {
    pub transparent_address: [u8; 32],
    pub ed448_pubkey: Vec<u8>,
    pub ed448_sig: Vec<u8>,
    pub output_commitment: Vec<u8>,
    pub output_range_proof: Vec<u8>,
    pub output_otk: Vec<u8>,
    pub balance_proof: Vec<u8>,
}

pub fn encode_shield(e: &ShieldEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&e.transparent_address);
    put_one(&mut out, &e.ed448_pubkey);
    put_one(&mut out, &e.ed448_sig);
    put_one(&mut out, &e.output_commitment);
    put_one(&mut out, &e.output_range_proof);
    put_one(&mut out, &e.output_otk);
    put_one(&mut out, &e.balance_proof);
    out
}
pub fn decode_shield(b: &[u8]) -> Result<ShieldEnvelope> {
    let mut transparent_address = [0u8; 32];
    transparent_address.copy_from_slice(
        b.get(0..32).ok_or_else(|| QuilError::InvalidArgument("shield: eof".into()))?,
    );
    let mut p = 32usize;
    Ok(ShieldEnvelope {
        transparent_address,
        ed448_pubkey: take_one(b, &mut p)?,
        ed448_sig: take_one(b, &mut p)?,
        output_commitment: take_one(b, &mut p)?,
        output_range_proof: take_one(b, &mut p)?,
        output_otk: take_one(b, &mut p)?,
        balance_proof: take_one(b, &mut p)?,
    })
}

/// The message an Ed448 legacy owner signs to shield their transparent coin: the
/// domain, the (public) amount, and the output commitment — so the shield is
/// bound to exactly this output and can't be replayed.
pub fn shield_message(domain: &[u8], amount: u128, output_commitment: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/legacy-shield/v1");
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update(amount.to_le_bytes());
    h.update((output_commitment.len() as u64).to_le_bytes());
    h.update(output_commitment);
    h.finalize().to_vec()
}

/// Verify a **one-way shield**: a transparent legacy coin `(owner_address,
/// amount)` is spent by its **Ed448** owner into a lattice private coin. Ed448
/// remains valid ONLY here (legacy owners only ever had Ed448 keys). The output
/// coin commits the *public* transparent `amount` (conservation via the mint
/// check). Returns the new coin's `cv` on success. The engine separately nullifies
/// the transparent entry and checks it isn't already shielded.
#[allow(clippy::too_many_arguments)]
pub fn verify_lattice_shield(
    np: &NetworkParams,
    domain: &[u8],
    owner_address: &[u8; 32],
    amount: u128,
    ed448_pubkey: &[u8],
    ed448_sig: &[u8],
    output_commitment: &[u8],
    output_range_proof: &[u8],
    balance_proof: &[u8],
) -> Result<Option<Vec<u8>>> {
    // 1. Ownership: the legacy address is poseidon(pubkey) OR poseidon(peerId) —
    //    accept either, matching the legacy verenc coin's address derivation.
    let addr_pk = quil_crypto::poseidon::hash_bytes_to_32(ed448_pubkey)?;
    let peer_id = quil_crypto::peer_id_multihash_from_ed448_pubkey(ed448_pubkey);
    let addr_pid = quil_crypto::poseidon::hash_bytes_to_32(&peer_id)?;
    if owner_address != &addr_pk && owner_address != &addr_pid {
        return Ok(None);
    }
    // 2. Ed448 signature over the shield context (binds the output).
    let msg = shield_message(domain, amount, output_commitment);
    if !quil_crypto::ed448_verify(ed448_pubkey, &msg, ed448_sig) {
        return Ok(None);
    }
    // 3. The output lattice coin commits exactly the (public) transparent amount
    //    — same conservation as a mint (Σ outputs = amount, no over-mint).
    if !verify_mint_crypto(np, amount, &[output_commitment.to_vec()], &[output_range_proof.to_vec()], balance_proof)? {
        return Ok(None);
    }
    let vlink = np.value_link_params();
    Ok(Some(wire::encode_polyvec(&vlink.compress(&decode_commit(output_commitment)?))))
}

// =====================================================================
// Wallet: confidential-transaction CONSTRUCTION (the prover side)
// =====================================================================

/// A coin the wallet owns and is spending. `auth_path` are the wire-encoded
/// sibling nodes for `leaf_index` at the *current* accumulator depth (the wallet
/// gets these by scanning the committed shadow tree).
pub struct SpendInput {
    pub sk: quil_lattice_ct::module::PolyVec,
    pub amount: u128,
    pub r_coin: quil_lattice_ct::module::PolyVec,
    pub leaf_index: usize,
    pub auth_path: Vec<Vec<u8>>,
}

/// A new output coin for a recipient (identified by their one-time key `P`).
pub struct NewOutput {
    pub amount: u128,
    pub recipient_otk: Vec<u8>, // wire-encoded P
}

/// The components of a built confidential transaction — exactly what
/// [`verify_lattice_transaction`] consumes, plus the new coins for materialize.
pub struct BuiltTransaction {
    pub input_spend_proofs: Vec<Vec<u8>>,
    pub output_commitments: Vec<Vec<u8>>,
    pub output_range_proofs: Vec<Vec<u8>>,
    pub balance_proof: Vec<u8>,
    pub fee: u128,
    /// `(P, cv)` per output — the coin-vertex fields the materialize path writes
    /// (and the shadow tree inserts).
    pub new_coins: Vec<(Vec<u8>, Vec<u8>)>,
    /// Wire-encoded output randomness `r_out` per output. The sender holds these
    /// (they are its own tx secrets) and uses them to build the per-output
    /// [`encrypt_ring_memo`] the recipient needs to recover `(amount, r_coin)`.
    /// Not part of the on-wire envelope.
    pub output_rand: Vec<Vec<u8>>,
}

/// Construct the confidential-value layer of a mint: output coins committing
/// amounts that sum **exactly** to the public `mint_amount`, with range proofs and
/// a conservation proof (`virtual(mint_amount) − Σ outputs = 0`). No spend proofs
/// (a mint creates value under an authorization, not by spending). Returns the
/// components + the new `(P, cv)` coins. The caller attaches the authorization
/// (PoMW / authority) and submits.
pub fn build_mint_transaction(
    np: &NetworkParams,
    mint_amount: u128,
    outputs: &[NewOutput],
    seed: u64,
) -> Result<BuiltTransaction> {
    use quil_lattice_ct::module::PolyVec;

    let vlink = np.value_link_params();
    let vkey = np.value_key();
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed);

    // Virtual input: the authorized mint amount as Commit(amount; 0).
    let vin = mint_virtual_input(mint_amount);
    let in_virtual = vec![virtual_limbs(&vin)?];
    let in_rand = vec![PolyVec::zero(vkey.a1.cols)];
    let in_amounts = vec![mint_amount];

    let mut output_commitments = Vec::with_capacity(outputs.len());
    let mut out_virtual = Vec::with_capacity(outputs.len());
    let mut out_rand = Vec::with_capacity(outputs.len());
    let mut out_amounts = Vec::with_capacity(outputs.len());
    let mut new_coins = Vec::with_capacity(outputs.len());
    for out in outputs {
        let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let c_out = commit_amount(&vkey, out.amount, &r_out);
        let cv_out = vlink.compress(&c_out);
        out_virtual.push(virtual_limbs(&c_out)?);
        output_commitments.push(wire::encode_commitment(&c_out));
        new_coins.push((out.recipient_otk.clone(), wire::encode_polyvec(&cv_out)));
        out_rand.push(r_out);
        out_amounts.push(out.amount);
    }

    // Conservation + non-negativity: virtual(mint) − Σ outputs = 0, full-width.
    // range_free ⇒ output ranges are the PACKED per-limb proofs (no legacy range_rq).
    let balance = quil_lattice_ct::limb_balance::prove_limb_balance_bound_ext(
        np.limb_range_key(), &in_virtual, &in_rand, &out_virtual, &out_rand,
        &in_amounts, &out_amounts, 0, VALUE_LIMBS, seed ^ 0x500, true,
    )
    .ok_or_else(|| QuilError::Internal("lattice-ct: mint balance failed (outputs ≠ mint amount?)".into()))?;
    let output_range_proofs = packed_output_range_blobs(np, &output_commitments, &out_amounts, &out_rand, seed ^ 0x5100)?;

    Ok(BuiltTransaction {
        input_spend_proofs: Vec::new(),
        output_commitments,
        output_range_proofs,
        balance_proof: wire::encode_limb_balance(&balance),
        fee: mint_amount, // carries the (public) minted total for the envelope
        new_coins,
        output_rand: out_rand.iter().map(wire::encode_polyvec).collect(),
    })
}

/// Wallet: build a FULL-WIDTH (fw) MINT. Output coins are
/// fw coins (`production(FW_COIN_SEED).commit(bit-polys)`); the single amortized IPA
/// proof (ranges + conservation `Σ outputs = mint_amount`) rides `balance_proof`, and
/// `output_range_proofs` carry the fw marker. The stored coin `cv` is the same
/// `vlink.compress(coin)` form (dimension-compatible), so the coin vertex / accumulator
/// are unchanged; `output_rand` carries each fw coin's randomness for the memo.
pub fn build_fw_mint_transaction(
    np: &NetworkParams,
    mint_amount: u128,
    outputs: &[NewOutput],
    seed: u64,
) -> Result<BuiltTransaction> {
    use quil_lattice_ct::labrador_ct::fullwidth::{commit_fw_mint, prove_fw_tx_ipa_zk};
    use quil_lattice_ct::wire::{encode_commitment, encode_full_ct_zk_ipa_compact, encode_polyvec};
    let vlink = np.value_link_params();
    let out_amounts: Vec<u128> = outputs.iter().map(|o| o.amount).collect();
    let (stmt, wit, coins) = commit_fw_mint(
        super::packed_range::FW_N_LIMBS,
        mint_amount,
        &out_amounts,
        &np.value_key(),
        seed,
    );
    let proof = prove_fw_tx_ipa_zk(&stmt, &wit, seed ^ 0xF117)
        .ok_or_else(|| QuilError::Internal("lattice-ct: fw mint prove failed (outputs ≠ mint amount?)".into()))?;
    let mut new_coins = Vec::with_capacity(outputs.len());
    let mut output_commitments = Vec::with_capacity(outputs.len());
    let mut output_rand = Vec::with_capacity(outputs.len());
    for ((out, coin), r) in outputs.iter().zip(&coins).zip(&wit.rand) {
        let cv = vlink.compress(coin);
        new_coins.push((out.recipient_otk.clone(), encode_polyvec(&cv)));
        output_commitments.push(encode_commitment(coin));
        output_rand.push(encode_polyvec(r));
    }
    Ok(BuiltTransaction {
        input_spend_proofs: Vec::new(),
        output_commitments,
        output_range_proofs: super::packed_range::fw_output_ranges_marker(),
        balance_proof: encode_full_ct_zk_ipa_compact(&proof),
        fee: mint_amount,
        new_coins,
        output_rand,
    })
}

/// Wallet: build a one-way SHIELD — spend a transparent legacy coin (`amount`,
/// owned by the Ed448 key `ed448_secret`/`ed448_pubkey`) into a lattice private
/// coin for `recipient_otk`. Produces the [`ShieldEnvelope`] the engine verifies.
#[allow(clippy::too_many_arguments)]
pub fn build_shield_transaction(
    np: &NetworkParams,
    domain: &[u8],
    transparent_address: [u8; 32],
    ed448_secret: &[u8; 57],
    ed448_pubkey: &[u8],
    amount: u128,
    recipient_otk: Vec<u8>,
    seed: u64,
) -> Result<ShieldEnvelope> {
    use quil_lattice_ct::module::PolyVec;

    let vkey = np.value_key();
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed);
    let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
    let c_out = commit_amount(&vkey, amount, &r_out);
    // Conservation: virtual(amount) − output = 0 (output commits the public amount),
    // full-width limb balance (folds the output-limb range proofs).
    let vin = mint_virtual_input(amount);
    // range_free ⇒ the output range is the PACKED per-limb proof (no legacy range_rq).
    let balance = quil_lattice_ct::limb_balance::prove_limb_balance_bound_ext(
        np.limb_range_key(),
        &[virtual_limbs(&vin)?],
        &[PolyVec::zero(vkey.a1.cols)],
        &[virtual_limbs(&c_out)?],
        &[r_out.clone()],
        &[amount],
        &[amount],
        0,
        VALUE_LIMBS,
        seed ^ 0x6,
        true,
    )
    .ok_or_else(|| QuilError::Internal("shield: balance failed".into()))?;

    let output_commitment = wire::encode_commitment(&c_out);
    let output_range_proof = packed_output_range_blobs(np, &[output_commitment.clone()], &[amount], &[r_out], seed ^ 0x6100)?
        .into_iter()
        .next()
        .unwrap_or_default();
    let msg = shield_message(domain, amount, &output_commitment);
    let signer = quil_crypto::Ed448Signer::from_bytes(ed448_secret, ed448_pubkey)
        .map_err(|e| QuilError::Internal(format!("shield: ed448 key: {e:?}")))?;
    let ed448_sig = quil_types::crypto::Signer::sign(&signer, &msg)
        .map_err(|e| QuilError::Internal(format!("shield: ed448 sign: {e:?}")))?;

    Ok(ShieldEnvelope {
        transparent_address,
        ed448_pubkey: ed448_pubkey.to_vec(),
        ed448_sig,
        output_commitment,
        output_range_proof, // coefficient-packed per-limb ranges
        output_otk: recipient_otk,
        balance_proof: wire::encode_limb_balance(&balance),
    })
}

/// Wallet: build a FULL-WIDTH (fw) one-way SHIELD. The
/// output is a single fw coin conserving the public `amount`; the fw proof rides
/// `balance_proof`, the fw marker rides `output_range_proof`. Ed448 ownership +
/// signature are unchanged (verify runs conservation through the fw mint dispatch).
#[allow(clippy::too_many_arguments)]
pub fn build_fw_shield_transaction(
    np: &NetworkParams,
    domain: &[u8],
    transparent_address: [u8; 32],
    ed448_secret: &[u8; 57],
    ed448_pubkey: &[u8],
    amount: u128,
    recipient_otk: Vec<u8>,
    seed: u64,
) -> Result<ShieldEnvelope> {
    let (coins, proof_bytes) =
        crate::token_intrinsic::packed_range::prove_fw_mint_bytes(&np.value_key(), amount, &[amount], seed)?;
    let output_commitment = coins.into_iter().next().unwrap_or_default();
    let msg = shield_message(domain, amount, &output_commitment);
    let signer = quil_crypto::Ed448Signer::from_bytes(ed448_secret, ed448_pubkey)
        .map_err(|e| QuilError::Internal(format!("fw shield: ed448 key: {e:?}")))?;
    let ed448_sig = quil_types::crypto::Signer::sign(&signer, &msg)
        .map_err(|e| QuilError::Internal(format!("fw shield: ed448 sign: {e:?}")))?;
    Ok(ShieldEnvelope {
        transparent_address,
        ed448_pubkey: ed448_pubkey.to_vec(),
        ed448_sig,
        output_commitment,
        output_range_proof: vec![crate::token_intrinsic::packed_range::RANGE_V_FULLWIDTH], // fw marker
        output_otk: recipient_otk,
        balance_proof: proof_bytes,
    })
}

/// Wallet: build an escrow CREATE — spend `inputs` and lock `escrow_amount` into
/// an escrow for the `to`/`refund` Falcon keys until `expiration`. Reuses the
/// confidential transfer builder with the escrow as the single output.
#[allow(clippy::too_many_arguments)]
pub fn build_pending_create(
    np: &NetworkParams,
    root: &[u8],
    depth: usize,
    domain: &[u8],
    inputs: &[SpendInput],
    escrow_amount: u128,
    fee: u128,
    to_key: Vec<u8>,
    refund_key: Vec<u8>,
    expiration: u64,
    memo: Vec<u8>,
    seed: u64,
) -> Result<PendingCreateEnvelope> {
    let outputs = [NewOutput { amount: escrow_amount, recipient_otk: Vec::new() }];
    let mut built = build_spend_transaction(np, root, depth, domain, inputs, &outputs, fee, seed)?;
    // Single escrow output ⇒ its packed per-limb ranges are output_range_proofs[0].
    let escrow_range_proof = built.output_range_proofs.drain(..).next().unwrap_or_default();
    Ok(PendingCreateEnvelope {
        input_spend_proofs: built.input_spend_proofs,
        escrow_commitment: built.output_commitments.into_iter().next().unwrap(),
        escrow_range_proof,
        balance_proof: built.balance_proof,
        fee,
        to_key,
        refund_key,
        expiration,
        memo,
        change_commitments: Vec::new(),
        change_otks: Vec::new(),
        change_memos: Vec::new(),
        change_range_proofs: Vec::new(),
    })
}

// NOTE: escrow uses the legacy limb-value coin format, NOT the full-width (fw) format.
// Escrow CREATE (`build_pending_create`) and CLAIM/REFUND (`build_pending_claim` /
// `verify_lattice_pending_claim`) both encode the escrow with `limbs_msg` (limb-value)
// and value-link it, so the escrow `cv` matches on claim — self-consistent and
// end-to-end tested (`escrow_create_scan_claim_end_to_end`). An fw escrow coin
// (message = `bitpoly_msg`) would NOT match a limb-value claim reconstruction, leaving
// funds UNCLAIMABLE; giving escrow the fw format requires changing CREATE, CLAIM (claim
// by fw-spending the escrow coin into an fw output), and the output-coin encoding together.

/// Wallet: build an escrow CLAIM/REFUND. The claimant knows the escrow amount +
/// randomness (`escrow_r`, from the memo) and holds the `to`/`refund` Falcon key.
/// Returns `(envelope, r_out)` — the claimant fills `envelope.output_memo` from
/// `r_out` (via [`build_output_memo`]) so the new coin is scannable + spendable.
#[allow(clippy::too_many_arguments)]
pub fn build_pending_claim(
    np: &NetworkParams,
    domain: &[u8],
    escrow_address: [u8; 32],
    escrow_amount: u128,
    escrow_r: &quil_lattice_ct::module::PolyVec,
    is_to: bool,
    recipient_falcon: &quil_crypto::FalconSigner,
    recipient_otk: Vec<u8>,
    seed: u64,
) -> Result<(PendingClaimEnvelope, quil_lattice_ct::module::PolyVec)> {
    use quil_lattice_ct::value_link::prove_value_link;
    use quil_types::crypto::Signer;

    let vlink = np.value_link_params();
    let vkey = np.value_key();
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed);
    let v = limbs_msg(escrow_amount);
    let r_out = quil_lattice_ct::module::PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
    // cv = H_B(Commit(amount; escrow_r)) is the escrow's committed cv; c_out is
    // the new coin commitment (ℓ=VALUE_LIMBS) to the same amount. Range is inherited
    // from the escrow's create-time bound (value link binds output ≡ escrow).
    let (_cv, c_out, vl) = prove_value_link(&vlink, &v, escrow_r, &r_out, seed ^ 0x7)
        .ok_or_else(|| QuilError::Internal("pending claim: value-link failed".into()))?;
    let output_commitment = wire::encode_commitment(&c_out);
    let mu = tx_challenge(domain, &[output_commitment.clone()], is_to as u128);
    let falcon_sig = recipient_falcon
        .sign_with_domain(&mint_auth_message(is_to as u128, &mu), domain)
        .map_err(|e| QuilError::Internal(format!("pending claim: falcon sign: {e:?}")))?;
    let env = PendingClaimEnvelope {
        escrow_address,
        is_to,
        falcon_sig,
        output_commitment,
        output_range_proof: Vec::new(), // range inherited from the escrow (value-linked)
        output_otk: recipient_otk,
        value_link_proof: wire::encode_opening(&vl),
        output_memo: Vec::new(), // caller fills from r_out
    };
    Ok((env, r_out))
}

/// The transaction challenge `mu` the spend proofs bind to — a domain-separated
/// hash of the transaction context (domain, outputs, fee). Derived identically by
/// the wallet and the engine, so no `mu` needs to travel on the wire, and a spend
/// cannot be replayed into a transaction with different outputs.
pub fn tx_challenge(domain: &[u8], output_commitments: &[Vec<u8>], fee: u128) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/tx-challenge/v1");
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update((output_commitments.len() as u64).to_le_bytes());
    for c in output_commitments {
        h.update((c.len() as u64).to_le_bytes());
        h.update(c);
    }
    h.update(fee.to_le_bytes());
    h.finalize().to_vec()
}

/// Construct a confidential transaction: for each output commit the amount,
/// range-prove it, and derive `cv = H_B(C)`; then for each owned input build a
/// spend proof (hiding the coin, revealing a fresh `C'`, bound to the derived
/// challenge); then prove balance `Σ C'_in = Σ C_out + fee`. The caller must
/// ensure conservation holds. `root` / `depth` are the committed shadow-tree root
/// the spends prove against.
#[allow(clippy::too_many_arguments)]
pub fn build_spend_transaction(
    np: &NetworkParams,
    root: &[u8],
    depth: usize,
    domain: &[u8],
    inputs: &[SpendInput],
    outputs: &[NewOutput],
    fee: u128,
    seed: u64,
) -> Result<BuiltTransaction> {
    // Packed-only by default: the legacy range_rq confidential format is retired.
    build_spend_transaction_ext(np, root, depth, domain, inputs, outputs, fee, seed, true)
}

/// `build_spend_transaction` with `range_free`: when `true` the limb balance omits
/// the output `range_rq` (the caller adds packed per-limb ranges to
/// `output_range_proofs`, verified `range_free` on the node).
#[allow(clippy::too_many_arguments)]
pub fn build_spend_transaction_ext(
    np: &NetworkParams,
    root: &[u8],
    depth: usize,
    domain: &[u8],
    inputs: &[SpendInput],
    outputs: &[NewOutput],
    fee: u128,
    seed: u64,
    range_free: bool,
) -> Result<BuiltTransaction> {
    use quil_lattice_ct::membership::{prove_spend, MembershipParams};
    use quil_lattice_ct::module::PolyVec;

    let vlink = np.value_link_params();
    let vkey = np.value_key();
    let mp = MembershipParams::production(depth);
    let root_node = wire::decode_polyvec(root)
        .map_err(|e| QuilError::InvalidArgument(format!("lattice-ct: root decode: {e:?}")))?;
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed);

    // --- outputs first: ℓ=VALUE_LIMBS commitments + cv (needed for the challenge) ---
    let mut output_commitments = Vec::with_capacity(outputs.len());
    let mut new_coins = Vec::with_capacity(outputs.len());
    let mut out_virtual = Vec::with_capacity(outputs.len());
    let mut out_rand = Vec::with_capacity(outputs.len());
    let mut out_amounts = Vec::with_capacity(outputs.len());
    for out in outputs {
        let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let c_out = commit_amount(&vkey, out.amount, &r_out);
        let cv_out = vlink.compress(&c_out);
        out_virtual.push(virtual_limbs(&c_out)?);
        output_commitments.push(wire::encode_commitment(&c_out));
        new_coins.push((out.recipient_otk.clone(), wire::encode_polyvec(&cv_out)));
        out_rand.push(r_out);
        out_amounts.push(out.amount);
    }

    // Derive the challenge from the (now fixed) output context.
    let mu = tx_challenge(domain, &output_commitments, fee);

    // --- inputs: spend proofs bound to `mu`; their C' feed the limb balance (+1) ---
    let mut input_spend_proofs = Vec::with_capacity(inputs.len());
    let mut in_virtual = Vec::with_capacity(inputs.len());
    let mut in_rand = Vec::with_capacity(inputs.len());
    let mut in_amounts = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let v = limbs_msg(inp.amount);
        let r_prime = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let path: Vec<_> = inp
            .auth_path
            .iter()
            .map(|b| wire::decode_polyvec(b))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| QuilError::InvalidArgument(format!("lattice-ct: auth path decode: {e:?}")))?;
        let sp = prove_spend(
            &mp, &vlink, &root_node, &inp.sk, &v, &inp.r_coin, &r_prime, inp.leaf_index, &path, &mu,
            seed ^ (0xA000 + i as u64),
        )
        .ok_or_else(|| QuilError::Internal("lattice-ct: spend proof failed (bad witness?)".into()))?;
        in_virtual.push(virtual_limbs(&sp.c_prime)?);
        in_rand.push(r_prime);
        in_amounts.push(inp.amount);
        input_spend_proofs.push(wire::encode_spend(&sp));
    }

    // --- full-width balance: Σ C'_in = Σ C_out + fee (carry chain) ---
    let balance = quil_lattice_ct::limb_balance::prove_limb_balance_bound_ext(
        np.limb_range_key(), &in_virtual, &in_rand, &out_virtual, &out_rand,
        &in_amounts, &out_amounts, fee, VALUE_LIMBS, seed ^ 0x400, range_free,
    )
    .ok_or_else(|| QuilError::Internal("lattice-ct: balance proof failed (not conserving?)".into()))?;

    // In range_free mode the limb balance omits its output range_rq; supply the
    // coefficient-PACKED per-limb ranges instead (one blob per output). Every
    // caller (transfer, escrow, tests) thus emits the packed-only format.
    let output_range_proofs = if range_free {
        packed_output_range_blobs(np, &output_commitments, &out_amounts, &out_rand, seed ^ 0x7000)?
    } else {
        Vec::new() // legacy: ranges folded into the limb balance
    };

    Ok(BuiltTransaction {
        input_spend_proofs,
        output_commitments,
        output_range_proofs,
        balance_proof: wire::encode_limb_balance(&balance),
        fee,
        new_coins,
        output_rand: out_rand.iter().map(wire::encode_polyvec).collect(),
    })
}

/// Wallet: build a FULL-WIDTH (fw) confidential TRANSFER.
/// Inputs are spent with the EXISTING spend proofs (value_key `c_prime`s); outputs are
/// fw coins; and ONE fw IPA proof covers the output ranges + the carry-chain balance,
/// binding each input's value to its spend-proof `c_prime` (the fw↔c_prime value-link).
/// So no separate limb-balance / packed ranges — one proof, marker `RANGE_V_FULLWIDTH`.
#[allow(clippy::too_many_arguments)]
pub fn build_fw_spend_transaction(
    np: &NetworkParams,
    root: &[u8],
    depth: usize,
    domain: &[u8],
    inputs: &[SpendInput],
    outputs: &[NewOutput],
    fee: u128,
    seed: u64,
) -> Result<BuiltTransaction> {
    use quil_lattice_ct::labrador_ct::fullwidth::{commit_fw_transfer_ext, prove_fw_transfer_ipa_zk};
    use quil_lattice_ct::membership::{prove_spend, MembershipParams};
    use quil_lattice_ct::module::PolyVec;

    let vlink = np.value_link_params();
    // UNIFORM fw: both the coins and the c_primes are `value_key.commit(bit-polys)`,
    // so minted/transferred coins are spendable via the (message-agnostic) membership
    // relation. The spend proof's message is the coin's BIT-POLYS, not limb values.
    let value_key = np.value_key();
    let mp = MembershipParams::production(depth);
    let root_node = wire::decode_polyvec(root)
        .map_err(|e| QuilError::InvalidArgument(format!("lattice-ct: root decode: {e:?}")))?;
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(seed);
    let out_amounts: Vec<u128> = outputs.iter().map(|o| o.amount).collect();
    let in_amounts: Vec<u128> = inputs.iter().map(|i| i.amount).collect();

    // Outputs as fw coins (production(FW_COIN_SEED).commit(bit-polys)); build them with
    // the transfer helper so their randomness matches the proof witness. The proof also
    // needs the input c_primes, so build the spend proofs FIRST to get them.
    // --- inputs: spend proofs bound to mu (derived from the fw output commitments) ---
    // First materialize the fw output coins (deterministic from out_amounts + seed) to
    // fix the challenge, THEN the spends, THEN the one fw proof over both.
    // Build the fw statement/witness once we have the c_primes; but the outputs are part
    // of `mu`, so pre-compute the fw output coins here (same rand the proof will use).
    let (pre_stmt, _pre_wit, pre_coins) = commit_fw_transfer_ext(
        super::packed_range::FW_N_LIMBS, &in_amounts,
        // placeholder c_primes/r_p just to fix the output coins deterministically:
        &vec![commit_amount(&value_key, 0, &PolyVec::zero(value_key.a1.cols)); inputs.len()],
        &vec![PolyVec::zero(value_key.a1.cols); inputs.len()],
        &out_amounts, fee, &value_key, &value_key, seed,
    );
    let output_commitments: Vec<Vec<u8>> = pre_coins.iter().map(wire::encode_commitment).collect();
    let mut new_coins = Vec::with_capacity(outputs.len());
    for (out, coin) in outputs.iter().zip(&pre_coins) {
        new_coins.push((out.recipient_otk.clone(), wire::encode_polyvec(&vlink.compress(coin))));
    }
    let _ = pre_stmt;
    let mu = tx_challenge(domain, &output_commitments, fee);

    let mut input_spend_proofs = Vec::with_capacity(inputs.len());
    let mut in_cprimes = Vec::with_capacity(inputs.len());
    let mut in_rp = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        // The coin's message is BIT-POLYS (uniform fw), so C' = value_key.commit(bit_polys; r').
        let v = bitpoly_msg(inp.amount);
        let r_prime = PolyVec::sample_short(value_key.a1.cols, ETA, &mut prg);
        let path: Vec<_> = inp
            .auth_path
            .iter()
            .map(|b| wire::decode_polyvec(b))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| QuilError::InvalidArgument(format!("lattice-ct: auth path decode: {e:?}")))?;
        let sp = prove_spend(
            &mp, &vlink, &root_node, &inp.sk, &v, &inp.r_coin, &r_prime, inp.leaf_index, &path, &mu,
            seed ^ (0xA000 + i as u64),
        )
        .ok_or_else(|| QuilError::Internal("lattice-ct: spend proof failed (bad witness?)".into()))?;
        in_cprimes.push(sp.c_prime.clone());
        in_rp.push(r_prime);
        input_spend_proofs.push(wire::encode_spend(&sp));
    }

    // The one fw transfer proof over the REAL spend c_primes + the fw output coins.
    let (stmt, wit, _coins) = commit_fw_transfer_ext(
        super::packed_range::FW_N_LIMBS, &in_amounts, &in_cprimes, &in_rp, &out_amounts, fee, &value_key, &value_key, seed,
    );
    let proof = prove_fw_transfer_ipa_zk(&stmt, &wit, seed ^ 0xF337)
        .ok_or_else(|| QuilError::Internal("lattice-ct: fw transfer prove failed (not conserving?)".into()))?;

    Ok(BuiltTransaction {
        input_spend_proofs,
        output_commitments,
        output_range_proofs: super::packed_range::fw_output_ranges_marker(),
        balance_proof: quil_lattice_ct::wire::encode_full_ct_zk_ipa_compact(&proof),
        fee,
        new_coins,
        output_rand: Vec::new(),
    })
}

// =====================================================================
// Escrow (pending): CREATE spends inputs → escrow; CLAIM/REFUND → a coin
// =====================================================================

/// Escrow CREATE on the wire.
pub struct PendingCreateEnvelope {
    pub input_spend_proofs: Vec<Vec<u8>>,
    pub escrow_commitment: Vec<u8>,
    pub escrow_range_proof: Vec<u8>,
    pub balance_proof: Vec<u8>,
    pub fee: u128,
    pub to_key: Vec<u8>,     // Falcon pubkey of the claimant
    pub refund_key: Vec<u8>, // Falcon pubkey of the refunder
    pub expiration: u64,
    pub memo: Vec<u8>,
    /// Optional change coins back to the sender (so inputs need not sum exactly to
    /// the escrow amount). Each is a regular coin output — commitment + one-time
    /// key + memo — folded into the same balance proof. Empty ⇒ no change.
    pub change_commitments: Vec<Vec<u8>>,
    pub change_otks: Vec<Vec<u8>>,
    pub change_memos: Vec<Vec<u8>>,
    /// Packed per-limb range proof for each change coin (parallel to
    /// `change_commitments`). The escrow's own packed ranges ride
    /// `escrow_range_proof`. Empty ⇒ no change.
    pub change_range_proofs: Vec<Vec<u8>>,
}

/// Escrow CLAIM/REFUND on the wire.
pub struct PendingClaimEnvelope {
    pub escrow_address: [u8; 32], // where the escrow vertex lives
    pub is_to: bool,
    pub falcon_sig: Vec<u8>,
    pub output_commitment: Vec<u8>,
    pub output_range_proof: Vec<u8>,
    pub output_otk: Vec<u8>,
    pub value_link_proof: Vec<u8>,
    /// Per-output memo (`kem_ciphertext ‖ ring_memo`, [`build_output_memo`]) for
    /// the NEW claimed coin, so the claimant can later scan + spend it. Consensus-
    /// opaque (verify ignores it; materialize stores it in the coin vertex). Empty
    /// ⇒ no memo (the coin is then unscannable — always set it for a real claim).
    pub output_memo: Vec<u8>,
}

pub fn encode_pending_create(e: &PendingCreateEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    put_vecs(&mut out, &e.input_spend_proofs);
    put_one(&mut out, &e.escrow_commitment);
    put_one(&mut out, &e.escrow_range_proof);
    put_one(&mut out, &e.balance_proof);
    out.extend_from_slice(&e.fee.to_le_bytes());
    put_one(&mut out, &e.to_key);
    put_one(&mut out, &e.refund_key);
    out.extend_from_slice(&e.expiration.to_le_bytes());
    put_one(&mut out, &e.memo);
    put_vecs(&mut out, &e.change_commitments);
    put_vecs(&mut out, &e.change_otks);
    put_vecs(&mut out, &e.change_memos);
    put_vecs(&mut out, &e.change_range_proofs);
    out
}
pub fn decode_pending_create(b: &[u8]) -> Result<PendingCreateEnvelope> {
    let mut p = 0usize;
    let input_spend_proofs = take_vecs(b, &mut p)?;
    let escrow_commitment = take_one(b, &mut p)?;
    let escrow_range_proof = take_one(b, &mut p)?;
    let balance_proof = take_one(b, &mut p)?;
    let fee = take_u128(b, &mut p)?;
    let to_key = take_one(b, &mut p)?;
    let refund_key = take_one(b, &mut p)?;
    let expiration = {
        let e = p + 8;
        let s = b.get(p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
        p = e;
        u64::from_le_bytes(s.try_into().unwrap())
    };
    let memo = take_one(b, &mut p)?;
    // Change fields were appended after the initial format; tolerate their
    // absence so an old-format escrow-create still decodes (no change).
    let change_commitments = take_vecs(b, &mut p).unwrap_or_default();
    let change_otks = take_vecs(b, &mut p).unwrap_or_default();
    let change_memos = take_vecs(b, &mut p).unwrap_or_default();
    let change_range_proofs = take_vecs(b, &mut p).unwrap_or_default();
    Ok(PendingCreateEnvelope {
        input_spend_proofs,
        escrow_commitment,
        escrow_range_proof,
        balance_proof,
        fee,
        to_key,
        refund_key,
        expiration,
        memo,
        change_commitments,
        change_otks,
        change_memos,
        change_range_proofs,
    })
}

pub fn encode_pending_claim(e: &PendingClaimEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&e.escrow_address);
    out.push(e.is_to as u8);
    put_one(&mut out, &e.falcon_sig);
    put_one(&mut out, &e.output_commitment);
    put_one(&mut out, &e.output_range_proof);
    put_one(&mut out, &e.output_otk);
    put_one(&mut out, &e.value_link_proof);
    put_one(&mut out, &e.output_memo);
    out
}
pub fn decode_pending_claim(b: &[u8]) -> Result<PendingClaimEnvelope> {
    let mut escrow_address = [0u8; 32];
    let s = b.get(0..32).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: claim eof".into()))?;
    escrow_address.copy_from_slice(s);
    let mut p = 32usize;
    let is_to = *b.get(p).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: claim eof".into()))? != 0;
    p += 1;
    let falcon_sig = take_one(b, &mut p)?;
    let output_commitment = take_one(b, &mut p)?;
    let output_range_proof = take_one(b, &mut p)?;
    let output_otk = take_one(b, &mut p)?;
    let value_link_proof = take_one(b, &mut p)?;
    // `output_memo` was appended after the initial format; tolerate its absence
    // so an old-format claim still decodes (empty memo ⇒ unscannable coin).
    let output_memo = take_one(b, &mut p).unwrap_or_default();
    Ok(PendingClaimEnvelope {
        escrow_address,
        is_to,
        falcon_sig,
        output_commitment,
        output_range_proof,
        output_otk,
        value_link_proof,
        output_memo,
    })
}

/// Verify an escrow CREATE: spend the input coins and lock the value into an
/// escrow whose amount commitment is `escrow_commitment` — conservation
/// `Σ inputs = escrow_amount + fee` (the escrow is the single "output"). Returns
/// the input key images (nullifiers) + the escrow's `cv = H_B(C)` for the pending
/// vertex. This is a confidential transfer with one escrow output.
#[allow(clippy::too_many_arguments)]
pub fn verify_lattice_pending_create(
    np: &NetworkParams,
    state: &HypergraphState,
    domain: &[u8],
    input_spend_proofs: &[Vec<u8>],
    escrow_commitment: &[u8],
    escrow_range_proof: &[u8],
    change_commitments: &[Vec<u8>],
    change_otks: &[Vec<u8>],
    change_range_proofs: &[Vec<u8>],
    balance_proof: &[u8],
    fee: u128,
) -> Result<Option<(Vec<Vec<u8>>, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>> {
    if change_otks.len() != change_commitments.len()
        || change_range_proofs.len() != change_commitments.len()
    {
        return Ok(None);
    }
    // Outputs are the escrow followed by any change coins; the balance proof
    // conserves over all of them (Σ inputs = escrow + Σ change + fee). Every
    // output carries its packed per-limb ranges (escrow + change) — the legacy
    // range_rq format is not accepted.
    let mut outs = vec![escrow_commitment.to_vec()];
    outs.extend(change_commitments.iter().cloned());
    let mut range_proofs = vec![escrow_range_proof.to_vec()];
    range_proofs.extend(change_range_proofs.iter().cloned());
    let mu = tx_challenge(domain, &outs, fee);
    let key_images = match verify_lattice_transaction(
        np,
        state,
        domain,
        input_spend_proofs,
        &outs,
        &range_proofs,
        balance_proof,
        fee,
        true,
        &mu,
    )? {
        Some(k) => k,
        None => return Ok(None),
    };
    let vlink = np.value_link_params();
    let cv = wire::encode_polyvec(&vlink.compress(&decode_commit(escrow_commitment)?));
    let mut change_coins = Vec::with_capacity(change_commitments.len());
    for (i, cc) in change_commitments.iter().enumerate() {
        let ccv = wire::encode_polyvec(&vlink.compress(&decode_commit(cc)?));
        change_coins.push((change_otks[i].clone(), ccv));
    }
    Ok(Some((key_images, cv, change_coins)))
}

/// Verify an escrow CLAIM (or REFUND): the claimant is the escrow's `to` (or
/// `refund`) party — proven by a **Falcon** signature — and the new coin
/// `output_commitment` commits the **same amount** as the escrow, proven by the
/// value-link against the escrow's committed `escrow_cv`. Returns the new coin's
/// `cv` for the shadow tree. Refund callers must additionally enforce
/// `frame ≥ expiration` (checked by the engine against the escrow vertex).
#[allow(clippy::too_many_arguments)]
pub fn verify_lattice_pending_claim(
    np: &NetworkParams,
    domain: &[u8],
    escrow_cv: &[u8],
    recipient_falcon_key: &[u8], // the escrow's to_key or refund_key
    is_to: bool,
    falcon_sig: &[u8],
    output_commitment: &[u8],
    output_range_proof: &[u8],
    value_link_proof: &[u8],
) -> Result<Option<Vec<u8>>> {
    // 1. Ownership: Falcon signature by the claim recipient over the output
    //    context (the `is_to` flag distinguishes claim vs refund signatures).
    let mu = tx_challenge(domain, &[output_commitment.to_vec()], is_to as u128);
    if !verify_mint_auth_signature(recipient_falcon_key, falcon_sig, is_to as u128, &mu, domain) {
        return Ok(None);
    }
    // 2. The output coin commits the escrow's amount, which was range-bounded at
    //    CREATE time; the value link (step 3) binds output ≡ escrow, so no fresh
    //    range proof is needed (`output_range_proof` vestigial, ignored).
    let _ = output_range_proof;
    let c_out = decode_commit(output_commitment)?;
    // 3. Value link: the output commits the escrow's amount (cv = H_B(escrow_C)).
    let vlink = np.value_link_params();
    let cv = wire::decode_polyvec(escrow_cv)
        .map_err(|e| QuilError::InvalidArgument(format!("pending: escrow cv decode: {e:?}")))?;
    let vl = wire::decode_opening(value_link_proof)
        .map_err(|e| QuilError::InvalidArgument(format!("pending: value-link decode: {e:?}")))?;
    if !quil_lattice_ct::value_link::verify_value_link(&vlink, &cv, &c_out, &vl) {
        return Ok(None);
    }
    Ok(Some(wire::encode_polyvec(&vlink.compress(&c_out))))
}

// =====================================================================
// Wire envelope — the wallet↔engine byte contract for a confidential tx
// =====================================================================

/// The confidential-transaction components on the wire. `cv` is NOT carried — the
/// engine recomputes `cv = H_B(C_out)` from each output commitment (never trust a
/// wallet-supplied accumulator node).
pub struct TxEnvelope {
    pub input_spend_proofs: Vec<Vec<u8>>,
    pub output_commitments: Vec<Vec<u8>>,
    pub output_range_proofs: Vec<Vec<u8>>,
    pub output_otks: Vec<Vec<u8>>, // recipient one-time key P per output
    /// Opaque per-output memo blob (`kem_ciphertext ‖ ring_memo`) the recipient
    /// uses to recover `(amount, r_coin)`. Consensus-opaque: verify ignores it;
    /// materialize stores it in the coin vertex. Empty ⇒ no memo (e.g. mint).
    pub output_memos: Vec<Vec<u8>>,
    pub balance_proof: Vec<u8>,
    pub fee: u128,
}

impl TxEnvelope {
    /// Build the envelope from a built transaction. `output_memos` is left
    /// empty; the wallet fills it per output using [`build_output_memo`] (it
    /// needs the recipient KEM ciphertext + shared secret, which live wallet-
    /// side, plus `BuiltTransaction::output_rand`).
    pub fn from_built(b: &BuiltTransaction) -> Self {
        TxEnvelope {
            input_spend_proofs: b.input_spend_proofs.clone(),
            output_commitments: b.output_commitments.clone(),
            output_range_proofs: b.output_range_proofs.clone(),
            output_otks: b.new_coins.iter().map(|(p, _)| p.clone()).collect(),
            output_memos: Vec::new(),
            balance_proof: b.balance_proof.clone(),
            fee: b.fee,
        }
    }
}

/// Assemble one output's memo blob: `put_one(kem_ciphertext) ‖
/// put_one(encrypt_ring_memo(ss, amount, r_out))`. The recipient splits it,
/// `decapsulate`s the KEM ciphertext with its `q-onion-key` to recover `ss`,
/// then [`open_ring_memo`]s to recover `(amount, r_coin)`.
pub fn build_output_memo(kem_ciphertext: &[u8], amount: u128, r_out: &PolyVec, shared_secret: &[u8]) -> Vec<u8> {
    let ring_memo = encrypt_ring_memo(shared_secret, amount, r_out);
    let mut out = Vec::with_capacity(8 + kem_ciphertext.len() + ring_memo.len());
    put_one(&mut out, kem_ciphertext);
    put_one(&mut out, &ring_memo);
    out
}

/// Build an escrow memo carrying `(amount, escrow_r)` recoverable by EITHER the
/// `to` or the `refund` party. Each half is a [`build_output_memo`] blob KEM-
/// encrypted to that party's `q-onion-key`; layout is `put_one(to) ‖ put_one(refund)`.
/// Consensus-opaque (stored verbatim in the escrow vertex).
pub fn build_escrow_memo(
    to_kem_pk: &[u8],
    refund_kem_pk: &[u8],
    amount: u128,
    escrow_r: &PolyVec,
) -> Result<Vec<u8>> {
    let half = |kem_pk: &[u8]| -> Result<Vec<u8>> {
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(kem_pk)
            .map_err(|e| QuilError::Internal(format!("escrow memo encapsulate: {e:?}")))?;
        Ok(build_output_memo(&kem_ct, amount, escrow_r, &ss))
    };
    let mut out = Vec::new();
    put_one(&mut out, &half(to_kem_pk)?);
    put_one(&mut out, &half(refund_kem_pk)?);
    Ok(out)
}

/// Recover `(amount, escrow_r)` from a [`build_escrow_memo`] blob using this
/// wallet's KEM secret + the escrow's committed `cv`. Tries both halves; returns
/// the first that decapsulates and opens (i.e. the half addressed to this wallet).
pub fn open_escrow_memo(
    np: &NetworkParams,
    kem_sk: &[u8],
    escrow_cv: &[u8],
    memo: &[u8],
) -> Option<(u128, PolyVec)> {
    let mut p = 0usize;
    for _ in 0..2 {
        let half = take_one(memo, &mut p).ok()?;
        if let Ok((kem_ct, ring_memo)) = split_output_memo(&half) {
            if let Ok(ss) = quil_crypto::sntrup761::decapsulate(&kem_ct, kem_sk) {
                if let Some(v) = open_ring_memo(np, &ss, escrow_cv, &ring_memo) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Split a memo blob built by [`build_output_memo`] into
/// `(kem_ciphertext, ring_memo)`.
pub fn split_output_memo(memo: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut p = 0usize;
    let kem = take_one(memo, &mut p)?;
    let ring = take_one(memo, &mut p)?;
    Ok((kem, ring))
}

// ---------------------------------------------------------------------------
// Consensus-opaque field size bounds (griefing / state-bloat hardening #5).
//
// Memos and recipient-key fields are NOT interpreted by verify — they are
// stored VERBATIM in the coin/escrow vertex that every node persists forever.
// The transaction fee is per-transaction (fixed), not per-byte, so without a
// size bound one cheap tx (or escrow-create) can force the whole network to
// store an arbitrarily large blob. These caps are far above any honest memo
// (a real output memo = kem_ct ~1KB ‖ ring_memo, a few KB; an escrow memo is
// two such halves) so they never reject a legitimate transaction, but they
// bound the state a single fee buys. A violation is an `InvalidArgument` →
// deterministic skip on every replica (never `Store`/`Io`), so it can't halt
// the shard or diverge state.
// ---------------------------------------------------------------------------

/// Max bytes for a single consensus-opaque per-output/coin memo blob.
pub const MAX_MEMO_BYTES: usize = 64 * 1024;
/// Max bytes for the escrow memo (structurally two [`build_output_memo`]
/// halves — one for `to`, one for `refund`).
pub const MAX_ESCROW_MEMO_BYTES: usize = 2 * MAX_MEMO_BYTES;
/// Max bytes for a consensus-opaque recipient key field (Falcon-512 pubkey =
/// 897 B; generous headroom).
pub const MAX_RECIPIENT_KEY_BYTES: usize = 4 * 1024;
/// Max bytes for a consensus-opaque one-time key (`P`, a wire-encoded PolyVec)
/// stored verbatim in the coin vertex. The canonical encoding at production
/// params is 12316 B (a_otk rows=6, ring degree D=256, u64 coeffs) — measured,
/// stable across ring sizes; this cap is ~2.6× that for safe headroom while
/// still bounding the state a single fixed-fee output can force every node to
/// store. (If the coin ring dimensions ever change, re-measure and revisit.)
pub const MAX_OTK_BYTES: usize = 32 * 1024;

/// Reject a single memo blob that exceeds [`MAX_MEMO_BYTES`].
pub fn check_memo_size(memo: &[u8]) -> Result<()> {
    if memo.len() > MAX_MEMO_BYTES {
        return Err(QuilError::InvalidArgument(format!(
            "lattice-ct: memo too large ({} > {} bytes)",
            memo.len(),
            MAX_MEMO_BYTES,
        )));
    }
    Ok(())
}

/// Reject any memo in a per-output memo list that exceeds [`MAX_MEMO_BYTES`].
pub fn check_memos_size(memos: &[Vec<u8>]) -> Result<()> {
    for m in memos {
        check_memo_size(m)?;
    }
    Ok(())
}

/// Reject an escrow memo that exceeds [`MAX_ESCROW_MEMO_BYTES`].
pub fn check_escrow_memo_size(memo: &[u8]) -> Result<()> {
    if memo.len() > MAX_ESCROW_MEMO_BYTES {
        return Err(QuilError::InvalidArgument(format!(
            "lattice-ct: escrow memo too large ({} > {} bytes)",
            memo.len(),
            MAX_ESCROW_MEMO_BYTES,
        )));
    }
    Ok(())
}

/// Reject a consensus-opaque recipient key that exceeds
/// [`MAX_RECIPIENT_KEY_BYTES`].
pub fn check_recipient_key_size(key: &[u8]) -> Result<()> {
    if key.len() > MAX_RECIPIENT_KEY_BYTES {
        return Err(QuilError::InvalidArgument(format!(
            "lattice-ct: recipient key too large ({} > {} bytes)",
            key.len(),
            MAX_RECIPIENT_KEY_BYTES,
        )));
    }
    Ok(())
}

/// Reject a one-time key blob that exceeds [`MAX_OTK_BYTES`].
pub fn check_otk_size(otk: &[u8]) -> Result<()> {
    if otk.len() > MAX_OTK_BYTES {
        return Err(QuilError::InvalidArgument(format!(
            "lattice-ct: one-time key too large ({} > {} bytes)",
            otk.len(),
            MAX_OTK_BYTES,
        )));
    }
    Ok(())
}

/// Reject any one-time key in a per-output list that exceeds [`MAX_OTK_BYTES`].
pub fn check_otks_size(otks: &[Vec<u8>]) -> Result<()> {
    for k in otks {
        check_otk_size(k)?;
    }
    Ok(())
}

fn put_one(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}
fn take_one(b: &[u8], p: &mut usize) -> Result<Vec<u8>> {
    let len = take_u32(b, p)?;
    let e = *p + len;
    let s = b.get(*p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
    *p = e;
    Ok(s.to_vec())
}
fn take_u128(b: &[u8], p: &mut usize) -> Result<u128> {
    let e = *p + 16;
    let s = b.get(*p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
    *p = e;
    Ok(u128::from_le_bytes(s.try_into().unwrap()))
}

fn put_vecs(out: &mut Vec<u8>, v: &[Vec<u8>]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for x in v {
        out.extend_from_slice(&(x.len() as u32).to_le_bytes());
        out.extend_from_slice(x);
    }
}
fn take_u32(b: &[u8], p: &mut usize) -> Result<usize> {
    let e = *p + 4;
    let s = b.get(*p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
    *p = e;
    Ok(u32::from_le_bytes(s.try_into().unwrap()) as usize)
}
fn take_vecs(b: &[u8], p: &mut usize) -> Result<Vec<Vec<u8>>> {
    let n = take_u32(b, p)?;
    // Cap the pre-allocation against remaining bytes (each entry is a 4-byte
    // length prefix + data) so an attacker-chosen count can't drive a multi-GB
    // `Vec::with_capacity` → OOM/abort before the per-entry read runs. Hint only:
    // the loop still bounds-checks each real entry, so legit envelopes are never
    // rejected.
    let mut v = Vec::with_capacity(n.min(b.len().saturating_sub(*p) / 4));
    for _ in 0..n {
        let len = take_u32(b, p)?;
        let e = *p + len;
        let s = b.get(*p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
        v.push(s.to_vec());
        *p = e;
    }
    Ok(v)
}

/// Encode a [`TxEnvelope`] to the canonical wire bytes.
pub fn encode_tx_envelope(e: &TxEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    put_vecs(&mut out, &e.input_spend_proofs);
    put_vecs(&mut out, &e.output_commitments);
    put_vecs(&mut out, &e.output_range_proofs);
    put_vecs(&mut out, &e.output_otks);
    put_vecs(&mut out, &e.output_memos);
    out.extend_from_slice(&(e.balance_proof.len() as u32).to_le_bytes());
    out.extend_from_slice(&e.balance_proof);
    out.extend_from_slice(&e.fee.to_le_bytes());
    out
}
/// Decode a [`TxEnvelope`].
pub fn decode_tx_envelope(b: &[u8]) -> Result<TxEnvelope> {
    let mut p = 0usize;
    let input_spend_proofs = take_vecs(b, &mut p)?;
    let output_commitments = take_vecs(b, &mut p)?;
    let output_range_proofs = take_vecs(b, &mut p)?;
    let output_otks = take_vecs(b, &mut p)?;
    let output_memos = take_vecs(b, &mut p)?;
    let bl = take_u32(b, &mut p)?;
    let be = p + bl;
    let balance_proof =
        b.get(p..be).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?.to_vec();
    p = be;
    let fe = p + 16;
    let fee = u128::from_le_bytes(
        b.get(p..fe).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?.try_into().unwrap(),
    );
    Ok(TxEnvelope {
        input_spend_proofs,
        output_commitments,
        output_range_proofs,
        output_otks,
        output_memos,
        balance_proof,
        fee,
    })
}

/// Encode a built transaction as a complete engine message: the 4-byte
/// [`TYPE_LATTICE_TRANSACTION`] prefix followed by the [`TxEnvelope`]. This is
/// exactly what a wallet submits; the token engine's dispatch reads the prefix
/// and hands the remainder to [`verify_envelope_and_derive_coins`].
pub fn encode_lattice_transaction_message(tx: &BuiltTransaction) -> Vec<u8> {
    let mut msg = TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec();
    msg.extend_from_slice(&encode_tx_envelope(&TxEnvelope::from_built(tx)));
    msg
}

/// A mint transaction on the wire: the PoMW inputs (reward claims) + the
/// confidential outputs. `output_otks` carries each recipient's `P`; `cv` is
/// recomputed by the engine.
pub struct MintEnvelope {
    /// The frame whose reward tree the PoMW proofs are against (reward-root source).
    pub cited_frame: u64,
    pub inputs: Vec<LatticeMintInput>,
    pub output_commitments: Vec<Vec<u8>>,
    pub output_range_proofs: Vec<Vec<u8>>,
    pub output_otks: Vec<Vec<u8>>,
    pub balance_proof: Vec<u8>,
    /// Per-output memo (`kem_ciphertext ‖ ring_memo`) so each minted coin is
    /// scannable + spendable. Consensus-opaque (verify ignores it; materialize
    /// stores it). Empty ⇒ no memo (the minted coin is then unscannable).
    pub output_memos: Vec<Vec<u8>>,
}

/// Encode a [`MintEnvelope`] to canonical wire bytes.
pub fn encode_mint_envelope(e: &MintEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&e.cited_frame.to_le_bytes());
    out.extend_from_slice(&(e.inputs.len() as u32).to_le_bytes());
    for i in &e.inputs {
        out.extend_from_slice(&i.value.to_le_bytes());
        put_one(&mut out, &i.owner_prover_address);
        put_one(&mut out, &i.falcon_pubkey);
        put_one(&mut out, &i.falcon_sig);
        put_one(&mut out, &i.forest_proof);
    }
    put_vecs(&mut out, &e.output_commitments);
    put_vecs(&mut out, &e.output_range_proofs);
    put_vecs(&mut out, &e.output_otks);
    put_one(&mut out, &e.balance_proof);
    put_vecs(&mut out, &e.output_memos);
    out
}
/// Decode a [`MintEnvelope`].
pub fn decode_mint_envelope(b: &[u8]) -> Result<MintEnvelope> {
    let mut p = 0usize;
    let cited_frame = {
        let e = p + 8;
        let s = b.get(p..e).ok_or_else(|| QuilError::InvalidArgument("lattice-ct: envelope eof".into()))?;
        p = e;
        u64::from_le_bytes(s.try_into().unwrap())
    };
    let n = take_u32(b, &mut p)?;
    // Cap pre-allocation vs remaining bytes (each input has a u128 value +
    // length-prefixed fields, ≥16 bytes) — attacker-count alloc-bomb guard.
    let mut inputs = Vec::with_capacity(n.min(b.len().saturating_sub(p) / 16));
    for _ in 0..n {
        inputs.push(LatticeMintInput {
            value: take_u128(b, &mut p)?,
            owner_prover_address: take_one(b, &mut p)?,
            falcon_pubkey: take_one(b, &mut p)?,
            falcon_sig: take_one(b, &mut p)?,
            forest_proof: take_one(b, &mut p)?,
        });
    }
    let output_commitments = take_vecs(b, &mut p)?;
    let output_range_proofs = take_vecs(b, &mut p)?;
    let output_otks = take_vecs(b, &mut p)?;
    let balance_proof = take_one(b, &mut p)?;
    // `output_memos` was appended after the initial format; tolerate its absence.
    let output_memos = take_vecs(b, &mut p).unwrap_or_default();
    Ok(MintEnvelope {
        cited_frame,
        inputs,
        output_commitments,
        output_range_proofs,
        output_otks,
        balance_proof,
        output_memos,
    })
}

/// Verify a mint envelope against the resolved `reward_root` AND derive what the
/// engine materializes: the new `(P, cv)` output coins and the per-owner reward
/// decrements `(owner_address, minted_value)`. `Ok(None)` if any check fails.
#[allow(clippy::type_complexity)]
pub fn verify_mint_envelope_and_derive(
    np: &NetworkParams,
    reward_root: &[u8; 32],
    domain: &[u8],
    env: &MintEnvelope,
) -> Result<Option<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, u128)>)>> {
    if env.output_otks.len() != env.output_commitments.len() {
        return Ok(None);
    }
    if verify_lattice_pomw_mint(
        np,
        reward_root,
        domain,
        &env.inputs,
        &env.output_commitments,
        &env.output_range_proofs,
        &env.balance_proof,
    )?
    .is_none()
    {
        return Ok(None);
    }
    // Derive output coins (P, cv=H_B(C_out)) and the reward decrements.
    let vlink = np.value_link_params();
    let mut new_coins = Vec::with_capacity(env.output_commitments.len());
    for (cb, p) in env.output_commitments.iter().zip(&env.output_otks) {
        let c = decode_commit(cb)?;
        new_coins.push((p.clone(), wire::encode_polyvec(&vlink.compress(&c))));
    }
    let decrements: Vec<(Vec<u8>, u128)> =
        env.inputs.iter().map(|i| (i.owner_prover_address.clone(), i.value)).collect();
    Ok(Some((new_coins, decrements)))
}

/// Apply the reward-balance decrements from a verified mint: for each `(owner,
/// value)`, subtract `value` from the owner's on-chain reward balance and write it
/// back. **Essential for soundness** — without it a prover could re-mint the same
/// reward (a fresh forest proof re-passes the unchanged `Balance == value` check).
/// Rejects if any balance is insufficient. Mirrors the decaf `materialize_pomw`
/// accounting (plain BigInt; no crypto).
pub fn apply_reward_decrements(
    state: &HypergraphState,
    tx_domain: &[u8],
    frame_number: u64,
    decrements: &[(Vec<u8>, u128)],
    is_quil: bool,
) -> Result<()> {
    use num_bigint::{BigInt, Sign};
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    for (owner, value) in decrements {
        let (reward_domain, reward_addr): (Vec<u8>, [u8; 32]) = if is_quil {
            (
                crate::domains::GLOBAL.to_vec(),
                crate::global_intrinsic::materialize::reward_address(owner)?,
            )
        } else {
            if owner.len() != 32 {
                return Err(QuilError::InvalidArgument("mint: non-QUIL owner must be 32 bytes".into()));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(owner);
            (tx_domain.to_vec(), a)
        };
        let blob = state
            .get(&reward_domain, &reward_addr, &va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument("mint: reward vertex not found".into()))?;
        let mut tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let bal = crate::global_intrinsic::materialize::read_reward_balance(&tree);
        let current = if bal.is_empty() { BigInt::from(0) } else { BigInt::from_bytes_be(Sign::Plus, &bal) };
        let dec = BigInt::from(*value);
        if current < dec {
            return Err(QuilError::InvalidArgument("mint: insufficient prover reward balance".into()));
        }
        let (_, trimmed) = (&current - &dec).to_bytes_be();
        let mut padded = vec![0u8; 32];
        if !trimmed.is_empty() {
            let start = 32usize.saturating_sub(trimmed.len());
            padded[start..].copy_from_slice(&trimmed);
        }
        crate::global_intrinsic::materialize::set_reward_balance(&mut tree, &padded)?;
        let new_blob = crate::prover_registry::vertex_tree_to_blob(&tree);
        state.set(&reward_domain, &reward_addr, &va_disc, frame_number, new_blob)?;
    }
    Ok(())
}

/// Verify a confidential transaction from its wire envelope AND derive the new
/// coins to materialize. Returns `Ok(Some((key_images, new_coins)))` where
/// `new_coins[i] = (P_i, cv_i = H_B(C_out_i))` — the coin-vertex fields the caller
/// writes and the shadow tree inserts. `Ok(None)` if any check fails.
///
/// DoS GUARD: the lattice arithmetic asserts on module-dimension mismatches
/// (e.g. a decoded polyvec of the wrong rank hitting `matvec`'s `assert_eq!`), so
/// an adversarial proof could otherwise PANIC the verifying node at block
/// execution → consensus halt. Verification is read-only on `state`, so a caught
/// panic simply rejects the transaction (never a halt, never a state change).
/// `AssertUnwindSafe` is sound here for that reason.
pub fn verify_envelope_and_derive_coins(
    np: &NetworkParams,
    state: &HypergraphState,
    domain: &[u8],
    env: &TxEnvelope,
    include_fee: bool,
) -> Result<Option<(Vec<Vec<u8>>, Vec<(Vec<u8>, Vec<u8>)>)>> {
    guard_verify(|| verify_envelope_and_derive_coins_inner(np, state, domain, env, include_fee))
}

/// Run a lattice verifier under a panic guard. The lattice arithmetic asserts on
/// module-dimension mismatches (e.g. a decoded polyvec of the wrong rank hitting
/// `matvec`'s `assert_eq!`), so an adversarial mint/escrow/shield proof could
/// otherwise PANIC the block-executing thread → consensus halt. The verifiers are
/// read-only on `state`, so a caught panic simply rejects the message (never a
/// halt, never a state change) — `AssertUnwindSafe` is sound for that reason.
/// Use this to wrap EVERY lattice-CT verify entry point called from the engine.
pub fn guard_verify<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        Err(QuilError::InvalidArgument(
            "lattice-ct: verifier panicked on malformed proof (rejected)".into(),
        ))
    })
}

fn verify_envelope_and_derive_coins_inner(
    np: &NetworkParams,
    state: &HypergraphState,
    domain: &[u8],
    env: &TxEnvelope,
    include_fee: bool,
) -> Result<Option<(Vec<Vec<u8>>, Vec<(Vec<u8>, Vec<u8>)>)>> {
    if env.output_otks.len() != env.output_commitments.len() {
        return Ok(None);
    }
    // The spends are bound to this derived challenge (same as the wallet computed).
    let mu = tx_challenge(domain, &env.output_commitments, env.fee);
    let key_images = match verify_lattice_transaction(
        np,
        state,
        domain,
        &env.input_spend_proofs,
        &env.output_commitments,
        &env.output_range_proofs,
        &env.balance_proof,
        env.fee,
        include_fee,
        &mu,
    )? {
        Some(k) => k,
        None => return Ok(None),
    };
    // Derive each output coin's (P, cv): cv = H_B(C_out), computed by us.
    let vlink = np.value_link_params();
    let mut new_coins = Vec::with_capacity(env.output_commitments.len());
    for (cb, p) in env.output_commitments.iter().zip(&env.output_otks) {
        let c = decode_commit(cb)?;
        let cv = vlink.compress(&c);
        new_coins.push((p.clone(), wire::encode_polyvec(&cv)));
    }
    Ok(Some((key_images, new_coins)))
}

// =====================================================================
// Transaction-level verify — the complete lattice confidential-tx check
// =====================================================================

/// Verify a full confidential transaction against committed state: every input's
/// spend proof (against the token's committed accumulator root), no double-spend
/// (key images unrecorded + unique within the tx), and balance
/// `Σ inputs = Σ outputs + fee` over the revealed pseudo-inputs `C'`.
///
/// Returns `Ok(Some(key_images))` — the nullifiers the caller records at
/// materialize — on success, or `Ok(None)` if any check fails. `mu` is the
/// transaction challenge the spend proofs are bound to.
#[allow(clippy::too_many_arguments)]
pub fn verify_lattice_transaction(
    np: &NetworkParams,
    state: &HypergraphState,
    domain: &[u8],
    input_spend_proofs: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    output_range_proofs: &[Vec<u8>],
    balance_proof: &[u8],
    fee: u128,
    include_fee: bool,
    mu: &[u8],
) -> Result<Option<Vec<Vec<u8>>>> {
    // Every confidential transaction MUST carry either the coefficient-packed per-limb
    // ranges OR the full-width (fw) amortized marker; the non-packed `range_rq` format
    // is not accepted. A tx with neither tag is rejected here.
    if !super::packed_range::is_packed_output_ranges(output_range_proofs)
        && !super::packed_range::is_fw_output_ranges(output_range_proofs)
    {
        return Ok(None);
    }
    // The token's committed coin-set root (+ its log-growing depth).
    let (depth, root) = match shadow_accumulator::read_root(state, domain)? {
        Some(dr) => dr,
        None => return Ok(None), // no coin set committed yet ⇒ nothing spendable
    };

    let mut key_images: Vec<Vec<u8>> = Vec::with_capacity(input_spend_proofs.len());
    let mut c_primes: Vec<Vec<u8>> = Vec::with_capacity(input_spend_proofs.len());
    for sp in input_spend_proofs {
        let (ki, cp) = match verify_spend_proof(np, &root, sp, mu, depth)? {
            Some(x) => x,
            None => return Ok(None), // invalid spend proof
        };
        // Double-spend: reject a key image already recorded on-chain OR repeated
        // within this transaction.
        if key_images.contains(&ki) {
            return Ok(None);
        }
        if !spent_check::check_key_image_not_spent(state, domain, &ki)? {
            return Ok(None);
        }
        key_images.push(ki);
        c_primes.push(cp);
    }

    // FULL-WIDTH amortized path: ONE IPA proof (in `balance_proof`) covers the output
    // ranges AND the carry-chain balance, with each input's value PINNED to its spend
    // `c_prime` (the fw↔c_prime value-link inside the proof). Outputs ARE fw coins.
    if super::packed_range::is_fw_output_ranges(output_range_proofs) {
        let out_coins: std::result::Result<Vec<RingCommitment>, _> =
            output_commitments.iter().map(|b| decode_commit(b)).collect();
        let c_prime_c: std::result::Result<Vec<RingCommitment>, _> =
            c_primes.iter().map(|b| decode_commit(b)).collect();
        let eff_fee = if include_fee { fee } else { 0 };
        if !super::packed_range::verify_fw_transfer(&np.value_key(), &out_coins?, &c_prime_c?, eff_fee, &decode_fw_proof(balance_proof)?)? {
            return Ok(None);
        }
        return Ok(Some(key_images));
    }

    // PACKED-RANGE path: when `output_range_proofs` carry the coefficient-packed
    // per-limb ranges (tag `RANGE_V_PACKED_LIMBS`), the coin format, spend proofs
    // and carry-chain balance stay LIMB (unchanged); only the OUTPUT range proofs
    // are packed (each limb range-proved + value-linked to its commitment slice).
    // The balance still binds the real values; packed ranges prove non-negativity.
    if super::packed_range::is_packed_output_ranges(output_range_proofs) {
        let out_c: std::result::Result<Vec<RingCommitment>, _> =
            output_commitments.iter().map(|b| decode_commit(b)).collect();
        let out_c = out_c?;
        let limb_vkey = np.limb_range_key().value_key();
        if !super::packed_range::verify_packed_output_ranges(
            np.packed_key(),
            &limb_vkey,
            &out_c,
            output_range_proofs,
            quil_lattice_ct::limb_balance::RANGE_BITS,
        )? {
            return Ok(None);
        }
        // Balance-only limb carry chain — range_free, since the packed per-limb
        // ranges above already prove output non-negativity (no redundant range_rq).
        if !verify_transaction_crypto_ext(np, &c_primes, output_commitments, balance_proof, fee, include_fee, true)? {
            return Ok(None);
        }
        return Ok(Some(key_images));
    }

    // Otherwise: full-width limb balance with legacy range_rq folded in.
    let _ = output_range_proofs;
    if !verify_transaction_crypto(np, &c_primes, output_commitments, balance_proof, fee, include_fee)? {
        return Ok(None);
    }
    Ok(Some(key_images))
}

// =====================================================================
// Full-width balance: 64/128-bit amounts via limb + carry chain
// =====================================================================

/// Verify a full-width confidential balance `Σ inputs = Σ outputs + fee` where
/// amounts are 64/128-bit, encoded as `n_limbs` base-`2^8` limbs. Each output
/// limb is range-proved (non-negative ⇒ no inflation) and balance holds per limb
/// with an explicit carry chain — every value stays `< q`, so no overflow-mint.
///
/// `in_c[i]` / `out_c[i]` are the per-limb value commitments of amount `i`
/// (`n_limbs` each), wire-encoded. This is the sound replacement for the
/// bounded single-coefficient [`verify_transaction_crypto`].
pub fn verify_transaction_balance_fullwidth(
    np: &NetworkParams,
    in_c: &[Vec<Vec<u8>>],
    out_c: &[Vec<Vec<u8>>],
    balance_proof: &[u8],
    fee: u128,
    n_limbs: usize,
) -> Result<bool> {
    let decode_rows = |rows: &[Vec<Vec<u8>>]| -> Result<Vec<Vec<RingCommitment>>> {
        rows.iter()
            .map(|row| row.iter().map(|b| decode_commit(b)).collect::<Result<Vec<_>>>())
            .collect()
    };
    let in_dec = decode_rows(in_c)?;
    let out_dec = decode_rows(out_c)?;
    let pf: LimbBalanceProof = wire::decode_limb_balance(balance_proof).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: limb-balance decode: {e:?}"))
    })?;
    Ok(verify_limb_balance(np.limb_range_key(), &in_dec, &out_dec, fee, n_limbs, &pf))
}

// =====================================================================
// Spend authority (linkable ring signature) + key image
// =====================================================================

/// Verify one input's linkable ring signature against the transaction
/// `challenge` (which the signature is bound to). On success returns the
/// wire-encoded **key image** — the double-spend nullifier the caller records /
/// checks for uniqueness. Returns `Ok(None)` when the signature is invalid.
pub fn verify_input_signature(
    np: &NetworkParams,
    ring_pubkeys: &[Vec<u8>],
    signature: &[u8],
    challenge: &[u8],
) -> Result<Option<Vec<u8>>> {
    if ring_pubkeys.is_empty() {
        return Err(QuilError::InvalidArgument("lattice-ct: empty ring".into()));
    }
    let mut ring = Vec::with_capacity(ring_pubkeys.len());
    for pk in ring_pubkeys {
        ring.push(wire::decode_polyvec(pk).map_err(|e| {
            QuilError::InvalidArgument(format!("lattice-ct: ring pubkey decode: {e:?}"))
        })?);
    }
    let key = np.sig_key(ring.len());
    let sig = wire::decode_ring_sig(signature).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: ring signature decode: {e:?}"))
    })?;
    if ring_verify(&key, &ring, &sig, challenge) {
        Ok(Some(wire::encode_polyvec(&sig.tag)))
    } else {
        Ok(None)
    }
}

// =====================================================================
// Spend authority (accumulator membership) — whole-set anonymity + key image
// =====================================================================

/// Verify one input's **accumulator-membership** spend proof against the current
/// coin-set `root` (a wire-encoded [`quil_lattice_ct::accumulator::Node`]), bound
/// to the transaction `mu` (challenge). This is the whole-set-anonymity spend
/// (Lelantus/Spark-style): the spender proves their coin is *somewhere* in the
/// entire coin set without a decoy ring. Returns the wire-encoded **key image**
/// (double-spend nullifier) on success, `Ok(None)` if the proof is invalid.
///
/// `depth` is the accumulator depth (must match the node's SIS shadow tree).
pub fn verify_input_membership(
    np: &NetworkParams,
    root: &[u8],
    proof: &[u8],
    mu: &[u8],
    depth: usize,
) -> Result<Option<Vec<u8>>> {
    let root_node = wire::decode_polyvec(root).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: accumulator root decode: {e:?}"))
    })?;
    let pf = wire::decode_membership(proof).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: membership proof decode: {e:?}"))
    })?;
    let mp = np.membership_params(depth);
    match verify_membership(&mp, &root_node, &pf, mu) {
        Some(key_image) => Ok(Some(wire::encode_polyvec(&key_image))),
        None => Ok(None),
    }
}

/// Verify a **full spend proof** (membership ⊕ value-link, folded) against the
/// coin-set `root`, bound to the transaction `mu`. This is the complete
/// anonymous-spend check: it proves the coin is in the set (hiding which),
/// yields the double-spend **key image**, and exposes the re-randomized value
/// commitment **`C'`** that enters the balance — without revealing the coin.
///
/// Returns `Ok(Some((key_image, c_prime)))` on success (both wire-encoded),
/// `Ok(None)` if the proof is invalid. `depth` must match the shadow tree.
pub fn verify_spend_proof(
    np: &NetworkParams,
    root: &[u8],
    proof: &[u8],
    mu: &[u8],
    depth: usize,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let root_node = wire::decode_polyvec(root).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: accumulator root decode: {e:?}"))
    })?;
    let pf = wire::decode_spend(proof).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: spend proof decode: {e:?}"))
    })?;
    let mp = np.membership_params(depth);
    let vlink = np.value_link_params();
    match verify_spend(&mp, &vlink, &root_node, &pf, mu) {
        Some(key_image) => {
            Ok(Some((wire::encode_polyvec(&key_image), wire::encode_commitment(&pf.c_prime))))
        }
        None => Ok(None),
    }
}

// =====================================================================
// Pseudo-output binding: tie a declared input amount to the real coin
// =====================================================================

/// Σ-params for the commitment-equality opening: the witness is the randomness
/// difference `r_real − r_pseudo`, whose norm is `≤ 2η`.
fn equality_params() -> RingSigmaParams {
    RingSigmaParams { mask_bound: MASK_BOUND, eta: 2 * ETA, tau: quil_lattice_ct::params::CHALLENGE_WEIGHT_TAU }
}

/// Verify that `c_pseudo` (the input's balance commitment) commits the **same
/// amount** as the real on-chain coin `c_real`: the difference `c_real −
/// c_pseudo` opens to message 0 with a short randomness difference. This is the
/// RingCT pseudo-output step — without it a spender could declare a false input
/// amount in the balance and inflate. Returns Ok(true) iff the amounts match.
pub fn verify_pseudo_output_binding(
    np: &NetworkParams,
    c_real: &[u8],
    c_pseudo: &[u8],
    proof: &[u8],
) -> Result<bool> {
    let cr = decode_commit(c_real)?;
    let cp = decode_commit(c_pseudo)?;
    let diff = RingCommitment { t1: cr.t1.sub(&cp.t1), t2: cr.t2.sub(&cp.t2) };
    let pf = wire::decode_opening(proof).map_err(|e| {
        QuilError::InvalidArgument(format!("lattice-ct: equality proof decode: {e:?}"))
    })?;
    let vkey = np.value_key();
    Ok(verify_ring_opening(&vkey.stacked_matrix(), &diff.stacked(), &pf, &equality_params(), b""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::sigma_rq::prove_ring_opening;
    use quil_lattice_ct::arith::SplitMix64;
    use quil_lattice_ct::linear_rq::prove_linear_rq;
    use quil_lattice_ct::range_rq::prove_range_rq;
    use quil_lattice_ct::ring_rq::sign as ring_sign;

    #[test]
    fn ring_memo_round_trips_and_binds_to_cv() {
        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let mut prg = SplitMix64::new(0x9E);
        let amount = 12_345u128;
        let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let cv = wire::encode_polyvec(&vlink.compress(&super::commit_amount(&vkey, amount, &r_out)));
        let ss = [0x42u8; 32];

        let memo = encrypt_ring_memo(&ss, amount, &r_out);
        // Correct ss recovers (amount, r_out) and binds to cv.
        let (a, r) = open_ring_memo(&np, &ss, &cv, &memo).expect("open");
        assert_eq!(a, amount);
        assert_eq!(wire::encode_polyvec(&r), wire::encode_polyvec(&r_out));
        // Wrong ss ⇒ garbage r_out ⇒ cv mismatch ⇒ None.
        assert!(open_ring_memo(&np, &[0u8; 32], &cv, &memo).is_none());
        // Right ss but wrong coin cv ⇒ None (memo bound to its coin).
        let bad_cv = wire::encode_polyvec(&PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg));
        assert!(open_ring_memo(&np, &ss, &bad_cv, &memo).is_none());
    }

    /// The whole wallet pipeline: a sender creates a coin addressed to the
    /// wallet (ring-stealth OTK + ring-memo), the wallet SCANS committed state
    /// to find + open it (recovering sk/amount/r_coin), fetches its accumulator
    /// witness, builds a spend, and the engine verifies it. Ties together every
    /// piece added for the token-infra track.
    /// End-to-end confidential spend: a sender creates a coin addressed to the
    /// wallet (ring-stealth OTK + ring-memo), the wallet SCANS committed state
    /// to find + open it (recovering sk/amount/r_coin), fetches its accumulator
    /// witness, builds a spend, and the engine verifies it. Exercises every
    /// piece of the token-infra track together.
    #[test]
    fn full_wallet_scan_recover_and_spend_end_to_end() {
        use super::super::materialize::{coin_type_hash, create_lattice_coin_vertex_tree};
        use super::super::shadow_accumulator;
        use crate::hypergraph_state::HypergraphState;
        use quil_types::store::HypergraphStore;
        use quil_lattice_ct::membership::MembershipParams;
        use quil_lattice_ct::accumulator::ACC_NODE_RANK;
        use quil_lattice_ct::stealth::{
            hash_to_short_polyvec, one_time_pubkey_ring, one_time_secret_ring, owns_ring,
        };
        use quil_lattice_ct::wire;
        use std::sync::Arc;

        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let mp = MembershipParams::production(1);
        let a_otk = &mp.a_otk;
        let cols = a_otk.cols;

        // Wallet long-term keys: lattice spend base (b, B) + sntrup761 KEM.
        let mut prg = SplitMix64::new(0xC0FFEE);
        // The wallet's long-term spend base uses eta=1 so the stealth one-time
        // secret `sk = offset(±1) + b(±1)` stays within the membership norm
        // bound ETA=2 (a wallet-side constraint for spendable stealth coins).
        let b = PolyVec::sample_short(cols, 1, &mut prg);
        let big_b = a_otk.matvec(&b);
        let kem = quil_crypto::sntrup761::Sntrup761KeyPair::generate();

        // ── Sender creates a coin worth 100 addressed to the wallet ──
        let amount = 100u128;
        let r_coin = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let cv = wire::encode_polyvec(&vlink.compress(&super::commit_amount(&vkey, amount, &r_coin)));
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&kem.public).unwrap();
        let offset = hash_to_short_polyvec(&ss, cols);
        let p = one_time_pubkey_ring(a_otk, &offset, &big_b);
        let p_bytes = wire::encode_polyvec(&p);
        let memo_blob = build_output_memo(&kem_ct, amount, &r_coin, &ss);

        // Materialize the coin (+ two decoys) into committed state.
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = quil_types::store::HypergraphStore::new_transaction(&*store, false).unwrap();
        let th = coin_type_hash(domain).unwrap();
        let shard = {
            use quil_hypergraph::addressing::{shard_key_for_location, Location};
            let mut app = [0u8; 32];
            app.copy_from_slice(domain);
            shard_key_for_location(&Location { app_address: app, data_address: [0u8; 32] })
        };
        let mut insert = |p_b: &[u8], cv_b: &[u8], memo: &[u8], tag: u8| {
            let tree = create_lattice_coin_vertex_tree(&[0, 0, 0, 1], p_b, cv_b, memo, &th).unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            let mut addr = quil_crypto::poseidon::hash_bytes_to_32(&blob).unwrap();
            addr[0] = tag; // keep addresses distinct + ordering deterministic
            let mut key = domain.to_vec();
            key.extend_from_slice(&addr);
            store
                .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob)
                .unwrap();
        };
        // Decoy coins: accumulator leaf nodes are ACC_NODE_RANK-dimensional.
        let decoy = |seed: u64, prg: &mut SplitMix64| {
            let _ = seed;
            wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, prg))
        };
        insert(&decoy(1, &mut prg), &decoy(2, &mut prg), &[], 0x01);
        insert(&p_bytes, &cv, &memo_blob, 0x02); // the wallet's coin
        insert(&decoy(3, &mut prg), &decoy(4, &mut prg), &[], 0x03);

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt);
        shadow_accumulator::refresh_root(&state, domain).unwrap();

        // ── Wallet scans committed state, finds + opens its coin ──
        let coins = shadow_accumulator::scan_domain_coins(&state, domain).unwrap();
        let mut recovered = None;
        for (_addr, p_i, cv_i, memo_i) in &coins {
            if memo_i.is_empty() {
                continue;
            }
            let (kem_ct_i, ring_memo_i) = split_output_memo(memo_i).unwrap();
            let ss_i = match quil_crypto::sntrup761::decapsulate(&kem_ct_i, &kem.secret) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let offset_i = hash_to_short_polyvec(&ss_i, cols);
            let p_dec = wire::decode_polyvec(p_i).unwrap();
            if owns_ring(a_otk, &offset_i, &big_b, &p_dec) {
                let (amt, r) = open_ring_memo(&np, &ss_i, cv_i, &ring_memo_i).unwrap();
                let sk = one_time_secret_ring(&offset_i, &b);
                assert_eq!(a_otk.matvec(&sk), p_dec, "recovered sk opens the coin's OTK");
                recovered = Some((p_i.clone(), sk, amt, r));
                break;
            }
        }
        let (my_p, sk, amt, r) = recovered.expect("wallet must find + open its own coin");
        assert_eq!(amt, amount);

        // ── Fetch the accumulator witness for the recovered coin ──
        let (depth, root, ws) =
            shadow_accumulator::coin_spend_witnesses(&state, domain, &[my_p.clone()]).unwrap();
        assert!(ws[0].found);

        // ── Build a spend (100 → 60 + 38 + fee 2) and verify through the engine ──
        let inputs = vec![SpendInput {
            sk,
            amount: amt,
            r_coin: r,
            leaf_index: ws[0].leaf_index as usize,
            auth_path: ws[0].auth_path.clone(),
        }];
        let outputs = vec![
            NewOutput { amount: 60, recipient_otk: wire::encode_polyvec(&PolyVec::sample_short(cols, ETA, &mut prg)) },
            NewOutput { amount: 38, recipient_otk: wire::encode_polyvec(&PolyVec::sample_short(cols, ETA, &mut prg)) },
        ];
        let tx = build_spend_transaction(&np, &root, depth, domain, &inputs, &outputs, 2, 7)
            .unwrap_or_else(|e| panic!("build_spend_transaction failed: {e}"));
        let env = TxEnvelope::from_built(&tx);
        // include_fee = true: this transfer carries a fee (Σin = Σout + fee).
        assert!(
            verify_envelope_and_derive_coins(&np, &state, domain, &env, true)
                .unwrap()
                .is_some(),
            "the scanned-and-rebuilt wallet spend verifies through the engine"
        );

    }

    #[test]
    fn open_ring_memo_scans_fw_coin() {
        // The wallet SCAN recovers (amount, r) for an fw coin (`value_key.commit(
        // bitpoly_msg(amount); r)`) — open_ring_memo recomputes the fw cv and matches.
        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let mut prg = SplitMix64::new(0x5CA4);
        let amount = 12_345u128;
        let r = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let coin = vkey.commit(&bitpoly_msg(amount), &r);
        let cv = wire::encode_polyvec(&vlink.compress(&coin));
        let ss = [7u8; 32];
        let memo = build_output_memo(b"kemct", amount, &r, &ss);
        let (_kem, ring_memo) = split_output_memo(&memo).unwrap();
        assert_eq!(
            open_ring_memo(&np, &ss, &cv, &ring_memo),
            Some((amount, r.clone())),
            "fw coin scans: recovers amount + randomness by recomputing the fw cv"
        );
        // A legacy (limb-value) coin with the same amount/r still scans (dual-format).
        let legacy = vkey.commit(&limbs_msg(amount), &r);
        let cv_legacy = wire::encode_polyvec(&vlink.compress(&legacy));
        assert!(open_ring_memo(&np, &ss, &cv_legacy, &ring_memo).is_some(), "legacy coin still scans");
    }

    #[test]
    fn fw_to_fw_spend_end_to_end() {
        // An fw coin (`value_key.commit(bit-polys; r)`) is
        // materialized into the accumulator, then SPENT via build_fw_spend_transaction
        // into fw output coins. The whole thing verifies through verify_lattice_transaction
        // — proving the (message-agnostic) membership relation spends fw coins with the
        // uniform fw money path. The coin is constructed directly (no memo/scan).
        use super::super::materialize::{coin_type_hash, create_lattice_coin_vertex_tree};
        use super::super::shadow_accumulator;
        use crate::hypergraph_state::HypergraphState;
        use quil_lattice_ct::accumulator::ACC_NODE_RANK;
        use quil_lattice_ct::membership::MembershipParams;
        use quil_lattice_ct::wire;
        use quil_types::store::HypergraphStore;
        use std::sync::Arc;

        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let mp = MembershipParams::production(1);
        let a_otk = &mp.a_otk;
        let cols = a_otk.cols;
        let mut prg = quil_lattice_ct::arith::SplitMix64::new(0xF00FEE);

        // Wallet spend key (eta=1 so the stealth secret stays within the membership bound).
        let sk = PolyVec::sample_short(cols, 1, &mut prg);
        // The fw coin: value_key.commit(bitpoly_msg(amount); r_coin).
        let amount = 100u128;
        let r_coin = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let coin_c = vkey.commit(&bitpoly_msg(amount), &r_coin);
        let cv = wire::encode_polyvec(&vlink.compress(&coin_c));
        let p = a_otk.matvec(&sk);
        let p_bytes = wire::encode_polyvec(&p);

        // Materialize the fw coin (+ decoys) into committed state.
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = quil_types::store::HypergraphStore::new_transaction(&*store, false).unwrap();
        let th = coin_type_hash(domain).unwrap();
        let shard = {
            use quil_hypergraph::addressing::{shard_key_for_location, Location};
            let mut app = [0u8; 32];
            app.copy_from_slice(domain);
            shard_key_for_location(&Location { app_address: app, data_address: [0u8; 32] })
        };
        let mut insert = |p_b: &[u8], cv_b: &[u8], tag: u8| {
            let tree = create_lattice_coin_vertex_tree(&[0, 0, 0, 1], p_b, cv_b, &[], &th).unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            let mut addr = quil_crypto::poseidon::hash_bytes_to_32(&blob).unwrap();
            addr[0] = tag;
            let mut key = domain.to_vec();
            key.extend_from_slice(&addr);
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob).unwrap();
        };
        let decoy = |prg: &mut quil_lattice_ct::arith::SplitMix64| wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, prg));
        insert(&decoy(&mut prg), &decoy(&mut prg), 0x01);
        insert(&p_bytes, &cv, 0x02);
        insert(&decoy(&mut prg), &decoy(&mut prg), 0x03);

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, Arc::new(quil_types::crypto::NoopInclusionProver)));
        let state = HypergraphState::new(crdt);
        shadow_accumulator::refresh_root(&state, domain).unwrap();

        // Fetch the accumulator witness for the fw coin.
        let (depth, root, ws) = shadow_accumulator::coin_spend_witnesses(&state, domain, &[p_bytes.clone()]).unwrap();
        assert!(ws[0].found, "fw coin found in accumulator");

        let inputs = vec![SpendInput {
            sk,
            amount,
            r_coin,
            leaf_index: ws[0].leaf_index as usize,
            auth_path: ws[0].auth_path.clone(),
        }];
        let outputs = vec![
            NewOutput { amount: 60, recipient_otk: wire::encode_polyvec(&PolyVec::sample_short(cols, ETA, &mut prg)) },
            NewOutput { amount: 38, recipient_otk: wire::encode_polyvec(&PolyVec::sample_short(cols, ETA, &mut prg)) },
        ];
        let fwtx = build_fw_spend_transaction(&np, &root, depth, domain, &inputs, &outputs, 2, 21)
            .unwrap_or_else(|e| panic!("build_fw_spend_transaction failed: {e}"));
        assert_eq!(fwtx.output_range_proofs, crate::token_intrinsic::packed_range::fw_output_ranges_marker());
        let fw_mu = tx_challenge(domain, &fwtx.output_commitments, 2);
        let kis = verify_lattice_transaction(
            &np, &state, domain, &fwtx.input_spend_proofs, &fwtx.output_commitments,
            &fwtx.output_range_proofs, &fwtx.balance_proof, 2, true, &fw_mu,
        )
        .unwrap();
        assert!(kis.is_some(), "fw→fw spend (fw coin → fw outputs) verifies through the engine");
    }

    #[test]
    fn escrow_create_scan_claim_end_to_end() {
        use super::super::materialize::{coin_type_hash, create_lattice_coin_vertex_tree};
        use super::super::shadow_accumulator;
        use crate::hypergraph_state::HypergraphState;
        use quil_crypto::FalconSigner;
        use quil_lattice_ct::accumulator::ACC_NODE_RANK;
        use quil_lattice_ct::membership::MembershipParams;
        use quil_lattice_ct::stealth::{
            hash_to_short_polyvec, one_time_pubkey_ring, one_time_secret_ring, owns_ring,
        };
        use quil_lattice_ct::wire;
        use quil_types::crypto::Signer;
        use quil_types::store::HypergraphStore;
        use std::sync::Arc;

        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let mp = MembershipParams::production(1);
        let a_otk = &mp.a_otk;
        let cols = a_otk.cols;

        // Two wallets: S (sender/refund) and R (recipient/to).
        let mut prg = SplitMix64::new(0xE5C204);
        let b_s = PolyVec::sample_short(cols, 1, &mut prg);
        let big_b_s = a_otk.matvec(&b_s);
        let kem_s = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let falcon_s = FalconSigner::generate();

        let b_r = PolyVec::sample_short(cols, 1, &mut prg);
        let big_b_r = a_otk.matvec(&b_r);
        let kem_r = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let falcon_r = FalconSigner::generate();

        // ── S owns a coin worth 100 (materialized into committed state) ──
        let src_amount = 100u128;
        let r_src = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let cv_src = wire::encode_polyvec(&vlink.compress(&super::commit_amount(&vkey, src_amount, &r_src)));
        let (ss_src, kem_ct_src) = quil_crypto::sntrup761::encapsulate(&kem_s.public).unwrap();
        let off_src = hash_to_short_polyvec(&ss_src, cols);
        let p_src = wire::encode_polyvec(&one_time_pubkey_ring(a_otk, &off_src, &big_b_s));
        let memo_src = build_output_memo(&kem_ct_src, src_amount, &r_src, &ss_src);

        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = quil_types::store::HypergraphStore::new_transaction(&*store, false).unwrap();
        let th = coin_type_hash(domain).unwrap();
        let shard = {
            use quil_hypergraph::addressing::{shard_key_for_location, Location};
            let mut app = [0u8; 32];
            app.copy_from_slice(domain);
            shard_key_for_location(&Location { app_address: app, data_address: [0u8; 32] })
        };
        let insert_coin = |p_b: &[u8], cv_b: &[u8], memo: &[u8], tag: u8| {
            let tree = create_lattice_coin_vertex_tree(&[0, 0, 0, 1], p_b, cv_b, memo, &th).unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            let mut addr = quil_crypto::poseidon::hash_bytes_to_32(&blob).unwrap();
            addr[0] = tag;
            let mut key = domain.to_vec();
            key.extend_from_slice(&addr);
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob).unwrap();
        };
        let decoy = |prg: &mut SplitMix64| wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, prg));
        insert_coin(&decoy(&mut prg), &decoy(&mut prg), &[], 0x01);
        insert_coin(&p_src, &cv_src, &memo_src, 0x02);

        // Insert a materialized vertex tree (escrow or coin) produced by materialize.
        let insert_tree = |addr: &[u8], tree: &quil_tries::VectorCommitmentTree| {
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            let mut key = domain.to_vec();
            key.extend_from_slice(addr);
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob).unwrap();
        };

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt);
        shadow_accumulator::refresh_root(&state, domain).unwrap();

        // S recovers its coin + fetches a spend witness.
        let sk_src = one_time_secret_ring(&off_src, &b_s);
        let (depth, root, ws) = shadow_accumulator::coin_spend_witnesses(&state, domain, &[p_src.clone()]).unwrap();
        assert!(ws[0].found);

        // ── S builds an escrow of 60 to R with 40 change back to S ──
        let escrow_amount = 60u128;
        let change_amount = src_amount - escrow_amount; // 40
        let inputs = vec![SpendInput {
            sk: sk_src,
            amount: src_amount,
            r_coin: r_src,
            leaf_index: ws[0].leaf_index as usize,
            auth_path: ws[0].auth_path.clone(),
        }];
        // Change output OTK back to S (+ its own memo so S can later spend it).
        let (ss_chg, kem_ct_chg) = quil_crypto::sntrup761::encapsulate(&kem_s.public).unwrap();
        let off_chg = hash_to_short_polyvec(&ss_chg, cols);
        let change_otk = wire::encode_polyvec(&one_time_pubkey_ring(a_otk, &off_chg, &big_b_s));
        let outputs = vec![
            NewOutput { amount: escrow_amount, recipient_otk: Vec::new() }, // escrow (index 0)
            NewOutput { amount: change_amount, recipient_otk: change_otk.clone() }, // change (index 1)
        ];
        let built = build_spend_transaction(&np, &root, depth, domain, &inputs, &outputs, 0, 11).unwrap();
        let escrow_r = wire::decode_polyvec(&built.output_rand[0]).unwrap();
        let change_r = wire::decode_polyvec(&built.output_rand[1]).unwrap();
        let escrow_memo = build_escrow_memo(&kem_r.public, &kem_s.public, escrow_amount, &escrow_r).unwrap();
        let change_memo = build_output_memo(&kem_ct_chg, change_amount, &change_r, &ss_chg);
        let create_env = PendingCreateEnvelope {
            input_spend_proofs: built.input_spend_proofs.clone(),
            escrow_commitment: built.output_commitments[0].clone(),
            escrow_range_proof: built.output_range_proofs[0].clone(),
            balance_proof: built.balance_proof.clone(),
            fee: 0,
            to_key: falcon_r.public_key().to_vec(),
            refund_key: falcon_s.public_key().to_vec(),
            expiration: 0,
            memo: escrow_memo,
            change_commitments: vec![built.output_commitments[1].clone()],
            change_otks: vec![change_otk],
            change_memos: vec![change_memo],
            change_range_proofs: vec![built.output_range_proofs[1].clone()],
        };

        // ── Materialize the escrow create (verify + write escrow + change coin) ──
        let (_ki, escrow_cv, change_coins) = verify_lattice_pending_create(
            &np, &state, domain,
            &create_env.input_spend_proofs, &create_env.escrow_commitment, &create_env.escrow_range_proof,
            &create_env.change_commitments, &create_env.change_otks, &create_env.change_range_proofs,
            &create_env.balance_proof, create_env.fee,
        )
        .unwrap()
        .expect("escrow create verifies");
        let frame = 5u64.to_be_bytes();
        let pend = super::super::materialize::materialize_lattice_pending(
            domain, &frame, &escrow_cv, &create_env.to_key, &create_env.refund_key,
            create_env.expiration, &create_env.memo, &[],
        )
        .unwrap();
        for (addr, tree) in &pend.coins {
            insert_tree(addr, tree);
        }
        let chg = super::super::materialize::materialize_lattice_transaction(
            domain, &frame, &change_coins, &[], &create_env.change_memos,
        )
        .unwrap();
        for (addr, tree) in &chg.coins {
            insert_tree(addr, tree);
        }
        shadow_accumulator::refresh_root(&state, domain).unwrap();

        // ── R scans escrows, finds it, opens the dual memo ──
        let escrows = shadow_accumulator::scan_domain_escrows(&state, domain).unwrap();
        let mine = escrows
            .iter()
            .find(|e| e.to_key == falcon_r.public_key())
            .expect("R finds the escrow addressed to it");
        let (amt, r_open) = open_escrow_memo(&np, &kem_r.secret, &mine.cv, &mine.memo)
            .expect("R opens the escrow memo");
        assert_eq!(amt, escrow_amount);

        // ── R builds a claim (accept) into a fresh coin to itself ──
        let (ss_claim, kem_ct_claim) = quil_crypto::sntrup761::encapsulate(&kem_r.public).unwrap();
        let off_claim = hash_to_short_polyvec(&ss_claim, cols);
        let claim_otk = wire::encode_polyvec(&one_time_pubkey_ring(a_otk, &off_claim, &big_b_r));
        let mut esc_addr = [0u8; 32];
        esc_addr.copy_from_slice(&mine.address);
        let (mut claim_env, r_out) = build_pending_claim(
            &np, domain, esc_addr, amt, &r_open, true, &falcon_r, claim_otk, 21,
        )
        .unwrap();
        claim_env.output_memo = build_output_memo(&kem_ct_claim, amt, &r_out, &ss_claim);

        // Verify + materialize the claim as the engine would.
        let new_cv = verify_lattice_pending_claim(
            &np, domain, &mine.cv, mine.to_key.as_slice(), claim_env.is_to, &claim_env.falcon_sig,
            &claim_env.output_commitment, &claim_env.output_range_proof, &claim_env.value_link_proof,
        )
        .unwrap()
        .expect("claim verifies");
        let claimed = super::super::materialize::materialize_lattice_transaction(
            domain, &frame, &[(claim_env.output_otk.clone(), new_cv)], &[mine.address.clone()],
            std::slice::from_ref(&claim_env.output_memo),
        )
        .unwrap();
        for (addr, tree) in &claimed.coins {
            insert_tree(addr, tree);
        }
        shadow_accumulator::refresh_root(&state, domain).unwrap();

        // ── R scans coins, finds + opens the claimed coin (spendable) ──
        let coins = shadow_accumulator::scan_domain_coins(&state, domain).unwrap();
        let mut found = false;
        for (_a, p_i, cv_i, memo_i) in &coins {
            if memo_i.is_empty() {
                continue;
            }
            let Ok((kc, ring)) = split_output_memo(memo_i) else { continue };
            let Ok(ss_i) = quil_crypto::sntrup761::decapsulate(&kc, &kem_r.secret) else { continue };
            let off_i = hash_to_short_polyvec(&ss_i, cols);
            let p_dec = wire::decode_polyvec(p_i).unwrap();
            if owns_ring(a_otk, &off_i, &big_b_r, &p_dec) {
                let (a2, r2) = open_ring_memo(&np, &ss_i, cv_i, &ring).unwrap();
                assert_eq!(a2, escrow_amount, "claimed coin holds the escrow amount");
                let sk = one_time_secret_ring(&off_i, &b_r);
                assert_eq!(a_otk.matvec(&sk), p_dec, "R can spend the claimed coin");
                let _ = r2;
                found = true;
                break;
            }
        }
        assert!(found, "R finds + opens its claimed coin");
    }

    #[test]
    fn mint_from_reward_witness_verifies_through_engine() {
        // The client-side mint assembly (build a coin worth the reward Balance +
        // Falcon-authorize it against a forest reward-membership proof) must be
        // accepted by the engine's `verify_mint_envelope_and_derive`. This proves
        // the whole mint crypto composition end-to-end; only the live node's
        // forest_proof/cited_frame production is out of scope (integration).
        use quil_crypto::FalconSigner;
        use quil_forest::{Forest, MembershipProof, Phase};
        use quil_lattice_ct::membership::MembershipParams;
        use quil_lattice_ct::stealth::{hash_to_short_polyvec, one_time_pubkey_ring};
        use quil_lattice_ct::wire;
        use quil_tries::VectorCommitmentTree;
        use quil_types::crypto::Signer;

        let np = NetworkParams::with_bits(16);
        let domain = &[0x77u8; 32][..]; // non-QUIL domain: reward_root is passed directly
        let value = 100u128;

        // Prover identity: owner = poseidon(falcon pubkey).
        let signer = FalconSigner::generate();
        let falcon_pk = signer.public_key().to_vec();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&falcon_pk).unwrap().to_vec();

        // ── Node: build + commit the reward:ProverReward vertex, prove membership ──
        let (prover_root_domain, leaf_owner) =
            crate::token_intrinsic::mint::derive_pomw_addressing(domain, &owner).unwrap();
        let mut vertex_id = [0u8; 64];
        vertex_id[..32].copy_from_slice(&prover_root_domain);
        vertex_id[32..].copy_from_slice(&leaf_owner);

        let deleg_key = crate::global_schema::field_key("reward:ProverReward", "DelegateAddress").unwrap();
        let bal_key = crate::global_schema::field_key("reward:ProverReward", "Balance").unwrap();
        let mut balance = [0u8; 32];
        balance[16..].copy_from_slice(&value.to_be_bytes()); // Balance == claimed value

        let mut vtree = VectorCommitmentTree::new();
        vtree.insert(&deleg_key, &owner, &[], &num_bigint::BigInt::from(owner.len())).unwrap();
        vtree.insert(&bal_key, &balance, &[], &num_bigint::BigInt::from(balance.len())).unwrap();
        let blob = quil_tries::serialize_go_tree(vtree.root.as_ref()).unwrap();
        let leaf = quil_tries::vertex_leaf_value(&blob).unwrap();

        let forest = Forest::in_memory();
        let reward_root = forest
            .commit_shard_phase_raw(b"reward-shard", Phase::VertexAdds, 0, vec![(leaf_owner.to_vec(), leaf)])
            .unwrap();
        let vp = forest
            .build_vertex_membership_proof(b"reward-shard", Phase::VertexAdds, 0, &vertex_id, &blob)
            .unwrap();
        let forest_proof = MembershipProof { inputs: vec![vp] }.to_bytes();

        // ── Client: build the mint output coin + Falcon authorization ──
        let mp = MembershipParams::production(1);
        let cols = mp.a_otk.cols;
        let mut prg = SplitMix64::new(0x312EE);
        let b = PolyVec::sample_short(cols, 1, &mut prg);
        let big_b = mp.a_otk.matvec(&b);
        let kem = quil_crypto::sntrup761::Sntrup761KeyPair::generate();
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&kem.public).unwrap();
        let offset = hash_to_short_polyvec(&ss, cols);
        let p_out = one_time_pubkey_ring(&mp.a_otk, &offset, &big_b);
        let outputs = vec![NewOutput { amount: value, recipient_otk: wire::encode_polyvec(&p_out) }];

        let built = build_mint_transaction(&np, value, &outputs, 0x9911).unwrap();
        let r_out = wire::decode_polyvec(&built.output_rand[0]).unwrap();
        let memo = build_output_memo(&kem_ct, value, &r_out, &ss);
        let mu = tx_challenge(domain, &built.output_commitments, value);
        let falcon_sig = signer.sign_with_domain(&mint_auth_message(value, &mu), domain).unwrap();

        let env = MintEnvelope {
            cited_frame: 0,
            inputs: vec![LatticeMintInput {
                value,
                owner_prover_address: owner,
                falcon_pubkey: falcon_pk,
                falcon_sig,
                forest_proof,
            }],
            output_commitments: built.output_commitments.clone(),
            output_range_proofs: built.output_range_proofs.clone(),
            output_otks: built.new_coins.iter().map(|(p, _)| p.clone()).collect(),
            balance_proof: built.balance_proof.clone(),
            output_memos: vec![memo],
        };

        // ── Engine: verify the mint (membership + Falcon auth + conservation) ──
        let mut root32 = [0u8; 32];
        root32.copy_from_slice(reward_root.as_ref());
        let (new_coins, decrements) = verify_mint_envelope_and_derive(&np, &root32, domain, &env)
            .unwrap()
            .expect("wallet-built mint verifies through the engine");
        assert_eq!(new_coins.len(), 1, "one minted coin");
        assert_eq!(decrements.len(), 1, "one reward decrement");
        assert_eq!(decrements[0].1, value, "decrement equals the minted value");
    }

    #[test]
    fn output_memo_transport_round_trips_through_envelope() {
        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let vlink = np.value_link_params();
        let mut prg = SplitMix64::new(0xBEEF);
        let amount = 777u128;
        let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let cv = wire::encode_polyvec(&vlink.compress(&super::commit_amount(&vkey, amount, &r_out)));
        let ss = [0x5Au8; 32];
        let kem_ct = vec![0xC7u8; 40]; // stand-in KEM ciphertext

        let memo = build_output_memo(&kem_ct, amount, &r_out, &ss);
        // Carry the memo through an envelope encode/decode (wire-format check).
        let env = TxEnvelope {
            input_spend_proofs: vec![],
            output_commitments: vec![],
            output_range_proofs: vec![],
            output_otks: vec![vec![1u8; 4]],
            output_memos: vec![memo.clone()],
            balance_proof: vec![9u8; 3],
            fee: 2,
        };
        let round = decode_tx_envelope(&encode_tx_envelope(&env)).unwrap();
        assert_eq!(round.output_memos, vec![memo.clone()]);

        // Split + open recovers (amount, r_out) bound to cv — the recipient path.
        let (kem2, ring) = split_output_memo(&round.output_memos[0]).unwrap();
        assert_eq!(kem2, kem_ct);
        let (a, r) = open_ring_memo(&np, &ss, &cv, &ring).unwrap();
        assert_eq!(a, amount);
        assert_eq!(wire::encode_polyvec(&r), wire::encode_polyvec(&r_out));
    }

    // Small amount width so the ~N binary proofs per output run fast.
    fn np() -> NetworkParams {
        NetworkParams::with_bits(16)
    }

    /// Commit an amount under the ℓ=VALUE_LIMBS value key with fresh randomness.
    fn commit_amount(
        np: &NetworkParams,
        v: u128,
        tag: u64,
    ) -> (RingCommitment, PolyVec) {
        let vkey = np.value_key();
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        (vkey.commit(&limbs_msg(v), &r), r)
    }

    #[test]
    fn overflow_mint_is_structurally_impossible() {
        // Full-width: the balance is a per-limb carry chain over ℤ (top
        // carry pinned to 0), so there is no modular wrap to exploit — a huge fee
        // simply fails to balance (returns false), it cannot mint `q`.
        let np = np();
        let (in_c, out_c, _rps, bal) = build_tx(&np, &[100], &[60, 38], 2);
        let res = verify_transaction_crypto(&np, &in_c, &out_c, &bal, Poly::Q as u128, true).unwrap();
        assert!(!res, "a wrong (enormous) fee must fail to balance, never overflow-mint");
    }

    #[test]
    fn pseudo_output_binding_same_amount_ok_diff_rejected() {
        let np = np();
        let vkey = np.value_key();
        let sub = |a: &PolyVec, b: &PolyVec| PolyVec(a.0.iter().zip(&b.0).map(|(x, y)| x.sub(y)).collect());
        let equal_proof = |cr: &RingCommitment, rr: &PolyVec, cp: &RingCommitment, rp: &PolyVec| {
            let diff = RingCommitment { t1: cr.t1.sub(&cp.t1), t2: cr.t2.sub(&cp.t2) };
            let delta = sub(rr, rp);
            prove_ring_opening(&vkey.stacked_matrix(), &diff.stacked(), &delta, &equality_params(), b"", 7)
                .unwrap()
        };
        // Same amount (different randomness) ⇒ equality proof verifies.
        let (c_real, r_real) = commit_amount(&np, 100, 1);
        let (c_pseudo, r_pseudo) = commit_amount(&np, 100, 2);
        let pf = equal_proof(&c_real, &r_real, &c_pseudo, &r_pseudo);
        assert!(verify_pseudo_output_binding(
            &np,
            &wire::encode_commitment(&c_real),
            &wire::encode_commitment(&c_pseudo),
            &wire::encode_opening(&pf),
        )
        .unwrap());

        // Different amount ⇒ the honest randomness-difference opens to (100−200)≠0,
        // so the "opens to 0" check fails: a false input amount is rejected.
        let (c_bad, r_bad) = commit_amount(&np, 200, 3);
        let pf_bad = equal_proof(&c_real, &r_real, &c_bad, &r_bad);
        assert!(!verify_pseudo_output_binding(
            &np,
            &wire::encode_commitment(&c_real),
            &wire::encode_commitment(&c_bad),
            &wire::encode_opening(&pf_bad),
        )
        .unwrap(), "declaring a different input amount than the real coin must reject");
    }

    /// Build a full, valid lattice-CT transaction's crypto: output commitments,
    /// range proofs, balance proof, and the byte containers the verify path
    /// consumes. Inputs sum to outputs + fee.
    #[allow(clippy::type_complexity)]
    fn build_tx(
        np: &NetworkParams,
        in_amounts: &[u128],
        out_amounts: &[u128],
        fee: u128,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<u8>) {
        // Commit inputs and outputs as ℓ=VALUE_LIMBS coins; balance over their
        // virtual per-limb slices (carry chain, folds output ranges).
        let mut in_wire = Vec::new();
        let mut in_virtual = Vec::new();
        let mut in_rand = Vec::new();
        for (i, &v) in in_amounts.iter().enumerate() {
            let (c, r) = commit_amount(np, v, 0x100 + i as u64);
            in_virtual.push(virtual_limbs(&c).unwrap());
            in_rand.push(r);
            in_wire.push(wire::encode_commitment(&c));
        }
        let mut out_wire = Vec::new();
        let mut out_virtual = Vec::new();
        let mut out_rand = Vec::new();
        for (i, &v) in out_amounts.iter().enumerate() {
            let (c, r) = commit_amount(np, v, 0x200 + i as u64);
            out_virtual.push(virtual_limbs(&c).unwrap());
            out_rand.push(r);
            out_wire.push(wire::encode_commitment(&c));
        }

        let balance = prove_limb_balance_bound(
            np.limb_range_key(), &in_virtual, &in_rand, &out_virtual, &out_rand,
            in_amounts, out_amounts, fee, VALUE_LIMBS, 0x400,
        )
        .expect("balances");

        (in_wire, out_wire, Vec::new(), wire::encode_limb_balance(&balance))
    }

    #[test]
    fn valid_transaction_verifies() {
        let np = np();
        // 100 in = 60 + 38 out + 2 fee.
        let (in_c, out_c, _rps, bal) = build_tx(&np, &[100], &[60, 38], 2);
        assert!(
            verify_transaction_crypto(&np, &in_c, &out_c, &bal, 2, true).unwrap(),
            "well-formed transaction verifies"
        );
    }

    #[test]
    fn full_width_transaction_verifies() {
        // An amount far beyond the old 2^20 single-coefficient cap round-trips.
        let np = np();
        let big = (1u128 << 60) + 12345;
        let (in_c, out_c, _rps, bal) = build_tx(&np, &[big + 2], &[big, 0], 2);
        assert!(
            verify_transaction_crypto(&np, &in_c, &out_c, &bal, 2, true).unwrap(),
            "a 2^60 amount balances under the full-width limb path"
        );
    }

    #[test]
    fn inflationary_transaction_rejected() {
        // Verify a balanced tx against a WRONG (larger) fee claim: the per-limb
        // carry chain is bound to the true fee, so a different fee must reject.
        let np = np();
        let (in_c, out_c, _rps, bal) = build_tx(&np, &[100], &[60, 38], 2);
        assert!(
            !verify_transaction_crypto(&np, &in_c, &out_c, &bal, 5, true).unwrap(),
            "balance bound to the true fee; a different fee must reject"
        );
    }

    #[test]
    fn inflating_output_is_unprovable() {
        // out (60+50) + fee 2 = 112 > 100 in ⇒ the carry chain cannot close, so
        // the prover cannot even produce a balance proof (no value creation).
        let np = np();
        let (c_in, r_in) = commit_amount(&np, 100, 1);
        let (c_o1, r_o1) = commit_amount(&np, 60, 2);
        let (c_o2, r_o2) = commit_amount(&np, 50, 3);
        let bal = prove_limb_balance_bound(
            np.limb_range_key(),
            &[virtual_limbs(&c_in).unwrap()],
            &[r_in],
            &[virtual_limbs(&c_o1).unwrap(), virtual_limbs(&c_o2).unwrap()],
            &[r_o1, r_o2],
            &[100],
            &[60, 50],
            2,
            VALUE_LIMBS,
            9,
        );
        assert!(bal.is_none(), "outputs exceeding inputs+fee cannot balance (no inflation)");
    }

    #[test]
    fn tampered_balance_proof_rejected() {
        let np = np();
        let (in_c, out_c, _rps, mut bal) = build_tx(&np, &[100], &[60, 38], 2);
        // Corrupt a byte inside the limb-balance proof.
        let mid = bal.len() / 2;
        bal[mid] ^= 0xFF;
        let res = verify_transaction_crypto(&np, &in_c, &out_c, &bal, 2, true);
        assert!(matches!(res, Ok(false) | Err(_)), "tampered balance proof must not pass");
    }

    #[test]
    fn ring_signature_spends_and_yields_key_image() {
        let np = np();
        let n_ring = 4;
        let key = np.sig_key(n_ring);
        // Build a ring; the spender is member 2.
        let mut sks = Vec::new();
        let mut ring = Vec::new();
        for i in 0..n_ring {
            let (sk, pk) = key.keygen(1000 + i as u64);
            sks.push(sk);
            ring.push(pk);
        }
        let signer = 2usize;
        let challenge = b"tx-challenge-bytes";
        let sig = ring_sign(&key, &ring, signer, &sks[signer], challenge, 1).expect("signs");

        let ring_b: Vec<Vec<u8>> = ring.iter().map(wire::encode_polyvec).collect();
        let sig_b = wire::encode_ring_sig(&sig);

        let ki = verify_input_signature(&np, &ring_b, &sig_b, challenge)
            .unwrap()
            .expect("valid spend yields a key image");
        assert_eq!(ki, wire::encode_polyvec(&sig.tag), "key image is the nullifier");

        // Wrong challenge (different transaction) must not verify.
        assert!(
            verify_input_signature(&np, &ring_b, &sig_b, b"other-tx").unwrap().is_none(),
            "signature is transaction-bound"
        );
    }

    #[test]
    fn pending_claim_verifies_and_rejects_wrong_recipient() {
        use quil_crypto::FalconSigner;
        use quil_lattice_ct::value_link::prove_value_link;
        use quil_types::crypto::Signer;

        let np = NetworkParams::with_bits(16);
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let cols = np.value_key().a1.cols;

        // Escrow amount 100: cv = H_B(escrow_C); the claim reveals output_C
        // committing the same amount, linked by prove_value_link.
        let mut prg = SplitMix64::new(1);
        let v = limbs_msg(100);
        let r_esc = PolyVec::sample_short(cols, ETA, &mut prg);
        let r_out = PolyVec::sample_short(cols, ETA, &mut prg);
        let (cv, output_c, vl) = prove_value_link(&vlink, &v, &r_esc, &r_out, 7).unwrap();

        // The escrow's `to` recipient Falcon-signs the claim.
        let recipient = FalconSigner::generate();
        let is_to = true;
        let out_c_bytes = wire::encode_commitment(&output_c);
        let mu = tx_challenge(domain, &[out_c_bytes.clone()], is_to as u128);
        let sig = recipient.sign_with_domain(&mint_auth_message(is_to as u128, &mu), domain).unwrap();

        let cv_b = wire::encode_polyvec(&cv);
        let rp_b: Vec<u8> = Vec::new(); // range folded into the escrow's create-time bound
        let vl_b = wire::encode_opening(&vl);
        let ok = verify_lattice_pending_claim(
            &np, domain, &cv_b, recipient.public_key(), is_to, &sig, &out_c_bytes, &rp_b, &vl_b,
        )
        .unwrap();
        assert!(ok.is_some(), "the `to` recipient claims the escrow into a coin");

        // A different key can't claim.
        let impostor = FalconSigner::generate();
        assert!(
            verify_lattice_pending_claim(
                &np, domain, &cv_b, impostor.public_key(), is_to, &sig, &out_c_bytes, &rp_b, &vl_b,
            )
            .unwrap()
            .is_none(),
            "wrong recipient key ⇒ claim rejected"
        );
    }

    #[test]
    fn mint_auth_falcon_signature_binds_value_and_domain() {
        use quil_crypto::FalconSigner;
        use quil_types::crypto::Signer;

        let signer = FalconSigner::generate();
        let (value, mu, domain) = (100u128, b"mint-mu".as_slice(), b"QUIL-dom".as_slice());
        let sig = signer.sign_with_domain(&mint_auth_message(value, mu), domain).unwrap();

        assert!(verify_mint_auth_signature(signer.public_key(), &sig, value, mu, domain));
        // Bound to the value, the outputs (via mu), and the domain.
        assert!(!verify_mint_auth_signature(signer.public_key(), &sig, 101, mu, domain), "value bound");
        assert!(!verify_mint_auth_signature(signer.public_key(), &sig, value, b"other", domain), "outputs bound");
        assert!(!verify_mint_auth_signature(signer.public_key(), &sig, value, mu, b"other"), "domain bound");
    }

    #[test]
    fn wallet_builds_pending_claim_that_verifies() {
        use quil_crypto::FalconSigner;
        use quil_types::crypto::Signer;
        let np = NetworkParams::with_bits(16);
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let amount = 250u128;

        // The escrow's amount + randomness (the claimant knows these via the memo);
        // its committed cv is what the engine reads from the escrow vertex.
        let mut prg = SplitMix64::new(2);
        let escrow_r = PolyVec::sample_short(np.value_key().a1.cols, ETA, &mut prg);
        let escrow_c = np.value_key().commit(&limbs_msg(amount), &escrow_r);
        let escrow_cv = wire::encode_polyvec(&vlink.compress(&escrow_c));

        let recipient = FalconSigner::generate();
        let (env, _r_out) = build_pending_claim(
            &np, domain, [0xCD; 32], amount, &escrow_r, true, &recipient, vec![0xEE; 200], 9,
        )
        .unwrap();
        // Verify as the engine would (escrow_cv + recipient key from the vertex).
        assert!(
            verify_lattice_pending_claim(
                &np, domain, &escrow_cv, recipient.public_key(), env.is_to, &env.falcon_sig,
                &env.output_commitment, &env.output_range_proof, &env.value_link_proof,
            )
            .unwrap()
            .is_some(),
            "wallet-built escrow claim verifies"
        );
    }

    #[test]
    fn wallet_builds_shield_that_verifies() {
        use ed448_rust::{PrivateKey, PublicKey};
        let np = NetworkParams::with_bits(16);
        let domain = &[0x51u8; 32][..];
        let seed = [3u8; 57];
        let sk = PrivateKey::from(&seed);
        let pubkey = PublicKey::from(&sk).as_byte().to_vec();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&pubkey).unwrap();
        let amount = 500u128;

        let env = build_shield_transaction(
            &np, domain, [0xAB; 32], &seed, &pubkey, amount, vec![0xEE; 200], 7,
        )
        .unwrap();
        // Round-trips + verifies (as the engine would, given owner+amount from state).
        let bytes = encode_shield(&env);
        let back = decode_shield(&bytes).unwrap();
        assert!(
            verify_lattice_shield(
                &np, domain, &owner, amount, &back.ed448_pubkey, &back.ed448_sig,
                &back.output_commitment, &back.output_range_proof, &back.balance_proof,
            )
            .unwrap()
            .is_some(),
            "wallet-built shield verifies"
        );
    }

    #[test]
    fn legacy_shield_verifies_and_rejects_wrong_owner() {
        use ed448_rust::{PrivateKey, PublicKey};
        use quil_lattice_ct::linear_rq::prove_linear_rq;
        use quil_lattice_ct::range_rq::prove_range_rq;

        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let domain = &[0x51u8; 32][..];
        let amount = 100u128;

        // Ed448 legacy owner.
        let sk = PrivateKey::from(&[7u8; 57]);
        let pubkey = PublicKey::from(&sk).as_byte().to_vec();
        let owner_address = quil_crypto::poseidon::hash_bytes_to_32(&pubkey).unwrap();

        // Output lattice coin (ℓ=VALUE_LIMBS) committing the public amount +
        // mint-style full-width balance (virtual(amount) − output = 0).
        let mut prg = SplitMix64::new(3);
        let r_out = PolyVec::sample_short(vkey.a1.cols, ETA, &mut prg);
        let c_out = vkey.commit(&limbs_msg(amount), &r_out);
        let vin = mint_virtual_input(amount);
        let balance = quil_lattice_ct::limb_balance::prove_limb_balance_bound_ext(
            np.limb_range_key(),
            &[virtual_limbs(&vin).unwrap()],
            &[PolyVec::zero(vkey.a1.cols)],
            &[virtual_limbs(&c_out).unwrap()],
            &[r_out.clone()],
            &[amount],
            &[amount],
            0,
            VALUE_LIMBS,
            0x44,
            true,
        )
        .unwrap();
        let out_c = wire::encode_commitment(&c_out);
        // Packed per-limb range for the shielded output.
        let rp_b: Vec<u8> = packed_output_range_blobs(&np, &[out_c.clone()], &[amount], &[r_out], 0x4400)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let bal_b = wire::encode_limb_balance(&balance);

        // Ed448-sign the shield context.
        let msg = shield_message(domain, amount, &out_c);
        let sig = sk.sign(&msg, None).unwrap().to_vec();

        let cv = verify_lattice_shield(
            &np, domain, &owner_address, amount, &pubkey, &sig, &out_c, &rp_b, &bal_b,
        )
        .unwrap();
        assert!(cv.is_some(), "legacy owner shields their transparent coin into a lattice coin");

        // A different Ed448 key can't shield this coin.
        let sk2 = PrivateKey::from(&[9u8; 57]);
        let pk2 = PublicKey::from(&sk2).as_byte().to_vec();
        let sig2 = sk2.sign(&msg, None).unwrap().to_vec();
        assert!(
            verify_lattice_shield(&np, domain, &owner_address, amount, &pk2, &sig2, &out_c, &rp_b, &bal_b)
                .unwrap()
                .is_none(),
            "wrong owner ⇒ shield rejected"
        );
    }

    #[test]
    fn mint_conservation_holds_and_rejects_over_mint() {
        let np = NetworkParams::with_bits(16);
        // Two output coins summing to the mint amount (full-width ℓ=L path).
        let outputs = vec![
            NewOutput { amount: 60, recipient_otk: vec![0xA1u8; 200] },
            NewOutput { amount: 40, recipient_otk: vec![0xA2u8; 200] },
        ];
        let mint = build_mint_transaction(&np, 100, &outputs, 0x33).unwrap();
        let out_c = mint.output_commitments.clone();
        let rp = mint.output_range_proofs.clone(); // packed per-limb ranges
        let bal = mint.balance_proof.clone();

        assert!(
            verify_mint_crypto(&np, 100, &out_c, &rp, &bal).unwrap(),
            "outputs summing to the mint amount verify"
        );
        // Claiming a larger mint amount than the outputs sum to ⇒ reject (no over-mint).
        assert!(
            !verify_mint_crypto(&np, 101, &out_c, &rp, &bal).unwrap(),
            "a mint amount != Σ outputs must reject"
        );
    }

    #[test]
    fn fw_transfer_node_verifies_with_network_value_key() {
        // The fw TRANSFER over the REAL network value_key (ell=VALUE_LIMBS with all
        // A2 rows equal — the shape a spend's c_prime actually uses). 2-in/2-out,
        // balanced; each input pinned to its c_prime.
        let np = NetworkParams::with_bits(16);
        let vkey = np.value_key();
        let ins = [1_000_000u128, 5_000u128];
        let outs = [900_000u128, 100_000u128];
        let fee = 5_000u128;
        let pr = &crate::token_intrinsic::packed_range::prove_fw_transfer_bytes;
        let vf = &crate::token_intrinsic::packed_range::verify_fw_transfer_bytes;
        let (out_bytes, cprime_bytes, proof_bytes) = pr(&vkey, &ins, &outs, fee, 0x9911).unwrap();
        assert!(vf(&vkey, &out_bytes, &cprime_bytes, fee, &proof_bytes).unwrap(), "fw transfer with network value_key verifies");
        // Wrong fee ⇒ balance target mismatch ⇒ reject.
        assert!(!vf(&vkey, &out_bytes, &cprime_bytes, fee + 1, &proof_bytes).unwrap_or(false), "wrong fee rejects");
        // Tampered output coin ⇒ reject.
        let mut bad = out_bytes.clone();
        *bad[0].last_mut().unwrap() ^= 1;
        assert!(!vf(&vkey, &bad, &cprime_bytes, fee, &proof_bytes).unwrap_or(false), "tampered output rejects");
        // Tampered c_prime (input value) ⇒ opening binding fails ⇒ reject (anti-inflation).
        let mut badcp = cprime_bytes.clone();
        *badcp[0].last_mut().unwrap() ^= 1;
        assert!(!vf(&vkey, &out_bytes, &badcp, fee, &proof_bytes).unwrap_or(false), "tampered c_prime rejects");
        println!("FW TRANSFER node proof = {} KB", proof_bytes.len() / 1024);
    }

    #[test]
    fn build_fw_shield_transaction_verifies_through_engine() {
        use ed448_rust::{PrivateKey, PublicKey};
        // WALLET BUILD: build_fw_shield_transaction emits an fw coin + fw
        // marker + fw proof; verify_lattice_shield accepts it (conservation via fw).
        let np = NetworkParams::with_bits(16);
        let domain = &[0x51u8; 32][..];
        let sk = PrivateKey::from(&[3u8; 57]);
        let pubkey = PublicKey::from(&sk).as_byte().to_vec();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&pubkey).unwrap();
        let amount = 250_000u128;
        let env = build_fw_shield_transaction(&np, domain, [0xAB; 32], &[3u8; 57], &pubkey, amount, vec![0xEE; 200], 0x8181).unwrap();
        let back = decode_shield(&encode_shield(&env)).unwrap();
        assert!(
            verify_lattice_shield(&np, domain, &owner, amount, &back.ed448_pubkey, &back.ed448_sig, &back.output_commitment, &back.output_range_proof, &back.balance_proof)
                .unwrap()
                .is_some(),
            "wallet-built fw shield verifies through the engine"
        );
    }

    #[test]
    fn shield_fw_amortized_verifies_through_engine() {
        use ed448_rust::{PrivateKey, PublicKey};
        // SHIELD via the fw path: conservation runs through verify_mint_crypto, so a
        // shield carrying the fw marker + fw proof dispatches to verify_fw_mint. A
        // single output coin commits the public transparent amount.
        let np = NetworkParams::with_bits(16);
        let domain = &[0x51u8; 32][..];
        let sk = PrivateKey::from(&[3u8; 57]);
        let pubkey = PublicKey::from(&sk).as_byte().to_vec();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&pubkey).unwrap();
        let amount = 250_000u128;
        let (coins, proof) = crate::token_intrinsic::packed_range::prove_fw_mint_bytes(&np.value_key(), amount, &[amount], 0x5111).unwrap();
        let output_commitment = coins[0].clone();
        let msg = shield_message(domain, amount, &output_commitment);
        let sig = sk.sign(&msg, None).unwrap().to_vec();
        let marker = crate::token_intrinsic::packed_range::RANGE_V_FULLWIDTH; // single tag byte
        assert!(
            verify_lattice_shield(&np, domain, &owner, amount, &pubkey, &sig, &output_commitment, &[marker], &proof)
                .unwrap()
                .is_some(),
            "fw shield conserving the public amount verifies through the engine"
        );
        // Claiming a LARGER amount than the coin conserves: sign the larger amount so
        // ownership+sig pass, then the fw conservation (Σ output = amount) rejects.
        let msg2 = shield_message(domain, amount + 1, &output_commitment);
        let sig2 = sk.sign(&msg2, None).unwrap().to_vec();
        assert!(
            verify_lattice_shield(&np, domain, &owner, amount + 1, &pubkey, &sig2, &output_commitment, &[marker], &proof)
                .unwrap()
                .is_none(),
            "fw shield over-claiming the amount rejects on conservation"
        );
    }

    #[test]
    fn build_fw_mint_transaction_verifies_through_engine() {
        // WALLET BUILD: build_fw_mint_transaction emits fw coins + the fw
        // marker + the fw proof; the built tx verifies through verify_mint_crypto.
        let np = NetworkParams::with_bits(16);
        let outputs = vec![
            NewOutput { amount: 600_000, recipient_otk: vec![0xA1u8; 200] },
            NewOutput { amount: 400_000, recipient_otk: vec![0xA2u8; 200] },
        ];
        let tx = build_fw_mint_transaction(&np, 1_000_000, &outputs, 0x4242).unwrap();
        assert_eq!(tx.output_range_proofs, crate::token_intrinsic::packed_range::fw_output_ranges_marker());
        assert!(
            verify_mint_crypto(&np, 1_000_000, &tx.output_commitments, &tx.output_range_proofs, &tx.balance_proof).unwrap(),
            "wallet-built fw mint verifies through the engine"
        );
        // Over-claim ⇒ reject.
        assert!(
            !verify_mint_crypto(&np, 1_000_001, &tx.output_commitments, &tx.output_range_proofs, &tx.balance_proof).unwrap_or(false),
            "claiming more than the outputs conserve rejects"
        );
        assert_eq!(tx.new_coins.len(), 2, "two output coins emitted for materialize");
    }

    #[test]
    fn mint_fw_amortized_verifies_through_engine() {
        // The full-width amortized mint dispatched THROUGH verify_mint_crypto: the
        // fw marker rides `output_range_proofs`, the single IPA proof rides
        // `balance_proof`, and the outputs ARE fw coins. Honest conservation verifies;
        // a wrong claimed mint amount and a tampered coin reject (fail-closed).
        let np = NetworkParams::with_bits(16);
        let mint = 1_000_000u128;
        let outs = [600_000u128, 400_000u128];
        let (coins, proof_bytes) = crate::token_intrinsic::packed_range::prove_fw_mint_bytes(&np.value_key(), mint, &outs, 0x77).unwrap();
        let marker = crate::token_intrinsic::packed_range::fw_output_ranges_marker();
        assert!(verify_mint_crypto(&np, mint, &coins, &marker, &proof_bytes).unwrap(), "fw mint conserves ⇒ verifies through engine");
        assert!(!verify_mint_crypto(&np, mint + 1, &coins, &marker, &proof_bytes).unwrap_or(false), "wrong mint amount rejects");
        let mut bad = coins.clone();
        *bad[0].last_mut().unwrap() ^= 1;
        assert!(!verify_mint_crypto(&np, mint, &bad, &marker, &proof_bytes).unwrap_or(false), "tampered coin rejects");
    }

    #[test]
    fn mint_envelope_round_trips() {
        let np = NetworkParams::with_bits(16);
        let outputs = vec![
            NewOutput { amount: 70, recipient_otk: vec![0xA1u8; 200] },
            NewOutput { amount: 30, recipient_otk: vec![0xA2u8; 200] },
        ];
        let mint = build_mint_transaction(&np, 100, &outputs, 5).unwrap();
        let env = MintEnvelope {
            cited_frame: 4242,
            inputs: vec![LatticeMintInput {
                value: 100,
                owner_prover_address: vec![0x11u8; 32],
                falcon_pubkey: vec![0x22u8; quil_crypto::FALCON_PUBLIC_KEY_LEN],
                falcon_sig: vec![0x33u8; 40],
                forest_proof: vec![0x44u8; 128],
            }],
            output_commitments: mint.output_commitments.clone(),
            output_range_proofs: mint.output_range_proofs.clone(),
            output_otks: mint.new_coins.iter().map(|(p, _)| p.clone()).collect(),
            balance_proof: mint.balance_proof.clone(),
            output_memos: Vec::new(),
        };
        let bytes = encode_mint_envelope(&env);
        let back = decode_mint_envelope(&bytes).unwrap();
        assert_eq!(encode_mint_envelope(&back), bytes, "mint envelope round-trip stable");
        assert_eq!(back.inputs.len(), 1);
        assert_eq!(back.inputs[0].value, 100);
        assert_eq!(back.output_commitments.len(), 2);
    }

    #[test]
    fn wallet_builds_mint_that_verifies() {
        let np = NetworkParams::with_bits(16);
        let mint_amount = 100u128;
        let outputs = vec![
            NewOutput { amount: 70, recipient_otk: vec![0xA1u8; 200] },
            NewOutput { amount: 30, recipient_otk: vec![0xA2u8; 200] },
        ];
        let mint = build_mint_transaction(&np, mint_amount, &outputs, 5).expect("mint builds");
        assert_eq!(mint.input_spend_proofs.len(), 0, "a mint has no spend inputs");
        assert_eq!(mint.new_coins.len(), 2);
        assert!(
            verify_mint_crypto(
                &np,
                mint_amount,
                &mint.output_commitments,
                &mint.output_range_proofs,
                &mint.balance_proof,
            )
            .unwrap(),
            "wallet-built mint's outputs sum to the mint amount"
        );
        // Outputs that don't sum to the claimed amount ⇒ reject.
        assert!(!verify_mint_crypto(&np, 99, &mint.output_commitments, &mint.output_range_proofs, &mint.balance_proof).unwrap());
    }

    #[test]
    fn wallet_builds_transaction_that_verifies() {
        use super::super::coin_accumulator::CoinAccumulator;
        use super::super::shadow_accumulator;
        use crate::hypergraph_state::HypergraphState;
        use quil_lattice_ct::accumulator::ACC_NODE_RANK;
        use quil_lattice_ct::membership::MembershipParams;
        use quil_lattice_ct::wire;
        use std::sync::Arc;

        let np = NetworkParams::with_bits(16);
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let mu = b"wallet-tx";

        // Owned coin (amount 100).
        let mut prg = SplitMix64::new(0xD0);
        let sk = PolyVec::sample_short(quil_lattice_ct::params::LWE_RANK_LAMBDA, ETA, &mut prg);
        let r_coin = PolyVec::sample_short(np.value_key().a1.cols, ETA, &mut prg);
        let c = vlink.vkey.commit(&limbs_msg(100), &r_coin);
        let cv = vlink.compress(&c);

        let mp_seed = MembershipParams::production(1);
        let p_otk = mp_seed.a_otk.matvec(&sk);
        let rand_node = |t: u64| {
            let mut p = SplitMix64::new(t);
            wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, &mut p))
        };
        let mut ca = CoinAccumulator::with_depth(8);
        ca.insert_coin(&rand_node(1), &rand_node(2)).unwrap();
        let idx = ca.insert_coin(&wire::encode_polyvec(&p_otk), &wire::encode_polyvec(&cv)).unwrap();
        ca.insert_coin(&rand_node(3), &rand_node(4)).unwrap();
        let depth = ca.current_depth();
        let root = ca.root_bytes();

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt);
        shadow_accumulator::write_root(&state, domain, &ca).unwrap();

        // Wallet constructs the transaction: 100 in → 60 + 38 out + fee 2.
        let inputs = vec![SpendInput {
            sk,
            amount: 100,
            r_coin,
            leaf_index: idx,
            auth_path: ca.auth_path(idx),
        }];
        let outputs = vec![
            NewOutput { amount: 60, recipient_otk: rand_node(20) },
            NewOutput { amount: 38, recipient_otk: rand_node(21) },
        ];
        let _ = mu; // challenge is now derived internally from the tx context
        let tx = build_spend_transaction(&np, &root, depth, domain, &inputs, &outputs, 2, 7)
            .expect("wallet builds a conserving transaction");
        assert_eq!(tx.new_coins.len(), 2, "one new coin (P,cv) per output");

        // Full wire loop: envelope encode → decode → verify + derive coins.
        // (mu is derived identically by wallet and engine — nothing on the wire.)
        let env = TxEnvelope::from_built(&tx);
        let bytes = encode_tx_envelope(&env);
        let env2 = decode_tx_envelope(&bytes).unwrap();
        assert_eq!(encode_tx_envelope(&env2), bytes, "envelope round-trip stable");
        let (kis, new_coins) = verify_envelope_and_derive_coins(&np, &state, domain, &env2, true)
            .unwrap()
            .expect("wallet-built transaction verifies through the engine path");
        assert_eq!(kis.len(), 1, "one nullifier for the single input");
        assert_eq!(new_coins.len(), 2, "two new coins to materialize");
        // The engine-derived cv equals H_B(C_out) (matches the wallet's).
        assert_eq!(new_coins, tx.new_coins, "engine-derived (P,cv) == wallet's new coins");

        // Full engine message: [4-byte TYPE_LATTICE_TRANSACTION][envelope]. Parse
        // it exactly as the engine dispatch does and re-verify.
        let msg = encode_lattice_transaction_message(&tx);
        assert_eq!(u32::from_be_bytes(msg[..4].try_into().unwrap()), TYPE_LATTICE_TRANSACTION);
        let env_from_msg = decode_tx_envelope(&msg[4..]).unwrap();
        assert!(
            verify_envelope_and_derive_coins(&np, &state, domain, &env_from_msg, true)
                .unwrap()
                .is_some(),
            "the engine-framed message parses and verifies"
        );
    }

    #[test]
    fn full_lattice_transaction_end_to_end_and_double_spend_blocked() {
        use super::super::coin_accumulator::CoinAccumulator;
        use super::super::shadow_accumulator;
        use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use quil_lattice_ct::accumulator::ACC_NODE_RANK;
        use quil_lattice_ct::linear_rq::prove_linear_rq;
        use quil_lattice_ct::membership::{prove_spend, MembershipParams};
        use quil_lattice_ct::range_rq::prove_range_rq;
        use quil_lattice_ct::wire;
        use std::sync::Arc;

        let np = NetworkParams::with_bits(16);
        let vlink = np.value_link_params();
        let domain = &[0x51u8; 32][..];
        let mu = b"lattice-tx-challenge";

        // ---- The coin: value 100, spend key sk; C, cv=H_B(C) under the network key.
        let mut prg = SplitMix64::new(0xC0);
        let sk = PolyVec::sample_short(quil_lattice_ct::params::LWE_RANK_LAMBDA, ETA, &mut prg);
        let v = limbs_msg(100);
        let r_coin = PolyVec::sample_short(np.value_key().a1.cols, ETA, &mut prg);
        let r_prime = PolyVec::sample_short(np.value_key().a1.cols, ETA, &mut prg);
        let c = vlink.vkey.commit(&v, &r_coin);
        let cv = vlink.compress(&c);

        // ---- Shadow accumulator holding the coin among decoys; commit its root.
        let mp_seed = MembershipParams::production(1); // A_otk depth-independent
        let p_otk = mp_seed.a_otk.matvec(&sk);
        let rand_node = |t: u64| {
            let mut p = SplitMix64::new(t);
            wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, &mut p))
        };
        let mut ca = CoinAccumulator::with_depth(8);
        ca.insert_coin(&rand_node(1), &rand_node(2)).unwrap();
        let idx = ca.insert_coin(&wire::encode_polyvec(&p_otk), &wire::encode_polyvec(&cv)).unwrap();
        ca.insert_coin(&rand_node(3), &rand_node(4)).unwrap();
        ca.insert_coin(&rand_node(5), &rand_node(6)).unwrap();
        let depth = ca.current_depth();
        let root_node = wire::decode_polyvec(&ca.root_bytes()).unwrap();
        let path: Vec<_> = ca.auth_path(idx).iter().map(|b| wire::decode_polyvec(b).unwrap()).collect();

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt);
        shadow_accumulator::write_root(&state, domain, &ca).unwrap();

        // ---- Build the spend proof (carries C' = re-randomized value commitment).
        let mp = MembershipParams::production(depth);
        let sp = prove_spend(&mp, &vlink, &root_node, &sk, &v, &r_coin, &r_prime, idx, &path, mu, 7)
            .expect("coin spends");
        let c_prime = sp.c_prime.clone();
        let spend_bytes = wire::encode_spend(&sp);

        // ---- Outputs 60 + 38, fee 2 (= 100). Full-width limb balance over the
        // revealed pseudo-input C' and the outputs' virtual per-limb slices.
        let make_out = |amt: u128, tag: u64| {
            let mut p = SplitMix64::new(tag);
            let r = PolyVec::sample_short(np.value_key().a1.cols, ETA, &mut p);
            (np.value_key().commit(&limbs_msg(amt), &r), r)
        };
        let (o1, r_o1) = make_out(60, 0x201);
        let (o2, r_o2) = make_out(38, 0x202);
        // PACKED-only: range_free limb balance + coefficient-packed per-limb ranges.
        let balance = quil_lattice_ct::limb_balance::prove_limb_balance_bound_ext(
            np.limb_range_key(),
            &[virtual_limbs(&c_prime).unwrap()],
            &[r_prime.clone()],
            &[virtual_limbs(&o1).unwrap(), virtual_limbs(&o2).unwrap()],
            &[r_o1.clone(), r_o2.clone()],
            &[100],
            &[60, 38],
            2,
            VALUE_LIMBS,
            0x400,
            true,
        )
        .expect("balances");

        let out_c = vec![wire::encode_commitment(&o1), wire::encode_commitment(&o2)];
        let limb_vkey = np.limb_range_key().value_key();
        let pack = |oc: &RingCommitment, amt: u128, r: &PolyVec, s: u64| {
            crate::token_intrinsic::packed_range::encode_packed_limb_ranges(
                &crate::token_intrinsic::packed_range::prove_packed_limb_ranges(
                    np.packed_key(), &limb_vkey, oc, amt, r, VALUE_LIMBS,
                    quil_lattice_ct::limb_balance::RANGE_BITS, s,
                )
                .unwrap(),
            )
        };
        let out_rp: Vec<Vec<u8>> = vec![pack(&o1, 60, &r_o1, 0x501), pack(&o2, 38, &r_o2, 0x502)];
        let bal_bytes = wire::encode_limb_balance(&balance);

        // ---- Verify the whole transaction.
        let kis = verify_lattice_transaction(
            &np, &state, domain, &[spend_bytes], &out_c, &out_rp, &bal_bytes, 2, true, mu,
        )
        .unwrap()
        .expect("valid confidential transaction verifies");
        assert_eq!(kis.len(), 1, "one key image (nullifier) returned");

        // ---- Double-spend: record the key image, re-verify ⇒ rejected.
        let disc = vertex_adds_discriminator().unwrap();
        let ki_addr = spent_check::key_image_spent_address(&kis[0]).unwrap();
        state.set(domain, &ki_addr, &disc, 1, b"spent".to_vec()).unwrap();
        // rebuild spend bytes (fresh proof would differ; reuse — the key image is the same).
        let sp2 = wire::encode_spend(&sp);
        assert!(
            verify_lattice_transaction(&np, &state, domain, &[sp2], &out_c, &out_rp, &bal_bytes, 2, true, mu)
                .unwrap()
                .is_none(),
            "recorded key image ⇒ double-spend rejected"
        );
    }

    #[test]
    fn fullwidth_balance_verifies_and_rejects_inflation() {
        use quil_lattice_ct::limb_balance::prove_limb_balance;
        let np = np();
        let rk = np.limb_range_key();
        // 64-bit (8-limb) amounts: 2^40+5 in = (2^40−100) + 103 out + fee 2.
        let (in_c, out_c, pf) =
            prove_limb_balance(rk, &[(1u128 << 40) + 5], &[(1u128 << 40) - 100, 103], 2, 8, 21)
                .unwrap();
        let enc = |rows: &[Vec<RingCommitment>]| -> Vec<Vec<Vec<u8>>> {
            rows.iter().map(|r| r.iter().map(wire::encode_commitment).collect()).collect()
        };
        let (in_e, out_e) = (enc(&in_c), enc(&out_c));
        let bal = wire::encode_limb_balance(&pf);
        assert!(verify_transaction_balance_fullwidth(&np, &in_e, &out_e, &bal, 2, 8).unwrap());
        // A wrong fee claim breaks the per-limb balance ⇒ reject.
        assert!(!verify_transaction_balance_fullwidth(&np, &in_e, &out_e, &bal, 3, 8).unwrap());
    }

    #[test]
    fn double_spend_shows_identical_key_image() {
        // The same spend key in two transactions produces the same key image —
        // the nullifier the double-spend check keys on.
        let np = np();
        let n_ring = 4;
        let key = np.sig_key(n_ring);
        let mut sks = Vec::new();
        let mut ring = Vec::new();
        for i in 0..n_ring {
            let (sk, pk) = key.keygen(2000 + i as u64);
            sks.push(sk);
            ring.push(pk);
        }
        let ring_b: Vec<Vec<u8>> = ring.iter().map(wire::encode_polyvec).collect();

        let s1 = ring_sign(&key, &ring, 1, &sks[1], b"tx-A", 3).unwrap();
        let s2 = ring_sign(&key, &ring, 1, &sks[1], b"tx-B", 4).unwrap();
        let ki1 = verify_input_signature(&np, &ring_b, &wire::encode_ring_sig(&s1), b"tx-A").unwrap().unwrap();
        let ki2 = verify_input_signature(&np, &ring_b, &wire::encode_ring_sig(&s2), b"tx-B").unwrap().unwrap();
        assert_eq!(ki1, ki2, "same spend key ⇒ same key image ⇒ double-spend caught");
    }

    #[test]
    fn opaque_field_size_bounds_reject_bloat_accept_legit() {
        // Legit-sized memos / keys pass (hardening #5).
        assert!(check_memo_size(&vec![0u8; 8 * 1024]).is_ok());
        assert!(check_memo_size(&vec![0u8; MAX_MEMO_BYTES]).is_ok());
        assert!(check_memos_size(&[vec![0u8; 4096], vec![0u8; 4096]]).is_ok());
        assert!(check_escrow_memo_size(&vec![0u8; 16 * 1024]).is_ok());
        assert!(check_escrow_memo_size(&vec![0u8; MAX_ESCROW_MEMO_BYTES]).is_ok());
        // Falcon-512 pubkey is 897 bytes — well under the cap.
        assert!(check_recipient_key_size(&vec![0u8; 897]).is_ok());
        // The canonical one-time key P encoding is 12316 bytes — under the cap.
        assert!(check_otk_size(&vec![0u8; 12_316]).is_ok());
        assert!(check_otk_size(&vec![0u8; MAX_OTK_BYTES]).is_ok());
        assert!(check_otks_size(&[vec![0u8; 12_316], vec![0u8; 12_316]]).is_ok());

        // Oversized blobs are rejected (state-bloat griefing).
        assert!(check_memo_size(&vec![0u8; MAX_MEMO_BYTES + 1]).is_err());
        assert!(check_memos_size(&[vec![0u8; 16], vec![0u8; MAX_MEMO_BYTES + 1]]).is_err());
        assert!(check_escrow_memo_size(&vec![0u8; MAX_ESCROW_MEMO_BYTES + 1]).is_err());
        assert!(check_recipient_key_size(&vec![0u8; MAX_RECIPIENT_KEY_BYTES + 1]).is_err());
        assert!(check_otk_size(&vec![0u8; MAX_OTK_BYTES + 1]).is_err());
        assert!(check_otks_size(&[vec![0u8; 16], vec![0u8; MAX_OTK_BYTES + 1]]).is_err());
    }
}
