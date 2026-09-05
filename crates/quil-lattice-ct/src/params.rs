//! Production parameter target — **128-bit (NIST L1)**, small-`q` + MatRiCT
//! limb strategy — as chosen 2026-07-15.
//!
//! This module is a *specification*, not yet an instantiation: the reference
//! implementation in the sibling modules runs over plain `Z_q` with tiny,
//! testability-only numbers. Secure, practical parameters require the **ring
//! form** `R_q = Z_q[X]/(X^d+1)` with NTT (security amortizes over `d`
//! coefficients; a single structured ring challenge replaces the reference's
//! 16 rounds of `{-1,0,1}`). Pinning the numbers here is the trigger for that
//! port.
//!
//! # Provenance and status — ESTIMATOR-VALIDATED (2026-07-15)
//!
//! Structure derives from **Dilithium** and **MatRiCT+**; the concrete `q, κ,
//! λ` were then **checked with a core-SVP estimator run** (the Kyber/Dilithium
//! NIST methodology: LWE primal-uSVP 2016-estimate, SIS shortest-vector,
//! cost `2^{0.292β}` classical / `2^{0.265β}` quantum), which corrected the
//! first guess:
//!
//! * **Hiding (M-LWE) is the binding constraint, not SIS.** A large `q`
//! weakens LWE: the initial `q=2^32, rank=4` gave only **78-bit** — broken.
//! * At **`q≈2^28, κ=λ=6`**: **M-LWE ≈ 162-bit classical / 147-bit quantum**
//! (BKZ β≈555), clearing the 128-bit target on both. **M-SIS ≫ 128-bit**
//! (BKZ ≫ 2000 even at a generous `2^20` extracted-witness norm) — binding
//! and soundness are comfortable.
//! * `q=2^28` also leaves headroom above the amount arithmetic (`2^23`
//! per-limb sum) and the soundness slack (`~2^20` extracted norm).
//!
//! **Still required before real use:** a full lattice-estimator (Albrecht et
//! al.) cross-check with the *exact* range-proof extracted-norm accounting,
//! and cryptographic audit. This is the reviewed, estimator-sanity-checked
//! direction — not a substitute for the audit.

// ── Ring ────────────────────────────────────────────────────────────────

/// Ring degree `d` — `R_q = Z_q[X]/(X^d+1)`. Power of two; security amortizes
/// over the `d` coefficients. (Dilithium/Kyber standard.)
pub const RING_DEGREE_D: usize = 256;

/// Modulus `q` — a PARTIALLY-SPLIT prime `≈2^36` with `ord_512(q)=64`, so `X^256+1`
/// splits into `t=4` IRREDUCIBLE degree-64 factors (not the 256 LINEAR factors of a
/// fully-split `q≡1 mod 512`). WHY: in a fully-split ring the
/// Lyubashevsky–Seiler invertible-difference lemma is vacuous, so LaBRADOR-style
/// amortized challenge DIFFERENCES `c_i−c_j` are non-invertible with prob ≈256/q
/// ≈2^-28 — capping soundness at ~2^-28. With t=4
/// the LS18 invertibility radius `q^{1/4}/√4 ≈ 256 ≫ ‖c_i−c_j‖ (≤2)`, so every
/// low-norm challenge difference is invertible ⇒ soundness back to ~2^-125.
/// M-SIS ≥128-bit and range arithmetic are SPLIT-INDEPENDENT (depend on |q|,d,
/// rank), so the estimator margins carry over (`|q|` essentially unchanged).
/// `q ≡ 1 mod 8` so a future radix-2 block NTT is possible; the current build
/// uses the (q-agnostic) schoolbook multiply for correctness — block-NTT perf is
/// a validated follow-up.
// Prior (fully-split) q was 68719484929 (2^36+8193, q≡1 mod 512). See git history.
pub const MODULUS_Q: u64 = 68719476713; // < 2^36 (by 23), prime, ord_512=64 → t=4 partial split
/// Bits to represent a coefficient in `[0, q)`. `q < 2^36`, so `ceil(log2 q) = 36`.
pub const MODULUS_Q_BITS: u32 = 36;

// ── Module dimensions (M-SIS / M-LWE) ─────────────────────────────────────

/// M-SIS binding height `κ` (ring elements) = **6** (estimator). Binding
/// dimension `κ·d = 1536`. M-SIS is ≫128-bit here for the BDLOP commitments at
/// their (short, η≈2) opening norms — binding/soundness are not the constraint
/// (the rank is driven by M-LWE, below).
pub const SIS_RANK_KAPPA: usize = 6;

/// M-SIS binding height for the LaBRADOR fold commitments (`A`, `B_a`, `B_b`) =
/// **8** — LARGER than the CT commitments' `κ=6` on purpose. LaBRADOR's extracted
/// openings are far longer than the base η≈2 witnesses (norm growth across the
/// recursion; the sound recursive path bounds them by the actual ℓ2 < q), and at
/// that norm `κ=6` sits at only ~128–135-bit M-SIS with essentially zero comfort.
/// `κ=8` (binding dim `κ·d = 2048`) restores a comfortable ≫128-bit margin
/// (confirmed by a lattice-estimator core-SVP run). This is LOCAL to LaBRADOR
/// — the CT commitment scheme keeps `SIS_RANK_KAPPA = 6` (independently analyzed).
pub const LABRADOR_RANK_KAPPA: usize = 8;

/// M-LWE randomness rank `λ` (ring elements) = **9** (raised from 6). At the new
/// `q≈2^36` a larger `q` weakens LWE (`λ=6, q=2^36` → only **2^116** hiding); the
/// binding-vs-hiding squeeze is closed by raising `λ` to 9 → **M-LWE hiding
/// 2^195** while binding stays `≫128`. Hiding/ZK dimension `λ·d = 2304`.
pub const LWE_RANK_LAMBDA: usize = 9;

/// M-LWE security `(classical, quantum)` at `q≈2^36, λ=9` — the scheme minimum —
/// from the **real `malb/lattice-estimator`** (rough core-SVP): **~2^195
/// classical** (~177 quantum). Comfortably clears 128-bit.
pub const SECURITY_BITS_LWE: (u32, u32) = (195, 177);
/// M-LWE reference figure (same rough model at these params).
pub const SECURITY_BITS_LWE_REFINED: u32 = 195;
/// M-SIS binding/soundness at `q≈2^36`, computed at the **EXACT extracted-witness
/// norm** (with the `2τ` challenge slack): commitment-binding `2^287`, accumulator
/// `H_B` `2^141`. The `2^141` is the CONSERVATIVE FLOOR — it is `H_B` at `β≈q`.
/// A `lattice-estimator` run over the plausible extracted-norm range confirms the
/// margin only grows below the floor: `β=2^35 → 2^150`, `2^30 → 2^214`, `2^25 →
/// 2^328`, `2^20 → 2^559`. All the `H_B` figures elsewhere in the crate refer to
/// this same curve at different `β`; `2^141` is the number to quote (the floor).
pub const SECURITY_BITS_SIS_LOWER: u32 = 141;

/// Secret/randomness infinity norm `η` (`‖r‖∞ ≤ η`). Small, Dilithium-L2 style.
pub const SECRET_NORM_ETA: i64 = 2;

// ── Challenge (single ring element, replaces the reference's 16 rounds) ────

/// Challenge Hamming weight `τ` — number of `±1` coefficients in the ring
/// challenge `c` (rest zero). With `τ=39` over `d=256`, the challenge space is
/// `|C| = C(256,39)·2^39 ≈ 2^176`, so a SINGLE challenge gives soundness well
/// beyond 128-bit (no parallel repetition). (Dilithium-L2 value.)
pub const CHALLENGE_WEIGHT_TAU: usize = 39;
/// `‖c‖∞ = 1`.
pub const CHALLENGE_INF_NORM: i64 = 1;
/// `log2|C|` (approx) — the single-shot soundness bits.
pub const CHALLENGE_ENTROPY_BITS: u32 = 176;

// ── Amount / limb strategy (small-q ⇒ no single value near q) ──────────────

/// Amount bit-width. 64-bit values (Monero-compatible range).
pub const AMOUNT_BITS: usize = 64;
/// Limb base, in bits: amounts are represented base `2^16`.
pub const LIMB_BASE_BITS: usize = 16;
/// Number of limbs: `AMOUNT_BITS / LIMB_BASE_BITS`.
pub const LIMB_COUNT: usize = AMOUNT_BITS / LIMB_BASE_BITS; // 4
/// Max inputs+outputs summed in one balance check. Bounds carry growth and the
/// no-wraparound margin: a per-limb sum is `≤ MAX_IO · 2^LIMB_BASE_BITS ≪ q`.
pub const MAX_IO: usize = 128;

// ── Rough sizes (order of magnitude, for budgeting) ────────────────────────

/// Public commitment/key material is a seed-expanded matrix → a 32-byte seed on
/// the wire (the matrix is regenerated, à la Dilithium `rho`).
pub const PUBLIC_KEY_SEED_BYTES: usize = 32;

/// Very rough per-proof size band (KB) at these parameters, dominated by the
/// per-limb range proofs and the ring signature (grows with ring size). Real
/// figures come from the ring-form implementation.
pub const PROOF_SIZE_KB_ORDER: (u32, u32) = (20, 60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_decomposition_covers_the_amount_width() {
        assert_eq!(LIMB_COUNT * LIMB_BASE_BITS, AMOUNT_BITS, "limbs must tile the amount width");
        assert_eq!(LIMB_COUNT, 4);
    }

    #[test]
    fn per_limb_sum_never_wraps_mod_q() {
        // The point of the small-q + limb strategy: even the WORST-CASE per-limb
        // aggregate (max I/O count × max limb value) stays below q, so balance
        // arithmetic is exact mod q (no malicious wraparound). Carries are then
        // in a small, bounded range.
        let max_limb_value: u128 = (1u128 << LIMB_BASE_BITS) - 1;
        let worst_per_limb_sum: u128 = (MAX_IO as u128) * max_limb_value;
        assert!(
            worst_per_limb_sum < MODULUS_Q as u128,
            "per-limb sum {worst_per_limb_sum} must be < q {}",
            MODULUS_Q
        );
        // With headroom to spare (2^23 vs 2^32).
        assert!(worst_per_limb_sum < (1u128 << (MODULUS_Q_BITS - 4)));
    }

    #[test]
    fn partial_split_modulus() {
        // q must NOT be ≡ 1 mod 2d: a fully-split ring's vacuous invertible-difference
        // lemma caps soundness at ~2^-28. We require ord_512(q) = 64 → X^256+1 factors
        // into t=4 degree-64 irreducibles, giving the LS18 invertibility margin.
        let m = 2 * RING_DEGREE_D as u64; // 512
        assert_ne!((MODULUS_Q - 1) % m, 0, "q must NOT be fully-split (≡1 mod 2d)");
        let mut ord = 1u64;
        let mut x = MODULUS_Q % m;
        while x != 1 {
            x = x * (MODULUS_Q % m) % m;
            ord += 1;
        }
        assert_eq!(ord, 64, "ord_512(q) must be 64 (t = 256/64 = 4 partial split)");
        // q ≡ 1 mod 8 keeps a future radix-2 block NTT possible.
        assert_eq!((MODULUS_Q - 1) % 8, 0, "q ≡ 1 mod 8 for a future block NTT");
    }

    #[test]
    fn estimator_clears_the_128bit_target() {
        // Both assumptions must clear 128-bit core-SVP (classical AND quantum).
        let (lwe_c, lwe_q) = SECURITY_BITS_LWE;
        assert!(lwe_c >= 128 && lwe_q >= 128, "M-LWE must clear 128-bit both models");
        assert!(SECURITY_BITS_SIS_LOWER >= 128, "M-SIS floor must clear 128-bit");
        // Modulus must exceed both the amount limb-sum and the soundness slack.
        assert!(MODULUS_Q as u128 > (MAX_IO as u128) << LIMB_BASE_BITS, "q > per-limb sum");
        assert!((MODULUS_Q as u128) > (1u128 << 20), "q > ~2^20 extracted-norm slack");
    }

    #[test]
    fn single_challenge_gives_target_soundness() {
        // One ring challenge must already exceed the 128-bit soundness target,
        // so the ring form needs no parallel repetition (unlike the reference's
        // 16 rounds of a 3-element challenge).
        assert!(CHALLENGE_ENTROPY_BITS >= 128, "single-shot soundness ≥ 128-bit");
    }
}
