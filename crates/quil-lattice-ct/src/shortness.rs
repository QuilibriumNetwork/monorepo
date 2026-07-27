//! Approximate-range (message-shortness) proof — the primitive that closes the
//! critical soundness gap in the accumulator membership argument.
//!
//! # Why it's needed
//!
//! The membership proof commits the gadget limbs as *messages* and only proves
//! the commitment *randomness* is short — so the limbs themselves are
//! unconstrained. But the `H_B` M-SIS binding needs them short (else a cheat
//! commits large limbs `x` with `B·x` hitting fabricated nodes that chain to the
//! real root → forged membership). This module proves a committed message vector
//! is short.
//!
//! # Construction
//!
//! For each message coordinate `m_i`, a structured opening proves knowledge of
//! short `(r, m_i)` with `(A1·r, A2[i]·r + m_i) = (C.t1, C.t2[i])`:
//! reveal `w = (A1·y_r, A2[i]·y_r + y_m)`, challenge `c`, responses
//! `z_r = y_r + c·r`, `z_m = y_m + c·m_i`, bounded-rejection. Verify
//! `A1·z_r = w1 + c·C.t1`, `A2[i]·z_r + z_m = w2 + c·C.t2[i]`, and `‖z‖ ≤ B`.
//! The special-soundness extractor yields `c̄·m_i = z_m − z_m'` of norm `≤ 2B`,
//! so `‖m_i‖` is bounded (relaxed) — an **approximate** range proof. A prover
//! with a large `m_i` cannot produce a bounded `z_m` (`‖c·m_i‖ ≫ B`), so the
//! proof does not exist.
//!
//! # ⚠ Parameter coupling and cost
//!
//! Per-coordinate rejection over `d=256` coefficients forces the mask (hence the
//! extracted norm `2B`) well above `τ·‖m_i‖`. That is only sound if the extracted
//! norm stays within the `H_B` M-SIS margin — which the estimator showed FAILS
//! at gadget base `b=2^14` (extracted `~2^22` → M-SIS `~2^12`) and HOLDS at
//! `b=2^7` (extracted `~2^20` → M-SIS `~2^183`). So wiring this into membership
//! requires the base reduction `2^14 → 2^7`. This per-element form is `O(ℓ)`
//! openings; MatRiCT+/LNP amortize it (the flagged optimization).
//!
//! # Opt C — projection amortization (unlocked by `q≈2^36`, not shipped)
//!
//! The `O(ℓ)` per-element cost can drop to `O(k)` by proving a few **random
//! projections** `⟨ρ_j, m⟩` are short instead of every coordinate. At the old
//! `q=2^28` this was infeasible — a projection of an `ℓ·d`-dim vector overflowed
//! `q`. The exact-slack re-parameterization to `q≈2^36` **enables it**: with
//! `ℓ≈438`, `‖m‖∞≤128`, a projection is `‖⟨ρ,m⟩‖∞ ≤ ℓ·d·1·128 ≈ 2^24 ≪ 2^36`, so
//! it no longer wraps. A naive union-bound needs `k≈92` projections (`2^-128`
//! error) — already `~4×` fewer openings than `ℓ`; the tight LNP/BLNS version
//! (Gaussian concentration, `‖⟨ρ,m⟩‖_2` estimates `‖m‖_2`) needs far fewer.
//! # Tight LNP — IMPLEMENTED as `prove/verify_projection_short` (2026-07-15)
//!
//! The tight version IS viable (see the reduction below). `prove_projection_short`
//! proves `‖m‖` short via `k` random ring-projections `⟨ρ_j, m⟩` (each a signed
//! sum of the `ℓ` limbs, so cheap adds), `O(k)` openings vs the per-element
//! `O(ℓ)`. Measured **16× prove / 6.6× verify** at `ℓ=128, k=16`; the win scales
//! `ℓ/k`.
//!
//! **Soundness parameters (the two swing factors from the evaluation):**
//! * **`k`:** each `ρ_j` catches a large coordinate iff `ρ_{j,k}≠0` (prob 2/3), so
//! `P[all k miss] = (1/3)^k`; a `2^-128` union bound over the `ℓ·d` coords needs
//! `k ≈ 92` — still `~7×` fewer than `ℓ≈657`.
//! * **challenge structure (the `2τ` question):** the reduction below shows a
//! *standalone* projection proof (independent FS challenge) gives the **double-
//! `τ`** H_B slack → M-SIS `2^124–2^146` at `q=2^36` (marginal, `≥128` only for
//! Gaussian `γ≤12`). Folding it under the membership's challenge (**shared**)
//! gives **single-`τ`** → M-SIS `2^215` (safe at `q=2^36`).
//!
//! **Reduction (why single vs double `τ`):** a forger's extracted limbs are
//! relaxed by the *main* opening's `c̄_main`; the standalone shortness proof bounds
//! a *different* relaxation `c̄_short`. The H_B collision `B·(x_f−x_r)=0` can only
//! be formed as `B·(c̄_short·c̄_main·(x_f−x_r))=0` — TWO challenge factors. Sharing
//! the challenge (`c̄_short=c̄_main`) collapses it to `c̄·(x_f−x_r)` — one factor.
//!
//! **Status:** the projection *mechanism* + the `2τ` reduction are done; the
//! `prove_projection_short` here is the standalone (double-`τ`) form. Making it the
//! membership DEFAULT safely needs the shared-challenge integration (single-`τ`,
//! safe at `q=2^36`) or `q=2^40`; until then the rigorous per-element form
//! (`prove_message_short`, batched in Opt A) stays the default — no soundness
//! regression on the money path.
//!
//! ---
//! **LNP concentration analysis DONE (2026-07-15) — the NAIVE (uniform-mask,
//! coord-wise) version is NOT safe:** The JL concentration is fine (`‖Rs‖₂ ≥ 6.28·‖s‖₂` at `2^-128`,
//! Monte-Carlo-confirmed). But the projected value `Rs` is *large* — a sum of
//! `n≈168k` terms, `‖Rs‖∞ ~ 2^17` — so proving it short via a masked opening
//! blows the extracted norm up (`mask ~ 2^29`, `ext‖s‖₂ ~ 2^31.6`), and after the
//! `2τ` challenge slack the H_B M-SIS solution norm is `~2^37.9 > q=2^36`
//! (BROKEN). Proving one *big* value costs more slack than proving many *small*
//! ones — so the per-element form (small limbs `≤128`, extracted `~2^20`, batched
//! in Opt A) is TIGHTER, not looser. A tight LNP (discrete-Gaussian masks +
//! range-proof amortized into the main protocol's rejection, not a separate
//! large-value opening) might fit but is the full framework and needs its own
//! re-analysis. Conclusion: keep the rigorous per-element shortness.

use sha2::{Digest, Sha256};

use crate::arith::SplitMix64;
use crate::module::{PolyMatrix, PolyVec, RingCommitKey, RingCommitment};
use crate::params::CHALLENGE_WEIGHT_TAU;
use crate::rq::Poly;

/// Parameters: `mask_bound` sized so per-coordinate rejection is feasible for
/// short messages (`‖m_i‖∞ ≤ msg_norm`); `eta` is the commitment-randomness norm.
#[derive(Clone, Debug)]
pub struct ShortnessParams {
    pub mask_bound: i64,
    pub eta: i64,
    pub tau: usize,
    /// Expected honest message-coordinate ∞-norm (drives the rejection bound).
    pub msg_norm: i64,
}
impl ShortnessParams {
    /// For gadget base `b = 2^7` limbs (`‖m_i‖∞ ≤ 127`): mask `2^19`, so the
    /// extracted norm `2·z_bound ≈ 2^20` — exactly the point the estimator
    /// certified `H_B` M-SIS `~2^183` at `b=2^7, δ=4`.
    pub fn base7() -> Self {
        ShortnessParams { mask_bound: 1 << 19, eta: crate::module::ETA, tau: CHALLENGE_WEIGHT_TAU, msg_norm: 128 }
    }
    fn z_bound(&self) -> u64 {
        (self.mask_bound - self.tau as i64 * self.msg_norm) as u64
    }
    fn zr_bound(&self) -> u64 {
        (self.mask_bound - self.tau as i64 * self.eta) as u64
    }
}

/// A per-coordinate short-opening.
#[derive(Clone, Debug)]
pub struct ElementOpening {
    pub w1: PolyVec, // A1·y_r (κ)
    pub w2: Poly,    // A2[i]·y_r + y_m
    pub z_r: PolyVec,
    pub z_m: Poly,
}

fn row_dot(row: &[Poly], v: &PolyVec) -> Poly {
    row.iter().zip(&v.0).fold(Poly::zero(), |acc, (a, x)| acc.add(&a.mul_ntt(x)))
}

fn el_challenge(ct1: &PolyVec, ct2_i: &Poly, w1: &PolyVec, w2: &Poly, tau: usize, aux: &[u8], idx: usize) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/shortness/v1");
    h.update((idx as u64).to_le_bytes());
    h.update((aux.len() as u64).to_le_bytes());
    h.update(aux);
    for p in ct1.0.iter().chain(w1.0.iter()).chain([ct2_i, w2]) {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let seed = h.finalize();
    let mut stream: Vec<u8> = Vec::new();
    let mut ctr = 0u32;
    let mut pos = 0usize;
    let mut next = |st: &mut Vec<u8>, p: &mut usize| -> u8 {
        if *p >= st.len() {
            let mut hh = Sha256::new();
            hh.update(seed);
            hh.update(ctr.to_le_bytes());
            st.extend_from_slice(&hh.finalize());
            ctr += 1;
        }
        let b = st[*p];
        *p += 1;
        b
    };
    let d = Poly::D;
    let mut c = vec![0i64; d];
    for i in (d - tau)..d {
        let j = loop {
            let b = next(&mut stream, &mut pos) as usize;
            if b <= i {
                break b;
            }
        };
        c[i] = c[j];
        c[j] = if next(&mut stream, &mut pos) & 1 == 1 { 1 } else { -1 };
    }
    Poly::from_signed(&c)
}

/// Prove `⟨a2_row, r⟩ + m_val = ct2` opens to a SHORT `m_val` against `C.t1=ct1`,
/// `A1=a1` (the operand is a linear view of the message — a single coordinate for
/// the per-element proof, or a `ρ`-weighted projection for the tight LNP proof).
#[allow(clippy::too_many_arguments)]
fn prove_element(
    a1: &PolyMatrix,
    a2_row: &[Poly],
    ct1: &PolyVec,
    ct2_i: &Poly,
    m_val: &Poly,
    r: &PolyVec,
    p: &ShortnessParams,
    aux: &[u8],
    idx: usize,
    seed: u64,
) -> Option<ElementOpening> {
    for attempt in 0..8000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x5A17));
        let y_r = PolyVec::sample_uniform_pm(a1.cols, p.mask_bound, &mut prg);
        let y_m = PolyVec::sample_uniform_pm(1, p.mask_bound, &mut prg).0[0].clone();
        let w1 = a1.matvec(&y_r);
        let w2 = row_dot(a2_row, &y_r).add(&y_m);
        let c = el_challenge(ct1, ct2_i, &w1, &w2, p.tau, aux, idx);
        let z_r = y_r.add(&r.mul_poly(&c));
        let z_m = y_m.add(&c.mul_ntt(m_val));
        if z_r.inf_norm() <= p.zr_bound() && z_m.inf_norm() <= p.z_bound() {
            return Some(ElementOpening { w1, w2, z_r, z_m });
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn verify_element(
    a1: &PolyMatrix,
    a2_row: &[Poly],
    ct1: &PolyVec,
    ct2_i: &Poly,
    o: &ElementOpening,
    p: &ShortnessParams,
    aux: &[u8],
    idx: usize,
) -> bool {
    if o.z_r.inf_norm() > p.zr_bound() || o.z_m.inf_norm() > p.z_bound() {
        return false;
    }
    let c = el_challenge(ct1, ct2_i, &o.w1, &o.w2, p.tau, aux, idx);
    if a1.matvec(&o.z_r) != o.w1.add(&ct1.mul_poly(&c)) {
        return false;
    }
    row_dot(a2_row, &o.z_r).add(&o.z_m) == o.w2.add(&c.mul_ntt(ct2_i))
}

/// Prove the whole committed message vector `m` is short (‖m_i‖∞ ≤ ~2B each).
pub fn prove_message_short(
    ck: &RingCommitKey,
    c: &RingCommitment,
    m: &[Poly],
    r: &PolyVec,
    p: &ShortnessParams,
    aux: &[u8],
    seed: u64,
) -> Option<Vec<ElementOpening>> {
    let mut out = Vec::with_capacity(m.len());
    for (i, m_i) in m.iter().enumerate() {
        out.push(prove_element(&ck.a1, &ck.a2.m[i], &c.t1, &c.t2.0[i], m_i, r, p, aux, i, seed ^ i as u64)?);
    }
    Some(out)
}

/// Like [`verify_message_short`] but does only the cheap per-element checks
/// (`row_dot` binding + norms) inline, pushing the expensive `a1·z_r = rhs`
/// opening checks (which all share `ck.a1`) into a batch buffer so a whole
/// block's shortness matvecs collapse into one [`crate::sigma_rq::batch_matvec_eq`].
pub fn verify_message_short_collect(
    ck: &RingCommitKey,
    c: &RingCommitment,
    openings: &[ElementOpening],
    p: &ShortnessParams,
    aux: &[u8],
    a1_items: &mut Vec<(PolyVec, PolyVec)>,
) -> bool {
    if openings.len() != c.t2.0.len() {
        return false;
    }
    for (i, o) in openings.iter().enumerate() {
        if o.z_r.inf_norm() > p.zr_bound() || o.z_m.inf_norm() > p.z_bound() {
            return false;
        }
        let ch = el_challenge(&c.t1, &c.t2.0[i], &o.w1, &o.w2, p.tau, aux, i);
        // Cheap binding check (row_dot + z_m) inline.
        if row_dot(&ck.a2.m[i], &o.z_r).add(&o.z_m) != o.w2.add(&ch.mul_ntt(&c.t2.0[i])) {
            return false;
        }
        // Batchable shared-a1 opening check.
        a1_items.push((o.z_r.clone(), o.w1.add(&c.t1.mul_poly(&ch))));
    }
    true
}

/// Verify a message-shortness proof.
pub fn verify_message_short(
    ck: &RingCommitKey,
    c: &RingCommitment,
    openings: &[ElementOpening],
    p: &ShortnessParams,
    aux: &[u8],
) -> bool {
    if openings.len() != c.t2.0.len() {
        return false;
    }
    openings
        .iter()
        .enumerate()
        .all(|(i, o)| verify_element(&ck.a1, &ck.a2.m[i], &c.t1, &c.t2.0[i], o, p, aux, i))
}

// ── Tight LNP: ring-projection shortness (Opt C', O(ℓ) → O(k)) ────────────────

/// Projection parameters: like [`ShortnessParams`] but the masked value is the
/// projection `⟨ρ, m⟩` (a `ρ`-weighted sum of `ℓ` limbs), so `msg_norm` is sized
/// for `‖⟨ρ, m⟩‖∞ ≤ (2ℓ/3)·128` (ternary `ρ`, ~2/3 nonzero).
#[derive(Clone, Debug)]
pub struct ProjectionParams {
    pub inner: ShortnessParams,
    /// Number of independent projections `k` (each a ternary `ρ_j ∈ {-1,0,1}^ℓ`).
    pub k: usize,
}
impl ProjectionParams {
    /// For a message of `ell` limbs (`‖m_i‖∞ ≤ 128`), with `k` projections.
    pub fn for_message(ell: usize, k: usize) -> Self {
        let proj_norm = (2 * ell as i64 / 3) * 128; // worst-case ‖⟨ρ,m⟩‖∞
        let mask_bound = (128i64) * CHALLENGE_WEIGHT_TAU as i64 * proj_norm; // C·τ·‖proj‖
        ProjectionParams {
            inner: ShortnessParams {
                mask_bound,
                eta: crate::module::ETA,
                tau: CHALLENGE_WEIGHT_TAU,
                msg_norm: proj_norm,
            },
            k,
        }
    }
}

/// Derive `k` ternary scalar projection vectors `ρ_j ∈ {-1,0,1}^ℓ` from the
/// commitment + aux (Fiat-Shamir; public, so verifier re-derives identically).
fn derive_rhos(c: &RingCommitment, k: usize, ell: usize, aux: &[u8]) -> Vec<Vec<i8>> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/lnp-projection/v1");
    h.update((k as u64).to_le_bytes());
    h.update((ell as u64).to_le_bytes());
    h.update((aux.len() as u64).to_le_bytes());
    h.update(aux);
    for p in c.t1.0.iter().chain(&c.t2.0) {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let seed = h.finalize();
    let mut out = Vec::with_capacity(k);
    for j in 0..k {
        let mut row = Vec::with_capacity(ell);
        let mut ctr = j as u32;
        let mut stream: Vec<u8> = Vec::new();
        let mut pos = 0usize;
        while row.len() < ell {
            if pos >= stream.len() {
                let mut hh = Sha256::new();
                hh.update(seed);
                hh.update(ctr.to_le_bytes());
                stream.extend_from_slice(&hh.finalize());
                ctr = ctr.wrapping_add(0x1000);
            }
            row.push((stream[pos] % 3) as i8 - 1); // {-1,0,1}
            pos += 1;
        }
        out.push(row);
    }
    out
}

/// `Σ ρ_i · v[i]` (ternary `ρ`, so signed adds — no multiply).
fn weighted_sum(rho: &[i8], v: &[Poly]) -> Poly {
    let mut acc = Poly::zero();
    for (&s, p) in rho.iter().zip(v) {
        if s == 1 {
            acc = acc.add(p);
        } else if s == -1 {
            acc = acc.sub(p);
        }
    }
    acc
}
/// `Σ ρ_i · A2[i]` — the `ρ`-weighted key-row (a `λ`-vector).
fn weighted_row(rho: &[i8], a2: &PolyMatrix) -> Vec<Poly> {
    let mut acc = vec![Poly::zero(); a2.cols];
    for (&s, r) in rho.iter().zip(&a2.m) {
        if s == 1 {
            for (a, x) in acc.iter_mut().zip(r) {
                *a = a.add(x);
            }
        } else if s == -1 {
            for (a, x) in acc.iter_mut().zip(r) {
                *a = a.sub(x);
            }
        }
    }
    acc
}

/// Tight-LNP shortness: prove the committed `m` is short via `k` random-projection
/// openings (`‖⟨ρ_j, m⟩‖` short ⇒ `‖m‖` short by JL concentration) — `O(k)` vs the
/// `O(ℓ)` per-element proof. See the module docs for the safety analysis.
pub fn prove_projection_short(
    ck: &RingCommitKey,
    c: &RingCommitment,
    m: &[Poly],
    r: &PolyVec,
    p: &ProjectionParams,
    aux: &[u8],
    seed: u64,
) -> Option<Vec<ElementOpening>> {
    let rhos = derive_rhos(c, p.k, m.len(), aux);
    let mut out = Vec::with_capacity(p.k);
    for (j, rho) in rhos.iter().enumerate() {
        let a2_row = weighted_row(rho, &ck.a2);
        let ct2 = weighted_sum(rho, &c.t2.0);
        let mval = weighted_sum(rho, m);
        out.push(prove_element(&ck.a1, &a2_row, &c.t1, &ct2, &mval, r, &p.inner, aux, j, seed ^ j as u64)?);
    }
    Some(out)
}

/// Verify a projection-shortness proof.
pub fn verify_projection_short(
    ck: &RingCommitKey,
    c: &RingCommitment,
    ell: usize,
    openings: &[ElementOpening],
    p: &ProjectionParams,
    aux: &[u8],
) -> bool {
    if openings.len() != p.k {
        return false;
    }
    let rhos = derive_rhos(c, p.k, ell, aux);
    rhos.iter().zip(openings).enumerate().all(|(j, (rho, o))| {
        let a2_row = weighted_row(rho, &ck.a2);
        let ct2 = weighted_sum(rho, &c.t2.0);
        verify_element(&ck.a1, &a2_row, &c.t1, &ct2, o, &p.inner, aux, j)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ETA;

    fn short_poly(prg: &mut SplitMix64, bound: i64) -> Poly {
        Poly::from_signed(&(0..Poly::D).map(|_| prg.uniform_pm(bound as i128) as i64).collect::<Vec<_>>())
    }

    #[test]
    fn short_message_verifies() {
        // A message of short (≤128, base-2^7-scale) coordinates: the shortness
        // proof verifies.
        let ell = 6;
        let ck = RingCommitKey::production(ell, 0x5401);
        let mut prg = SplitMix64::new(1);
        let m: Vec<Poly> = (0..ell).map(|_| short_poly(&mut prg, 128)).collect();
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);
        let p = ShortnessParams::base7();
        let pf = prove_message_short(&ck, &c, &m, &r, &p, b"", 7).expect("short message proves");
        assert!(verify_message_short(&ck, &c, &pf, &p, b""));
    }

    #[test]
    fn large_coordinate_is_unprovable() {
        // The gap-1 protection: a message with one LARGE coordinate cannot be
        // proven short — ‖c·m_i‖ ≫ mask, so no bounded z_m exists.
        let ell = 4;
        let ck = RingCommitKey::production(ell, 0x5402);
        let mut prg = SplitMix64::new(2);
        let mut m: Vec<Poly> = (0..ell).map(|_| short_poly(&mut prg, 128)).collect();
        m[2].c[0] = 1 << 24; // a large limb — the forgery vector
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);
        let p = ShortnessParams::base7();
        // The prover cannot produce a valid shortness proof for the large coord.
        assert!(prove_message_short(&ck, &c, &m, &r, &p, b"", 9).is_none(), "large limb unprovable");
    }

    #[test]
    fn projection_short_completeness_and_is_o_k() {
        // Tight LNP: k projection openings instead of ℓ per-element — a short
        // message verifies, and the proof is O(k) with k ≪ ℓ.
        let ell = 40;
        let k = 4;
        let ck = RingCommitKey::production(ell, 0x7401);
        let mut prg = SplitMix64::new(1);
        let m: Vec<Poly> = (0..ell).map(|_| short_poly(&mut prg, 128)).collect();
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);
        let p = ProjectionParams::for_message(ell, k);
        let pf = prove_projection_short(&ck, &c, &m, &r, &p, b"", 7).expect("short message proves");
        assert_eq!(pf.len(), k, "O(k) openings, not O(ℓ={ell})");
        assert!(verify_projection_short(&ck, &c, ell, &pf, &p, b""));
    }

    #[test]
    fn projection_catches_large_message() {
        // A message that is large in many coordinates makes the random
        // projections large ⇒ unprovable (the JL soundness direction).
        let ell = 40;
        let k = 4;
        let ck = RingCommitKey::production(ell, 0x7402);
        let mut prg = SplitMix64::new(2);
        let m: Vec<Poly> = (0..ell)
            .map(|i| if i % 2 == 0 { let mut p = Poly::zero(); p.c[0] = 1 << 24; p } else { short_poly(&mut prg, 128) })
            .collect();
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);
        let p = ProjectionParams::for_message(ell, k);
        assert!(prove_projection_short(&ck, &c, &m, &r, &p, b"", 9).is_none(), "large message unprovable");
    }

    #[test]
    #[ignore] // timing; run with --ignored --nocapture --release
    fn projection_vs_per_element_timing() {
        use std::time::Instant;
        let ell = 128; // ~ a shallow membership witness
        let ck = RingCommitKey::production(ell, 0x7403);
        let mut prg = SplitMix64::new(3);
        let m: Vec<Poly> = (0..ell).map(|_| short_poly(&mut prg, 128)).collect();
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);

        let sp = ShortnessParams::base7();
        let t0 = Instant::now();
        let pe = prove_message_short(&ck, &c, &m, &r, &sp, b"", 1).unwrap();
        let t_pe = t0.elapsed().as_secs_f64() * 1000.0;
        let t1 = Instant::now();
        assert!(verify_message_short(&ck, &c, &pe, &sp, b""));
        let v_pe = t1.elapsed().as_secs_f64() * 1000.0;

        for k in [16usize, 32] {
            let pp = ProjectionParams::for_message(ell, k);
            let t2 = Instant::now();
            let pj = prove_projection_short(&ck, &c, &m, &r, &pp, b"", 2).unwrap();
            let t_pj = t2.elapsed().as_secs_f64() * 1000.0;
            let t3 = Instant::now();
            assert!(verify_projection_short(&ck, &c, ell, &pj, &pp, b""));
            let v_pj = t3.elapsed().as_secs_f64() * 1000.0;
            println!(
                "ell={ell}: per-element(ℓ) prove {t_pe:.0}ms verify {v_pe:.0}ms  |  \
                 projection(k={k}) prove {t_pj:.0}ms verify {v_pj:.0}ms  \
                 (prove {:.1}×, verify {:.1}×)",
                t_pe / t_pj,
                v_pe / v_pj
            );
        }
    }

    #[test]
    fn tampered_opening_rejected() {
        let ell = 3;
        let ck = RingCommitKey::production(ell, 0x5403);
        let mut prg = SplitMix64::new(3);
        let m: Vec<Poly> = (0..ell).map(|_| short_poly(&mut prg, 100)).collect();
        let r = PolyVec::sample_short(ck.a1.cols, ETA, &mut prg);
        let c = ck.commit(&PolyVec(m.clone()), &r);
        let p = ShortnessParams::base7();
        let mut pf = prove_message_short(&ck, &c, &m, &r, &p, b"", 4).unwrap();
        pf[1].z_m.c[0] ^= 1;
        assert!(!verify_message_short(&ck, &c, &pf, &p, b""));
    }
}
