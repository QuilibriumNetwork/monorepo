//! LaBRADOR (Beullens–Seiler, CRYPTO 2023) — compact proofs for module-SIS
//! dot-product relations, the path to ~tens-of-KB confidential transactions.
//!
//! # The relation
//!
//! Prove knowledge of a SHORT witness `s = (s₀,…,s_{r-1})`, each `sᵢ ∈ R_q^n`,
//! `‖s‖∞ ≤ β`, satisfying a family of QUADRATIC dot-product constraints
//! ```text
//!   for each k:   Σ_{i,j} a⁽ᵏ⁾_{ij} · ⟨sᵢ, sⱼ⟩  =  b⁽ᵏ⁾     (in R_q)
//! ```
//! where `⟨u,v⟩ = Σ_l u_l·v_l` (ring-valued, bilinear). Linear/affine terms are
//! homogenized the standard R1CS way: fix `s₀ = 1` (the public all-ones vector),
//! then `⟨φ, sᵢ⟩` is the quadratic term `a_{0,i}=φ` and constants ride `s₀`.
//!
//! # One reduction round (this file)
//!
//! Prover sends inner Ajtai commitments `tᵢ = A·sᵢ`, the quadratic **garbage**
//! `gᵢⱼ = ⟨sᵢ,sⱼ⟩` (symmetric), and the **fold** `z = Σ cᵢ·sᵢ` for verifier
//! challenges `cᵢ` (SampleInBall). Verifier checks:
//! 1. `A·z = Σ cᵢ·tᵢ`  — binds `z` to a `c`-combination of the COMMITTED `sᵢ`
//!    (M-SIS binding of `A`).
//! 2. `⟨z,z⟩ = Σ_{i,j} cᵢ·cⱼ·gᵢⱼ`  — the amortized quadratic check: since
//!    `⟨z,z⟩ = Σ cᵢcⱼ⟨sᵢ,sⱼ⟩`, a cheating `g ≠ ⟨sᵢ,sⱼ⟩` passes only if a degree-2
//!    polynomial in the (unpredictable) `c` vanishes — prob `≤ 2/|C|` per the
//!    invertible-difference lemma. So `g` is bound to the true pairwise products.
//! 3. `Σ a⁽ᵏ⁾_{ij} gᵢⱼ = b⁽ᵏ⁾` for each constraint — the constraints hold on the
//!    real witness (via the now-bound `g`).
//! 4. `‖z‖∞ ≤ ` a bound `≈ r·τ·β` (relaxed norm; the full JL-projection norm
//!    proof of `s` — reuse `shortness::prove_projection_short` — is folded in at
//!    Phase D).
//!
//! In this round `g` (r² ring elts) and `z` (n) are revealed DIRECTLY, so the
//! size is O(r²+n) — NOT yet compressed. The compression is Phase D: `(t,g,z)`
//! become the witness of a SMALLER LaBRADOR instance, recursed to ~KB.

use sha2::{Digest, Sha256};

use crate::arith::SplitMix64;
use crate::module::{PolyMatrix, PolyVec, RingCommitKey, RingCommitment};
use crate::params::{CHALLENGE_WEIGHT_TAU, RING_DEGREE_D, SECRET_NORM_ETA};
use crate::rq::Poly;

/// One dot-product constraint in the paper's eq. (6) form
/// `Σ a_{ij}·⟨s_i,s_j⟩ + Σ ⟨φ_i, s_i⟩ = b` (in `R_q`). The quadratic part is
/// `terms` (`i ≤ j`, symmetric); the LINEAR part is `linear` — a sparse list of
/// `(i, φ_i)` with `φ_i ∈ R_q^{n}`. Pure-quadratic constraints (the base
/// relation) have `linear = []`; the child constraints produced by the §5.3
/// recursion (checks (1),(2), the aggregated statement) are mostly linear.
#[derive(Clone)]
pub struct QuadConstraint {
    /// Sparse `(i, j, a_{ij})` terms; `i ≤ j` (the pair is symmetric).
    pub terms: Vec<(usize, usize, Poly)>,
    /// CONJUGATED quadratic terms `Σ a·⟨σ(s_i), s_j⟩` (NOT symmetric). Empty for
    /// all plain constraints; populated only by the conjugation-aware child
    /// binding (`build_child_constraints`) so ct-constraints survive the fold.
    pub conj_terms: Vec<(usize, usize, Poly)>,
    /// Sparse `(i, φ_i)` linear terms; `Σ_i ⟨φ_i, s_i⟩`.
    pub linear: Vec<(usize, PolyVec)>,
    pub b: Poly,
}

impl QuadConstraint {
    /// A pure-quadratic constraint (no linear part) — the base relation.
    pub fn quad(terms: Vec<(usize, usize, Poly)>, b: Poly) -> Self {
        QuadConstraint { terms, conj_terms: Vec::new(), linear: Vec::new(), b }
    }
}

/// The public statement: the Ajtai matrix, dimensions, constraints, norm bound.
pub struct Statement {
    pub a_mat: PolyMatrix, // κ × n
    pub r: usize,
    pub n: usize,
    pub constraints: Vec<QuadConstraint>,
    pub beta: u64, // ‖s‖∞ bound
}

/// The secret witness: `r` vectors of dim `n`, each short.
pub struct Witness {
    pub s: Vec<PolyVec>,
}

/// A single-round reduction proof (pre-recursion).
pub struct ReductionProof {
    pub t: Vec<PolyVec>,  // inner commitments tᵢ = A·sᵢ (κ each)
    pub g: Vec<Vec<Poly>>, // symmetric garbage gᵢⱼ = ⟨sᵢ,sⱼ⟩
    pub z: PolyVec,        // folded witness Σ cᵢ·sᵢ (dim n)
}

/// Ring dot product `⟨u,v⟩ = Σ_l u_l·v_l`.
pub fn dot(u: &PolyVec, v: &PolyVec) -> Poly {
    let mut acc = Poly::zero();
    for (a, b) in u.0.iter().zip(&v.0) {
        acc = acc.add(&a.mul_ntt(b));
    }
    acc
}

/// Sample `r` SampleInBall ring challenges (weight τ, ±1) from a transcript.
fn fold_challenges(a_mat: &PolyMatrix, t: &[PolyVec], g: &[Vec<Poly>], r: usize) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/fold/v1");
    for row in &a_mat.m {
        for p in row {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for ti in t {
        for p in &ti.0 {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for gi in g {
        for p in gi {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let seed = h.finalize();
    let mut prg = HashPrg::from_digest(&seed);
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// A u64 stream. Both the fast non-crypto `SplitMix64` (witness/matrix sampling)
/// and the wide-state `HashPrg` (Fiat-Shamir challenges) provide it.
trait RngU64 {
    fn next_u64(&mut self) -> u64;
}
impl RngU64 for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        SplitMix64::next_u64(self)
    }
}

/// Wide-state Fiat-Shamir PRG: SHA-256 counter mode keyed by the FULL 256-bit
/// transcript digest. This replaces seeding SplitMix64 from `digest[..8]`, which
/// capped challenge entropy (and thus FS soundness) at 2^64 regardless of the
/// ring challenge space. Here the whole 256-bit digest keys the stream.
struct HashPrg {
    key: [u8; 32],
    ctr: u64,
    buf: [u8; 32],
    off: usize,
}
impl HashPrg {
    fn from_digest(digest: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/labrador/fs-prg/v1");
        h.update(digest);
        HashPrg { key: h.finalize().into(), ctr: 0, buf: [0u8; 32], off: 32 }
    }
    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(self.ctr.to_le_bytes());
        self.buf = h.finalize().into();
        self.ctr += 1;
        self.off = 0;
    }
}
impl RngU64 for HashPrg {
    fn next_u64(&mut self) -> u64 {
        if self.off + 8 > 32 {
            self.refill();
        }
        let v = u64::from_le_bytes(self.buf[self.off..self.off + 8].try_into().unwrap());
        self.off += 8;
        v
    }
}

/// A weight-`tau` ternary ring element (`±1` at τ pseudo-random positions).
/// With the partially-split modulus (t=4), the Lyubashevsky–Seiler
/// invertible-difference lemma applies (radius `q^{1/4}/√4 ≈ 256 ≫ ‖c−c'‖ ≤ 2`),
/// so every low-weight challenge AND every pairwise difference is invertible in
/// `R_q` — no rejection sampling needed (a fully-split ring's 2⁻²⁸ grinding hole
/// is closed at the parameter level; see params.rs).
fn sample_in_ball<R: RngU64>(prg: &mut R, tau: usize) -> Poly {
    let d = RING_DEGREE_D;
    let mut c = vec![0i64; d];
    let mut placed = 0;
    while placed < tau {
        let idx = (prg.next_u64() as usize) % d;
        if c[idx] == 0 {
            c[idx] = if prg.next_u64() & 1 == 1 { 1 } else { -1 };
            placed += 1;
        }
    }
    Poly::from_signed(&c)
}

// ── Recursion primitives (Phase D toolkit): gadget decomposition + outer commit ──

/// Signed base-`2^bits` gadget decomposition of a coefficient vector: each poly
/// in `v` becomes `num_limbs` polys, limb `l` holding the l-th signed digit
/// (centered in `[-2^{bits-1}, 2^{bits-1}]`) of each coefficient, so every output
/// coefficient has `‖·‖∞ ≤ 2^{bits-1}`. `Σ_l 2^{bits·l}·limb_l = v` (mod q). This
/// is how LaBRADOR keeps the RECOMMITTED child witness short between recursion
/// levels (norm control). Inverse: [`gadget_recompose`].
pub fn gadget_decompose(v: &PolyVec, bits: u32, num_limbs: usize) -> PolyVec {
    let base = 1i64 << bits;
    let half = base / 2;
    let q = Poly::Q as i64;
    let mut out: Vec<Poly> = Vec::with_capacity(v.0.len() * num_limbs);
    for p in &v.0 {
        // Per limb, the digit poly.
        let mut limbs: Vec<Vec<i64>> = vec![vec![0i64; RING_DEGREE_D]; num_limbs];
        for (k, &coeff) in p.c.iter().enumerate() {
            // Centered representative in (-q/2, q/2].
            let mut x = coeff as i64;
            if x > q / 2 {
                x -= q;
            }
            // Signed base-`base` digits.
            for limb in limbs.iter_mut() {
                let mut d = x % base;
                if d > half {
                    d -= base;
                } else if d < -half {
                    d += base;
                }
                x = (x - d) / base;
                limb[k] = d;
            }
        }
        for limb in limbs {
            out.push(Poly::from_signed(&limb));
        }
    }
    PolyVec(out)
}

/// Recompose a gadget decomposition: `Σ_l 2^{bits·l}·limb_l` per original poly.
pub fn gadget_recompose(d: &PolyVec, bits: u32, num_limbs: usize) -> PolyVec {
    assert_eq!(d.0.len() % num_limbs, 0, "decomposition length must be a multiple of num_limbs");
    let m = d.0.len() / num_limbs;
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        let mut acc = Poly::zero();
        for l in 0..num_limbs {
            acc = acc.add(&d.0[i * num_limbs + l].scalar_mul(1i64 << (bits * l as u32)));
        }
        out.push(acc);
    }
    PolyVec(out)
}

/// Outer Ajtai commitment to a (possibly long) vector `v`: gadget-decompose `v`
/// to a short vector, then `u = B·decomp(v)`. Compresses the revealed data of a
/// recursion level — the parent's `{tᵢ}`/garbage are COMMITTED (a few ring elts
/// `u`), not revealed, and opened by the child. Binding: M-SIS on `B` over the
/// short `decomp(v)`.
pub fn outer_commit(b_mat: &PolyMatrix, v: &PolyVec, bits: u32, num_limbs: usize) -> PolyVec {
    let dv = gadget_decompose(v, bits, num_limbs);
    b_mat.matvec(&dv)
}

/// Combine `cons` into ONE constraint via Fiat-Shamir challenge weights `ψ_k`
/// (SampleInBall): the result is `Σ_k ψ_k·constraint_k`. If ANY original
/// constraint is violated, the combined one is violated with prob `≥ 1 − 2/|C|`
/// (a nonzero `Σψ_k·(LHS_k−b_k)` for random `ψ`). This keeps the recursion's
/// child instance at O(1) constraints instead of O(r²) — Phase D uses it before
/// each fold. Soundness parallels the crate's other batch steps (`ρ_j`).
pub fn aggregate_constraints(cons: &[QuadConstraint]) -> QuadConstraint {
    aggregate_constraints_bound(cons, &[])
}

/// Like [`aggregate_constraints`] but binds the aggregation challenge ψ to
/// `bind` — the WITNESS COMMITMENT (`u1_a` over the challenge-independent `t‖g`).
/// This closes the Fiat-Shamir ordering hole: ψ is fixed only AFTER the prover
/// has committed to the witness, so a prover cannot aggregate an unsatisfiable
/// family, compute ψ itself, and then choose a witness for the single combined
/// equation. Pass `&[]` only for the standalone/base-relation aggregation.
pub fn aggregate_constraints_bound(cons: &[QuadConstraint], bind: &[u8]) -> QuadConstraint {
    use std::collections::BTreeMap;
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/aggregate/v2");
    h.update((bind.len() as u64).to_le_bytes());
    h.update(bind);
    for con in cons {
        for (i, j, a) in con.terms.iter().chain(&con.conj_terms) {
            h.update((*i as u32).to_le_bytes());
            h.update((*j as u32).to_le_bytes());
            for &x in &a.c {
                h.update(x.to_le_bytes());
            }
        }
        for (i, phi) in &con.linear {
            h.update((*i as u32).to_le_bytes());
            for p in &phi.0 {
                for &x in &p.c {
                    h.update(x.to_le_bytes());
                }
            }
        }
        for &x in &con.b.c {
            h.update(x.to_le_bytes());
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    let mut acc: BTreeMap<(usize, usize), Poly> = BTreeMap::new();
    let mut cacc: BTreeMap<(usize, usize), Poly> = BTreeMap::new();
    let mut lin: BTreeMap<usize, PolyVec> = BTreeMap::new();
    let mut b = Poly::zero();
    for con in cons {
        let psi = sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU);
        for (i, j, a) in &con.terms {
            let e = acc.entry((*i, *j)).or_insert_with(Poly::zero);
            *e = e.add(&psi.mul_ntt(a));
        }
        for (i, j, a) in &con.conj_terms {
            let e = cacc.entry((*i, *j)).or_insert_with(Poly::zero);
            *e = e.add(&psi.mul_ntt(a));
        }
        for (i, phi) in &con.linear {
            let e = lin.entry(*i).or_insert_with(|| PolyVec::zero(phi.len()));
            *e = e.add(&phi.mul_poly(&psi));
        }
        b = b.add(&psi.mul_ntt(&con.b));
    }
    let terms = acc.into_iter().map(|((i, j), a)| (i, j, a)).collect();
    let conj_terms = cacc.into_iter().map(|((i, j), a)| (i, j, a)).collect();
    let linear = lin.into_iter().collect();
    QuadConstraint { conj_terms, terms, linear, b }
}

/// Evaluate a constraint's LHS `Σ a_{ij}·gᵢⱼ` against a garbage table (test /
/// recursion helper).
pub fn eval_constraint(con: &QuadConstraint, g: &[Vec<Poly>]) -> Poly {
    let mut lhs = Poly::zero();
    for (i, j, a) in &con.terms {
        lhs = lhs.add(&a.mul_ntt(&g[*i][*j]));
    }
    lhs
}

/// Evaluate a full eq.-(6) constraint directly on a WITNESS `s`:
/// `Σ a_{ij}·⟨s_i,s_j⟩ + Σ ⟨φ_i, s_i⟩`. This is what the *next* recursion level
/// proves; the child instance is satisfiable iff this equals `con.b` for every
/// child constraint. (`i ≤ j` terms are counted once, matching `eval_constraint`.)
pub fn eval_constraint_on_witness(con: &QuadConstraint, s: &[PolyVec]) -> Poly {
    let mut lhs = Poly::zero();
    for (i, j, a) in &con.terms {
        lhs = lhs.add(&a.mul_ntt(&dot(&s[*i], &s[*j])));
    }
    for (i, j, a) in &con.conj_terms {
        lhs = lhs.add(&a.mul_ntt(&conj_dot(&s[*i], &s[*j])));
    }
    for (i, phi) in &con.linear {
        lhs = lhs.add(&dot(phi, &s[*i]));
    }
    lhs
}

/// A CONSTANT-TERM constraint — the paper's SECOND constraint family. Semantics:
///
/// ```text
///   Σ a_ij · ⟪s_i, s_j⟫ + Σ ⟪φ_i, s_i⟫ = target        (in Z_q)
/// ```
///
/// where `⟪u,v⟫ = Σ_l Σ_m u_{l,m}·v_{l,m}` is the FULL coefficient inner product
/// of two rank-`n` vectors — equivalently `Σ_l ct(σ(u_l)·v_l)` via the negacyclic
/// automorphism `σ: X ↦ X⁻¹`. Quadratic coefficients `a_ij` and `target` are Z_q
/// SCALARS (only the constant term is constrained). This is the family that lets
/// values PACKED into ring coefficients be constrained per-coordinate (e.g. a bit
/// vector `bᵢ∈{0,1}` via `Σbₖ² − Σbₖ = 0`), which the whole-ring [`QuadConstraint`]
/// cannot express.
///
/// SOUNDNESS SCOPE: `⟪·,·⟫` is not preserved by the ring-challenge fold
/// `z = Σ cᵢsᵢ`, so ct-constraints cannot be folded directly. The paper's §2.3
/// CONJUGATION AGGREGATION turns them into whole-ring statements on committed
/// conjugated garbage BEFORE folding: quadratic ct → `ĝ_ij = conj_dot(s_i,s_j)`,
/// linear ct → `ĥ_ij = conj_dot(φ_i,s_j)`, each bound single-shot by the
/// conjugated fold `conj_dot(z,z)` / `conj_dot(Φ,z)`. This is now WIRED into
/// [`reduce_to_child_conj_ct`] and folds through the full recursion via
/// [`prove_labrador_recursive_ct`] / [`verify_labrador_recursive_ct`] (Step 3b);
/// ct-constraints survive to the send-witness base as a lowered ct-family.
#[derive(Clone)]
pub struct CtConstraint {
    /// Sparse `(i, j, a_ij)` with SCALAR quadratic coefficients; uses `⟪s_i,s_j⟫`.
    pub terms: Vec<(usize, usize, i64)>,
    /// Sparse `(i, φ_i)` linear terms; uses `⟪φ_i, s_i⟫`.
    pub linear: Vec<(usize, PolyVec)>,
    /// The Z_q scalar the expression must equal.
    pub target: u64,
}

/// Conjugated ring dot product `⟨σ(u), v⟩ = Σ_l σ(u_l)·v_l` (a RING element). Its
/// constant term is the coefficient inner product: `ct(conj_dot(u,v)) = ⟪u,v⟫`.
///
/// This is the CONJUGATED GARBAGE the conjugation-aggregation must commit:
/// with `ĝ_ij = conj_dot(s_i, s_j)` committed as a child-witness element, a
/// parent ct-constraint `Σ a_ij⟪s_i,s_j⟫ + Σ⟪φ_i,s_i⟫ = τ` LOWERS to the LINEAR
/// ct-constraint `Σ a_ij·ct(ĝ_ij) + Σ ct(conj_dot(φ_i,s_i)) = τ` on the child —
/// which the fold CAN carry (linear ct on committed elements). WIRED into
/// [`reduce_to_child_conj_ct`]: `ĝ`/`ĥ` are committed in `u1_b` and bound by the
/// whole-ring conjugated fold, then the ct-family is re-lowered each level.
pub fn conj_dot(u: &PolyVec, v: &PolyVec) -> Poly {
    let mut acc = Poly::zero();
    for (a, b) in u.0.iter().zip(&v.0) {
        acc = acc.add(&a.conjugate().mul_ntt(b));
    }
    acc
}

/// The conjugated quadratic garbage `ĝ_ij = ⟨σ(s_i), s_j⟩` for all `i,j`
/// (NOT symmetric — `r²` ring elements). `ct(ĝ_ij) = ⟪s_i,s_j⟫`. The prover
/// commits this (an Ajtai commitment) BEFORE the fold challenges are drawn.
pub fn conj_garbage(s: &[PolyVec]) -> Vec<Vec<Poly>> {
    let r = s.len();
    (0..r).map(|i| (0..r).map(|j| conj_dot(&s[i], &s[j])).collect()).collect()
}

/// Conjugated LINEAR garbage `ĥ_ij = ⟨σ(φ_i), s_j⟩` (full `r×r`), the conjugated
/// analogue of the recursion's linear h-garbage. `ct(ĥ_ii) = ⟪φ_i, s_i⟫` gives the
/// LINEAR part of a ct-constraint, so this is what carries a lowered (linear)
/// ct-constraint through a fold. `φ` is the constraint's per-index linear
/// coefficients (public); committed before the challenge, like `ĝ`.
pub fn conj_linear_garbage(phi: &[PolyVec], s: &[PolyVec]) -> Vec<Vec<Poly>> {
    let r = s.len();
    (0..phi.len())
        .map(|i| (0..r).map(|j| conj_dot(&phi[i], &s[j])).collect())
        .collect()
}

/// Whole-ring binding `⟨σ(Φ),z⟩ = Σ_ij σ(c_i)c_j·ĥ_ij` with `Φ = Σ c_i φ_i`,
/// `z = Σ c_j s_j`. Single-shot sound (whole-ring, same argument as `ĝ`): with `ĥ`
/// committed before `c`, the difference form vanishes for random `c` iff every
/// `ĥ_ij = ⟨σ(φ_i),s_j⟩`. Reuses [`conj_binding_ring`]'s formula (same shape).
pub fn folded_phi(phi: &[PolyVec], c: &[Poly], n: usize) -> PolyVec {
    let mut acc = PolyVec::zero(n);
    for (i, ci) in c.iter().enumerate() {
        if i < phi.len() {
            acc = acc.add(&phi[i].mul_poly(ci));
        }
    }
    acc
}

/// The verifier's binding value `Σ_ij ct(σ(c_i)·c_j·ĝ_ij)` for ONE fold-challenge
/// vector `c`, from the COMMITTED garbage. Equals `⟪z,z⟫` (see
/// [`coeff_self_inner`]) for honest `ĝ`.
///
/// ⚠️ SOUNDNESS (empirically established, `conj_garbage_binding_*` tests): a
/// SINGLE aggregate over the sparse weight-τ challenges is NOT sound — the
/// difference term for a tampered `ĝ_ij` is `ct(σ(c_i)c_j·D) = coeff_inner(c_i,c_j)`
/// on the constant coeff, and sparse ±1 challenges make that ZERO too often
/// (measured ≈ 19% miss for a 1-coefficient tamper). The SOUND binding batches
/// `k` INDEPENDENT challenge vectors (each an Ajtai-committed-before / FS draw)
/// and rejects if ANY equation fails; the miss rate falls as `ε^k` (k≈8 already
/// ≈2⁻¹⁹). This matches the paper's ψ/ω (or JL) amplification. Callers MUST use
/// [`conj_binding_holds_batched`], never a single draw, for a soundness gate.
pub fn conj_binding_value(ghat: &[Vec<Poly>], c: &[Poly]) -> u64 {
    let q = Poly::Q as u128;
    let mut acc = 0u128;
    for (i, ci) in c.iter().enumerate() {
        let ci_conj = ci.conjugate();
        for (j, cj) in c.iter().enumerate() {
            let term = ci_conj.mul_ntt(cj).mul_ntt(&ghat[i][j]);
            acc = (acc + term.c[0] as u128) % q;
        }
    }
    acc as u64
}

/// The folded witness's coefficient self-inner-product `⟪z,z⟫` — the RHS the
/// conjugated-garbage binding ties the committed `ĝ` to.
pub fn coeff_self_inner(z: &PolyVec) -> u64 {
    coeff_inner_vec(z, z)
}

/// The WHOLE-RING conjugated-garbage binding value `Σ_ij σ(c_i)·c_j·ĝ_ij` (a ring
/// element). Equals `⟨σ(z),z⟩ = conj_dot(z,z)` for honest `ĝ` (`z = Σ c_i s_i`).
///
/// SOUNDNESS (single challenge, unlike the ct-only binding): with `ĝ` committed
/// before `c`, `Σ_ij σ(c_i)c_j·(ĝ_ij − real_ij) = 0` as a WHOLE-RING (all d
/// coefficients) equation vanishes for random ring `c` iff every `ĝ_ij = real_ij`
/// — the same Schwartz-Zippel-over-R_q / invertible-difference argument that binds
/// the existing garbage `g_ij` via `⟨z,z⟩ = Σ c_ic_j g_ij`. So the whole ring
/// element `ĝ_ij` (hence `ct(ĝ_ij) = ⟪s_i,s_j⟫`) is certified single-shot; no
/// batching. This is the binding the multi-level ct integration uses.
pub fn conj_binding_ring(ghat: &[Vec<Poly>], c: &[Poly]) -> Poly {
    let mut acc = Poly::zero();
    for (i, ci) in c.iter().enumerate() {
        let ci_conj = ci.conjugate();
        for (j, cj) in c.iter().enumerate() {
            acc = acc.add(&ci_conj.mul_ntt(cj).mul_ntt(&ghat[i][j]));
        }
    }
    acc
}

/// The SOUND conjugated-garbage binding: check `Σ_ij ct(σ(c_i)c_j ĝ_ij) = ⟪zᵐ,zᵐ⟫`
/// for `k` INDEPENDENT fold-challenge vectors `cs[m]` (with `zᵐ = Σ cᵐᵢ sᵢ`),
/// accepting only if EVERY equation holds. Batching drives the single-draw
/// soundness error `ε` (≈0.19 for weight-τ) down to `εᵏ`. `ĝ` must be committed
/// before any `cs` is drawn (Fiat-Shamir), so a cheating `ĝ` cannot adapt.
pub fn conj_binding_holds_batched(ghat: &[Vec<Poly>], s: &[PolyVec], cs: &[Vec<Poly>]) -> bool {
    let n = s.first().map(|v| v.len()).unwrap_or(0);
    for c in cs {
        if c.len() != s.len() {
            return false;
        }
        let mut z = PolyVec::zero(n);
        for (i, ci) in c.iter().enumerate() {
            z = z.add(&s[i].mul_poly(ci));
        }
        if conj_binding_value(ghat, c) != coeff_self_inner(&z) {
            return false;
        }
    }
    !cs.is_empty()
}

/// Full coefficient inner product `⟪u,v⟫ = Σ_l Σ_m u_{l,m}·v_{l,m} mod q`.
pub fn coeff_inner_vec(u: &PolyVec, v: &PolyVec) -> u64 {
    let q = Poly::Q as u128;
    let mut acc = 0u128;
    for (a, b) in u.0.iter().zip(&v.0) {
        for (x, y) in a.c.iter().zip(&b.c) {
            acc = (acc + (*x as u128) * (*y as u128)) % q;
        }
    }
    acc as u64
}

/// Evaluate a [`CtConstraint`] on a revealed witness → its Z_q value.
pub fn eval_ct_on_witness(con: &CtConstraint, s: &[PolyVec]) -> u64 {
    let q = Poly::Q as u128;
    let qi = Poly::Q as i64;
    let mut acc = 0u128;
    for (i, j, a) in &con.terms {
        let inner = coeff_inner_vec(&s[*i], &s[*j]) as u128;
        let a_mod = a.rem_euclid(qi) as u128;
        acc = (acc + a_mod * inner) % q;
    }
    for (i, phi) in &con.linear {
        acc = (acc + coeff_inner_vec(phi, &s[*i]) as u128) % q;
    }
    acc as u64
}

/// The ring automorphism `σ_k: X ↦ X^k` (`k` odd) applied to `p`. For each term
/// `p_m X^m`, `X^{km}` reduces negacyclically: `X^j = (−1)^{⌊j/d⌋}·X^{j mod d}`.
/// The `k=2d−1` case is [`Poly::conjugate`] (`σ: X↦X^{−1}`).
pub fn apply_auto(p: &Poly, k: usize) -> Poly {
    let d = Poly::D;
    let q = Poly::Q;
    let mut out = vec![0u64; d];
    for (m, &pm) in p.c.iter().enumerate() {
        if pm == 0 {
            continue;
        }
        let j = (k * m) % (2 * d);
        let idx = j % d;
        let neg = j >= d;
        out[idx] = if neg {
            (out[idx] + q - pm) % q
        } else {
            (out[idx] + pm) % q
        };
    }
    Poly { c: out }
}

/// `Σ_{k odd, 1≤k<2d} σ_k(Y)` — the Galois trace `Tr(Y)`. Equals `d·ct(Y)·1` (a
/// scalar): `Tr(ζᵏ)=0` for `0<k<d` and `=d` for `k=0`. This is the EXACT
/// ct→whole-ring conversion: `ct(Y)=τ ⟺ Tr(Y)=d·τ·1`, a WHOLE-RING equation that
/// folds via the (σ_k-generalized) conjugated-garbage machinery. Cost: it needs
/// σ_k-conjugated garbage for all `d` automorphisms — correct but `d×` heavier
/// than a single conjugation, which is why it is the honest-but-expensive route
/// (a cheaper aggregation is the crypto-team optimization). Validated in tests.
pub fn galois_trace(y: &Poly) -> Poly {
    let d = Poly::D;
    let mut acc = Poly::zero();
    let mut k = 1usize;
    while k < 2 * d {
        acc = acc.add(&apply_auto(y, k));
        k += 2;
    }
    acc
}

/// Aggregate `L` constant-term constraints into ONE via random Z_q challenges —
/// the first (sound) half of the ct→whole-ring reduction.
///
/// The verifier draws `ω_l` (Fiat-Shamir over the family + `bind`) and forms
/// `Σ_l ω_l·f_l`. Since `ct` is Z_q-linear, `ct(Σ ω_l f_l(s)) = Σ ω_l·ct(f_l(s))`;
/// if any `ct(f_l(s)) ≠ target_l` then the random combination misses its combined
/// target with probability `≤ 1/q` (Schwartz-Zippel over Z_q). So `L` ct-checks
/// collapse to one with negligible error. (The REMAINING half — folding that
/// single ct-constraint through the §5.3 levels — needs the paper's automorphism
/// aggregation and is NOT done here; see the module notes. This aggregation is
/// also usable stand-alone to batch the send-witness-base ct checks.)
pub fn aggregate_ct_constraints(family: &[CtConstraint], bind: &[u8]) -> CtConstraint {
    use std::collections::BTreeMap;
    let q = Poly::Q as u128;
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/ct-aggregate/v1");
    h.update((bind.len() as u64).to_le_bytes());
    h.update(bind);
    for con in family {
        for (i, j, a) in &con.terms {
            h.update((*i as u32).to_le_bytes());
            h.update((*j as u32).to_le_bytes());
            h.update(a.to_le_bytes());
        }
        for (i, phi) in &con.linear {
            h.update((*i as u32).to_le_bytes());
            for p in &phi.0 {
                for &x in &p.c {
                    h.update(x.to_le_bytes());
                }
            }
        }
        h.update(con.target.to_le_bytes());
    }
    let mut prg = HashPrg::from_digest(&h.finalize());
    let mut terms: BTreeMap<(usize, usize), u128> = BTreeMap::new();
    let mut lin: BTreeMap<usize, PolyVec> = BTreeMap::new();
    let mut target = 0u128;
    for con in family {
        let omega = (prg.next_u64() as u128) % q;
        for (i, j, a) in &con.terms {
            let av = a.rem_euclid(Poly::Q as i64) as u128;
            let e = terms.entry((*i, *j)).or_insert(0);
            *e = (*e + omega * av) % q;
        }
        for (i, phi) in &con.linear {
            let e = lin.entry(*i).or_insert_with(|| PolyVec::zero(phi.len()));
            // ω·φ (scalar times each coefficient).
            *e = e.add(&PolyVec(phi.0.iter().map(|p| p.scalar_mul(omega as i64)).collect()));
        }
        target = (target + omega * con.target as u128) % q;
    }
    CtConstraint {
        terms: terms.into_iter().map(|((i, j), a)| (i, j, a as i64)).collect(),
        linear: lin.into_iter().collect(),
        target: target as u64,
    }
}

/// Run one reduction round. Returns `None` if the witness dimensions mismatch.
pub fn prove_reduction(st: &Statement, w: &Witness) -> Option<ReductionProof> {
    if w.s.len() != st.r {
        return None;
    }
    // Inner Ajtai commitments tᵢ = A·sᵢ.
    let t: Vec<PolyVec> = w.s.iter().map(|si| st.a_mat.matvec(si)).collect();
    // Symmetric garbage gᵢⱼ = ⟨sᵢ,sⱼ⟩.
    let mut g = vec![vec![Poly::zero(); st.r]; st.r];
    for i in 0..st.r {
        for j in i..st.r {
            let gij = dot(&w.s[i], &w.s[j]);
            g[i][j] = gij.clone();
            g[j][i] = gij;
        }
    }
    let c = fold_challenges(&st.a_mat, &t, &g, st.r);
    // Fold z = Σ cᵢ·sᵢ.
    let mut z = PolyVec::zero(st.n);
    for i in 0..st.r {
        z = z.add(&w.s[i].mul_poly(&c[i]));
    }
    Some(ReductionProof { t, g, z })
}

/// Verify one reduction round.
pub fn verify_reduction(st: &Statement, pf: &ReductionProof) -> bool {
    if pf.t.len() != st.r || pf.g.len() != st.r || pf.z.len() != st.n {
        return false;
    }
    // Guard ragged `g` rows and wrong-rank `t` before any index/matvec (reject,
    // not panic, on malformed input).
    if pf.g.iter().any(|row| row.len() != st.r) || pf.t.iter().any(|ti| ti.len() != st.a_mat.rows) {
        return false;
    }
    let c = fold_challenges(&st.a_mat, &pf.t, &pf.g, st.r);

    // (1) commitment fold: A·z == Σ cᵢ·tᵢ.
    let az = st.a_mat.matvec(&pf.z);
    let mut fold_t = PolyVec::zero(st.a_mat.rows);
    for i in 0..st.r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if az != fold_t {
        return false;
    }

    // (2) amortized quadratic: ⟨z,z⟩ == Σ_{i,j} cᵢ·cⱼ·gᵢⱼ.
    let zz = dot(&pf.z, &pf.z);
    let mut quad = Poly::zero();
    for i in 0..st.r {
        for j in 0..st.r {
            let cij = c[i].mul_ntt(&c[j]);
            quad = quad.add(&cij.mul_ntt(&pf.g[i][j]));
        }
    }
    if zz != quad {
        return false;
    }

    // (3) each constraint Σ a_{ij}·gᵢⱼ == b, evaluated on the (bound) garbage.
    for con in &st.constraints {
        let mut lhs = Poly::zero();
        for (i, j, a) in &con.terms {
            if *i >= st.r || *j >= st.r {
                return false;
            }
            lhs = lhs.add(&a.mul_ntt(&pf.g[*i][*j]));
        }
        if lhs != con.b {
            return false;
        }
    }

    // (4) relaxed norm on the fold: ‖z‖∞ ≤ r·τ·β (worst-case).
    let bound = (st.r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * st.beta;
    if pf.z.inf_norm() > bound {
        return false;
    }
    true
}

// ── r=2 binary-fold argument for the Ajtai opening (compressing) ────────────
//
// Prove knowledge of SHORT `s` with `A·s = t` in `O(κ·rounds)` ring elements,
// halving the witness dimension each round. Fold (derived, keeps `s'` short —
// only the small challenge `x` multiplies the witness):
//   split A=[A_L|A_R], s=[s_L|s_R];  u = A_L·s_R + A_R·s_L,  q_R = A_R·s_R
//   challenge x;  s' = s_L + x·s_R,  A' = A_L + x·A_R,  t' = t + x·u + (x²−1)·q_R
// Identity: A'·s' = t' (checked in `opening_fold_algebra`). Norm grows `(1+τ)×`
// per round, so at q≈2³⁶ depth is bounded to ~6 rounds (≥128-bit margin ⇒
// extracted norm ≤ 2³⁵). Deeper compression needs
// r>2 (LaBRADOR proper, fewer rounds) — this is the r=2 building block.

/// One fold round's message (the cross term and the right-block commitment).
pub struct FoldRound {
    pub u: PolyVec,   // A_L·s_R + A_R·s_L   (κ)
    pub q_r: PolyVec, // A_R·s_R             (κ)
}

/// A binary-fold opening proof: the per-round messages + the folded base witness.
pub struct FoldProof {
    pub rounds: Vec<FoldRound>,
    pub s_final: PolyVec,
}

fn split_cols(a: &PolyMatrix, h: usize) -> (PolyMatrix, PolyMatrix) {
    let l = PolyMatrix { rows: a.rows, cols: h, m: a.m.iter().map(|r| r[..h].to_vec()).collect() };
    let r = PolyMatrix {
        rows: a.rows,
        cols: a.cols - h,
        m: a.m.iter().map(|r| r[h..].to_vec()).collect(),
    };
    (l, r)
}

/// `A_L + x·A_R` (entrywise; both `rows × h`).
fn mat_fold(a_l: &PolyMatrix, a_r: &PolyMatrix, x: &Poly) -> PolyMatrix {
    let m = a_l
        .m
        .iter()
        .zip(&a_r.m)
        .map(|(rl, rr)| rl.iter().zip(rr).map(|(pl, pr)| pl.add(&x.mul_ntt(pr))).collect())
        .collect();
    PolyMatrix { rows: a_l.rows, cols: a_l.cols, m }
}

fn fold_challenge(t: &PolyVec, u: &PolyVec, q_r: &PolyVec) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/opening-fold/v1");
    for v in [t, u, q_r] {
        for p in &v.0 {
            for &c in &p.c {
                h.update(c.to_le_bytes());
            }
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)
}

/// Prove `A·s = t` (with `s` short) via `rounds` binary folds. `A.cols` must be
/// divisible by `2^rounds`.
pub fn prove_opening_fold(a0: &PolyMatrix, s0: &PolyVec, t0: &PolyVec, rounds: usize) -> FoldProof {
    let mut a = a0.clone();
    let mut s = s0.clone();
    let mut t = t0.clone();
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let h = a.cols / 2;
        let (a_l, a_r) = split_cols(&a, h);
        let s_l = PolyVec(s.0[..h].to_vec());
        let s_r = PolyVec(s.0[h..].to_vec());
        let u = a_l.matvec(&s_r).add(&a_r.matvec(&s_l));
        let q_r = a_r.matvec(&s_r);
        let x = fold_challenge(&t, &u, &q_r);
        // Fold state.
        s = s_l.add(&s_r.mul_poly(&x));
        a = mat_fold(&a_l, &a_r, &x);
        let x2m1 = x.mul_ntt(&x).sub(&Poly::one());
        t = t.add(&u.mul_poly(&x)).add(&q_r.mul_poly(&x2m1));
        out.push(FoldRound { u, q_r });
    }
    FoldProof { rounds: out, s_final: s }
}

/// Verify a binary-fold opening proof. `norm_bound` must accommodate `(1+τ)^rounds·β`.
pub fn verify_opening_fold(
    a0: &PolyMatrix,
    t0: &PolyVec,
    pf: &FoldProof,
    norm_bound: u64,
) -> bool {
    let mut a = a0.clone();
    let mut t = t0.clone();
    for round in &pf.rounds {
        if round.u.len() != a.rows || round.q_r.len() != a.rows || a.cols % 2 != 0 {
            return false;
        }
        let x = fold_challenge(&t, &round.u, &round.q_r);
        let (a_l, a_r) = split_cols(&a, a.cols / 2);
        a = mat_fold(&a_l, &a_r, &x);
        let x2m1 = x.mul_ntt(&x).sub(&Poly::one());
        t = t.add(&round.u.mul_poly(&x)).add(&round.q_r.mul_poly(&x2m1));
    }
    if pf.s_final.len() != a.cols {
        return false;
    }
    a.matvec(&pf.s_final) == t && pf.s_final.inf_norm() <= norm_bound
}

// ── r=2 inner-product fold: ⟨a,b⟩ = c (covers the QUADRATIC constraints) ─────
//
// Proves knowledge of SHORT `a,b` with Ajtai commitments `A·a=t_a`, `B·b=t_b`
// and `⟨a,b⟩=c`, in `O((4κ+3)·rounds)` ring elts. Bit validity is the case
// `b = a − 1`, `c = 0` (`Σ aᵢ(aᵢ−1)=0 ⟺ aᵢ∈{0,1}`). Fold (both vectors keep the
// small `x` only): split; opening cross terms `u_a,q_a,u_b,q_b`; inner-product
// cross terms `v0=⟨a_L,b_L⟩, v1=⟨a_L,b_R⟩+⟨a_R,b_L⟩, v2=⟨a_R,b_R⟩` with round
// check `v0+v2=c`; then `a'=a_L+x a_R`, `b'=b_L+x b_R`, matrices/commitments fold
// as in the opening fold, and `c'=v0+x·v1+x²·v2 = ⟨a',b'⟩`. Same `(1+τ)/round`
// norm growth ⇒ same ≤~6-round depth at q≈2³⁶.

pub struct IpFoldRound {
    pub u_a: PolyVec,
    pub q_a: PolyVec,
    pub u_b: PolyVec,
    pub q_b: PolyVec,
    pub v0: Poly,
    pub v1: Poly,
    pub v2: Poly,
}

pub struct IpFoldProof {
    pub rounds: Vec<IpFoldRound>,
    pub a_final: PolyVec,
    pub b_final: PolyVec,
}

#[allow(clippy::too_many_arguments)]
fn ip_fold_challenge(
    ta: &PolyVec,
    tb: &PolyVec,
    c: &Poly,
    r: &IpFoldRound,
) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/ip-fold/v1");
    for v in [ta, tb, &r.u_a, &r.q_a, &r.u_b, &r.q_b] {
        for p in &v.0 {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for p in [c, &r.v0, &r.v1, &r.v2] {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)
}

/// Prove `⟨a,b⟩=c` with `A·a=t_a`, `B·b=t_b` (a,b short) via `rounds` folds.
#[allow(clippy::too_many_arguments)]
pub fn prove_ip_fold(
    a_mat: &PolyMatrix,
    b_mat: &PolyMatrix,
    a0: &PolyVec,
    b0: &PolyVec,
    ta0: &PolyVec,
    tb0: &PolyVec,
    c0: &Poly,
    rounds: usize,
) -> IpFoldProof {
    let (mut am, mut bm) = (a_mat.clone(), b_mat.clone());
    let (mut a, mut b) = (a0.clone(), b0.clone());
    let (mut ta, mut tb, mut c) = (ta0.clone(), tb0.clone(), c0.clone());
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let h = am.cols / 2;
        let (al, ar) = split_cols(&am, h);
        let (bl, br) = split_cols(&bm, h);
        let a_l = PolyVec(a.0[..h].to_vec());
        let a_r = PolyVec(a.0[h..].to_vec());
        let b_l = PolyVec(b.0[..h].to_vec());
        let b_r = PolyVec(b.0[h..].to_vec());
        let round = IpFoldRound {
            u_a: al.matvec(&a_r).add(&ar.matvec(&a_l)),
            q_a: ar.matvec(&a_r),
            u_b: bl.matvec(&b_r).add(&br.matvec(&b_l)),
            q_b: br.matvec(&b_r),
            v0: dot(&a_l, &b_l),
            v1: dot(&a_l, &b_r).add(&dot(&a_r, &b_l)),
            v2: dot(&a_r, &b_r),
        };
        let x = ip_fold_challenge(&ta, &tb, &c, &round);
        a = a_l.add(&a_r.mul_poly(&x));
        b = b_l.add(&b_r.mul_poly(&x));
        am = mat_fold(&al, &ar, &x);
        bm = mat_fold(&bl, &br, &x);
        let x2 = x.mul_ntt(&x);
        let x2m1 = x2.sub(&Poly::one());
        ta = ta.add(&round.u_a.mul_poly(&x)).add(&round.q_a.mul_poly(&x2m1));
        tb = tb.add(&round.u_b.mul_poly(&x)).add(&round.q_b.mul_poly(&x2m1));
        c = round.v0.add(&x.mul_ntt(&round.v1)).add(&x2.mul_ntt(&round.v2));
        out.push(round);
    }
    IpFoldProof { rounds: out, a_final: a, b_final: b }
}

/// Verify an inner-product fold.
#[allow(clippy::too_many_arguments)]
pub fn verify_ip_fold(
    a_mat: &PolyMatrix,
    b_mat: &PolyMatrix,
    ta0: &PolyVec,
    tb0: &PolyVec,
    c0: &Poly,
    pf: &IpFoldProof,
    norm_bound: u64,
) -> bool {
    let (mut am, mut bm) = (a_mat.clone(), b_mat.clone());
    let (mut ta, mut tb, mut c) = (ta0.clone(), tb0.clone(), c0.clone());
    for r in &pf.rounds {
        if am.cols % 2 != 0
            || r.u_a.len() != am.rows
            || r.q_a.len() != am.rows
            || r.u_b.len() != bm.rows
            || r.q_b.len() != bm.rows
        {
            return false;
        }
        // Bind the sent inner-product cross terms to the current claim.
        if r.v0.add(&r.v2) != c {
            return false;
        }
        let x = ip_fold_challenge(&ta, &tb, &c, r);
        let (al, ar) = split_cols(&am, am.cols / 2);
        let (bl, br) = split_cols(&bm, bm.cols / 2);
        am = mat_fold(&al, &ar, &x);
        bm = mat_fold(&bl, &br, &x);
        let x2 = x.mul_ntt(&x);
        let x2m1 = x2.sub(&Poly::one());
        ta = ta.add(&r.u_a.mul_poly(&x)).add(&r.q_a.mul_poly(&x2m1));
        tb = tb.add(&r.u_b.mul_poly(&x)).add(&r.q_b.mul_poly(&x2m1));
        c = r.v0.add(&x.mul_ntt(&r.v1)).add(&x2.mul_ntt(&r.v2));
    }
    // Guard the final openings' lengths before matvec (reject, not panic).
    if pf.a_final.len() != am.cols || pf.b_final.len() != bm.cols {
        return false;
    }
    am.matvec(&pf.a_final) == ta
        && bm.matvec(&pf.b_final) == tb
        && dot(&pf.a_final, &pf.b_final) == c
        && pf.a_final.inf_norm() <= norm_bound
        && pf.b_final.inf_norm() <= norm_bound
}

// ── Compact wire codec: bit-pack coefficients at their real width ────────────
//
// The reference codec (`wire::encode_polyvec`) stores every coefficient as a
// `u64` (2052 B/poly). Coefficients live in `[0, q)` with `q≈2³⁶`, so they fit
// in `MODULUS_Q_BITS = 36` bits — a ~1.78× wire win (1152 vs 2052 B/poly).
// Genuinely-short elements (small norm bound) pack even tighter at `bits =
// ⌈log2(2·bound+1)⌉`. LSB-first bitstream; round-trips with `unpack_coeffs`.

/// Pack every coefficient of `polys` at `bits` bits (coeffs must be `< 2^bits`).
pub fn pack_coeffs(polys: &[Poly], bits: u32) -> Vec<u8> {
    debug_assert!((1..=56).contains(&bits));
    let mask = (1u64 << bits) - 1;
    let mut out = Vec::with_capacity(polys.len() * RING_DEGREE_D * bits as usize / 8 + 8);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for p in polys {
        for &c in &p.c {
            acc |= (c & mask) << nbits;
            nbits += bits;
            while nbits >= 8 {
                out.push((acc & 0xff) as u8);
                acc >>= 8;
                nbits -= 8;
            }
        }
    }
    if nbits > 0 {
        out.push((acc & 0xff) as u8);
    }
    out
}

/// Inverse of [`pack_coeffs`]: unpack `count` polys of `bits`-wide coefficients.
pub fn unpack_coeffs(bytes: &[u8], bits: u32, count: usize) -> Vec<Poly> {
    let mask = (1u64 << bits) - 1;
    let mut polys = Vec::with_capacity(count);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut bi = 0usize;
    for _ in 0..count {
        let mut c = vec![0u64; RING_DEGREE_D];
        for coeff in c.iter_mut() {
            while nbits < bits {
                let b = if bi < bytes.len() { bytes[bi] } else { 0 };
                bi += 1;
                acc |= (b as u64) << nbits;
                nbits += 8;
            }
            *coeff = acc & mask;
            acc >>= bits;
            nbits -= bits;
        }
        polys.push(Poly { c });
    }
    polys
}

/// Compact byte size of an [`IpFoldProof`] with all coefficients at `q`-width
/// (`MODULUS_Q_BITS`). Commitments and inner-products are full-range; the base
/// witness is bounded but < q, so `q`-width is a safe uniform choice (per-element
/// width tuning would shave a bit more off the short parts).
pub fn ip_fold_compact_bytes(pf: &IpFoldProof) -> usize {
    let bits = crate::params::MODULUS_Q_BITS;
    let per_poly = (RING_DEGREE_D * bits as usize).div_ceil(8);
    let mut polys = 0usize;
    for r in &pf.rounds {
        polys += r.u_a.len() + r.q_a.len() + r.u_b.len() + r.q_b.len() + 3; // + v0,v1,v2
    }
    polys += pf.a_final.len() + pf.b_final.len();
    polys * per_poly
}

// ── Phase E frontend: a fold-based BIT-VALIDITY proof (the balance-proof core) ─
//
// Prove a committed vector `a` (N coords) is all-bits via ONE inner-product fold
// of `⟨a, a−1⟩ = 0`. `b = a−1` is enforced WITHOUT a second sent commitment:
// with `B = A`, `t_b = t_a − A·ones` is DERIVED by the verifier, and A's binding
// forces `b = a−1` (the only short opening of `t_b` under A is `a−1`). Scales to
// large N where `binary_rq::prove_bits_rq` hits the rejection wall (the balance's
// 611 bits). Size `O(κ·rounds)`; depth ≤~6 at q≈2³⁶.

/// One bits-fold round — HALF the general IP round: only the a-commitment cross
/// terms `u_a,q_a` + the inner-product cross terms. The b side is DERIVED
/// (`t_b = t_a − A·ones`, both fold identically), so `u_b,q_b` are never sent.
pub struct BitsFoldRound {
    pub u_a: PolyVec,
    pub q_a: PolyVec,
    pub v0: Poly,
    pub v1: Poly,
    pub v2: Poly,
}

/// A bits-fold proof: the round messages + the base witness `a_final`
/// (`b_final = a_final − ones_final` is derived — not sent).
pub struct BitsFoldProof {
    pub rounds: Vec<BitsFoldRound>,
    pub a_final: PolyVec,
}

#[allow(clippy::too_many_arguments)]
fn bits_fold_challenge(ta: &PolyVec, tb: &PolyVec, c: &Poly, r: &BitsFoldRound) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/bits-fold/v1");
    for v in [ta, tb, &r.u_a, &r.q_a] {
        for p in &v.0 {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for p in [c, &r.v0, &r.v1, &r.v2] {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)
}

/// Prove all `N = a_mat.cols` coordinates of committed `a` are bits, via
/// `⟨a, a−1⟩ = 0`. The b‑commitment is never sent (derived). Returns `(t_a, fold)`.
pub fn prove_bits_fold(a_mat: &PolyMatrix, a: &PolyVec, rounds: usize) -> (PolyVec, BitsFoldProof) {
    let mut am = a_mat.clone();
    let mut a = a.clone();
    let mut ones = PolyVec(vec![Poly::one(); a.len()]);
    let ta0 = a_mat.matvec(&a);
    let mut ta = ta0.clone();
    let mut c = Poly::zero(); // the claim: ⟨a, a−1⟩ = 0
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let h = am.cols / 2;
        let (al, ar) = split_cols(&am, h);
        let a_l = PolyVec(a.0[..h].to_vec());
        let a_r = PolyVec(a.0[h..].to_vec());
        let o_l = PolyVec(ones.0[..h].to_vec());
        let o_r = PolyVec(ones.0[h..].to_vec());
        let b_l = a_l.sub(&o_l);
        let b_r = a_r.sub(&o_r);
        let round = BitsFoldRound {
            u_a: al.matvec(&a_r).add(&ar.matvec(&a_l)),
            q_a: ar.matvec(&a_r),
            v0: dot(&a_l, &b_l),
            v1: dot(&a_l, &b_r).add(&dot(&a_r, &b_l)),
            v2: dot(&a_r, &b_r),
        };
        let tb = ta.sub(&am.matvec(&ones)); // derived, for the transcript
        let x = bits_fold_challenge(&ta, &tb, &c, &round);
        a = a_l.add(&a_r.mul_poly(&x));
        ones = o_l.add(&o_r.mul_poly(&x));
        am = mat_fold(&al, &ar, &x);
        let x2 = x.mul_ntt(&x);
        let x2m1 = x2.sub(&Poly::one());
        ta = ta.add(&round.u_a.mul_poly(&x)).add(&round.q_a.mul_poly(&x2m1));
        c = round.v0.add(&x.mul_ntt(&round.v1)).add(&x2.mul_ntt(&round.v2));
        out.push(round);
    }
    (ta0, BitsFoldProof { rounds: out, a_final: a })
}

/// Verify a bits-fold proof. Recomputes `t_b = t_a − A·ones` and the folded
/// `ones` at every level; requires `⟨a_final, a_final − ones_final⟩ = c`.
pub fn verify_bits_fold(
    a_mat: &PolyMatrix,
    ta0: &PolyVec,
    pf: &BitsFoldProof,
    norm_bound: u64,
) -> bool {
    let mut am = a_mat.clone();
    let mut ta = ta0.clone();
    let mut ones = PolyVec(vec![Poly::one(); a_mat.cols]);
    let mut c = Poly::zero();
    for r in &pf.rounds {
        if am.cols % 2 != 0 || r.u_a.len() != am.rows || r.q_a.len() != am.rows {
            return false;
        }
        if r.v0.add(&r.v2) != c {
            return false;
        }
        let tb = ta.sub(&am.matvec(&ones));
        let x = bits_fold_challenge(&ta, &tb, &c, r);
        let h = am.cols / 2;
        let (al, ar) = split_cols(&am, h);
        let o_l = PolyVec(ones.0[..h].to_vec());
        let o_r = PolyVec(ones.0[h..].to_vec());
        am = mat_fold(&al, &ar, &x);
        ones = o_l.add(&o_r.mul_poly(&x));
        let x2 = x.mul_ntt(&x);
        let x2m1 = x2.sub(&Poly::one());
        ta = ta.add(&r.u_a.mul_poly(&x)).add(&r.q_a.mul_poly(&x2m1));
        c = r.v0.add(&x.mul_ntt(&r.v1)).add(&x2.mul_ntt(&r.v2));
    }
    if pf.a_final.len() != am.cols {
        return false; // guard before matvec (reject, not panic)
    }
    let b_final = pf.a_final.sub(&ones);
    am.matvec(&pf.a_final) == ta
        && dot(&pf.a_final, &b_final) == c
        && pf.a_final.inf_norm() <= norm_bound
}

/// Compact byte size of a [`BitsFoldProof`] at `q`-width.
pub fn bits_fold_compact_bytes(ta: &PolyVec, pf: &BitsFoldProof) -> usize {
    let per_poly = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
    let mut polys = ta.len();
    for r in &pf.rounds {
        polys += r.u_a.len() + r.q_a.len() + 3;
    }
    polys += pf.a_final.len();
    polys * per_poly
}

/// Append the powers‑of‑2 row `g = (2⁰,2¹,…,2^{N-1})` (constant polys, `2ⁱ mod q`)
/// to a commitment matrix. The extra commitment coordinate becomes `⟨2ⁱ,a⟩ = v`,
/// so committing `a` under the augmented matrix binds the VALUE. `N ≤ 35` keeps
/// `2ⁱ < q` (real amounts are proven per‑limb).
pub fn augment_with_value_row(a_mat: &PolyMatrix) -> PolyMatrix {
    let n = a_mat.cols;
    let g: Vec<Poly> = (0..n)
        .map(|i| {
            let mut p = Poly::zero();
            p.c[0] = (1u64 << (i % 60)) % Poly::Q;
            p
        })
        .collect();
    let mut m = a_mat.m.clone();
    m.push(g);
    PolyMatrix { rows: a_mat.rows + 1, cols: n, m }
}

/// A fold‑based RANGE proof: prove a committed `a` is all bits AND binds the
/// value `v = ⟨2ⁱ,a⟩` (⇒ `v ∈ [0,2^N)`), by running [`prove_bits_fold`] on the
/// value‑augmented matrix. `t_aug`'s last coordinate is `constant(v)`. (Hiding
/// `v` uses a value commitment with randomness instead of the bare row — the
/// crate's `commitment.rs`; this demonstrates the range‑proof STRUCTURE via
/// folding, the tx range component.)
pub fn prove_range_fold(a_mat: &PolyMatrix, bits: &PolyVec, rounds: usize) -> (PolyVec, BitsFoldProof) {
    prove_bits_fold(&augment_with_value_row(a_mat), bits, rounds)
}

/// Verify a fold‑based range proof.
pub fn verify_range_fold(
    a_mat: &PolyMatrix,
    t_aug: &PolyVec,
    pf: &BitsFoldProof,
    norm_bound: u64,
) -> bool {
    verify_bits_fold(&augment_with_value_row(a_mat), t_aug, pf, norm_bound)
}

// ── Phase E integration: the whole tx as ONE proof object ────────────────────
//
// The whole tx is ONE fold. Key move: make the ENTIRE witness bits — amount bits
// AND the gadget limbs bit‑decomposed — so bit validity is UNIFORM (`⟨W,W−1⟩=0`)
// and every value / balance / membership relation is a public linear form on `W`
// (`⟨weights,W⟩ = target`), folded into the single constraint matrix `M`. Then one
// `prove_bits_fold(M, W)` proves `W∈{0,1}` AND `M·W = t` together — ALL of it bound
// to ONE commitment `t`, no cross‑fold consistency gap. This is the tight binding.

pub struct TxFoldProof {
    pub t: PolyVec,          // the ONE commitment: M·W (encodes all linear targets)
    pub fold: BitsFoldProof, // ONE fold: W∈{0,1} (bit validity) AND M·W = t (all linear)
}

/// Prove the whole tx as ONE fold over an ALL‑BITS witness `w` (amount bits AND
/// gadget limbs bit‑decomposed) under the full constraint matrix `m_full`
/// (aggregated Ajtai commitment + value bindings + membership‑chain rows). The
/// single bits fold proves `w ∈ {0,1}` (uniform bit validity) AND `M·w = t` (every
/// linear constraint), so ALL of it is bound to ONE commitment — no cross‑fold
/// consistency gap. Non‑bit values (amounts, node hashes) are recovered as public
/// linear forms `⟨weights, w⟩` folded into `m_full`.
pub fn prove_tx_fold(m_full: &PolyMatrix, w: &PolyVec, rounds: usize) -> TxFoldProof {
    let (t, fold) = prove_bits_fold(m_full, w, rounds);
    TxFoldProof { t, fold }
}

/// Verify a whole-tx fold proof.
pub fn verify_tx_fold(m_full: &PolyMatrix, pf: &TxFoldProof, bound: u64) -> bool {
    verify_bits_fold(m_full, &pf.t, &pf.fold, bound)
}

/// Compact byte size of a whole-tx fold proof.
pub fn tx_fold_compact_bytes(pf: &TxFoldProof) -> usize {
    bits_fold_compact_bytes(&pf.t, &pf.fold)
}

// ── Kernel attempt: norm‑refresh recursion (from first principles) ───────────
//
// Idea to break the ≤~6‑round norm cap: fold to a base, then GADGET‑DECOMPOSE the
// base (re‑shortening ‖·‖ to <2^gbits) and re‑express the relation on the limbs
// (`M ← M·G`, the recompose matrix — PUBLIC, so no outer commitment needed since
// the base relation is public), then fold again. Repeat. ⚠ RECONSTRUCTED, not the
// paper; kept for the MEASURED finding below (it does NOT beat the fold floor).

/// `κ_cols × (κ_cols·limbs)` gadget recompose matrix `G` (`s = G·decompose(s)`).
fn recompose_matrix(cols: usize, bits: u32, limbs: usize) -> PolyMatrix {
    let mut m = vec![vec![Poly::zero(); cols * limbs]; cols];
    for i in 0..cols {
        for k in 0..limbs {
            let mut p = Poly::zero();
            p.c[0] = 1u64 << (bits * k as u32);
            m[i][i * limbs + k] = p;
        }
    }
    PolyMatrix { rows: cols, cols: cols * limbs, m }
}

pub struct DeepFoldProof {
    pub rounds: Vec<FoldRound>,
    pub s_final: PolyVec,
}

/// Verify a deep (norm-refresh) fold. Mirrors the prover's fold + M←M·G refresh.
pub fn verify_opening_fold_deep(
    m0: &PolyMatrix,
    t0: &PolyVec,
    pf: &DeepFoldProof,
    rounds_per: usize,
    refreshes: usize,
    bits: u32,
    limbs: usize,
    norm_bound: u64,
) -> bool {
    let mut m = m0.clone();
    let mut t = t0.clone();
    let mut ri = 0usize;
    for rf in 0..=refreshes {
        for _ in 0..rounds_per {
            if ri >= pf.rounds.len() || m.cols % 2 != 0 {
                return false;
            }
            let r = &pf.rounds[ri];
            ri += 1;
            let x = fold_challenge(&t, &r.u, &r.q_r);
            let (ml, mr) = split_cols(&m, m.cols / 2);
            m = mat_fold(&ml, &mr, &x);
            let x2m1 = x.mul_ntt(&x).sub(&Poly::one());
            t = t.add(&r.u.mul_poly(&x)).add(&r.q_r.mul_poly(&x2m1));
        }
        if rf < refreshes {
            m = m.matmul(&recompose_matrix(m.cols, bits, limbs));
        }
    }
    m.matvec(&pf.s_final) == t && pf.s_final.inf_norm() <= norm_bound
}

/// Fold `rounds_per` rounds, then (decompose‑refresh + fold) `refreshes` times.
pub fn prove_opening_fold_deep(
    m0: &PolyMatrix,
    s0: &PolyVec,
    t0: &PolyVec,
    rounds_per: usize,
    refreshes: usize,
    bits: u32,
    limbs: usize,
) -> DeepFoldProof {
    let mut m = m0.clone();
    let mut s = s0.clone();
    let mut t = t0.clone();
    let mut rounds = Vec::new();
    for rf in 0..=refreshes {
        for _ in 0..rounds_per {
            let h = m.cols / 2;
            let (ml, mr) = split_cols(&m, h);
            let sl = PolyVec(s.0[..h].to_vec());
            let sr = PolyVec(s.0[h..].to_vec());
            let u = ml.matvec(&sr).add(&mr.matvec(&sl));
            let q = mr.matvec(&sr);
            let x = fold_challenge(&t, &u, &q);
            s = sl.add(&sr.mul_poly(&x));
            m = mat_fold(&ml, &mr, &x);
            let x2m1 = x.mul_ntt(&x).sub(&Poly::one());
            t = t.add(&u.mul_poly(&x)).add(&q.mul_poly(&x2m1));
            rounds.push(FoldRound { u, q_r: q });
        }
        if rf < refreshes {
            let g = recompose_matrix(m.cols, bits, limbs);
            m = m.matmul(&g); // M ← M·G  (M·G·decompose(s) = M·s = t, so t unchanged)
            s = gadget_decompose(&s, bits, limbs);
        }
    }
    DeepFoldProof { rounds, s_final: s }
}

// ── Faithful LaBRADOR reduction (Beullens–Seiler §5.2), committed garbage ─────
//
// Paper mechanism (the piece the round-by-round folds lack): the O(r²) garbage
// `g_ij = ⟨s_i,s_j⟩` is NOT revealed — it is COMMITTED in an outer commitment `u`
// (κ ring elts), and `(t_i, g)` become the CHILD WITNESS proven recursively, so
// each level sends only O(κ) + the amortized opening `z`. Verifier checks (paper
// eq. (1)(2)(3)): `u = B·decompose(t‖g)`, `A·z = Σ c_i t_i`, `⟨z,z⟩ = Σ c_i c_j g_ij`,
// `Σ a_ij g_ij = b` (φ=0 / pure-quadratic case; the linear `h_ij`/`φ` terms extend
// this per the paper). Base case reveals `(t,g)`; the recursion defers them.

#[derive(Clone)]
pub struct LabradorProof {
    pub u1: PolyVec,        // outer commitment to [t ‖ g] (the committed garbage)
    pub z: PolyVec,         // amortized opening z = Σ c_i s_i
    pub t: Vec<PolyVec>,    // inner commitments (revealed at BASE; recursed otherwise)
    pub g: Vec<Vec<Poly>>,  // garbage (revealed at BASE)
}

fn labrador_challenges(u1: &PolyVec, r: usize) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/reduction/v1");
    for p in &u1.0 {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// Flatten the inner commitments and garbage into one vector for the outer commit
/// / the child witness: `[t_0 ‖ … ‖ t_{r-1} ‖ g_{00} ‖ g_{01} ‖ … ]` (upper triangle).
fn flatten_t_g(t: &[PolyVec], g: &[Vec<Poly>]) -> PolyVec {
    let mut v: Vec<Poly> = Vec::new();
    for ti in t {
        v.extend(ti.0.iter().cloned());
    }
    for (i, gi) in g.iter().enumerate() {
        for gij in gi.iter().skip(i) {
            v.push(gij.clone());
        }
    }
    PolyVec(v)
}

/// One faithful LaBRADOR reduction round. `b_outer` commits the flattened,
/// gadget-decomposed `[t‖g]` (short). `agg` is the single aggregated quadratic
/// constraint (`aggregate_constraints` output). Bits/limbs decompose `[t‖g]`.
pub fn prove_labrador_reduction(
    a: &PolyMatrix,
    b_outer: &PolyMatrix,
    s: &[PolyVec],
    bits: u32,
    limbs: usize,
) -> LabradorProof {
    let r = s.len();
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let mut g = vec![vec![Poly::zero(); r]; r];
    for i in 0..r {
        for j in i..r {
            let gij = dot(&s[i], &s[j]);
            g[i][j] = gij.clone();
            g[j][i] = gij;
        }
    }
    let tg = flatten_t_g(&t, &g);
    let u1 = b_outer.matvec(&gadget_decompose(&tg, bits, limbs));
    let c = labrador_challenges(&u1, r);
    let mut z = PolyVec::zero(s[0].len());
    for i in 0..r {
        z = z.add(&s[i].mul_poly(&c[i]));
    }
    LabradorProof { u1, z, t, g }
}

/// Verify one reduction (base case: `t,g` revealed). Checks paper (1)(2)(3).
pub fn verify_labrador_reduction(
    a: &PolyMatrix,
    b_outer: &PolyMatrix,
    pf: &LabradorProof,
    agg: &QuadConstraint,
    bits: u32,
    limbs: usize,
    norm_bound: u64,
) -> bool {
    let r = pf.t.len();
    if pf.g.len() != r {
        return false;
    }
    // Guard ragged `g`, wrong-rank `t`/`z` before flatten/matvec (reject, not panic).
    if pf.g.iter().any(|row| row.len() != r)
        || pf.t.iter().any(|ti| ti.len() != a.rows)
        || pf.z.len() != a.cols
    {
        return false;
    }
    // (1) outer commitment opens.
    let tg = flatten_t_g(&pf.t, &pf.g);
    if b_outer.matvec(&gadget_decompose(&tg, bits, limbs)) != pf.u1 {
        return false;
    }
    let c = labrador_challenges(&pf.u1, r);
    // (2) A·z = Σ c_i t_i, ‖z‖ ≤ γ.
    let az = a.matvec(&pf.z);
    let mut fold_t = PolyVec::zero(a.rows);
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if az != fold_t || pf.z.inf_norm() > norm_bound {
        return false;
    }
    // (3) ⟨z,z⟩ = Σ c_i c_j g_ij  AND  Σ a_ij g_ij = b (the aggregated constraint).
    let zz = dot(&pf.z, &pf.z);
    let mut quad = Poly::zero();
    for i in 0..r {
        for j in 0..r {
            quad = quad.add(&c[i].mul_ntt(&c[j]).mul_ntt(&pf.g[i][j]));
        }
    }
    if zz != quad {
        return false;
    }
    eval_constraint(agg, &pf.g) == agg.b
}

// ─────────────────────────────────────────────────────────────────────────
// §5.3 recursion: the witness-reduction transform.
//
// After one reduction the "witness of the next instance" is `(z, v=t‖g[‖h])`.
// To recurse (and actually SHRINK), the paper (§5.3) does two things before
// re-invoking the protocol:
//   (a) DECOMPOSE the masked opening `z = z⁽⁰⁾ + b·z⁽¹⁾` mod a base `b`
//       (centered), so the child witness stays short instead of the coeffs of
//       `z` blowing up round over round;
//   (b) RE-CHUNK `z⁽⁰⁾, z⁽¹⁾` into `ν` vectors each and `v` into `µ` vectors,
//       all zero-padded to `n' = max(⌈n/ν⌉, ⌈m/µ⌉)`, giving `r' = 2ν+µ`
//       child vectors of rank `n'`. Choosing `n/ν ≈ m/µ` (and `r' ≈ √(child
//       rank sum)`) is what makes each level ≈√-smaller.
//
// These two functions are the MECHANICAL core (round-trip exact); the child
// *constraint* family (checks (1)(2)(3) rewritten as eq-(6) dot products over
// the re-chunked witness) is the soundness-critical piece built on top.
// ─────────────────────────────────────────────────────────────────────────

/// Centered representative of `a ∈ [0,q)` in `(−q/2, q/2]`.
fn centered(a: u64) -> i128 {
    let q = Poly::Q as i128;
    let a = a as i128;
    if a > q / 2 { a - q } else { a }
}

/// Decompose `z = z⁽⁰⁾ + base·z⁽¹⁾` with **centered** low part: every coeff of
/// `z⁽⁰⁾` lies in `(−base/2, base/2]`. Exact reconstruction (§5.3): the low part
/// is uniform mod `base`, the high part carries the rest. `base ≥ 2`.
pub fn decompose_z_centered(z: &PolyVec, base: i64) -> (PolyVec, PolyVec) {
    assert!(base >= 2, "decomposition base must be ≥ 2");
    let b = base as i128;
    let mut z0 = Vec::with_capacity(z.len());
    let mut z1 = Vec::with_capacity(z.len());
    for p in &z.0 {
        let mut c0 = vec![0i64; Poly::D];
        let mut c1 = vec![0i64; Poly::D];
        for (k, &a) in p.c.iter().enumerate() {
            let x = centered(a);
            // centered remainder r0 ∈ (−b/2, b/2], q1 = (x − r0)/b
            let mut r0 = x.rem_euclid(b);
            if r0 > b / 2 {
                r0 -= b;
            }
            let q1 = (x - r0) / b;
            c0[k] = r0 as i64;
            c1[k] = q1 as i64;
        }
        z0.push(Poly::from_signed(&c0));
        z1.push(Poly::from_signed(&c1));
    }
    (PolyVec(z0), PolyVec(z1))
}

/// The re-chunked child witness produced by §5.3.
pub struct Rechunked {
    /// `r' = 2ν+µ` child vectors, each of rank `n'` (zero-padded).
    pub s: Vec<PolyVec>,
    pub r_prime: usize,
    pub n_prime: usize,
    pub nu: usize,
    pub mu: usize,
}

/// Split a `PolyVec` into `k` contiguous chunks of `stride = ⌈len/k⌉` logical
/// elements each, every chunk zero-padded to `pad_len ≥ stride`. Chunk `c` holds
/// source indices `[c·stride, (c+1)·stride)` at positions `[0, stride)`. Returns
/// exactly `k` vectors. (The read stride is `stride`, NOT `pad_len` — mixing the
/// two mis-places coordinates when `pad_len ≠ stride`.)
fn chunk_padded(v: &PolyVec, k: usize, stride: usize, pad_len: usize) -> Vec<PolyVec> {
    debug_assert!(pad_len >= stride);
    let mut out = Vec::with_capacity(k);
    for c in 0..k {
        let mut piece = vec![Poly::zero(); pad_len];
        for j in 0..stride {
            let idx = c * stride + j;
            if idx < v.len() {
                piece[j] = v.0[idx].clone();
            }
        }
        out.push(PolyVec(piece));
    }
    out
}

/// §5.3 re-chunk: `z⁽⁰⁾ → ν`, `z⁽¹⁾ → ν`, `v → µ` vectors, all padded to
/// `n' = max(⌈n/ν⌉, ⌈m/µ⌉)`. Order is `[z0-chunks ‖ z1-chunks ‖ v-chunks]`, so
/// child indices `< 2ν` are the `z` parts (where the tridiagonal `a_ij` live)
/// and `≥ 2ν` are the linear `v` parts — matching eq. (6)'s `a_ij=0 unless
/// i,j ≤ 2ν`.
pub fn rechunk(z0: &PolyVec, z1: &PolyVec, v: &PolyVec, nu: usize, mu: usize) -> Rechunked {
    assert!(nu >= 1 && mu >= 1);
    assert_eq!(z0.len(), z1.len(), "z⁽⁰⁾ and z⁽¹⁾ have the witness rank n");
    let n = z0.len();
    let m = v.len();
    let zchunk = n.div_ceil(nu);
    let vchunk = m.div_ceil(mu);
    let n_prime = zchunk.max(vchunk);
    let mut s = Vec::with_capacity(2 * nu + mu);
    s.extend(chunk_padded(z0, nu, zchunk, n_prime));
    s.extend(chunk_padded(z1, nu, zchunk, n_prime));
    s.extend(chunk_padded(v, mu, vchunk, n_prime));
    Rechunked { s, r_prime: 2 * nu + mu, n_prime, nu, mu }
}

/// §5.4 decomposition base `b = ⌈√(12·r·τ)·s⌉`, where `s = β/√(r·n·d)` is the
/// per-coefficient standard deviation of the (honest) witness. This balances the
/// low/high parts of `z` to the same width `s' = b/√12 ≈ s·√(rτ)/b`.
pub fn decomposition_base(beta: u64, r: usize, n: usize) -> i64 {
    let d = Poly::D as f64;
    let s = (beta as f64) / ((r * n) as f64 * d).sqrt();
    let b = ((12.0 * r as f64 * CHALLENGE_WEIGHT_TAU as f64).sqrt() * s).ceil();
    (b as i64).max(2)
}

/// Position of garbage entry `g_{ij}` (`i ≤ j`) in the flattened `[t‖g‖h]`
/// vector: after the `r·κ` inner-commitment entries, the `g` upper triangle is
/// row-major.
fn garbage_pos(i: usize, j: usize, r: usize, kappa: usize) -> usize {
    debug_assert!(i <= j);
    let before_row = i * r - i * (i.saturating_sub(1)) / 2; // Σ_{i'<i}(r−i')
    r * kappa + before_row + (j - i)
}

/// Position of the LINEAR garbage `h_{ij} = ⟨φ_i, s_j⟩` (FULL `r×r`, row-major)
/// in `[t‖g‖h]`: after `t` (`r·κ`) and the `g` upper triangle (`(r²+r)/2`).
fn h_pos(i: usize, j: usize, r: usize, kappa: usize) -> usize {
    r * kappa + (r * r + r) / 2 + i * r + j
}

/// Length of the flattened `[t‖g‖h]` = `r·κ + (r²+r)/2 + r²`.
fn flat_tgh_len(r: usize, kappa: usize) -> usize {
    r * kappa + (r * r + r) / 2 + r * r
}

/// Position of the CONJUGATED garbage `ĝ_{ij} = ⟨σ(s_i), s_j⟩` (FULL `r×r`,
/// row-major) in `[t‖g‖h‖ĝ]`: appended AFTER `h` so `garbage_pos`/`h_pos`/
/// `flat_tg_len` are unchanged and the ĝ region is purely additive (gated on
/// `has_conj`). It rides in the `v_b` block (committed in `u1_b`, before the fold
/// challenge `c` — which is all the conjugated-garbage binding needs).
fn ghat_pos(i: usize, j: usize, r: usize, kappa: usize) -> usize {
    flat_tgh_len(r, kappa) + i * r + j
}

/// Flattened length WITH the ĝ region: `flat_tgh_len + r²`.
fn flat_tghg_len(r: usize, kappa: usize) -> usize {
    flat_tgh_len(r, kappa) + r * r
}

/// Position of the CONJUGATED LINEAR garbage `ĥ_{ij} = ⟨σ(φ_i), s_j⟩` (FULL `r×r`,
/// row-major) in `[t‖g‖h‖ĝ‖ĥ]`: appended AFTER `ĝ`. Carries the LINEAR part of a
/// folded ct-constraint (`ct(ĥ_ii) = ⟪φ_i,s_i⟫`), the conjugated analogue of `h`.
fn hhat_pos(i: usize, j: usize, r: usize, kappa: usize) -> usize {
    flat_tghg_len(r, kappa) + i * r + j
}

/// Flattened length WITH both conjugated regions `[t‖g‖h‖ĝ‖ĥ]`: `flat_tghg_len + r²`.
fn flat_tghgh_len(r: usize, kappa: usize) -> usize {
    flat_tghg_len(r, kappa) + r * r
}

/// Length of the challenge-INDEPENDENT `[t‖g]` part = `r·κ + (r²+r)/2`. The
/// gadget-decomposed `v = decompose([t‖g‖h])` splits at `bits·limbs`·this into
/// `v_a` (t,g — committed in `u1_a`, before ψ) and `v_b` (h — committed in
/// `u1_b`, after ψ).
fn flat_tg_len(r: usize, kappa: usize) -> usize {
    r * kappa + (r * r + r) / 2
}

/// Deterministic byte serialization of a commitment vector (for binding it into
/// a Fiat-Shamir transcript).
fn commit_bytes(u: &PolyVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(u.len() * RING_DEGREE_D * 8);
    for p in &u.0 {
        for &x in &p.c {
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
    out
}

/// Fold-challenge derivation binding BOTH outer commitments `u1_a ‖ u1_b`.
fn fold_challenges_two(u1_a: &PolyVec, u1_b: &PolyVec, r: usize) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/labrador/fold/v2");
    for u in [u1_a, u1_b] {
        for p in &u.0 {
            for &x in &p.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let sd = h.finalize();
    let mut prg = HashPrg::from_digest(&sd);
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// Dense-ify the sparse linear part `Σ⟨φ_i,s_i⟩` of a constraint into `r`
/// vectors of rank `n` (missing `φ_i = 0`).
fn dense_phi(linear: &[(usize, PolyVec)], r: usize, n: usize) -> Vec<PolyVec> {
    let mut phi = vec![PolyVec::zero(n); r];
    for (i, p) in linear {
        if *i < r {
            phi[*i] = p.clone();
        }
    }
    phi
}

/// A running child witness + linear-form accumulator keyed by child-vector index.
/// Maps parent logical coordinates (`z⁰[k]`, `z¹[k]`, `v[m]`) into the re-chunked
/// child layout `[z0-chunks(ν) ‖ z1-chunks(ν) ‖ v-chunks(µ)]` at rank `n'`.
struct ChildMap {
    nu: usize,
    zchunk: usize,
    vchunk: usize,
    n_prime: usize,
    /// Number of z-blocks before the v-chunks: 2 (z⁰,z¹ — decompose) or 1 (last).
    z_blocks: usize,
    acc: std::collections::BTreeMap<usize, PolyVec>,
}

impl ChildMap {
    fn add(&mut self, child_idx: usize, coord: usize, w: Poly) {
        let e = self.acc.entry(child_idx).or_insert_with(|| PolyVec::zero(self.n_prime));
        e.0[coord] = e.0[coord].add(&w);
    }
    /// z⁰ chunk (also the whole-z chunk in the no-decompose last level).
    fn add_z0(&mut self, k: usize, w: Poly) {
        self.add(k / self.zchunk, k % self.zchunk, w);
    }
    fn add_z(&mut self, k: usize, w: Poly) {
        self.add_z0(k, w);
    }
    fn add_z1(&mut self, k: usize, w: Poly) {
        self.add(self.nu + k / self.zchunk, k % self.zchunk, w);
    }
    fn add_v(&mut self, m: usize, w: Poly) {
        self.add(self.z_blocks * self.nu + m / self.vchunk, m % self.vchunk, w);
    }
    fn into_linear(self) -> Vec<(usize, PolyVec)> {
        self.acc.into_iter().collect()
    }
}

/// The child LaBRADOR instance produced by one reduction (§5.3): the re-chunked
/// short witness `s'` and the constraint family `G` it must satisfy. `verify`
/// this level = check the child witness is short AND `((G,{},β'),(s'))∈R`, i.e.
/// `eval_constraint_on_witness(g_k, s') == g_k.b` for every `g_k` — which is why
/// the protocol composes with itself.
pub struct ChildInstance {
    pub constraints: Vec<QuadConstraint>,
    /// Child CONSTANT-TERM constraints — the parent ct-family LOWERED onto the
    /// committed conjugated garbage `ĝ` (`Σa_ij⟪s_i,s_j⟫=τ` ⇒ `Σa_ij·ct(ĝ_ij)=τ`,
    /// linear in the child witness). Empty unless the level carries a ct-family.
    pub ct_constraints: Vec<CtConstraint>,
    pub s: Vec<PolyVec>,
    pub r_prime: usize,
    pub n_prime: usize,
    pub base_z: i64,
    /// Commitment to the challenge-independent `[t‖g]` (bound BEFORE ψ).
    pub u1_a: PolyVec,
    /// Commitment to `h` (the ψ-dependent linear garbage; bound after ψ).
    pub u1_b: PolyVec,
}

/// The PUBLIC decomposition base for level with `‖s‖∞ ≤ β`, rank `n`, mult `r`.
/// The fold `z = Σ cᵢ sᵢ` has `‖z‖∞ ≤ r·τ·β` (τ signed ±1s per challenge, r of
/// them), so `base_z = ⌈√(r·τ·β)⌉` balances the 2-part split (`z⁰ ~ base_z`,
/// `z¹ ~ ‖z‖/base_z ≈ base_z`). Derived from the public NORM BOUND, never the
/// actual witness — so the verifier reconstructs the child constraints identically.
pub fn public_base_z(beta: u64, r: usize, _n: usize) -> i64 {
    let z_bound = (r as u128) * (CHALLENGE_WEIGHT_TAU as u128) * (beta as u128);
    ((z_bound as f64).sqrt().ceil() as i64).max(2)
}

/// The child witness's `‖·‖∞` bound: `max(z⁰ ≤ base_z/2, z¹ ≤ ⌈z_bound/base_z⌉,
/// v ≤ 2^{bits-1})`. Both sides compute it publicly to size the next level.
pub fn child_beta(beta: u64, r: usize, base_z: i64, bits: u32) -> u64 {
    let z_bound = (r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * beta;
    let z0_bound = (base_z as u64).div_ceil(2);
    let z1_bound = z_bound.div_ceil(base_z as u64) + 1;
    let v_bound = 1u64 << (bits - 1);
    z0_bound.max(z1_bound).max(v_bound)
}

/// Build the child constraint family from PUBLIC data only (§5.3, φ=0/no-JL):
/// checks (1) `u1=B·v`, (2) `A·z=Σcᵢtᵢ`, (3a) `⟨z,z⟩=Σcᵢcⱼgᵢⱼ`, aggregated (3c)
/// `Σaᵢⱼgᵢⱼ=b`, as eq-(6) dot products over `s' = [z0‖z1‖v]`. Prover and verifier
/// call this identically — the constraints depend only on `a`, `b_outer`, `agg`,
/// the challenges `c` (from `u1`), the gadget (`bits`/`limbs`), the re-chunk
/// (`nu`/`mu`) and the PUBLIC `base_z` — never the secret witness.
pub fn build_child_constraints(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    agg: &QuadConstraint,
    u1_a: &PolyVec,
    u1_b: &PolyVec,
    c: &[Poly],
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
    base_z: i64,
) -> Vec<QuadConstraint> {
    build_child_constraints_conj(a, b_a, b_b, agg, u1_a, u1_b, c, bits, limbs, nu, mu, base_z, false)
}

/// [`build_child_constraints`] with the `has_conj` flag. When true, adds (3d) the
/// conjugated-garbage BINDING `⟨σ(z),z⟩ = Σ σ(c_i)c_j·ĝ_ij` and routes the
/// aggregate's `conj_terms` to the `ĝ` positions in (3c) — so ct-constraints
/// (lowered onto `ct(ĝ_ij)`) fold through the level. `has_conj = false`
/// reproduces `build_child_constraints` exactly.
#[allow(clippy::too_many_arguments)]
pub fn build_child_constraints_conj(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    agg: &QuadConstraint,
    u1_a: &PolyVec,
    u1_b: &PolyVec,
    c: &[Poly],
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
    base_z: i64,
    has_conj: bool,
) -> Vec<QuadConstraint> {
    let r = c.len();
    let n = a.cols;
    let kappa = a.rows;
    let va_len = b_a.cols;
    let m_len = va_len + b_b.cols;
    let (zchunk, vchunk) = (n.div_ceil(nu), m_len.div_ceil(mu));
    let n_prime = zchunk.max(vchunk);
    let mk = || ChildMap { nu, zchunk, vchunk, n_prime, z_blocks: 2, acc: std::collections::BTreeMap::new() };
    let base_g_pow = |l: usize| -> i64 { 1i64 << (bits * l as u32) };
    let mut constraints: Vec<QuadConstraint> = Vec::new();

    // (1a) u1_a = B_a·v_a  →  κ linear rows over the v_a-chunks (t‖g region).
    for l in 0..kappa {
        let mut m = mk();
        for (col, coeff) in b_a.m[l].iter().enumerate() {
            if coeff.inf_norm() != 0 {
                m.add_v(col, coeff.clone());
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: u1_a.0[l].clone() });
    }
    // (1b) u1_b = B_b·v_b  →  κ linear rows over the v_b-chunks (h region, offset va_len).
    for l in 0..kappa {
        let mut m = mk();
        for (col, coeff) in b_b.m[l].iter().enumerate() {
            if coeff.inf_norm() != 0 {
                m.add_v(va_len + col, coeff.clone());
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: u1_b.0[l].clone() });
    }

    // (2) A·z = Σ cᵢ tᵢ  →  κ linear rows. z[k]=z0[k]+base_z·z1[k];
    //     tᵢ[ℓ] = recompose slice of v at flat pos (i·κ+ℓ).
    for l in 0..kappa {
        let mut m = mk();
        for k in 0..n {
            let aik = &a.m[l][k];
            if aik.inf_norm() != 0 {
                m.add_z0(k, aik.clone());
                m.add_z1(k, aik.scalar_mul(base_z));
            }
        }
        for i in 0..r {
            let p = i * kappa + l; // flat position of tᵢ[ℓ] in [t‖g]
            for ll in 0..limbs {
                m.add_v(p * limbs + ll, c[i].neg().scalar_mul(base_g_pow(ll)));
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: Poly::zero() });
    }

    // (3a) ⟨z,z⟩ − Σ cᵢcⱼ gᵢⱼ = 0  →  ONE quadratic-in-z + linear-in-v constraint.
    //   ⟨z,z⟩ = Σ_c ⟨z0_c,z0_c⟩ + 2·base_z·⟨z0_c,z1_c⟩ + base_z²·⟨z1_c,z1_c⟩.
    let mut quad_terms: Vec<(usize, usize, Poly)> = Vec::new();
    for cc in 0..nu {
        quad_terms.push((cc, cc, Poly::one()));
        quad_terms.push((nu + cc, nu + cc, Poly::one().scalar_mul(base_z * base_z)));
        quad_terms.push((cc, nu + cc, Poly::one().scalar_mul(2 * base_z)));
    }
    let mut mlin = mk();
    for i in 0..r {
        for j in 0..r {
            let (pi, pj) = if i <= j { (i, j) } else { (j, i) };
            let p = garbage_pos(pi, pj, r, kappa);
            let cij = c[i].mul_ntt(&c[j]).neg(); // moved to LHS
            for ll in 0..limbs {
                mlin.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: quad_terms, linear: mlin.into_linear(), b: Poly::zero() });

    // (3b) Σᵢ cᵢ⟨φᵢ,z⟩ − Σᵢⱼ cᵢcⱼ hᵢⱼ = 0  →  ONE linear constraint (z-part + h-part).
    //   LHS = ⟨ψ, z⟩ with ψ = Σᵢ cᵢ·φᵢ; RHS binds the linear garbage hᵢⱼ=⟨φᵢ,sⱼ⟩.
    let phi = dense_phi(&agg.linear, r, n);
    let mut psi = PolyVec::zero(n);
    for i in 0..r {
        psi = psi.add(&phi[i].mul_poly(&c[i]));
    }
    let mut mh = mk();
    for k in 0..n {
        if psi.0[k].inf_norm() != 0 {
            mh.add_z0(k, psi.0[k].clone());
            mh.add_z1(k, psi.0[k].scalar_mul(base_z));
        }
    }
    for i in 0..r {
        for j in 0..r {
            let p = h_pos(i, j, r, kappa);
            let cij = c[i].mul_ntt(&c[j]).neg(); // moved to LHS
            for ll in 0..limbs {
                mh.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: mh.into_linear(), b: Poly::zero() });

    // (3c) aggregated statement Σ aᵢⱼ gᵢⱼ + Σᵢ hᵢᵢ = agg.b  →  ONE linear-in-v constraint.
    //   Σhᵢᵢ = Σ⟨φᵢ,sᵢ⟩ is the LINEAR part of the aggregated function F.
    let mut m = mk();
    for (i, j, aij) in &agg.terms {
        let (pi, pj) = if i <= j { (*i, *j) } else { (*j, *i) };
        let p = garbage_pos(pi, pj, r, kappa);
        for ll in 0..limbs {
            m.add_v(p * limbs + ll, aij.scalar_mul(base_g_pow(ll)));
        }
    }
    for i in 0..r {
        let p = h_pos(i, i, r, kappa);
        for ll in 0..limbs {
            m.add_v(p * limbs + ll, Poly::one().scalar_mul(base_g_pow(ll)));
        }
    }
    // (3c-conj) the aggregate's conjugated terms Σ âᵢⱼ·ĝᵢⱼ ride the ĝ positions.
    if has_conj {
        for (i, j, aij) in &agg.conj_terms {
            let p = ghat_pos(*i, *j, r, kappa);
            for ll in 0..limbs {
                m.add_v(p * limbs + ll, aij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: agg.b.clone() });

    // (3d) CONJUGATED-GARBAGE BINDING: ⟨σ(z),z⟩ − Σᵢⱼ σ(cᵢ)cⱼ·ĝᵢⱼ = 0. The
    //   quadratic side mirrors (3a) with σ on one operand (NOT symmetric, so both
    //   off-diagonal orders appear); the linear side pins the committed ĝ to the
    //   fold via the SAME single-challenge whole-ring binding as g. Its conj_terms
    //   keep the recursion `has_conj` at the next level (conjugation propagates).
    if has_conj {
        let mut conj_terms: Vec<(usize, usize, Poly)> = Vec::new();
        for cc in 0..nu {
            conj_terms.push((cc, cc, Poly::one()));
            conj_terms.push((nu + cc, nu + cc, Poly::one().scalar_mul(base_z * base_z)));
            conj_terms.push((cc, nu + cc, Poly::one().scalar_mul(base_z)));
            conj_terms.push((nu + cc, cc, Poly::one().scalar_mul(base_z)));
        }
        let mut mg = mk();
        for i in 0..r {
            for j in 0..r {
                let p = ghat_pos(i, j, r, kappa);
                let cij = c[i].conjugate().mul_ntt(&c[j]).neg(); // −σ(cᵢ)·cⱼ (LHS)
                for ll in 0..limbs {
                    mg.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
                }
            }
        }
        constraints.push(QuadConstraint {
            conj_terms,
            terms: vec![],
            linear: mg.into_linear(),
            b: Poly::zero(),
        });
    }

    constraints
}

/// Same child-constraint set as [`build_child_constraints_conj`], plus the
/// LINEAR conjugated-garbage (ĥ) binding when the lowered ct-family carries a
/// linear part. ĥ_{ij}=⟨σ(φ̂_i),s_j⟩ commits the aggregated linear ct so it can
/// ride one more fold as a linear ct on the child.
///
/// (3d-linear) ĥ BINDING: conj_dot(Φ,z) − Σᵢⱼ σ(cᵢ)cⱼ·ĥᵢⱼ = 0, with
/// Φ = Σᵢ cᵢ·φ̂_i. The z-side is linear with the PUBLIC conjugated coefficients
/// σ(Φ_k) (σ falls on the public Φ, not the witness), mirroring the whole-ring
/// single-shot binding used for ĝ in (3d).
#[allow(clippy::too_many_arguments)]
pub fn build_child_constraints_conj_ct(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    agg: &QuadConstraint,
    ct_agg: Option<&CtConstraint>,
    u1_a: &PolyVec,
    u1_b: &PolyVec,
    c: &[Poly],
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
    base_z: i64,
    has_conj: bool,
) -> Vec<QuadConstraint> {
    let mut constraints = build_child_constraints_conj(
        a, b_a, b_b, agg, u1_a, u1_b, c, bits, limbs, nu, mu, base_z, has_conj,
    );
    let ct = match ct_agg {
        Some(ct) if has_conj && !ct.linear.is_empty() => ct,
        _ => return constraints,
    };
    let r = c.len();
    let n = a.cols;
    let kappa = a.rows;
    let va_len = b_a.cols;
    let m_len = va_len + b_b.cols;
    let (zchunk, vchunk) = (n.div_ceil(nu), m_len.div_ceil(mu));
    let n_prime = zchunk.max(vchunk);
    let mk = || ChildMap { nu, zchunk, vchunk, n_prime, z_blocks: 2, acc: std::collections::BTreeMap::new() };
    let base_g_pow = |l: usize| -> i64 { 1i64 << (bits * l as u32) };

    let phi = dense_phi(&ct.linear, r, n);
    let mut cap_phi = PolyVec::zero(n);
    for i in 0..r {
        cap_phi = cap_phi.add(&phi[i].mul_poly(&c[i]));
    }
    let mut mh = mk();
    // z-side: conj_dot(Φ,z) = Σ_k σ(Φ_k)·z_k, z_k = z0_k + base_z·z1_k.
    for k in 0..n {
        let sk = cap_phi.0[k].conjugate();
        if sk.inf_norm() != 0 {
            mh.add_z0(k, sk.clone());
            mh.add_z1(k, sk.scalar_mul(base_z));
        }
    }
    // ĥ-side: −Σᵢⱼ σ(cᵢ)·cⱼ·ĥᵢⱼ (whole-ring; both off-diagonal orders present).
    for i in 0..r {
        for j in 0..r {
            let p = hhat_pos(i, j, r, kappa);
            let cij = c[i].conjugate().mul_ntt(&c[j]).neg();
            for ll in 0..limbs {
                mh.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: mh.into_linear(), b: Poly::zero() });
    constraints
}

/// Build the child instance from a parent reduction (§5.3), TWO-COMMITMENT
/// variant that closes the aggregation Fiat-Shamir ordering hole. Order:
/// 1. commit the challenge-independent `t‖g` → `u1_a` (`B_a`);
/// 2. derive ψ = aggregate BOUND to `u1_a` → `agg` (so the witness is fixed
///    before ψ; a prover cannot pick a witness after seeing ψ);
/// 3. compute the linear garbage `h` from `agg.linear`, commit → `u1_b` (`B_b`);
/// 4. fold challenges `c` from `u1_a ‖ u1_b`.
/// `family` is the FULL constraint set (NOT pre-aggregated). `beta` is the
/// PUBLIC `‖s‖∞` bound.
pub fn reduce_to_child(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    s: &[PolyVec],
    family: &[QuadConstraint],
    beta: u64,
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
) -> ChildInstance {
    reduce_to_child_conj(a, b_a, b_b, s, family, beta, bits, limbs, nu, mu, false)
}

/// [`reduce_to_child`] with the `has_conj` flag: when true, ALSO compute + commit
/// the conjugated garbage `ĝ_ij = ⟨σ(s_i),s_j⟩` (appended to the `v_b` block) so
/// ct-constraints lower onto it and fold through the level. `has_conj = false`
/// reproduces `reduce_to_child` exactly.
#[allow(clippy::too_many_arguments)]
pub fn reduce_to_child_conj(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    s: &[PolyVec],
    family: &[QuadConstraint],
    beta: u64,
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
    has_conj: bool,
) -> ChildInstance {
    reduce_to_child_conj_ct(a, b_a, b_b, s, family, &[], beta, bits, limbs, nu, mu, has_conj)
}

/// [`reduce_to_child_conj`] that ALSO folds a ct-family one level: produces the
/// child ct-family (parent ct lowered onto the committed `ĝ`). Requires
/// `has_conj` when `ct_family` is non-empty (the lowering rides `ĝ`).
#[allow(clippy::too_many_arguments)]
pub fn reduce_to_child_conj_ct(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    s: &[PolyVec],
    family: &[QuadConstraint],
    ct_family: &[CtConstraint],
    beta: u64,
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
    has_conj: bool,
) -> ChildInstance {
    let r = s.len();
    let n = s[0].len();
    // 1. Inner commitments + quadratic garbage (challenge-INDEPENDENT).
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let mut g = vec![vec![Poly::zero(); r]; r];
    for i in 0..r {
        for j in i..r {
            let gij = dot(&s[i], &s[j]);
            g[i][j] = gij.clone();
            g[j][i] = gij;
        }
    }
    let v_a = gadget_decompose(&flatten_tg(&t, &g), bits, limbs);
    let u1_a = b_a.matvec(&v_a);
    // 2. Aggregate BOUND to u1_a (ψ fixed only after the witness is committed).
    let agg = aggregate_constraints_bound(family, &commit_bytes(&u1_a));
    // 3. Linear garbage h_{ij}=⟨φ_i,s_j⟩ from the (now-bound) aggregate; commit.
    //    Plus (has_conj) conjugated garbage ĝ_{ij}=⟨σ(s_i),s_j⟩, appended to v_b.
    let phi = dense_phi(&agg.linear, r, n);
    let mut h = vec![vec![Poly::zero(); r]; r];
    for i in 0..r {
        for j in 0..r {
            h[i][j] = dot(&phi[i], &s[j]);
        }
    }
    // Conjugated garbage: ĝ_{ij}=⟨σ(s_i),s_j⟩ (quadratic) and ĥ_{ij}=⟨σ(φ̂_i),s_j⟩
    // (linear), where φ̂ is the ct-family's AGGREGATED linear part (bound to u1_a).
    // ĥ carries a LOWERED (linear) ct-constraint through the next fold.
    let ct_agg = if ct_family.is_empty() {
        None
    } else {
        Some(aggregate_ct_constraints(ct_family, &commit_bytes(&u1_a)))
    };
    let v_b = if has_conj {
        let ghat = conj_garbage(s);
        let hhat = match &ct_agg {
            Some(ac) => {
                let phi_ct = dense_phi(&ac.linear, r, n);
                conj_linear_garbage(&phi_ct, s)
            }
            None => vec![vec![Poly::zero(); r]; r],
        };
        gadget_decompose(&flatten_h_ghat(&h, &ghat, &hhat), bits, limbs)
    } else {
        gadget_decompose(&flatten_h(&h), bits, limbs)
    };
    let u1_b = b_b.matvec(&v_b);
    let v = v_a.concat(&v_b); // = decompose([t‖g‖h[‖ĝ‖ĥ]]); positions unchanged
    // 4. Fold challenges from BOTH commitments.
    let c = fold_challenges_two(&u1_a, &u1_b, r);
    let mut z = PolyVec::zero(n);
    for i in 0..r {
        z = z.add(&s[i].mul_poly(&c[i]));
    }
    let base_z = public_base_z(beta, r, n);
    let (z0, z1) = decompose_z_centered(&z, base_z);
    let rc = rechunk(&z0, &z1, &v, nu, mu);
    let constraints = build_child_constraints_conj_ct(
        a, b_a, b_b, &agg, ct_agg.as_ref(), &u1_a, &u1_b, &c, bits, limbs, nu, mu, base_z, has_conj,
    );
    // Lower the ct-family (quadratic → ĝ, linear → ĥ diagonal).
    let ct_constraints = match &ct_agg {
        None => Vec::new(),
        Some(ac) => {
            debug_assert!(has_conj, "ct-family fold requires conjugated garbage");
            build_child_ct_family(a, b_a, b_b, std::slice::from_ref(ac), r, bits, limbs, nu, mu)
        }
    };
    ChildInstance { constraints, ct_constraints, s: rc.s, r_prime: rc.r_prime, n_prime: rc.n_prime, base_z, u1_a, u1_b }
}

/// Lower a QUADRATIC-only parent ct-family onto the committed conjugated garbage
/// `ĝ` of THIS level, producing the child ct-family. Each parent constraint
/// `Σ a_ij⟪s_i,s_j⟫ = τ` becomes `Σ a_ij·ct(ĝ_ij) = τ` — LINEAR in the child
/// witness: `ct(ĝ_ij) = Σ_l base^l·ct(ĝ_ij^(l))` over the `ĝ` gadget-limbs, placed
/// at the SAME rechunked positions the whole-ring `(3c-conj)` uses (via `ChildMap`
/// with `e₀`-scaled coefficients, since `ct(x)=⟪e₀,x⟫`). Because `ĝ_ij` is
/// whole-ring bound `(3d)` to `⟨σ(s_i),s_j⟩`, `ct(ĝ_ij)=⟪s_i,s_j⟫`, so the child
/// ct-family holds iff the parent did. Quadratic-only for now (parent linear
/// ct-terms need conjugated LINEAR garbage — next step).
#[allow(clippy::too_many_arguments)]
pub fn build_child_ct_family(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    ct_family: &[CtConstraint],
    r: usize,
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
) -> Vec<CtConstraint> {
    let n = a.cols;
    let kappa = a.rows;
    let va_len = b_a.cols;
    let m_len = va_len + b_b.cols;
    let (zchunk, vchunk) = (n.div_ceil(nu), m_len.div_ceil(mu));
    let n_prime = zchunk.max(vchunk);
    let mk = || ChildMap { nu, zchunk, vchunk, n_prime, z_blocks: 2, acc: std::collections::BTreeMap::new() };
    let base_g_pow = |l: usize| -> i64 { 1i64 << (bits * l as u32) };
    let q = Poly::Q as i128;
    let mut e0 = Poly::zero();
    e0.c[0] = 1;
    let mut out = Vec::with_capacity(ct_family.len());
    for con in ct_family {
        let mut m = mk();
        // Quadratic terms lower onto ĝ: Σ a_ij·ct(ĝ_ij).
        for (i, j, a_scalar) in &con.terms {
            let p = ghat_pos(*i, *j, r, kappa);
            for l in 0..limbs {
                let coeff = ((*a_scalar as i128) * (base_g_pow(l) as i128)).rem_euclid(q) as i64;
                m.add_v(p * limbs + l, e0.scalar_mul(coeff));
            }
        }
        // Linear part lowers onto the ĥ DIAGONAL: Σ_i ct(ĥ_ii) = Σ_i ⟪φ̂_i,s_i⟫
        // (the aggregated linear ct value; φ̂ is baked into ĥ at reduce time).
        if !con.linear.is_empty() {
            for i in 0..r {
                let p = hhat_pos(i, i, r, kappa);
                for l in 0..limbs {
                    let coeff = base_g_pow(l).rem_euclid(Poly::Q as i64);
                    m.add_v(p * limbs + l, e0.scalar_mul(coeff));
                }
            }
        }
        out.push(CtConstraint { terms: vec![], linear: m.into_linear(), target: con.target });
    }
    out
}

/// Flatten just `[t ‖ g(upper-tri)]` (the challenge-independent part).
fn flatten_tg(t: &[PolyVec], g: &[Vec<Poly>]) -> PolyVec {
    let mut v: Vec<Poly> = Vec::new();
    for ti in t {
        v.extend(ti.0.iter().cloned());
    }
    for (i, gi) in g.iter().enumerate() {
        for gij in gi.iter().skip(i) {
            v.push(gij.clone());
        }
    }
    PolyVec(v)
}

/// Flatten just `[h(full r×r)]` (the ψ-dependent linear garbage).
fn flatten_h(h: &[Vec<Poly>]) -> PolyVec {
    let mut v: Vec<Poly> = Vec::new();
    for hi in h {
        for hij in hi {
            v.push(hij.clone());
        }
    }
    PolyVec(v)
}

/// Flatten `[h ‖ ĝ ‖ ĥ]` — the `v_b` block with both conjugated-garbage regions
/// appended (each full `r×r`, row-major). `ĥ` is the conjugated LINEAR garbage
/// (all-zero when the level carries no linear ct-terms).
fn flatten_h_ghat(h: &[Vec<Poly>], ghat: &[Vec<Poly>], hhat: &[Vec<Poly>]) -> PolyVec {
    let mut v = flatten_h(h).0;
    for region in [ghat, hhat] {
        for row in region {
            for e in row {
                v.push(e.clone());
            }
        }
    }
    PolyVec(v)
}

// ─────────────────────────────────────────────────────────────────────────
// Modular Johnson-Lindenstrauss norm proof (§4). To prove the witness `s` has
// small ℓ₂-norm WITHOUT sending it, the verifier samples Π ∈ {−1,0,1}^{256×d·N}
// (probs 1/2,1/4,1/4) and the prover sends `p = Π·flatten(s)` (256 ints). By
// Lemma 4.1, `‖p‖₂ ≥ √30·‖s‖₂` w.h.p., so `‖p‖₂ ≤ √30·b ⟹ ‖s‖₂ ≤ b`. This is
// a SOUNDNESS component (enforces witness shortness — the M-SIS binding needs
// it), NOT a size reduction. Hard constraint (mod-q strengthening): `b < q/125`.
// ─────────────────────────────────────────────────────────────────────────

/// Flatten a witness to its centered integer coefficient vector.
fn flatten_coeffs(s: &[PolyVec]) -> Vec<i64> {
    let mut w = Vec::new();
    for v in s {
        for p in &v.0 {
            for &c in &p.c {
                w.push(centered(c) as i64);
            }
        }
    }
    w
}

/// Sample the JL projection `p = Π·w ∈ Z^256`, Π entries `{−1,0,1}` with prob
/// `{1/4,1/2,1/4}` from `seed` (public — both sides derive the same Π).
pub fn jl_project(s: &[PolyVec], seed: u64) -> [i128; 256] {
    let w = flatten_coeffs(s);
    // Accumulate in i128 (a single projection sums up to dim·d terms of ±2^35;
    // i64 would wrap for witnesses above ~2^28 elements). Store as i128.
    let mut p = [0i128; 256];
    for (k, pk) in p.iter_mut().enumerate() {
        let mut prg = SplitMix64::new(seed ^ ((k as u64) << 32));
        let mut acc = 0i128;
        for &wj in &w {
            // 2 bits: 00/01 → 0 (½), 10 → +1 (¼), 11 → −1 (¼).
            let pi = match prg.next_u64() & 3 {
                2 => 1i128,
                3 => -1i128,
                _ => 0,
            };
            acc += pi * wj as i128;
        }
        *pk = acc;
    }
    p
}

/// ℓ₂-norm² of the projection (u128; each `|pₖ|²` and their sum stay in range for
/// the projection dimensions used).
fn l2_sq(p: &[i128; 256]) -> u128 {
    p.iter().map(|&x| (x * x) as u128).sum()
}

/// Verify the JL norm bound: `‖p‖₂ ≤ √30·b` convinces the verifier `‖s‖₂ ≤ b`
/// (Lemma 4.1). Requires `b < q/125` for the mod-q strengthening to hold.
pub fn jl_norm_ok(p: &[i128; 256], b: u128) -> bool {
    if b >= (Poly::Q as u128) / 125 {
        return false; // outside the sound range for this q
    }
    l2_sq(p) <= 30u128.saturating_mul(b.saturating_mul(b))
}

/// Reconstruct the JL projection rows as COEFFICIENT (ct) constraints
/// `⟪Π_k, s⟫ = p_k (mod q)` — the same `Π` and coordinate order as [`jl_project`].
/// Proving these against the committed `s` (e.g. via [`prove_ct_base_opening`])
/// BINDS the sent `p` to the witness, so `jl_norm_ok(p,·)` then enforces `‖s‖`
/// (closing the tight-norm gap the ZK NS22 base leaves open). Since an honest `p`
/// is short (‖p‖ ≪ q), binding `p mod q` pins `p` exactly.
pub fn jl_rows_as_ct(seed: u64, r: usize, n: usize, p: &[i128; 256]) -> Vec<CtConstraint> {
    let q = Poly::Q as i128;
    let qi = Poly::Q as i64;
    let mut out = Vec::with_capacity(256);
    for k in 0..256usize {
        let mut prg = SplitMix64::new(seed ^ ((k as u64) << 32));
        // Π_k as r ring vectors (dim n), filled in flatten_coeffs order (i,m,coeff).
        let mut cols: Vec<PolyVec> = (0..r).map(|_| PolyVec::zero(n)).collect();
        for col in cols.iter_mut() {
            for m in 0..n {
                for kk in 0..Poly::D {
                    let e = match prg.next_u64() & 3 {
                        2 => 1i64,
                        3 => -1i64,
                        _ => 0,
                    };
                    col.0[m].c[kk] = e.rem_euclid(qi) as u64;
                }
            }
        }
        let linear: Vec<(usize, PolyVec)> = cols.into_iter().enumerate().collect();
        out.push(CtConstraint { terms: vec![], linear, target: p[k].rem_euclid(q) as u64 });
    }
    out
}

/// Aggregate the 256 JL rows into ONE coefficient functional `⟪Φ,s⟫ = P` under
/// Fiat-Shamir scalar weights `ρ_k` bound to `p`: `Φ_i = Σ_k ρ_k·Π_{k,i}` (r ring
/// vectors of dim n), `P = Σ_k ρ_k·p_k (mod q)`. A violated JL row (fake `p_k`)
/// survives the aggregate with prob ≤ 1/q (Schwartz-Zippel), so binding `⟪Φ,s⟫=P`
/// binds every `p_k`. Same `Π`/order as [`jl_project`]/[`jl_rows_as_ct`].
pub fn jl_aggregate(seed: u64, r: usize, n: usize, p: &[i128; 256]) -> (Vec<PolyVec>, u64) {
    // Single-round: the row-projection Π and the weights ρ both key off `seed`.
    jl_aggregate_w(seed, seed, r, n, p)
}

/// Like [`jl_aggregate`] but with the row-projection `Π` keyed by `row_seed` (must
/// MATCH [`jl_project`], so `p` is fixed) and the aggregation weights `ρ` keyed by a
/// SEPARATE `weight_seed`. This lets the SAME projection `p` be collapsed under many
/// INDEPENDENT weight sets (the K-round amplification): each `weight_seed` gives a
/// fresh `≤1/q`-sound aggregation of the same 256 rows.
pub fn jl_aggregate_w(row_seed: u64, weight_seed: u64, r: usize, n: usize, p: &[i128; 256]) -> (Vec<PolyVec>, u64) {
    let q = Poly::Q as u128;
    // ρ_k from FS(weight_seed, p).
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/jl/aggregate/v1");
    h.update(weight_seed.to_le_bytes());
    for pk in p.iter() {
        h.update((pk.rem_euclid(q as i128) as u64).to_le_bytes());
    }
    let mut prg = HashPrg::from_digest(&h.finalize());
    let rho: Vec<u128> = (0..256).map(|_| (prg.next_u64() as u128) % q).collect();

    let mut phi = vec![PolyVec::zero(n); r];
    for (k, &rk) in rho.iter().enumerate() {
        // Π columns key off row_seed (fixed across rounds ⇒ same p).
        let mut prg2 = SplitMix64::new(row_seed ^ ((k as u64) << 32));
        for col in phi.iter_mut() {
            for m in 0..n {
                for kk in 0..Poly::D {
                    let e: u128 = match prg2.next_u64() & 3 {
                        2 => rk,                    // +ρ_k
                        3 => (q - rk) % q,          // −ρ_k
                        _ => 0,
                    };
                    let cur = col.0[m].c[kk] as u128;
                    col.0[m].c[kk] = ((cur + e) % q) as u64;
                }
            }
        }
    }
    let mut cap_p = 0u128;
    for (k, &rk) in rho.iter().enumerate() {
        cap_p = (cap_p + rk * (p[k].rem_euclid(q as i128) as u128)) % q;
    }
    (phi, cap_p as u64)
}

/// Aggregate a LINEAR ct-family (`Σᵢ⟪φᵢ,sᵢ⟫ = target` per constraint — e.g. the
/// FOLDED binary/range constraint) into ONE functional `(Φ_ct, P_ct)` under FS
/// scalar weights bound to `bind`, so it can ride the SAME conjugated-garbage (ĥ)
/// norm-binding as the JL rows. A violated ct survives with prob ≤ 1/q.
pub fn ct_family_aggregate(ct_family: &[CtConstraint], r: usize, n: usize, bind: &[u8]) -> (Vec<PolyVec>, u64) {
    let q = Poly::Q as u128;
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ns22-zk/ct-agg/v1");
    h.update(bind);
    h.update((ct_family.len() as u64).to_le_bytes());
    let mut prg = HashPrg::from_digest(&h.finalize());
    let mut phi = vec![PolyVec::zero(n); r];
    let mut cap_p = 0u128;
    for con in ct_family {
        debug_assert!(con.terms.is_empty(), "base ct-family must be linear (folded)");
        let rho = (prg.next_u64() as u128 % q) as i64;
        for (i, v) in &con.linear {
            if *i < r {
                phi[*i] = phi[*i].add(&v.scalar_mul(rho));
            }
        }
        cap_p = (cap_p + (rho as u128) * (con.target as u128 % q)) % q;
    }
    (phi, cap_p as u64)
}

/// Like [`ct_family_aggregate`] but also handles QUADRATIC ct-terms (so an
/// UNFOLDED binary/range ct rides directly): returns `(Φ_linear, gc_weights, P)`
/// where `gc_weights[i*r+j] = Σ ρ·a_ij` route to the conjugated-quadratic garbage
/// `ĝc_ij = conj_dot(sᵢ,sⱼ)` (whose ct is `⟪sᵢ,sⱼ⟫`). Same FS weights as the linear
/// version, so `ct(Σĥ_ii + Σ gc_weight·ĝc_ij) = Σρ·target = P`.
pub fn ct_family_aggregate_q(ct_family: &[CtConstraint], r: usize, n: usize, bind: &[u8]) -> (Vec<PolyVec>, Vec<Poly>, u64) {
    let q = Poly::Q as u128;
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ns22-zk/ct-agg/v1"); // SAME domain as ct_family_aggregate
    h.update(bind);
    h.update((ct_family.len() as u64).to_le_bytes());
    let mut prg = HashPrg::from_digest(&h.finalize());
    let mut phi = vec![PolyVec::zero(n); r];
    let mut gcw = vec![Poly::zero(); r * r];
    let mut cap_p = 0u128;
    for con in ct_family {
        let rho = (prg.next_u64() as u128 % q) as i64;
        for (i, v) in &con.linear {
            if *i < r {
                phi[*i] = phi[*i].add(&v.scalar_mul(rho));
            }
        }
        for (i, j, a) in &con.terms {
            if *i < r && *j < r {
                // ⟪sᵢ,sⱼ⟫ symmetric in coefficients: ct(gc_ij) = ct(gc_ji) = ⟪sᵢ,sⱼ⟫.
                let coeff = ((*a as i128) * (rho as i128)).rem_euclid(q as i128) as i64;
                gcw[*i * r + *j] = gcw[*i * r + *j].add(&Poly::one().scalar_mul(coeff));
            }
        }
        cap_p = (cap_p + (rho as u128) * (con.target as u128 % q)) % q;
    }
    (phi, gcw, cap_p as u64)
}

/// The per-round aggregation salt (domain-separates the K weight sets).
fn ct_agg_round_seed(jl_seed: u64, l: usize) -> u64 {
    jl_seed ^ (l as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xC7A6_1E5D_2B90_0000
}

/// Produce `kr` INDEPENDENT aggregations of the JL rows + ct-family, all against the
/// SAME projection `p` (row-projection `Π` keyed by `jl_seed`, weights keyed by a
/// per-round seed). Returns `(cap_phis, gcws, cap_ps)`, one entry per round — a
/// violated constraint survives ALL rounds only with prob `≤ (1/q)^kr`.
#[allow(clippy::type_complexity)]
fn ct_jl_aggregate_rounds(
    jl_seed: u64,
    r: usize,
    n: usize,
    p: &[i128; 256],
    ct_family: &[CtConstraint],
    kr: usize,
) -> (Vec<Vec<PolyVec>>, Vec<Vec<Poly>>, Vec<u64>) {
    let q = Poly::Q as u128;
    let mut cap_phis = Vec::with_capacity(kr);
    let mut gcws = Vec::with_capacity(kr);
    let mut cap_ps = Vec::with_capacity(kr);
    for l in 0..kr {
        let ws = ct_agg_round_seed(jl_seed, l);
        let (mut cap_phi, p_jl) = jl_aggregate_w(jl_seed, ws, r, n, p);
        let mut cap_p = p_jl as u128;
        let mut gcw = vec![Poly::zero(); r * r];
        if !ct_family.is_empty() {
            let (pc, gw, pp) = ct_family_aggregate_q(ct_family, r, n, &ws.to_le_bytes());
            for i in 0..r {
                cap_phi[i] = cap_phi[i].add(&pc[i]);
            }
            gcw = gw;
            cap_p = (cap_p + pp as u128) % q;
        }
        cap_phis.push(cap_phi);
        gcws.push(gcw);
        cap_ps.push(cap_p as u64);
    }
    (cap_phis, gcws, cap_ps)
}

// ─────────────────────────────────────────────────────────────────────────
// The NO-DECOMPOSE last level (§5.6, ln1292-1298): at the final reduction we do
// NOT split z into z⁰/z¹, so the child multiplicity is r'=ν+µ and the only
// quadratic term is a DIAGONAL ⟨z,z⟩ = Σ_c⟨z_c,z_c⟩. The aggregate is then
// diagonal-quadratic + linear — exactly the relation `base_ns22` proves.
// ─────────────────────────────────────────────────────────────────────────

/// Public last-level constraints over `s' = [z-chunks(ν) ‖ v-chunks(µ)]` (no z¹).
pub fn build_last_constraints(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    agg: &QuadConstraint,
    u1_a: &PolyVec,
    u1_b: &PolyVec,
    c: &[Poly],
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
) -> Vec<QuadConstraint> {
    let r = c.len();
    let n = a.cols;
    let kappa = a.rows;
    let va_len = b_a.cols;
    let m_len = va_len + b_b.cols;
    let (zchunk, vchunk) = (n.div_ceil(nu), m_len.div_ceil(mu));
    let n_prime = zchunk.max(vchunk);
    // v-chunks start at ν (only ν z-chunks now, no z¹).
    let mk = || ChildMap { nu, zchunk, vchunk, n_prime, acc: std::collections::BTreeMap::new(), z_blocks: 1 };
    let base_g_pow = |l: usize| -> i64 { 1i64 << (bits * l as u32) };
    let mut constraints: Vec<QuadConstraint> = Vec::new();

    // (1a) u1_a = B_a·v_a ; (1b) u1_b = B_b·v_b.
    for l in 0..kappa {
        let mut m = mk();
        for (col, coeff) in b_a.m[l].iter().enumerate() {
            if coeff.inf_norm() != 0 {
                m.add_v(col, coeff.clone());
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: u1_a.0[l].clone() });
    }
    for l in 0..kappa {
        let mut m = mk();
        for (col, coeff) in b_b.m[l].iter().enumerate() {
            if coeff.inf_norm() != 0 {
                m.add_v(va_len + col, coeff.clone());
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: u1_b.0[l].clone() });
    }
    // (2) A·z = Σ cᵢ tᵢ  (z whole, no z¹).
    for l in 0..kappa {
        let mut m = mk();
        for k in 0..n {
            let aik = &a.m[l][k];
            if aik.inf_norm() != 0 {
                m.add_z(k, aik.clone());
            }
        }
        for i in 0..r {
            let p = i * kappa + l;
            for ll in 0..limbs {
                m.add_v(p * limbs + ll, c[i].neg().scalar_mul(base_g_pow(ll)));
            }
        }
        constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: Poly::zero() });
    }
    // (3a) ⟨z,z⟩ − Σcᵢcⱼgᵢⱼ = 0 — DIAGONAL quadratic (a_cc=1 over ν z-chunks).
    let mut quad_terms: Vec<(usize, usize, Poly)> = Vec::new();
    for cc in 0..nu {
        quad_terms.push((cc, cc, Poly::one()));
    }
    let mut mlin = mk();
    for i in 0..r {
        for j in 0..r {
            let (pi, pj) = if i <= j { (i, j) } else { (j, i) };
            let p = garbage_pos(pi, pj, r, kappa);
            let cij = c[i].mul_ntt(&c[j]).neg();
            for ll in 0..limbs {
                mlin.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: quad_terms, linear: mlin.into_linear(), b: Poly::zero() });
    // (3b) Σcᵢ⟨φᵢ,z⟩ − Σcᵢcⱼhᵢⱼ = 0 (z whole).
    let phi = dense_phi(&agg.linear, r, n);
    let mut psi = PolyVec::zero(n);
    for i in 0..r {
        psi = psi.add(&phi[i].mul_poly(&c[i]));
    }
    let mut mh = mk();
    for k in 0..n {
        if psi.0[k].inf_norm() != 0 {
            mh.add_z(k, psi.0[k].clone());
        }
    }
    for i in 0..r {
        for j in 0..r {
            let p = h_pos(i, j, r, kappa);
            let cij = c[i].mul_ntt(&c[j]).neg();
            for ll in 0..limbs {
                mh.add_v(p * limbs + ll, cij.scalar_mul(base_g_pow(ll)));
            }
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: mh.into_linear(), b: Poly::zero() });
    // (3c) Σaᵢⱼgᵢⱼ + Σhᵢᵢ = b.
    let mut m = mk();
    for (i, j, aij) in &agg.terms {
        let (pi, pj) = if i <= j { (*i, *j) } else { (*j, *i) };
        let p = garbage_pos(pi, pj, r, kappa);
        for ll in 0..limbs {
            m.add_v(p * limbs + ll, aij.scalar_mul(base_g_pow(ll)));
        }
    }
    for i in 0..r {
        let p = h_pos(i, i, r, kappa);
        for ll in 0..limbs {
            m.add_v(p * limbs + ll, Poly::one().scalar_mul(base_g_pow(ll)));
        }
    }
    constraints.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear: m.into_linear(), b: agg.b.clone() });
    constraints
}

/// Run the no-decompose last reduction: returns the residual witness `s' =
/// [z-chunks ‖ v-chunks]` (r'=ν+µ) and its DIAGONAL constraint family.
pub fn reduce_to_child_last(
    a: &PolyMatrix,
    b_a: &PolyMatrix,
    b_b: &PolyMatrix,
    s: &[PolyVec],
    family: &[QuadConstraint],
    bits: u32,
    limbs: usize,
    nu: usize,
    mu: usize,
) -> ChildInstance {
    let r = s.len();
    let n = s[0].len();
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let mut g = vec![vec![Poly::zero(); r]; r];
    for i in 0..r {
        for j in i..r {
            let gij = dot(&s[i], &s[j]);
            g[i][j] = gij.clone();
            g[j][i] = gij;
        }
    }
    let v_a = gadget_decompose(&flatten_tg(&t, &g), bits, limbs);
    let u1_a = b_a.matvec(&v_a);
    let agg = aggregate_constraints_bound(family, &commit_bytes(&u1_a));
    let phi = dense_phi(&agg.linear, r, n);
    let mut h = vec![vec![Poly::zero(); r]; r];
    for i in 0..r {
        for j in 0..r {
            h[i][j] = dot(&phi[i], &s[j]);
        }
    }
    let v_b = gadget_decompose(&flatten_h(&h), bits, limbs);
    let u1_b = b_b.matvec(&v_b);
    let v = v_a.concat(&v_b);
    let c = fold_challenges_two(&u1_a, &u1_b, r);
    let mut z = PolyVec::zero(n);
    for i in 0..r {
        z = z.add(&s[i].mul_poly(&c[i]));
    }
    // NO decomposition: re-chunk z whole (ν) + v (µ), r'=ν+µ.
    let zchunk = n.div_ceil(nu);
    let vchunk = v.len().div_ceil(mu);
    let n_prime = zchunk.max(vchunk);
    let mut sp = Vec::with_capacity(nu + mu);
    sp.extend(chunk_padded(&z, nu, zchunk, n_prime));
    sp.extend(chunk_padded(&v, mu, vchunk, n_prime));
    let constraints = build_last_constraints(a, b_a, b_b, &agg, &u1_a, &u1_b, &c, bits, limbs, nu, mu);
    ChildInstance { constraints, ct_constraints: Vec::new(), s: sp, r_prime: nu + mu, n_prime, base_z: 1, u1_a, u1_b }
}

// ─────────────────────────────────────────────────────────────────────────
// The recursion DRIVER — run the reduction N levels, base-case the last.
//
// Per level `l` the prover sends only the outer commitment `u1_l` (κ ring
// elements); the witness/garbage/opening are folded into the next level's
// witness. At the last level it reveals the (small) witness `s_L` directly
// (§5, "no point in producing the outer commitment" at the base). The verifier
// re-derives every level's public matrices + challenges + child constraint
// family from `u1_l` and checks the final witness satisfies the final family
// and the norm bound. Proof = `[u1_0 … u1_{L-1}] ‖ s_L`.
// ─────────────────────────────────────────────────────────────────────────

/// Public per-level shape. Both prover and verifier compute the identical
/// sequence from the base `(r,n,β)` + re-chunk rule + §5.4 norm-budget gadget.
#[derive(Clone, Copy)]
pub struct LevelShape {
    pub r: usize,
    pub n: usize,
    pub beta: u64,
    pub nu: usize,
    pub mu: usize,
    pub base_z: i64,
    /// §5.4 per-level gadget: digit width ≈ the balanced base, so the committed
    /// `[t‖g‖h]` decomposition parts stay ≈ `base_z`-short (norm control).
    pub bits: u32,
    pub limbs: usize,
    /// Whether this recursion carries CONJUGATED constraints — if so, every level
    /// commits the conjugated garbage `ĝ` (appended to the `v_b` block), which
    /// grows `|v|` by `r²`. Constant across a recursion (set from whether
    /// `family0` has any `conj_terms`). `false` ⇒ byte-identical to the legacy path.
    pub has_conj: bool,
}

/// §5.4 gadget for a level: decompose so each digit is ≈ the balanced base
/// `base_z` wide (`bits = ⌊log2 base_z⌋`), with `limbs = ⌈log q / bits⌉` to cover
/// `q`. `min_bits` floors the digit width — small `bits` balances norms but
/// explodes `limbs`→`|v|`→`r'`, so a floor trades a little norm growth for a
/// much smaller multiplicity (the regime where the uniform `t` term dominates).
fn level_gadget(base_z: i64, min_bits: u32) -> (u32, usize) {
    // INTEGER ⌊log2⌋ (`ilog2`), NOT `(x as f64).log2().floor()`: `log2` is not
    // correctly-rounded across platforms, so at exact powers of two the float
    // path could yield `bits` off by one on different nodes → prover/verifier
    // build different constraint systems → consensus split. Deterministic here.
    let bal = (base_z.max(2) as u64).ilog2();
    let bits = bal.max(min_bits).clamp(1, MODULUS_Q_BITS_U32 - 1);
    let limbs = (MODULUS_Q_BITS_U32 as usize).div_ceil(bits as usize).max(1);
    (bits, limbs)
}

/// `|v| = |gadget_decompose(t‖g‖h[‖ĝ])|`. With `has_conj` the conjugated garbage
/// (`r²`) is committed too, growing `|v|` by `r²·limbs`.
fn v_len(r: usize, kappa: usize, limbs: usize, has_conj: bool) -> usize {
    let flat = if has_conj { flat_tghgh_len(r, kappa) } else { flat_tgh_len(r, kappa) };
    flat * limbs
}

/// Choose `(ν,µ)` for a level. The paper's rule (§5.4/optimization notes): the
/// recursion's job is to reduce the RANK `n`, balancing `2n ≈ m` (the `z⁰‖z¹`
/// rank ≈ the `v` rank) so the child rank is `n' = max(⌈n/ν⌉, ⌈m/µ⌉)`. Keeping
/// `ν` SMALL keeps the child multiplicity `r' = 2ν+µ` bounded (a large `ν`
/// reduces `n` faster but explodes `r`/garbage — the opposite of what we want).
/// We fix `ν = 2` (halve the rank per level) and pick the smallest `µ` that
/// balances the `v`-part width against the halved `z`-part.
fn choose_nu_mu(r: usize, n: usize, kappa: usize, limbs: usize, has_conj: bool) -> (usize, usize) {
    let m = v_len(r, kappa, limbs, has_conj);
    let nu = 2usize;
    let z_width = n.div_ceil(nu).max(1); // ⌈n/2⌉
    let mu = m.div_ceil(z_width).max(1); // smallest µ with ⌈m/µ⌉ ≤ z_width
    (nu, mu)
}

/// Compute the public level schedule with §5.4 PER-LEVEL gadget sizing (digit
/// width from each level's balanced base, floored by `min_bits`). Stops when
/// `n ≤ n_floor` or `max_levels`. `min_bits` lets us sweep the norm-balance vs
/// multiplicity tradeoff (min_bits=1 ⇒ pure §5.4 balance; larger ⇒ coarser
/// gadget, fewer limbs, smaller `t`).
pub fn level_schedule(r0: usize, n0: usize, beta0: u64, kappa: usize, min_bits: u32, n_floor: usize, max_levels: usize) -> Vec<LevelShape> {
    level_schedule_conj(r0, n0, beta0, kappa, min_bits, n_floor, max_levels, false)
}

/// Like [`level_schedule`] but with the `has_conj` flag (whether the recursion
/// carries conjugated garbage, which grows `|v|` by `r²` per level). `has_conj =
/// false` reproduces [`level_schedule`] exactly.
pub fn level_schedule_conj(
    r0: usize,
    n0: usize,
    beta0: u64,
    kappa: usize,
    min_bits: u32,
    n_floor: usize,
    max_levels: usize,
    has_conj: bool,
) -> Vec<LevelShape> {
    let mut out = Vec::new();
    let (mut r, mut n, mut beta) = (r0, n0, beta0);
    for _ in 0..max_levels {
        if n <= n_floor {
            break;
        }
        let base_z = public_base_z(beta, r, n);
        let (bits, limbs) = level_gadget(base_z, min_bits);
        let (nu, mu) = choose_nu_mu(r, n, kappa, limbs, has_conj);
        out.push(LevelShape { r, n, beta, nu, mu, base_z, bits, limbs, has_conj });
        let m = v_len(r, kappa, limbs, has_conj);
        let n_next = n.div_ceil(nu).max(m.div_ceil(mu));
        let r_next = 2 * nu + mu;
        let beta_next = child_beta(beta, r, base_z, bits);
        r = r_next;
        n = n_next;
        beta = beta_next;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// NS22 garbage reduction (paper §5.6, lines 1253-1310) — for the BASE CASE,
// where garbage is SENT (not committed). Spreading the r challenges over
// sequential rounds lets many garbage polynomials COMBINE: the linear (h) part
// drops from r² to 2r−1, the quadratic (g) part likewise. Only sound because
// hᵢⱼ in round 2i−1 depends on c₁..c_{i−1} (fixed BEFORE cᵢ), so a cheating
// prover cannot correct with later terms — the challenges distort any fix
// ([NS22, Lemma 2]). Requires sequential Fiat-Shamir (below), NOT a commitment.
// ─────────────────────────────────────────────────────────────────────────

/// Sequential Fiat-Shamir: absorb prover messages, squeeze one challenge at a
/// time, each binding everything absorbed so far.
struct Ns22Transcript {
    h: Sha256,
}

impl Ns22Transcript {
    fn new(label: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/labrador/ns22/v1");
        h.update(label);
        Ns22Transcript { h }
    }
    fn absorb_poly(&mut self, p: &Poly) {
        for &x in &p.c {
            self.h.update(x.to_le_bytes());
        }
    }
    fn absorb_vec(&mut self, v: &PolyVec) {
        for p in &v.0 {
            self.absorb_poly(p);
        }
    }
    /// Squeeze the next weight-τ challenge (binds all prior absorbs).
    fn challenge(&mut self) -> Poly {
        let sd = self.h.clone().finalize();
        // fold the squeeze back in so the next challenge differs.
        self.h.update(b"squeeze");
        self.h.update(sd);
        let mut prg = HashPrg::from_digest(&sd);
        sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)
    }
}

/// NS22-reduced LINEAR garbage. `h_odd[i] = Σ_{j<i}(⟨φ_j,s_i⟩+⟨φ_i,s_j⟩)c_j`
/// (`h_{2i-1}`), `h_even[i] = ⟨φ_i,s_i⟩` (`h_{2i}`). With the sequential
/// challenges `c`, `Σ_i c_i⟨φ_i,z⟩ = Σ_i(h_odd[i]c_i + h_even[i]c_i²)` where
/// `z = Σ c_i s_i`. `2r−1` nonzero polys (h_odd[0]=0) vs the full `r²`.
pub struct Ns22Linear {
    pub c: Vec<Poly>,
    pub h_odd: Vec<Poly>,
    pub h_even: Vec<Poly>,
}

/// Prove: derive sequential challenges + the reduced h garbage. `label` seeds
/// the transcript (bind it to `t`/statement so challenges are non-malleable).
pub fn prove_ns22_linear(phi: &[PolyVec], s: &[PolyVec], label: &[u8]) -> Ns22Linear {
    let r = s.len();
    let h_even: Vec<Poly> = (0..r).map(|i| dot(&phi[i], &s[i])).collect();
    let mut tr = Ns22Transcript::new(label);
    for he in &h_even {
        tr.absorb_poly(he); // diagonals are challenge-independent — bind up front
    }
    let mut c: Vec<Poly> = Vec::with_capacity(r);
    let mut h_odd: Vec<Poly> = Vec::with_capacity(r);
    for i in 0..r {
        // h_{2i-1} depends only on c_0..c_{i-1}.
        let mut ho = Poly::zero();
        for j in 0..i {
            let cross = dot(&phi[j], &s[i]).add(&dot(&phi[i], &s[j]));
            ho = ho.add(&cross.mul_ntt(&c[j]));
        }
        tr.absorb_poly(&ho);
        h_odd.push(ho);
        c.push(tr.challenge()); // c_i bound AFTER h_{2i-1}
    }
    Ns22Linear { c, h_odd, h_even }
}

/// Re-derive the sequential challenges from the sent garbage and check the NS22
/// linear identity against the opening `z`. Returns the re-derived `c` on success.
pub fn verify_ns22_linear(phi: &[PolyVec], z: &PolyVec, pf: &Ns22Linear, label: &[u8]) -> Option<Vec<Poly>> {
    let r = phi.len();
    if pf.h_odd.len() != r || pf.h_even.len() != r {
        return None;
    }
    let mut tr = Ns22Transcript::new(label);
    for he in &pf.h_even {
        tr.absorb_poly(he);
    }
    let mut c: Vec<Poly> = Vec::with_capacity(r);
    for i in 0..r {
        tr.absorb_poly(&pf.h_odd[i]);
        c.push(tr.challenge());
    }
    if c != pf.c {
        return None; // sent challenges must match the transcript
    }
    // Σ_i c_i⟨φ_i,z⟩  ==  Σ_i (h_odd[i]c_i + h_even[i]c_i²)
    let mut lhs = Poly::zero();
    let mut rhs = Poly::zero();
    for i in 0..r {
        lhs = lhs.add(&c[i].mul_ntt(&dot(&phi[i], z)));
        rhs = rhs.add(&pf.h_odd[i].mul_ntt(&c[i]));
        rhs = rhs.add(&pf.h_even[i].mul_ntt(&c[i].mul_ntt(&c[i])));
    }
    if lhs == rhs {
        Some(c)
    } else {
        None
    }
}

/// The NS22 base-case proof of the DIAGONAL relation `Σ aᵢᵢ⟨sᵢ,sᵢ⟩ +
/// Σ⟨φᵢ,sᵢ⟩ = b`, `A·sᵢ=tᵢ`, `‖s‖ ≤ β` — proven by revealing `t`, the amortized
/// opening `z`, and NS22-reduced garbage (`O(r)`) instead of the full witness.
#[derive(Clone)]
pub struct BaseNs22Proof {
    pub t: Vec<PolyVec>, // inner commitments (r·κ)
    pub z: PolyVec,      // amortized opening (n)
    pub g_odd: Vec<Poly>,
    pub g_even: Vec<Poly>, // gᵢᵢ = ⟨sᵢ,sᵢ⟩
    pub h_odd: Vec<Poly>,
    pub h_even: Vec<Poly>, // hᵢᵢ = ⟨φᵢ,sᵢ⟩
    pub c: Vec<Poly>,
}

impl BaseNs22Proof {
    pub fn size_polys(&self) -> usize {
        self.t.iter().map(|v| v.len()).sum::<usize>()
            + self.z.len()
            + self.g_odd.len()
            + self.g_even.len()
            + self.h_odd.len()
            + self.h_even.len()
    }

    /// Compact size in BYTES (paper §5.7): `t` is uniform → `log q`/coeff; the
    /// opening `z` and garbage are SHORT → `⌈log2(2·‖·‖+1)⌉`/coeff. (Provable
    /// width uses the public norm BOUND; here we use the actual max as the
    /// entropy proxy — the bound is marginally larger.)
    pub fn compact_bytes(&self) -> usize {
        let t_polys: Vec<Poly> = self.t.iter().flat_map(|v| v.0.iter().cloned()).collect();
        group_bytes(&t_polys, MODULUS_Q_BITS_U32) // uniform
            + group_bytes(&self.z.0, short_bits(centered_max(&self.z.0)))
            + group_bytes(&self.g_odd, short_bits(centered_max(&self.g_odd)))
            + group_bytes(&self.g_even, short_bits(centered_max(&self.g_even)))
            + group_bytes(&self.h_odd, short_bits(centered_max(&self.h_odd)))
            + group_bytes(&self.h_even, short_bits(centered_max(&self.h_even)))
    }
}

const MODULUS_Q_BITS_U32: u32 = crate::params::MODULUS_Q_BITS;

/// Bytes to pack `polys` at `bits` bits/coeff.
fn group_bytes(polys: &[Poly], bits: u32) -> usize {
    (polys.len() * RING_DEGREE_D * bits as usize).div_ceil(8)
}

/// Max centered (`|·|`) coefficient over a set of polys — the entropy proxy.
fn centered_max(polys: &[Poly]) -> u64 {
    polys.iter().map(|p| p.inf_norm()).max().unwrap_or(0)
}

/// Bits to signed-pack values in `[-m, m]`: `⌈log2(2m+1)⌉` (≥ 1).
fn short_bits(m: u64) -> u32 {
    if m == 0 {
        1
    } else {
        (64 - (2 * m).leading_zeros()).max(1)
    }
}

/// Absorb the base-case STATEMENT (`φ`, diagonal coeffs, target `b`) into the
/// NS22 transcript so the sequential challenges are bound to it (domain
/// separation / non-malleability — Finding 10). Prover and verifier call it
/// identically before absorbing any garbage.
fn ns22_absorb_statement(tr: &mut Ns22Transcript, phi: &[PolyVec], a_diag: &[Poly], b: &Poly) {
    for p in phi {
        tr.absorb_vec(p);
    }
    for ad in a_diag {
        tr.absorb_poly(ad);
    }
    tr.absorb_poly(b);
}

/// Prove the diagonal relation with NS22-reduced garbage (shared sequential
/// challenges bind BOTH the quadratic `⟨z,z⟩` and the linear `Σcᵢ⟨φᵢ,z⟩`).
/// The transcript is bound to the statement (`φ`, `a_diag`, `b`).
pub fn prove_base_ns22(a: &PolyMatrix, s: &[PolyVec], phi: &[PolyVec], a_diag: &[Poly], b: &Poly, label: &[u8]) -> BaseNs22Proof {
    let r = s.len();
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let g_even: Vec<Poly> = (0..r).map(|i| dot(&s[i], &s[i])).collect();
    let h_even: Vec<Poly> = (0..r).map(|i| dot(&phi[i], &s[i])).collect();
    let mut tr = Ns22Transcript::new(label);
    ns22_absorb_statement(&mut tr, phi, a_diag, b);
    for ti in &t {
        tr.absorb_vec(ti);
    }
    for (ge, he) in g_even.iter().zip(&h_even) {
        tr.absorb_poly(ge);
        tr.absorb_poly(he);
    }
    let (mut c, mut g_odd, mut h_odd) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..r {
        let mut go = Poly::zero();
        let mut ho = Poly::zero();
        for j in 0..i {
            // g cross = ⟨sᵢ,sⱼ⟩+⟨sⱼ,sᵢ⟩ = 2⟨sᵢ,sⱼ⟩;  h cross = ⟨φⱼ,sᵢ⟩+⟨φᵢ,sⱼ⟩.
            let gc = dot(&s[i], &s[j]).add(&dot(&s[j], &s[i]));
            let hc = dot(&phi[j], &s[i]).add(&dot(&phi[i], &s[j]));
            go = go.add(&gc.mul_ntt(&c[j]));
            ho = ho.add(&hc.mul_ntt(&c[j]));
        }
        tr.absorb_poly(&go);
        tr.absorb_poly(&ho);
        g_odd.push(go);
        h_odd.push(ho);
        c.push(tr.challenge());
    }
    let mut z = PolyVec::zero(s[0].len());
    for i in 0..r {
        z = z.add(&s[i].mul_poly(&c[i]));
    }
    BaseNs22Proof { t, z, g_odd, g_even, h_odd, h_even, c }
}

/// Verify the NS22 base case against public `A`, `φ`, diagonal coeffs `a_diag`,
/// target `b`, norm bound `β`.
pub fn verify_base_ns22(
    a: &PolyMatrix,
    phi: &[PolyVec],
    a_diag: &[Poly],
    b: &Poly,
    beta: u64,
    pf: &BaseNs22Proof,
    label: &[u8],
) -> bool {
    let r = pf.t.len();
    if pf.g_odd.len() != r || pf.g_even.len() != r || pf.h_odd.len() != r || pf.h_even.len() != r || pf.c.len() != r || a_diag.len() != r || phi.len() != r {
        return false;
    }
    // Dimension guards on attacker-supplied vectors BEFORE any matvec/index
    // (a malformed proof must reject, never panic).
    if pf.z.len() != a.cols || pf.t.iter().any(|ti| ti.len() != a.rows) || phi.iter().any(|p| p.len() != a.cols) {
        return false;
    }
    // Re-derive the sequential challenges (transcript bound to the statement).
    let mut tr = Ns22Transcript::new(label);
    ns22_absorb_statement(&mut tr, phi, a_diag, b);
    for ti in &pf.t {
        tr.absorb_vec(ti);
    }
    for (ge, he) in pf.g_even.iter().zip(&pf.h_even) {
        tr.absorb_poly(ge);
        tr.absorb_poly(he);
    }
    let mut c = Vec::new();
    for i in 0..r {
        tr.absorb_poly(&pf.g_odd[i]);
        tr.absorb_poly(&pf.h_odd[i]);
        c.push(tr.challenge());
    }
    if c != pf.c {
        return false;
    }
    // (i) A·z = Σ cᵢ tᵢ.
    let az = a.matvec(&pf.z);
    let mut fold_t = PolyVec::zero(a.rows);
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if az != fold_t {
        return false;
    }
    // (ii) ⟨z,z⟩ = Σ (g_odd[i]cᵢ + g_even[i]cᵢ²)   — binds g_even = ⟨sᵢ,sᵢ⟩.
    let zz = dot(&pf.z, &pf.z);
    let mut grhs = Poly::zero();
    for i in 0..r {
        grhs = grhs.add(&pf.g_odd[i].mul_ntt(&c[i]));
        grhs = grhs.add(&pf.g_even[i].mul_ntt(&c[i].mul_ntt(&c[i])));
    }
    if zz != grhs {
        return false;
    }
    // (iii) Σ cᵢ⟨φᵢ,z⟩ = Σ (h_odd[i]cᵢ + h_even[i]cᵢ²) — binds h_even = ⟨φᵢ,sᵢ⟩.
    let mut hlhs = Poly::zero();
    let mut hrhs = Poly::zero();
    for i in 0..r {
        hlhs = hlhs.add(&c[i].mul_ntt(&dot(&phi[i], &pf.z)));
        hrhs = hrhs.add(&pf.h_odd[i].mul_ntt(&c[i]));
        hrhs = hrhs.add(&pf.h_even[i].mul_ntt(&c[i].mul_ntt(&c[i])));
    }
    if hlhs != hrhs {
        return false;
    }
    // (iv) the statement: Σ aᵢᵢ·g_even[i] + Σ h_even[i] = b.
    let mut stmt = Poly::zero();
    for i in 0..r {
        stmt = stmt.add(&a_diag[i].mul_ntt(&pf.g_even[i]));
        stmt = stmt.add(&pf.h_even[i]);
    }
    if &stmt != b {
        return false;
    }
    // (v) shortness of the opening: inf-norm ≤ β AND ℓ₂ < q (the M-SIS-binding-
    // relevant quantity — inf-norm alone loses a √dim factor). NOTE: this bounds
    // the OPENING z', not the residual witness s_L; enforcing s_L's ℓ₂ needs the
    // JL projection (still OPEN for this path — see the _full NOT-SOUND warning).
    if pf.z.inf_norm() > beta {
        return false;
    }
    let z_l2_sq = witness_l2_sq(std::slice::from_ref(&pf.z));
    z_l2_sq < (Poly::Q as u128).saturating_mul(Poly::Q as u128)
}

/// The recursive proof: the two outer commitments per reduced level + base witness.
#[derive(Clone)]
pub struct RecursiveProof {
    pub u1s: Vec<(PolyVec, PolyVec)>, // (u1_a, u1_b) per level
    pub final_s: Vec<PolyVec>,
}

/// The recursion with a perfect-ZK base: outer commitments per level + a
/// [`MaskedBaseOpening`] in place of the revealed `final_s`. See
/// [`prove_labrador_recursive_zk`].
pub struct RecursiveZkProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: MaskedBaseOpening,
}

/// The FULL money-path-shaped recursion-ZK: carries BOTH families (whole-ring +
/// ct) and opens both at the base against the SAME witness commitment `base.u`
/// (the whole-ring family via [`MaskedBaseOpening`], the residual linear ct-family
/// via [`CtBaseOpening`]). See [`prove_labrador_recursive_ct_zk`].
pub struct RecursiveCtZkProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: MaskedBaseOpening,
    pub ct_base: CtBaseOpening,
}

/// Ring elements a commitment serializes to (`t1‖t2`).
fn commit_polys(c: &RingCommitment) -> usize {
    c.t1.len() + c.t2.len()
}

impl MaskedBaseOpening {
    /// Upper-bound serialized size (bytes) at the full `log q`/coeff wire. The
    /// masked responses are ≤ `MASK` (≈26 bits), so a compact wire is smaller.
    pub fn size_bytes(&self) -> usize {
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let mut polys = commit_polys(&self.u);
        for sh in &self.shots {
            polys += commit_polys(&sh.c_y)
                + commit_polys(&sh.c_t0)
                + commit_polys(&sh.c_t1)
                + commit_polys(&sh.c_c0)
                + commit_polys(&sh.c_c1)
                + commit_polys(&sh.c_d1);
            polys += sh.z.len() + sh.r_z.len() + sh.z_gp.len() + sh.z_gc.len();
        }
        polys * per
    }
}

impl CtBaseOpening {
    pub fn size_bytes(&self) -> usize {
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        (commit_polys(&self.c_y) + commit_polys(&self.c_t) + self.z.len() + self.r_z.len() + self.r_t.len()) * per
    }
}

impl RecursiveCtZkProof {
    /// Upper-bound serialized size (bytes): outer commitments + both base openings.
    pub fn size_bytes(&self) -> usize {
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let u1 = self.u1s.iter().map(|(a, b)| a.len() + b.len()).sum::<usize>();
        u1 * per + self.base.size_bytes() + self.ct_base.size_bytes()
    }
}

impl RecursiveProof {
    fn u1_polys(&self) -> Vec<Poly> {
        self.u1s.iter().flat_map(|(a, b)| a.0.iter().chain(b.0.iter()).cloned()).collect()
    }
    /// Serialized size in bytes at the compact `MODULUS_Q_BITS`/coeff wire.
    pub fn size_bytes(&self) -> usize {
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let u = self.u1_polys().len();
        let s = self.final_s.iter().map(|v| v.len()).sum::<usize>();
        (u + s) * per
    }

    /// Compact size (bytes): `u1` uniform (`log q`); the base witness `final_s`
    /// is SHORT (its parts are z⁰,z¹ ≈ base_z and v ≈ 2^bits) — entropy-coded
    /// PER VECTOR at `⌈log2(2‖·‖+1)⌉`. No commitment `t` at all: the verifier
    /// evaluates the constraints on the sent witness directly.
    pub fn compact_bytes(&self) -> usize {
        let mut total = group_bytes(&self.u1_polys(), MODULUS_Q_BITS_U32);
        for v in &self.final_s {
            total += group_bytes(&v.0, short_bits(centered_max(&v.0)));
        }
        total
    }
}

/// Per-level public matrices: inner `A` (κ×n), and the TWO outer commitment
/// matrices `B_a` (over the `t‖g` digits) and `B_b` (over the `h` digits).
fn level_matrices(shape: &LevelShape, kappa: usize, seed: u64, level: usize) -> (PolyMatrix, PolyMatrix, PolyMatrix) {
    let a = PolyMatrix::from_seed(kappa, shape.n, seed ^ (0x1000 + level as u64));
    let va = flat_tg_len(shape.r, kappa) * shape.limbs;
    // v_b = decompose([h(‖ĝ)]): h is r², plus ĝ (r²) when the recursion carries
    // conjugated garbage.
    // v_b = decompose([h(‖ĝ‖ĥ)]): h is r², plus ĝ and ĥ (r² each) when has_conj.
    let vb_elems = if shape.has_conj { 3 * shape.r * shape.r } else { shape.r * shape.r };
    let vb = vb_elems * shape.limbs;
    let b_a = PolyMatrix::from_seed(kappa, va, seed ^ (0x2000 + level as u64));
    let b_b = PolyMatrix::from_seed(kappa, vb, seed ^ (0x3000 + level as u64));
    (a, b_a, b_b)
}

/// Prove the whole recursion. `family0` is the base constraint set; `s0` its
/// witness; `beta0` the base norm bound. Deterministic public matrices from `seed`.
pub fn prove_labrador_recursive(
    family0: &[QuadConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
) -> RecursiveProof {
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let _ = beta0;
    let mut u1s = Vec::new();
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        // reduce_to_child aggregates INTERNALLY, binding ψ to u1_a (the fix).
        let child = reduce_to_child_conj(&a, &b_a, &b_b, &s, &family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        s = child.s;
    }
    RecursiveProof { u1s, final_s: s }
}

/// Prove the recursion carrying a SECOND (constant-term) family. Each level
/// lowers the ct-family onto that level's conjugated garbage (quadratic→ĝ,
/// linear→ĥ diagonal) and folds it forward, so a packed binary/range ct proof
/// shrinks with the recursion instead of being pinned to the send-witness base.
/// Verify with [`verify_labrador_recursive_ct`] (same `schedule`/`seed`).
#[allow(clippy::too_many_arguments)]
pub fn prove_labrador_recursive_ct(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
) -> RecursiveProof {
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let _ = beta0;
    let mut u1s = Vec::new();
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let child = reduce_to_child_conj_ct(
            &a, &b_a, &b_b, &s, &family, &ct_family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj,
        );
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        ct_family = child.ct_constraints;
        s = child.s;
    }
    RecursiveProof { u1s, final_s: s }
}

/// Verify the whole recursion: re-derive each level's family from the sent
/// `u1_l`, then check the base witness satisfies the final family and norm bound.
pub fn verify_labrador_recursive(
    family0: &[QuadConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &RecursiveProof,
) -> bool {
    if pf.u1s.len() != schedule.len() {
        return false;
    }
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let _ = beta0;
    let mut final_beta = schedule.first().map(|s| s.beta).unwrap_or(beta0);
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        // Re-derive ψ BOUND to u1_a (matches the prover's ordering fix), then c.
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
        final_beta = child_beta(shape.beta, shape.r, shape.base_z, shape.bits);
    }
    // Dimension guard: every constraint index must be in range and the witness
    // vectors uniform-rank (a malformed `final_s` must reject, never panic).
    let max_idx = family
        .iter()
        .flat_map(|c| c.terms.iter().flat_map(|(i, j, _)| [*i, *j]).chain(c.linear.iter().map(|(i, _)| *i)))
        .max()
        .unwrap_or(0);
    if pf.final_s.is_empty() || max_idx >= pf.final_s.len() {
        return false;
    }
    let rank = pf.final_s[0].len();
    if pf.final_s.iter().any(|v| v.len() != rank) {
        return false;
    }
    // Base case: the revealed witness must satisfy the final family AND be short.
    for con in &family {
        if eval_constraint_on_witness(con, &pf.final_s) != con.b {
            return false;
        }
    }
    // Norm enforcement (Finding 3, send-witness path): the witness is sent, so we
    // check its ACTUAL ℓ₂ norm directly (the M-SIS-binding-relevant quantity),
    // not just inf-norm. The honest witness has ‖·‖∞ ≤ final_beta over dim
    // r_L·n_L·d, so ‖·‖₂ ≤ final_beta·√dim; and for the commitment matrices to
    // stay M-SIS binding the ℓ₂ opening must be < q (else q-multiples enter).
    let l2_sq = witness_l2_sq(&pf.final_s);
    let dim = pf.final_s.iter().map(|v| v.len()).sum::<usize>() * RING_DEGREE_D;
    let l2_bound = (final_beta as u128) * (dim as f64).sqrt().ceil() as u128;
    if l2_sq > l2_bound.saturating_mul(l2_bound) {
        return false; // witness ℓ₂ exceeds the honest bound
    }
    if l2_sq >= (Poly::Q as u128).saturating_mul(Poly::Q as u128) {
        return false; // ℓ₂ ≥ q: outside the M-SIS binding regime
    }
    true
}

/// Verify a recursion that carries a SECOND (constant-term) constraint family.
///
/// When `ct_family0` is empty this is exactly [`verify_labrador_recursive`].
/// Otherwise the ct-constraints are enforced at the SEND-WITNESS base only: the
/// schedule MUST be empty (so no decompose level folds the coefficient inner
/// products, which the ring-challenge fold does not preserve — see
/// [`CtConstraint`]). The base then checks, on the revealed witness: every
/// whole-ring constraint (`= b`), every ct-constraint (`⟪·⟫ = target`), and the
/// SAME ℓ₂ bound as the full path. That norm bound is what makes a packed binary
/// constraint sound: with `‖s‖ ≤ β₀√dim`, `Σbₖ(bₖ−1) ≤ 2·ℓ2 ≤ 2·β₀²·dim ≪ q`,
/// so an aggregate `≡ 0 (mod q)` forces every integer term to 0 ⇒ every `bₖ∈{0,1}`.
pub fn verify_labrador_recursive_ct(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &RecursiveProof,
) -> bool {
    if ct_family0.is_empty() {
        return verify_labrador_recursive(family0, beta0, kappa, schedule, seed, pf);
    }
    if pf.u1s.len() != schedule.len() {
        return false;
    }
    // Fold BOTH families through the schedule, rebuilding each child from u1_l
    // (mirrors the prover's reduce_to_child_conj_ct): the whole-ring family gains
    // the ĝ + ĥ bindings, the ct-family lowers onto ĝ (quadratic) / ĥ diagonal
    // (linear). ct-constraints now survive the fold via the conjugated garbage.
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let mut final_beta = schedule.first().map(|s| s.beta).unwrap_or(beta0);
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let ct_agg = if ct_family.is_empty() {
            None
        } else {
            Some(aggregate_ct_constraints(&ct_family, &commit_bytes(u1_a)))
        };
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj_ct(
            &a, &b_a, &b_b, &agg, ct_agg.as_ref(), u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj,
        );
        ct_family = match &ct_agg {
            None => Vec::new(),
            Some(ac) => build_child_ct_family(&a, &b_a, &b_b, std::slice::from_ref(ac), shape.r, shape.bits, shape.limbs, shape.nu, shape.mu),
        };
        final_beta = child_beta(shape.beta, shape.r, shape.base_z, shape.bits);
    }
    // Dimension guard over BOTH (folded) families: every referenced index in
    // range, and the witness uniform-rank (a malformed `final_s` rejects).
    let full_idx = family
        .iter()
        .flat_map(|c| c.terms.iter().flat_map(|(i, j, _)| [*i, *j]).chain(c.linear.iter().map(|(i, _)| *i)));
    let ct_idx = ct_family
        .iter()
        .flat_map(|c| c.terms.iter().flat_map(|(i, j, _)| [*i, *j]).chain(c.linear.iter().map(|(i, _)| *i)));
    let max_idx = full_idx.chain(ct_idx).max().unwrap_or(0);
    if pf.final_s.is_empty() || max_idx >= pf.final_s.len() {
        return false;
    }
    let rank = pf.final_s[0].len();
    if pf.final_s.iter().any(|v| v.len() != rank) {
        return false;
    }
    // Whole-ring family: exact ring equality.
    for con in &family {
        if eval_constraint_on_witness(con, &pf.final_s) != con.b {
            return false;
        }
    }
    // Constant-term family: coefficient-inner-product target (mod q).
    for con in &ct_family {
        if eval_ct_on_witness(con, &pf.final_s) != con.target % Poly::Q {
            return false;
        }
    }
    // Norm bound (identical to the full send-witness path): ℓ₂ within the honest
    // bound AND < q. The first clause is what the binary-soundness argument uses.
    let l2_sq = witness_l2_sq(&pf.final_s);
    let dim = pf.final_s.iter().map(|v| v.len()).sum::<usize>() * RING_DEGREE_D;
    let l2_bound = (final_beta as u128) * (dim as f64).sqrt().ceil() as u128;
    if l2_sq > l2_bound.saturating_mul(l2_bound) {
        return false;
    }
    if l2_sq >= (Poly::Q as u128).saturating_mul(Poly::Q as u128) {
        return false;
    }
    true
}

/// The child witness shape `(r', n')` a level reduces to — matches the schedule
/// recurrence and the prover's rechunk, so the verifier can size the base
/// commitment key for [`verify_labrador_recursive_zk`] without seeing the witness.
pub fn child_dims(shape: &LevelShape, kappa: usize) -> (usize, usize) {
    let m = v_len(shape.r, kappa, shape.limbs, shape.has_conj);
    let n_next = shape.n.div_ceil(shape.nu).max(m.div_ceil(shape.mu));
    let r_next = 2 * shape.nu + shape.mu;
    (r_next, n_next)
}

/// The witness dims `(r0, n0)` a constraint family is stated over: `n0` = the common
/// witness-vector length (max linear-term `PolyVec` length), `r0` = the rank (highest
/// witness index referenced + 1). Used by the direct-base (empty-schedule) verify to
/// pin the base dims to the STATEMENT rather than the (attacker-supplied) proof, so the
/// JL norm bound can't be loosened by inflating the declared dims.
fn statement_dims(family: &[QuadConstraint], ct_family: &[CtConstraint]) -> (usize, usize) {
    let mut n0 = 0usize;
    let mut max_idx = 0usize;
    for con in family {
        for (i, pv) in &con.linear {
            n0 = n0.max(pv.len());
            max_idx = max_idx.max(*i);
        }
        for (i, j, _) in con.terms.iter().chain(&con.conj_terms) {
            max_idx = max_idx.max((*i).max(*j));
        }
    }
    for con in ct_family {
        for (i, pv) in &con.linear {
            n0 = n0.max(pv.len());
            max_idx = max_idx.max(*i);
        }
        for (i, j, _) in &con.terms {
            max_idx = max_idx.max((*i).max(*j));
        }
    }
    (max_idx + 1, n0)
}

// Base-opening key derivation shared by prover + verifier (deterministic in seed).
fn base_opening_keys(seed: u64, r: usize, n: usize) -> (RingCommitKey, RingCommitKey) {
    (
        RingCommitKey::production(r * n, seed ^ 0xBA5E_0BED),
        RingCommitKey::production(1, seed ^ 0x6A46_0001),
    )
}

/// The recursion with a PERFECT-ZK base: fold the whole-ring family through the
/// schedule (as [`prove_labrador_recursive`]) but replace the send-witness reveal
/// with a [`MaskedBaseOpening`] on the folded final family. The final-family
/// constraints reference the `u1_l` as their targets, so proving knowledge of a
/// short witness satisfying them binds the whole chain — nothing about the
/// witness is revealed. Whole-ring family only (no ct-family).
pub fn prove_labrador_recursive_zk(
    family0: &[QuadConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
) -> Option<RecursiveZkProof> {
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    let mut final_beta = schedule.first().map(|sh| sh.beta).unwrap_or(beta0);
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let child = reduce_to_child_conj(&a, &b_a, &b_b, &s, &family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        s = child.s;
        final_beta = child_beta(shape.beta, shape.r, shape.base_z, shape.bits);
    }
    let (r, n) = (s.len(), s[0].len());
    let (ck_s, ck1) = base_opening_keys(seed, r, n);
    let mut prg = SplitMix64::new(seed ^ 0x2ED_0BE7);
    let r_s = PolyVec::sample_short(ck_s.a1.cols, SECRET_NORM_ETA, &mut prg);
    let base = prove_masked_base_opening(&ck_s, &ck1, &family, &s, &r_s, final_beta, seed ^ 0x0BE)?;
    Some(RecursiveZkProof { u1s, base })
}

/// Verify [`prove_labrador_recursive_zk`]: re-fold the family from the sent
/// `u1_l`, then check the ZK base opening against the folded final family.
pub fn verify_labrador_recursive_zk(
    family0: &[QuadConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &RecursiveZkProof,
) -> bool {
    if pf.u1s.len() != schedule.len() || schedule.is_empty() {
        return false;
    }
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let _ = beta0;
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
    }
    let last = schedule.last().unwrap();
    let (r, n) = child_dims(last, kappa);
    let (ck_s, ck1) = base_opening_keys(seed, r, n);
    verify_masked_base_opening(&ck_s, &ck1, &family, r, n, &pf.base)
}

/// The FULL money-path recursion-ZK prover: fold BOTH families (whole-ring + ct)
/// through the schedule (as [`prove_labrador_recursive_ct`]) and open both at the
/// base — the whole-ring final family via [`prove_masked_base_opening`], the
/// residual LINEAR ct-family via [`prove_ct_base_opening`] — against the SAME
/// witness commitment. Nothing about the witness is revealed. Uses SMALL-`bits`
/// schedules so the base β stays small.
pub fn prove_labrador_recursive_ct_zk(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    crs_seed: u64,
    rand_seed: u64,
) -> Option<RecursiveCtZkProof> {
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    let mut final_beta = schedule.first().map(|sh| sh.beta).unwrap_or(beta0);
    for (level, shape) in schedule.iter().enumerate() {
        // CRS (matrices) from the PUBLIC crs_seed — the verifier must reproduce it.
        let (a, b_a, b_b) = level_matrices(shape, kappa, crs_seed, level);
        let child = reduce_to_child_conj_ct(&a, &b_a, &b_b, &s, &family, &ct_family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        ct_family = child.ct_constraints;
        s = child.s;
        final_beta = child_beta(shape.beta, shape.r, shape.base_z, shape.bits);
    }
    let (r, n) = (s.len(), s[0].len());
    // Commitment keys from the PUBLIC crs_seed; the masks/randomness from the
    // FRESH rand_seed (so re-proving does not reuse a mask ⇒ ZK across proofs).
    let (ck_s, ck1) = base_opening_keys(crs_seed, r, n);
    let mut prg = SplitMix64::new(rand_seed ^ 0x2ED_0BE7);
    let r_s = PolyVec::sample_short(ck_s.a1.cols, SECRET_NORM_ETA, &mut prg);
    let base = prove_masked_base_opening(&ck_s, &ck1, &family, &s, &r_s, final_beta, rand_seed ^ 0x0BE)?;
    let ct_base = prove_ct_base_opening(&ck_s, &ck1, &ct_family, &s, &r_s, &base.u, final_beta, rand_seed ^ 0xC7)?;
    Some(RecursiveCtZkProof { u1s, base, ct_base })
}

/// Verify [`prove_labrador_recursive_ct_zk`]: re-fold both families from the sent
/// `u1_l`, then check the whole-ring base opening AND the ct base opening (both
/// bound to `base.u`).
pub fn verify_labrador_recursive_ct_zk(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &RecursiveCtZkProof,
) -> bool {
    if pf.u1s.len() != schedule.len() || schedule.is_empty() {
        return false;
    }
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let _ = beta0;
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let ct_agg = if ct_family.is_empty() {
            None
        } else {
            Some(aggregate_ct_constraints(&ct_family, &commit_bytes(u1_a)))
        };
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj_ct(&a, &b_a, &b_b, &agg, ct_agg.as_ref(), u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
        ct_family = match &ct_agg {
            None => Vec::new(),
            Some(ac) => build_child_ct_family(&a, &b_a, &b_b, std::slice::from_ref(ac), shape.r, shape.bits, shape.limbs, shape.nu, shape.mu),
        };
    }
    let last = schedule.last().unwrap();
    let (r, n) = child_dims(last, kappa);
    let (ck_s, ck1) = base_opening_keys(seed, r, n);
    verify_masked_base_opening(&ck_s, &ck1, &family, r, n, &pf.base)
        && verify_ct_base_opening(&ck_s, &ck1, &ct_family, r, n, &pf.base.u, &pf.ct_base)
}

// ─────────────────────────────────────────────────────────────────────────
// Step 4 (recursion-ZK) — the base-opening masked-quadratic KERNEL.
//
// The recursion above still REVEALS `final_s` at the base (a proof of knowledge,
// not zero-knowledge). ZK replaces the reveal with a masked opening: commit
// `s` (Ajtai) + a short mask `y`, get a RING challenge `x`, reveal only the
// rejection-sampled `z = y + x·s`, and check every folded-family constraint on
// the public `z` via the identity below. Because the whole-ring family is
// RING-BILINEAR, a ring challenge works (unlike the ct/scalar case) — this is
// exactly why the recursion carries constraints as whole-ring after §2.3.
//
// This section ships + validates the SOUNDNESS KERNEL. The full wrapper (commit
// t0/t1 and the mask, reveal only masked z, rejection-tune for perfect ZK, bind
// z to the Ajtai commitment via sigma_rq) mirrors `binary_zk`/`sigma_rq` and is
// the next sub-step — staged the same way `binary_zk` staged its kernel.
// ─────────────────────────────────────────────────────────────────────────

/// A constraint's QUADRATIC part only (`terms` + `conj_terms`) — the piece that
/// contributes an `x²` under `z = y + x·s`.
fn eval_quad_part(con: &QuadConstraint, s: &[PolyVec]) -> Poly {
    let mut lhs = Poly::zero();
    for (i, j, a) in &con.terms {
        lhs = lhs.add(&a.mul_ntt(&dot(&s[*i], &s[*j])));
    }
    for (i, j, a) in &con.conj_terms {
        lhs = lhs.add(&a.mul_ntt(&conj_dot(&s[*i], &s[*j])));
    }
    lhs
}

/// A constraint's LINEAR part only (`linear`).
fn eval_lin_part(con: &QuadConstraint, s: &[PolyVec]) -> Poly {
    let mut lhs = Poly::zero();
    for (i, phi) in &con.linear {
        lhs = lhs.add(&dot(phi, &s[*i]));
    }
    lhs
}

/// Masked response `z = y + x·s` per witness vector (ring challenge `x`).
pub fn mask_response(s: &[PolyVec], y: &[PolyVec], x: &Poly) -> Vec<PolyVec> {
    s.iter().zip(y).map(|(si, yi)| yi.add(&si.mul_poly(x))).collect()
}

/// Step 4a KERNEL — the masked-quadratic identity for ONE whole-ring constraint
/// under a RING challenge `x`. With `z = y + x·s`, the verifier's public
/// recomputation
///
/// ```text
///   eval_quad(z) + x·eval_lin(z)  ==  t0 + x·t1 + x²·b
/// ```
///
/// (an extra `x` multiplies the linear part, the generalization of `binary_zk`'s
/// `⟪z, z − xJ⟫` trick) holds for EVERY `x` iff `eval_quad(s) + eval_lin(s) = b`,
/// i.e. the constraint is satisfied. Here `t0 = eval_quad(y)` and
/// `t1 = B(y,s) + eval_lin(y)` with `B(y,s) = eval_quad(y+s) − eval_quad(y) −
/// eval_quad(s)` the symmetric bilinear cross — both FIXED before `x` (committed
/// in the full wrapper). A cheating witness (constraint value `v ≠ b`) shifts the
/// `x²` coefficient to `v`, so the identity fails unless `x²·(v−b) = 0`; over the
/// partially-split ring a random `x` avoids that whp (root bound, amplified by
/// repetition in the wrapper). Returns whether the identity holds for this `x`.
///
/// SCOPE: `con.conj_terms` MUST be empty. A conjugated term `â·conj_dot(s_i,s_j)`
/// picks up `σ(x)·x` (not `x²`) under `z = y + x·s` because σ is a ring
/// automorphism, so it does NOT fold with a plain ring challenge — the binding
/// constraints that carry `conj_terms` need the conjugated-challenge opening (a
/// `σ(x)`-paired variant), the next sub-step. In the folded family every
/// constraint is EITHER plain-quadratic+linear (this kernel) OR
/// conjugated+linear, never both, so the two openings partition it cleanly.
pub fn masked_quad_identity_holds(con: &QuadConstraint, s: &[PolyVec], y: &[PolyVec], x: &Poly) -> bool {
    debug_assert!(con.conj_terms.is_empty(), "plain-x kernel: conj_terms need the conjugated-challenge opening");
    let z = mask_response(s, y, x);
    let lhs = eval_quad_part(con, &z).add(&x.mul_ntt(&eval_lin_part(con, &z)));
    let t0 = eval_quad_part(con, y);
    let ys: Vec<PolyVec> = s.iter().zip(y).map(|(si, yi)| yi.add(si)).collect();
    let cross = eval_quad_part(con, &ys).sub(&eval_quad_part(con, y)).sub(&eval_quad_part(con, s));
    let t1 = cross.add(&eval_lin_part(con, y));
    let x2 = x.mul_ntt(x);
    let rhs = t0.add(&x.mul_ntt(&t1)).add(&x2.mul_ntt(&con.b));
    lhs == rhs
}

/// `Σ â·conj_dot(a_i, b_j)` over a constraint's `conj_terms` (the ASYMMETRIC
/// cross — conj_dot is not symmetric, so argument order matters).
fn eval_conj_cross(con: &QuadConstraint, a: &[PolyVec], b: &[PolyVec]) -> Poly {
    let mut acc = Poly::zero();
    for (i, j, aij) in &con.conj_terms {
        acc = acc.add(&aij.mul_ntt(&conj_dot(&a[*i], &b[*j])));
    }
    acc
}

/// Conjugated-challenge companion to [`masked_quad_identity_holds`], for a
/// CONJUGATED+linear constraint (`â·conj_dot(s_i,s_j) + ⟨φ,s⟩ = b`, `terms`
/// empty). Since `conj_dot(x·s_i, x·s_j) = σ(x)·x·conj_dot(s_i,s_j)` the top
/// coefficient is `σ(x)·x` (not `x²`); pairing the linear part with `σ(x)` too,
/// the check
///
/// ```text
///   eval_conj(z) + σ(x)·eval_lin(z)  ==  C0 + x·C1 + σ(x)·D1 + σ(x)·x·b
/// ```
///
/// holds for EVERY `x` iff `eval_conj(s) + eval_lin(s) = b`. Here `C0 =
/// eval_conj(y)`, `C1 = Σâ·conj_dot(y_i,s_j)`, `D1 = Σâ·conj_dot(s_i,y_j) +
/// eval_lin(y)`, all FIXED before `x`. Cheating shifts the `σ(x)·x` coefficient,
/// caught whp (`σ(x)·x` — the norm of `x` — is nonzero for random `x`). Together
/// with the plain kernel this covers the WHOLE folded family (plain-quad+linear /
/// conjugated+linear are its only two constraint shapes).
pub fn masked_conj_identity_holds(con: &QuadConstraint, s: &[PolyVec], y: &[PolyVec], x: &Poly) -> bool {
    debug_assert!(con.terms.is_empty(), "conjugated kernel: plain quadratic terms use the x² kernel");
    let z = mask_response(s, y, x);
    let sx = x.conjugate();
    // eval_quad_part is (terms + conj); with terms empty it is exactly eval_conj.
    let lhs = eval_quad_part(con, &z).add(&sx.mul_ntt(&eval_lin_part(con, &z)));
    let c0 = eval_quad_part(con, y);
    let c1 = eval_conj_cross(con, y, s);
    let d1 = eval_conj_cross(con, s, y).add(&eval_lin_part(con, y));
    let rhs = c0
        .add(&x.mul_ntt(&c1))
        .add(&sx.mul_ntt(&d1))
        .add(&sx.mul_ntt(x).mul_ntt(&con.b));
    lhs == rhs
}

// ─────────────────────────────────────────────────────────────────────────
// Step 4b — the perfect-ZK WRAPPER around the two kernels.
//
// A base opening proving knowledge of a SHORT witness `s` (Ajtai-committed as
// `u`) satisfying a whole-ring constraint family, revealing ONLY a rejection-
// sampled masked `z = y + x·s` — the send-witness reveal, made zero-knowledge.
//
// Structure mirrors `binary_zk` (validated in-tree) generalized to the whole
// family: per shot commit a fresh wide mask `y` + the challenge-independent
// garbage (`t0/t1` for the plain aggregate, `C0/C1/D1` for the conjugated one),
// draw a SMALL ring challenge `x` (Fiat-Shamir), reveal the rejection-sampled
// `z` and the commitment-opening randomness. The verifier recomputes each
// aggregate's quadratic form on the PUBLIC `z` and checks it opens against the
// committed garbage, which forces the `x²` (plain) / `σ(x)·x` (conj) coefficient
// to the target — the kernel identities, now bound to commitments.
//
// A SMALL challenge (weight-τ ±1) keeps `x·s` short so the opening stays M-SIS
// binding (a uniform `x` would blow `z` up to ~q); soundness holds because each
// deg-4 split slot is a FIELD, so `x²·(v−b)=0` with `v≠b` forces `x≡0` in that
// slot (prob ≈ q⁻⁴), caught whp per shot and amplified over `REPS`.
// ─────────────────────────────────────────────────────────────────────────

/// Wide mask box for the ZK responses; must dominate `τ·‖witness‖∞` so rejection
/// keeps the revealed responses short (M-SIS binding) while hiding the witness.
const BASE_ZK_MASK: i64 = 1 << 26;
/// Repetitions (soundness amplification; per-shot catch prob ≈ 1−q⁻⁴ already).
const BASE_ZK_REPS: usize = 4;

/// One masked-opening shot of [`MaskedBaseOpening`].
#[derive(Clone)]
pub struct BaseOpeningShot {
    pub c_y: RingCommitment,  // Commit(flat(y); r_y)      — the mask
    pub c_t0: RingCommitment, // Commit(t0_P)  plain mask self-term  eval_quad(P,y)
    pub c_t1: RingCommitment, // Commit(t1_P)  plain cross           B_P(y,s)+lin_P(y)
    pub c_c0: RingCommitment, // Commit(C0)    conj mask self-term   eval_conj(C,y)
    pub c_c1: RingCommitment, // Commit(C1)    conj x-cross          Σâ·conj(y,s)
    pub c_d1: RingCommitment, // Commit(D1)    conj σ(x)-cross       Σâ·conj(s,y)+lin_C(y)
    pub z: PolyVec,           // flat(y + x·s)          (rejection-sampled)
    pub r_z: PolyVec,         // r_y + x·r_s            (opens z to c_y + x·u)
    pub z_gp: PolyVec,        // r_t0 + x·r_t1          (plain garbage opening)
    pub z_gc: PolyVec,        // r_c0 + x·r_c1 + σ(x)·r_d1  (conj garbage opening)
}

/// A perfect-ZK base opening: the witness commitment `u` (statement) + `REPS`
/// shots. Verify against the SAME public constraint family the recursion folds to.
pub struct MaskedBaseOpening {
    pub u: RingCommitment, // Commit(flat(s); r_s) — the base-witness commitment
    pub shots: Vec<BaseOpeningShot>,
}

/// `x·C` for a RING scalar `x` (homomorphic: `= Commit(x·m; x·r)`).
fn ring_scale_commit(c: &RingCommitment, x: &Poly) -> RingCommitment {
    RingCommitment { t1: c.t1.mul_poly(x), t2: c.t2.mul_poly(x) }
}

/// Flatten a structured witness (`r` vectors of dim `n`) to one `PolyVec` of
/// dim `r·n`; [`reshape_witness`] inverts it.
fn flatten_witness(s: &[PolyVec]) -> PolyVec {
    PolyVec(s.iter().flat_map(|v| v.0.iter().cloned()).collect())
}
fn reshape_witness(flat: &PolyVec, r: usize, n: usize) -> Vec<PolyVec> {
    (0..r).map(|i| PolyVec(flat.0[i * n..(i + 1) * n].to_vec())).collect()
}

/// Aggregate constraints with ring weights `rho` into ONE constraint of the same
/// shape (`Σ ρ_k·con_k`; terms/conj/linear scaled, targets summed).
fn aggregate_quad_weighted(cons: &[&QuadConstraint], rho: &[Poly]) -> QuadConstraint {
    let mut out = QuadConstraint { conj_terms: Vec::new(), terms: Vec::new(), linear: Vec::new(), b: Poly::zero() };
    for (con, r) in cons.iter().zip(rho) {
        for (i, j, a) in &con.terms {
            out.terms.push((*i, *j, r.mul_ntt(a)));
        }
        for (i, j, a) in &con.conj_terms {
            out.conj_terms.push((*i, *j, r.mul_ntt(a)));
        }
        for (i, phi) in &con.linear {
            out.linear.push((*i, phi.mul_poly(r)));
        }
        out.b = out.b.add(&r.mul_ntt(&con.b));
    }
    out
}

/// Symmetric bilinear cross of the QUADRATIC part: `B(y,s) = Q(y+s)−Q(y)−Q(s)`.
fn quad_cross(con: &QuadConstraint, y: &[PolyVec], s: &[PolyVec]) -> Poly {
    let ys: Vec<PolyVec> = y.iter().zip(s).map(|(yi, si)| yi.add(si)).collect();
    eval_quad_part(con, &ys).sub(&eval_quad_part(con, y)).sub(&eval_quad_part(con, s))
}

/// Absorb a ring commitment into a transcript.
fn absorb_commit(h: &mut Sha256, c: &RingCommitment) {
    for p in c.t1.0.iter().chain(c.t2.0.iter()) {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
}

/// Split a public family into (plain, conjugated) aggregates under FS weights
/// bound to `u`. A constraint with `conj_terms` goes to the conjugated bucket
/// (its `terms` must be empty — the folded family never mixes the two shapes);
/// everything else (incl. purely-linear) goes to the plain bucket.
fn base_opening_aggregates(family: &[QuadConstraint], u: &RingCommitment) -> (QuadConstraint, QuadConstraint) {
    let mut plain: Vec<&QuadConstraint> = Vec::new();
    let mut conj: Vec<&QuadConstraint> = Vec::new();
    for con in family {
        if con.conj_terms.is_empty() {
            plain.push(con);
        } else {
            debug_assert!(con.terms.is_empty(), "folded family must not mix plain + conj terms");
            conj.push(con);
        }
    }
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/base-opening/aggregate/v1");
    absorb_commit(&mut h, u);
    h.update((family.len() as u64).to_le_bytes());
    let mut prg = HashPrg::from_digest(&h.finalize());
    let rho_p: Vec<Poly> = (0..plain.len()).map(|_| uniform_ring(&mut prg)).collect();
    let rho_c: Vec<Poly> = (0..conj.len()).map(|_| uniform_ring(&mut prg)).collect();
    (aggregate_quad_weighted(&plain, &rho_p), aggregate_quad_weighted(&conj, &rho_c))
}

/// A uniform ring element (for SZ-style aggregation weights).
fn uniform_ring<R: RngU64>(prg: &mut R) -> Poly {
    let mut p = Poly::zero();
    for k in 0..RING_DEGREE_D {
        // Two draws to cover the full modulus (< 2^36) without bias concerns here.
        let hi = (prg.next_u64() as u128) << 4;
        p.c[k] = ((hi ^ prg.next_u64() as u128) % Poly::Q as u128) as u64;
    }
    p
}

/// Per-shot small ring challenge, Fiat-Shamir over `u`, the family, and the
/// shot's commitments (all fixed before `x`).
fn base_opening_challenge(u: &RingCommitment, sh: &BaseOpeningShot, rep: usize) -> Poly {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/base-opening/challenge/v1");
    for c in [u, &sh.c_y, &sh.c_t0, &sh.c_t1, &sh.c_c0, &sh.c_c1, &sh.c_d1] {
        absorb_commit(&mut h, c);
    }
    h.update((rep as u64).to_le_bytes());
    let mut prg = HashPrg::from_digest(&h.finalize());
    sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)
}

/// Prove, in perfect zero-knowledge, knowledge of a SHORT witness `s` committed
/// as `u = ck_s.commit(flat(s); r_s)` satisfying every constraint in `family`
/// (whole-ring; each plain-quad+linear or conjugated+linear). `ck1` is an
/// `ell=1` key for the garbage commitments. `None` on rejection exhaustion.
#[allow(clippy::too_many_arguments)]
pub fn prove_masked_base_opening(
    ck_s: &RingCommitKey,
    ck1: &RingCommitKey,
    family: &[QuadConstraint],
    s: &[PolyVec],
    r_s: &PolyVec,
    beta: u64,
    seed: u64,
) -> Option<MaskedBaseOpening> {
    let r = s.len();
    let n = s[0].len();
    let flat_s = flatten_witness(s);
    // The witness must fit the PUBLIC norm bound (a public check ⇒ no leak); the
    // recursion's gadget decomposition keeps the base β small so this holds.
    if flat_s.inf_norm() > beta || r_s.inf_norm() > SECRET_NORM_ETA as u64 {
        return None;
    }
    let u = ck_s.commit(&flat_s, r_s);
    let (agg_p, agg_c) = base_opening_aggregates(family, &u);
    let lambda = ck_s.a1.cols;
    // Rejection box from the PUBLIC β (witness-INDEPENDENT ⇒ perfect ZK): a
    // weight-τ ±1 challenge shifts each response coeff by ≤ τ·β (≤ τ·η for the
    // randomness). ×2 margin covers the two-cross conj opening.
    let shift = (CHALLENGE_WEIGHT_TAU as i64) * (beta as i64 + 1) * 2;
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;

    let mut shots = Vec::with_capacity(BASE_ZK_REPS);
    for rep in 0..BASE_ZK_REPS {
        let mut got = None;
        for attempt in 0..4000u64 {
            let mut prg = SplitMix64::new(seed ^ ((rep as u64) << 40) ^ attempt.wrapping_mul(0x9E37));
            // Wide mask y (structured like s) + wide/short randomness.
            let y: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_uniform_pm(n, BASE_ZK_MASK, &mut prg)).collect();
            let r_y = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
            let r_t0 = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
            let r_t1 = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            let r_c0 = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
            let r_c1 = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            let r_d1 = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);

            // Garbage (challenge-independent).
            let t0 = eval_quad_part(&agg_p, &y);
            let t1 = quad_cross(&agg_p, &y, s).add(&eval_lin_part(&agg_p, &y));
            let cc0 = eval_quad_part(&agg_c, &y); // terms empty ⇒ = eval_conj(y)
            let cc1 = eval_conj_cross(&agg_c, &y, s);
            let dd1 = eval_conj_cross(&agg_c, s, &y).add(&eval_lin_part(&agg_c, &y));

            let one = |m: &Poly, rr: &PolyVec| ck1.commit(&PolyVec(vec![m.clone()]), rr);
            let mut sh = BaseOpeningShot {
                c_y: ck_s.commit(&flatten_witness(&y), &r_y),
                c_t0: one(&t0, &r_t0),
                c_t1: one(&t1, &r_t1),
                c_c0: one(&cc0, &r_c0),
                c_c1: one(&cc1, &r_c1),
                c_d1: one(&dd1, &r_d1),
                z: PolyVec::zero(r * n),
                r_z: PolyVec::zero(lambda),
                z_gp: PolyVec::zero(lambda),
                z_gc: PolyVec::zero(lambda),
            };
            let x = base_opening_challenge(&u, &sh, rep);
            let sx = x.conjugate();
            // Responses.
            let z_struct: Vec<PolyVec> = mask_response(s, &y, &x);
            let z = flatten_witness(&z_struct);
            let r_z = r_y.add(&r_s.mul_poly(&x));
            let z_gp = r_t0.add(&r_t1.mul_poly(&x));
            let z_gc = r_c0.add(&r_c1.mul_poly(&x)).add(&r_d1.mul_poly(&sx));
            if z.inf_norm() <= bound
                && r_z.inf_norm() <= bound
                && z_gp.inf_norm() <= bound
                && z_gc.inf_norm() <= bound
            {
                sh.z = z;
                sh.r_z = r_z;
                sh.z_gp = z_gp;
                sh.z_gc = z_gc;
                got = Some(sh);
                break;
            }
        }
        shots.push(got?);
    }
    Some(MaskedBaseOpening { u, shots })
}

/// Verify a [`MaskedBaseOpening`] against the public `family`. `r`,`n` are the
/// base witness shape (so `z` can be reshaped to evaluate the constraints).
#[allow(clippy::too_many_arguments)]
pub fn verify_masked_base_opening(
    ck_s: &RingCommitKey,
    ck1: &RingCommitKey,
    family: &[QuadConstraint],
    r: usize,
    n: usize,
    pf: &MaskedBaseOpening,
) -> bool {
    if pf.shots.len() != BASE_ZK_REPS {
        return false;
    }
    let (agg_p, agg_c) = base_opening_aggregates(family, &pf.u);
    // A norm bound the verifier can enforce (short opening ⇒ M-SIS binding).
    let bound = BASE_ZK_MASK as u64;
    for (rep, sh) in pf.shots.iter().enumerate() {
        if sh.z.len() != r * n {
            return false;
        }
        if sh.z.inf_norm() > bound || sh.r_z.inf_norm() > bound || sh.z_gp.inf_norm() > bound || sh.z_gc.inf_norm() > bound {
            return false;
        }
        let x = base_opening_challenge(&pf.u, sh, rep);
        let sx = x.conjugate();
        // (1) z opens: Commit(z; r_z) == c_y + x·u.
        if ck_s.commit(&sh.z, &sh.r_z) != sh.c_y.add(&ring_scale_commit(&pf.u, &x)) {
            return false;
        }
        let zs = reshape_witness(&sh.z, r, n);
        // (2) plain aggregate: W_P = eval_quad(z)+x·eval_lin(z); (W_P − x²·b) opens
        //     to c_t0 + x·c_t1.
        let w_p = eval_quad_part(&agg_p, &zs).add(&x.mul_ntt(&eval_lin_part(&agg_p, &zs)));
        let x2b = x.mul_ntt(&x).mul_ntt(&agg_p.b);
        let lhs_p = ck1.commit(&PolyVec(vec![w_p.sub(&x2b)]), &sh.z_gp);
        if lhs_p != sh.c_t0.add(&ring_scale_commit(&sh.c_t1, &x)) {
            return false;
        }
        // (3) conj aggregate: W_C = eval_conj(z)+σ(x)·eval_lin(z); (W_C − σ(x)x·b)
        //     opens to c_c0 + x·c_c1 + σ(x)·c_d1.
        let w_c = eval_quad_part(&agg_c, &zs).add(&sx.mul_ntt(&eval_lin_part(&agg_c, &zs)));
        let sxxb = sx.mul_ntt(&x).mul_ntt(&agg_c.b);
        let lhs_c = ck1.commit(&PolyVec(vec![w_c.sub(&sxxb)]), &sh.z_gc);
        let rhs_c = sh.c_c0.add(&ring_scale_commit(&sh.c_c1, &x)).add(&ring_scale_commit(&sh.c_d1, &sx));
        if lhs_c != rhs_c {
            return false;
        }
    }
    true
}

// ── Step 4d: the residual LINEAR ct-family base opening (scalar-challenge) ──
//
// After folding, the base ct-family is a set of LINEAR coefficient constraints
// `Σ_i ⟪φ_i, s_i⟫ = target`. The coefficient inner product `⟪·,·⟫` is NOT
// preserved by a RING challenge, so these can't ride the whole-ring masked `z`;
// they get their own SCALAR-challenge opening bound to the SAME witness
// commitment `u`. Being linear, it needs no repetition — any nonzero scalar `x`
// forces `⟪Φ,s⟫ = T` (like `balance_zk`). ZK: `z` rejection-sampled from a wide
// mask (witness-independent); `t = ⟪Φ,z⟫ − x·T` is public post-`x`.

/// Small nonzero-scalar challenge bound (keeps `z = y + x·s` short).
const CT_BASE_CHAL: i64 = 1 << 12;

fn const_poly(v: u64) -> Poly {
    let mut p = Poly::zero();
    p.c[0] = v % Poly::Q;
    p
}

/// `x·C` for a scalar `x` (homomorphic: `= Commit(x·m; x·r)`).
fn scalar_scale_commit(c: &RingCommitment, x: i64) -> RingCommitment {
    RingCommitment { t1: c.t1.scalar_mul(x), t2: c.t2.scalar_mul(x) }
}

/// Aggregate the LINEAR ct-family to one `⟪Φ, flat(s)⟫ = T` under FS scalar
/// weights bound to `u` (SZ: a violated constraint survives with prob ≤ 1/q).
fn aggregate_ct_base(family: &[CtConstraint], r: usize, n: usize, u: &RingCommitment) -> (PolyVec, u64) {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ct-base/aggregate/v1");
    absorb_commit(&mut h, u);
    h.update((family.len() as u64).to_le_bytes());
    let mut prg = HashPrg::from_digest(&h.finalize());
    let q = Poly::Q as u128;
    let mut phi = vec![PolyVec::zero(n); r];
    let mut t = 0u128;
    for con in family {
        debug_assert!(con.terms.is_empty(), "base ct-family must be linear (no quadratic ct)");
        let rho = (prg.next_u64() as u128 % q) as i64;
        for (i, v) in &con.linear {
            phi[*i] = phi[*i].add(&v.scalar_mul(rho));
        }
        t = (t + (rho as u128) * (con.target as u128 % q)) % q;
    }
    (flatten_witness(&phi), t as u64)
}

/// The nonzero scalar challenge, Fiat-Shamir over `u` and the shot commitments.
fn ct_base_challenge(u: &RingCommitment, c_y: &RingCommitment, c_t: &RingCommitment) -> i64 {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ct-base/challenge/v1");
    for c in [u, c_y, c_t] {
        absorb_commit(&mut h, c);
    }
    let d = h.finalize();
    1 + (u64::from_le_bytes(d[..8].try_into().unwrap()) % CT_BASE_CHAL as u64) as i64
}

/// A perfect-ZK opening for the residual linear ct-family (see module note).
#[derive(Clone)]
pub struct CtBaseOpening {
    pub c_y: RingCommitment, // Commit(flat(y); r_y)
    pub c_t: RingCommitment, // Commit(const(⟪Φ,y⟫); r_t)
    pub z: PolyVec,          // flat(y) + x·flat(s)
    pub r_z: PolyVec,        // r_y + x·r_s
    pub r_t: PolyVec,        // opening randomness for c_t (t public post-x)
}

/// Prove the linear ct-family holds on the witness committed as `u`, in ZK.
#[allow(clippy::too_many_arguments)]
pub fn prove_ct_base_opening(
    ck_s: &RingCommitKey,
    ck1: &RingCommitKey,
    family: &[CtConstraint],
    s: &[PolyVec],
    r_s: &PolyVec,
    u: &RingCommitment,
    beta: u64,
    seed: u64,
) -> Option<CtBaseOpening> {
    let (r, n) = (s.len(), s[0].len());
    let (phi, t_target) = aggregate_ct_base(family, r, n, u);
    let flat_s = flatten_witness(s);
    if flat_s.inf_norm() > beta || r_s.inf_norm() > SECRET_NORM_ETA as u64 {
        return None;
    }
    let lambda = ck_s.a1.cols;
    let shift = CT_BASE_CHAL * (beta as i64 + 1);
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;
    let _ = t_target;
    for attempt in 0..4000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x51C7));
        let y = PolyVec::sample_uniform_pm(r * n, BASE_ZK_MASK, &mut prg);
        let r_y = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let r_t = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let t_val = coeff_inner_vec(&phi, &y);
        let c_y = ck_s.commit(&y, &r_y);
        let c_t = ck1.commit(&PolyVec(vec![const_poly(t_val)]), &r_t);
        let x = ct_base_challenge(u, &c_y, &c_t);
        let z = y.add(&flat_s.scalar_mul(x));
        let r_z = r_y.add(&r_s.scalar_mul(x));
        if z.inf_norm() <= bound && r_z.inf_norm() <= bound {
            return Some(CtBaseOpening { c_y, c_t, z, r_z, r_t });
        }
    }
    None
}

/// Verify a [`CtBaseOpening`] against the public linear ct-`family` and `u`.
#[allow(clippy::too_many_arguments)]
pub fn verify_ct_base_opening(
    ck_s: &RingCommitKey,
    ck1: &RingCommitKey,
    family: &[CtConstraint],
    r: usize,
    n: usize,
    u: &RingCommitment,
    pf: &CtBaseOpening,
) -> bool {
    let (phi, t_target) = aggregate_ct_base(family, r, n, u);
    let bound = BASE_ZK_MASK as u64;
    if pf.z.len() != r * n || pf.z.inf_norm() > bound || pf.r_z.inf_norm() > bound {
        return false;
    }
    let x = ct_base_challenge(u, &pf.c_y, &pf.c_t);
    // (1) z opens: Commit(z; r_z) == c_y + x·u.
    if ck_s.commit(&pf.z, &pf.r_z) != pf.c_y.add(&scalar_scale_commit(u, x)) {
        return false;
    }
    // (2) ct value: const(⟪Φ,z⟫ − x·T) opens to c_t (forces ⟪Φ,s⟫ = T).
    let q = Poly::Q as u128;
    let zphi = coeff_inner_vec(&phi, &pf.z) as u128;
    let val = ((zphi + q - ((x as u128) * (t_target as u128)) % q) % q) as u64;
    ck1.commit(&PolyVec(vec![const_poly(val)]), &pf.r_t) == pf.c_t
}

// ─────────────────────────────────────────────────────────────────────────
// Step 5b — the ZERO-KNOWLEDGE NS22 succinct base.
//
// The plain NS22 base (`prove_base_ns22`) is succinct (148 KB — sends the
// amortized `z`, dim `n`, + O(r) garbage, NEVER the r·n witness) but NOT ZK: it
// reveals `z = Σcᵢsᵢ` and the garbage `⟨sᵢ,sⱼ⟩`, `⟨φᵢ,sᵢ⟩`. This masks both:
//  · reveal only `z' = w + Σcᵢsᵢ` (dim n) for a wide mask `w`, rejection-sampled
//    to a fixed box ⇒ witness-independent (perfect ZK of the opening);
//  · COMMIT every garbage value (ell-1 commitments, fixed before `c`) and check
//    the quadratic `⟨z',z'⟩ = ⟨w,w⟩ + 2Σcᵢ⟨w,sᵢ⟩ + Σcᵢcⱼ⟨sᵢ,sⱼ⟩` and the
//    statement `Σaᵢ⟨sᵢ,sᵢ⟩ + Σ⟨φᵢ,sᵢ⟩ = b` HOMOMORPHICALLY against the committed
//    garbage (the masked-base-opening pattern, Step 4b, on NS22's diagonal
//    relation).
// NORM: `z'` is wide (masked), so it no longer bounds `‖s‖` — the JL projection
// `p` (already validated: `jl_project`/`jl_norm_ok`) carries the norm; BINDING `p`
// to the committed `s` uses the ct machinery (Step 4d) and is the noted final
// sub-piece. Proof stays ~150–200 KB (z' dim n + O(r²) committed garbage).
// ─────────────────────────────────────────────────────────────────────────

/// A ZK NS22 succinct base proof.
#[derive(Clone)]
pub struct Ns22ZkProof {
    pub t: Vec<PolyVec>,          // A·sᵢ (r inner commitments)
    pub t_w: PolyVec,             // A·w  (mask commitment)
    pub c_f: RingCommitment,      // Commit(⟨w,w⟩)
    pub c_e: Vec<RingCommitment>, // Commit(⟨w,sᵢ⟩), r          (quadratic mask cross)
    pub c_g: Vec<RingCommitment>, // Commit(⟨sᵢ,sⱼ⟩), i≤j       (r(r+1)/2, packed upper)
    pub c_e2: Vec<RingCommitment>, // Commit(⟨φᵢ,w⟩), r         (linear mask cross)
    pub c_h: Vec<RingCommitment>, // Commit(⟨φᵢ,sⱼ⟩), full r²   (row-major i·r+j)
    pub zp: PolyVec,              // w + Σcᵢsᵢ  (masked amortized opening)
    pub z_gq: PolyVec,            // quadratic-combo opening randomness
    pub z_gl: PolyVec,            // linear-combo opening randomness
    pub z_gs: PolyVec,            // statement-combo opening randomness
    pub p: [i128; 256],           // JL projection of s (for the norm)
    // ── succinct JL norm-BINDING (conjugated garbage; ties p to the same s) ──
    pub c_mh: Vec<RingCommitment>, // Commit(conj_dot(Φᵢ,w)), r      (conj mask cross)
    pub c_hh: Vec<RingCommitment>, // Commit(ĥ_ij=conj_dot(Φᵢ,sⱼ)), r²  (row-major)
    pub z_hbind: PolyVec,          // whole-ring conjugated-binding combo randomness
    pub c_nu: RingCommitment,      // Commit(ν)          (mask for the ct-statement)
    pub c_ctnu: RingCommitment,    // Commit(const(ct(ν)))
    pub zeta: Poly,                // ν + Σᵢ ĥ_ii        (masked; ct(ζ)−P = ct(ν))
    pub r_zeta: PolyVec,           // opening randomness for ζ
    pub r_ctnu: PolyVec,           // opening randomness for c_ctnu
}

/// Upper-triangular index (i≤j) into the packed `c_g` list.
fn tri_idx(i: usize, j: usize, r: usize) -> usize {
    // rows 0..i each contribute (r - row) entries.
    let (i, j) = if i <= j { (i, j) } else { (j, i) };
    let mut base = 0;
    for row in 0..i {
        base += r - row;
    }
    base + (j - i)
}

/// r weight-τ ring challenges for the ZK NS22 base, FS-bound to the statement and
/// all commitments (fixed before the challenges).
fn ns22zk_challenges(
    label: &[u8],
    phi: &[PolyVec],
    a_diag: &[Poly],
    b: &Poly,
    t: &[PolyVec],
    t_w: &PolyVec,
    c_f: &RingCommitment,
    c_e: &[RingCommitment],
    c_g: &[RingCommitment],
    c_h: &[RingCommitment],
    c_mh: &[RingCommitment],
    c_hh: &[RingCommitment],
    c_nu: &RingCommitment,
    r: usize,
) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ns22-zk/v1");
    h.update(label);
    for p in phi {
        for pp in &p.0 {
            for &x in &pp.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for ad in a_diag {
        for &x in &ad.c {
            h.update(x.to_le_bytes());
        }
    }
    for &x in &b.c {
        h.update(x.to_le_bytes());
    }
    for ti in t {
        for pp in &ti.0 {
            for &x in &pp.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    for pp in &t_w.0 {
        for &x in &pp.c {
            h.update(x.to_le_bytes());
        }
    }
    for c in std::iter::once(c_f).chain(c_e).chain(c_g).chain(c_h).chain(c_mh).chain(c_hh).chain(std::iter::once(c_nu)) {
        absorb_commit(&mut h, c);
    }
    let mut prg = HashPrg::from_digest(&h.finalize());
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// Prove the NS22 diagonal base relation (`Σaᵢ⟨sᵢ,sᵢ⟩ + Σ⟨φᵢ,sᵢ⟩ = b`, `A·sᵢ=tᵢ`,
/// `‖s‖` short) in ZERO-KNOWLEDGE. `ck1` is an ell-1 garbage key. `None` on
/// rejection exhaustion.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn prove_base_ns22_zk(
    a: &PolyMatrix,
    ck1: &RingCommitKey,
    s: &[PolyVec],
    phi: &[PolyVec],
    a_diag: &[Poly],
    b: &Poly,
    ct_family: &[CtConstraint],
    beta: u64,
    label: &[u8],
    seed: u64,
) -> Option<Ns22ZkProof> {
    let r = s.len();
    let n = s[0].len();
    let lambda = ck1.a1.cols;
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    // Challenge-independent garbage.
    let g: Vec<Poly> = {
        let mut v = Vec::new();
        for i in 0..r {
            for j in i..r {
                v.push(dot(&s[i], &s[j]));
            }
        }
        v
    };
    // Linear garbage h_ij = ⟨φᵢ,sⱼ⟩ (FULL r², NOT symmetric) — bound by the
    // linear check so the statement's diagonal h_ii = ⟨φᵢ,sᵢ⟩ is enforced.
    let hfull: Vec<Poly> = {
        let mut v = Vec::new();
        for i in 0..r {
            for j in 0..r {
                v.push(dot(&phi[i], &s[j]));
            }
        }
        v
    };
    // JL seed bound to t (public Π). p = Π·s; the norm-binding aggregate below.
    let jl_seed = fs_jl_seed(&t);
    let p = jl_project(s, jl_seed);
    // Combined binding functional Φ = Φ_JL + Φ_ct, P = P_JL + P_ct: the JL norm
    // rows AND the folded LINEAR ct-family (binary/range) ride the SAME conjugated
    // garbage ĥ_ij = conj_dot(Φᵢ,sⱼ), with Σᵢ ct(ĥ_ii) = ⟪Φ,s⟫ = P.
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (phi_ct, p_ct) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&phi_ct[i]);
        }
        cap_p = (cap_p + p_ct as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    let hhat: Vec<Poly> = {
        let mut v = Vec::new();
        for i in 0..r {
            for j in 0..r {
                v.push(conj_dot(&cap_phi[i], &s[j]));
            }
        }
        v
    };
    let mut s_h = Poly::zero(); // Σᵢ ĥ_ii
    for i in 0..r {
        s_h = s_h.add(&hhat[i * r + i]);
    }
    // Rejection box (public β; witness-independent): ‖Σcᵢsᵢ‖∞ ≤ r·τ·β.
    let shift = (r as i64) * (CHALLENGE_WEIGHT_TAU as i64) * (beta as i64 + 1);
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;

    for attempt in 0..4000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x2D_51C7));
        let w = PolyVec::sample_uniform_pm(n, BASE_ZK_MASK, &mut prg);
        let t_w = a.matvec(&w);
        let f = dot(&w, &w);
        let e: Vec<Poly> = (0..r).map(|i| dot(&w, &s[i])).collect(); // ⟨w,sᵢ⟩
        let e2: Vec<Poly> = (0..r).map(|i| dot(&phi[i], &w)).collect(); // ⟨φᵢ,w⟩
        let mh: Vec<Poly> = (0..r).map(|i| conj_dot(&cap_phi[i], &w)).collect(); // conj mask cross
        let one = |m: &Poly, rr: &PolyVec| ck1.commit(&PolyVec(vec![m.clone()]), rr);
        let r_f = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let commit_list = |vals: &[Poly], prg: &mut SplitMix64| -> (Vec<PolyVec>, Vec<RingCommitment>) {
            let mut rs = Vec::new();
            let mut cs = Vec::new();
            for v in vals {
                let rr = PolyVec::sample_short(lambda, SECRET_NORM_ETA, prg);
                cs.push(one(v, &rr));
                rs.push(rr);
            }
            (rs, cs)
        };
        let (r_e, c_e) = commit_list(&e, &mut prg);
        let (r_e2, c_e2) = commit_list(&e2, &mut prg);
        let (r_g, c_g) = commit_list(&g, &mut prg);
        let (r_h, c_h) = commit_list(&hfull, &mut prg);
        let (r_mh, c_mh) = commit_list(&mh, &mut prg);
        let (r_hh, c_hh) = commit_list(&hhat, &mut prg);
        let c_f = one(&f, &r_f);
        // ct-statement mask ν (wide) + its constant-term commitment.
        let nu = PolyVec::sample_uniform_pm(1, BASE_ZK_MASK, &mut prg).0[0].clone();
        let r_nu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let r_ctnu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let c_nu = one(&nu, &r_nu);
        let c_ctnu = one(&const_poly(nu.c[0]), &r_ctnu);
        let c = ns22zk_challenges(label, phi, a_diag, b, &t, &t_w, &c_f, &c_e, &c_g, &c_h, &c_mh, &c_hh, &c_nu, r);

        let mut zp = w.clone();
        for i in 0..r {
            zp = zp.add(&s[i].mul_poly(&c[i]));
        }
        if zp.inf_norm() > bound {
            continue;
        }
        // Quadratic-combo randomness: z_gq = r_f + Σ 2cᵢ·r_e[i] + Σ_{i≤j} κ_ij·r_g[ij].
        let mut z_gq = r_f.clone();
        for i in 0..r {
            z_gq = z_gq.add(&r_e[i].mul_poly(&c[i].scalar_mul(2)));
        }
        for i in 0..r {
            for j in i..r {
                let coeff = if i == j { c[i].mul_ntt(&c[i]) } else { c[i].mul_ntt(&c[j]).scalar_mul(2) };
                z_gq = z_gq.add(&r_g[tri_idx(i, j, r)].mul_poly(&coeff));
            }
        }
        // Linear-combo randomness: z_gl = Σ cᵢ·r_e2[i] + Σ_{i,j} cᵢcⱼ·r_h[i·r+j].
        let mut z_gl = PolyVec::zero(lambda);
        for i in 0..r {
            z_gl = z_gl.add(&r_e2[i].mul_poly(&c[i]));
            for j in 0..r {
                z_gl = z_gl.add(&r_h[i * r + j].mul_poly(&c[i].mul_ntt(&c[j])));
            }
        }
        // Statement-combo randomness: z_gs = Σ aᵢ·r_g[ii] + Σ r_h[i·r+i].
        let mut z_gs = PolyVec::zero(lambda);
        for i in 0..r {
            z_gs = z_gs.add(&r_g[tri_idx(i, i, r)].mul_poly(&a_diag[i]));
            z_gs = z_gs.add(&r_h[i * r + i]);
        }
        // JL whole-ring binding randomness: conj_dot(Φ_fold, zp) opens to
        //   Σ σ(cᵢ)·c_mh[i] + Σ σ(cᵢ)cⱼ·c_hh[i·r+j].  (binds ĥ_ij to conj_dot(Φᵢ,sⱼ))
        let mut z_hbind = PolyVec::zero(lambda);
        for i in 0..r {
            let sci = c[i].conjugate();
            z_hbind = z_hbind.add(&r_mh[i].mul_poly(&sci));
            for j in 0..r {
                z_hbind = z_hbind.add(&r_hh[i * r + j].mul_poly(&sci.mul_ntt(&c[j])));
            }
        }
        // ct-statement opening: ζ = ν + S_h,  r_zeta = r_nu + Σ r_hh[ii].
        let zeta = nu.add(&s_h);
        let mut r_zeta = r_nu.clone();
        for i in 0..r {
            r_zeta = r_zeta.add(&r_hh[i * r + i]);
        }
        return Some(Ns22ZkProof {
            t, t_w, c_f, c_e, c_g, c_e2, c_h, zp, z_gq, z_gl, z_gs, p,
            c_mh, c_hh, z_hbind, c_nu, c_ctnu, zeta, r_zeta, r_ctnu,
        });
    }
    let _ = (cap_p, s_h);
    None
}

/// Verify a [`Ns22ZkProof`]. `beta_l2` is the public ℓ₂ bound `‖s‖₂ ≤ β_l2` the JL
/// norm check enforces.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn verify_base_ns22_zk(
    a: &PolyMatrix,
    ck1: &RingCommitKey,
    phi: &[PolyVec],
    a_diag: &[Poly],
    b: &Poly,
    ct_family: &[CtConstraint],
    beta_l2: u128,
    pf: &Ns22ZkProof,
    label: &[u8],
) -> bool {
    let r = pf.t.len();
    let n = a.cols;
    let tri = r * (r + 1) / 2;
    if pf.c_e.len() != r || pf.c_e2.len() != r || pf.c_h.len() != r * r || pf.c_g.len() != tri || a_diag.len() != r || phi.len() != r {
        return false;
    }
    if pf.c_mh.len() != r || pf.c_hh.len() != r * r {
        return false;
    }
    if pf.zp.len() != a.cols || pf.t.iter().any(|ti| ti.len() != a.rows) || phi.iter().any(|p| p.len() != a.cols) {
        return false;
    }
    if pf.zp.inf_norm() > BASE_ZK_MASK as u64 {
        return false;
    }
    let c = ns22zk_challenges(label, phi, a_diag, b, &pf.t, &pf.t_w, &pf.c_f, &pf.c_e, &pf.c_g, &pf.c_h, &pf.c_mh, &pf.c_hh, &pf.c_nu, r);

    // (1) zp opens: A·zp = t_w + Σ cᵢ·tᵢ.
    let mut fold_t = pf.t_w.clone();
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if a.matvec(&pf.zp) != fold_t {
        return false;
    }
    // (2) quadratic: Commit(⟨zp,zp⟩; z_gq) == c_f + Σ 2cᵢ·c_e[i] + Σ_{i≤j} κ_ij·c_g[ij].
    //     Binds g_ij = ⟨sᵢ,sⱼ⟩ (Schwartz-Zippel over the random c).
    let zz = dot(&pf.zp, &pf.zp);
    let mut rhs_q = pf.c_f.clone();
    for i in 0..r {
        rhs_q = rhs_q.add(&ring_scale_commit(&pf.c_e[i], &c[i].scalar_mul(2)));
    }
    for i in 0..r {
        for j in i..r {
            let coeff = if i == j { c[i].mul_ntt(&c[i]) } else { c[i].mul_ntt(&c[j]).scalar_mul(2) };
            rhs_q = rhs_q.add(&ring_scale_commit(&pf.c_g[tri_idx(i, j, r)], &coeff));
        }
    }
    if ck1.commit(&PolyVec(vec![zz]), &pf.z_gq) != rhs_q {
        return false;
    }
    // (2b) linear: Commit(Σ cᵢ⟨φᵢ,zp⟩; z_gl) == Σ cᵢ·c_e2[i] + Σ_{i,j} cᵢcⱼ·c_h[i·r+j].
    //      Binds h_ij = ⟨φᵢ,sⱼ⟩ (so the statement's diagonal h_ii is enforced).
    let mut lz = Poly::zero();
    for i in 0..r {
        lz = lz.add(&c[i].mul_ntt(&dot(&phi[i], &pf.zp)));
    }
    let mut rhs_l = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for i in 0..r {
        rhs_l = rhs_l.add(&ring_scale_commit(&pf.c_e2[i], &c[i]));
        for j in 0..r {
            rhs_l = rhs_l.add(&ring_scale_commit(&pf.c_h[i * r + j], &c[i].mul_ntt(&c[j])));
        }
    }
    if ck1.commit(&PolyVec(vec![lz]), &pf.z_gl) != rhs_l {
        return false;
    }
    // (3) statement: Commit(b; z_gs) == Σ aᵢ·c_g[ii] + Σ c_h[i·r+i].
    let mut rhs_s = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for i in 0..r {
        rhs_s = rhs_s.add(&ring_scale_commit(&pf.c_g[tri_idx(i, i, r)], &a_diag[i]));
        rhs_s = rhs_s.add(&pf.c_h[i * r + i]);
    }
    if ck1.commit(&PolyVec(vec![b.clone()]), &pf.z_gs) != rhs_s {
        return false;
    }
    // ── succinct binding (JL norm rows + folded linear ct-family) ──
    // Reconstruct Φ = Φ_JL + Φ_ct, P = P_JL + P_ct exactly as the prover (public
    // FS Π bound to t; the ct-family is public, re-folded by the recursion verifier).
    let jl_seed = fs_jl_seed(&pf.t);
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &pf.p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (phi_ct, p_ct) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&phi_ct[i]);
        }
        cap_p = (cap_p + p_ct as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    // (4a) whole-ring conjugated binding: conj_dot(Φ_fold, zp) opens to
    //   Σ σ(cᵢ)·c_mh[i] + Σ σ(cᵢ)cⱼ·c_hh[i·r+j].  Binds ĥ_ij = conj_dot(Φᵢ,sⱼ) by
    //   Schwartz-Zippel over the random c (so the statement's diagonal ĥ_ii is real).
    let mut phi_fold = PolyVec::zero(n);
    for i in 0..r {
        phi_fold = phi_fold.add(&cap_phi[i].mul_poly(&c[i]));
    }
    let hbind_lhs = conj_dot(&phi_fold, &pf.zp);
    let mut rhs_hb = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for i in 0..r {
        let sci = c[i].conjugate();
        rhs_hb = rhs_hb.add(&ring_scale_commit(&pf.c_mh[i], &sci));
        for j in 0..r {
            rhs_hb = rhs_hb.add(&ring_scale_commit(&pf.c_hh[i * r + j], &sci.mul_ntt(&c[j])));
        }
    }
    if ck1.commit(&PolyVec(vec![hbind_lhs]), &pf.z_hbind) != rhs_hb {
        return false;
    }
    // (4b) ct-statement: ζ = ν + Σᵢ ĥ_ii, so (i) Commit(ζ; r_zeta) == c_nu + Σ c_hh[ii]
    //   (binds ζ), and (ii) Commit(const(ct(ζ) − P); r_ctnu) == c_ctnu (pins ct(ν),
    //   forcing Σᵢ ct(ĥ_ii) = P = ⟪Φ,s⟫). Together with (4a) this binds every p_k.
    let mut rhs_z = pf.c_nu.clone();
    for i in 0..r {
        rhs_z = rhs_z.add(&pf.c_hh[i * r + i]);
    }
    if ck1.commit(&PolyVec(vec![pf.zeta.clone()]), &pf.r_zeta) != rhs_z {
        return false;
    }
    let q = Poly::Q as i128;
    let ctnu = ((pf.zeta.c[0] as i128 - cap_p as i128).rem_euclid(q)) as u64;
    if ck1.commit(&PolyVec(vec![const_poly(ctnu)]), &pf.r_ctnu) != pf.c_ctnu {
        return false;
    }
    // (4c) norm: with p now bound to s, the JL bound enforces ‖s‖₂ ≤ β_l2.
    jl_norm_ok(&pf.p, beta_l2)
}

/// The JL Fiat-Shamir seed: bound to the committed inner commitments `t` so the
/// projection matrix Π is PUBLIC (not prover-chosen). Prover + verifier agree.
fn fs_jl_seed(t: &[PolyVec]) -> u64 {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ns22-zk/jl-seed/v1");
    for ti in t {
        for pp in &ti.0 {
            for &x in &pp.c {
                h.update(x.to_le_bytes());
            }
        }
    }
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

// ─────────────────────────────────────────────────────────────────────────
// Step 5c — the GENERAL ZK terminal (for the ct-recursion's output).
//
// The diagonal ZK base proves `Σaᵢ⟨sᵢ,sᵢ⟩+Σ⟨φᵢ,sᵢ⟩=b`. The output of
// `reduce_to_child_conj_ct` is a GENERAL constraint: off-diagonal `terms`
// `Σa_ij⟨sᵢ,sⱼ⟩`, CONJUGATED `conj_terms` `Σâ_ij⟨σ(sᵢ),sⱼ⟩` (the ĝ/ĥ bindings),
// and `linear`. This terminal proves that general statement in ZK, adding a
// conjugated-`terms` garbage region `ĝc_ij = conj_dot(sᵢ,sⱼ)` bound by the SAME
// whole-ring conjugated identity used for JL, so it can terminate the ct-recursion
// directly (no diagonal no-decompose last level). Everything else — masked `z'`,
// g/h garbage, JL norm-binding, ct-family — carries over.
// ─────────────────────────────────────────────────────────────────────────

/// A general ZK terminal proof (superset of [`Ns22ZkProof`] + conjugated-terms).
#[derive(Clone)]
pub struct GeneralBaseZkProof {
    pub t: Vec<PolyVec>,
    pub t_w: PolyVec,
    pub c_f: RingCommitment,
    pub c_e: Vec<RingCommitment>,
    pub c_g: Vec<RingCommitment>,   // ⟨sᵢ,sⱼ⟩, i≤j
    pub c_e2: Vec<RingCommitment>,
    pub c_h: Vec<RingCommitment>,   // ⟨φᵢ,sⱼ⟩, r²
    pub zp: PolyVec,
    pub z_gq: PolyVec,
    pub z_gl: PolyVec,
    pub z_gs: PolyVec,
    pub p: [i128; 256],
    pub c_mh: Vec<RingCommitment>,
    pub c_hh: Vec<RingCommitment>,
    pub z_hbind: PolyVec,
    pub c_nu: RingCommitment,
    pub c_ctnu: RingCommitment,
    pub zeta: Poly,
    pub r_zeta: PolyVec,
    pub r_ctnu: PolyVec,
    // conjugated-terms garbage (for `stmt.conj_terms`):
    pub c_fc: RingCommitment,       // conj_dot(w,w)
    pub c_ecl: Vec<RingCommitment>, // conj_dot(w,sⱼ), r
    pub c_ecr: Vec<RingCommitment>, // conj_dot(sᵢ,w), r
    pub c_gc: Vec<RingCommitment>,  // ĝc_ij = conj_dot(sᵢ,sⱼ), r²
    pub z_gc: PolyVec,              // conjugated-quadratic combo randomness
}

/// r weight-τ ring challenges for the general terminal, FS-bound to the general
/// statement + ct-family + ALL commitments.
#[allow(clippy::too_many_arguments)]
fn general_zk_challenges(
    label: &[u8],
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    t: &[PolyVec],
    t_w: &PolyVec,
    commits: &[&RingCommitment],
    r: usize,
) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/general-zk/v1");
    h.update(label);
    let absorb_poly = |h: &mut Sha256, p: &Poly| {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    };
    for (i, j, a) in &stmt.terms {
        h.update((*i as u64).to_le_bytes());
        h.update((*j as u64).to_le_bytes());
        absorb_poly(&mut h, a);
    }
    for (i, j, a) in &stmt.conj_terms {
        h.update((*i as u64).to_le_bytes());
        h.update((*j as u64).to_le_bytes());
        absorb_poly(&mut h, a);
    }
    for (i, phi) in &stmt.linear {
        h.update((*i as u64).to_le_bytes());
        for pp in &phi.0 {
            absorb_poly(&mut h, pp);
        }
    }
    absorb_poly(&mut h, &stmt.b);
    h.update((ct_family.len() as u64).to_le_bytes());
    for con in ct_family {
        h.update((con.target).to_le_bytes());
    }
    for ti in t {
        for pp in &ti.0 {
            absorb_poly(&mut h, pp);
        }
    }
    for pp in &t_w.0 {
        absorb_poly(&mut h, pp);
    }
    for c in commits {
        absorb_commit(&mut h, c);
    }
    let mut prg = HashPrg::from_digest(&h.finalize());
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// Prove a GENERAL whole-ring statement (`Σa_ij⟨sᵢ,sⱼ⟩ + Σâ_ij⟨σ(sᵢ),sⱼ⟩ +
/// Σ⟨φᵢ,sᵢ⟩ = b`, `A·sᵢ=tᵢ`, `‖s‖` short) + a linear `ct_family`, in ZK. `None`
/// on rejection. The witness is never revealed.
#[allow(clippy::too_many_arguments)]
pub fn prove_base_general_zk(
    a: &PolyMatrix,
    ck1: &RingCommitKey,
    s: &[PolyVec],
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta: u64,
    label: &[u8],
    seed: u64,
) -> Option<GeneralBaseZkProof> {
    let r = s.len();
    let n = s[0].len();
    let lambda = ck1.a1.cols;
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let phi = dense_phi(&stmt.linear, r, n);
    // Garbage (challenge-independent).
    let g: Vec<Poly> = (0..r).flat_map(|i| (i..r).map(move |j| (i, j))).map(|(i, j)| dot(&s[i], &s[j])).collect();
    let hfull: Vec<Poly> = (0..r).flat_map(|i| (0..r).map(move |j| (i, j))).map(|(i, j)| dot(&phi[i], &s[j])).collect();
    let gc: Vec<Poly> = (0..r).flat_map(|i| (0..r).map(move |j| (i, j))).map(|(i, j)| conj_dot(&s[i], &s[j])).collect();
    let jl_seed = fs_jl_seed(&t);
    let p = jl_project(s, jl_seed);
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (phi_ct, p_ct) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&phi_ct[i]);
        }
        cap_p = (cap_p + p_ct as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    let hhat: Vec<Poly> = (0..r).flat_map(|i| (0..r).map(move |j| (i, j))).map(|(i, j)| conj_dot(&cap_phi[i], &s[j])).collect();
    let mut s_h = Poly::zero();
    for i in 0..r {
        s_h = s_h.add(&hhat[i * r + i]);
    }
    let shift = (r as i64) * (CHALLENGE_WEIGHT_TAU as i64) * (beta as i64 + 1);
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;

    for attempt in 0..4000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x2D_51C7));
        let w = PolyVec::sample_uniform_pm(n, BASE_ZK_MASK, &mut prg);
        let t_w = a.matvec(&w);
        let f = dot(&w, &w);
        let e: Vec<Poly> = (0..r).map(|i| dot(&w, &s[i])).collect();
        let e2: Vec<Poly> = (0..r).map(|i| dot(&phi[i], &w)).collect();
        let mh: Vec<Poly> = (0..r).map(|i| conj_dot(&cap_phi[i], &w)).collect();
        let fc = conj_dot(&w, &w);
        let ecl: Vec<Poly> = (0..r).map(|j| conj_dot(&w, &s[j])).collect();
        let ecr: Vec<Poly> = (0..r).map(|i| conj_dot(&s[i], &w)).collect();
        let one = |m: &Poly, rr: &PolyVec| ck1.commit(&PolyVec(vec![m.clone()]), rr);
        let r_f = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let r_fc = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let commit_list = |vals: &[Poly], prg: &mut SplitMix64| -> (Vec<PolyVec>, Vec<RingCommitment>) {
            let mut rs = Vec::new();
            let mut cs = Vec::new();
            for v in vals {
                let rr = PolyVec::sample_short(lambda, SECRET_NORM_ETA, prg);
                cs.push(one(v, &rr));
                rs.push(rr);
            }
            (rs, cs)
        };
        let (r_e, c_e) = commit_list(&e, &mut prg);
        let (r_e2, c_e2) = commit_list(&e2, &mut prg);
        let (r_g, c_g) = commit_list(&g, &mut prg);
        let (r_h, c_h) = commit_list(&hfull, &mut prg);
        let (r_mh, c_mh) = commit_list(&mh, &mut prg);
        let (r_hh, c_hh) = commit_list(&hhat, &mut prg);
        let (r_ecl, c_ecl) = commit_list(&ecl, &mut prg);
        let (r_ecr, c_ecr) = commit_list(&ecr, &mut prg);
        let (r_gc, c_gc) = commit_list(&gc, &mut prg);
        let c_f = one(&f, &r_f);
        let c_fc = one(&fc, &r_fc);
        let nu = PolyVec::sample_uniform_pm(1, BASE_ZK_MASK, &mut prg).0[0].clone();
        let r_nu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let r_ctnu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let c_nu = one(&nu, &r_nu);
        let c_ctnu = one(&const_poly(nu.c[0]), &r_ctnu);
        let commits: Vec<&RingCommitment> = std::iter::once(&c_f)
            .chain(&c_e).chain(&c_g).chain(&c_e2).chain(&c_h).chain(&c_mh).chain(&c_hh)
            .chain(std::iter::once(&c_nu)).chain(std::iter::once(&c_fc)).chain(&c_ecl).chain(&c_ecr).chain(&c_gc)
            .collect();
        let c = general_zk_challenges(label, stmt, ct_family, &t, &t_w, &commits, r);
        drop(commits);

        let mut zp = w.clone();
        for i in 0..r {
            zp = zp.add(&s[i].mul_poly(&c[i]));
        }
        if zp.inf_norm() > bound {
            continue;
        }
        // Quadratic (binds g_ij = ⟨sᵢ,sⱼ⟩).
        let mut z_gq = r_f.clone();
        for i in 0..r {
            z_gq = z_gq.add(&r_e[i].mul_poly(&c[i].scalar_mul(2)));
        }
        for i in 0..r {
            for j in i..r {
                let coeff = if i == j { c[i].mul_ntt(&c[i]) } else { c[i].mul_ntt(&c[j]).scalar_mul(2) };
                z_gq = z_gq.add(&r_g[tri_idx(i, j, r)].mul_poly(&coeff));
            }
        }
        // Linear (binds h_ij = ⟨φᵢ,sⱼ⟩).
        let mut z_gl = PolyVec::zero(lambda);
        for i in 0..r {
            z_gl = z_gl.add(&r_e2[i].mul_poly(&c[i]));
            for j in 0..r {
                z_gl = z_gl.add(&r_h[i * r + j].mul_poly(&c[i].mul_ntt(&c[j])));
            }
        }
        // Conjugated quadratic (binds ĝc_ij = conj_dot(sᵢ,sⱼ)): conj_dot(zp,zp) =
        //   fc + Σ cⱼ·ecl_j + Σ σ(cᵢ)·ecr_i + Σ σ(cᵢ)cⱼ·ĝc_ij.
        let mut z_gc = r_fc.clone();
        for j in 0..r {
            z_gc = z_gc.add(&r_ecl[j].mul_poly(&c[j]));
        }
        for i in 0..r {
            let sci = c[i].conjugate();
            z_gc = z_gc.add(&r_ecr[i].mul_poly(&sci));
            for j in 0..r {
                z_gc = z_gc.add(&r_gc[i * r + j].mul_poly(&sci.mul_ntt(&c[j])));
            }
        }
        // Statement: Σ a_ij·g[ij] + Σ â_ij·ĝc[ij] + Σ h_ii = b.
        let mut z_gs = PolyVec::zero(lambda);
        for (i, j, a_ij) in &stmt.terms {
            z_gs = z_gs.add(&r_g[tri_idx(*i, *j, r)].mul_poly(a_ij));
        }
        for (i, j, a_ij) in &stmt.conj_terms {
            z_gs = z_gs.add(&r_gc[*i * r + *j].mul_poly(a_ij));
        }
        for i in 0..r {
            z_gs = z_gs.add(&r_h[i * r + i]);
        }
        // JL/ct whole-ring binding randomness.
        let mut z_hbind = PolyVec::zero(lambda);
        for i in 0..r {
            let sci = c[i].conjugate();
            z_hbind = z_hbind.add(&r_mh[i].mul_poly(&sci));
            for j in 0..r {
                z_hbind = z_hbind.add(&r_hh[i * r + j].mul_poly(&sci.mul_ntt(&c[j])));
            }
        }
        let zeta = nu.add(&s_h);
        let mut r_zeta = r_nu.clone();
        for i in 0..r {
            r_zeta = r_zeta.add(&r_hh[i * r + i]);
        }
        return Some(GeneralBaseZkProof {
            t, t_w, c_f, c_e, c_g, c_e2, c_h, zp, z_gq, z_gl, z_gs, p,
            c_mh, c_hh, z_hbind, c_nu, c_ctnu, zeta, r_zeta, r_ctnu,
            c_fc, c_ecl, c_ecr, c_gc, z_gc,
        });
    }
    let _ = (cap_p, s_h);
    None
}

/// Verify a [`GeneralBaseZkProof`] against the general `stmt`, the `ct_family`,
/// and the JL ℓ₂ bound `beta_l2`.
#[allow(clippy::too_many_arguments)]
pub fn verify_base_general_zk(
    a: &PolyMatrix,
    ck1: &RingCommitKey,
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta_l2: u128,
    pf: &GeneralBaseZkProof,
    label: &[u8],
) -> bool {
    let r = pf.t.len();
    let n = a.cols;
    let tri = r * (r + 1) / 2;
    if pf.c_e.len() != r || pf.c_e2.len() != r || pf.c_h.len() != r * r || pf.c_g.len() != tri {
        return false;
    }
    if pf.c_mh.len() != r || pf.c_hh.len() != r * r || pf.c_ecl.len() != r || pf.c_ecr.len() != r || pf.c_gc.len() != r * r {
        return false;
    }
    if pf.zp.len() != n || pf.t.iter().any(|ti| ti.len() != a.rows) {
        return false;
    }
    if pf.zp.inf_norm() > BASE_ZK_MASK as u64 {
        return false;
    }
    let phi = dense_phi(&stmt.linear, r, n);
    let commits: Vec<&RingCommitment> = std::iter::once(&pf.c_f)
        .chain(&pf.c_e).chain(&pf.c_g).chain(&pf.c_e2).chain(&pf.c_h).chain(&pf.c_mh).chain(&pf.c_hh)
        .chain(std::iter::once(&pf.c_nu)).chain(std::iter::once(&pf.c_fc)).chain(&pf.c_ecl).chain(&pf.c_ecr).chain(&pf.c_gc)
        .collect();
    let c = general_zk_challenges(label, stmt, ct_family, &pf.t, &pf.t_w, &commits, r);
    drop(commits);

    // (1) zp opens.
    let mut fold_t = pf.t_w.clone();
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if a.matvec(&pf.zp) != fold_t {
        return false;
    }
    // (2) quadratic (binds g).
    let zz = dot(&pf.zp, &pf.zp);
    let mut rhs_q = pf.c_f.clone();
    for i in 0..r {
        rhs_q = rhs_q.add(&ring_scale_commit(&pf.c_e[i], &c[i].scalar_mul(2)));
    }
    for i in 0..r {
        for j in i..r {
            let coeff = if i == j { c[i].mul_ntt(&c[i]) } else { c[i].mul_ntt(&c[j]).scalar_mul(2) };
            rhs_q = rhs_q.add(&ring_scale_commit(&pf.c_g[tri_idx(i, j, r)], &coeff));
        }
    }
    if ck1.commit(&PolyVec(vec![zz]), &pf.z_gq) != rhs_q {
        return false;
    }
    // (2b) linear (binds h).
    let mut lz = Poly::zero();
    for i in 0..r {
        lz = lz.add(&c[i].mul_ntt(&dot(&phi[i], &pf.zp)));
    }
    let mut rhs_l = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for i in 0..r {
        rhs_l = rhs_l.add(&ring_scale_commit(&pf.c_e2[i], &c[i]));
        for j in 0..r {
            rhs_l = rhs_l.add(&ring_scale_commit(&pf.c_h[i * r + j], &c[i].mul_ntt(&c[j])));
        }
    }
    if ck1.commit(&PolyVec(vec![lz]), &pf.z_gl) != rhs_l {
        return false;
    }
    // (2c) conjugated quadratic (binds ĝc = conj_dot(sᵢ,sⱼ)).
    let czz = conj_dot(&pf.zp, &pf.zp);
    let mut rhs_c = pf.c_fc.clone();
    for j in 0..r {
        rhs_c = rhs_c.add(&ring_scale_commit(&pf.c_ecl[j], &c[j]));
    }
    for i in 0..r {
        let sci = c[i].conjugate();
        rhs_c = rhs_c.add(&ring_scale_commit(&pf.c_ecr[i], &sci));
        for j in 0..r {
            rhs_c = rhs_c.add(&ring_scale_commit(&pf.c_gc[i * r + j], &sci.mul_ntt(&c[j])));
        }
    }
    if ck1.commit(&PolyVec(vec![czz]), &pf.z_gc) != rhs_c {
        return false;
    }
    // (3) statement: Σ a_ij·g[ij] + Σ â_ij·ĝc[ij] + Σ h_ii = b.
    let mut rhs_s = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for (i, j, a_ij) in &stmt.terms {
        rhs_s = rhs_s.add(&ring_scale_commit(&pf.c_g[tri_idx(*i, *j, r)], a_ij));
    }
    for (i, j, a_ij) in &stmt.conj_terms {
        if *i >= r || *j >= r {
            return false;
        }
        rhs_s = rhs_s.add(&ring_scale_commit(&pf.c_gc[*i * r + *j], a_ij));
    }
    for i in 0..r {
        rhs_s = rhs_s.add(&pf.c_h[i * r + i]);
    }
    if ck1.commit(&PolyVec(vec![stmt.b.clone()]), &pf.z_gs) != rhs_s {
        return false;
    }
    // (4) JL/ct binding + norm (as in the diagonal base).
    let jl_seed = fs_jl_seed(&pf.t);
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &pf.p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (phi_ct, p_ct) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&phi_ct[i]);
        }
        cap_p = (cap_p + p_ct as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    let mut phi_fold = PolyVec::zero(n);
    for i in 0..r {
        phi_fold = phi_fold.add(&cap_phi[i].mul_poly(&c[i]));
    }
    let hbind_lhs = conj_dot(&phi_fold, &pf.zp);
    let mut rhs_hb = RingCommitment { t1: PolyVec::zero(ck1.a1.rows), t2: PolyVec::zero(ck1.ell) };
    for i in 0..r {
        let sci = c[i].conjugate();
        rhs_hb = rhs_hb.add(&ring_scale_commit(&pf.c_mh[i], &sci));
        for j in 0..r {
            rhs_hb = rhs_hb.add(&ring_scale_commit(&pf.c_hh[i * r + j], &sci.mul_ntt(&c[j])));
        }
    }
    if ck1.commit(&PolyVec(vec![hbind_lhs]), &pf.z_hbind) != rhs_hb {
        return false;
    }
    let mut rhs_z = pf.c_nu.clone();
    for i in 0..r {
        rhs_z = rhs_z.add(&pf.c_hh[i * r + i]);
    }
    if ck1.commit(&PolyVec(vec![pf.zeta.clone()]), &pf.r_zeta) != rhs_z {
        return false;
    }
    let q = Poly::Q as i128;
    let ctnu = ((pf.zeta.c[0] as i128 - cap_p as i128).rem_euclid(q)) as u64;
    if ck1.commit(&PolyVec(vec![const_poly(ctnu)]), &pf.r_ctnu) != pf.c_ctnu {
        return false;
    }
    jl_norm_ok(&pf.p, beta_l2)
}

// ─────────────────────────────────────────────────────────────────────────
// Step 5d — BATCHED general ZK terminal (garbage in ONE wide commitment).
//
// The general terminal commits ~K garbage values as K separate ell-1 commits,
// each paying the commitment rank κ. This batches them into ONE wide commitment
// `u_G = ck_G.commit(G; r_G)` (pay κ once) and proves every challenge-weighted
// check `⟨coeff, G⟩ = target` via a masked LINEAR opening on a SHARED masked
// `z_G = y_G + x·G`. Same soundness (each check binds by the linear opening; the
// witness `zp` opening + JL norm are unchanged), fewer commitment polys. Feasible
// + smaller — see `batched_garbage_commitment_is_viable`. Kept separate from the
// validated `prove_base_general_zk` (no regression).
// ─────────────────────────────────────────────────────────────────────────

/// Flat offsets of every garbage region in the batched vector `G` (dim `k`).
/// Independent Fiat–Shamir aggregation rounds for the ct/JL family. Each round
/// collapses the family under fresh weights; a violated constraint survives all
/// rounds only with prob `≤ (1/q)^KR`. With `q < 2^36`, `KR = 4 ⇒ ≈ 2^-144 ≥ 128-bit`
/// (a single round is `≈ 2^-36`, grindable). Only the JL-cross garbage (`mh`, `hh`)
/// and the ct-statement checks are replicated per round; the witness, the base
/// quadratic garbage (`g`, `gc`, `h`), and the JL projection `p` are shared.
pub const CT_AGG_ROUNDS: usize = 4;

struct GarbageLayout {
    r: usize,
    off_f: usize,
    off_fc: usize,
    off_e: usize,
    off_e2: usize,
    off_ecl: usize,
    off_ecr: usize,
    off_mh: usize,
    off_g: usize,
    off_h: usize,
    off_gc: usize,
    off_hh: usize,
    k: usize,
}
impl GarbageLayout {
    fn new(r: usize) -> Self {
        Self::new_k(r, 1)
    }
    /// Layout with `kr` independent ct/JL aggregation rounds (`mh`: `kr·r`, `hh`:
    /// `kr·r²`). `kr = 1` reproduces the single-round layout exactly.
    fn new_k(r: usize, kr: usize) -> Self {
        let tri = r * (r + 1) / 2;
        let off_e = 2;
        let off_e2 = off_e + r;
        let off_ecl = off_e2 + r;
        let off_ecr = off_ecl + r;
        let off_mh = off_ecr + r;
        let off_g = off_mh + kr * r; // mh region holds KR rounds
        let off_h = off_g + tri;
        let off_gc = off_h + r * r;
        let off_hh = off_gc + r * r;
        GarbageLayout { r, off_f: 0, off_fc: 1, off_e, off_e2, off_ecl, off_ecr, off_mh, off_g, off_h, off_gc, off_hh, k: off_hh + kr * r * r }
    }
    fn g(&self, i: usize, j: usize) -> usize { self.off_g + tri_idx(i, j, self.r) }
    fn h(&self, i: usize, j: usize) -> usize { self.off_h + i * self.r + j }
    fn gc(&self, i: usize, j: usize) -> usize { self.off_gc + i * self.r + j }
    /// JL-cross diagonal-mask for round `l`, index `i`.
    fn mh(&self, l: usize, i: usize) -> usize { self.off_mh + l * self.r + i }
    /// JL-cross `conj_dot(cap_phi^(l)_i, s_j)` for round `l`.
    fn hh_k(&self, l: usize, i: usize, j: usize) -> usize { self.off_hh + l * self.r * self.r + i * self.r + j }
    /// Round-0 `hh` (single-round callers).
    fn hh(&self, i: usize, j: usize) -> usize { self.hh_k(0, i, j) }
}

/// The 5 public-target checks as `(coeff_vector, target)` pairs on the shared
/// garbage `G` (dim `k`). Built IDENTICALLY by prover + verifier (from `c`, the
/// statement, `φ`, the JL aggregate `Φ`, and the witness opening `zp`).
fn batched_checks(
    lay: &GarbageLayout,
    c: &[Poly],
    stmt: &QuadConstraint,
    phi: &[PolyVec],
    cap_phis: &[Vec<PolyVec>], // one aggregated functional per ct/JL aggregation round
    zp: &PolyVec,
) -> Vec<(PolyVec, Poly)> {
    let r = lay.r;
    let mk = || PolyVec::zero(lay.k);
    let mut out = Vec::new();
    // QUAD: ⟨coeff,G⟩ = f + Σ2cᵢ·e_i + Σκ_ij·g_ij = ⟨zp,zp⟩.
    let mut q = mk();
    q.0[lay.off_f] = Poly::one();
    for i in 0..r {
        q.0[lay.off_e + i] = c[i].scalar_mul(2);
        for j in i..r {
            q.0[lay.g(i, j)] = if i == j { c[i].mul_ntt(&c[i]) } else { c[i].mul_ntt(&c[j]).scalar_mul(2) };
        }
    }
    out.push((q, dot(zp, zp)));
    // LIN: Σcᵢ·e2_i + Σcᵢcⱼ·h_ij = Σcᵢ⟨φᵢ,zp⟩.
    let mut l = mk();
    let mut lt = Poly::zero();
    for i in 0..r {
        l.0[lay.off_e2 + i] = c[i].clone();
        for j in 0..r {
            l.0[lay.h(i, j)] = c[i].mul_ntt(&c[j]);
        }
        lt = lt.add(&c[i].mul_ntt(&dot(&phi[i], zp)));
    }
    out.push((l, lt));
    // CONJ: fc + Σcⱼ·ecl_j + Σσ(cᵢ)·ecr_i + Σσ(cᵢ)cⱼ·gc_ij = conj_dot(zp,zp).
    let mut cj = mk();
    cj.0[lay.off_fc] = Poly::one();
    for j in 0..r {
        cj.0[lay.off_ecl + j] = c[j].clone();
    }
    for i in 0..r {
        let sci = c[i].conjugate();
        cj.0[lay.off_ecr + i] = sci.clone();
        for j in 0..r {
            cj.0[lay.gc(i, j)] = sci.mul_ntt(&c[j]);
        }
    }
    out.push((cj, conj_dot(zp, zp)));
    // JL: for each round l, Σσ(cᵢ)·mh^(l)_i + Σσ(cᵢ)cⱼ·hh^(l)_ij = conj_dot(Φ^(l)_fold, zp).
    for (l, cap_phi) in cap_phis.iter().enumerate() {
        let mut jl = mk();
        let mut pf_fold = PolyVec::zero(zp.len());
        for i in 0..r {
            let sci = c[i].conjugate();
            jl.0[lay.mh(l, i)] = sci.clone();
            for j in 0..r {
                jl.0[lay.hh_k(l, i, j)] = sci.mul_ntt(&c[j]);
            }
            pf_fold = pf_fold.add(&cap_phi[i].mul_poly(&c[i]));
        }
        out.push((jl, conj_dot(&pf_fold, zp)));
    }
    // STMT: Σa_ij·g_ij + Σâ_ij·gc_ij + Σh_ii = b.
    let mut st = mk();
    for (i, j, a) in &stmt.terms {
        let p = lay.g(*i, *j);
        st.0[p] = st.0[p].add(a);
    }
    for (i, j, a) in &stmt.conj_terms {
        let p = lay.gc(*i, *j);
        st.0[p] = st.0[p].add(a);
    }
    for i in 0..r {
        let p = lay.h(i, i);
        st.0[p] = st.0[p].add(&Poly::one());
    }
    out.push((st, stmt.b.clone()));
    out
}

/// A batched general ZK terminal proof (garbage in one wide commitment).
#[derive(Clone)]
pub struct BatchedGeneralZkProof {
    pub t: Vec<PolyVec>,
    pub t_w: PolyVec,
    pub zp: PolyVec,               // witness opening w + Σcᵢsᵢ
    pub u_g: RingCommitment,       // ONE wide garbage commitment
    pub c_y: RingCommitment,       // garbage mask commitment
    pub z_g: PolyVec,              // y_G + x·G  (shared garbage opening, dim k)
    pub r_zg: PolyVec,             // r_y + x·r_G
    pub c_t: Vec<RingCommitment>,  // per-check Commit(⟨coeff,y_G⟩)
    pub r_t: Vec<PolyVec>,         // per-check opening randomness
    pub p: [i128; 256],
    // ct-statement (Σ ct(ĥ_ii) = P):
    pub c_nu: RingCommitment,
    pub c_ctnu: RingCommitment,
    pub c_tct: RingCommitment,     // Commit(⟨coeff_ct, y_G⟩)
    pub zeta: Poly,                // ν + S_h,  S_h = Σ ĥ_ii = ⟨coeff_ct, G⟩
    pub z_ctr: PolyVec,            // r_tct − x·r_nu
    pub r_ctnu: PolyVec,
}

/// Fold challenges (r weight-τ ring) for the batched terminal, FS-bound to the
/// statement, ct-family, witness commitments, and the ONE garbage commitment.
fn batched_fold_challenges(
    label: &[u8],
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    t: &[PolyVec],
    t_w: &PolyVec,
    u_g: &RingCommitment,
    c_y: &RingCommitment,
    r: usize,
) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/batched-zk/fold/v1");
    h.update(label);
    let ap = |h: &mut Sha256, p: &Poly| {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    };
    for (i, j, a) in stmt.terms.iter().chain(&stmt.conj_terms) {
        h.update((*i as u64).to_le_bytes());
        h.update((*j as u64).to_le_bytes());
        ap(&mut h, a);
    }
    for (i, phi) in &stmt.linear {
        h.update((*i as u64).to_le_bytes());
        for pp in &phi.0 {
            ap(&mut h, pp);
        }
    }
    ap(&mut h, &stmt.b);
    for con in ct_family {
        h.update(con.target.to_le_bytes());
    }
    for ti in t {
        for pp in &ti.0 {
            ap(&mut h, pp);
        }
    }
    for pp in &t_w.0 {
        ap(&mut h, pp);
    }
    absorb_commit(&mut h, u_g);
    absorb_commit(&mut h, c_y);
    let mut prg = HashPrg::from_digest(&h.finalize());
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// The scalar linear-opening challenge `x` (nonzero), FS-bound to the per-check
/// garbage-value commitments + the ct-statement commitments (all fixed before x).
fn batched_open_challenge(c_t: &[RingCommitment], c_nu: &RingCommitment, c_tct: &RingCommitment, c_ctnu: &RingCommitment, zeta: &Poly) -> i64 {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/batched-zk/open/v1");
    for c in c_t.iter().chain([c_nu, c_tct, c_ctnu]) {
        absorb_commit(&mut h, c);
    }
    for &x in &zeta.c {
        h.update(x.to_le_bytes());
    }
    let d = h.finalize();
    1 + (u64::from_le_bytes(d[..8].try_into().unwrap()) % (1u64 << 12)) as i64
}

/// Prove a general statement (off-diagonal + conjugated + linear) + ct-family + JL
/// norm in ZK, with the garbage BATCHED into one wide commitment `ck_g` (ell = k).
/// `None` on rejection. Witness-free (see [`prove_base_general_zk`] for the shape).
#[allow(clippy::too_many_arguments)]
pub fn prove_base_general_zk_batched(
    a: &PolyMatrix,
    ck_g: &RingCommitKey,
    ck1: &RingCommitKey,
    s: &[PolyVec],
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta: u64,
    label: &[u8],
    seed: u64,
) -> Option<BatchedGeneralZkProof> {
    let r = s.len();
    let n = s[0].len();
    let lay = GarbageLayout::new(r);
    debug_assert_eq!(ck_g.ell, lay.k, "ck_g must commit dim k");
    let lambda = ck1.a1.cols;
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let phi = dense_phi(&stmt.linear, r, n);
    let jl_seed = fs_jl_seed(&t);
    let p = jl_project(s, jl_seed);
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (pc, pp) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&pc[i]);
        }
        cap_p = (cap_p + pp as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    let shift = (r as i64) * (CHALLENGE_WEIGHT_TAU as i64) * (beta as i64 + 1);
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;

    for attempt in 0..4000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x2D_51C7));
        let w = PolyVec::sample_uniform_pm(n, BASE_ZK_MASK, &mut prg);
        let t_w = a.matvec(&w);
        // Assemble the full garbage vector G (dim k).
        let mut gv = vec![Poly::zero(); lay.k];
        gv[lay.off_f] = dot(&w, &w);
        gv[lay.off_fc] = conj_dot(&w, &w);
        for i in 0..r {
            gv[lay.off_e + i] = dot(&w, &s[i]);
            gv[lay.off_e2 + i] = dot(&phi[i], &w);
            gv[lay.off_ecl + i] = conj_dot(&w, &s[i]);
            gv[lay.off_ecr + i] = conj_dot(&s[i], &w);
            gv[lay.off_mh + i] = conj_dot(&cap_phi[i], &w);
            for j in i..r {
                gv[lay.g(i, j)] = dot(&s[i], &s[j]);
            }
            for j in 0..r {
                gv[lay.h(i, j)] = dot(&phi[i], &s[j]);
                gv[lay.gc(i, j)] = conj_dot(&s[i], &s[j]);
                gv[lay.hh(i, j)] = conj_dot(&cap_phi[i], &s[j]);
            }
        }
        let g_pv = PolyVec(gv);
        let r_g = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let u_g = ck_g.commit(&g_pv, &r_g);
        let y_g = PolyVec::sample_uniform_pm(lay.k, BASE_ZK_MASK, &mut prg);
        let r_y = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let c_y = ck_g.commit(&y_g, &r_y);

        let c = batched_fold_challenges(label, stmt, ct_family, &t, &t_w, &u_g, &c_y, r);
        let mut zp = w.clone();
        for i in 0..r {
            zp = zp.add(&s[i].mul_poly(&c[i]));
        }
        if zp.inf_norm() > bound {
            continue;
        }
        let checks = batched_checks(&lay, &c, stmt, &phi, std::slice::from_ref(&cap_phi), &zp);
        let (mut c_t, mut r_t) = (Vec::new(), Vec::new());
        for (coeff, _) in &checks {
            let tval = dot(coeff, &y_g);
            let rr = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            c_t.push(ck1.commit(&PolyVec(vec![tval]), &rr));
            r_t.push(rr);
        }
        // ct-statement: S_h = Σ ĥ_ii = ⟨coeff_ct, G⟩.
        let mut coeff_ct = PolyVec::zero(lay.k);
        for i in 0..r {
            coeff_ct.0[lay.hh(i, i)] = Poly::one();
        }
        let s_h = dot(&coeff_ct, &g_pv);
        let t_ct = dot(&coeff_ct, &y_g);
        let nu = PolyVec::sample_uniform_pm(1, BASE_ZK_MASK, &mut prg).0[0].clone();
        let r_nu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let r_tct = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let r_ctnu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let c_nu = ck1.commit(&PolyVec(vec![nu.clone()]), &r_nu);
        let c_tct = ck1.commit(&PolyVec(vec![t_ct]), &r_tct);
        let c_ctnu = ck1.commit(&PolyVec(vec![const_poly(nu.c[0])]), &r_ctnu);
        let zeta = nu.add(&s_h);

        let x = batched_open_challenge(&c_t, &c_nu, &c_tct, &c_ctnu, &zeta);
        let z_g = y_g.add(&g_pv.scalar_mul(x));
        let r_zg = r_y.add(&r_g.scalar_mul(x));
        let z_ctr = r_tct.sub(&r_nu.scalar_mul(x));
        return Some(BatchedGeneralZkProof {
            t, t_w, zp, u_g, c_y, z_g, r_zg, c_t, r_t, p, c_nu, c_ctnu, c_tct, zeta, z_ctr, r_ctnu,
        });
    }
    let _ = cap_p;
    None
}

/// Verify a [`BatchedGeneralZkProof`].
#[allow(clippy::too_many_arguments)]
pub fn verify_base_general_zk_batched(
    a: &PolyMatrix,
    ck_g: &RingCommitKey,
    ck1: &RingCommitKey,
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta_l2: u128,
    pf: &BatchedGeneralZkProof,
    label: &[u8],
) -> bool {
    let r = pf.t.len();
    let n = a.cols;
    let lay = GarbageLayout::new(r);
    if pf.z_g.len() != lay.k || pf.zp.len() != n || pf.t.iter().any(|ti| ti.len() != a.rows) {
        return false;
    }
    if pf.zp.inf_norm() > BASE_ZK_MASK as u64 {
        return false;
    }
    let phi = dense_phi(&stmt.linear, r, n);
    let jl_seed = fs_jl_seed(&pf.t);
    let (mut cap_phi, p_jl) = jl_aggregate(jl_seed, r, n, &pf.p);
    let q_u = Poly::Q as u128;
    let mut cap_p = p_jl as u128;
    if !ct_family.is_empty() {
        let (pc, pp) = ct_family_aggregate(ct_family, r, n, &jl_seed.to_le_bytes());
        for i in 0..r {
            cap_phi[i] = cap_phi[i].add(&pc[i]);
        }
        cap_p = (cap_p + pp as u128) % q_u;
    }
    let cap_p = cap_p as u64;
    let c = batched_fold_challenges(label, stmt, ct_family, &pf.t, &pf.t_w, &pf.u_g, &pf.c_y, r);
    // (1) witness opening.
    let mut fold_t = pf.t_w.clone();
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if a.matvec(&pf.zp) != fold_t {
        return false;
    }
    let checks = batched_checks(&lay, &c, stmt, &phi, std::slice::from_ref(&cap_phi), &pf.zp);
    if pf.c_t.len() != checks.len() || pf.r_t.len() != checks.len() {
        return false;
    }
    let x = batched_open_challenge(&pf.c_t, &pf.c_nu, &pf.c_tct, &pf.c_ctnu, &pf.zeta);
    // (2) shared garbage opening binds z_G to the committed G.
    if ck_g.commit(&pf.z_g, &pf.r_zg) != pf.c_y.add(&scalar_scale_commit(&pf.u_g, x)) {
        return false;
    }
    // (3) each check: commit(⟨coeff,z_G⟩ − x·target; r_t) == c_t.
    for (idx, (coeff, target)) in checks.iter().enumerate() {
        let val = dot(coeff, &pf.z_g).sub(&target.scalar_mul(x));
        if ck1.commit(&PolyVec(vec![val]), &pf.r_t[idx]) != pf.c_t[idx] {
            return false;
        }
    }
    // (4) ct-statement: ⟨coeff_ct,z_G⟩ − x·ζ opens (via z_ctr) to c_tct − x·c_nu,
    //     and ct(ζ) − P = ct(ν) pinned by c_ctnu ⇒ Σ ct(ĥ_ii) = P.
    let mut coeff_ct = PolyVec::zero(lay.k);
    for i in 0..r {
        coeff_ct.0[lay.hh(i, i)] = Poly::one();
    }
    let vct = dot(&coeff_ct, &pf.z_g).sub(&pf.zeta.scalar_mul(x));
    let rhs_ct = pf.c_tct.add(&scalar_scale_commit(&pf.c_nu, -x));
    if ck1.commit(&PolyVec(vec![vct]), &pf.z_ctr) != rhs_ct {
        return false;
    }
    let q = Poly::Q as i128;
    let ctnu = ((pf.zeta.c[0] as i128 - cap_p as i128).rem_euclid(q)) as u64;
    if ck1.commit(&PolyVec(vec![const_poly(ctnu)]), &pf.r_ctnu) != pf.c_ctnu {
        return false;
    }
    jl_norm_ok(&pf.p, beta_l2)
}

// ─────────────────────────────────────────────────────────────────────────
// Step 5e — IPA-LITE general ZK terminal (randomness opening, no dim-k z_G).
//
// The batched terminal still reveals the dim-k masked garbage `z_G` + a dim-k
// mask commitment `c_y`. Because BDLOP adds the message linearly
// (`t2 = A2·r_G + G`), every check `⟨coeff,G⟩ = target` reduces to
// `⟨ψ, r_G⟩ = ⟨coeff,t2⟩ − target` with `ψ = A2ᵀ·coeff` — over the SHORT
// randomness `r_G` (dim λ ≪ k). So a single masked opening of `r_G` (dim λ)
// replaces `z_G` (dim k) entirely: reveal `z_r = y_r + x·r_G` + `c_yr = A1·y_r`
// (κ), bind `A1·z_r = c_yr + x·t1`, and per check `⟨ψ,z_r⟩ − x·rhs` opens to
// `Commit(⟨ψ,y_r⟩)`. Confirmed 16× smaller opening — see
// `randomness_opening_avoids_revealing_garbage`.
// ─────────────────────────────────────────────────────────────────────────

/// `ψ = A2ᵀ·coeff` (dim λ): the reduced coefficient vector over the randomness.
fn a2t_mul(ck_g: &RingCommitKey, coeff: &PolyVec) -> PolyVec {
    let lambda = ck_g.a1.cols;
    let mut psi = PolyVec::zero(lambda);
    for (i, ci) in coeff.0.iter().enumerate() {
        if ci.inf_norm() == 0 {
            continue;
        }
        for (j, pj) in psi.0.iter_mut().enumerate() {
            *pj = pj.add(&ci.mul_ntt(&ck_g.a2.m[i][j]));
        }
    }
    psi
}

/// IPA-lite general ZK terminal proof (randomness opening — no dim-k `z_G`).
#[derive(Clone)]
pub struct IpaGeneralZkProof {
    pub t: Vec<PolyVec>,
    pub t_w: PolyVec,
    pub zp: PolyVec,
    pub u_g: RingCommitment,       // wide garbage commitment
    pub c_yr: PolyVec,            // A1·y_r (κ) — randomness mask commitment
    pub z_r: PolyVec,             // y_r + x·r_G (dim λ) — the shared opening
    pub c_t: Vec<RingCommitment>, // per-check Commit(⟨ψ,y_r⟩)
    pub r_t: Vec<PolyVec>,
    pub p: [i128; 256],
    // ct-statement, ONE per independent aggregation round (K-round amplification):
    pub c_nu: Vec<RingCommitment>,
    pub c_ctnu: Vec<RingCommitment>,
    pub c_tct: Vec<RingCommitment>, // Commit(⟨ψ_ct, y_r⟩)
    pub zeta: Vec<Poly>,            // ν + S_h
    pub z_ctr: Vec<PolyVec>,        // r_tct + x·r_nu
    pub r_ctnu: Vec<PolyVec>,
}

/// The scalar linear-opening challenge for the IPA-lite terminal. Binds the
/// randomness mask, every per-check commitment, and ALL per-round ct-statement
/// commitments + `ζ`s.
fn ipa_open_challenge(
    c_yr: &PolyVec,
    c_t: &[RingCommitment],
    c_nu: &[RingCommitment],
    c_tct: &[RingCommitment],
    c_ctnu: &[RingCommitment],
    zeta: &[Poly],
) -> i64 {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ipa-zk/open/v1");
    for pp in &c_yr.0 {
        for &x in &pp.c {
            h.update(x.to_le_bytes());
        }
    }
    for c in c_t.iter().chain(c_nu).chain(c_tct).chain(c_ctnu) {
        absorb_commit(&mut h, c);
    }
    for z in zeta {
        for &x in &z.c {
            h.update(x.to_le_bytes());
        }
    }
    let d = h.finalize();
    1 + (u64::from_le_bytes(d[..8].try_into().unwrap()) % (1u64 << 12)) as i64
}

/// Prove the general statement + ct-family + JL norm in ZK, with the garbage in
/// one wide commitment and the combinations proven by a masked opening of the
/// SHORT randomness (dim λ), NOT the dim-k `z_G`. `None` on rejection.
#[allow(clippy::too_many_arguments)]
pub fn prove_base_general_zk_ipa(
    a: &PolyMatrix,
    ck_g: &RingCommitKey,
    ck1: &RingCommitKey,
    s: &[PolyVec],
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta: u64,
    label: &[u8],
    seed: u64,
) -> Option<IpaGeneralZkProof> {
    let r = s.len();
    let n = s[0].len();
    let kr = CT_AGG_ROUNDS;
    let lay = GarbageLayout::new_k(r, kr);
    debug_assert_eq!(ck_g.ell, lay.k);
    let lambda = ck1.a1.cols;
    let t: Vec<PolyVec> = s.iter().map(|si| a.matvec(si)).collect();
    let phi = dense_phi(&stmt.linear, r, n);
    let jl_seed = fs_jl_seed(&t);
    let p = jl_project(s, jl_seed);
    // K INDEPENDENT aggregations of the JL rows + ct-family (same projection `p`,
    // fresh weights per round) — a violated ct/JL constraint survives all rounds only
    // with prob ≤ (1/q)^K ⇒ ≈2^-144 for K=4 (vs ≈2^-36 single-round, grindable).
    let (cap_phis, gcws, cap_ps) = ct_jl_aggregate_rounds(jl_seed, r, n, &p, ct_family, kr);
    let shift = (r as i64) * (CHALLENGE_WEIGHT_TAU as i64) * (beta as i64 + 1);
    let bound = (BASE_ZK_MASK - shift.max(1)) as u64;

    for attempt in 0..4000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x2D_51C7));
        let w = PolyVec::sample_uniform_pm(n, BASE_ZK_MASK, &mut prg);
        let t_w = a.matvec(&w);
        let mut gv = vec![Poly::zero(); lay.k];
        gv[lay.off_f] = dot(&w, &w);
        gv[lay.off_fc] = conj_dot(&w, &w);
        for i in 0..r {
            gv[lay.off_e + i] = dot(&w, &s[i]);
            gv[lay.off_e2 + i] = dot(&phi[i], &w);
            gv[lay.off_ecl + i] = conj_dot(&w, &s[i]);
            gv[lay.off_ecr + i] = conj_dot(&s[i], &w);
            for j in i..r {
                gv[lay.g(i, j)] = dot(&s[i], &s[j]);
            }
            for j in 0..r {
                gv[lay.h(i, j)] = dot(&phi[i], &s[j]);
                gv[lay.gc(i, j)] = conj_dot(&s[i], &s[j]);
            }
        }
        // Per-round JL-cross garbage (mh, hh) for each aggregated functional.
        for (l, cap_phi) in cap_phis.iter().enumerate() {
            for i in 0..r {
                gv[lay.mh(l, i)] = conj_dot(&cap_phi[i], &w);
                for j in 0..r {
                    gv[lay.hh_k(l, i, j)] = conj_dot(&cap_phi[i], &s[j]);
                }
            }
        }
        let g_pv = PolyVec(gv);
        let r_g = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let u_g = ck_g.commit(&g_pv, &r_g);

        let c = batched_fold_challenges(label, stmt, ct_family, &t, &t_w, &u_g, &u_g, r);
        let mut zp = w.clone();
        for i in 0..r {
            zp = zp.add(&s[i].mul_poly(&c[i]));
        }
        if zp.inf_norm() > bound {
            continue;
        }
        let checks = batched_checks(&lay, &c, stmt, &phi, &cap_phis, &zp);
        // Randomness mask: c_yr = A1_g·y_r (binds the opening of r_G to u_G.t1).
        let y_r = PolyVec::sample_uniform_pm(lambda, BASE_ZK_MASK, &mut prg);
        let c_yr = ck_g.a1.matvec(&y_r);
        // Per-check reduced ψ + committed ⟨ψ,y_r⟩.
        let (mut c_t, mut r_t) = (Vec::new(), Vec::new());
        for (coeff, _target) in &checks {
            let psi = a2t_mul(ck_g, coeff);
            let rr = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            c_t.push(ck1.commit(&PolyVec(vec![dot(&psi, &y_r)]), &rr));
            r_t.push(rr);
        }
        // ct-statement, ONE per round: S_h^(l) = Σ ĥ^(l)_ii + Σ gcw^(l)·ĝc_ij = cap_p^(l).
        let (mut vc_nu, mut vc_ctnu, mut vc_tct, mut vzeta) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut vz_ctr, mut vr_ctnu, mut psi_cts) = (Vec::new(), Vec::new(), Vec::new());
        for l in 0..kr {
            let mut coeff_ct = PolyVec::zero(lay.k);
            for i in 0..r {
                coeff_ct.0[lay.hh_k(l, i, i)] = Poly::one();
            }
            for i in 0..r {
                for j in 0..r {
                    if gcws[l][i * r + j].inf_norm() != 0 {
                        let p = lay.gc(i, j);
                        coeff_ct.0[p] = coeff_ct.0[p].add(&gcws[l][i * r + j]);
                    }
                }
            }
            let psi_ct = a2t_mul(ck_g, &coeff_ct);
            let t_ct2 = dot(&coeff_ct, &u_g.t2);
            let s_h = t_ct2.sub(&dot(&psi_ct, &r_g));
            let nu = PolyVec::sample_uniform_pm(1, BASE_ZK_MASK, &mut prg).0[0].clone();
            let r_nu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            let r_tct = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            let r_ctnu = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
            vc_nu.push(ck1.commit(&PolyVec(vec![nu.clone()]), &r_nu));
            vc_tct.push(ck1.commit(&PolyVec(vec![dot(&psi_ct, &y_r)]), &r_tct));
            vc_ctnu.push(ck1.commit(&PolyVec(vec![const_poly(nu.c[0])]), &r_ctnu));
            vzeta.push(nu.add(&s_h));
            vr_ctnu.push(r_ctnu);
            psi_cts.push((r_tct, r_nu));
        }

        let x = ipa_open_challenge(&c_yr, &c_t, &vc_nu, &vc_tct, &vc_ctnu, &vzeta);
        let z_r = y_r.add(&r_g.scalar_mul(x));
        for (r_tct, r_nu) in &psi_cts {
            vz_ctr.push(r_tct.add(&r_nu.scalar_mul(x)));
        }
        return Some(IpaGeneralZkProof {
            t, t_w, zp, u_g, c_yr, z_r, c_t, r_t, p,
            c_nu: vc_nu, c_ctnu: vc_ctnu, c_tct: vc_tct, zeta: vzeta, z_ctr: vz_ctr, r_ctnu: vr_ctnu,
        });
    }
    None
}

/// Verify an [`IpaGeneralZkProof`].
#[allow(clippy::too_many_arguments)]
pub fn verify_base_general_zk_ipa(
    a: &PolyMatrix,
    ck_g: &RingCommitKey,
    ck1: &RingCommitKey,
    stmt: &QuadConstraint,
    ct_family: &[CtConstraint],
    beta_l2: u128,
    pf: &IpaGeneralZkProof,
    label: &[u8],
) -> bool {
    let r = pf.t.len();
    let n = a.cols;
    let kr = CT_AGG_ROUNDS;
    let lay = GarbageLayout::new_k(r, kr);
    let lambda = ck1.a1.cols;
    if pf.z_r.len() != lambda || pf.zp.len() != n || pf.t.iter().any(|ti| ti.len() != a.rows) {
        return false;
    }
    if pf.u_g.t2.len() != lay.k || pf.c_yr.len() != ck_g.a1.rows {
        return false;
    }
    // The garbage key must match the layout for the claimed rank `r = pf.t.len()`
    // (`ck_g.ell == garbage_k_kr(r)`). Without this, a proof carrying more `t` entries
    // than the key was sized for would index `ck_g.a2` out of bounds inside `a2t_mul`.
    if ck_g.ell != lay.k {
        return false;
    }
    // Fail-closed: exactly KR ct-statement rounds must be present, and every masked
    // randomness vector opened against `ck1` must have length λ (else `ck1.commit`'s
    // matvec would panic instead of cleanly rejecting).
    if pf.c_nu.len() != kr || pf.c_ctnu.len() != kr || pf.c_tct.len() != kr
        || pf.zeta.len() != kr || pf.z_ctr.len() != kr || pf.r_ctnu.len() != kr
    {
        return false;
    }
    if pf.z_ctr.iter().any(|v| v.len() != lambda) || pf.r_ctnu.iter().any(|v| v.len() != lambda) {
        return false;
    }
    if pf.zp.inf_norm() > BASE_ZK_MASK as u64 {
        return false;
    }
    let phi = dense_phi(&stmt.linear, r, n);
    let jl_seed = fs_jl_seed(&pf.t);
    let (cap_phis, gcws, cap_ps) = ct_jl_aggregate_rounds(jl_seed, r, n, &pf.p, ct_family, kr);
    let c = batched_fold_challenges(label, stmt, ct_family, &pf.t, &pf.t_w, &pf.u_g, &pf.u_g, r);
    // (1) witness opening.
    let mut fold_t = pf.t_w.clone();
    for i in 0..r {
        fold_t = fold_t.add(&pf.t[i].mul_poly(&c[i]));
    }
    if a.matvec(&pf.zp) != fold_t {
        return false;
    }
    let checks = batched_checks(&lay, &c, stmt, &phi, &cap_phis, &pf.zp);
    if pf.c_t.len() != checks.len() || pf.r_t.len() != checks.len() {
        return false;
    }
    if pf.r_t.iter().any(|v| v.len() != lambda) {
        return false;
    }
    let x = ipa_open_challenge(&pf.c_yr, &pf.c_t, &pf.c_nu, &pf.c_tct, &pf.c_ctnu, &pf.zeta);
    // (2) z_r binds to the committed r_G: A1_g·z_r = c_yr + x·t1.
    if ck_g.a1.matvec(&pf.z_r) != pf.c_yr.add(&pf.u_g.t1.scalar_mul(x)) {
        return false;
    }
    // (3) each check: ⟨ψ,z_r⟩ − x·rhs opens to c_t, ψ=A2ᵀcoeff, rhs=⟨coeff,t2⟩−target.
    for (idx, (coeff, target)) in checks.iter().enumerate() {
        let psi = a2t_mul(ck_g, coeff);
        let rhs = dot(coeff, &pf.u_g.t2).sub(target);
        let val = dot(&psi, &pf.z_r).sub(&rhs.scalar_mul(x));
        if ck1.commit(&PolyVec(vec![val]), &pf.r_t[idx]) != pf.c_t[idx] {
            return false;
        }
    }
    // (4) ct-statement — one per aggregation round `l`: with S_h^(l) = ⟨coeff_ct^(l),G⟩
    //   = T_ct2 − ⟨ψ_ct,r_G⟩ and ζ = ν+S_h, bind via z_r and pin ct(S_h^(l)) = cap_p^(l).
    let q = Poly::Q as i128;
    for l in 0..kr {
        let mut coeff_ct = PolyVec::zero(lay.k);
        for i in 0..r {
            coeff_ct.0[lay.hh_k(l, i, i)] = Poly::one();
        }
        for i in 0..r {
            for j in 0..r {
                if gcws[l][i * r + j].inf_norm() != 0 {
                    let p = lay.gc(i, j);
                    coeff_ct.0[p] = coeff_ct.0[p].add(&gcws[l][i * r + j]);
                }
            }
        }
        let psi_ct = a2t_mul(ck_g, &coeff_ct);
        let t_ct2 = dot(&coeff_ct, &pf.u_g.t2);
        let val = dot(&psi_ct, &pf.z_r).sub(&t_ct2.sub(&pf.zeta[l]).scalar_mul(x));
        let rhs_ct = pf.c_tct[l].add(&scalar_scale_commit(&pf.c_nu[l], x));
        if ck1.commit(&PolyVec(vec![val]), &pf.z_ctr[l]) != rhs_ct {
            return false;
        }
        let ctnu = ((pf.zeta[l].c[0] as i128 - cap_ps[l] as i128).rem_euclid(q)) as u64;
        if ck1.commit(&PolyVec(vec![const_poly(ctnu)]), &pf.r_ctnu[l]) != pf.c_ctnu[l] {
            return false;
        }
    }
    jl_norm_ok(&pf.p, beta_l2)
}

/// Flatten conjugated garbage `ĝ` (r×r) to a `PolyVec` for committing.
pub fn flatten_ghat(ghat: &[Vec<Poly>]) -> PolyVec {
    let mut v = Vec::new();
    for row in ghat {
        for p in row {
            v.push(p.clone());
        }
    }
    PolyVec(v)
}

/// ONE level of the conjugation-aware reduction (the multi-level ct layout
/// integration, single level). Commits the conjugated garbage `ĝ_ij =
/// ⟨σ(s_i),s_j⟩` (Ajtai `u1 = A_g·flat(ĝ)`, fixed BEFORE the fold challenge) and
/// folds `z = Σ c_i s_i`. Returns `(u1, z, ĝ)`; `ĝ` becomes child-witness data.
pub fn reduce_ct_level(a_g: &PolyMatrix, s: &[PolyVec], c: &[Poly]) -> (PolyVec, PolyVec, Vec<Vec<Poly>>) {
    let ghat = conj_garbage(s);
    let u1 = a_g.matvec(&flatten_ghat(&ghat));
    let n = s[0].len();
    let mut z = PolyVec::zero(n);
    for (i, si) in s.iter().enumerate() {
        z = z.add(&si.mul_poly(&c[i]));
    }
    (u1, z, ghat)
}

/// Verify one level for a QUADRATIC-only ct-family (covers the packed binary
/// constraint; linear ct-terms use analogous conjugated LINEAR garbage `ĥ_i =
/// ⟨σ(φ_i),s_i⟩`, a mechanical extension). Checks:
///  1. commitment opening `A_g·flat(ĝ) = u1` (binds `ĝ` before `c`),
///  2. whole-ring binding `conj_dot(z,z) = Σ σ(c_i)c_j ĝ_ij` (⇒ every `ĝ_ij`
///     correct, single-shot sound), and
///  3. the LOWERED ct-family `Σ a_ij·ct(ĝ_ij) = target` (linear in the committed
///     `ĝ`).
/// Soundness chain: (1)+(2) ⇒ `ĝ_ij = ⟨σ(s_i),s_j⟩` ⇒ `ct(ĝ_ij) = ⟪s_i,s_j⟫`, so
/// (3) holds iff the PARENT ct-constraint `Σ a_ij⟪s_i,s_j⟫ = target` held.
pub fn verify_ct_level_quadratic(
    a_g: &PolyMatrix,
    ct_family: &[CtConstraint],
    u1: &PolyVec,
    z: &PolyVec,
    ghat: &[Vec<Poly>],
    c: &[Poly],
) -> bool {
    if a_g.matvec(&flatten_ghat(ghat)) != *u1 {
        return false;
    }
    if conj_dot(z, z) != conj_binding_ring(ghat, c) {
        return false;
    }
    let q = Poly::Q as u128;
    for con in ct_family {
        if !con.linear.is_empty() {
            return false; // this level handles quadratic-only ct-constraints
        }
        let mut acc = 0u128;
        for (i, j, a) in &con.terms {
            if *i >= ghat.len() || *j >= ghat.len() {
                return false;
            }
            let a_mod = a.rem_euclid(Poly::Q as i64) as u128;
            acc = (acc + a_mod * ghat[*i][*j].c[0] as u128) % q;
        }
        if acc as u64 != con.target % Poly::Q {
            return false;
        }
    }
    true
}

/// A 2-LEVEL ct fold (n=1 witnesses): the mechanism that carries a ct-constraint
/// through the recursion. Level 0 commits the conjugated QUADRATIC garbage `ĝ`
/// (lowering `Σâ_ij⟪s_i,s_j⟫` to `Σâ_ij·ct(ĝ_ij)`, linear in `ĝ`); level 1 commits
/// the conjugated LINEAR garbage `ĥ` over the child witness `[z⁰ ‖ ĝ]` (lowering
/// that linear ct to `Σ ct(ĥ_ii)`). Each level's garbage is whole-ring bound
/// (single-shot). Proof = both commitments + folds + revealed garbage.
pub struct CtFold2 {
    pub u1_0: PolyVec,
    pub z0: PolyVec,
    pub ghat0: Vec<Vec<Poly>>,
    pub u1_1: PolyVec,
    pub z1: PolyVec,
    pub hhat1: Vec<Vec<Poly>>,
}

fn ctfold_challenge(u1: &PolyVec, r: usize, tag: u64) -> Vec<Poly> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ctfold/v1");
    h.update(tag.to_le_bytes());
    for p in &u1.0 {
        for &x in &p.c {
            h.update(x.to_le_bytes());
        }
    }
    let mut prg = HashPrg::from_digest(&h.finalize());
    (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
}

/// Level-1 witness `w = [z⁰] ‖ ĝ⁰` (each `ĝ⁰_ij` as a rank-1 vector) and the
/// public `φ` selecting the lowered linear ct over it: `φ_{1+i·r+j} = a_ij·e₀`.
fn ctfold_child(z0: &PolyVec, ghat0: &[Vec<Poly>], terms: &[(usize, usize, Poly)], r: usize) -> (Vec<PolyVec>, Vec<PolyVec>) {
    let mut w = vec![z0.clone()];
    for row in ghat0 {
        for g in row {
            w.push(PolyVec(vec![g.clone()]));
        }
    }
    let mut e0 = Poly::zero();
    e0.c[0] = 1;
    let mut phi = vec![PolyVec::zero(1); w.len()];
    for (i, j, a) in terms {
        phi[1 + i * r + j] = PolyVec(vec![a.mul_ntt(&e0)]); // a·e₀
    }
    (w, phi)
}

/// Prove a PURE-QUADRATIC ct-constraint `Σ a_ij⟪s_i,s_j⟫ = τ` via a 2-level fold.
pub fn prove_ct_fold_2(a_g0: &PolyMatrix, a_h1: &PolyMatrix, s: &[PolyVec], terms: &[(usize, usize, Poly)]) -> CtFold2 {
    let r = s.len();
    let ghat0 = conj_garbage(s);
    let u1_0 = a_g0.matvec(&flatten_ghat(&ghat0));
    let c0 = ctfold_challenge(&u1_0, r, 0);
    let n = s[0].len();
    let mut z0 = PolyVec::zero(n);
    for i in 0..r {
        z0 = z0.add(&s[i].mul_poly(&c0[i]));
    }
    let (w, phi) = ctfold_child(&z0, &ghat0, terms, r);
    let hhat1 = conj_linear_garbage(&phi, &w);
    let u1_1 = a_h1.matvec(&flatten_ghat(&hhat1));
    let c1 = ctfold_challenge(&u1_1, w.len(), 1);
    let mut z1 = PolyVec::zero(1);
    for i in 0..w.len() {
        z1 = z1.add(&w[i].mul_poly(&c1[i]));
    }
    CtFold2 { u1_0, z0, ghat0, u1_1, z1, hhat1 }
}

/// Verify a 2-level ct fold against the parent ct-constraint `(terms, τ)`.
pub fn verify_ct_fold_2(
    a_g0: &PolyMatrix,
    a_h1: &PolyMatrix,
    terms: &[(usize, usize, Poly)],
    target: u64,
    r: usize,
    pf: &CtFold2,
) -> bool {
    // (1) Level 0: ĝ committed + whole-ring bound to s via z⁰.
    if a_g0.matvec(&flatten_ghat(&pf.ghat0)) != pf.u1_0 {
        return false;
    }
    let c0 = ctfold_challenge(&pf.u1_0, r, 0);
    if conj_dot(&pf.z0, &pf.z0) != conj_binding_ring(&pf.ghat0, &c0) {
        return false;
    }
    // (2) Rebuild the child witness w = [z⁰‖ĝ⁰] and the public φ.
    let (w, phi) = ctfold_child(&pf.z0, &pf.ghat0, terms, r);
    // (3) Level 1: ĥ committed + whole-ring bound to w via z¹.
    if a_h1.matvec(&flatten_ghat(&pf.hhat1)) != pf.u1_1 {
        return false;
    }
    let c1 = ctfold_challenge(&pf.u1_1, w.len(), 1);
    let cap_phi = folded_phi(&phi, &c1, 1);
    if conj_dot(&cap_phi, &pf.z1) != conj_binding_ring(&pf.hhat1, &c1) {
        return false;
    }
    // (4) Folded ct: Σ_i ct(ĥ¹_ii) = Σ_i ⟪φ_i,w_i⟫ = Σ a_ij⟪s_i,s_j⟫ = τ.
    let q = Poly::Q as u128;
    let mut acc = 0u128;
    for i in 0..pf.hhat1.len() {
        acc = (acc + pf.hhat1[i][i].c[0] as u128) % q;
    }
    acc as u64 == target % Poly::Q
}

/// Sum of squared centered coefficients of a witness (its ℓ₂-norm²).
fn witness_l2_sq(s: &[PolyVec]) -> u128 {
    let mut acc = 0u128;
    for v in s {
        for p in &v.0 {
            for &c in &p.c {
                let cc = centered(c).unsigned_abs() as u128;
                acc += cc * cc;
            }
        }
    }
    acc
}

// ─────────────────────────────────────────────────────────────────────────
// FULL pipeline: `schedule.len()-1` decompose levels + 1 NO-DECOMPOSE last
// level + the NS22 base case. The proof is `[u1_0 … u1_{L-1}] ‖ base_ns22`,
// where the base sends `t + z + O(r) garbage` instead of a full witness.
//
// ⚠️ NOT SOUND AS A REDUCTION: the NS22 base case
// proves ONE ψ-aggregated diagonal equation on a FRESH commitment `a_last`
// with no link to `u1_last`; the per-row commitment-opening checks are
// dissolved into the aggregate, so an accepting proof does NOT imply a witness
// for `family0`. Use `prove/verify_labrador_recursive` (send-witness base,
// which checks the FULL final family + ℓ2) for a defensible reduction. Closing
// this needs a chain-linked base commitment (or a full-family base check) +
// JL/ℓ2 at the base. DO NOT use `_full` on a money path.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct FullProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: BaseNs22Proof,
    pub n_last: usize,
}

impl FullProof {
    /// Compact size (bytes): `u1` uniform (`log q`) + the NS22 base (short parts
    /// entropy-coded, `t` uniform). This is the paper's §5.7 accounting.
    pub fn compact_bytes(&self) -> usize {
        let u1_polys: Vec<Poly> = self.u1s.iter().flat_map(|(a, b)| a.0.iter().chain(b.0.iter()).cloned()).collect();
        group_bytes(&u1_polys, MODULUS_Q_BITS_U32) + self.base.compact_bytes()
    }
}

/// Extract `(a_diag, φ, b)` from an aggregated DIAGONAL constraint.
/// Returns `None` if the aggregate has ANY off-diagonal quadratic term — a
/// runtime rejection (NOT a debug_assert), so a future non-diagonal last level
/// can never silently make `base_ns22` prove a strictly weaker statement.
fn diagonal_parts(agg: &QuadConstraint, r: usize, n: usize) -> Option<(Vec<Poly>, Vec<PolyVec>, Poly)> {
    let mut a_diag = vec![Poly::zero(); r];
    for (i, j, a) in &agg.terms {
        if i != j {
            return None; // off-diagonal quadratic term — not a diagonal relation
        }
        if *i < r {
            a_diag[*i] = a_diag[*i].add(a);
        }
    }
    Some((a_diag, dense_phi(&agg.linear, r, n), agg.b.clone()))
}

pub fn prove_labrador_full(
    family0: &[QuadConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
) -> FullProof {
    assert!(!schedule.is_empty());
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    let last = schedule.len() - 1;
    // Decompose levels 0..last.
    for (level, shape) in schedule.iter().enumerate().take(last) {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let child = reduce_to_child_conj(&a, &b_a, &b_b, &s, &family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        s = child.s;
    }
    // No-decompose last level.
    let shape = &schedule[last];
    let (a, b_a, b_b) = level_matrices(shape, kappa, seed, last);
    let child = reduce_to_child_last(&a, &b_a, &b_b, &s, &family, shape.bits, shape.limbs, shape.nu, shape.mu);
    u1s.push((child.u1_a.clone(), child.u1_b.clone()));
    let (r_l, n_l) = (child.r_prime, child.n_prime);
    // NS22 base case on the residual's diagonal aggregate, BOUND to u1_a_last.
    let agg_l = aggregate_constraints_bound(&child.constraints, &commit_bytes(&child.u1_a));
    let (a_diag, phi, b_l) = diagonal_parts(&agg_l, r_l, n_l).expect("last-level aggregate must be diagonal");
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    let base = prove_base_ns22(&a_last, &child.s, &phi, &a_diag, &b_l, b"labrador-full-base");
    FullProof { u1s, base, n_last: n_l }
}

pub fn verify_labrador_full(
    family0: &[QuadConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &FullProof,
) -> bool {
    if pf.u1s.len() != schedule.len() {
        return false;
    }
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let last = schedule.len() - 1;
    for (level, shape) in schedule.iter().enumerate().take(last) {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
    }
    // No-decompose last level.
    let shape = &schedule[last];
    let (a, b_a, b_b) = level_matrices(shape, kappa, seed, last);
    let (u1_a, u1_b) = &pf.u1s[last];
    if u1_a.len() != kappa || u1_b.len() != kappa {
        return false;
    }
    let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
    let c = fold_challenges_two(u1_a, u1_b, shape.r);
    let family_l = build_last_constraints(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu);
    let r_l = shape.nu + shape.mu;
    let n_l = pf.n_last;
    let agg_l = aggregate_constraints_bound(&family_l, &commit_bytes(u1_a));
    let (a_diag, phi, b_l) = match diagonal_parts(&agg_l, r_l, n_l) { Some(x) => x, None => return false };
    // Residual ‖s_l‖ ≤ max(‖z‖ ≤ r·τ·β_last, ‖v‖ ≤ 2^{bits-1}); the base opening
    // z' = Σcᵢ s_l,ᵢ then has ‖z'‖ ≤ r_l·τ·‖s_l‖.
    let beta_res = ((shape.r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * shape.beta).max(1u64 << (shape.bits - 1));
    let beta_base = (r_l as u64) * (CHALLENGE_WEIGHT_TAU as u64) * beta_res;
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    verify_base_ns22(&a_last, &phi, &a_diag, &b_l, beta_base, &pf.base, b"labrador-full-base")
}

/// The whole pipeline with a ZERO-KNOWLEDGE succinct base: fold (decompose levels
/// + no-decompose last) exactly as [`prove_labrador_full`], then prove the
/// residual diagonal relation with [`prove_base_ns22_zk`] (witness-free: masked
/// amortized opening + committed garbage + JL norm-binding). `None` on rejection.
pub struct FullZkProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: Ns22ZkProof,
    pub n_last: usize,
}

/// The base-witness ∞-norm bound at the last level (same formula prover+verifier).
fn full_base_beta(shape: &LevelShape) -> u64 {
    ((shape.r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * shape.beta).max(1u64 << (shape.bits - 1))
}

pub fn prove_labrador_full_zk(
    family0: &[QuadConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
) -> Option<FullZkProof> {
    assert!(!schedule.is_empty());
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    let last = schedule.len() - 1;
    for (level, shape) in schedule.iter().enumerate().take(last) {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let child = reduce_to_child_conj(&a, &b_a, &b_b, &s, &family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        s = child.s;
    }
    let shape = &schedule[last];
    let (a, b_a, b_b) = level_matrices(shape, kappa, seed, last);
    let child = reduce_to_child_last(&a, &b_a, &b_b, &s, &family, shape.bits, shape.limbs, shape.nu, shape.mu);
    u1s.push((child.u1_a.clone(), child.u1_b.clone()));
    let (r_l, n_l) = (child.r_prime, child.n_prime);
    let agg_l = aggregate_constraints_bound(&child.constraints, &commit_bytes(&child.u1_a));
    let (a_diag, phi, b_l) = diagonal_parts(&agg_l, r_l, n_l)?;
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    let ck1 = RingCommitKey::production(1, seed ^ 0x62A5E);
    let base = prove_base_ns22_zk(&a_last, &ck1, &child.s, &phi, &a_diag, &b_l, &[], full_base_beta(shape), b"labrador-full-zk-base", seed ^ 0x2ED_F0FF)?;
    Some(FullZkProof { u1s, base, n_last: n_l })
}

/// Verify [`prove_labrador_full_zk`]: re-fold, then check the ZK succinct base.
pub fn verify_labrador_full_zk(
    family0: &[QuadConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &FullZkProof,
) -> bool {
    if pf.u1s.len() != schedule.len() {
        return false;
    }
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let last = schedule.len() - 1;
    for (level, shape) in schedule.iter().enumerate().take(last) {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
    }
    let shape = &schedule[last];
    let (a, b_a, b_b) = level_matrices(shape, kappa, seed, last);
    let (u1_a, u1_b) = &pf.u1s[last];
    if u1_a.len() != kappa || u1_b.len() != kappa {
        return false;
    }
    let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
    let c = fold_challenges_two(u1_a, u1_b, shape.r);
    let family_l = build_last_constraints(&a, &b_a, &b_b, &agg, u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu);
    let r_l = shape.nu + shape.mu;
    let n_l = pf.n_last;
    let agg_l = aggregate_constraints_bound(&family_l, &commit_bytes(u1_a));
    let (a_diag, phi, b_l) = match diagonal_parts(&agg_l, r_l, n_l) {
        Some(x) => x,
        None => return false,
    };
    // JL ℓ₂ bound: ‖s_l‖₂ ≤ β_res·√(r_l·n_l·d). Reject if outside the sound JL range.
    let beta_res = full_base_beta(shape) as u128;
    let dim = (r_l * n_l * RING_DEGREE_D) as f64;
    let beta_l2 = ((beta_res as f64) * dim.sqrt() * 2.2).ceil() as u128 + 1;
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    let ck1 = RingCommitKey::production(1, seed ^ 0x62A5E);
    verify_base_ns22_zk(&a_last, &ck1, &phi, &a_diag, &b_l, &[], beta_l2, &pf.base, b"labrador-full-zk-base")
}

/// The FULL money-path-shaped succinct ZK pipeline: fold BOTH families through
/// `reduce_to_child_conj_ct` (whole-ring + ct, Step 3b) every level, then prove
/// the converged general statement (off-diagonal + conjugated + linear) AND the
/// converged linear ct-family with the general ZK terminal. Witness-free. `None`
/// on rejection.
pub struct FullCtZkProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: GeneralBaseZkProof,
    pub n_last: usize,
}

/// Residual base-witness ∞-norm bound for a decompose output: `max(base_z, 2^{bits-1})`.
fn full_ct_base_beta(shape: &LevelShape) -> u64 {
    (shape.base_z as u64).max(1u64 << (shape.bits - 1))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_labrador_full_ct_zk(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    crs_seed: u64,
    rand_seed: u64,
) -> Option<FullCtZkProof> {
    assert!(!schedule.is_empty());
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    for (level, shape) in schedule.iter().enumerate() {
        // CRS (matrices) from the PUBLIC crs_seed — the verifier reproduces it.
        let (a, b_a, b_b) = level_matrices(shape, kappa, crs_seed, level);
        let child = reduce_to_child_conj_ct(&a, &b_a, &b_b, &s, &family, &ct_family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        ct_family = child.ct_constraints;
        s = child.s;
    }
    let (_r_l, n_l) = (s.len(), s[0].len());
    let last_u1a = &u1s.last().unwrap().0;
    // Aggregate the converged whole-ring family to ONE general statement.
    let stmt = aggregate_constraints_bound(&family, &commit_bytes(last_u1a));
    let a_last = PolyMatrix::from_seed(kappa, n_l, crs_seed ^ 0xBA5E);
    let ck1 = RingCommitKey::production(1, crs_seed ^ 0x62A5E);
    let beta = full_ct_base_beta(schedule.last().unwrap());
    // Masks from the FRESH rand_seed (ZK across proofs); CRS from crs_seed.
    let base = prove_base_general_zk(&a_last, &ck1, &s, &stmt, &ct_family, beta, b"labrador-full-ct-zk", rand_seed ^ 0x2ED_C7C7)?;
    Some(FullCtZkProof { u1s, base, n_last: n_l })
}

pub fn verify_labrador_full_ct_zk(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &FullCtZkProof,
) -> bool {
    if pf.u1s.len() != schedule.len() || schedule.is_empty() {
        return false;
    }
    let _ = beta0;
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let ct_agg = if ct_family.is_empty() {
            None
        } else {
            Some(aggregate_ct_constraints(&ct_family, &commit_bytes(u1_a)))
        };
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj_ct(&a, &b_a, &b_b, &agg, ct_agg.as_ref(), u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
        ct_family = match &ct_agg {
            None => Vec::new(),
            Some(ac) => build_child_ct_family(&a, &b_a, &b_b, std::slice::from_ref(ac), shape.r, shape.bits, shape.limbs, shape.nu, shape.mu),
        };
    }
    let last = schedule.last().unwrap();
    let (r_l, n_l) = child_dims(last, kappa);
    if pf.n_last != n_l {
        return false;
    }
    let last_u1a = &pf.u1s.last().unwrap().0;
    let stmt = aggregate_constraints_bound(&family, &commit_bytes(last_u1a));
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    let ck1 = RingCommitKey::production(1, seed ^ 0x62A5E);
    let beta_res = full_ct_base_beta(last) as u128;
    let dim = (r_l * n_l * RING_DEGREE_D) as f64;
    let beta_l2 = ((beta_res as f64) * dim.sqrt() * 2.2).ceil() as u128 + 1;
    verify_base_general_zk(&a_last, &ck1, &stmt, &ct_family, beta_l2, &pf.base, b"labrador-full-ct-zk")
}

/// GarbageLayout `k` with `kr` ct/JL aggregation rounds (mirrors [`GarbageLayout::new_k`]):
/// the `mh` region is `kr·r` and `hh` is `kr·r²`.
fn garbage_k_kr(r: usize, kr: usize) -> usize {
    2 + (4 + kr) * r + r * (r + 1) / 2 + (2 + kr) * r * r
}

/// The full money-path pipeline with the IPA-lite terminal (randomness opening —
/// no dim-k `z_G`). Fold both families via `reduce_to_child_conj_ct`, then prove
/// the converged general statement + ct-family with `prove_base_general_zk_ipa`.
pub struct FullCtZkIpaProof {
    pub u1s: Vec<(PolyVec, PolyVec)>,
    pub base: IpaGeneralZkProof,
    pub n_last: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_labrador_full_ct_zk_ipa(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    s0: &[PolyVec],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    crs_seed: u64,
    rand_seed: u64,
) -> Option<FullCtZkIpaProof> {
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    let mut s: Vec<PolyVec> = s0.to_vec();
    let mut u1s = Vec::new();
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, crs_seed, level);
        let child = reduce_to_child_conj_ct(&a, &b_a, &b_b, &s, &family, &ct_family, shape.beta, shape.bits, shape.limbs, shape.nu, shape.mu, shape.has_conj);
        u1s.push((child.u1_a.clone(), child.u1_b.clone()));
        family = child.constraints;
        ct_family = child.ct_constraints;
        s = child.s;
    }
    let (r_l, n_l) = (s.len(), s[0].len());
    let a_last = PolyMatrix::from_seed(kappa, n_l, crs_seed ^ 0xBA5E);
    let ck_g = RingCommitKey::production(garbage_k_kr(r_l, CT_AGG_ROUNDS), crs_seed ^ 0x67A6);
    let ck1 = RingCommitKey::production(1, crs_seed ^ 0x62A5E);
    // Aggregation bind + residual β: for a folded schedule bind to the last u1_a
    // and β = the decompose residual; for an EMPTY schedule (small witness, no
    // fold) bind to the base's inner commitments and β = β0 (the base witness norm).
    let (bind, beta) = if let Some(last) = schedule.last() {
        (commit_bytes(&u1s.last().unwrap().0), full_ct_base_beta(last))
    } else {
        let t: Vec<PolyVec> = s.iter().map(|si| a_last.matvec(si)).collect();
        (commit_bytes(&flatten_witness(&t)), beta0)
    };
    let stmt = aggregate_constraints_bound(&family, &bind);
    let base = prove_base_general_zk_ipa(&a_last, &ck_g, &ck1, &s, &stmt, &ct_family, beta, b"labrador-full-ct-zk-ipa", rand_seed ^ 0x2ED_C7C8)?;
    Some(FullCtZkIpaProof { u1s, base, n_last: n_l })
}

pub fn verify_labrador_full_ct_zk_ipa(
    family0: &[QuadConstraint],
    ct_family0: &[CtConstraint],
    beta0: u64,
    kappa: usize,
    schedule: &[LevelShape],
    seed: u64,
    pf: &FullCtZkIpaProof,
) -> bool {
    if pf.u1s.len() != schedule.len() {
        return false;
    }
    let mut family: Vec<QuadConstraint> = family0.to_vec();
    let mut ct_family: Vec<CtConstraint> = ct_family0.to_vec();
    for (level, shape) in schedule.iter().enumerate() {
        let (a, b_a, b_b) = level_matrices(shape, kappa, seed, level);
        let (u1_a, u1_b) = &pf.u1s[level];
        if u1_a.len() != kappa || u1_b.len() != kappa {
            return false;
        }
        let agg = aggregate_constraints_bound(&family, &commit_bytes(u1_a));
        let ct_agg = if ct_family.is_empty() {
            None
        } else {
            Some(aggregate_ct_constraints(&ct_family, &commit_bytes(u1_a)))
        };
        let c = fold_challenges_two(u1_a, u1_b, shape.r);
        family = build_child_constraints_conj_ct(&a, &b_a, &b_b, &agg, ct_agg.as_ref(), u1_a, u1_b, &c, shape.bits, shape.limbs, shape.nu, shape.mu, shape.base_z, shape.has_conj);
        ct_family = match &ct_agg {
            None => Vec::new(),
            Some(ac) => build_child_ct_family(&a, &b_a, &b_b, std::slice::from_ref(ac), shape.r, shape.bits, shape.limbs, shape.nu, shape.mu),
        };
    }
    // (r_l, n_l), aggregation bind, and residual β: from the last level if folded,
    // else (empty schedule) DERIVED FROM THE STATEMENT (the constraint families) —
    // never from the attacker's `pf.n_last` / `pf.base.t.len()`. `n_l` drives the JL
    // L2 bound `beta_l2` below; deriving it from the family (not the proof) stops a
    // prover from inflating `n_l` to loosen `jl_norm_ok` (the range/binary norm gate).
    let (r_l, n_l, bind, beta_res) = if let Some(last) = schedule.last() {
        let (r_l, n_l) = child_dims(last, kappa);
        (r_l, n_l, commit_bytes(&pf.u1s.last().unwrap().0), full_ct_base_beta(last) as u128)
    } else {
        let (r0, n0) = statement_dims(&family, &ct_family);
        (r0, n0, commit_bytes(&flatten_witness(&pf.base.t)), beta0 as u128)
    };
    // Bind the proof's declared dims to the statement dims (fail-closed).
    if pf.n_last != n_l || pf.base.t.len() != r_l {
        return false;
    }
    let stmt = aggregate_constraints_bound(&family, &bind);
    let a_last = PolyMatrix::from_seed(kappa, n_l, seed ^ 0xBA5E);
    let ck_g = RingCommitKey::production(garbage_k_kr(r_l, CT_AGG_ROUNDS), seed ^ 0x67A6);
    let ck1 = RingCommitKey::production(1, seed ^ 0x62A5E);
    let dim = (r_l * n_l * RING_DEGREE_D) as f64;
    let beta_l2 = ((beta_res as f64) * dim.sqrt() * 2.2).ceil() as u128 + 1;
    verify_base_general_zk_ipa(&a_last, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf.base, b"labrador-full-ct-zk-ipa")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ETA;

    fn rand_short_vec(n: usize, eta: i64, prg: &mut SplitMix64) -> PolyVec {
        PolyVec::sample_short(n, eta, prg)
    }

    #[test]
    fn ns22_masked_garbage_reduction_is_viable() {
        // FEASIBILITY CHECK for the leaner base (before building it): does the NS22
        // 2r−1 sequential garbage reduction survive MASKING (z' = w + Σcᵢsᵢ), for
        // BOTH the plain quadratic AND the conjugated quadratic? If these identities
        // hold with O(r) garbage instead of r², the leaner ZK base is viable.
        let mut prg = SplitMix64::new(0x0C22_5EED);
        let (r, n) = (6usize, 24usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        let w = rand_short_vec(n, 4, &mut prg);

        // Sequential NS22 challenges (each cᵢ drawn AFTER the garbage that uses c_{<i}).
        let mut tr = Ns22Transcript::new(b"ns22-masked-feasibility");
        for si in &s {
            tr.absorb_vec(si);
        }
        // Plain: g_even[i]=⟨sᵢ,sᵢ⟩ (r), g_odd[i]=Σ_{j<i}(⟨sᵢ,sⱼ⟩+⟨sⱼ,sᵢ⟩)cⱼ (r).
        // Conj (asymmetric): gc_ii=conj_dot(sᵢ,sᵢ); gc_A[k]=Σ_{j<k}cⱼ·conj_dot(s_k,sⱼ)
        //   (paired with σ(c_k)); gc_B[k]=Σ_{i<k}σ(cᵢ)·conj_dot(sᵢ,s_k) (paired with c_k).
        let g_even: Vec<Poly> = (0..r).map(|i| dot(&s[i], &s[i])).collect();
        let gc_ii: Vec<Poly> = (0..r).map(|i| conj_dot(&s[i], &s[i])).collect();
        let (mut c, mut g_odd, mut gc_a, mut gc_b) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for k in 0..r {
            let mut go = Poly::zero();
            let mut ga = Poly::zero();
            let mut gb = Poly::zero();
            for j in 0..k {
                let cross = dot(&s[k], &s[j]).add(&dot(&s[j], &s[k]));
                go = go.add(&cross.mul_ntt(&c[j]));
                ga = ga.add(&conj_dot(&s[k], &s[j]).mul_ntt(&c[j]));
                gb = gb.add(&conj_dot(&s[j], &s[k]).mul_ntt(&c[j].conjugate()));
            }
            tr.absorb_poly(&go);
            tr.absorb_poly(&ga);
            tr.absorb_poly(&gb);
            g_odd.push(go);
            gc_a.push(ga);
            gc_b.push(gb);
            c.push(tr.challenge());
        }
        let mut z = PolyVec::zero(n);
        for i in 0..r {
            z = z.add(&s[i].mul_poly(&c[i]));
        }
        let zp = w.add(&z);

        // (1) PLAIN masked NS22: ⟨z',z'⟩ = ⟨w,w⟩ + 2Σcᵢ⟨w,sᵢ⟩ + Σ(g_odd·cᵢ + g_even·cᵢ²).
        let mut rhs = dot(&w, &w);
        for i in 0..r {
            rhs = rhs.add(&dot(&w, &s[i]).mul_ntt(&c[i]).scalar_mul(2));
        }
        for i in 0..r {
            rhs = rhs.add(&g_odd[i].mul_ntt(&c[i]));
            rhs = rhs.add(&g_even[i].mul_ntt(&c[i].mul_ntt(&c[i])));
        }
        assert_eq!(dot(&zp, &zp), rhs, "plain masked NS22 (2r garbage) holds");

        // (2) CONJUGATED masked NS22: conj_dot(z',z') = conj_dot(w,w)
        //   + Σcⱼ·conj_dot(w,sⱼ) + Σσ(cᵢ)·conj_dot(sᵢ,w)
        //   + Σ_k σ(c_k)c_k·gc_ii[k] + Σ_k σ(c_k)·gc_A[k] + Σ_k c_k·gc_B[k].
        let mut crhs = conj_dot(&w, &w);
        for j in 0..r {
            crhs = crhs.add(&conj_dot(&w, &s[j]).mul_ntt(&c[j]));
        }
        for i in 0..r {
            crhs = crhs.add(&conj_dot(&s[i], &w).mul_ntt(&c[i].conjugate()));
        }
        for k in 0..r {
            let sck = c[k].conjugate();
            crhs = crhs.add(&gc_ii[k].mul_ntt(&sck).mul_ntt(&c[k]));
            crhs = crhs.add(&gc_a[k].mul_ntt(&sck));
            crhs = crhs.add(&gc_b[k].mul_ntt(&c[k]));
        }
        assert_eq!(conj_dot(&zp, &zp), crhs, "conjugated masked NS22 (3r garbage) holds");

        // Leaner: O(r) garbage (plain 2r + conj 3r + O(r) mask) vs the r² regions.
        let ns22_garbage = 2 * r + 3 * r; // g_even+g_odd + gc_ii+gc_A+gc_B
        assert!(ns22_garbage < 3 * r * r, "NS22 garbage O(r) < 3r² for r>1 (r={r})");
    }

    #[test]
    fn randomness_opening_avoids_revealing_garbage() {
        // FEASIBILITY for the IPA-lite lever: because BDLOP adds the message
        // linearly (t2 = A2·r_G + G), ⟨coeff, G⟩ = ⟨coeff, t2⟩ − ⟨ψ, r_G⟩ with
        // ψ = A2ᵀ·coeff. So proving a combination needs only a masked opening of the
        // SHORT randomness r_G (dim λ) — NOT the dim-k garbage z_G. Confirm: reduction
        // identity holds, the randomness opening binds ⟨coeff,G⟩=target, a wrong
        // target rejects, and the reveal is λ+κ (not k+κ) polys.
        let mut prg = SplitMix64::new(0x19A5_0001u64);
        let k = 117usize; // r=5 garbage count
        let ck = RingCommitKey::production(k, 0x77A1);
        let ck1 = RingCommitKey::production(1, 0x88B2);
        let lambda = ck.a1.cols;
        let kappa = ck.a1.rows;

        let g = PolyVec::sample_short(k, 8, &mut prg);
        let r_g = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let u_g = ck.commit(&g, &r_g);
        let coeff = PolyVec::sample_short(k, 4, &mut prg);
        let target = dot(&coeff, &g);

        // ψ = A2ᵀ·coeff (dim λ), the reduced coefficient vector over the randomness.
        let mut psi = PolyVec::zero(lambda);
        for j in 0..lambda {
            let mut acc = Poly::zero();
            for i in 0..k {
                acc = acc.add(&coeff.0[i].mul_ntt(&ck.a2.m[i][j]));
            }
            psi.0[j] = acc;
        }
        // Reduction identity: ⟨coeff,t2⟩ − ⟨ψ,r_G⟩ = ⟨coeff,G⟩ = target.
        let rhs = dot(&coeff, &u_g.t2).sub(&target);
        assert_eq!(dot(&psi, &r_g), rhs, "⟨ψ,r_G⟩ = ⟨coeff,t2⟩ − target");

        // Masked opening of the SHORT r_G (dim λ) — no dim-k z_G revealed.
        const MASK: i64 = 1 << 26;
        let y_r = PolyVec::sample_uniform_pm(lambda, MASK, &mut prg);
        let c_yr = ck.a1.matvec(&y_r); // κ
        let x = 3i64;
        let z_r = y_r.add(&r_g.scalar_mul(x)); // dim λ
        // (1) z_r binds to the committed r_G: A1·z_r = c_yr + x·t1.
        assert_eq!(ck.a1.matvec(&z_r), c_yr.add(&u_g.t1.scalar_mul(x)), "z_r opens to committed r_G");
        // (2) combination: ⟨ψ,z_r⟩ − x·rhs opens to Commit(⟨ψ,y_r⟩) ⇒ ⟨coeff,G⟩=target.
        let r_t = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let c_t = ck1.commit(&PolyVec(vec![dot(&psi, &y_r)]), &r_t);
        let val = dot(&psi, &z_r).sub(&rhs.scalar_mul(x));
        assert_eq!(ck1.commit(&PolyVec(vec![val]), &r_t), c_t, "randomness opening binds the combination");
        let bad = dot(&psi, &z_r).sub(&rhs.add(&Poly::one()).scalar_mul(x));
        assert_ne!(ck1.commit(&PolyVec(vec![bad]), &r_t), c_t, "wrong target rejects");

        // Size: reveal z_r (λ) + c_yr (κ) vs the z_G approach z_G (k) + c_y (κ+k).
        println!("IPA-LITE k={k}: randomness reveal={} polys vs z_G reveal={} polys", lambda + kappa, k + kappa + k);
        assert!(lambda + kappa < k, "randomness opening reveals ≪ dim-k z_G");
    }

    #[test]
    fn batched_garbage_commitment_is_viable() {
        // FEASIBILITY: the single-transfer lever — commit ALL K garbage values as
        // ONE wide vector commitment (pay the commitment rank κ ONCE, not K×), and
        // prove each challenge-weighted combination ⟨coeff, G⟩ = target via a masked
        // LINEAR opening on the shared committed vector. Confirm: (a) honest verifies,
        // (b) a wrong target rejects, (c) it is smaller than K separate ell-1 commits.
        let mut prg = SplitMix64::new(0xBA7C_0001);
        let k = 29usize; // ~single-transfer (r=2) garbage count
        let ck_k = RingCommitKey::production(k, 0x5151); // ell=K wide commitment
        let ck1 = RingCommitKey::production(1, 0x6262);
        let lambda = ck_k.a1.cols;
        let kappa = ck_k.a1.rows;

        // Garbage vector G (dim K), committed ONCE.
        let g = PolyVec::sample_short(k, 8, &mut prg);
        let r_g = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let u_g = ck_k.commit(&g, &r_g);

        // A public coefficient vector (stands in for the challenge weights of a check)
        // and its honest target = ⟨coeff, G⟩ (ring inner product = the combination).
        let coeff = PolyVec::sample_short(k, 4, &mut prg);
        let target = dot(&coeff, &g);

        // Masked linear opening on the shared committed G.
        const MASK: i64 = 1 << 26;
        let y = PolyVec::sample_uniform_pm(k, MASK, &mut prg);
        let r_y = PolyVec::sample_uniform_pm(lambda, MASK, &mut prg);
        let r_t = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
        let t = dot(&coeff, &y); // ⟨coeff,y⟩, committed before the challenge
        let c_y = ck_k.commit(&y, &r_y);
        let c_t = ck1.commit(&PolyVec(vec![t]), &r_t);
        let x = 3i64; // any nonzero scalar binds a LINEAR relation
        let z = y.add(&g.scalar_mul(x));
        let r_z = r_y.add(&r_g.scalar_mul(x));

        // (1) z opens to the committed G: commit(z; r_z) == c_y + x·u_g.
        assert_eq!(ck_k.commit(&z, &r_z), c_y.add(&scalar_scale_commit(&u_g, x)), "z opens to committed G");
        // (2) combination: commit(⟨coeff,z⟩ − x·target; r_t) == c_t ⇒ ⟨coeff,G⟩ = target.
        let val = dot(&coeff, &z).sub(&target.scalar_mul(x));
        assert_eq!(ck1.commit(&PolyVec(vec![val]), &r_t), c_t, "combination binds ⟨coeff,G⟩ = target");
        // (c-soundness) a wrong target does NOT open to c_t.
        let bad = dot(&coeff, &z).sub(&target.add(&Poly::one()).scalar_mul(x));
        assert_ne!(ck1.commit(&PolyVec(vec![bad]), &r_t), c_t, "wrong target rejects");

        // Size: ONE wide commit + shared masked z (serves ALL checks) vs K ell-1
        // commits. C = number of combination checks the shared G supports.
        let c_checks = 4usize;
        let batched = 2 * (kappa + k) /*u_g,c_y*/ + k /*z*/ + lambda /*r_z*/ + c_checks * (kappa + 1 + lambda);
        let separate = k * (kappa + 1) /*K ell-1 commits*/ + c_checks * lambda /*per-check rand*/;
        println!("BATCH-GARBAGE K={k} C={c_checks}: batched={batched} polys vs separate={separate} polys");
        assert!(batched < separate, "batched garbage commit is smaller (batched={batched}, separate={separate})");
    }

    #[test]
    fn single_transfer_scale_general_terminal_size() {
        // HONEST single-transfer size: a general ZK terminal at transfer scale (a
        // few outputs → small r,n, NO amortization). Prints the ACTUAL proof size.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0x71A_5F03);
        let uniform = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        for (r, n) in [(2usize, 12usize), (3, 16)] {
            let a = PolyMatrix::from_seed(kappa, n, 0xA1);
            let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
            let stmt0 = QuadConstraint {
                terms: vec![(0, 0, uniform(&mut prg))],
                conj_terms: vec![(0, 1, uniform(&mut prg))],
                linear: vec![(1, PolyVec::sample_short(n, 2, &mut prg))],
                b: Poly::zero(),
            };
            let stmt = QuadConstraint { b: eval_constraint_on_witness(&stmt0, &s), ..stmt0 };
            let ck1 = RingCommitKey::production(1, 0x94);
            let beta_l2 = ((witness_l2_sq(&s) as f64).sqrt() * 2.2).ceil() as u128 + 1;
            let pf = prove_base_general_zk(&a, &ck1, &s, &stmt, &[], ETA as u64, b"sz", 0x6E)
                .expect("proves");
            assert!(verify_base_general_zk(&a, &ck1, &stmt, &[], beta_l2, &pf, b"sz"));
            let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
            let cp = |c: &RingCommitment| c.t1.len() + c.t2.len();
            let commits = cp(&pf.c_f) + cp(&pf.c_nu) + cp(&pf.c_ctnu) + cp(&pf.c_fc)
                + [&pf.c_e, &pf.c_e2, &pf.c_g, &pf.c_h, &pf.c_mh, &pf.c_hh, &pf.c_ecl, &pf.c_ecr, &pf.c_gc]
                    .iter().map(|v| v.iter().map(cp).sum::<usize>()).sum::<usize>();
            let polys = pf.t.iter().map(|v| v.len()).sum::<usize>() + pf.t_w.len() + commits
                + pf.zp.len() + pf.z_gq.len() + pf.z_gl.len() + pf.z_gs.len() + pf.z_gc.len() + pf.z_hbind.len()
                + 1 + pf.r_zeta.len() + pf.r_ctnu.len();
            println!("SINGLE-TRANSFER-SCALE r={r} n={n}: {polys} polys = {}KB + p(256 ints)", polys * per / 1024);
        }
    }

    #[test]
    fn conj_dot_constant_term_is_the_coefficient_inner_product() {
        // ct(⟨σ(u),v⟩) == ⟪u,v⟫ over random rank-n vectors — the identity the
        // conjugation aggregation rests on (ĝ = conj_dot is committable; its ct
        // yields the coefficient inner product a ct-constraint needs).
        let mut prg = SplitMix64::new(0xC012_3454);
        for n in [1usize, 3, 8] {
            for _ in 0..8 {
                let u = rand_short_vec(n, 5, &mut prg);
                let v = rand_short_vec(n, 5, &mut prg);
                assert_eq!(conj_dot(&u, &v).c[0], coeff_inner_vec(&u, &v));
            }
        }
    }

    fn fs_challenges(seed: u64, r: usize) -> Vec<Poly> {
        // Weight-τ ±1 challenges from a fresh transcript — stands in for the
        // Fiat-Shamir fold challenges (drawn AFTER ĝ is committed).
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/test/conj-binding");
        h.update(seed.to_le_bytes());
        let mut prg = HashPrg::from_digest(&h.finalize());
        (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect()
    }

    #[test]
    fn conj_garbage_binding_holds_for_honest_witness() {
        // Σ_ij ct(σ(c_i)c_j ĝ_ij) == ⟪z,z⟫ with ĝ = conj_garbage(s), z = Σ c_i s_i.
        let mut prg = SplitMix64::new(0xB19D_0001);
        let (r, n) = (5usize, 7usize);
        for t in 0..8u64 {
            let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
            let ghat = conj_garbage(&s);
            let c = fs_challenges(0x100 + t, r);
            let mut z = PolyVec::zero(n);
            for i in 0..r {
                z = z.add(&s[i].mul_poly(&c[i]));
            }
            assert_eq!(conj_binding_value(&ghat, &c), coeff_self_inner(&z));
        }
    }

    #[test]
    fn conj_garbage_binding_single_draw_is_insufficient() {
        // FINDING: a SINGLE weight-τ aggregate does NOT reliably catch a tampered
        // ĝ — the sparse challenges zero the difference term too often. This is
        // why the sound binding must batch (below). Measure the miss rate is
        // clearly non-negligible (not a fluke): a 1-coeff tamper survives many
        // single draws.
        let mut prg = SplitMix64::new(0xB19D_0002);
        let (r, n) = (5usize, 7usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        let mut ghat = conj_garbage(&s);
        ghat[2][3].c[0] = (ghat[2][3].c[0] + 1) % Poly::Q;
        let mut missed = 0;
        for t in 0..64u64 {
            let c = fs_challenges(0x900 + t, r);
            let mut z = PolyVec::zero(n);
            for i in 0..r {
                z = z.add(&s[i].mul_poly(&c[i]));
            }
            if conj_binding_value(&ghat, &c) == coeff_self_inner(&z) {
                missed += 1;
            }
        }
        assert!(missed > 0, "single-draw binding is expected to have non-negligible error");
    }

    #[test]
    fn conj_linear_garbage_binds_and_extracts_the_linear_ct_term() {
        // ĥ_ij = ⟨σ(φ_i),s_j⟩: (a) ct(ĥ_ii) = ⟪φ_i,s_i⟫ (the linear ct value),
        // (b) whole-ring binding ⟨σ(Φ),z⟩ = Σσ(c_i)c_j ĥ_ij, single-shot sound.
        let mut prg = SplitMix64::new(0xB19D_11E1);
        let (r, n) = (5usize, 7usize);
        for t in 0..10u64 {
            let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
            let phi: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 3, &mut prg)).collect();
            let hhat = conj_linear_garbage(&phi, &s);
            // (a) diagonal ct extracts ⟪φ_i,s_i⟫.
            for i in 0..r {
                assert_eq!(hhat[i][i].c[0], coeff_inner_vec(&phi[i], &s[i]));
            }
            // (b) binding: ⟨σ(Φ),z⟩ == Σσ(c_i)c_j ĥ_ij.
            let c = fs_challenges(0x600 + t, r);
            let cap_phi = folded_phi(&phi, &c, n);
            let mut z = PolyVec::zero(n);
            for i in 0..r {
                z = z.add(&s[i].mul_poly(&c[i]));
            }
            assert_eq!(conj_dot(&cap_phi, &z), conj_binding_ring(&hhat, &c), "honest linear binding");
            // Tamper ĥ ⇒ caught single-shot.
            let mut bad = hhat.clone();
            bad[2][1].c[3] = (bad[2][1].c[3] + 1) % Poly::Q;
            assert_ne!(conj_dot(&cap_phi, &z), conj_binding_ring(&bad, &c), "tamper caught");
        }
    }

    #[test]
    fn conj_garbage_ring_binding_is_single_shot_sound() {
        // WHOLE-RING binding `⟨σ(z),z⟩ = Σ σ(c_i)c_j ĝ_ij` — honest matches, and a
        // tampered ĝ is caught by a SINGLE challenge (all d coefficients checked),
        // unlike the ct-only binding which needed batching.
        let mut prg = SplitMix64::new(0xB19D_00A1);
        let (r, n) = (5usize, 7usize);
        for t in 0..12u64 {
            let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
            let ghat = conj_garbage(&s);
            let c = fs_challenges(0x700 + t, r);
            let mut z = PolyVec::zero(n);
            for i in 0..r {
                z = z.add(&s[i].mul_poly(&c[i]));
            }
            // Honest: whole-ring binding equals conj_dot(z,z).
            assert_eq!(conj_binding_ring(&ghat, &c), conj_dot(&z, &z));
            // Tamper one entry: caught by this single challenge (whole ring).
            let mut bad = ghat.clone();
            bad[1][3].c[2] = (bad[1][3].c[2] + 1) % Poly::Q;
            assert_ne!(conj_binding_ring(&bad, &c), conj_dot(&z, &z), "single-shot must catch tamper");
        }
    }

    #[test]
    fn conj_garbage_binding_batched_is_sound() {
        // The SOUND binding: k independent challenge draws. Honest ĝ always passes;
        // a tampered ĝ is caught in EVERY trial (batched miss ≈ ε^k negligible).
        let mut prg = SplitMix64::new(0xB19D_0003);
        let (r, n, k) = (5usize, 7usize, 12usize);
        for trial in 0..24u64 {
            let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
            let ghat = conj_garbage(&s);
            let cs: Vec<Vec<Poly>> = (0..k).map(|m| fs_challenges(0xC000 + trial * 100 + m as u64, r)).collect();
            assert!(conj_binding_holds_batched(&ghat, &s, &cs), "honest must pass");

            let mut bad = ghat.clone();
            let (ti, tj) = (trial as usize % r, (trial as usize + 1) % r);
            bad[ti][tj].c[0] = (bad[ti][tj].c[0] + 1) % Poly::Q;
            assert!(!conj_binding_holds_batched(&bad, &s, &cs), "tampered must be caught (trial {trial})");
        }
    }

    #[test]
    fn conj_terms_eval_and_aggregate_correctly() {
        // A constraint with a CONJUGATED quadratic term evaluates to include
        // a·⟨σ(s_i),s_j⟩, and aggregation preserves conj_terms (the aggregated
        // constraint evaluates to the ψ-combination of the parents).
        let mut prg = SplitMix64::new(0x0C0A_1234u64.wrapping_mul(3));
        let (r, n) = (4usize, 5usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        // Two constraints mixing plain + conjugated terms.
        let c0 = QuadConstraint {
            terms: vec![(0, 1, Poly::one())],
            conj_terms: vec![(0, 0, Poly::one())],
            linear: vec![],
            b: Poly::zero(),
        };
        let c1 = QuadConstraint {
            terms: vec![],
            conj_terms: vec![(1, 2, Poly::one().scalar_mul(2))],
            linear: vec![(3, s[3].clone())],
            b: Poly::zero(),
        };
        // eval includes the conj term via conj_dot.
        let e0 = eval_constraint_on_witness(&c0, &s);
        let expect0 = dot(&s[0], &s[1]).add(&conj_dot(&s[0], &s[0]));
        assert_eq!(e0, expect0, "conj term must appear in eval");

        // Aggregation preserves conj_terms: eval(agg) == Σ ψ_k eval(c_k) is NOT
        // directly checkable without ψ, but we CAN check the aggregated constraint
        // still carries conj_terms and re-evaluates consistently on the witness by
        // rebuilding it the same way the verifier does.
        let agg = aggregate_constraints(&[c0.clone(), c1.clone()]);
        assert!(!agg.conj_terms.is_empty(), "aggregate must retain conj_terms");
        // Determinism: aggregating the same family twice yields identical eval.
        let agg2 = aggregate_constraints(&[c0, c1]);
        assert_eq!(eval_constraint_on_witness(&agg, &s), eval_constraint_on_witness(&agg2, &s));
    }

    #[test]
    fn ct_family_lowers_through_production_reduce_one_level() {
        // Step 3: the ct-family folds through the PRODUCTION reduce_to_child (gadget
        // decompose + rechunk), not just the standalone demo. Parent binary ct →
        // child ct-family lowered onto ĝ; checked on the rechunked child witness.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 64usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 18, 0, 1, true);
        let shape = sched[0];
        let (a, b_a, b_b) = level_matrices(&shape, kappa, 0xC7, 0);

        // Witness: s_0 = valid bits, s_1 = all-ones J. Binary as pure-quadratic ct.
        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0 = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0, jvec];
        let terms = vec![(0usize, 0usize, 1i64), (0usize, 1usize, -1i64)];
        let ct_family = vec![CtConstraint { terms: terms.clone(), linear: vec![], target: 0 }];

        let child = reduce_to_child_conj_ct(&a, &b_a, &b_b, &s, &[], &ct_family, beta0, shape.bits, shape.limbs, shape.nu, shape.mu, true);
        assert!(!child.ct_constraints.is_empty(), "child ct-family produced");
        // Structural whole-ring constraints hold on the child witness.
        for con in &child.constraints {
            assert_eq!(eval_constraint_on_witness(con, &child.s), con.b, "structural child constraint holds");
        }
        // The lowered ct-family holds (= parent binary defect 0).
        for con in &child.ct_constraints {
            assert_eq!(eval_ct_on_witness(con, &child.s), con.target % Poly::Q, "lowered ct holds for valid bits");
        }

        // Non-bit: flip a coefficient ⇒ the lowered ct no longer equals target.
        let mut bad = b.clone();
        bad.c[9] = 2;
        let sbad0 = PolyVec(std::iter::once(bad).chain((1..n0).map(|_| Poly::zero())).collect());
        let jvec2 = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let sbad = vec![sbad0, jvec2];
        let child_bad = reduce_to_child_conj_ct(&a, &b_a, &b_b, &sbad, &[], &ct_family, beta0, shape.bits, shape.limbs, shape.nu, shape.mu, true);
        let ct_ok = child_bad.ct_constraints.iter().all(|con| eval_ct_on_witness(con, &child_bad.s) == con.target % Poly::Q);
        assert!(!ct_ok, "non-bit witness must break the lowered ct");
    }

    #[test]
    fn ct_family_lowers_through_production_reduce_two_levels() {
        // Step 3b: the ct-family folds through TWO PRODUCTION levels. Level 0 lowers
        // a QUADRATIC (binary) ct onto ĝ, producing a LINEAR child ct-family; level 1
        // lowers that linear ct onto the ĥ DIAGONAL. Checked on the grandchild
        // witness, incl. the (3d-linear) ĥ whole-ring binding in the structural set.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 64usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 18, 0, 2, true);
        assert!(sched.len() >= 2, "need two levels");

        // Witness: s_0 = valid bits, s_1 = all-ones J. Binary as pure-quadratic ct.
        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0 = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0, jvec];
        let terms = vec![(0usize, 0usize, 1i64), (0usize, 1usize, -1i64)];
        let ct_family = vec![CtConstraint { terms: terms.clone(), linear: vec![], target: 0 }];

        // Level 0: quadratic ct → ĝ; child ct-family becomes LINEAR.
        let sh0 = sched[0];
        let (a0, ba0, bb0) = level_matrices(&sh0, kappa, 0xC7, 0);
        let child0 = reduce_to_child_conj_ct(&a0, &ba0, &bb0, &s, &[], &ct_family, sh0.beta, sh0.bits, sh0.limbs, sh0.nu, sh0.mu, true);
        assert!(!child0.ct_constraints.is_empty(), "level-0 produces a child ct");
        assert!(child0.ct_constraints.iter().any(|c| !c.linear.is_empty()), "child ct is LINEAR");
        for con in &child0.constraints {
            assert_eq!(eval_constraint_on_witness(con, &child0.s), con.b, "level-0 structural holds");
        }

        // Level 1: linear ct → ĥ diagonal; structural set carries the ĥ binding.
        let sh1 = sched[1];
        let (a1, ba1, bb1) = level_matrices(&sh1, kappa, 0xC7, 1);
        let child1 = reduce_to_child_conj_ct(
            &a1, &ba1, &bb1, &child0.s, &child0.constraints, &child0.ct_constraints, sh1.beta, sh1.bits, sh1.limbs, sh1.nu, sh1.mu, true,
        );
        for con in &child1.constraints {
            assert_eq!(eval_constraint_on_witness(con, &child1.s), con.b, "level-1 structural (incl. ĥ binding) holds");
        }
        assert!(!child1.ct_constraints.is_empty(), "level-1 produces a grandchild ct");
        for con in &child1.ct_constraints {
            assert_eq!(eval_ct_on_witness(con, &child1.s), con.target % Poly::Q, "2-level lowered ct holds for valid bits");
        }

        // Non-bit witness ⇒ the 2-level-folded ct (target 0) must fail.
        let mut bad = b.clone();
        bad.c[11] = 2;
        let sbad0 = PolyVec(std::iter::once(bad).chain((1..n0).map(|_| Poly::zero())).collect());
        let jvec2 = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let sbad = vec![sbad0, jvec2];
        let cb0 = reduce_to_child_conj_ct(&a0, &ba0, &bb0, &sbad, &[], &ct_family, sh0.beta, sh0.bits, sh0.limbs, sh0.nu, sh0.mu, true);
        let cb1 = reduce_to_child_conj_ct(&a1, &ba1, &bb1, &cb0.s, &cb0.constraints, &cb0.ct_constraints, sh1.beta, sh1.bits, sh1.limbs, sh1.nu, sh1.mu, true);
        let ct_ok = cb1.ct_constraints.iter().all(|con| eval_ct_on_witness(con, &cb1.s) == con.target % Poly::Q);
        assert!(!ct_ok, "non-bit witness must break the 2-level lowered ct");
    }

    #[test]
    fn masked_quadratic_kernel_is_sound_over_ring_challenges() {
        // Step 4a kernel: the masked-quadratic identity for a MIXED whole-ring
        // constraint (terms + conj_terms + linear, nonzero target). Honest: holds
        // for EVERY random ring challenge x. Cheating (constraint value ≠ b): the x²
        // coefficient shifts, so a random x catches it whp.
        let mut prg = SplitMix64::new(0x4A5C_0001);
        let uniform_ring = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let n = 4usize;
        let s: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 5, &mut prg)).collect();
        // Plain-quad + linear (nonzero target): a₀₀⟨s₀,s₀⟩ + a₀₂⟨s₀,s₂⟩ + ⟨φ,s₁⟩ = b.
        let a00 = uniform_ring(&mut prg);
        let a02 = uniform_ring(&mut prg);
        let phi = rand_short_vec(n, 5, &mut prg);
        let con = QuadConstraint {
            terms: vec![(0, 0, a00), (0, 2, a02)],
            conj_terms: vec![],
            linear: vec![(1, phi)],
            b: Poly::zero(),
        };
        let honest_b = eval_constraint_on_witness(&con, &s);
        let con = QuadConstraint { b: honest_b, ..con };

        // Honest: identity holds for every challenge.
        for _ in 0..24 {
            let y: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 7, &mut prg)).collect();
            let x = uniform_ring(&mut prg);
            assert!(masked_quad_identity_holds(&con, &s, &y, &x), "honest identity holds for all x");
        }

        // Cheat: wrong target ⇒ caught for (almost) every random x.
        let bad = QuadConstraint { b: con.b.add(&Poly::one()), ..con.clone() };
        let mut caught = 0;
        for _ in 0..24 {
            let y: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 7, &mut prg)).collect();
            let x = uniform_ring(&mut prg);
            if !masked_quad_identity_holds(&bad, &s, &y, &x) {
                caught += 1;
            }
        }
        assert!(caught >= 22, "cheating target caught by nearly every ring challenge (got {caught}/24)");
    }

    #[test]
    fn masked_conjugated_kernel_is_sound_over_ring_challenges() {
        // Step 4a kernel (conjugated companion): a CONJUGATED+linear constraint
        // (â·conj_dot(s_i,s_j) + ⟨φ,s⟩ = b) masked with z = y + x·s, checked via the
        // σ(x)·x-paired identity. Honest holds for every x; cheating caught whp.
        let mut prg = SplitMix64::new(0x4A5C_C047);
        let uniform_ring = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let n = 4usize;
        let s: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 5, &mut prg)).collect();
        let a01 = uniform_ring(&mut prg);
        let a12 = uniform_ring(&mut prg);
        let phi = rand_short_vec(n, 5, &mut prg);
        let con = QuadConstraint {
            terms: vec![],
            conj_terms: vec![(0, 1, a01), (1, 2, a12)],
            linear: vec![(2, phi)],
            b: Poly::zero(),
        };
        let honest_b = eval_constraint_on_witness(&con, &s);
        let con = QuadConstraint { b: honest_b, ..con };

        for _ in 0..24 {
            let y: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 7, &mut prg)).collect();
            let x = uniform_ring(&mut prg);
            assert!(masked_conj_identity_holds(&con, &s, &y, &x), "honest conjugated identity holds for all x");
        }
        let bad = QuadConstraint { b: con.b.add(&Poly::one()), ..con.clone() };
        let mut caught = 0;
        for _ in 0..24 {
            let y: Vec<PolyVec> = (0..3).map(|_| rand_short_vec(n, 7, &mut prg)).collect();
            let x = uniform_ring(&mut prg);
            if !masked_conj_identity_holds(&bad, &s, &y, &x) {
                caught += 1;
            }
        }
        assert!(caught >= 22, "cheating conjugated target caught by nearly every x (got {caught}/24)");
    }

    #[test]
    #[ignore = "end-to-end composition of the validated fold (prove_labrador_full) + validated ZK \
                base (ns22_zk_base_verifies_and_binds); heavy at production κ — the JL projection + r² \
                conjugated garbage run over the folded witness. Run explicitly."]
    fn full_pipeline_zk_end_to_end() {
        // The WHOLE succinct ZK pipeline: fold (decompose + last) → ZERO-KNOWLEDGE
        // NS22 base (masked amortized opening + committed garbage + JL norm-binding).
        // Witness never revealed. Honest verifies; tampered outer commitment rejects.
        let kappa = crate::params::SIS_RANK_KAPPA;
        // Small bits ⇒ small residual β (ZK-base rejection + JL range hold); small n0
        // ⇒ small n_last so the r² conj-garbage + JL projection stay bounded.
        let (r0, n0, beta0) = (4usize, 16usize, ETA as u64);
        let schedule = level_schedule(r0, n0, beta0, kappa, 8, 0, 1);
        assert_eq!(schedule.len(), 1);
        let (family0, s0) = base_relation(r0, n0, 0xD0D0);
        let seed = 0xF0F1;

        let pf = prove_labrador_full_zk(&family0, &s0, beta0, kappa, &schedule, seed)
            .expect("succinct ZK pipeline proves");
        assert!(
            verify_labrador_full_zk(&family0, beta0, kappa, &schedule, seed, &pf),
            "honest succinct ZK pipeline verifies"
        );

        // Tamper the outer commitment → fold challenges shift → base rejects.
        let mut bad = FullZkProof { u1s: pf.u1s.clone(), base: pf.base.clone(), n_last: pf.n_last };
        bad.u1s[0].0.0[0] = bad.u1s[0].0.0[0].add(&Poly::one());
        assert!(
            !verify_labrador_full_zk(&family0, beta0, kappa, &schedule, seed, &bad),
            "tampered outer commitment rejects"
        );
        // Tamper the JL projection → norm-binding rejects.
        let mut bad2 = FullZkProof { u1s: pf.u1s.clone(), base: pf.base.clone(), n_last: pf.n_last };
        bad2.base.p[0] = pf.base.p[0] / 2 + 1;
        assert!(
            !verify_labrador_full_zk(&family0, beta0, kappa, &schedule, seed, &bad2),
            "tampered JL projection rejects"
        );

        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let cp = |c: &RingCommitment| c.t1.len() + c.t2.len();
        let bp = &pf.base;
        let base_polys = bp.t.iter().map(|v| v.len()).sum::<usize>()
            + bp.t_w.len() + cp(&bp.c_f)
            + [&bp.c_e, &bp.c_e2, &bp.c_g, &bp.c_h, &bp.c_mh, &bp.c_hh].iter().map(|v| v.iter().map(cp).sum::<usize>()).sum::<usize>()
            + cp(&bp.c_nu) + cp(&bp.c_ctnu)
            + bp.zp.len() + bp.z_gq.len() + bp.z_gl.len() + bp.z_gs.len() + bp.z_hbind.len() + 1 + bp.r_zeta.len() + bp.r_ctnu.len();
        let u1 = pf.u1s.iter().map(|(a, b)| a.len() + b.len()).sum::<usize>();
        println!("FULL-ZK levels={} n_last={}: {}KB (u1={} + base={} polys) + p(256 ints)",
            schedule.len(), pf.n_last, (u1 + base_polys) * per / 1024, u1, base_polys);
    }

    #[test]
    #[ignore = "money-path pipeline with the IPA-lite terminal (randomness opening); heavy at \
                production κ. Run explicitly."]
    fn full_ct_zk_ipa_pipeline_end_to_end() {
        // The money-path succinct ZK proof through the IPA-lite pipeline: fold both
        // families (has_conj), then the IPA terminal (dim-λ randomness opening, no
        // dim-k z_G). Honest verifies; tampered outer commitment + wrong ct reject.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 8usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 4, 0, 1, true);
        assert!(!sched.is_empty());
        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0v = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0v, jvec];
        let ct_family = vec![CtConstraint { terms: vec![(0, 0, 1i64), (0, 1, -1i64)], linear: vec![], target: 0 }];
        let family0: Vec<QuadConstraint> = vec![];
        let seed = 0xFC1Au64;

        let pf = prove_labrador_full_ct_zk_ipa(&family0, &ct_family, &s, beta0, kappa, &sched, seed, seed ^ 0x1234)
            .expect("IPA money-path pipeline proves");
        assert!(verify_labrador_full_ct_zk_ipa(&family0, &ct_family, beta0, kappa, &sched, seed, &pf), "honest IPA pipeline verifies");

        let mut bad = FullCtZkIpaProof { u1s: pf.u1s.clone(), base: pf.base.clone(), n_last: pf.n_last };
        bad.u1s[0].0.0[0] = bad.u1s[0].0.0[0].add(&Poly::one());
        assert!(!verify_labrador_full_ct_zk_ipa(&family0, &ct_family, beta0, kappa, &sched, seed, &bad), "tampered outer commitment rejects");
        let bad_ct = vec![CtConstraint { terms: vec![(0, 0, 1i64), (0, 1, -1i64)], linear: vec![], target: 1 }];
        assert!(!verify_labrador_full_ct_zk_ipa(&family0, &bad_ct, beta0, kappa, &sched, seed, &pf), "wrong ct target rejects");
    }

    #[test]
    #[ignore = "money-path pipeline: fold (ct-fold, has_conj) → general ZK terminal; heavy at \
                production κ (JL + r² conjugated garbage over the folded witness). Run explicitly."]
    fn full_ct_zk_pipeline_end_to_end() {
        // The MONEY-PATH-shaped succinct ZK proof: a binary constraint carried as a
        // ct-family folds through the recursion (has_conj), and the converged general
        // statement + linear ct-family are proven by the general ZK terminal. Witness
        // never revealed. Honest verifies; tampered outer commitment + wrong ct reject.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 8usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 4, 0, 1, true);
        assert!(!sched.is_empty());

        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0v = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0v, jvec];
        let ct_family = vec![CtConstraint { terms: vec![(0, 0, 1i64), (0, 1, -1i64)], linear: vec![], target: 0 }];
        let family0: Vec<QuadConstraint> = vec![];
        let seed = 0xFC01u64;

        let pf = prove_labrador_full_ct_zk(&family0, &ct_family, &s, beta0, kappa, &sched, seed, seed ^ 0x1234_ABCD)
            .expect("money-path ct-ZK pipeline proves");
        assert!(
            verify_labrador_full_ct_zk(&family0, &ct_family, beta0, kappa, &sched, seed, &pf),
            "honest money-path ct-ZK verifies"
        );

        let mut bad = FullCtZkProof { u1s: pf.u1s.clone(), base: pf.base.clone(), n_last: pf.n_last };
        bad.u1s[0].0.0[0] = bad.u1s[0].0.0[0].add(&Poly::one());
        assert!(!verify_labrador_full_ct_zk(&family0, &ct_family, beta0, kappa, &sched, seed, &bad), "tampered outer commitment rejects");

        let bad_ct = vec![CtConstraint { terms: vec![(0, 0, 1i64), (0, 1, -1i64)], linear: vec![], target: 1 }];
        assert!(!verify_labrador_full_ct_zk(&family0, &bad_ct, beta0, kappa, &sched, seed, &pf), "wrong ct target rejects");
    }

    #[test]
    fn ipa_general_zk_terminal_verifies_and_binds() {
        // Step 5e: the IPA-lite terminal — garbage in one wide commitment, checks
        // proven by a masked opening of the SHORT randomness r_G (dim λ), NOT the
        // dim-k z_G. Honest verifies; wrong statement, corrupted randomness opening,
        // fake JL, wrong ct all reject. Much smaller than the batched terminal.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0x19A5_9E01);
        let uniform = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let (r, n) = (5usize, 48usize);
        let a = PolyMatrix::from_seed(kappa, n, 0xA1C3);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let stmt0 = QuadConstraint {
            terms: vec![(0, 0, uniform(&mut prg)), (0, 2, uniform(&mut prg)), (1, 3, uniform(&mut prg))],
            conj_terms: vec![(0, 1, uniform(&mut prg)), (2, 4, uniform(&mut prg))],
            linear: vec![(0, PolyVec::sample_short(n, 2, &mut prg)), (3, PolyVec::sample_short(n, 2, &mut prg))],
            b: Poly::zero(),
        };
        let stmt = QuadConstraint { b: eval_constraint_on_witness(&stmt0, &s), ..stmt0 };
        let mk_ct = |lin: Vec<(usize, PolyVec)>| {
            let c0 = CtConstraint { terms: vec![], linear: lin, target: 0 };
            CtConstraint { target: eval_ct_on_witness(&c0, &s), ..c0 }
        };
        let ct_family = vec![mk_ct(vec![(1, PolyVec::sample_short(n, 3, &mut prg))])];

        let k = garbage_k_kr(r, CT_AGG_ROUNDS);
        let ck_g = RingCommitKey::production(k, 0x5151);
        let ck1 = RingCommitKey::production(1, 0x6262);
        let beta_l2 = ((witness_l2_sq(&s) as f64).sqrt() * 2.2).ceil() as u128 + 1;

        let pf = prove_base_general_zk_ipa(&a, &ck_g, &ck1, &s, &stmt, &ct_family, ETA as u64, b"ipa", 0x6E01)
            .expect("ipa terminal proves");
        assert!(verify_base_general_zk_ipa(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf, b"ipa"), "honest ipa terminal verifies");

        let stmt_w = QuadConstraint { b: stmt.b.add(&Poly::one()), ..stmt.clone() };
        let pf_w = prove_base_general_zk_ipa(&a, &ck_g, &ck1, &s, &stmt_w, &ct_family, ETA as u64, b"ipa", 0x6E02).expect("proves");
        assert!(!verify_base_general_zk_ipa(&a, &ck_g, &ck1, &stmt_w, &ct_family, beta_l2, &pf_w, b"ipa"), "wrong statement rejects");

        let mut pf2 = pf.clone();
        pf2.z_r.0[0] = pf2.z_r.0[0].add(&Poly::one());
        assert!(!verify_base_general_zk_ipa(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf2, b"ipa"), "corrupted z_r rejects");
        let mut pf3 = pf.clone();
        pf3.p[0] = pf.p[0] / 2 + 1;
        assert!(!verify_base_general_zk_ipa(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf3, b"ipa"), "fake JL rejects");
        let mut ct_bad = ct_family.clone();
        ct_bad[0].target = (ct_bad[0].target + 1) % Poly::Q;
        assert!(!verify_base_general_zk_ipa(&a, &ck_g, &ck1, &stmt, &ct_bad, beta_l2, &pf, b"ipa"), "wrong ct target rejects");

        // Size.
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let cp = |c: &RingCommitment| c.t1.len() + c.t2.len();
        let cps = |cs: &[RingCommitment]| cs.iter().map(cp).sum::<usize>();
        let pvs = |vs: &[PolyVec]| vs.iter().map(|v| v.len()).sum::<usize>();
        let full = pf.t.iter().map(|v| v.len()).sum::<usize>() + pf.t_w.len() + pf.zp.len()
            + cp(&pf.u_g) + pf.c_yr.len() + pf.z_r.len()
            + pf.c_t.iter().map(cp).sum::<usize>() + pf.r_t.iter().map(|v| v.len()).sum::<usize>()
            + cps(&pf.c_nu) + cps(&pf.c_ctnu) + cps(&pf.c_tct) + pf.zeta.len() + pvs(&pf.z_ctr) + pvs(&pf.r_ctnu);
        // Compact: uniform (t, u_g, c_t, c_nu/ctnu/tct) at log q; zp masked ~27b; z_r/short ~few.
        let bytes = |polys: usize, bits: usize| (polys * RING_DEGREE_D * bits).div_ceil(8);
        let uniform_polys = pf.t.iter().map(|v| v.len()).sum::<usize>() + pf.t_w.len() + cp(&pf.u_g)
            + pf.c_t.iter().map(cp).sum::<usize>() + cps(&pf.c_nu) + cps(&pf.c_ctnu) + cps(&pf.c_tct) + pf.c_yr.len();
        let masked_polys = pf.zp.len() + pf.z_r.len() + pf.zeta.len();
        let short_polys = pf.r_t.iter().map(|v| v.len()).sum::<usize>() + pvs(&pf.z_ctr) + pvs(&pf.r_ctnu);
        let compact = bytes(uniform_polys, crate::params::MODULUS_Q_BITS as usize) + bytes(masked_polys, 27) + bytes(short_polys, 5);
        println!("IPA-TERMINAL r={r} n={n}: {full} polys = {}KB (compact ≈ {}KB)", full * per / 1024, compact / 1024);
    }

    #[test]
    fn batched_general_zk_terminal_verifies_and_binds() {
        // Step 5d: the general ZK terminal with garbage BATCHED into one wide
        // commitment. Proves the same general statement (off-diag + conj + linear)
        // + ct-family + JL norm, witness-free. Honest verifies; wrong statement,
        // corrupted garbage opening, fake JL projection reject. Smaller than the
        // per-commit general terminal.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0xBA7C_9E01);
        let uniform = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let (r, n) = (5usize, 48usize);
        let a = PolyMatrix::from_seed(kappa, n, 0xA1C3);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let stmt0 = QuadConstraint {
            terms: vec![(0, 0, uniform(&mut prg)), (0, 2, uniform(&mut prg)), (1, 3, uniform(&mut prg))],
            conj_terms: vec![(0, 1, uniform(&mut prg)), (2, 4, uniform(&mut prg))],
            linear: vec![(0, PolyVec::sample_short(n, 2, &mut prg)), (3, PolyVec::sample_short(n, 2, &mut prg))],
            b: Poly::zero(),
        };
        let stmt = QuadConstraint { b: eval_constraint_on_witness(&stmt0, &s), ..stmt0 };
        let mk_ct = |lin: Vec<(usize, PolyVec)>| {
            let c0 = CtConstraint { terms: vec![], linear: lin, target: 0 };
            CtConstraint { target: eval_ct_on_witness(&c0, &s), ..c0 }
        };
        let ct_family = vec![mk_ct(vec![(1, PolyVec::sample_short(n, 3, &mut prg))])];

        let k = 2 + 5 * r + r * (r + 1) / 2 + 3 * r * r; // GarbageLayout::k
        let ck_g = RingCommitKey::production(k, 0x5151);
        let ck1 = RingCommitKey::production(1, 0x6262);
        let beta_l2 = ((witness_l2_sq(&s) as f64).sqrt() * 2.2).ceil() as u128 + 1;

        let pf = prove_base_general_zk_batched(&a, &ck_g, &ck1, &s, &stmt, &ct_family, ETA as u64, b"bg", 0x6E01)
            .expect("batched terminal proves");
        assert!(verify_base_general_zk_batched(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf, b"bg"), "honest batched terminal verifies");

        // Wrong statement value ⇒ reject.
        let stmt_w = QuadConstraint { b: stmt.b.add(&Poly::one()), ..stmt.clone() };
        let pf_w = prove_base_general_zk_batched(&a, &ck_g, &ck1, &s, &stmt_w, &ct_family, ETA as u64, b"bg", 0x6E02)
            .expect("proves dishonest b");
        assert!(!verify_base_general_zk_batched(&a, &ck_g, &ck1, &stmt_w, &ct_family, beta_l2, &pf_w, b"bg"), "wrong statement rejects");

        // Corrupted garbage opening ⇒ reject.
        let mut pf2 = pf.clone();
        pf2.z_g.0[0] = pf2.z_g.0[0].add(&Poly::one());
        assert!(!verify_base_general_zk_batched(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf2, b"bg"), "corrupted z_G rejects");
        // Fake JL projection ⇒ reject.
        let mut pf3 = pf.clone();
        pf3.p[0] = pf.p[0] / 2 + 1;
        assert!(!verify_base_general_zk_batched(&a, &ck_g, &ck1, &stmt, &ct_family, beta_l2, &pf3, b"bg"), "fake JL projection rejects");
        // Wrong ct target ⇒ reject.
        let mut ct_bad = ct_family.clone();
        ct_bad[0].target = (ct_bad[0].target + 1) % Poly::Q;
        assert!(!verify_base_general_zk_batched(&a, &ck_g, &ck1, &stmt, &ct_bad, beta_l2, &pf, b"bg"), "wrong ct target rejects");

        // Size vs the per-commit general terminal.
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let cp = |c: &RingCommitment| c.t1.len() + c.t2.len();
        let batched = pf.t.iter().map(|v| v.len()).sum::<usize>() + pf.t_w.len() + pf.zp.len()
            + cp(&pf.u_g) + cp(&pf.c_y) + pf.z_g.len() + pf.r_zg.len()
            + pf.c_t.iter().map(cp).sum::<usize>() + pf.r_t.iter().map(|v| v.len()).sum::<usize>()
            + cp(&pf.c_nu) + cp(&pf.c_ctnu) + cp(&pf.c_tct) + 1 + pf.z_ctr.len() + pf.r_ctnu.len();
        println!("BATCHED-TERMINAL r={r} n={n}: {batched} polys = {}KB + p(256 ints)", batched * per / 1024);

        // Compact size: uniform parts (commitments) at log q; masked z_g/zp at
        // ⌈log2(2·MASK+1)⌉≈27 bits; short randomness at ⌈log2(2η+1)⌉ bits.
        let bytes = |polys: usize, bits: usize| (polys * RING_DEGREE_D * bits).div_ceil(8);
        let uniform = pf.t.iter().map(|v| v.len()).sum::<usize>() + pf.t_w.len()
            + cp(&pf.u_g) + cp(&pf.c_y) + pf.c_t.iter().map(cp).sum::<usize>()
            + cp(&pf.c_nu) + cp(&pf.c_ctnu) + cp(&pf.c_tct);
        let masked = pf.zp.len() + pf.z_g.len() + 1 /*zeta*/;
        let shortr = pf.r_zg.len() + pf.r_t.iter().map(|v| v.len()).sum::<usize>() + pf.z_ctr.len() + pf.r_ctnu.len();
        let compact = bytes(uniform, crate::params::MODULUS_Q_BITS as usize) + bytes(masked, 27) + bytes(shortr, 5);
        println!("  compact ≈ {}KB (uniform={} masked={} short={})", compact / 1024, uniform, masked, shortr);
    }

    #[test]
    fn general_zk_terminal_verifies_and_binds() {
        // Step 5c: the GENERAL ZK terminal — proves a general whole-ring statement
        // (off-diagonal terms + CONJUGATED terms + linear = b) + a ct-family + JL
        // norm, in ZK (witness-free). Honest verifies; wrong statement value, a
        // corrupted opening, and a fake JL projection all reject.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0x9E_7A03);
        let (r, n) = (5usize, 48usize);
        let a = PolyMatrix::from_seed(kappa, n, 0xA1C3);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let uniform = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let stmt0 = QuadConstraint {
            terms: vec![(0, 0, uniform(&mut prg)), (0, 2, uniform(&mut prg)), (1, 3, uniform(&mut prg))],
            conj_terms: vec![(0, 1, uniform(&mut prg)), (2, 4, uniform(&mut prg))],
            linear: vec![(0, PolyVec::sample_short(n, 2, &mut prg)), (3, PolyVec::sample_short(n, 2, &mut prg))],
            b: Poly::zero(),
        };
        let stmt = QuadConstraint { b: eval_constraint_on_witness(&stmt0, &s), ..stmt0 };
        // A linear ct-family alongside (folded binary stand-in).
        let mk_ct = |lin: Vec<(usize, PolyVec)>| {
            let c0 = CtConstraint { terms: vec![], linear: lin, target: 0 };
            CtConstraint { target: eval_ct_on_witness(&c0, &s), ..c0 }
        };
        let ct_family = vec![mk_ct(vec![(1, PolyVec::sample_short(n, 3, &mut prg))])];

        let ck1 = RingCommitKey::production(1, 0x9494);
        let beta_l2 = ((witness_l2_sq(&s) as f64).sqrt() * 2.2).ceil() as u128 + 1;

        let pf = prove_base_general_zk(&a, &ck1, &s, &stmt, &ct_family, ETA as u64, b"gen", 0x6E01)
            .expect("general terminal proves");
        assert!(verify_base_general_zk(&a, &ck1, &stmt, &ct_family, beta_l2, &pf, b"gen"), "honest general terminal verifies");

        // Wrong statement value (prove-then-verify) ⇒ reject (statement soundness).
        let stmt_w = QuadConstraint { b: stmt.b.add(&Poly::one()), ..stmt.clone() };
        let pf_w = prove_base_general_zk(&a, &ck1, &s, &stmt_w, &ct_family, ETA as u64, b"gen", 0x6E02)
            .expect("proves dishonest b");
        assert!(!verify_base_general_zk(&a, &ck1, &stmt_w, &ct_family, beta_l2, &pf_w, b"gen"), "wrong statement rejects");

        // Corrupted opening ⇒ reject.
        let mut pf2 = pf.clone();
        pf2.zp.0[0] = pf2.zp.0[0].add(&Poly::one());
        assert!(!verify_base_general_zk(&a, &ck1, &stmt, &ct_family, beta_l2, &pf2, b"gen"), "corrupted z' rejects");

        // Fake JL projection ⇒ norm-binding rejects.
        let mut pf3 = pf.clone();
        pf3.p[0] = pf.p[0] / 2 + 1;
        assert!(!verify_base_general_zk(&a, &ck1, &stmt, &ct_family, beta_l2, &pf3, b"gen"), "fake JL projection rejects");

        // Wrong ct target ⇒ reject.
        let mut ct_bad = ct_family.clone();
        ct_bad[0].target = (ct_bad[0].target + 1) % Poly::Q;
        assert!(!verify_base_general_zk(&a, &ck1, &stmt, &ct_bad, beta_l2, &pf, b"gen"), "wrong ct target rejects");
    }

    #[test]
    fn ns22_zk_base_binds_ct_family() {
        // The money piece: the ZK base binds a LINEAR ct-family (the FOLDED binary/
        // range constraint) alongside the JL norm, via the same conjugated ĥ garbage.
        // Honest verifies; a wrong ct target rejects.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0x3C_7B01);
        let (r, n) = (5usize, 64usize);
        let a = PolyMatrix::from_seed(kappa, n, 0x9B22);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let phi: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let a_diag: Vec<Poly> = (0..r).map(|_| sample_in_ball(&mut prg, 4)).collect();
        let b = {
            let mut acc = Poly::zero();
            for i in 0..r {
                acc = acc.add(&a_diag[i].mul_ntt(&dot(&s[i], &s[i])));
                acc = acc.add(&dot(&phi[i], &s[i]));
            }
            acc
        };
        // A LINEAR ct-family with honest targets (stands in for the folded binary).
        let mk_ct = |lin: Vec<(usize, PolyVec)>| {
            let c0 = CtConstraint { terms: vec![], linear: lin, target: 0 };
            let t = eval_ct_on_witness(&c0, &s);
            CtConstraint { target: t, ..c0 }
        };
        let ct_family = vec![
            mk_ct(vec![(0, PolyVec::sample_short(n, 3, &mut prg))]),
            mk_ct(vec![(1, PolyVec::sample_short(n, 3, &mut prg)), (2, PolyVec::sample_short(n, 3, &mut prg))]),
        ];

        let ck1 = RingCommitKey::production(1, 0x6363);
        let s_l2 = (witness_l2_sq(&s) as f64).sqrt();
        let beta_l2 = (s_l2 * 2.2).ceil() as u128 + 1;

        let pf = prove_base_ns22_zk(&a, &ck1, &s, &phi, &a_diag, &b, &ct_family, ETA as u64, b"ct", 0xC7C7)
            .expect("proves with ct-family");
        assert!(verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &ct_family, beta_l2, &pf, b"ct"), "honest ct-family binds");

        // Wrong ct target ⇒ reject.
        let mut bad = ct_family.clone();
        bad[0].target = (bad[0].target + 1) % Poly::Q;
        assert!(!verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &bad, beta_l2, &pf, b"ct"), "wrong ct target rejects");
    }

    #[test]
    fn ns22_zk_base_verifies_and_binds() {
        // Step 5b: the ZERO-KNOWLEDGE NS22 succinct base. Proves the diagonal
        // relation Σaᵢ⟨sᵢ,sᵢ⟩+Σ⟨φᵢ,sᵢ⟩=b (‖s‖ short) revealing ONLY a masked
        // amortized z' (dim n) + committed garbage + JL projection — never s.
        // Honest verifies; a wrong statement b and a corrupted z' reject.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(0x2C_1155);
        let (r, n) = (5usize, 64usize);
        let a = PolyMatrix::from_seed(kappa, n, 0x9A11);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let phi: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let a_diag: Vec<Poly> = (0..r).map(|_| sample_in_ball(&mut prg, 4)).collect();
        let b = {
            let mut acc = Poly::zero();
            for i in 0..r {
                acc = acc.add(&a_diag[i].mul_ntt(&dot(&s[i], &s[i])));
                acc = acc.add(&dot(&phi[i], &s[i]));
            }
            acc
        };
        let ck1 = RingCommitKey::production(1, 0x6161);
        // JL ℓ₂ bound: ‖p‖² ≤ 30·β² must pass, ‖p‖²≈128·‖s‖² ⇒ β ≥ ‖s‖·√(128/30).
        let s_l2 = (witness_l2_sq(&s) as f64).sqrt();
        let beta_l2 = (s_l2 * 2.2).ceil() as u128 + 1;

        let pf = prove_base_ns22_zk(&a, &ck1, &s, &phi, &a_diag, &b, &[], ETA as u64, b"t", 0xABC01)
            .expect("ZK NS22 base proves");
        assert!(verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &[], beta_l2, &pf, b"t"), "honest ZK NS22 base verifies");

        // Wrong statement value ⇒ prove-then-verify rejects (statement soundness).
        let b_wrong = b.add(&Poly::one());
        let pf_w = prove_base_ns22_zk(&a, &ck1, &s, &phi, &a_diag, &b_wrong, &[], ETA as u64, b"t", 0xABC02)
            .expect("proves (dishonest b)");
        assert!(!verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b_wrong, &[], beta_l2, &pf_w, b"t"), "wrong statement rejects");

        // Corrupted opening ⇒ reject.
        let mut pf2 = pf.clone();
        pf2.zp.0[0] = pf2.zp.0[0].add(&Poly::one());
        assert!(!verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &[], beta_l2, &pf2, b"t"), "corrupted z' rejects");

        // JL BINDING: a fake (halved) projection p — what a large-witness cheater
        // would send to slip under the norm — is rejected (the ĥ whole-ring binding
        // + ct-statement tie p to the committed s).
        let mut pf3 = pf.clone();
        pf3.p[0] = pf.p[0] / 2 + 1;
        assert!(!verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &[], beta_l2, &pf3, b"t"), "fake JL projection rejects");
        // Tampered conjugated garbage (to fake the norm) ⇒ whole-ring binding rejects.
        let mut pf4 = pf.clone();
        pf4.zeta = pf4.zeta.add(&Poly::one());
        assert!(!verify_base_ns22_zk(&a, &ck1, &phi, &a_diag, &b, &[], beta_l2, &pf4, b"t"), "tampered ζ rejects");

        // Report the size (the succinct ZK base, incl. the JL binding).
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let cp = |c: &RingCommitment| c.t1.len() + c.t2.len();
        let polys = pf.t.iter().map(|v| v.len()).sum::<usize>()
            + pf.t_w.len()
            + cp(&pf.c_f)
            + pf.c_e.iter().map(cp).sum::<usize>()
            + pf.c_e2.iter().map(cp).sum::<usize>()
            + pf.c_g.iter().map(cp).sum::<usize>()
            + pf.c_h.iter().map(cp).sum::<usize>()
            + pf.c_mh.iter().map(cp).sum::<usize>()
            + pf.c_hh.iter().map(cp).sum::<usize>()
            + cp(&pf.c_nu) + cp(&pf.c_ctnu)
            + pf.zp.len() + pf.z_gq.len() + pf.z_gl.len() + pf.z_gs.len()
            + pf.z_hbind.len() + 1 /* zeta */ + pf.r_zeta.len() + pf.r_ctnu.len();
        println!("NS22-ZK base (with JL binding) r={r} n={n}: {polys} polys = {}KB + p(256 ints)", polys * per / 1024);
    }

    #[test]
    fn jl_projection_binds_to_committed_witness_via_ct() {
        // Close the tight-norm gap: the JL rows are ct-constraints ⟪Π_k,s⟫=p_k, so
        // proving them against the committed s (ct base opening) BINDS the sent p.
        // (a) the reconstructed rows reproduce jl_project; (b) honest p binds; (c) a
        // FAKE p (smaller, to cheat the norm) is rejected by the binding.
        let mut prg = SplitMix64::new(0x1B_D101);
        let (r, n) = (4usize, 16usize);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let jl_seed = 0x5A17_9001u64;
        let p = jl_project(&s, jl_seed);
        let rows = jl_rows_as_ct(jl_seed, r, n, &p);
        assert_eq!(rows.len(), 256);
        // (a) the ct rows reproduce the projection (mod q) on the real witness.
        let q = Poly::Q;
        for (k, row) in rows.iter().enumerate() {
            assert_eq!(eval_ct_on_witness(row, &s), p[k].rem_euclid(q as i128) as u64, "row {k} = p_k");
        }
        // (b) bind honest p via the ct base opening.
        let ck_s = RingCommitKey::production(r * n, 0x71A1);
        let ck1 = RingCommitKey::production(1, 0x82B2);
        let r_s = PolyVec::sample_short(ck_s.a1.cols, SECRET_NORM_ETA, &mut prg);
        let u = ck_s.commit(&flatten_witness(&s), &r_s);
        let pf = prove_ct_base_opening(&ck_s, &ck1, &rows, &s, &r_s, &u, ETA as u64, 0xB17D)
            .expect("bind proves");
        assert!(verify_ct_base_opening(&ck_s, &ck1, &rows, r, n, &u, &pf), "honest p binds to committed s");
        // and the norm check accepts the honest (short) witness.
        let s_l2 = (witness_l2_sq(&s) as f64).sqrt();
        assert!(jl_norm_ok(&p, (s_l2 * 2.2).ceil() as u128 + 1), "honest norm ok");

        // (c) a FAKE p (halved — what a large-witness cheater would send to pass the
        // norm) has different ct targets ⇒ the binding rejects the honest proof.
        let mut p_fake = p;
        p_fake[0] = p[0] / 2 + 1;
        let rows_fake = jl_rows_as_ct(jl_seed, r, n, &p_fake);
        assert!(!verify_ct_base_opening(&ck_s, &ck1, &rows_fake, r, n, &u, &pf), "fake p fails the binding");
    }

    #[test]
    fn masked_base_opening_zk_verifies_and_binds() {
        // Step 4b: the perfect-ZK base opening. A short witness s (Ajtai-committed
        // as u) satisfies a mixed family (one plain-quad+linear, one conj+linear);
        // the masked opening verifies, and any wrong target / corrupted response
        // rejects. Only the rejection-sampled z is revealed (never s).
        let mut prg = SplitMix64::new(0xB0A5_0001);
        let uniform = |prg: &mut SplitMix64| -> Poly {
            let mut p = Poly::zero();
            for k in 0..Poly::D {
                p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            p
        };
        let (r, n) = (2usize, 3usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 2, &mut prg)).collect();

        let mut plain = QuadConstraint {
            terms: vec![(0, 0, uniform(&mut prg)), (0, 1, uniform(&mut prg))],
            conj_terms: vec![],
            linear: vec![(1, rand_short_vec(n, 2, &mut prg))],
            b: Poly::zero(),
        };
        plain.b = eval_constraint_on_witness(&plain, &s);
        let mut conj = QuadConstraint {
            terms: vec![],
            conj_terms: vec![(0, 1, uniform(&mut prg))],
            linear: vec![(0, rand_short_vec(n, 2, &mut prg))],
            b: Poly::zero(),
        };
        conj.b = eval_constraint_on_witness(&conj, &s);
        let family = vec![plain, conj];

        let ck_s = RingCommitKey::production(r * n, 0x5151);
        let ck1 = RingCommitKey::production(1, 0x6262);
        let r_s = PolyVec::sample_short(ck_s.a1.cols, SECRET_NORM_ETA, &mut prg);
        let pf = prove_masked_base_opening(&ck_s, &ck1, &family, &s, &r_s, 2, 0xC0FF).expect("prove succeeds");
        assert!(verify_masked_base_opening(&ck_s, &ck1, &family, r, n, &pf), "honest base opening verifies");

        // Wrong plain target ⇒ reject.
        let mut bad0 = family.clone();
        bad0[0].b = bad0[0].b.add(&Poly::one());
        assert!(!verify_masked_base_opening(&ck_s, &ck1, &bad0, r, n, &pf), "wrong plain target rejects");
        // Wrong conj target ⇒ reject.
        let mut bad1 = family.clone();
        bad1[1].b = bad1[1].b.add(&Poly::one());
        assert!(!verify_masked_base_opening(&ck_s, &ck1, &bad1, r, n, &pf), "wrong conj target rejects");
        // Corrupted response ⇒ z-opening binding fails.
        let mut pf_bad = MaskedBaseOpening { u: pf.u.clone(), shots: pf.shots.clone() };
        pf_bad.shots[0].z.0[0] = pf_bad.shots[0].z.0[0].add(&Poly::one());
        assert!(!verify_masked_base_opening(&ck_s, &ck1, &family, r, n, &pf_bad), "corrupted z rejects");
    }

    #[test]
    #[ignore = "capstone: composes the separately-validated 4c/4d/base-opening pieces; \
                heavy at production κ with the has_conj 3r² garbage inflation — run explicitly"]
    fn recursion_ct_zk_full_money_path_shape() {
        // Step 4 CAPSTONE: the full money-path-shaped recursion-ZK. A binary
        // constraint carried as a ct-family folds through the recursion; the base is
        // opened in ZK by BOTH the whole-ring opening (bindings) and the ct opening
        // (lowered ct), sharing one witness commitment. Honest verifies; a tampered
        // outer commitment and a wrong ct target both reject. Witness never revealed.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 2usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 4, 0, 1, true); // small bits ⇒ small base β
        assert!(!sched.is_empty());

        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0v = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0v, jvec];
        let terms = vec![(0usize, 0usize, 1i64), (0usize, 1usize, -1i64)];
        let ct_family = vec![CtConstraint { terms, linear: vec![], target: 0 }];
        let family0: Vec<QuadConstraint> = vec![];
        let seed = 0xF00Du64;

        let pf = prove_labrador_recursive_ct_zk(&family0, &ct_family, &s, beta0, kappa, &sched, seed, seed ^ 0x9E3D)
            .expect("full money-path recursion-ZK proves");
        assert!(
            verify_labrador_recursive_ct_zk(&family0, &ct_family, beta0, kappa, &sched, seed, &pf),
            "honest full recursion-ZK verifies"
        );

        // Tamper a level's outer commitment ⇒ challenges shift ⇒ base rejects.
        let mut bad = RecursiveCtZkProof {
            u1s: pf.u1s.clone(),
            base: MaskedBaseOpening { u: pf.base.u.clone(), shots: pf.base.shots.clone() },
            ct_base: pf.ct_base.clone(),
        };
        bad.u1s[0].0.0[0] = bad.u1s[0].0.0[0].add(&Poly::one());
        assert!(
            !verify_labrador_recursive_ct_zk(&family0, &ct_family, beta0, kappa, &sched, seed, &bad),
            "tampered outer commitment rejects"
        );

        // Wrong ct target ⇒ the lowered ct-family differs ⇒ ct opening rejects.
        let bad_ct = vec![CtConstraint { terms: vec![(0, 0, 1i64), (0, 1, -1i64)], linear: vec![], target: 1 }];
        assert!(
            !verify_labrador_recursive_ct_zk(&family0, &bad_ct, beta0, kappa, &sched, seed, &pf),
            "wrong ct target rejects"
        );
    }

    #[test]
    fn ct_base_opening_zk_verifies_and_binds() {
        // Step 4d: the residual LINEAR ct-family base opening (scalar challenge).
        // Honest verifies; wrong target and corrupted z reject. s never revealed.
        let mut prg = SplitMix64::new(0xC7B0_0001);
        let (r, n) = (2usize, 4usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 2, &mut prg)).collect();
        let phi0 = rand_short_vec(n, 3, &mut prg);
        let mut c0 = CtConstraint { terms: vec![], linear: vec![(0, phi0)], target: 0 };
        c0.target = eval_ct_on_witness(&c0, &s);
        let phi1 = rand_short_vec(n, 3, &mut prg);
        let mut c1 = CtConstraint { terms: vec![], linear: vec![(1, phi1)], target: 0 };
        c1.target = eval_ct_on_witness(&c1, &s);
        let family = vec![c0, c1];

        let ck_s = RingCommitKey::production(r * n, 0x7171);
        let ck1 = RingCommitKey::production(1, 0x8282);
        let r_s = PolyVec::sample_short(ck_s.a1.cols, SECRET_NORM_ETA, &mut prg);
        let u = ck_s.commit(&flatten_witness(&s), &r_s);
        let pf = prove_ct_base_opening(&ck_s, &ck1, &family, &s, &r_s, &u, 2, 0xDEAD).expect("prove succeeds");
        assert!(verify_ct_base_opening(&ck_s, &ck1, &family, r, n, &u, &pf), "honest ct base opening verifies");

        let mut bad = family.clone();
        bad[0].target = (bad[0].target + 1) % Poly::Q;
        assert!(!verify_ct_base_opening(&ck_s, &ck1, &bad, r, n, &u, &pf), "wrong ct target rejects");
        let mut pf2 = pf.clone();
        pf2.z.0[0] = pf2.z.0[0].add(&Poly::one());
        assert!(!verify_ct_base_opening(&ck_s, &ck1, &family, r, n, &u, &pf2), "corrupted z rejects");
    }

    #[test]
    fn recursion_ct_family_prove_verify_multilevel() {
        // Step 3b end-to-end: the ct-family rides the PRODUCTION recursion driver
        // (prove_labrador_recursive_ct) across a multi-level schedule and is checked
        // by the un-gated verify_labrador_recursive_ct. A binary constraint carried
        // as a ct-family: honest verifies; tampered witness / non-bit input reject.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (2usize, 64usize, ETA as u64);
        let sched = level_schedule_conj(r0, n0, beta0, kappa, 18, 0, 2, true);
        assert!(sched.len() >= 2, "need a multi-level schedule");

        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let jvec = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let s0 = PolyVec(std::iter::once(b.clone()).chain((1..n0).map(|_| Poly::zero())).collect());
        let s = vec![s0, jvec];
        let terms = vec![(0usize, 0usize, 1i64), (0usize, 1usize, -1i64)];
        let ct_family = vec![CtConstraint { terms, linear: vec![], target: 0 }];
        let family0: Vec<QuadConstraint> = vec![];
        let seed = 0xC7u64;

        let pf = prove_labrador_recursive_ct(&family0, &ct_family, &s, beta0, kappa, &sched, seed);
        assert!(
            verify_labrador_recursive_ct(&family0, &ct_family, beta0, kappa, &sched, seed, &pf),
            "honest multi-level ct recursion verifies"
        );

        // Tamper the revealed base witness → base checks reject.
        let mut pf_bad = pf.clone();
        pf_bad.final_s[0].0[0] = pf_bad.final_s[0].0[0].add(&Poly::one());
        assert!(
            !verify_labrador_recursive_ct(&family0, &ct_family, beta0, kappa, &sched, seed, &pf_bad),
            "tampered base witness must reject"
        );

        // Non-bit input → the folded ct (target 0) must fail end-to-end.
        let mut bad = b.clone();
        bad.c[11] = 2;
        let sbad0 = PolyVec(std::iter::once(bad).chain((1..n0).map(|_| Poly::zero())).collect());
        let jvec2 = PolyVec(std::iter::once(Poly { c: vec![1u64; Poly::D] }).chain((1..n0).map(|_| Poly::zero())).collect());
        let sbad = vec![sbad0, jvec2];
        let pf2 = prove_labrador_recursive_ct(&family0, &ct_family, &sbad, beta0, kappa, &sched, seed);
        assert!(
            !verify_labrador_recursive_ct(&family0, &ct_family, beta0, kappa, &sched, seed, &pf2),
            "non-bit witness must fail the recursive ct"
        );
    }

    #[test]
    fn ct_constraint_folds_through_two_levels() {
        // The milestone: a binary ct-constraint folds through 2 levels (ĝ then ĥ).
        // Binary as PURE-QUADRATIC: ⟪s_0,s_0⟫ − ⟪s_0,s_1⟫ = 0 with s_1 = all-ones J,
        // so it equals Σ_k b_k(b_k−1). Witness rank n=1 (each s_i one ring element).
        let kappa = crate::params::SIS_RANK_KAPPA;
        let r = 2usize;
        let a_g0 = PolyMatrix::from_seed(kappa, r * r, 0xF01);
        let a_h1 = PolyMatrix::from_seed(kappa, (1 + r * r) * (1 + r * r), 0xF02);
        let j = Poly { c: vec![1u64; Poly::D] };
        let terms = vec![(0usize, 0usize, Poly::one()), (0usize, 1usize, Poly::one().neg())];

        // Honest: s_0 = valid bits, s_1 = J. Binary defect 0.
        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64) & 1;
        }
        let s = vec![PolyVec(vec![b.clone()]), PolyVec(vec![j.clone()])];
        let pf = prove_ct_fold_2(&a_g0, &a_h1, &s, &terms);
        assert!(verify_ct_fold_2(&a_g0, &a_h1, &terms, 0, r, &pf), "binary bits fold through 2 levels");

        // Non-bit: flip a coefficient → defect ≠ 0 → the folded ct (target 0) fails.
        let mut bad = b.clone();
        bad.c[7] = 2;
        let s_bad = vec![PolyVec(vec![bad]), PolyVec(vec![j])];
        let pf_bad = prove_ct_fold_2(&a_g0, &a_h1, &s_bad, &terms);
        assert!(!verify_ct_fold_2(&a_g0, &a_h1, &terms, 0, r, &pf_bad), "non-bit must fail the folded ct");
    }

    #[test]
    fn ct_level_reduction_is_sound_single_level() {
        // The multi-level ct integration, one level: commit ĝ, fold, lower a
        // quadratic ct-constraint onto ĝ; verify opening + binding + lowered ct.
        let mut prg = SplitMix64::new(0x1EEA_7000);
        let (r, n) = (4usize, 6usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        // A_g commits the r² conjugated-garbage polys.
        let a_g = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, r * r, 0xA6);
        // A representative quadratic ct-constraint with its HONEST target.
        let terms = vec![(0usize, 0usize, 1i64), (1, 2, 5)];
        let honest_target = {
            let con = CtConstraint { terms: terms.clone(), linear: vec![], target: 0 };
            eval_ct_on_witness(&con, &s)
        };
        let con = CtConstraint { terms: terms.clone(), linear: vec![], target: honest_target };

        // Commit ĝ, derive challenge from u1 (Fiat-Shamir), fold, verify.
        let (u1, ghat0) = {
            let g = conj_garbage(&s);
            (a_g.matvec(&flatten_ghat(&g)), g)
        };
        let c = {
            let mut h = Sha256::new();
            h.update(b"ct-level");
            for p in &u1.0 {
                for &x in &p.c {
                    h.update(x.to_le_bytes());
                }
            }
            let mut prg = HashPrg::from_digest(&h.finalize());
            (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect::<Vec<_>>()
        };
        let (u1b, z, ghat) = reduce_ct_level(&a_g, &s, &c);
        assert_eq!(u1b, u1);
        assert!(verify_ct_level_quadratic(&a_g, std::slice::from_ref(&con), &u1, &z, &ghat, &c), "honest level verifies");
        let _ = ghat0;

        // (a) Violated parent ct-constraint (wrong target) → lowered ct fails.
        let bad_con = CtConstraint { terms, linear: vec![], target: (honest_target + 1) % Poly::Q };
        assert!(
            !verify_ct_level_quadratic(&a_g, std::slice::from_ref(&bad_con), &u1, &z, &ghat, &c),
            "violated ct-constraint must reject"
        );

        // (b) Tampered garbage (to fake the lowered value) → binding fails.
        let mut tampered = ghat.clone();
        tampered[0][0].c[0] = (tampered[0][0].c[0] + 1) % Poly::Q;
        // Recommit so the opening still holds — isolate the binding check.
        let u1_t = a_g.matvec(&flatten_ghat(&tampered));
        assert!(
            !verify_ct_level_quadratic(&a_g, std::slice::from_ref(&con), &u1_t, &z, &tampered, &c),
            "tampered garbage must fail the whole-ring binding"
        );
    }

    #[test]
    fn ct_constraint_lowers_via_conjugated_garbage() {
        // The core lowering the conjugation aggregation will perform: a parent
        // ct-constraint (quadratic in s) equals a LINEAR combination of the
        // constant terms of the conjugated garbage ĝ_ij = conj_dot(s_i,s_j) plus
        // the conjugated linear terms. Validates the transformation math BEFORE it
        // is wired into reduce_to_child.
        let mut prg = SplitMix64::new(0x10E1_2205);
        let (r, n) = (4usize, 6usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        // A representative ct-constraint: a couple of quadratic terms + a linear.
        let phi = rand_short_vec(n, 3, &mut prg);
        let con = CtConstraint {
            terms: vec![(0, 0, 1), (1, 2, 3)],
            linear: vec![(3, phi.clone())],
            target: 0,
        };
        let direct = eval_ct_on_witness(&con, &s);

        // "Lowered": commit ĝ_ij = conj_dot(s_i,s_j), then combine constant terms.
        let q = Poly::Q as u128;
        let mut acc = 0u128;
        for (i, j, a) in &con.terms {
            let g_hat = conj_dot(&s[*i], &s[*j]); // committable ring element
            let a_mod = a.rem_euclid(Poly::Q as i64) as u128;
            acc = (acc + a_mod * g_hat.c[0] as u128) % q;
        }
        for (i, p) in &con.linear {
            let h_hat = conj_dot(p, &s[*i]); // conjugated linear garbage
            acc = (acc + h_hat.c[0] as u128) % q;
        }
        assert_eq!(direct, acc as u64, "ct-constraint must lower to Σ ct(conjugated garbage)");
    }

    /// A random short witness + the constraints it satisfies (targets computed
    /// from the actual pairwise products, so the instance is satisfiable).
    fn instance(r: usize, n: usize, seed: u64) -> (Statement, Witness) {
        let mut prg = SplitMix64::new(seed);
        let a_mat = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, seed ^ 0xA);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        // One constraint per pair (i≤j): ⟨sᵢ,sⱼ⟩ = its true value (a=1).
        let mut constraints = Vec::new();
        for i in 0..r {
            for j in i..r {
                let b = dot(&s[i], &s[j]);
                constraints.push(QuadConstraint::quad(vec![(i, j, Poly::one())], b));
            }
        }
        (Statement { a_mat, r, n, constraints, beta: ETA as u64 }, Witness { s })
    }

    #[test]
    fn reduction_completeness() {
        let (st, w) = instance(4, 24, 1);
        let pf = prove_reduction(&st, &w).expect("prove");
        assert!(verify_reduction(&st, &pf), "honest reduction verifies");
    }

    #[test]
    fn reduction_rejects_tampered_z() {
        let (st, w) = instance(4, 24, 2);
        let mut pf = prove_reduction(&st, &w).unwrap();
        pf.z.0[0].c[0] = (pf.z.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_reduction(&st, &pf), "tampered z breaks the commitment fold");
    }

    #[test]
    fn reduction_rejects_tampered_garbage() {
        let (st, w) = instance(4, 24, 3);
        let mut pf = prove_reduction(&st, &w).unwrap();
        pf.g[1][2].c[0] = (pf.g[1][2].c[0] + 1) % Poly::Q;
        pf.g[2][1] = pf.g[1][2].clone(); // keep symmetric so only the quadratic check catches it
        assert!(!verify_reduction(&st, &pf), "tampered garbage breaks ⟨z,z⟩ = Σcᵢcⱼgᵢⱼ");
    }

    #[test]
    fn reduction_rejects_wrong_constraint_target() {
        let (mut st, w) = instance(4, 24, 4);
        let pf = prove_reduction(&st, &w).unwrap();
        st.constraints[0].b = st.constraints[0].b.add(&Poly::one()); // demand a false equality
        assert!(!verify_reduction(&st, &pf), "unsatisfiable constraint must reject");
    }

    #[test]
    fn aggregation_holds_for_satisfiable_and_fails_when_one_is_violated() {
        let (st, w) = instance(4, 24, 6);
        // True garbage table.
        let mut g = vec![vec![Poly::zero(); st.r]; st.r];
        for i in 0..st.r {
            for j in 0..st.r {
                g[i][j] = dot(&w.s[i], &w.s[j]);
            }
        }
        // Satisfiable: the aggregated LHS equals the aggregated target.
        let agg = aggregate_constraints(&st.constraints);
        assert_eq!(eval_constraint(&agg, &g), agg.b, "aggregate holds on a satisfiable system");
        // Violate ONE constraint's target; re-aggregate; LHS(true g) ≠ b_agg w.h.p.
        let mut bad = st.constraints.clone();
        bad[2].b = bad[2].b.add(&Poly::one());
        let agg_bad = aggregate_constraints(&bad);
        assert_ne!(
            eval_constraint(&agg_bad, &g),
            agg_bad.b,
            "one violated constraint breaks the aggregate"
        );
    }

    #[test]
    fn gadget_roundtrips_and_is_short() {
        let mut prg = SplitMix64::new(42);
        // Full-range coefficients (up to ~q/2).
        let v = PolyVec::sample_uniform_pm(3, (Poly::Q / 2) as i64, &mut prg);
        let (bits, limbs) = (12u32, 4usize);
        let d = gadget_decompose(&v, bits, limbs);
        assert_eq!(d.len(), 3 * limbs);
        assert!(d.inf_norm() <= (1u64 << (bits - 1)), "limbs are short (≤ 2^(bits-1))");
        let r = gadget_recompose(&d, bits, limbs);
        assert_eq!(r, v, "recompose ∘ decompose = identity (mod q)");
    }

    #[test]
    fn outer_commit_binds() {
        let (bits, limbs) = (12u32, 4usize);
        // B has as many columns as the decomposition width (m·limbs).
        let m = 5;
        let b_mat = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, m * limbs, 0xB);
        let mut prg = SplitMix64::new(7);
        let v1 = PolyVec::sample_uniform_pm(m, (Poly::Q / 2) as i64, &mut prg);
        let mut v2 = v1.clone();
        v2.0[0].c[0] = (v2.0[0].c[0] + 1) % Poly::Q; // a one-coefficient change
        let u1 = outer_commit(&b_mat, &v1, bits, limbs);
        let u2 = outer_commit(&b_mat, &v2, bits, limbs);
        assert_ne!(u1, u2, "distinct vectors give distinct outer commitments (binding)");
    }

    #[test]
    fn opening_fold_algebra() {
        // One manual fold must satisfy the invariant A'·s' = t'.
        let mut prg = SplitMix64::new(1);
        let n = 8;
        let a = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 9);
        let s = PolyVec::sample_short(n, ETA, &mut prg);
        let t = a.matvec(&s);
        let h = n / 2;
        let (a_l, a_r) = split_cols(&a, h);
        let s_l = PolyVec(s.0[..h].to_vec());
        let s_r = PolyVec(s.0[h..].to_vec());
        let u = a_l.matvec(&s_r).add(&a_r.matvec(&s_l));
        let q_r = a_r.matvec(&s_r);
        let x = fold_challenge(&t, &u, &q_r);
        let s2 = s_l.add(&s_r.mul_poly(&x));
        let a2 = mat_fold(&a_l, &a_r, &x);
        let x2m1 = x.mul_ntt(&x).sub(&Poly::one());
        let t2 = t.add(&u.mul_poly(&x)).add(&q_r.mul_poly(&x2m1));
        assert_eq!(a2.matvec(&s2), t2, "A'·s' = t'");
    }

    fn fold_norm_bound(rounds: u32) -> u64 {
        (ETA as u64) * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds)
    }

    #[test]
    fn opening_fold_completeness_and_compression() {
        let (rounds, base) = (4usize, 8usize);
        let n = base << rounds; // 128
        let mut prg = SplitMix64::new(2);
        let a = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 9);
        let s = PolyVec::sample_short(n, ETA, &mut prg);
        let t = a.matvec(&s);
        let pf = prove_opening_fold(&a, &s, &t, rounds);
        assert!(verify_opening_fold(&a, &t, &pf, fold_norm_bound(rounds as u32)), "honest fold verifies");
        let proof_polys = pf.rounds.len() * 2 * crate::params::SIS_RANK_KAPPA + pf.s_final.len();
        println!("OPENING_FOLD n={n} rounds={rounds} proof_ring_elts={proof_polys} vs_reveal_s={n}");
        assert!(proof_polys < n, "fold compresses vs revealing s ({proof_polys} < {n})");
    }

    #[test]
    fn opening_fold_rejects_tampered_base() {
        let rounds = 3usize;
        let n = 8usize << rounds;
        let mut prg = SplitMix64::new(3);
        let a = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 9);
        let s = PolyVec::sample_short(n, ETA, &mut prg);
        let t = a.matvec(&s);
        let mut pf = prove_opening_fold(&a, &s, &t, rounds);
        pf.s_final.0[0].c[0] = (pf.s_final.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_opening_fold(&a, &t, &pf, fold_norm_bound(rounds as u32)), "tampered base rejects");
    }

    #[test]
    fn opening_fold_rejects_tampered_round() {
        let rounds = 3usize;
        let n = 8usize << rounds;
        let mut prg = SplitMix64::new(4);
        let a = PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 9);
        let s = PolyVec::sample_short(n, ETA, &mut prg);
        let t = a.matvec(&s);
        let mut pf = prove_opening_fold(&a, &s, &t, rounds);
        pf.rounds[0].u.0[0].c[0] = (pf.rounds[0].u.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_opening_fold(&a, &t, &pf, fold_norm_bound(rounds as u32)), "tampered round rejects");
    }

    #[test]
    fn ip_fold_completeness_and_compression() {
        let (rounds, base) = (3usize, 4usize);
        let n = base << rounds; // 32
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(10);
        let am = PolyMatrix::from_seed(kappa, n, 20);
        let bm = PolyMatrix::from_seed(kappa, n, 21);
        let a = PolyVec::sample_short(n, ETA, &mut prg);
        let b = PolyVec::sample_short(n, ETA, &mut prg);
        let (ta, tb) = (am.matvec(&a), bm.matvec(&b));
        let c = dot(&a, &b);
        let pf = prove_ip_fold(&am, &bm, &a, &b, &ta, &tb, &c, rounds);
        let bound = fold_norm_bound(rounds as u32);
        assert!(verify_ip_fold(&am, &bm, &ta, &tb, &c, &pf, bound), "honest IP fold verifies");
        let elts = pf.rounds.len() * (4 * kappa + 3) + 2 * pf.a_final.len();
        println!("IP_FOLD n={n} rounds={rounds} proof_ring_elts={elts} vs_reveal_ab={}", 2 * n);
    }

    #[test]
    fn ip_fold_rejects_wrong_inner_product() {
        let (rounds, base) = (3usize, 4usize);
        let n = base << rounds;
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(11);
        let am = PolyMatrix::from_seed(kappa, n, 20);
        let bm = PolyMatrix::from_seed(kappa, n, 21);
        let a = PolyVec::sample_short(n, ETA, &mut prg);
        let b = PolyVec::sample_short(n, ETA, &mut prg);
        let (ta, tb) = (am.matvec(&a), bm.matvec(&b));
        let c_true = dot(&a, &b);
        let c_wrong = c_true.add(&Poly::one());
        // Prover proves the TRUE inner product; verifier is told a WRONG one.
        let pf = prove_ip_fold(&am, &bm, &a, &b, &ta, &tb, &c_true, rounds);
        assert!(
            !verify_ip_fold(&am, &bm, &ta, &tb, &c_wrong, &pf, fold_norm_bound(rounds as u32)),
            "a wrong claimed inner product must reject"
        );
    }

    #[test]
    fn ip_fold_rejects_tampered_witness() {
        let (rounds, base) = (3usize, 4usize);
        let n = base << rounds;
        let kappa = crate::params::SIS_RANK_KAPPA;
        let mut prg = SplitMix64::new(12);
        let am = PolyMatrix::from_seed(kappa, n, 20);
        let bm = PolyMatrix::from_seed(kappa, n, 21);
        let a = PolyVec::sample_short(n, ETA, &mut prg);
        let b = PolyVec::sample_short(n, ETA, &mut prg);
        let (ta, tb) = (am.matvec(&a), bm.matvec(&b));
        let c = dot(&a, &b);
        let mut pf = prove_ip_fold(&am, &bm, &a, &b, &ta, &tb, &c, rounds);
        pf.a_final.0[0].c[0] = (pf.a_final.0[0].c[0] + 1) % Poly::Q;
        assert!(
            !verify_ip_fold(&am, &bm, &ta, &tb, &c, &pf, fold_norm_bound(rounds as u32)),
            "tampered witness rejects"
        );
    }

    #[test]
    fn bit_validity_via_ip_fold() {
        // The tx application: aᵢ ∈ {0,1} ⟺ ⟨a, a−1⟩ = Σ aᵢ(aᵢ−1) = 0.
        let (rounds, base) = (3usize, 4usize);
        let n = base << rounds; // 32 bits
        let kappa = crate::params::SIS_RANK_KAPPA;
        let am = PolyMatrix::from_seed(kappa, n, 20);
        let bm = PolyMatrix::from_seed(kappa, n, 21);
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = ((v % Poly::Q as i64 + Poly::Q as i64) % Poly::Q as i64) as u64;
            p
        };
        // A valid bit vector.
        let bits: Vec<u64> = (0..n).map(|i| ((i * 5 + 1) & 1) as u64).collect();
        let a = PolyVec(bits.iter().map(|&x| cst(x as i64)).collect());
        let b = PolyVec(a.0.iter().map(|ai| ai.sub(&Poly::one())).collect()); // a − 1
        let (ta, tb) = (am.matvec(&a), bm.matvec(&b));
        let c = dot(&a, &b);
        assert_eq!(c, Poly::zero(), "bits ⇒ ⟨a,a−1⟩ = 0");
        let pf = prove_ip_fold(&am, &bm, &a, &b, &ta, &tb, &c, rounds);
        // norm bound: bits/‖a−1‖ ≤ 1, times the fold growth.
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_ip_fold(&am, &bm, &ta, &tb, &c, &pf, bound), "bit-validity proof verifies");

        // A NON-bit (a₀ = 2): the real ⟨a,a−1⟩ ≠ 0, so proving c=0 is rejected.
        let mut a2 = a.clone();
        a2.0[0] = cst(2);
        let b2 = PolyVec(a2.0.iter().map(|ai| ai.sub(&Poly::one())).collect());
        let (ta2, tb2) = (am.matvec(&a2), bm.matvec(&b2));
        let pf2 = prove_ip_fold(&am, &bm, &a2, &b2, &ta2, &tb2, &Poly::zero(), rounds);
        assert!(
            !verify_ip_fold(&am, &bm, &ta2, &tb2, &Poly::zero(), &pf2, bound),
            "a non-bit must fail the ⟨a,a−1⟩ = 0 check"
        );
    }

    #[test]
    fn bits_fold_completeness_and_soundness() {
        let (rounds, base) = (3usize, 4usize);
        let n = base << rounds; // 32
        let kappa = crate::params::SIS_RANK_KAPPA;
        let a_mat = PolyMatrix::from_seed(kappa, n, 30);
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = ((v % Poly::Q as i64 + Poly::Q as i64) % Poly::Q as i64) as u64;
            p
        };
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        // Valid bits.
        let a = PolyVec((0..n).map(|i| cst(((i * 3 + 1) & 1) as i64)).collect());
        let (ta, pf) = prove_bits_fold(&a_mat, &a, rounds);
        assert!(verify_bits_fold(&a_mat, &ta, &pf, bound), "all-bit vector verifies");
        // One non-bit coordinate.
        let mut abad = a.clone();
        abad.0[3] = cst(2);
        let (ta2, pf2) = prove_bits_fold(&a_mat, &abad, rounds);
        assert!(!verify_bits_fold(&a_mat, &ta2, &pf2, bound), "a non-bit coordinate must reject");
    }

    #[test]
    #[ignore = "measurement: fold-based bit validity at balance scale (a few seconds)"]
    fn bits_fold_scales_to_balance() {
        // 512 bits (near the balance's 611) in ONE fold — where prove_bits_rq
        // hits the rejection wall. Measure size; scales, unlike the amortized form.
        let (rounds, base) = (6usize, 8usize);
        let n = base << rounds; // 512
        let kappa = crate::params::SIS_RANK_KAPPA;
        let a_mat = PolyMatrix::from_seed(kappa, n, 31);
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = v as u64;
            p
        };
        let a = PolyVec((0..n).map(|i| cst(((i * 7 + 1) & 1) as i64)).collect());
        let (ta, pf) = prove_bits_fold(&a_mat, &a, rounds);
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_bits_fold(&a_mat, &ta, &pf, bound), "512-bit validity verifies");
        let ring_elts = ta.len() + pf.rounds.len() * (2 * kappa + 3) + pf.a_final.len();
        let naive_kb = ring_elts * (4 + 256 * 8) / 1024;
        let compact_kb = bits_fold_compact_bytes(&ta, &pf) / 1024;
        println!(
            "BITS_FOLD n={n} rounds={rounds} ring_elts={ring_elts} naive~{naive_kb}KB compact~{compact_kb}KB — derived u_b,q_b (2κ+3/round); one fold for the whole balance's bit-validity (prove_bits_rq FAILS at this ℓ)"
        );
    }

    #[test]
    fn compact_codec_roundtrips_and_shrinks() {
        let mut prg = SplitMix64::new(77);
        let polys: Vec<Poly> = (0..5)
            .map(|_| Poly { c: (0..RING_DEGREE_D).map(|_| prg.uniform_below(Poly::Q as u128) as u64).collect() })
            .collect();
        let bits = crate::params::MODULUS_Q_BITS;
        let packed = pack_coeffs(&polys, bits);
        let back = unpack_coeffs(&packed, bits, polys.len());
        assert_eq!(back, polys, "compact codec round-trips at q-width");
        let naive = polys.len() * RING_DEGREE_D * 8;
        assert!(packed.len() * 100 < naive * 60, "compact is <60% of naive: {} vs {}", packed.len(), naive);
    }

    #[test]
    fn range_fold_binds_value_and_bits() {
        // A real range proof via folding: 32-bit value, bits + value binding.
        let (rounds, base) = (5usize, 1usize);
        let n = base << rounds; // 32
        let kappa = crate::params::SIS_RANK_KAPPA;
        let a_mat = PolyMatrix::from_seed(kappa, n, 40);
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = v as u64;
            p
        };
        let value: u64 = 0xABCD1234;
        let a = PolyVec((0..n).map(|i| cst(((value >> i) & 1) as i64)).collect());
        let (t_aug, pf) = prove_range_fold(&a_mat, &a, rounds);
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_range_fold(&a_mat, &t_aug, &pf, bound), "range proof verifies");
        // The augmented commitment's last coordinate is the bound value v.
        assert_eq!(t_aug.0[kappa], cst(value as i64), "value binding: ⟨2ⁱ,a⟩ = v");
        // A non-bit breaks it.
        let mut abad = a.clone();
        abad.0[0] = cst(2);
        let (t2, pf2) = prove_range_fold(&a_mat, &abad, rounds);
        assert!(!verify_range_fold(&a_mat, &t2, &pf2, bound), "a non-bit must reject");
        let elts = t_aug.len() + pf.rounds.len() * (2 * kappa + 3) + pf.a_final.len();
        println!("RANGE_FOLD n={n}(bits) rounds={rounds} ring_elts={elts} compact~{}KB", bits_fold_compact_bytes(&t_aug, &pf) / 1024);
    }

    #[test]
    fn membership_path_fold_real_multilevel() {
        // FULL multi-level membership via folding, REAL accumulator: a valid depth-D
        // path X = [x_0‖…‖x_{D-1}] (each x_ℓ = 2κδ real gadget limbs), with the
        // chaining `G·x_ℓ[:κδ] = B·x_{ℓ-1} = u_{ℓ-1}` (linear) aggregated into κ rows,
        // the Ajtai binding of X, and the root `B·x_{D-1}=root`. One opening fold.
        use crate::accumulator::{
            gadget_decompose, AccumulatorParams, ACC_GADGET_BASE_BITS, ACC_GADGET_LIMBS,
            ACC_NODE_RANK,
        };
        let kappa = ACC_NODE_RANK;
        let delta = ACC_GADGET_LIMBS;
        let width = 2 * kappa * delta; // 72 limbs per level
        let depth = 8;
        let n = depth * width;
        let params = AccumulatorParams::production(depth);
        let b = &params.b_hash; // κ × 2κδ
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = (v as u64) % Poly::Q;
            p
        };
        // G: κ × κδ gadget recompose (node_i = Σ_k 2^{7k}·limb_{iδ+k}).
        let g = {
            let mut m = vec![vec![Poly::zero(); kappa * delta]; kappa];
            for i in 0..kappa {
                for k in 0..delta {
                    m[i][i * delta + k] = cst(1i64 << (k as u32 * ACC_GADGET_BASE_BITS));
                }
            }
            PolyMatrix { rows: kappa, cols: kappa * delta, m }
        };
        // Build a VALID path forward: x_ℓ = [g⁻¹(u_{ℓ-1}); g⁻¹(sibling)], u_ℓ = B·x_ℓ.
        let mut prg = SplitMix64::new(95);
        let mut prev = PolyVec::sample_uniform_pm(kappa, (Poly::Q / 2) as i64, &mut prg); // leaf
        let mut x_all: Vec<Poly> = Vec::with_capacity(n);
        let mut nodes: Vec<PolyVec> = Vec::with_capacity(depth);
        for _ in 0..depth {
            let sib = PolyVec::sample_uniform_pm(kappa, (Poly::Q / 2) as i64, &mut prg);
            let mut x_l = gadget_decompose(&prev);
            x_l.0.extend(gadget_decompose(&sib).0);
            prev = b.matvec(&x_l); // u_ℓ
            nodes.push(prev.clone());
            x_all.extend(x_l.0);
        }
        let x = PolyVec(x_all);
        let root = nodes[depth - 1].clone();

        // Assemble the AGGREGATED constraint matrix M (rows: κ Ajtai + κ chaining + κ root).
        let place = |dst: &mut Vec<Vec<Poly>>, blk: &PolyMatrix, row0: usize, col0: usize, scale: &Poly| {
            for i in 0..blk.rows {
                for j in 0..blk.cols {
                    dst[row0 + i][col0 + j] = dst[row0 + i][col0 + j].add(&scale.mul_ntt(&blk.m[i][j]));
                }
            }
        };
        let one = Poly::one();
        let mut m = vec![vec![Poly::zero(); n]; 3 * kappa];
        let mut t = PolyVec::zero(3 * kappa);
        // (a) Ajtai binding rows [0,κ): random A·X = t_a.
        let a_ajtai = PolyMatrix::from_seed(kappa, n, 96);
        for i in 0..kappa {
            m[i] = a_ajtai.m[i].clone();
        }
        let t_a = a_ajtai.matvec(&x);
        for i in 0..kappa {
            t.0[i] = t_a.0[i].clone();
        }
        // (b) chaining rows [κ,2κ): aggregate ℓ=1..depth-1 of `G·x_ℓ[:κδ] − B·x_{ℓ-1} = 0`.
        let mut cprg = SplitMix64::new(97);
        for l in 1..depth {
            let rho = sample_in_ball(&mut cprg, CHALLENGE_WEIGHT_TAU);
            place(&mut m, &g, kappa, l * width, &rho); // +ρ·G on x_ℓ[:κδ]
            let neg_b = PolyMatrix { rows: kappa, cols: b.cols, m: b.m.iter().map(|r| r.iter().map(|p| p.neg()).collect()).collect() };
            place(&mut m, &neg_b, kappa, (l - 1) * width, &rho); // −ρ·B on x_{ℓ-1}
        }
        // (c) root rows [2κ,3κ): B·x_{D-1} = root.
        place(&mut m, b, 2 * kappa, (depth - 1) * width, &one);
        for i in 0..kappa {
            t.0[2 * kappa + i] = root.0[i].clone();
        }
        let m_full = PolyMatrix { rows: 3 * kappa, cols: n, m };
        assert_eq!(m_full.matvec(&x), t, "valid path satisfies the assembled constraints");

        // One opening fold over the real membership system.
        let rounds = 4; // n=576=2^6·9 ⇒ base 36; limbs<2⁷ ⇒ norm 2⁷·40⁴≈2²⁸ < 2³⁵
        let pf = prove_opening_fold(&m_full, &x, &t, rounds);
        let bound = 128u64 * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_opening_fold(&m_full, &t, &pf, bound), "real multi-level membership path verifies");
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let elts = pf.rounds.len() * 2 * m_full.rows + pf.s_final.len();
        println!(
            "MEMBERSHIP_PATH depth={depth} n={n} rows={} rounds={rounds} compact~{}KB (real B+G, aggregated chaining)",
            m_full.rows, elts * per / 1024
        );
    }

    #[test]
    fn membership_fold_real_accumulator_hash() {
        // REAL matrix plumbing: prove one actual accumulator hash level
        // `u = H_B(u_L,u_R) = B·[g⁻¹(u_L); g⁻¹(u_R)]` via the opening fold, using the
        // production `b_hash` (κ×2κδ=6×72) and real gadget decomposition (base 2⁷).
        use crate::accumulator::{gadget_decompose, AccumulatorParams, ACC_NODE_RANK};
        let params = AccumulatorParams::production(32);
        let b = &params.b_hash;
        let mut prg = SplitMix64::new(90);
        // Two child nodes ∈ R_q^κ; their real gadget limbs form the 2κδ hash input.
        let u_l = PolyVec::sample_uniform_pm(ACC_NODE_RANK, (Poly::Q / 2) as i64, &mut prg);
        let u_r = PolyVec::sample_uniform_pm(ACC_NODE_RANK, (Poly::Q / 2) as i64, &mut prg);
        let mut x = gadget_decompose(&u_l);
        x.0.extend(gadget_decompose(&u_r).0); // [g⁻¹(u_L); g⁻¹(u_R)], 2κδ = 72 short limbs
        assert_eq!(x.len(), b.cols, "hash input width = 2κδ");
        let u = b.matvec(&x); // = H_B(u_L, u_R), the real node hash
        // Prove knowledge of the short limbs opening this real hash.
        let rounds = 3; // 72 = 8·9 ⇒ base 9; limbs < 2⁷ ⇒ norm 2⁷·40³ ≈ 2²³ < 2³⁵
        let pf = prove_opening_fold(b, &x, &u, rounds);
        let bound = 128u64 * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(
            verify_opening_fold(b, &u, &pf, bound),
            "real accumulator hash level verifies via the opening fold"
        );
    }

    #[test]
    fn membership_fold_via_opening() {
        // The accumulator PATH `H_B(u_L,u_R) = B·[g⁻¹(u_L); g⁻¹(u_R)]` is a LINEAR
        // relation `M·X = T` on SHORT gadget limbs (base 2¹⁴, δ=2 ⇒ ‖limb‖ < 2⁷,
        // accumulator.rs). A depth-32 path ≈ 32·(2κδ=24) = 768 limbs. Proven by the
        // opening fold ⇒ O(κ·rounds), vs the current O(depth) full sub-proofs.
        // (Real `M` = the aggregated B + gadget-consistency rows; here a
        // representative random public matrix — the fold shape is identical.)
        let n = 32 * 24; // 768 gadget limbs (depth 32)
        let kappa = crate::params::SIS_RANK_KAPPA;
        let m = PolyMatrix::from_seed(kappa, n, 50);
        let mut prg = SplitMix64::new(51);
        let x = PolyVec::sample_uniform_pm(n, 64, &mut prg); // ‖X‖∞ ≤ 2⁶ (short limbs)
        let t = m.matvec(&x);
        let rounds = 5; // norm: 2⁶·(1+τ)⁵ ≈ 2³³·⁶ < 2³⁵ budget
        let pf = prove_opening_fold(&m, &x, &t, rounds);
        let bound = 64u64 * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_opening_fold(&m, &t, &pf, bound), "membership-sized linear relation verifies");
        let elts = pf.rounds.len() * 2 * kappa + pf.s_final.len();
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        println!(
            "MEMBERSHIP_FOLD n={n}(limbs) rounds={rounds} ring_elts={elts} compact~{}KB (vs ~20MB current depth-32 membership)",
            elts * per / 1024
        );
    }

    #[test]
    #[ignore = "measurement: whole confidential tx via folding (assembles all components)"]
    fn tx_fold_whole_size() {
        let kappa = crate::params::SIS_RANK_KAPPA;
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = ((v % Poly::Q as i64 + Poly::Q as i64) % Poly::Q as i64) as u64;
            p
        };

        // ── Component 1: ALL bits (range + balance, ~611 → 1024) + value binding.
        let n_bits = 1024;
        let a_bits = PolyVec((0..n_bits).map(|i| cst(((i * 7 + 1) & 1) as i64)).collect());
        let a_mat = augment_with_value_row(&PolyMatrix::from_seed(kappa, n_bits, 60));
        let (t_bits, bits_pf) = prove_bits_fold(&a_mat, &a_bits, 6);
        let bound_b = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(6);
        assert!(verify_bits_fold(&a_mat, &t_bits, &bits_pf, bound_b), "bits+value fold verifies");
        let bits_bytes = bits_fold_compact_bytes(&t_bits, &bits_pf);

        // ── Component 2: membership (depth 32, 768 gadget limbs), all LINEAR.
        let n_mem = 768;
        let m_mem = PolyMatrix::from_seed(kappa, n_mem, 61);
        let mut prg = SplitMix64::new(62);
        let x_mem = PolyVec::sample_uniform_pm(n_mem, 64, &mut prg);
        let t_mem = m_mem.matvec(&x_mem);
        let mem_pf = prove_opening_fold(&m_mem, &x_mem, &t_mem, 5);
        let bound_m = 64u64 * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(5);
        assert!(verify_opening_fold(&m_mem, &t_mem, &mem_pf, bound_m), "membership fold verifies");
        let mem_bytes = (mem_pf.rounds.len() * 2 * kappa + mem_pf.s_final.len()) * per;

        let total_kb = (bits_bytes + mem_bytes) / 1024;
        println!(
            "TX_FOLD_WHOLE bits+value~{}KB membership~{}KB TOTAL~{}KB (vs ~54MB current tx; ~{}× ) — all components via folding, scales, covers membership",
            bits_bytes / 1024,
            mem_bytes / 1024,
            total_kb,
            54 * 1024 / total_kb.max(1)
        );
    }

    #[test]
    fn tx_fold_unified_verifies_and_measures() {
        // The whole tx as ONE fold over an ALL-BITS witness (amount bits + gadget
        // limbs bit-decomposed) under the full constraint matrix M. One commitment
        // binds everything: W∈{0,1} AND M·W=t (commitment + value + membership).
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = (v as u64) % Poly::Q;
            p
        };
        // ~611 amount bits + ~5400 membership-limb bits (768 limbs × 7 bits) ⇒ 8192.
        let n = 8192;
        let w = PolyVec((0..n).map(|i| cst(((i * 7 + 1) & 1) as i64)).collect());
        // M = aggregated Ajtai commitment + value-binding + membership-chain rows.
        let m_full = augment_with_value_row(&PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 71));
        let rounds = 6;
        let pf = prove_tx_fold(&m_full, &w, rounds);
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        assert!(verify_tx_fold(&m_full, &pf, bound), "unified all-bits tx fold verifies");
        let kb = tx_fold_compact_bytes(&pf) / 1024;
        println!(
            "TX_FOLD_UNIFIED n={n}(all bits) rounds={rounds} ONE-proof compact~{kb}KB — bit-validity AND all linear (commit+value+membership) in ONE fold, ONE commitment"
        );
    }

    #[test]
    #[ignore = "perf measurement: whole-tx fold prove/verify time"]
    fn tx_fold_timing() {
        use std::time::Instant;
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = (v as u64) % Poly::Q;
            p
        };
        let n = 8192;
        let w = PolyVec((0..n).map(|i| cst(((i * 7 + 1) & 1) as i64)).collect());
        let m = augment_with_value_row(&PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 71));
        let rounds = 6;
        let t0 = Instant::now();
        let pf = prove_tx_fold(&m, &w, rounds);
        let prove_ms = t0.elapsed().as_millis();
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rounds as u32);
        let t1 = Instant::now();
        let ok = verify_tx_fold(&m, &pf, bound);
        let verify_ms = t1.elapsed().as_millis();
        assert!(ok);
        println!("TX_FOLD_TIMING n={n} rounds={rounds} prove={prove_ms}ms verify={verify_ms}ms (dev build)");
    }

    #[test]
    fn tx_fold_hides_value() {
        // CONFIDENTIAL value binding: v = ⟨2ⁱ,bits⟩ is committed as C = v + ⟨wρ, ρ⟩
        // with short randomness ρ IN the witness. Only C is public; ρ hides v.
        // Structurally: W = [amount_bits ‖ randomness_bits], and the value‑commitment
        // row goes into M with public target C (never the plaintext v).
        let kappa = crate::params::SIS_RANK_KAPPA;
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = ((v % Poly::Q as i64 + Poly::Q as i64) % Poly::Q as i64) as u64;
            p
        };
        let (n_bits, n_rand) = (32usize, 32usize);
        let n = n_bits + n_rand;
        let value: u64 = 0xABCD1234 & ((1 << n_bits) - 1);
        let mut prg = SplitMix64::new(80);
        let mut w: Vec<Poly> = (0..n_bits).map(|i| cst(((value >> i) & 1) as i64)).collect();
        w.extend((0..n_rand).map(|_| cst((prg.next_u64() & 1) as i64))); // randomness bits ρ
        let w = PolyVec(w);

        // M = Ajtai(κ×n) + ONE value‑commitment row: 2ⁱ on the amount bits, random
        // public weights on ρ. The row's committed value is C = v + ⟨wρ,ρ⟩ (hiding).
        let mut m_full = PolyMatrix::from_seed(kappa, n, 81);
        let mut vrow: Vec<Poly> = (0..n_bits).map(|i| cst(1i64 << i)).collect();
        let mut wprg = SplitMix64::new(82);
        vrow.extend((0..n_rand).map(|_| cst((wprg.next_u64() % Poly::Q) as i64)));
        m_full.m.push(vrow);
        m_full.rows += 1;

        let pf = prove_tx_fold(&m_full, &w, 5);
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(5);
        assert!(verify_tx_fold(&m_full, &pf, bound), "hiding-value tx fold verifies");
        // The public commitment coordinate C = v + ⟨wρ,ρ⟩ ≠ the plaintext value.
        let c_public = pf.t.0[kappa].clone();
        assert_ne!(c_public, cst(value as i64), "C hides v (public C ≠ plaintext v)");
        println!("TX_FOLD_HIDING v bound to a hiding commitment C (v NOT in the public proof); verifies");
    }

    #[test]
    fn tx_fold_rejects_tampered() {
        let cst = |v: i64| {
            let mut p = Poly::zero();
            p.c[0] = (v as u64) % Poly::Q;
            p
        };
        let n = 256;
        let w = PolyVec((0..n).map(|i| cst((i & 1) as i64)).collect());
        let m_full = augment_with_value_row(&PolyMatrix::from_seed(crate::params::SIS_RANK_KAPPA, n, 74));
        let mut pf = prove_tx_fold(&m_full, &w, 5);
        let bound = (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(5);
        assert!(verify_tx_fold(&m_full, &pf, bound));
        pf.fold.a_final.0[0].c[0] = (pf.fold.a_final.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_tx_fold(&m_full, &pf, bound), "tampered tx fold rejects");
    }

    #[test]
    fn deep_fold_vs_single_kernel_attempt() {
        // KERNEL ATTEMPT: does norm-refresh recursion beat the single fold's floor?
        let kappa = crate::params::SIS_RANK_KAPPA;
        let n = 2048;
        let m = PolyMatrix::from_seed(kappa, n, 200);
        let mut prg = SplitMix64::new(201);
        let s = PolyVec::sample_uniform_pm(n, 32, &mut prg); // ‖s‖ ≤ 2^5 short
        let t = m.matvec(&s);
        let (bits, limbs) = (18u32, 2usize); // limbs=2 keeps dims power-of-2 aligned

        // Single fold: 5 rounds (norm cap) ⇒ base 2048/32 = 64 REVEALED.
        let single = prove_opening_fold(&m, &s, &t, 5);
        assert!(verify_opening_fold(&m, &t, &single, 32 * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(5)));
        let single_elts = single.rounds.len() * 2 * kappa + single.s_final.len();

        // Deep fold: 3 rounds + 3 refreshes (decompose re-shortens ⇒ base tiny).
        let (rp, rf) = (3usize, 3usize);
        let deep = prove_opening_fold_deep(&m, &s, &t, rp, rf, bits, limbs);
        let deep_bound = (1u64 << (bits - 1)) * (CHALLENGE_WEIGHT_TAU as u64 + 1).pow(rp as u32);
        assert!(
            verify_opening_fold_deep(&m, &t, &deep, rp, rf, bits, limbs, deep_bound),
            "deep fold is a VALID proof"
        );
        let deep_elts = deep.rounds.len() * 2 * kappa + deep.s_final.len();

        println!(
            "DEEP_FOLD_KERNEL single: base={} elts={} | deep: base={} elts={} ⇒ deep {} the single fold",
            single.s_final.len(),
            single_elts,
            deep.s_final.len(),
            deep_elts,
            if deep_elts < single_elts { "BEATS" } else { "does NOT beat" }
        );
    }

    #[test]
    fn labrador_reduction_faithful() {
        // Paper §5.2 one-level reduction with COMMITTED garbage (the mechanism the
        // round-by-round folds lack). Completeness + soundness + the key property:
        // only u1+z are SENT; the O(r²) garbage is committed (recursed, not sent).
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r, n) = (4usize, 32usize);
        let mut prg = SplitMix64::new(300);
        let a = PolyMatrix::from_seed(kappa, n, 301);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let mut cons = Vec::new();
        for i in 0..r {
            for j in i..r {
                cons.push(QuadConstraint::quad(vec![(i, j, Poly::one())], dot(&s[i], &s[j])));
            }
        }
        let agg = aggregate_constraints(&cons);
        let (bits, limbs) = (18u32, 2usize);
        let tg_len = r * kappa + (r * r + r) / 2;
        let b_outer = PolyMatrix::from_seed(kappa, tg_len * limbs, 302);
        let pf = prove_labrador_reduction(&a, &b_outer, &s, bits, limbs);
        let bound = (r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * (ETA as u64);
        assert!(
            verify_labrador_reduction(&a, &b_outer, &pf, &agg, bits, limbs, bound),
            "faithful reduction verifies"
        );
        let per = (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
        let sent = (pf.u1.len() + pf.z.len()) * per;
        println!(
            "LABRADOR_REDUCTION r={r} n={n} sent(u1+z)={}B; garbage_committed={} elts (NOT sent — becomes child witness)",
            sent,
            (r * r + r) / 2
        );
        // Soundness: tampering garbage breaks the outer commitment (1) AND ⟨z,z⟩ (3).
        let mut bad = pf.clone();
        bad.g[1][2] = bad.g[1][2].add(&Poly::one());
        bad.g[2][1] = bad.g[1][2].clone();
        assert!(
            !verify_labrador_reduction(&a, &b_outer, &bad, &agg, bits, limbs, bound),
            "tampered garbage rejects"
        );
    }

    fn base_relation(r: usize, n: usize, seed: u64) -> (Vec<QuadConstraint>, Vec<PolyVec>) {
        let mut prg = SplitMix64::new(seed);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let mut fam = Vec::new();
        for i in 0..r {
            for j in i..r {
                fam.push(QuadConstraint::quad(vec![(i, j, Poly::one())], dot(&s[i], &s[j])));
            }
        }
        (fam, s)
    }

    #[test]
    fn galois_trace_extracts_constant_term() {
        // Tr(Y) = Σ_{k odd} σ_k(Y) = d·ct(Y)·1 — the EXACT ct→whole-ring conversion.
        // So ct(Y)=τ becomes the WHOLE-RING equation Tr(Y) = d·τ·1, which folds.
        let mut prg = SplitMix64::new(0x77ACE);
        let d = Poly::D as u64;
        for _ in 0..16 {
            let mut y = Poly::zero();
            for k in 0..Poly::D {
                y.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            let tr = galois_trace(&y);
            // Tr(Y) must be the scalar d·Y_0 (constant poly, no higher terms).
            let want0 = ((d as u128 * y.c[0] as u128) % Poly::Q as u128) as u64;
            assert_eq!(tr.c[0], want0, "Tr(Y)_0 = d·ct(Y)");
            for k in 1..Poly::D {
                assert_eq!(tr.c[k], 0, "Tr(Y) has no higher-degree terms (it is a scalar)");
            }
        }
        // σ_k is an automorphism: σ_1 = identity, σ_{2d−1} = conjugate.
        let mut prg2 = SplitMix64::new(0x9);
        let mut a = Poly::zero();
        for k in 0..Poly::D {
            a.c[k] = prg2.uniform_below(Poly::Q as u128) as u64;
        }
        assert_eq!(apply_auto(&a, 1), a, "σ_1 = id");
        assert_eq!(apply_auto(&a, 2 * Poly::D - 1), a.conjugate(), "sigma_2d_minus_1 = conjugate");
    }

    #[test]
    fn ct_binary_folds_via_trace_conversion() {
        // The full ct→whole-ring path for the packed binary. The binary defect is
        // ct(W), W = σ(b)·b − σ(J)·b. Converting via the trace, Tr(W) = d·ct(W) is
        // a WHOLE-RING element that (a) is ZERO iff b is coefficient-binary, and
        // (b) is a conjugated whole-ring form the ĝ machinery folds. So a ct
        // (constant-term) constraint becomes a foldable whole-ring constraint.
        let j = Poly { c: vec![1u64; Poly::D] }; // all-ones
        let make = |bits: &[u64]| {
            let mut b = Poly::zero();
            for (k, &v) in bits.iter().enumerate() {
                b.c[k] = v;
            }
            let w = b.conjugate().mul_ntt(&b).sub(&j.conjugate().mul_ntt(&b));
            (b, galois_trace(&w))
        };
        // Valid bit vector → Tr(W) = 0 (whole ring).
        let valid: Vec<u64> = (0..Poly::D).map(|k| (k as u64) & 1).collect();
        let (_b, tr_valid) = make(&valid);
        assert_eq!(tr_valid, Poly::zero(), "valid bits ⇒ Tr(W)=0 ⇒ ct(W)=0");
        // Non-bit coefficient → Tr(W) ≠ 0.
        let mut bad = valid.clone();
        bad[10] = 2;
        let (_b2, tr_bad) = make(&bad);
        assert_ne!(tr_bad, Poly::zero(), "a non-bit ⇒ Tr(W)≠0 ⇒ ct(W)≠0");
    }

    #[test]
    fn ct_constraint_aggregation_is_sound() {
        // L ct-constraints aggregate into 1: all-satisfied ⇒ aggregate satisfied;
        // any violated ⇒ aggregate violated (random-ω Schwartz-Zippel over Z_q).
        let mut prg = SplitMix64::new(0xC7A66);
        let (r, n) = (5usize, 6usize);
        let s: Vec<PolyVec> = (0..r).map(|_| rand_short_vec(n, 4, &mut prg)).collect();
        // Build satisfied ct-constraints (target = actual value).
        let mk = |terms: Vec<(usize, usize, i64)>, lin: Vec<(usize, PolyVec)>| {
            let c0 = CtConstraint { terms, linear: lin, target: 0 };
            let t = eval_ct_on_witness(&c0, &s);
            CtConstraint { target: t, ..c0 }
        };
        let fam = vec![
            mk(vec![(0, 0, 1)], vec![]),
            mk(vec![(1, 2, 3)], vec![(3, s[3].clone())]),
            mk(vec![(4, 4, 2), (0, 1, 1)], vec![]),
        ];
        let agg = aggregate_ct_constraints(&fam, b"bind");
        assert_eq!(eval_ct_on_witness(&agg, &s), agg.target % Poly::Q, "all-satisfied ⇒ aggregate holds");

        // Violate ONE constraint (bump its target) ⇒ aggregate fails w.h.p.
        let mut fails = 0;
        for t in 0..8u64 {
            let mut bad = fam.clone();
            bad[1].target = (bad[1].target + 1) % Poly::Q;
            let a = aggregate_ct_constraints(&bad, &t.to_le_bytes());
            if eval_ct_on_witness(&a, &s) != a.target % Poly::Q {
                fails += 1;
            }
        }
        assert_eq!(fails, 8, "a violated ct-constraint must fail the aggregate every time");
    }

    #[test]
    fn conjugated_family_folds_through_recursion() {
        // The ĝ-region surgery: a family with a WHOLE-RING conjugated constraint
        // `⟨σ(s_0),s_0⟩ = ĝ_00` folds through the has_conj recursion (ĝ committed,
        // bound by (3d), the aggregate's conj_terms ride the ĝ positions). Honest
        // verifies; a tampered conjugated target rejects.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, n0, beta0) = (4usize, 64usize, ETA as u64);
        let (mut fam, s) = base_relation(r0, n0, 0xC04A);
        // Add a conjugated constraint with its HONEST target.
        let ct_target = conj_dot(&s[0], &s[0]);
        fam.push(QuadConstraint {
            terms: vec![],
            conj_terms: vec![(0, 0, Poly::one())],
            linear: vec![],
            b: ct_target,
        });
        let seed = 0xC0FFEE_A5;
        for levels in [1usize, 2] {
            let sched = level_schedule_conj(r0, n0, beta0, kappa, 18, 0, levels, true);
            assert!(sched.iter().all(|sh| sh.has_conj), "schedule carries has_conj");
            let pf = prove_labrador_recursive(&fam, &s, beta0, kappa, &sched, seed);
            assert!(
                verify_labrador_recursive(&fam, beta0, kappa, &sched, seed, &pf),
                "conjugated family must verify at {levels} level(s)"
            );
            // Tampered conjugated target → reject.
            let mut bad = fam.clone();
            let last = bad.len() - 1;
            bad[last].b = bad[last].b.add(&Poly::one());
            assert!(
                !verify_labrador_recursive(&bad, beta0, kappa, &sched, seed, &pf),
                "tampered conjugated target must reject at {levels} level(s)"
            );
        }
    }

    #[test]
    fn recursion_driver_composes_and_binds() {
        // The DRIVER: run the reduction N levels, base-case the last, and check
        // the whole chain verifies — the multi-level composition of the kernel.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (bits, limbs) = (18u32, 2usize);
        let (r0, n0, beta0) = (4usize, 64usize, ETA as u64);
        let (family0, s0) = base_relation(r0, n0, 9001);
        let seed = 0xC0FFEE;

        for levels_cap in [1usize, 2] {
            // n_floor=0 ⇒ exactly `levels_cap` reductions (force multi-level).
            let schedule = level_schedule(r0, n0, beta0, kappa, bits, 0, levels_cap);
            assert_eq!(schedule.len(), levels_cap, "forced {levels_cap} levels");
            let pf = prove_labrador_recursive(&family0, &s0, beta0, kappa, &schedule, seed);
            assert!(
                verify_labrador_recursive(&family0, beta0, kappa, &schedule, seed, &pf),
                "honest {levels_cap}-level recursion verifies"
            );
            let last = schedule.last().unwrap();
            let final_r = 2 * last.nu + last.mu;
            let final_n = pf.final_s.first().map(|v| v.len()).unwrap_or(0);
            println!(
                "DRIVER levels={} final(r={final_r},n={final_n}) proof={}B (u1s={} + final_s={} polys) — r explodes w/ r² garbage; NS22 needed",
                schedule.len(),
                pf.size_bytes(),
                pf.u1s.iter().map(|(a,b)| a.len()+b.len()).sum::<usize>(),
                pf.final_s.iter().map(|v| v.len()).sum::<usize>(),
            );

            // Binding: tamper the final witness → some final constraint fails.
            let mut bad = pf.clone();
            bad.final_s[0].0[0] = bad.final_s[0].0[0].add(&Poly::one());
            assert!(
                !verify_labrador_recursive(&family0, beta0, kappa, &schedule, seed, &bad),
                "tampered final witness rejects"
            );
            // Binding: tamper a level's outer commitment → challenges shift, chain breaks.
            let mut bad2 = pf.clone();
            bad2.u1s[0].0.0[0] = bad2.u1s[0].0.0[0].add(&Poly::one());
            assert!(
                !verify_labrador_recursive(&family0, beta0, kappa, &schedule, seed, &bad2),
                "tampered outer commitment rejects"
            );
        }
    }

    #[test]
    fn recursion_zk_base_composes_and_binds() {
        // Step 4c: the recursion with a PERFECT-ZK base. Fold N levels, then open the
        // final family via the masked base opening (never revealing final_s). Honest
        // verifies; a tampered outer commitment (challenges shift) rejects; a
        // corrupted base response rejects.
        let kappa = crate::params::SIS_RANK_KAPPA;
        // SMALL bits ⇒ small base-witness norm β (gadget limbs ≤ 2^{bits-1}), which
        // the rejection-sampled base opening needs (a large β kills acceptance over
        // the witness dimension). 1 level keeps r from exploding (r² garbage). The
        // base opening is separately validated at width in masked_base_opening_zk_*.
        let bits = 4u32;
        let (r0, n0, beta0) = (2usize, 6usize, ETA as u64);
        let (family0, s0) = base_relation(r0, n0, 9001);
        let seed = 0xC0FFEE;

        for levels_cap in [1usize] {
            let schedule = level_schedule(r0, n0, beta0, kappa, bits, 0, levels_cap);
            assert_eq!(schedule.len(), levels_cap, "forced {levels_cap} levels");
            let pf = prove_labrador_recursive_zk(&family0, &s0, beta0, kappa, &schedule, seed)
                .expect("zk recursion proves");
            assert!(
                verify_labrador_recursive_zk(&family0, beta0, kappa, &schedule, seed, &pf),
                "honest {levels_cap}-level ZK recursion verifies"
            );

            // Tamper a level's outer commitment → fold challenges shift → base rejects.
            let mut bad = RecursiveZkProof {
                u1s: pf.u1s.clone(),
                base: MaskedBaseOpening { u: pf.base.u.clone(), shots: pf.base.shots.clone() },
            };
            bad.u1s[0].0.0[0] = bad.u1s[0].0.0[0].add(&Poly::one());
            assert!(
                !verify_labrador_recursive_zk(&family0, beta0, kappa, &schedule, seed, &bad),
                "tampered outer commitment rejects"
            );

            // Corrupt a base response → z-opening binding fails.
            let mut bad2 = RecursiveZkProof {
                u1s: pf.u1s.clone(),
                base: MaskedBaseOpening { u: pf.base.u.clone(), shots: pf.base.shots.clone() },
            };
            bad2.base.shots[0].z.0[0] = bad2.base.shots[0].z.0[0].add(&Poly::one());
            assert!(
                !verify_labrador_recursive_zk(&family0, beta0, kappa, &schedule, seed, &bad2),
                "corrupted base response rejects"
            );
        }
    }

    #[test]
    fn ns22_linear_reduces_and_binds() {
        // NS22: r² linear garbage → 2r−1, via sequential challenges. Completeness
        // (the identity holds on the honest opening) + soundness (tampering a
        // reduced garbage poly, keeping the SAME challenges, breaks the identity).
        let mut prg = SplitMix64::new(5150);
        let (r, n) = (6usize, 24usize);
        let phi: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let pf = prove_ns22_linear(&phi, &s, b"test");
        let mut z = PolyVec::zero(n);
        for i in 0..r {
            z = z.add(&s[i].mul_poly(&pf.c[i]));
        }
        assert!(verify_ns22_linear(&phi, &z, &pf, b"test").is_some(), "honest NS22 linear verifies");
        // 2r−1 nonzero: h_odd[0] must be 0 (empty sum).
        assert_eq!(pf.h_odd[0].inf_norm(), 0, "h_1 = 0");
        let nonzero = pf.h_odd.iter().skip(1).filter(|p| p.inf_norm() != 0).count()
            + pf.h_even.iter().filter(|p| p.inf_norm() != 0).count();
        println!("NS22_LINEAR r={r} garbage_sent={} polys (was r²={})", 2 * r - 1, r * r);
        assert!(nonzero <= 2 * r - 1, "at most 2r−1 nonzero garbage");
        // Soundness: tamper a diagonal h_even (challenge-independent) — identity breaks.
        let mut bad = Ns22Linear { c: pf.c.clone(), h_odd: pf.h_odd.clone(), h_even: pf.h_even.clone() };
        bad.h_even[2] = bad.h_even[2].add(&Poly::one());
        // Re-derivation of c would differ (h_even is absorbed), so verify must reject.
        assert!(verify_ns22_linear(&phi, &z, &bad, b"test").is_none(), "tampered diagonal rejects");
    }

    #[test]
    fn full_pipeline_end_to_end_compact() {
        // The WHOLE thing: decompose levels + no-decompose last + NS22 base,
        // measured at the compact (§5.7) wire. Honest verify + the real size.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, beta0, n0) = (4usize, ETA as u64, 512usize);
        // §5.4 EXPERIMENT: sweep the per-level gadget floor `min_bits`. min_bits=1
        // ⇒ pure norm-balanced gadget (digit width = base_z, short witness, but
        // many limbs); larger ⇒ coarser gadget (fewer limbs, smaller base_r/t).
        for min_bits in [1u32, 4, 8, 12, 18] {
            let schedule = level_schedule(r0, n0, beta0, kappa, min_bits, 100, 8);
            let (family0, s0) = base_relation(r0, n0, 0xD00D);
            let seed = 0xF01;
            let pf = prove_labrador_full(&family0, &s0, beta0, kappa, &schedule, seed);
            assert!(
                verify_labrador_full(&family0, beta0, kappa, &schedule, seed, &pf),
                "honest full pipeline verifies (min_bits={min_bits})"
            );
            let fat = (pf.u1s.iter().map(|(a,b)| a.len()+b.len()).sum::<usize>() + pf.base.size_polys())
                * (RING_DEGREE_D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);
            let per_level_bits: Vec<u32> = schedule.iter().map(|s| s.bits).collect();
            println!(
                "FULL n0={n0} min_bits={min_bits} levels={} compact={}KB (fat={}KB) base_r={} base_n={} bits={:?}",
                schedule.len(),
                pf.compact_bytes() / 1024,
                fat / 1024,
                schedule.last().unwrap().nu + schedule.last().unwrap().mu,
                pf.n_last,
                per_level_bits,
            );
        }
    }

    #[test]
    fn jl_projection_preserves_norm_and_binds() {
        // Empirically verify Lemma 4.1: ‖Π·w‖₂ concentrates around √128·‖w‖₂ and
        // stays in [√30, √337]·‖w‖₂. Then the norm check: an honest short witness
        // passes ‖p‖ ≤ √30·b at a b ≈ 2‖s‖, and a witness with ‖s‖ > b fails.
        let mut prg = SplitMix64::new(9001);
        let (r, n) = (4usize, 64usize);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let w = flatten_coeffs(&s);
        let wn2 = (w.iter().map(|&x| (x * x) as u128).sum::<u128>() as f64).sqrt();
        // Average the ratio over several projections.
        let mut ratios = Vec::new();
        for seed in 0..8u64 {
            let p = jl_project(&s, 0x5A17 ^ seed);
            let pn2 = (l2_sq(&p) as f64).sqrt();
            ratios.push(pn2 / wn2);
        }
        let avg = ratios.iter().sum::<f64>() / ratios.len() as f64;
        println!("JL ‖p‖/‖w‖ avg={avg:.2} (√128≈11.31); per-proj={ratios:?}");
        assert!(ratios.iter().all(|&x| x >= 30f64.sqrt() && x <= 337f64.sqrt()), "JL band [√30,√337]");

        // Norm-bound check: choose b so ‖p‖ ≤ √30·b passes for the honest witness.
        let p = jl_project(&s, 0x5A17);
        let pn2 = (l2_sq(&p) as f64).sqrt();
        let b_ok = (pn2 / 30f64.sqrt()).ceil() as u128 + 1;
        assert!(jl_norm_ok(&p, b_ok), "honest witness within b passes");
        // A witness scaled 100× has ‖s‖ ≫ b_ok → its projection fails the same b.
        let big: Vec<PolyVec> = s.iter().map(|v| v.scalar_mul(100)).collect();
        let pb = jl_project(&big, 0x5A17);
        assert!(!jl_norm_ok(&pb, b_ok), "a large witness fails the same bound");
        // Out-of-range b (≥ q/125) is rejected.
        assert!(!jl_norm_ok(&p, (Poly::Q as u128) / 125), "b ≥ q/125 rejected");
    }

    #[test]
    fn base_case_send_witness_vs_ns22_compact() {
        // Two base-case strategies at the compact wire:
        //  (A) send the residual witness (all parts short) — NO commitment `t`;
        //  (B) NS22 base (t + z + O(r) garbage).
        // Whichever is smaller is the right base. (A) removes `t` entirely.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r0, beta0, n0) = (4usize, ETA as u64, 512usize);
        let min_bits = 18u32;
        let schedule = level_schedule(r0, n0, beta0, kappa, min_bits, 100, 8);
        let (family0, s0) = base_relation(r0, n0, 0xD00D);
        let seed = 0xF01;
        // (A) recursive driver, send-witness base.
        let rp = prove_labrador_recursive(&family0, &s0, beta0, kappa, &schedule, seed);
        assert!(verify_labrador_recursive(&family0, beta0, kappa, &schedule, seed, &rp));
        // (B) full pipeline, NS22 base.
        let fp = prove_labrador_full(&family0, &s0, beta0, kappa, &schedule, seed);
        assert!(verify_labrador_full(&family0, beta0, kappa, &schedule, seed, &fp));
        println!(
            "BASE_COMPARE (A) send-witness compact={}KB (final_s={} polys) vs (B) NS22 compact={}KB (t={} polys)",
            rp.compact_bytes() / 1024,
            rp.final_s.iter().map(|v| v.len()).sum::<usize>(),
            fp.compact_bytes() / 1024,
            fp.base.t.iter().map(|v| v.len()).sum::<usize>(),
        );
    }

    #[test]
    fn full_pipeline_rejects_tampering() {
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (bits, limbs) = (18u32, 2usize);
        let (family0, s0) = base_relation(4, 256, 0x1234);
        let schedule = level_schedule(4, 256, ETA as u64, kappa, bits, 100, 8);
        let seed = 0xF02;
        let pf = prove_labrador_full(&family0, &s0, ETA as u64, kappa, &schedule, seed);
        assert!(verify_labrador_full(&family0, ETA as u64, kappa, &schedule, seed, &pf));
        // Tamper the base opening.
        let mut bad = pf.clone();
        bad.base.z.0[0] = bad.base.z.0[0].add(&Poly::one());
        assert!(!verify_labrador_full(&family0, ETA as u64, kappa, &schedule, seed, &bad), "tampered base z rejects");
        // Tamper an intermediate outer commitment.
        let mut bad2 = pf.clone();
        bad2.u1s[0].0.0[0] = bad2.u1s[0].0.0[0].add(&Poly::one());
        assert!(!verify_labrador_full(&family0, ETA as u64, kappa, &schedule, seed, &bad2), "tampered u1 rejects");
    }

    #[test]
    fn base_ns22_proves_diagonal_relation_compactly() {
        // The NS22 base case: prove Σaᵢᵢ⟨sᵢ,sᵢ⟩+Σ⟨φᵢ,sᵢ⟩=b, A·sᵢ=tᵢ, ‖s‖≤β by
        // sending t+z+O(r) garbage instead of the full r·n witness.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r, n) = (7usize, 64usize);
        let mut prg = SplitMix64::new(2718);
        let a = PolyMatrix::from_seed(kappa, n, 2719);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let phi: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let a_diag: Vec<Poly> = (0..r).map(|_| sample_in_ball(&mut prg, CHALLENGE_WEIGHT_TAU)).collect();
        // The honest target b = Σ aᵢᵢ⟨sᵢ,sᵢ⟩ + Σ⟨φᵢ,sᵢ⟩.
        let mut b = Poly::zero();
        for i in 0..r {
            b = b.add(&a_diag[i].mul_ntt(&dot(&s[i], &s[i])));
            b = b.add(&dot(&phi[i], &s[i]));
        }
        let beta = (r as u64) * (CHALLENGE_WEIGHT_TAU as u64) * (ETA as u64);
        let pf = prove_base_ns22(&a, &s, &phi, &a_diag, &b, b"base");
        assert!(verify_base_ns22(&a, &phi, &a_diag, &b, beta, &pf, b"base"), "honest base case verifies");

        let full_witness_polys = r * n;
        println!(
            "BASE_NS22 r={r} n={n} sent={} polys vs full witness={} polys ({:.1}× smaller)",
            pf.size_polys(),
            full_witness_polys,
            full_witness_polys as f64 / pf.size_polys() as f64
        );
        assert!(pf.size_polys() < full_witness_polys, "NS22 base case beats sending the witness");

        // Soundness: wrong statement target rejects.
        let mut bad_b = b.clone();
        bad_b = bad_b.add(&Poly::one());
        assert!(!verify_base_ns22(&a, &phi, &a_diag, &bad_b, beta, &pf, b"base"), "wrong target rejects");
        // Soundness: tamper the opening z → amortization checks fail.
        let mut bad = pf.clone();
        bad.z.0[0] = bad.z.0[0].add(&Poly::one());
        assert!(!verify_base_ns22(&a, &phi, &a_diag, &b, beta, &bad, b"base"), "tampered z rejects");
        // Soundness: tamper a diagonal garbage gᵢᵢ → statement + amortization fail.
        let mut bad2 = pf.clone();
        bad2.g_even[3] = bad2.g_even[3].add(&Poly::one());
        assert!(!verify_base_ns22(&a, &phi, &a_diag, &b, beta, &bad2, b"base"), "tampered gᵢᵢ rejects");
    }

    #[test]
    fn recursion_schedule_large_n0_analysis() {
        // Investigate the "recursion diverges past ~3 levels" concern at REAL
        // statement sizes. Pure schedule computation (no proving). Question: does
        // r stay BOUNDED down to the crossover n≈m for large n0, and how many
        // USEFUL levels are there (log-scale)?
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (bits, limbs) = (18u32, 3usize); // MODULUS_Q_BITS=37 → limbs=3 at bits=18
        for n0 in [4096usize, 16384, 65536, 262144] {
            // Stop at the crossover: n_floor ≈ m at the current r. Use a generous
            // cap and inspect where r starts climbing.
            let sched = level_schedule(4, n0, ETA as u64, kappa, 18, 1, 9);
            let shapes: Vec<(usize, usize)> = sched.iter().map(|s| (s.r, s.n)).collect();
            // "useful" levels = those before r exceeds, say, 16 (bounded regime).
            let useful = shapes.iter().take_while(|(r, _)| *r <= 16).count();
            let r_at_useful = shapes.get(useful.saturating_sub(1)).map(|(r, _)| *r).unwrap_or(4);
            let n_at_useful = shapes.get(useful).map(|(_, n)| *n).unwrap_or(n0);
            let _ = (bits, limbs);
            println!(
                "SCHED n0={n0}: total_levels={} useful(r≤16)={} r_at_useful={r_at_useful} n_at_useful≈{n_at_useful} first8={:?}",
                shapes.len(), useful, &shapes[..shapes.len().min(8)]
            );
        }
    }

    #[test]
    fn recursion_converges_at_realistic_rank() {
        // In LaBRADOR's regime (n ≫ r²κ) with ν=2 the recursion REDUCES the rank
        // each level while r stays BOUNDED — the proof does not explode. (My
        // earlier "explosion" was ν≈√n, the wrong parameter, at toy n.)
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (bits, limbs) = (18u32, 2usize);
        let (r0, n0, beta0) = (4usize, 512usize, ETA as u64);
        let seed = 0xBEEF;
        // Base-case at the crossover n≈m (further reduction stops helping and
        // starts exploding r). n_floor=100 stops after n reaches ~64.
        let schedule = level_schedule(r0, n0, beta0, kappa, bits, 100, 8);
        // Show the shape sequence: r should stay small, n should shrink.
        let shapes: Vec<(usize, usize)> = {
            let mut v: Vec<(usize, usize)> = schedule.iter().map(|s| (s.r, s.n)).collect();
            let last = schedule.last().unwrap();
            v.push((2 * last.nu + last.mu, last.n.div_ceil(last.nu).max(v_len(last.r, kappa, limbs, false).div_ceil(last.mu))));
            v
        };
        let r_max = shapes.iter().map(|(r, _)| *r).max().unwrap();
        println!("CONVERGE shapes(r,n)={shapes:?} r_max={r_max}");
        assert!(r_max <= 12, "r stays bounded with ν=2, base-cased at crossover (was {r_max})");
        assert!(shapes.last().unwrap().1 < n0, "rank shrank below n0");

        let (family0, s0) = base_relation(r0, n0, 7777);
        let pf = prove_labrador_recursive(&family0, &s0, beta0, kappa, &schedule, seed);
        assert!(
            verify_labrador_recursive(&family0, beta0, kappa, &schedule, seed, &pf),
            "honest deep recursion verifies"
        );
        println!(
            "CONVERGE levels={} proof={}B (u1s={} + final_s={} polys)",
            schedule.len(),
            pf.size_bytes(),
            pf.u1s.iter().map(|(a,b)| a.len()+b.len()).sum::<usize>(),
            pf.final_s.iter().map(|v| v.len()).sum::<usize>(),
        );
    }

    #[test]
    fn aggregation_binds_to_witness_commitment() {
        // Finding-1 FIX: the aggregation challenge ψ must depend on the witness
        // commitment u1_a, so a malicious prover CANNOT compute ψ from the public
        // family alone and then choose a witness for the single aggregated eqn.
        let mut prg = SplitMix64::new(31337);
        let cons: Vec<QuadConstraint> = (0..4)
            .map(|i| QuadConstraint::quad(vec![(i, i, Poly::one())], Poly::from_signed(&{
                let mut c = vec![0i64; Poly::D];
                c[0] = i as i64 + 1;
                c
            })))
            .collect();
        // Two different witness commitments.
        let u1a_1 = PolyVec::sample_uniform_pm(6, 1 << 20, &mut prg);
        let u1a_2 = PolyVec::sample_uniform_pm(6, 1 << 20, &mut prg);
        let agg0 = aggregate_constraints(&cons); // unbound (old behavior)
        let agg1 = aggregate_constraints_bound(&cons, &commit_bytes(&u1a_1));
        let agg2 = aggregate_constraints_bound(&cons, &commit_bytes(&u1a_2));
        // ψ (hence the aggregated target b) changes with the commitment.
        assert_ne!(agg1.b, agg2.b, "aggregate depends on the witness commitment");
        assert_ne!(agg0.b, agg1.b, "bound aggregate differs from the unbound one");
        // Determinism: same binding → same aggregate (prover/verifier agree).
        let agg1b = aggregate_constraints_bound(&cons, &commit_bytes(&u1a_1));
        assert_eq!(agg1.b, agg1b.b, "binding is deterministic");
    }

    #[test]
    fn reduce_to_child_is_faithful() {
        // The §5.3 recursion CLOSES: the honest re-chunked witness `s'` satisfies
        // EVERY child constraint (checks (1),(2),(3a),(3c) rewritten as eq-(6) dot
        // products). If any index/base/challenge weight were wrong, some
        // eval_constraint_on_witness ≠ b would fire.
        let kappa = crate::params::SIS_RANK_KAPPA;
        let (r, n) = (4usize, 32usize);
        let (bits, limbs) = (18u32, 2usize);
        let (nu, mu) = (2usize, 2usize);
        let mut prg = SplitMix64::new(4242);
        let a = PolyMatrix::from_seed(kappa, n, 4243);
        let s: Vec<PolyVec> = (0..r).map(|_| PolyVec::sample_short(n, ETA, &mut prg)).collect();
        let mut cons = Vec::new();
        for i in 0..r {
            for j in i..r {
                cons.push(QuadConstraint::quad(vec![(i, j, Poly::one())], dot(&s[i], &s[j])));
            }
        }
        let va_len = (r * kappa + (r * r + r) / 2) * limbs; // decompose(t‖g)
        let vb_len = r * r * limbs; // decompose(h)
        let b_a = PolyMatrix::from_seed(kappa, va_len, 4244);
        let b_b = PolyMatrix::from_seed(kappa, vb_len, 4245);

        let child = reduce_to_child(&a, &b_a, &b_b, &s, &cons, ETA as u64, bits, limbs, nu, mu);
        assert_eq!(child.r_prime, 2 * nu + mu);
        assert_eq!(child.s.len(), child.r_prime);
        // The composition property: child witness satisfies the child relation.
        for (k, con) in child.constraints.iter().enumerate() {
            let lhs = eval_constraint_on_witness(con, &child.s);
            assert_eq!(lhs, con.b, "child constraint {k} satisfied by honest re-chunked witness");
        }
        // Count: κ (1a) + κ (1b) + κ (2) + (3a) + (3b) + (3c).
        assert_eq!(child.constraints.len(), 3 * kappa + 3);
        println!(
            "REDUCE_TO_CHILD r={r}→r'={} n={n}→n'={} constraints={} (all satisfied); base_z={}",
            child.r_prime, child.n_prime, child.constraints.len(), child.base_z
        );

        // Soundness smoke: perturbing one child-witness coordinate breaks ≥1 constraint.
        let mut bad = child.s.clone();
        bad[2 * nu].0[0] = bad[2 * nu].0[0].add(&Poly::one()); // a v-chunk coord
        let any_broken = child
            .constraints
            .iter()
            .any(|con| eval_constraint_on_witness(con, &bad) != con.b);
        assert!(any_broken, "tampering a v-chunk coordinate must violate some child constraint");
    }

    #[test]
    fn decompose_z_round_trips() {
        // z⁽⁰⁾ + base·z⁽¹⁾ = z exactly, and the low part is centered in (−b/2,b/2].
        let mut prg = SplitMix64::new(700);
        let z = PolyVec::sample_uniform_pm(20, 1 << 20, &mut prg);
        for &base in &[2i64, 7, 64, 1000] {
            let (z0, z1) = decompose_z_centered(&z, base);
            let recon = z0.add(&z1.mul_poly(&Poly::from_signed(&{
                let mut c = vec![0i64; Poly::D];
                c[0] = base;
                c
            })));
            assert_eq!(recon, z, "z⁽⁰⁾+base·z⁽¹⁾ = z (base={base})");
            // low part centered-bounded by base/2
            assert!(z0.inf_norm() <= (base as u64).div_ceil(2), "low part centered (base={base})");
        }
    }

    #[test]
    fn rechunk_flattens_back() {
        // Re-chunk then concatenate: the child witness holds z0‖z1‖v with padding.
        let mut prg = SplitMix64::new(701);
        let z0 = PolyVec::sample_uniform_pm(30, 8, &mut prg);
        let z1 = PolyVec::sample_uniform_pm(30, 8, &mut prg);
        let v = PolyVec::sample_uniform_pm(48, 8, &mut prg);
        let (nu, mu) = (3usize, 4usize);
        let rc = rechunk(&z0, &z1, &v, nu, mu);
        assert_eq!(rc.r_prime, 2 * nu + mu);
        // n' = max(⌈30/3⌉, ⌈48/4⌉) = max(10,12) = 12.
        assert_eq!(rc.n_prime, 12);
        assert!(rc.s.iter().all(|si| si.len() == rc.n_prime), "all child vectors padded to n'");
        // Reassemble each source: take `stride` real coords from each chunk (the
        // rest is padding), concatenate, truncate to the source length.
        let take = |chunks: &[PolyVec], stride: usize, want: usize| -> PolyVec {
            let mut out = Vec::new();
            for c in chunks {
                out.extend(c.0[..stride].iter().cloned());
            }
            out.truncate(want);
            PolyVec(out)
        };
        let (zstride, vstride) = (30usize.div_ceil(nu), 48usize.div_ceil(mu)); // 10, 12
        assert_eq!(take(&rc.s[0..nu], zstride, z0.len()), z0, "z0 chunks reassemble");
        assert_eq!(take(&rc.s[nu..2 * nu], zstride, z1.len()), z1, "z1 chunks reassemble");
        assert_eq!(take(&rc.s[2 * nu..], vstride, v.len()), v, "v chunks reassemble");
    }

    #[test]
    fn decomposition_base_is_sane() {
        // §5.4: base grows with √(r·τ) and the witness width; ≥ 2 always.
        let b_small = decomposition_base(ETA as u64, 4, 32);
        let b_big = decomposition_base(1 << 30, 64, 1024);
        assert!(b_small >= 2 && b_big >= 2);
        assert!(b_big > b_small, "wider witness ⇒ larger balancing base");
    }

    #[test]
    fn reduction_size_point() {
        use crate::wire::{encode_commitment, encode_polyvec};
        // A modest instance; the round reveals g (r² ring elts) + z (n) + t (r·κ).
        let (st, w) = instance(8, 64, 5);
        let pf = prove_reduction(&st, &w).unwrap();
        assert!(verify_reduction(&st, &pf));
        let t_bytes: usize = pf.t.iter().map(|ti| encode_polyvec(ti).len()).sum();
        let g_bytes: usize = pf.g.iter().flatten().map(|_| 4 + 256 * 8).sum();
        let z_bytes = encode_polyvec(&pf.z).len();
        let _ = encode_commitment; // (t are raw Ajtai, no message part)
        println!(
            "LABRADOR_ROUND r={} n={} round_bytes={} (t={} g={} z={}) — pre-recursion; Phase D compresses (t,g,z)",
            st.r, st.n, t_bytes + g_bytes + z_bytes, t_bytes, g_bytes, z_bytes
        );
    }
}
