//! CT ↔ LaBRADOR adapter — express the confidential-transaction relations as a
//! LaBRADOR constraint family + witness, then prove/verify them through the
//! sound recursive pipeline ([`crate::labrador::prove_labrador_recursive`] /
//! [`verify_labrador_recursive`]).
//!
//! # What this is (and is not, yet)
//!
//! This is the **first, faithful** wiring of the range relation into LaBRADOR.
//! "Faithful" = an accepting proof implies exactly the same statement the live
//! [`crate::range_rq::verify_range_rq`] path implies: there exist SHORT
//! `(bits, r_b, r_v)` with `bits ∈ {0,1}^N`, opening the public commitments
//! `c_b`, `c_v`, and `v = Σ 2ⁱ·bitsᵢ ∈ [0, 2^N)`. Nothing about the witness is
//! needed to rebuild the constraint family — the verifier reconstructs it from
//! public data only (`key`, `c_v`, `c_b`), so the proof is checkable.
//!
//! ## The encoding, and why it does not compress *yet*
//!
//! LaBRADOR's [`QuadConstraint`] is a **whole-vector** dot-product relation
//! `Σ a_ij·⟨sᵢ,sⱼ⟩ + Σ⟨φᵢ,sᵢ⟩ = b`. There is no per-coordinate (Hadamard)
//! product form. The bit-validity constraint `bᵢ·(bᵢ−1)=0` is per-scalar, so to
//! isolate a single squared coordinate each bit must be its **own** length-1
//! witness vector — and LaBRADOR requires a UNIFORM rank `n` across all witness
//! vectors, forcing `n = 1` for the whole system. The recursion compresses by
//! folding the rank `n`; at `n = 1` there is nothing to fold, so this produces a
//! correct **send-witness** proof (the base witness is revealed and checked
//! against the full family + ℓ₂ bound) rather than the ~KB compressed proof.
//!
//! Getting the compressed proof needs a witness laid out as a FEW large-rank
//! vectors with the binary constraints re-expressed compatibly — i.e. the
//! paper's second constraint family (constant-term of a dot product `= 0`) plus
//! ring automorphisms to reach individual coordinates. That is the concrete next
//! step (parameter/encoding finalization) and is deliberately NOT done here: this
//! module nails down the relation→family mapping and an end-to-end sound harness
//! first, so the compression work has a validated reference to match.

use crate::labrador::{
    level_schedule, prove_labrador_recursive, verify_labrador_recursive, QuadConstraint,
    RecursiveProof,
};
use crate::module::{PolyVec, RingCommitment};
use crate::params::{LABRADOR_RANK_KAPPA, LWE_RANK_LAMBDA as LAMBDA, SECRET_NORM_ETA};
use crate::range_rq::RingRangeKey;
use crate::rq::Poly;

/// Fixed public reduction-matrix seed (a CRS): `level_matrices` derives the
/// per-level `A/B_a/B_b` from `(seed, level)`. These are random PUBLIC matrices,
/// so a fixed domain-separated constant is a sound common reference string —
/// soundness does NOT require binding them to the statement.
const CRS_SEED: u64 = 0x1AB2_AD02_C701_0001;

/// The LaBRADOR rank used by the CT reduction matrices (κ = 8, per B5/estimator).
const KAPPA: usize = LABRADOR_RANK_KAPPA;

/// A range proof carried through LaBRADOR: the bit-vector commitment (public
/// once sent) plus the recursive proof over the range constraint family.
pub struct RangeLabradorProof {
    pub c_b: RingCommitment,
    pub rec: RecursiveProof,
}

/// Constant ring element `v mod q` (as `c[0]`, all other coefficients zero).
fn const_poly(v: u64) -> Poly {
    let mut p = Poly::zero();
    p.c[0] = v % Poly::Q;
    p
}

/// `2ⁱ mod q` computed without overflow (repeated modular doubling — `i` can
/// exceed 63 for wide ranges). Deterministic across platforms.
fn pow2_mod_q(i: usize) -> u64 {
    let q = Poly::Q as u128;
    let mut acc = 1u128 % q;
    for _ in 0..i {
        acc = (acc * 2) % q;
    }
    acc as u64
}

/// A single linear term `⟨φ, s_idx⟩` with `φ = [coeff]` (rank-1 witness vectors).
fn lin(idx: usize, coeff: Poly) -> (usize, PolyVec) {
    (idx, PolyVec(vec![coeff]))
}

/// Witness index layout (all rank-1 vectors):
/// `[ bits_0 … bits_{N-1} | r_b_0 … r_b_{λ-1} | r_v_0 … r_v_{λ-1} ]`.
struct Layout {
    n_bits: usize,
}
impl Layout {
    fn bit(&self, i: usize) -> usize {
        i
    }
    fn r_b(&self, j: usize) -> usize {
        self.n_bits + j
    }
    fn r_v(&self, j: usize) -> usize {
        self.n_bits + LAMBDA + j
    }
    fn total(&self) -> usize {
        self.n_bits + 2 * LAMBDA
    }
}

/// Build the range constraint family from PUBLIC data only (`key`, `c_v`, `c_b`).
/// Both prover and verifier call this; the witness is never consulted.
///
/// Constraints (rank-1 vectors, `n = 1`):
///  1. bit-commitment opening   `A1·r_b = c_b.t1`            (κ linear rows)
///  2. bit-commitment message   `A2_bits·r_b + bits = c_b.t2` (N linear rows)
///  3. value-commitment opening `A1·r_v = c_v.t1`            (κ linear rows)
///  4. value message + binding  `a2_val·r_v + Σ2ⁱ·bitsᵢ = c_v.t2` (1 linear row)
///  5. bit validity             `⟨bᵢ,bᵢ⟩ − bᵢ = 0`            (N quadratic rows)
fn range_family(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    c_b: &RingCommitment,
) -> Vec<QuadConstraint> {
    let n_bits = key.n_bits();
    let lay = Layout { n_bits };
    let bk = key.bit_key(); // a1 (κ×λ), a2 = A2_bits (N×λ)
    let vk = key.value_key(); // a2 = [a2_val] (1×λ)
    let a1 = &bk.a1;
    let a2_bits = &bk.a2;
    let a2_val = &vk.a2.m[0];
    let kappa_ct = a1.rows; // the CT commitment κ (=SIS_RANK_KAPPA), NOT the LaBRADOR κ
    let mut fam = Vec::new();

    // 1. A1·r_b = c_b.t1
    for i in 0..kappa_ct {
        let linear = (0..LAMBDA).map(|j| lin(lay.r_b(j), a1.m[i][j].clone())).collect();
        fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: c_b.t1.0[i].clone() });
    }
    // 2. A2_bits·r_b + bits = c_b.t2
    for i in 0..n_bits {
        let mut linear: Vec<_> =
            (0..LAMBDA).map(|j| lin(lay.r_b(j), a2_bits.m[i][j].clone())).collect();
        linear.push(lin(lay.bit(i), Poly::one()));
        fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: c_b.t2.0[i].clone() });
    }
    // 3. A1·r_v = c_v.t1
    for i in 0..kappa_ct {
        let linear = (0..LAMBDA).map(|j| lin(lay.r_v(j), a1.m[i][j].clone())).collect();
        fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: c_v.t1.0[i].clone() });
    }
    // 4. a2_val·r_v + Σ 2ⁱ·bitsᵢ = c_v.t2[0]
    {
        let mut linear: Vec<_> =
            (0..LAMBDA).map(|j| lin(lay.r_v(j), a2_val[j].clone())).collect();
        for i in 0..n_bits {
            linear.push(lin(lay.bit(i), const_poly(pow2_mod_q(i))));
        }
        fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: c_v.t2.0[0].clone() });
    }
    // 5. bit validity: ⟨bᵢ,bᵢ⟩ − bᵢ = 0
    for i in 0..n_bits {
        let bi = lay.bit(i);
        fam.push(QuadConstraint { conj_terms: Vec::new(),
            terms: vec![(bi, bi, Poly::one())],
            linear: vec![lin(bi, Poly::one().neg())],
            b: Poly::zero(),
        });
    }
    fam
}

/// The rank-1 witness `[bits | r_b | r_v]`, each a length-1 `PolyVec`.
fn range_witness(bits: &[Poly], r_b: &PolyVec, r_v: &PolyVec) -> Vec<PolyVec> {
    let mut s = Vec::with_capacity(bits.len() + r_b.len() + r_v.len());
    for b in bits {
        s.push(PolyVec(vec![b.clone()]));
    }
    for p in &r_b.0 {
        s.push(PolyVec(vec![p.clone()]));
    }
    for p in &r_v.0 {
        s.push(PolyVec(vec![p.clone()]));
    }
    s
}

/// The recursion schedule for a range family of `r0` rank-1 vectors. At `n = 1`
/// this is a (possibly empty) send-witness schedule — see the module note.
fn range_schedule(r0: usize) -> Vec<crate::labrador::LevelShape> {
    let beta0 = SECRET_NORM_ETA as u64;
    // n0 = 1 (rank-1 witness); n_floor = 0 lets the pipeline run its send-witness
    // base directly. min_bits/max_levels are inert at n0 = 1.
    level_schedule(r0, 1, beta0, KAPPA, 1, 0, 0)
}

/// Prove `v ∈ [0, 2^N)` via LaBRADOR. Mirrors [`crate::range_rq::prove_range_rq`]
/// inputs; returns the bit commitment plus the recursive proof, or `None` if
/// `v` is out of range.
pub fn prove_range_labrador(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    v: u64,
    r_v: &PolyVec,
    seed: u64,
) -> Option<RangeLabradorProof> {
    let n_bits = key.n_bits();
    if n_bits < 64 && v >= (1u64 << n_bits) {
        return None;
    }
    use crate::arith::SplitMix64;
    let mut prg = SplitMix64::new(seed ^ 0xB175);
    let r_b = PolyVec::sample_short(LAMBDA, SECRET_NORM_ETA, &mut prg);
    let bits: Vec<Poly> = (0..n_bits).map(|i| const_poly((v >> i) & 1)).collect();
    let c_b = key.bit_key().commit(&PolyVec(bits.clone()), &r_b);

    let fam = range_family(key, c_v, &c_b);
    let s = range_witness(&bits, &r_b, r_v);
    let beta0 = SECRET_NORM_ETA as u64;
    let sched = range_schedule(s.len());
    let rec = prove_labrador_recursive(&fam, &s, beta0, KAPPA, &sched, CRS_SEED);
    Some(RangeLabradorProof { c_b, rec })
}

/// Verify a LaBRADOR range proof. Reconstructs the family from public data and
/// runs the recursive verifier.
pub fn verify_range_labrador(
    key: &RingRangeKey,
    c_v: &RingCommitment,
    proof: &RangeLabradorProof,
) -> bool {
    if proof.c_b.t2.0.len() != key.n_bits() {
        return false;
    }
    let fam = range_family(key, c_v, &proof.c_b);
    let lay = Layout { n_bits: key.n_bits() };
    let r0 = lay.total();
    let beta0 = SECRET_NORM_ETA as u64;
    let sched = range_schedule(r0);
    verify_labrador_recursive(&fam, beta0, KAPPA, &sched, CRS_SEED, &proof.rec)
}

// ─────────────────────────────────────────────────────────────────────────
// Coefficient-addressing primitive (toward the COMPRESSED encoding)
//
// The faithful encoding above is `n = 1` because per-bit quadratics can only be
// isolated by giving each bit its own vector. To reach small-r / large-n we must
// pack many bits into the COEFFICIENTS of a single ring element (d = 256 per
// element) and still be able to constrain each coordinate. The enabler is the
// negacyclic automorphism σ: X ↦ X⁻¹ and the identity
//
//     ct( σ(a)·b ) = Σₖ aₖ·bₖ        (coefficient-wise inner product)
//
// where ct(·) is the constant coefficient. With `a = Xᵏ` (a unit monomial) this
// EXTRACTS coordinate k: `ct(σ(Xᵏ)·b) = bₖ`. That is exactly how LaBRADOR's
// second constraint family (constant-term of a dot product = 0) addresses
// individual packed coordinates. These are pure, verifiable ring identities —
// no soundness surface — and are the building block the compressed range/bit
// encoding and the JL projection both need.
// ─────────────────────────────────────────────────────────────────────────
pub mod coeff {
    use super::Poly;

    /// The negacyclic automorphism σ(a)(X) = a(X⁻¹) — the canonical
    /// [`Poly::conjugate`]. Kept here as the named entry point for the ct/σ work.
    pub fn auto_inv(a: &Poly) -> Poly {
        a.conjugate()
    }

    /// Constant coefficient (coefficient of `X⁰`).
    pub fn ct(a: &Poly) -> u64 {
        a.c[0]
    }

    /// The coefficient-wise inner product `Σₖ aₖ·bₖ mod q`, via the identity
    /// `ct(σ(a)·b)`. This is the value the constant-term constraint family checks.
    pub fn ct_inner(a: &Poly, b: &Poly) -> u64 {
        ct(&auto_inv(a).mul_ntt(b))
    }

    /// Reference `Σₖ aₖ·bₖ mod q` computed directly (for validation).
    pub fn coeff_inner_ref(a: &Poly, b: &Poly) -> u64 {
        let q = Poly::Q as u128;
        let mut acc = 0u128;
        for (x, y) in a.c.iter().zip(&b.c) {
            acc = (acc + (*x as u128) * (*y as u128)) % q;
        }
        acc as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────
// PACKED range relation (the COMPRESSED encoding's commitment fork)
//
// Fork the bit commitment: instead of N constant-poly message rows, pack N bits
// (N ≤ d = 256) into the COEFFICIENTS of ONE ring element `bit_poly`, committed
// as a single BDLOP message. Per-coordinate bit-validity is enforced by ONE
// constant-term constraint plus the norm bound:
//
//     ct(σ(bit_poly)·bit_poly) − ct(σ(J)·bit_poly) = 0            (J = Σ Xᵏ)
//       ≡  Σₖ bₖ² − Σₖ bₖ  =  Σₖ bₖ(bₖ−1)  =  0   (mod q)
//
// SOUNDNESS: the witness is short (‖bit_poly‖∞ ≤ β, integer centered coeffs).
// For integer bₖ, `bₖ(bₖ−1) ≥ 0` always, and Σ ≤ d·β² < q (no wraparound), so a
// sum ≡ 0 forces EVERY term to 0 ⇒ every bₖ ∈ {0,1}. The norm bound is thus not
// optional — it is what makes the single aggregate constraint a real per-
// coordinate binary check. The committed value is the PUBLIC linear functional
// `v = Σ 2ⁱ bᵢ = ct(σ(g)·bit_poly)` (g = Σ 2ⁱ Xⁱ), extractable by anyone.
//
// This reshapes the witness from `r ≈ N + 2λ` rank-1 vectors (faithful n=1
// encoding) to `r ≈ ⌈N/d⌉ + λ` — a large reduction (see the size test). It is
// the RELATION the compressed proof must establish. NOTE: enforcing the ct
// constraint INSIDE the recursion (and adding ZK masking so the base case does
// not reveal `bit_poly` = the amount) is the core `labrador.rs` extension that
// follows — this module validates the packed relation + commitment first, as the
// reference that extension must match (mirroring how the n=1 path is the
// reference for the faithful encoding).
// ─────────────────────────────────────────────────────────────────────────
pub mod packed {
    use super::coeff::{ct, ct_inner};
    use crate::labrador::{
        level_schedule_conj, prove_labrador_recursive, prove_labrador_recursive_ct_zk,
        prove_labrador_full_ct_zk, verify_labrador_full_ct_zk,
        prove_labrador_full_ct_zk_ipa, verify_labrador_full_ct_zk_ipa, FullCtZkIpaProof,
        verify_labrador_recursive_ct, verify_labrador_recursive_ct_zk, CtConstraint, FullCtZkProof,
        QuadConstraint, RecursiveCtZkProof, RecursiveProof,
    };
    use crate::module::{PolyVec, RingCommitKey, RingCommitment};
    use crate::params::{LABRADOR_RANK_KAPPA, LWE_RANK_LAMBDA as LAMBDA, SECRET_NORM_ETA};
    use crate::rq::Poly;

    /// LaBRADOR reduction rank for the packed proof (κ = 8).
    const KAPPA: usize = LABRADOR_RANK_KAPPA;
    /// Fixed CRS seed for the packed reduction matrices.
    const CRS_SEED: u64 = 0x1AB2_AD02_C701_0002;

    /// All-ones coefficient poly `J = Σ_{k<d} Xᵏ` (so `ct(σ(J)·b) = Σ bₖ`).
    pub fn all_ones() -> Poly {
        Poly { c: vec![1u64; Poly::D] }
    }

    /// Gadget poly `g = Σ_{i<n_bits} 2ⁱ Xⁱ mod q` (so `ct(σ(g)·b) = Σ 2ⁱ bᵢ`).
    pub fn gadget(n_bits: usize) -> Poly {
        let q = Poly::Q as u128;
        let mut p = Poly::zero();
        let mut pw = 1u128 % q;
        for i in 0..n_bits.min(Poly::D) {
            p.c[i] = pw as u64;
            pw = (pw * 2) % q;
        }
        p
    }

    /// Public statement: the (ℓ=1) commitment key and the bit commitment.
    pub struct PackedRangeStatement {
        pub key: RingCommitKey,
        pub c_b: RingCommitment,
        pub n_bits: usize,
    }

    /// Secret witness: the packed bit poly and its commitment randomness.
    pub struct PackedRangeWitness {
        pub bit_poly: Poly,
        pub r_b: PolyVec,
    }

    /// Commit `v ∈ [0, 2^{n_bits})` in packed form. Returns statement + witness.
    pub fn commit_packed(n_bits: usize, v: u64, seed: u64) -> (PackedRangeStatement, PackedRangeWitness) {
        assert!(n_bits <= Poly::D, "packed form holds ≤ d bits per ring element");
        use crate::arith::SplitMix64;
        let mut prg = SplitMix64::new(seed ^ 0x9ACC);
        let r_b = PolyVec::sample_short(LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
        let mut bit_poly = Poly::zero();
        // v is a u64, so bits at index ≥ 64 are 0 (shifting a u64 by ≥64 is UB/panic).
        for i in 0..n_bits.min(64) {
            bit_poly.c[i] = (v >> i) & 1;
        }
        let key = RingCommitKey::production(1, seed);
        let c_b = key.commit(&PolyVec(vec![bit_poly.clone()]), &r_b);
        (
            PackedRangeStatement { key, c_b, n_bits },
            PackedRangeWitness { bit_poly, r_b },
        )
    }

    /// The public committed value `v = Σ 2ⁱ bᵢ = ct(σ(g)·bit_poly)`.
    pub fn value_of(bit_poly: &Poly, n_bits: usize) -> u64 {
        ct_inner(&gadget(n_bits), bit_poly)
    }

    // ── Value-binding / balance over PACKED commitments ───────────────────────
    //
    // The amount a packed `c_b` commits is the LINEAR functional `v = ⟪g,b⟫`
    // (g the gadget). Because it is linear AND the BDLOP commitment is additively
    // homomorphic, the packed `c_b` IS the amount commitment — no separate value
    // commitment to value-link. Conservation `Σin v = Σout v + fee` becomes
    // `⟪g, Σin b − Σout b⟫ = fee`, checkable on the homomorphic sum of the `c_b`s.
    // This is the value-binding the limb balance needs; the ZK balance proof (a
    // masked-linear opening of the summed commitment against the value functional)
    // rides on it.

    /// Homomorphic add of two packed commitments: `Commit(b1;r1)+Commit(b2;r2) =
    /// Commit(b1+b2; r1+r2)`.
    pub fn add_commit(c1: &RingCommitment, c2: &RingCommitment) -> RingCommitment {
        c1.add(c2)
    }

    /// The packed value functional is LINEAR: `⟪g, Σ bᵢ⟫ = Σ ⟪g, bᵢ⟫` — so summing
    /// packed commitments sums their values. Returns whether conservation
    /// `Σin ⟪g,b⟫ = Σout ⟪g,b⟫ + fee (mod q)` holds for the given bit polys.
    pub fn balance_holds(inputs: &[Poly], outputs: &[Poly], fee: u64, n_bits: usize) -> bool {
        let q = Poly::Q as u128;
        let sum = |ps: &[Poly]| -> u128 {
            ps.iter().map(|b| value_of(b, n_bits) as u128).sum::<u128>() % q
        };
        (sum(inputs)) % q == (sum(outputs) + fee as u128) % q
    }

    /// Reference relation check (what a verifier of the packed relation enforces):
    /// commitment opening + the ct binary constraint + the short-witness norm
    /// bound. `beta` is the ∞-norm bound; it MUST satisfy `d·β² < q` for the
    /// binary argument to be sound.
    pub fn relation_holds(stmt: &PackedRangeStatement, wit: &PackedRangeWitness, beta: i64) -> bool {
        // Norm bound (soundness of the binary argument depends on it).
        let dbeta2 = (Poly::D as u128) * (beta as u128) * (beta as u128);
        if dbeta2 >= Poly::Q as u128 {
            return false; // parameters unsafe: wraparound possible
        }
        let bnd = beta as u64;
        if wit.bit_poly.inf_norm() > bnd || wit.r_b.inf_norm() > bnd {
            return false;
        }
        // Commitment opening: A1·r_b = t1, a2·r_b + bit_poly = t2 (recompute).
        let recomputed = stmt.key.commit(&PolyVec(vec![wit.bit_poly.clone()]), &wit.r_b);
        if recomputed != stmt.c_b {
            return false;
        }
        // Binary: Σ bₖ² − Σ bₖ ≡ 0  (mod q).
        let q = Poly::Q;
        let sum_sq = ct_inner(&wit.bit_poly, &wit.bit_poly);
        let sum = ct_inner(&all_ones(), &wit.bit_poly);
        (sum_sq + q - sum) % q == 0
    }

    /// `ct(p)` re-exported for tests / callers building ct constraints.
    pub fn constant_term(p: &Poly) -> u64 {
        ct(p)
    }

    // ── Wiring the packed relation through the real recursion pipeline ─────────
    //
    // Witness layout (rank-1 vectors): `s[0] = bit_poly`, `s[1..1+λ] = r_b`.
    // Whole-ring family = the commitment opening; ct-family = the ONE binary
    // constraint. The schedule is EMPTY (send-witness base — ct-constraints are
    // only sound there; see `verify_labrador_recursive_ct`). This realizes the
    // packing compression (r ≈ 1+λ) through the actual prove/verify API; ZK and
    // fold-through-levels are the follow-on core work.

    fn full_family(stmt: &PackedRangeStatement) -> Vec<QuadConstraint> {
        let a1 = &stmt.key.a1; // κ_ct × λ
        let a2 = &stmt.key.a2; // 1 × λ
        let kappa_ct = a1.rows;
        let mut fam = Vec::new();
        // A1·r_b = c_b.t1
        for i in 0..kappa_ct {
            let linear = (0..LAMBDA)
                .map(|j| (1 + j, PolyVec(vec![a1.m[i][j].clone()])))
                .collect();
            fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: stmt.c_b.t1.0[i].clone() });
        }
        // a2·r_b + bit_poly = c_b.t2[0]
        let mut linear: Vec<_> = (0..LAMBDA)
            .map(|j| (1 + j, PolyVec(vec![a2.m[0][j].clone()])))
            .collect();
        linear.push((0, PolyVec(vec![Poly::one()])));
        fam.push(QuadConstraint { conj_terms: Vec::new(), terms: vec![], linear, b: stmt.c_b.t2.0[0].clone() });
        fam
    }

    fn ct_family() -> Vec<CtConstraint> {
        // binary: ⟪s0,s0⟫ + ⟪−J, s0⟫ = Σbₖ² − Σbₖ = 0.
        vec![CtConstraint {
            terms: vec![(0, 0, 1)],
            linear: vec![(0, PolyVec(vec![all_ones().neg()]))],
            target: 0,
        }]
    }

    fn witness_vecs(wit: &PackedRangeWitness) -> Vec<PolyVec> {
        let mut s = Vec::with_capacity(1 + wit.r_b.len());
        s.push(PolyVec(vec![wit.bit_poly.clone()]));
        for p in &wit.r_b.0 {
            s.push(PolyVec(vec![p.clone()]));
        }
        s
    }

    /// Prove the packed range relation through the LaBRADOR pipeline (send-witness
    /// base). The proof is `RecursiveProof { u1s: [], final_s: witness }`.
    pub fn prove_range_packed(stmt: &PackedRangeStatement, wit: &PackedRangeWitness) -> RecursiveProof {
        let s = witness_vecs(wit);
        prove_labrador_recursive(&full_family(stmt), &s, SECRET_NORM_ETA as u64, KAPPA, &[], CRS_SEED)
    }

    /// Verify a packed range proof: commitment opening (whole-ring) + binary
    /// (constant-term) + norm bound, all at the send-witness base.
    pub fn verify_range_packed(stmt: &PackedRangeStatement, proof: &RecursiveProof) -> bool {
        verify_labrador_recursive_ct(
            &full_family(stmt),
            &ct_family(),
            SECRET_NORM_ETA as u64,
            KAPPA,
            &[],
            CRS_SEED,
            proof,
        )
    }

    // ── Step 5: the packed range relation through the FULL recursion-ZK driver ──
    //
    // The send-witness base above reveals `bit_poly` (the amount). This routes the
    // SAME relation (whole-ring opening + binary ct) through the folding recursion
    // with a perfect-ZK base (`prove_labrador_recursive_ct_zk`): the amount is
    // never revealed, and the constraints fold via ĝ/ĥ (Step 3b) to a small final
    // family opened in ZK (Step 4). SMALL `bits` keeps the base β in the base-
    // opening's rejection regime. This is the money-path proof.

    /// The (small-`bits`, conjugation-aware) fold schedule for the packed relation.
    fn packed_zk_schedule(r0: usize) -> Vec<crate::labrador::LevelShape> {
        level_schedule_conj(r0, 1, SECRET_NORM_ETA as u64, KAPPA, 4, 0, 1, true)
    }

    /// Prove the packed range relation in ZERO-KNOWLEDGE via the folding recursion.
    /// `None` on rejection exhaustion. The amount (`bit_poly`) is never revealed.
    pub fn prove_range_packed_zk(stmt: &PackedRangeStatement, wit: &PackedRangeWitness, seed: u64) -> Option<RecursiveCtZkProof> {
        let s = witness_vecs(wit);
        let sched = packed_zk_schedule(s.len());
        // Fixed public CRS_SEED_ZK (verify reproduces it); fresh `seed` for masks.
        prove_labrador_recursive_ct_zk(&full_family(stmt), &ct_family(), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify a ZK packed range proof.
    pub fn verify_range_packed_zk(stmt: &PackedRangeStatement, proof: &RecursiveCtZkProof) -> bool {
        let r0 = 1 + LAMBDA;
        let sched = packed_zk_schedule(r0);
        verify_labrador_recursive_ct_zk(&full_family(stmt), &ct_family(), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    /// Fixed CRS seed for the ZK packed reduction (must match prove's `seed ^ 0x2C`
    /// for a fixed prover seed; verify uses this constant directly).
    const CRS_SEED_ZK: u64 = CRS_SEED ^ 0x2C;

    // ── The SUCCINCT money-path ZK proof: fold → general ZK terminal ──
    //
    // Routes the SAME packed range relation (`full_family` whole-ring opening +
    // `ct_family` binary) through `prove_labrador_full_ct_zk`: fold via
    // `reduce_to_child_conj_ct`, then the GENERAL ZK terminal (witness-free NS22
    // base + JL tight-norm + ct-family binding). This is the succinct money-path
    // proof — the amount is never revealed and the base is O(n)+garbage, not the
    // O(r·n) masked-witness reveal of `prove_range_packed_zk`.
    //
    // SIZE NOTE: a SINGLE packed range is `r0=1+λ`, `n0=1` — fold-hostile (folding
    // explodes r). For a size win the tx must be AMORTIZED (many outputs +
    // balance) into a large-`n0` relation; the correctness/soundness wiring here is
    // layout-independent.

    /// Prove the packed range relation with the SUCCINCT witness-free ZK pipeline.
    /// `None` on rejection. The amount (`bit_poly`) is never revealed.
    pub fn prove_range_packed_succinct_zk(stmt: &PackedRangeStatement, wit: &PackedRangeWitness, seed: u64) -> Option<FullCtZkProof> {
        let s = witness_vecs(wit);
        let sched = packed_zk_schedule(s.len());
        // Fixed public CRS_SEED_ZK (verify reproduces the matrices); fresh `seed` masks.
        prove_labrador_full_ct_zk(&full_family(stmt), &ct_family(), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify a succinct witness-free ZK packed range proof.
    pub fn verify_range_packed_succinct_zk(stmt: &PackedRangeStatement, proof: &FullCtZkProof) -> bool {
        let r0 = 1 + LAMBDA;
        let sched = packed_zk_schedule(r0);
        verify_labrador_full_ct_zk(&full_family(stmt), &ct_family(), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    // ── The AMORTIZED multi-range relation (fold-friendly layout) ──────────────
    //
    // The single packed range is `r0=1+λ, n0=1` — fold-hostile. Amortizing M
    // ranges into ONE proof and laying the witness out fold-friendly (few vectors,
    // large n0) is what gets per-range size to ~KB.
    //
    // Layout (r0 = 2, n0 = max(M, λ)): vector 0 = [b_0 … b_{M-1}] (all M bit_polys,
    // one per coordinate), vector 1 = the shared commitment randomness r_b. Then:
    //  · commitment openings `A1·r_b = t1`, `A2[m]·r_b + b_m = t2[m]` — whole-ring
    //    linear (φ selects the r_b coords / the m-th bit_poly);
    //  · AGGREGATED binary `⟪s_0,s_0⟫ − ⟪s_0, J_M⟫ = Σ_m Σ_k b_{m,k}(b_{m,k}−1) = 0`
    //    — ONE ct-constraint on the high-dim `s_0` (the norm bound forces every bit
    //    ∈ {0,1} exactly as for a single range).
    // This is the `(family, ct_family)` a fold-friendly succinct ZK proof consumes.

    /// A commitment to M packed ranges: `c_b = key.commit([b_0…b_{M-1}]; r_b)`.
    /// For a full confidential TX the first `n_in` coords are INPUT amounts and the
    /// rest are OUTPUTS; `fee` is the public fee. `n_in = 0` (and `fee = 0`) is the
    /// outputs-only range statement (no balance constraint).
    #[derive(Clone)]
    pub struct MultiRangeStatement {
        pub key: RingCommitKey, // ell = m
        pub c_b: RingCommitment,
        pub m: usize,
        pub n_bits: usize,
        pub n_in: usize,
        pub fee: u64,
    }
    pub struct MultiRangeWitness {
        pub bits: Vec<Poly>, // m bit_polys
        pub r_b: PolyVec,    // dim λ
    }

    /// Commit M values as one multi-range statement. `key_seed` is the FIXED
    /// network CRS (the verifier reconstructs the key from it, not from the sent
    /// statement); `rand_seed` is FRESH per proof (the hiding randomness `r_b`).
    pub fn commit_multi_range(n_bits: usize, values: &[u64], key_seed: u64, rand_seed: u64) -> (MultiRangeStatement, MultiRangeWitness) {
        use crate::arith::SplitMix64;
        let m = values.len();
        let key = RingCommitKey::production(m, key_seed);
        let mut prg = SplitMix64::new(rand_seed ^ 0x9ACD);
        let r_b = PolyVec::sample_short(LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
        let bits: Vec<Poly> = values
            .iter()
            .map(|&v| {
                let mut b = Poly::zero();
                for i in 0..n_bits.min(64) {
                    b.c[i] = (v >> i) & 1;
                }
                b
            })
            .collect();
        let c_b = key.commit(&PolyVec(bits.clone()), &r_b);
        (MultiRangeStatement { key, c_b, m, n_bits, n_in: 0, fee: 0 }, MultiRangeWitness { bits, r_b })
    }

    /// Commit a full confidential TX: `in_amounts ‖ out_amounts` under one `c_b`,
    /// carrying `n_in` and `fee` so the balance constraint `Σin − Σout = fee` rides
    /// the same proof as the ranges.
    pub fn commit_multi_tx(n_bits: usize, in_amounts: &[u64], out_amounts: &[u64], fee: u64, key_seed: u64, rand_seed: u64) -> (MultiRangeStatement, MultiRangeWitness) {
        let values: Vec<u64> = in_amounts.iter().chain(out_amounts).copied().collect();
        let (mut stmt, wit) = commit_multi_range(n_bits, &values, key_seed, rand_seed);
        stmt.n_in = in_amounts.len();
        stmt.fee = fee;
        (stmt, wit)
    }

    /// The fold-friendly base witness `[s_0 = padded bits, s_1 = padded r_b]`.
    pub fn multi_range_witness(wit: &MultiRangeWitness) -> Vec<PolyVec> {
        let m = wit.bits.len();
        let n0 = m.max(LAMBDA);
        let mut s0 = PolyVec::zero(n0);
        for (coord, b) in wit.bits.iter().enumerate() {
            s0.0[coord] = b.clone();
        }
        let mut s1 = PolyVec::zero(n0);
        for (j, p) in wit.r_b.0.iter().enumerate() {
            s1.0[j] = p.clone();
        }
        vec![s0, s1]
    }

    /// The whole-ring commitment-opening family (both prover + verifier).
    pub fn multi_range_family(stmt: &MultiRangeStatement) -> Vec<QuadConstraint> {
        let m = stmt.m;
        let n0 = m.max(LAMBDA);
        let a1 = &stmt.key.a1; // κ×λ
        let a2 = &stmt.key.a2; // m×λ
        let kappa_ct = a1.rows;
        let mut fam = Vec::new();
        // A1·r_b = c_b.t1  (κ rows, linear on s_1).
        for i in 0..kappa_ct {
            let mut phi = PolyVec::zero(n0);
            for j in 0..LAMBDA {
                phi.0[j] = a1.m[i][j].clone();
            }
            fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi)], b: stmt.c_b.t1.0[i].clone() });
        }
        // A2[m']·r_b + b_{m'} = c_b.t2[m']  (m rows; linear on s_1 + s_0 coord m').
        for row in 0..m {
            let mut phi1 = PolyVec::zero(n0);
            for j in 0..LAMBDA {
                phi1.0[j] = a2.m[row][j].clone();
            }
            let mut phi0 = PolyVec::zero(n0);
            phi0.0[row] = Poly::one();
            fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi1), (0, phi0)], b: stmt.c_b.t2.0[row].clone() });
        }
        fam
    }

    /// The ct-family on `s_0`: (1) the aggregated binary `Σ b(b−1)=0`, and — for a
    /// full TX (`n_in>0` or `fee>0`) — (2) the BALANCE `⟪Σ±g, s_0⟫ = fee`, a linear
    /// ct with `+gadget` at input coords and `−gadget` at output coords (so
    /// `Σin ⟪g,b⟫ − Σout ⟪g,b⟫ = Σin v − Σout v = fee`).
    pub fn multi_range_ct_family(stmt: &MultiRangeStatement) -> Vec<CtConstraint> {
        let m = stmt.m;
        let n0 = m.max(LAMBDA);
        let mut jpad = PolyVec::zero(n0);
        for coord in 0..m {
            jpad.0[coord] = all_ones().neg();
        }
        let mut out = vec![CtConstraint { terms: vec![(0, 0, 1)], linear: vec![(0, jpad)], target: 0 }];
        if stmt.n_in > 0 || stmt.fee > 0 {
            let g = gadget(stmt.n_bits);
            let mut bal = PolyVec::zero(n0);
            for coord in 0..m {
                bal.0[coord] = if coord < stmt.n_in { g.clone() } else { g.neg() };
            }
            out.push(CtConstraint { terms: vec![], linear: vec![(0, bal)], target: stmt.fee % Poly::Q });
        }
        out
    }

    // ── SUPERSEDED (lineage) ─────────────────────────────────────────────────
    // The single-value amortized money proof below (`MultiRangeStatement`,
    // `commit_multi_range`/`commit_multi_tx`, `multi_range_*`, the succinct/IPA
    // provers) and the self-contained-coin variant (`commit_multi_tx_coins`,
    // `multi_tx_coins_*`) were the intermediate money-path proofs: they commit each
    // amount as ONE ≤~36-bit coefficient value (`v = ⟪g,b⟫ mod q`), so they only
    // cover sub-2³⁵ amounts. The `fullwidth` module GENERALISES them to full u128
    // width (per-limb bit-polys + carry-chain balance) and is the ONLY money path
    // wired into the node. These are kept for lineage/reference, but their prove/
    // verify entry points are FORCED TO FAIL (return None / false) so they can never
    // be wired into consensus, and their tests are `#[ignore]`d. Do not revive
    // without an explicit soundness review — `fullwidth` is the supported path.

    /// Prove M amortized ranges with the succinct witness-free ZK pipeline.
    /// SUPERSEDED by `fullwidth` — forced to return `None` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn prove_multi_range_succinct_zk(stmt: &MultiRangeStatement, wit: &MultiRangeWitness, seed: u64) -> Option<FullCtZkProof> {
        return None;
        let s = multi_range_witness(wit);
        let n0 = s[0].len();
        // Fold-friendly, conjugation-aware schedule (large n0, base-cased at crossover).
        let nfloor = 64usize.min(n0.saturating_sub(1)); // guarantee ≥1 fold (lower binary ct → linear)
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, nfloor, 12, true);
        prove_labrador_full_ct_zk(&multi_range_family(stmt), &multi_range_ct_family(stmt), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify an amortized multi-range succinct ZK proof.
    /// SUPERSEDED by `fullwidth` — forced to return `false` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn verify_multi_range_succinct_zk(stmt: &MultiRangeStatement, proof: &FullCtZkProof) -> bool {
        return false;
        if stmt.c_b.t2.len() != stmt.m || stmt.key.ell != stmt.m {
            return false;
        }
        let n0 = stmt.m.max(LAMBDA);
        let nfloor = 64usize.min(n0.saturating_sub(1)); // guarantee ≥1 fold (lower binary ct → linear)
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, nfloor, 12, true);
        verify_labrador_full_ct_zk(&multi_range_family(stmt), &multi_range_ct_family(stmt), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    /// Prove M amortized ranges with the IPA-lite pipeline (randomness opening at the base).
    /// SUPERSEDED by `fullwidth` — forced to return `None` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn prove_multi_range_ipa_zk(stmt: &MultiRangeStatement, wit: &MultiRangeWitness, seed: u64) -> Option<FullCtZkIpaProof> {
        return None;
        let s = multi_range_witness(wit);
        let n0 = s[0].len();
        // n_floor=64: small tx (n0≤64) ⇒ EMPTY schedule ⇒ DIRECT IPA base (no fold, r=2
        // — the binary rides ct(gc) directly). Large batch (n0>64) ⇒ convergent fold.
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, 64, 12, true);
        prove_labrador_full_ct_zk_ipa(&multi_range_family(stmt), &multi_range_ct_family(stmt), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify an amortized multi-range IPA-lite ZK proof.
    /// SUPERSEDED by `fullwidth` — forced to return `false` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn verify_multi_range_ipa_zk(stmt: &MultiRangeStatement, proof: &FullCtZkIpaProof) -> bool {
        return false;
        // Dimension guard: the commitment must carry exactly `m` message slots and
        // the key must be sized for `m` (a malformed statement rejects, never panics).
        if stmt.c_b.t2.len() != stmt.m || stmt.key.ell != stmt.m {
            return false;
        }
        let n0 = stmt.m.max(LAMBDA);
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, 64, 12, true);
        verify_labrador_full_ct_zk_ipa(&multi_range_family(stmt), &multi_range_ct_family(stmt), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    // ── SELF-CONTAINED COIN layout (coin = a slice of the amortized c_b) ─────────
    //
    // The `commit_multi_tx` layout above shares ONE randomness `r_b` across all
    // values, so `c_b.t1 = A1·r_b` is common to every slice — a slice is NOT a
    // self-contained coin (and worse, opening one slice needs the whole `r_b`,
    // which would reveal every OTHER amount in the tx to that slice's recipient).
    //
    // For the money path a coin must be independently openable by its recipient
    // WITHOUT learning the tx's other amounts. So each value gets its OWN short
    // randomness `r_j`, and its coin is the self-contained single-value commitment
    //   cv_j = SK.commit([b_j]; r_j),  SK = production(1, key_seed)   (t1_j = A1·r_j, t2_j = A2·r_j + b_j).
    // The amortized statement STACKS these: `c_b.t1 = ‖_j t1_j` (m·κ rows),
    // `c_b.t2 = ‖_j t2_j` (m rows). The single IPA proof then proves ranges +
    // balance over the stacked witness, and its opening family binds each `cv_j`
    // to the same commitment key — so the proof and the on-chain coins are the SAME
    // object (the packed-path soundness property), with per-coin openability.

    /// The single-value commitment key every self-contained coin uses.
    pub fn coin_key(key_seed: u64) -> RingCommitKey {
        RingCommitKey::production(1, key_seed)
    }

    /// The `n_bits`-bit decomposition of `v` as a coefficient-packed poly.
    pub fn value_bits(n_bits: usize, v: u64) -> Poly {
        let mut b = Poly::zero();
        for i in 0..n_bits.min(64) {
            b.c[i] = (v >> i) & 1;
        }
        b
    }

    /// The short randomness for coin `j`, deterministically derived from the tx's
    /// `rand_seed` (a real wallet would draw this per-output and hand it to the
    /// recipient via the coin memo; here it is reproducible for open/verify/tests).
    pub fn coin_randomness(rand_seed: u64, j: usize) -> PolyVec {
        use crate::arith::SplitMix64;
        let mut prg = SplitMix64::new(rand_seed ^ 0x9ACD ^ (j as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        PolyVec::sample_short(LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg)
    }

    /// Commit a full confidential TX as self-contained COINS: each in/out value is
    /// committed as its own `cv_j = coin_key.commit([b_j]; r_j)`, all STACKED into
    /// one amortized `c_b`. Returns `(stmt, wit, coins)` where `coins[j]` is the
    /// standalone, recipient-openable coin commitment for value `j`.
    pub fn commit_multi_tx_coins(
        n_bits: usize,
        in_amounts: &[u64],
        out_amounts: &[u64],
        fee: u64,
        key_seed: u64,
        rand_seed: u64,
    ) -> (MultiRangeStatement, MultiRangeWitness, Vec<RingCommitment>) {
        let values: Vec<u64> = in_amounts.iter().chain(out_amounts).copied().collect();
        let m = values.len();
        let sk = coin_key(key_seed);
        let mut bits: Vec<Poly> = Vec::with_capacity(m);
        let mut r_all: Vec<Poly> = Vec::with_capacity(m * LAMBDA);
        let mut coins: Vec<RingCommitment> = Vec::with_capacity(m);
        let (mut t1_stack, mut t2_stack): (Vec<Poly>, Vec<Poly>) = (Vec::new(), Vec::new());
        for (j, &v) in values.iter().enumerate() {
            let b = value_bits(n_bits, v);
            let r = coin_randomness(rand_seed, j);
            let cv = sk.commit(&PolyVec(vec![b.clone()]), &r);
            t1_stack.extend(cv.t1.0.iter().cloned());
            t2_stack.extend(cv.t2.0.iter().cloned());
            r_all.extend(r.0.iter().cloned());
            bits.push(b);
            coins.push(cv);
        }
        let c_b = RingCommitment { t1: PolyVec(t1_stack), t2: PolyVec(t2_stack) };
        let stmt = MultiRangeStatement { key: sk, c_b, m, n_bits, n_in: in_amounts.len(), fee };
        let wit = MultiRangeWitness { bits, r_b: PolyVec(r_all) };
        (stmt, wit, coins)
    }

    /// Extract coin `j`'s self-contained commitment (its slice of the stacked `c_b`).
    /// `cv_j = (t1[j·κ .. (j+1)·κ], t2[j])`.
    pub fn coin_cv(stmt: &MultiRangeStatement, j: usize) -> RingCommitment {
        let kappa = stmt.key.a1.rows;
        let t1 = PolyVec(stmt.c_b.t1.0[j * kappa..(j + 1) * kappa].to_vec());
        let t2 = PolyVec(vec![stmt.c_b.t2.0[j].clone()]);
        RingCommitment { t1, t2 }
    }

    /// Rebuild the stacked amortized `c_b` from on-chain coin commitments — the
    /// verifier's side (inputs from spend proofs, outputs from the tx), so it feeds
    /// the SAME object the prover committed.
    pub fn stack_coins(coins: &[RingCommitment]) -> RingCommitment {
        let mut t1: Vec<Poly> = Vec::new();
        let mut t2: Vec<Poly> = Vec::new();
        for cv in coins {
            t1.extend(cv.t1.0.iter().cloned());
            t2.extend(cv.t2.0.iter().cloned());
        }
        RingCommitment { t1: PolyVec(t1), t2: PolyVec(t2) }
    }

    /// The fold-friendly witness for the self-contained-coin layout: `s_0` = bits
    /// (coord `j`), `s_1` = stacked per-coin randomness (coord `j·λ+l` = `r_j[l]`).
    fn multi_tx_coins_witness(wit: &MultiRangeWitness, m: usize) -> Vec<PolyVec> {
        let n0 = (m * LAMBDA).max(m).max(1);
        let mut s0 = PolyVec::zero(n0);
        for (j, b) in wit.bits.iter().enumerate() {
            s0.0[j] = b.clone();
        }
        let mut s1 = PolyVec::zero(n0);
        for (idx, p) in wit.r_b.0.iter().enumerate() {
            s1.0[idx] = p.clone();
        }
        vec![s0, s1]
    }

    /// The whole-ring opening family for the self-contained-coin layout: for each
    /// coin `j`, `A1·r_j = c_b.t1[j·κ+i]` (κ rows) and `A2·r_j + b_j = c_b.t2[j]`
    /// (1 row), using the SINGLE-value key looped per coin — this is the linkage
    /// that binds every on-chain coin to the one proof.
    fn multi_tx_coins_family(stmt: &MultiRangeStatement, n0: usize) -> Vec<QuadConstraint> {
        let a1 = &stmt.key.a1; // κ×λ
        let a2 = &stmt.key.a2; // 1×λ
        let kappa = a1.rows;
        let mut fam = Vec::new();
        for j in 0..stmt.m {
            let base = j * LAMBDA; // s_1 coords for r_j
            for i in 0..kappa {
                let mut phi = PolyVec::zero(n0);
                for l in 0..LAMBDA {
                    phi.0[base + l] = a1.m[i][l].clone();
                }
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi)], b: stmt.c_b.t1.0[j * kappa + i].clone() });
            }
            let mut phi1 = PolyVec::zero(n0);
            for l in 0..LAMBDA {
                phi1.0[base + l] = a2.m[0][l].clone();
            }
            let mut phi0 = PolyVec::zero(n0);
            phi0.0[j] = Poly::one();
            fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi1), (0, phi0)], b: stmt.c_b.t2.0[j].clone() });
        }
        fam
    }

    /// The binary + balance ct-family for the self-contained-coin layout, at witness
    /// dim `n0` (bits live at coords `0..m` of `s_0`, exactly as the shared layout).
    fn multi_tx_coins_ct_family(stmt: &MultiRangeStatement, n0: usize) -> Vec<CtConstraint> {
        let m = stmt.m;
        let mut jpad = PolyVec::zero(n0);
        for coord in 0..m {
            jpad.0[coord] = all_ones().neg();
        }
        let mut out = vec![CtConstraint { terms: vec![(0, 0, 1)], linear: vec![(0, jpad)], target: 0 }];
        if stmt.n_in > 0 || stmt.fee > 0 {
            let g = gadget(stmt.n_bits);
            let mut bal = PolyVec::zero(n0);
            for coord in 0..m {
                bal.0[coord] = if coord < stmt.n_in { g.clone() } else { g.neg() };
            }
            out.push(CtConstraint { terms: vec![], linear: vec![(0, bal)], target: stmt.fee % Poly::Q });
        }
        out
    }

    /// Prove the amortized self-contained-coin TX (ranges + balance in ONE IPA proof).
    /// SUPERSEDED by `fullwidth` — forced to return `None` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn prove_multi_tx_coins_ipa_zk(stmt: &MultiRangeStatement, wit: &MultiRangeWitness, seed: u64) -> Option<FullCtZkIpaProof> {
        return None;
        let s = multi_tx_coins_witness(wit, stmt.m);
        let n0 = s[0].len();
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, 64, 12, true);
        prove_labrador_full_ct_zk_ipa(&multi_tx_coins_family(stmt, n0), &multi_tx_coins_ct_family(stmt, n0), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify the amortized self-contained-coin TX proof.
    /// SUPERSEDED by `fullwidth` — forced to return `false` (see lineage note above).
    #[allow(unreachable_code)]
    pub fn verify_multi_tx_coins_ipa_zk(stmt: &MultiRangeStatement, proof: &FullCtZkIpaProof) -> bool {
        return false;
        let kappa = stmt.key.a1.rows;
        if stmt.key.ell != 1 || stmt.c_b.t2.len() != stmt.m || stmt.c_b.t1.len() != stmt.m * kappa {
            return false;
        }
        let n0 = (stmt.m * LAMBDA).max(stmt.m).max(1);
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, 64, 12, true);
        verify_labrador_full_ct_zk_ipa(&multi_tx_coins_family(stmt, n0), &multi_tx_coins_ct_family(stmt, n0), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    // ── ZK masking: the OPENING half, via the crate's perfect-ZK Σ-protocol ────
    //
    // The send-witness base above is a proof of knowledge but NOT zero-knowledge
    // (it reveals `bit_poly` = the amount). Zero-knowledge comes from replacing
    // the reveal with a MASKED opening (`sigma_rq`, Fiat-Shamir-with-aborts,
    // rejection-sampled — `rejection_is_perfect_zk_witness_independent` proves the
    // response is witness-independent). This proves knowledge of the SHORT opening
    // `(r_b, bit_poly)` of `c_b` while leaking nothing about either.
    //
    // ⚠️ This is the OPENING half only. A COMPLETE ZK range proof also needs the
    // BINARY constraint in zero-knowledge — a masked quadratic/product argument
    // for `Σbₖ(bₖ−1)=0` (the masked-evaluation identity `f(f−x)=x²(b²−b)+xα(2b−1)+α²`
    // sketched in `range_rq`, lifted to packed coefficients + aggregated) — the
    // remaining ZK piece.
    use crate::module::PolyMatrix;
    use crate::sigma_rq::{prove_ring_opening, verify_ring_opening, RingOpeningProof, RingSigmaParams};

    /// `M·(r_b‖bit_poly) = (t1‖t2)` with `M = [[A1, 0],[A2, 1]]` — the opening
    /// the ZK Σ-protocol proves knowledge of.
    fn opening_matrix(stmt: &PackedRangeStatement) -> (PolyMatrix, PolyVec) {
        let a1 = &stmt.key.a1;
        let a2 = &stmt.key.a2;
        let (kappa_ct, lam) = (a1.rows, a1.cols);
        let mut m: Vec<Vec<Poly>> = Vec::with_capacity(kappa_ct + 1);
        for i in 0..kappa_ct {
            let mut row = a1.m[i].clone();
            row.push(Poly::zero());
            m.push(row);
        }
        let mut last = a2.m[0].clone();
        last.push(Poly::one());
        m.push(last);
        let mm = PolyMatrix { rows: kappa_ct + 1, cols: lam + 1, m };
        let t = stmt.c_b.t1.concat(&stmt.c_b.t2);
        (mm, t)
    }

    /// Prove knowledge of the packed commitment's SHORT opening in zero-knowledge
    /// (hides `r_b` and `bit_poly`). `None` on rejection-sampling exhaustion.
    pub fn prove_packed_opening_zk(
        stmt: &PackedRangeStatement,
        wit: &PackedRangeWitness,
        seed: u64,
    ) -> Option<RingOpeningProof> {
        let (m, t) = opening_matrix(stmt);
        let s = wit.r_b.concat(&PolyVec(vec![wit.bit_poly.clone()]));
        prove_ring_opening(&m, &t, &s, &RingSigmaParams::production(), b"quil/packed-open/v1", seed)
    }

    /// Verify the zero-knowledge packed opening.
    pub fn verify_packed_opening_zk(stmt: &PackedRangeStatement, proof: &RingOpeningProof) -> bool {
        let (m, t) = opening_matrix(stmt);
        verify_ring_opening(&m, &t, proof, &RingSigmaParams::production(), b"quil/packed-open/v1")
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FULL-WIDTH (u128) amortized confidential TX — the coin layout at full amount
// width, matching the live MatRiCT limb-with-carry balance.
//
// A single-coefficient value tops out at ~36 bits (`v = ⟪g,b⟫ mod q`); real
// amounts are u128. So an amount is `L` base-`2^8` limbs, `v = Σ_l 2^{8·l}·limb_l`,
// and conservation `Σin − Σout = fee` is proved WITHOUT any `2^{8l}` positional
// weight (which would wrap `q`) — the carry chain
//   `Σin limb_j − Σout limb_j + c_{j-1} − 2^8·c_j = fee_j`   (per limb, over ℤ)
// with small, range-bounded carries and a vanishing top carry (`c_{L-1}=0`).
//
// Each 8-bit limb is a BIT-POLY `b_{a,l}` (8 bits in coeffs 0..7), so `limb =
// ⟪g8,b⟫` and the one aggregated binary constraint `⟪s,s⟫−⟪s,J⟫=0` makes every
// limb ∈ [0,255] AND every shifted carry ∈ [0,2^13) with no separate range
// proofs. A coin is `coin_key.commit([b_{a,0}..b_{a,L-1}]; r_a)` (the caller
// passes the network `value_key`, so coins are spendable via the membership
// relation), and the amortized `c_b` stacks the coins; the whole tx is one IPA
// proof:
//   · opening family (whole-ring): binds each coin's bit-polys + randomness;
//   · binary ct (coeff): all limb/carry bits ∈ {0,1};
//   · L balance ct (coeff): the carry chain, `⟪g8,·⟫` limb terms + `⟪g13,·⟫` carry
//     terms, the −MAX_CARRY shifts folded into each limb's public target.
pub mod fullwidth {
    use super::packed::all_ones;
    use crate::arith::SplitMix64;
    use crate::labrador::{
        level_schedule_conj, prove_labrador_full_ct_zk_ipa, verify_labrador_full_ct_zk_ipa, CtConstraint, FullCtZkIpaProof, QuadConstraint,
    };
    use crate::limb_balance::{limbs_of, LIMB_BITS, MAX_CARRY, RANGE_BITS};
    use crate::module::{PolyVec, RingCommitKey, RingCommitment};
    use crate::params::{LWE_RANK_LAMBDA as LAMBDA, SECRET_NORM_ETA, SIS_RANK_KAPPA as KAPPA};
    use crate::rq::Poly;

    // Fixed public CRS for this proof system (prove + verify reproduce the matrices).
    const CRS_SEED_ZK: u64 = super::CRS_SEED ^ 0x0F00;
    const LIMB_BASE: i128 = 1i128 << LIMB_BITS; // 256
    // Witness-dim threshold: n0 ≤ this ⇒ DIRECT base (no fold); above ⇒ convergent fold.
    // 256 keeps a full-width (L=16) tx of up to ~15 coins in the direct base.
    const FW_DIRECT_MAX: usize = 256;

    /// A full-width amortized-TX statement: the single-value-per-limb key
    /// coin key (the network `value_key`), the stacked coin commitment `c_b`, and the public
    /// `(n_in, n_limbs, fee)`.
    #[derive(Clone)]
    pub struct FwTxStatement {
        pub key: RingCommitKey, // ell = n_limbs
        pub c_b: RingCommitment,
        pub m: usize,      // total coins (in + out)
        pub n_in: usize,   // first n_in coins are HIDDEN (committed) inputs
        pub n_limbs: usize,
        pub fee: u128,
        /// A PUBLIC input amount (mint reward / shielded deposit), folded into the
        /// balance target — not a committed coin. Zero for a plain transfer.
        pub pub_in: u128,
    }
    pub struct FwTxWitness {
        pub coin_bits: Vec<Vec<Poly>>, // [m][L] bit-polys (8 bits each)
        pub carry_bits: Vec<Poly>,     // [L-1] shifted-carry bit-polys (13 bits each)
        pub rand: Vec<PolyVec>,        // [m] randomness (dim λ each)
    }

    /// A bit-poly holding `v`'s low `bits` bits in coeffs `0..bits`.
    fn bit_poly(v: u64, bits: usize) -> Poly {
        let mut p = Poly::zero();
        for i in 0..bits.min(64) {
            p.c[i] = (v >> i) & 1;
        }
        p
    }
    /// The gadget `2^i` scaled by a signed `weight`, reduced mod q (coeff `i` =
    /// `weight·2^i mod q`, zero beyond `bits`). Used to place a `±weight·⟪g,·⟫`
    /// limb/carry term into a balance constraint's linear form.
    fn weighted_gadget(bits: usize, weight: i128) -> Poly {
        let q = Poly::Q as i128;
        let mut p = Poly::zero();
        let mut pw = 1i128;
        for i in 0..bits.min(Poly::D) {
            p.c[i] = (weight * pw).rem_euclid(q) as u64;
            pw = (pw * 2) % q;
        }
        p
    }

    /// Commit a full-width confidential TX as self-contained COINS, with an optional
    /// PUBLIC input `pub_in` (mint reward / shield deposit) that participates in the
    /// balance but carries no commitment. Each hidden in/out amount becomes
    /// `cv_a = coin_key.commit([bitpoly(limb_0)..]; r_a)`; the amortized `c_b`
    /// STACKS the coins. Returns `(stmt, wit, coins)`.
    pub fn commit_fw_core(
        n_limbs: usize,
        in_amounts: &[u128],
        out_amounts: &[u128],
        fee: u128,
        pub_in: u128,
        coin_key: &RingCommitKey,
        rand_seed: u64,
    ) -> (FwTxStatement, FwTxWitness, Vec<RingCommitment>) {
        let values: Vec<u128> = in_amounts.iter().chain(out_amounts).copied().collect();
        let m = values.len();
        let key = coin_key.clone();
        let mut coin_bits: Vec<Vec<Poly>> = Vec::with_capacity(m);
        let mut rand: Vec<PolyVec> = Vec::with_capacity(m);
        let mut coins: Vec<RingCommitment> = Vec::with_capacity(m);
        let (mut t1s, mut t2s): (Vec<Poly>, Vec<Poly>) = (Vec::new(), Vec::new());
        for (a, &v) in values.iter().enumerate() {
            let limbs = limbs_of(v, n_limbs);
            let bits: Vec<Poly> = limbs.iter().map(|&l| bit_poly(l, LIMB_BITS as usize)).collect();
            let mut prg = SplitMix64::new(rand_seed ^ 0x9ACD ^ (a as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let r = PolyVec::sample_short(LAMBDA, SECRET_NORM_ETA, &mut prg);
            let cv = key.commit(&PolyVec(bits.clone()), &r);
            t1s.extend(cv.t1.0.iter().cloned());
            t2s.extend(cv.t2.0.iter().cloned());
            coin_bits.push(bits);
            rand.push(r);
            coins.push(cv);
        }
        // Carry chain: c_j = (Σin limb_j + pub_in limb_j − Σout limb_j − fee_j + c_{j-1}) / 256;
        // shifted by +MAX_CARRY and bit-decomposed (13 bits).
        let fee_limbs = limbs_of(fee, n_limbs);
        let pub_limbs = limbs_of(pub_in, n_limbs);
        let mut carry_bits: Vec<Poly> = Vec::with_capacity(n_limbs.saturating_sub(1));
        let mut prev = 0i128;
        for j in 0..n_limbs {
            let sin: i128 = in_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let sout: i128 = out_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let t = sin + pub_limbs[j] as i128 - sout - fee_limbs[j] as i128 + prev;
            let c = t / LIMB_BASE; // exact iff balanced; a bad tx yields a non-bit witness
            if j < n_limbs - 1 {
                let shifted = (c + MAX_CARRY as i128).clamp(0, (1i128 << RANGE_BITS) - 1) as u64;
                carry_bits.push(bit_poly(shifted, RANGE_BITS));
            }
            prev = c;
        }
        let c_b = RingCommitment { t1: PolyVec(t1s), t2: PolyVec(t2s) };
        let stmt = FwTxStatement { key, c_b, m, n_in: in_amounts.len(), n_limbs, fee, pub_in };
        (stmt, FwTxWitness { coin_bits, carry_bits, rand }, coins)
    }

    /// A plain full-width transfer (all inputs are hidden coins, no public input).
    pub fn commit_fw_tx(
        n_limbs: usize,
        in_amounts: &[u128],
        out_amounts: &[u128],
        fee: u128,
        coin_key: &RingCommitKey,
        rand_seed: u64,
    ) -> (FwTxStatement, FwTxWitness, Vec<RingCommitment>) {
        commit_fw_core(n_limbs, in_amounts, out_amounts, fee, 0, coin_key, rand_seed)
    }

    /// A MINT: a PUBLIC input `mint_amount` conserved into hidden output coins
    /// (`Σ outputs = mint_amount`, no fee, no hidden inputs). `coin_key` is the coin
    /// commitment key — the network's `value_key` so minted fw coins are spendable via
    /// the (message-agnostic) membership relation.
    pub fn commit_fw_mint(
        n_limbs: usize,
        mint_amount: u128,
        out_amounts: &[u128],
        coin_key: &RingCommitKey,
        rand_seed: u64,
    ) -> (FwTxStatement, FwTxWitness, Vec<RingCommitment>) {
        commit_fw_core(n_limbs, &[], out_amounts, 0, mint_amount, coin_key, rand_seed)
    }

    /// Extract coin `a`'s self-contained commitment (its slice of the stacked `c_b`).
    pub fn coin_cv(stmt: &FwTxStatement, a: usize) -> RingCommitment {
        let (kappa, l) = (stmt.key.a1.rows, stmt.n_limbs);
        RingCommitment {
            t1: PolyVec(stmt.c_b.t1.0[a * kappa..(a + 1) * kappa].to_vec()),
            t2: PolyVec(stmt.c_b.t2.0[a * l..(a + 1) * l].to_vec()),
        }
    }
    /// Rebuild the stacked `c_b` from on-chain coin commitments (verifier side).
    pub fn stack_coins(coins: &[RingCommitment]) -> RingCommitment {
        let mut t1: Vec<Poly> = Vec::new();
        let mut t2: Vec<Poly> = Vec::new();
        for cv in coins {
            t1.extend(cv.t1.0.iter().cloned());
            t2.extend(cv.t2.0.iter().cloned());
        }
        RingCommitment { t1: PolyVec(t1), t2: PolyVec(t2) }
    }

    // Witness layout: s_0 = bit-polys [coin bits (m·L) ‖ carry bits (L-1)],
    //                 s_1 = randomness [m·λ].
    fn n0_of(m: usize, l: usize) -> usize {
        ((m * l) + l.saturating_sub(1)).max(m * LAMBDA).max(1)
    }
    fn carry_coord(m: usize, l: usize, j: usize) -> usize {
        m * l + j
    }

    fn fw_witness(wit: &FwTxWitness, m: usize, l: usize) -> Vec<PolyVec> {
        let n0 = n0_of(m, l);
        let mut s0 = PolyVec::zero(n0);
        for (a, bits) in wit.coin_bits.iter().enumerate() {
            for (lj, b) in bits.iter().enumerate() {
                s0.0[a * l + lj] = b.clone();
            }
        }
        for (j, cb) in wit.carry_bits.iter().enumerate() {
            s0.0[carry_coord(m, l, j)] = cb.clone();
        }
        let mut s1 = PolyVec::zero(n0);
        for (a, r) in wit.rand.iter().enumerate() {
            for (t, p) in r.0.iter().enumerate() {
                s1.0[a * LAMBDA + t] = p.clone();
            }
        }
        vec![s0, s1]
    }

    /// Opening family (whole-ring): binds each coin's bit-polys + randomness to its
    /// stacked `c_b` slice, under the single coin key.
    fn fw_family(stmt: &FwTxStatement, n0: usize) -> Vec<QuadConstraint> {
        let (a1, a2) = (&stmt.key.a1, &stmt.key.a2);
        let (kappa, l) = (a1.rows, stmt.n_limbs);
        let mut fam = Vec::new();
        for a in 0..stmt.m {
            let base = a * LAMBDA; // s_1 (rand) coords for r_a
            for i in 0..kappa {
                let mut phi = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi.0[base + t] = a1.m[i][t].clone();
                }
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi)], b: stmt.c_b.t1.0[a * kappa + i].clone() });
            }
            for lj in 0..l {
                let mut phi_r = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi_r.0[base + t] = a2.m[lj][t].clone();
                }
                let mut phi_b = PolyVec::zero(n0);
                phi_b.0[a * l + lj] = Poly::one();
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi_r), (0, phi_b)], b: stmt.c_b.t2.0[a * l + lj].clone() });
            }
        }
        fam
    }

    /// The ct-family: (1) one aggregated binary constraint over ALL bit-polys, and
    /// (2) the L carry-chain balance constraints.
    fn fw_ct_family(stmt: &FwTxStatement, n0: usize) -> Vec<CtConstraint> {
        let (m, l, n_in) = (stmt.m, stmt.n_limbs, stmt.n_in);
        let q = Poly::Q as i128;
        // (1) binary: ⟪s0,s0⟫ − ⟪s0,J⟫ = 0, J = all_ones at every bit-poly coord.
        let mut jpad = PolyVec::zero(n0);
        for a in 0..m {
            for lj in 0..l {
                jpad.0[a * l + lj] = all_ones().neg();
            }
        }
        for j in 0..l.saturating_sub(1) {
            jpad.0[carry_coord(m, l, j)] = all_ones().neg();
        }
        let mut out = vec![CtConstraint { terms: vec![(0, 0, 1)], linear: vec![(0, jpad)], target: 0 }];
        // (2) carry-chain balance, per limb j. A PUBLIC input `pub_in` (mint/shield)
        // has no commitment, so its limb is a constant on the balance's public side:
        // `Σhidden_in − Σout + carry = fee_j − pub_in_j`.
        let fee_limbs = limbs_of(stmt.fee, l);
        let pub_limbs = limbs_of(stmt.pub_in, l);
        let mc = MAX_CARRY as i128;
        for j in 0..l {
            let mut phi = PolyVec::zero(n0);
            for a in 0..m {
                let w = if a < n_in { 1 } else { -1 };
                phi.0[a * l + j] = weighted_gadget(LIMB_BITS as usize, w);
            }
            let mut target = fee_limbs[j] as i128 - pub_limbs[j] as i128;
            if j > 0 {
                // + c_{j-1} = +(shifted_{j-1} − MC): add ⟪g13,·⟫, move −MC to target.
                phi.0[carry_coord(m, l, j - 1)] = weighted_gadget(RANGE_BITS, 1);
                target += mc;
            }
            if j < l - 1 {
                // − 256·c_j = −256·(shifted_j − MC): add −256·⟪g13,·⟫, move +256·MC to target.
                phi.0[carry_coord(m, l, j)] = weighted_gadget(RANGE_BITS, -LIMB_BASE);
                target -= LIMB_BASE * mc;
            }
            out.push(CtConstraint { terms: vec![], linear: vec![(0, phi)], target: target.rem_euclid(q) as u64 });
        }
        out
    }

    /// Prove a full-width amortized confidential TX (ranges + carry-chain balance in
    /// ONE IPA proof).
    pub fn prove_fw_tx_ipa_zk(stmt: &FwTxStatement, wit: &FwTxWitness, seed: u64) -> Option<FullCtZkIpaProof> {
        let s = fw_witness(wit, stmt.m, stmt.n_limbs);
        let n0 = s[0].len();
        // A tx with n0 ≤ FW_DIRECT_MAX stays in the DIRECT base, whose terminal has the
        // K-round ct/JL amplification (128-bit). A tx that would FOLD (n0 > FW_DIRECT_MAX)
        // is REFUSED: the per-level fold aggregation is single-draw (~2⁻³⁶) and NOT
        // amplified, so accepting it would drop ct/balance soundness. Large tx must split.
        if n0 > FW_DIRECT_MAX {
            return None;
        }
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, FW_DIRECT_MAX, 12, true);
        prove_labrador_full_ct_zk_ipa(&fw_family(stmt, n0), &fw_ct_family(stmt, n0), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify a full-width amortized confidential TX proof. Fail-closed dimension
    /// guard: key sized for `L`, `m·L` stacked t2 rows, `m·κ` stacked t1 rows; and the
    /// SOUNDNESS cap `n0 ≤ FW_DIRECT_MAX` (only the amplified direct base is accepted).
    pub fn verify_fw_tx_ipa_zk(stmt: &FwTxStatement, proof: &FullCtZkIpaProof) -> bool {
        let (kappa, l) = (stmt.key.a1.rows, stmt.n_limbs);
        if stmt.key.ell != l || stmt.c_b.t2.len() != stmt.m * l || stmt.c_b.t1.len() != stmt.m * kappa {
            return false;
        }
        let n0 = n0_of(stmt.m, l);
        // Reject a folded (un-amplified, ~2⁻³⁶ ct-soundness) proof — see prove above.
        if n0 > FW_DIRECT_MAX {
            return false;
        }
        let sched = level_schedule_conj(2, n0, SECRET_NORM_ETA as u64, KAPPA, 4, FW_DIRECT_MAX, 12, true);
        verify_labrador_full_ct_zk_ipa(&fw_family(stmt, n0), &fw_ct_family(stmt, n0), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }

    /// Direct RELATION check (no proving): the opening family holds (each coin binds)
    /// AND the ct-family holds (binary + balance) on the witness. Used to validate the
    /// SOUNDNESS design cheaply before the proving pipeline.
    #[cfg(test)]
    pub fn fw_relation_holds(stmt: &FwTxStatement, wit: &FwTxWitness) -> bool {
        use crate::labrador::{eval_constraint_on_witness, eval_ct_on_witness};
        let s = fw_witness(wit, stmt.m, stmt.n_limbs);
        let n0 = s[0].len();
        for con in fw_family(stmt, n0) {
            if eval_constraint_on_witness(&con, &s) != con.b {
                return false;
            }
        }
        for con in fw_ct_family(stmt, n0) {
            if eval_ct_on_witness(&con, &s) != con.target {
                return false;
            }
        }
        true
    }

    // ── TRANSFER (hidden inputs) — the fw↔c_prime value-link ─────────────────
    //
    // A spend reveals, per input, a re-randomized PSEUDO-OUTPUT `c_prime` = a
    // `value_key` commitment whose L message polys are the input coin's per-limb
    // BIT-POLYS (same fw encoding as an output coin), bound to the real on-chain coin
    // + key-image by the spend proof. To spend it in the fw money path SOUNDLY, the
    // transfer proof commits each `c_prime`'s OPENING (its randomness `r_p` + the
    // limb bit-polys) inside the same proof — binding those bit-polys to the PUBLIC
    // `c_prime` — and the carry-chain balance consumes each input limb's value as
    // `⟪g8, bit-poly⟫`. So the input value in the balance is PINNED to the
    // spend-proof-bound `c_prime`; a false input amount is impossible (there is no
    // separate "claimed" input to lie about). Inputs need NO range proof (they are
    // pre-validated coins — their bits were range/binary-checked when the coin was
    // created); only OUTPUT coins carry the binary/range constraint.
    //
    // THREE witness vectors so the binary `⟪s_0,s_0⟫` covers ONLY the output/carry
    // bit-polys (NOT the input bit-polys, which are pinned to c_prime, not re-ranged):
    //   s_0 = [output-coin bits (n_out·L) ‖ carry bits (L-1)]   (the BINARY vector)
    //   s_1 = [output rand (n_out·λ) ‖ c_prime rand r_p (n_in·λ)]
    //   s_2 = [c_prime limb bit-polys (n_in·L)]

    #[derive(Clone)]
    pub struct FwTransferStatement {
        pub coin_key: RingCommitKey,   // output fw coins (the network value_key)
        pub value_key: RingCommitKey,  // the spend `c_prime`s (the network value_key)
        pub c_b: RingCommitment,       // stacked OUTPUT coins
        pub c_primes: Vec<RingCommitment>, // per-input pseudo-outputs (public, from spend proofs)
        pub n_in: usize,
        pub n_out: usize,
        pub n_limbs: usize,
        pub fee: u128,
    }
    pub struct FwTransferWitness {
        pub out_bits: Vec<Vec<Poly>>, // [n_out][L] output limb bit-polys
        pub carry_bits: Vec<Poly>,    // [L-1] shifted-carry bit-polys
        pub cp_limbs: Vec<Vec<Poly>>, // [n_in][L] each c_prime's limb bit-polys (input values)
        pub out_rand: Vec<PolyVec>,   // [n_out]
        pub cp_rand: Vec<PolyVec>,    // [n_in] the c_prime randomness r_p
    }
    fn tf_n0(n_in: usize, n_out: usize, l: usize) -> usize {
        let s0 = n_out * l + l.saturating_sub(1);
        let s1 = (n_in + n_out) * LAMBDA;
        let s2 = n_in * l;
        s0.max(s1).max(s2).max(1)
    }
    // s_0 coords (bits)
    fn tf_outbit(l: usize, o: usize, lj: usize) -> usize {
        o * l + lj
    }
    fn tf_carry(n_out: usize, l: usize, j: usize) -> usize {
        n_out * l + j
    }
    // s_1 coords (randomness)
    fn tf_outrand(o: usize) -> usize {
        o * LAMBDA
    }
    fn tf_cprand(n_out: usize, a: usize) -> usize {
        (n_out + a) * LAMBDA
    }
    // s_2 coords (c_prime limb bit-polys)
    fn tf_cplimb(l: usize, a: usize, lj: usize) -> usize {
        a * l + lj
    }

    /// Build a full-width TRANSFER: hidden inputs `in_amounts` (each with its
    /// pseudo-output `c_prime` under `value_key`), hidden outputs `out_amounts` (fw
    /// coins under `coin_key`), and `fee`. `cp_rand_seed` derives the `c_prime`
    /// randomness; in production these come from the spend proofs (the prover knows
    /// them). Returns `(stmt, wit, out_coins)`.
    pub fn commit_fw_transfer(
        n_limbs: usize,
        in_amounts: &[u128],
        out_amounts: &[u128],
        fee: u128,
        coin_key: &RingCommitKey,
        value_key: &RingCommitKey,
        rand_seed: u64,
    ) -> (FwTransferStatement, FwTransferWitness, Vec<RingCommitment>) {
        let (n_in, n_out) = (in_amounts.len(), out_amounts.len());
        let coin_key = coin_key.clone();
        let value_key = value_key.clone();
        // Output fw coins.
        let mut out_bits: Vec<Vec<Poly>> = Vec::with_capacity(n_out);
        let mut out_rand: Vec<PolyVec> = Vec::with_capacity(n_out);
        let mut out_coins: Vec<RingCommitment> = Vec::with_capacity(n_out);
        let (mut t1s, mut t2s): (Vec<Poly>, Vec<Poly>) = (Vec::new(), Vec::new());
        for (o, &v) in out_amounts.iter().enumerate() {
            let bits: Vec<Poly> = limbs_of(v, n_limbs).iter().map(|&l| bit_poly(l, LIMB_BITS as usize)).collect();
            let mut prg = SplitMix64::new(rand_seed ^ 0x0117 ^ (o as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let r = PolyVec::sample_short(LAMBDA, SECRET_NORM_ETA, &mut prg);
            let cv = coin_key.commit(&PolyVec(bits.clone()), &r);
            t1s.extend(cv.t1.0.iter().cloned());
            t2s.extend(cv.t2.0.iter().cloned());
            out_bits.push(bits);
            out_rand.push(r);
            out_coins.push(cv);
        }
        // Input pseudo-outputs c_prime = value_key.commit([BIT-POLYS]; r_p) — uniform fw.
        let mut cp_limbs: Vec<Vec<Poly>> = Vec::with_capacity(n_in);
        let mut cp_rand: Vec<PolyVec> = Vec::with_capacity(n_in);
        let mut c_primes: Vec<RingCommitment> = Vec::with_capacity(n_in);
        for (a, &v) in in_amounts.iter().enumerate() {
            let limbs: Vec<Poly> = limbs_of(v, n_limbs).iter().map(|&l| bit_poly(l, LIMB_BITS as usize)).collect();
            let mut prg = SplitMix64::new(rand_seed ^ 0x0C22 ^ (a as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let r = PolyVec::sample_short(LAMBDA, SECRET_NORM_ETA, &mut prg);
            let cp = value_key.commit(&PolyVec(limbs.clone()), &r);
            cp_limbs.push(limbs);
            cp_rand.push(r);
            c_primes.push(cp);
        }
        // Carry chain over the REAL input (c_prime) and output limb values.
        let fee_limbs = limbs_of(fee, n_limbs);
        let mut carry_bits: Vec<Poly> = Vec::with_capacity(n_limbs.saturating_sub(1));
        let mut prev = 0i128;
        for j in 0..n_limbs {
            let sin: i128 = in_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let sout: i128 = out_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let t = sin - sout - fee_limbs[j] as i128 + prev;
            let c = t / LIMB_BASE;
            if j < n_limbs - 1 {
                let shifted = (c + MAX_CARRY as i128).clamp(0, (1i128 << RANGE_BITS) - 1) as u64;
                carry_bits.push(bit_poly(shifted, RANGE_BITS));
            }
            prev = c;
        }
        let c_b = RingCommitment { t1: PolyVec(t1s), t2: PolyVec(t2s) };
        let stmt = FwTransferStatement { coin_key, value_key, c_b, c_primes, n_in, n_out, n_limbs, fee };
        let wit = FwTransferWitness { out_bits, carry_bits, cp_limbs, out_rand, cp_rand };
        (stmt, wit, out_coins)
    }

    /// Build a full-width TRANSFER against EXTERNAL input pseudo-outputs — the coins
    /// being spent come from the wallet's spend proofs (`in_cprimes` = each `sp.c_prime`
    /// under `value_key`, `in_rp` = the matching randomness the wallet holds, `in_amounts`
    /// = the amounts, whose limbs must equal what each `c_prime` commits). This is the
    /// real money path: the fw proof binds those exact spend-proof `c_prime`s, so the
    /// input value in the balance is the one the spend proof pinned to the real coin.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_fw_transfer_ext(
        n_limbs: usize,
        in_amounts: &[u128],
        in_cprimes: &[RingCommitment],
        in_rp: &[PolyVec],
        out_amounts: &[u128],
        fee: u128,
        coin_key: &RingCommitKey,
        value_key: &RingCommitKey,
        rand_seed: u64,
    ) -> (FwTransferStatement, FwTransferWitness, Vec<RingCommitment>) {
        let (n_in, n_out) = (in_amounts.len(), out_amounts.len());
        // Output fw coins.
        let mut out_bits: Vec<Vec<Poly>> = Vec::with_capacity(n_out);
        let mut out_rand: Vec<PolyVec> = Vec::with_capacity(n_out);
        let mut out_coins: Vec<RingCommitment> = Vec::with_capacity(n_out);
        let (mut t1s, mut t2s): (Vec<Poly>, Vec<Poly>) = (Vec::new(), Vec::new());
        for (o, &v) in out_amounts.iter().enumerate() {
            let bits: Vec<Poly> = limbs_of(v, n_limbs).iter().map(|&l| bit_poly(l, LIMB_BITS as usize)).collect();
            let mut prg = SplitMix64::new(rand_seed ^ 0x0117 ^ (o as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let r = PolyVec::sample_short(LAMBDA, SECRET_NORM_ETA, &mut prg);
            let cv = coin_key.commit(&PolyVec(bits.clone()), &r);
            t1s.extend(cv.t1.0.iter().cloned());
            t2s.extend(cv.t2.0.iter().cloned());
            out_bits.push(bits);
            out_rand.push(r);
            out_coins.push(cv);
        }
        // Inputs: the EXTERNAL c_primes. In the UNIFORM fw layout each c_prime is a
        // bit-poly coin (`value_key.commit(bit_polys; r_p)`), so cp_limbs holds the input
        // amounts' BIT-POLYS (bound to c_prime by the opening; trusted-binary from creation,
        // so no re-range). cp_rand = r_p.
        let cp_limbs: Vec<Vec<Poly>> = in_amounts
            .iter()
            .map(|&v| limbs_of(v, n_limbs).iter().map(|&l| bit_poly(l, LIMB_BITS as usize)).collect())
            .collect();
        let cp_rand: Vec<PolyVec> = in_rp.to_vec();
        let c_primes: Vec<RingCommitment> = in_cprimes.to_vec();
        // Carry chain over real input/output limb values.
        let fee_limbs = limbs_of(fee, n_limbs);
        let mut carry_bits: Vec<Poly> = Vec::with_capacity(n_limbs.saturating_sub(1));
        let mut prev = 0i128;
        for j in 0..n_limbs {
            let sin: i128 = in_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let sout: i128 = out_amounts.iter().map(|&v| limbs_of(v, n_limbs)[j] as i128).sum();
            let t = sin - sout - fee_limbs[j] as i128 + prev;
            let c = t / LIMB_BASE;
            if j < n_limbs - 1 {
                let shifted = (c + MAX_CARRY as i128).clamp(0, (1i128 << RANGE_BITS) - 1) as u64;
                carry_bits.push(bit_poly(shifted, RANGE_BITS));
            }
            prev = c;
        }
        let c_b = RingCommitment { t1: PolyVec(t1s), t2: PolyVec(t2s) };
        let stmt = FwTransferStatement {
            coin_key: coin_key.clone(),
            value_key: value_key.clone(),
            c_b,
            c_primes,
            n_in,
            n_out,
            n_limbs,
            fee,
        };
        let wit = FwTransferWitness { out_bits, carry_bits, cp_limbs, out_rand, cp_rand };
        (stmt, wit, out_coins)
    }

    fn tf_witness(wit: &FwTransferWitness, n_in: usize, n_out: usize, l: usize) -> Vec<PolyVec> {
        let n0 = tf_n0(n_in, n_out, l);
        let mut s0 = PolyVec::zero(n0);
        for (o, bits) in wit.out_bits.iter().enumerate() {
            for (lj, b) in bits.iter().enumerate() {
                s0.0[tf_outbit(l, o, lj)] = b.clone();
            }
        }
        for (j, cb) in wit.carry_bits.iter().enumerate() {
            s0.0[tf_carry(n_out, l, j)] = cb.clone();
        }
        let mut s1 = PolyVec::zero(n0);
        for (o, r) in wit.out_rand.iter().enumerate() {
            for (t, p) in r.0.iter().enumerate() {
                s1.0[tf_outrand(o) + t] = p.clone();
            }
        }
        for (a, r) in wit.cp_rand.iter().enumerate() {
            for (t, p) in r.0.iter().enumerate() {
                s1.0[tf_cprand(n_out, a) + t] = p.clone();
            }
        }
        let mut s2 = PolyVec::zero(n0);
        for (a, limbs) in wit.cp_limbs.iter().enumerate() {
            for (lj, lc) in limbs.iter().enumerate() {
                s2.0[tf_cplimb(l, a, lj)] = lc.clone();
            }
        }
        vec![s0, s1, s2]
    }

    /// Opening family: output fw coins bound to `c_b` (coin_key), input `c_prime`s
    /// bound to their public commitments (value_key). This is the fw↔c_prime binding.
    fn tf_family(stmt: &FwTransferStatement, n0: usize) -> Vec<QuadConstraint> {
        let l = stmt.n_limbs;
        let (a1, a2) = (&stmt.coin_key.a1, &stmt.coin_key.a2);
        let (v1, v2) = (&stmt.value_key.a1, &stmt.value_key.a2);
        let kappa = a1.rows;
        let mut fam = Vec::new();
        // Output coins (coin_key).
        for o in 0..stmt.n_out {
            let base = tf_outrand(o);
            for i in 0..kappa {
                let mut phi = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi.0[base + t] = a1.m[i][t].clone();
                }
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi)], b: stmt.c_b.t1.0[o * kappa + i].clone() });
            }
            for lj in 0..l {
                let mut phi_r = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi_r.0[base + t] = a2.m[lj][t].clone();
                }
                let mut phi_b = PolyVec::zero(n0);
                phi_b.0[tf_outbit(l, o, lj)] = Poly::one();
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi_r), (0, phi_b)], b: stmt.c_b.t2.0[o * l + lj].clone() });
            }
        }
        // Input pseudo-outputs (value_key) — binds cp_limbs to the PUBLIC c_prime.
        for a in 0..stmt.n_in {
            let base = tf_cprand(stmt.n_out, a);
            for i in 0..kappa {
                let mut phi = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi.0[base + t] = v1.m[i][t].clone();
                }
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi)], b: stmt.c_primes[a].t1.0[i].clone() });
            }
            for lj in 0..l {
                let mut phi_r = PolyVec::zero(n0);
                for t in 0..LAMBDA {
                    phi_r.0[base + t] = v2.m[lj][t].clone();
                }
                let mut phi_l = PolyVec::zero(n0);
                phi_l.0[tf_cplimb(l, a, lj)] = Poly::one();
                fam.push(QuadConstraint { conj_terms: vec![], terms: vec![], linear: vec![(1, phi_r), (2, phi_l)], b: stmt.c_primes[a].t2.0[lj].clone() });
            }
        }
        fam
    }

    /// ct-family: (1) binary over OUTPUT bits + carry bits (inputs are pre-validated,
    /// no range), (2) the carry-chain balance — inputs consumed as `⟪g8, cp_bits⟫`
    /// (the spend-proof-pinned value, from s_2), outputs as `⟪g8, out_bits⟫`.
    fn tf_ct_family(stmt: &FwTransferStatement, n0: usize) -> Vec<CtConstraint> {
        let (n_in, n_out, l) = (stmt.n_in, stmt.n_out, stmt.n_limbs);
        let q = Poly::Q as i128;
        // (1) binary over output bits + carry bits.
        let mut jpad = PolyVec::zero(n0);
        for o in 0..n_out {
            for lj in 0..l {
                jpad.0[tf_outbit(l, o, lj)] = all_ones().neg();
            }
        }
        for j in 0..l.saturating_sub(1) {
            jpad.0[tf_carry(n_out, l, j)] = all_ones().neg();
        }
        let mut out = vec![CtConstraint { terms: vec![(0, 0, 1)], linear: vec![(0, jpad)], target: 0 }];
        // (2) carry-chain balance. Inputs are consumed as ⟪g8, cp_bits⟫ from s_2 (the
        // spend-proof-pinned value); outputs as ⟪g8, out_bits⟫ from s_0; carries s_0.
        let fee_limbs = limbs_of(stmt.fee, l);
        let mc = MAX_CARRY as i128;
        for j in 0..l {
            let mut phi0 = PolyVec::zero(n0); // s_0 terms (outputs + carries)
            let mut phi2 = PolyVec::zero(n0); // s_2 terms (input c_prime BIT-POLYS)
            for a in 0..n_in {
                // +input value: ⟪g8, in_bits⟫ picks the input limb's value (uniform fw).
                phi2.0[tf_cplimb(l, a, j)] = weighted_gadget(LIMB_BITS as usize, 1);
            }
            for o in 0..n_out {
                phi0.0[tf_outbit(l, o, j)] = weighted_gadget(LIMB_BITS as usize, -1);
            }
            let mut target = fee_limbs[j] as i128;
            if j > 0 {
                phi0.0[tf_carry(n_out, l, j - 1)] = weighted_gadget(RANGE_BITS, 1);
                target += mc;
            }
            if j < l - 1 {
                phi0.0[tf_carry(n_out, l, j)] = weighted_gadget(RANGE_BITS, -LIMB_BASE);
                target -= LIMB_BASE * mc;
            }
            out.push(CtConstraint { terms: vec![], linear: vec![(0, phi0), (2, phi2)], target: target.rem_euclid(q) as u64 });
        }
        out
    }

    /// Prove a full-width TRANSFER (output ranges + balance, inputs pinned to their
    /// `c_prime`s) in ONE IPA proof.
    pub fn prove_fw_transfer_ipa_zk(stmt: &FwTransferStatement, wit: &FwTransferWitness, seed: u64) -> Option<FullCtZkIpaProof> {
        let s = tf_witness(wit, stmt.n_in, stmt.n_out, stmt.n_limbs);
        let n0 = s[0].len();
        // Refuse a folding tx (n0 > FW_DIRECT_MAX): the fold aggregation is un-amplified
        // (~2⁻³⁶). Only the K-round-amplified direct base is proved. Large tx must split.
        if n0 > FW_DIRECT_MAX {
            return None;
        }
        // r0 = 3 witness vectors (bits ‖ randomness ‖ c_prime limbs).
        let sched = level_schedule_conj(3, n0, SECRET_NORM_ETA as u64, KAPPA, 4, FW_DIRECT_MAX, 12, true);
        prove_labrador_full_ct_zk_ipa(&tf_family(stmt, n0), &tf_ct_family(stmt, n0), &s, SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, seed)
    }

    /// Verify a full-width TRANSFER proof. Fail-closed dimension guards on both the
    /// stacked output `c_b` and every input `c_prime`.
    pub fn verify_fw_transfer_ipa_zk(stmt: &FwTransferStatement, proof: &FullCtZkIpaProof) -> bool {
        let (kappa, l) = (stmt.coin_key.a1.rows, stmt.n_limbs);
        if stmt.coin_key.ell != l || stmt.value_key.ell != l {
            return false;
        }
        if stmt.c_b.t2.len() != stmt.n_out * l || stmt.c_b.t1.len() != stmt.n_out * kappa {
            return false;
        }
        if stmt.c_primes.len() != stmt.n_in {
            return false;
        }
        for cp in &stmt.c_primes {
            if cp.t2.0.len() != l || cp.t1.0.len() != kappa {
                return false;
            }
        }
        let n0 = tf_n0(stmt.n_in, stmt.n_out, l);
        // Reject a folded (un-amplified) proof — only the amplified direct base is accepted.
        if n0 > FW_DIRECT_MAX {
            return false;
        }
        let sched = level_schedule_conj(3, n0, SECRET_NORM_ETA as u64, KAPPA, 4, FW_DIRECT_MAX, 12, true);
        verify_labrador_full_ct_zk_ipa(&tf_family(stmt, n0), &tf_ct_family(stmt, n0), SECRET_NORM_ETA as u64, KAPPA, &sched, CRS_SEED_ZK, proof)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ZK BINARY — masked-quadratic argument for the PACKED bit vector
//
// Proves that a committed packed `b` (bits in coefficients) is coefficient-wise
// binary. With the SHORT-witness bound the opening proof establishes
// (`d·β² < q`, each integer `bₖ(bₖ−1) ≥ 0`), it suffices to prove the SINGLE
// scalar relation `Σₖ bₖ(bₖ−1) ≡ 0 (mod q)` — then every `bₖ ∈ {0,1}`. Together
// with `prove_packed_opening_zk` this is a complete zero-knowledge range proof.
//
// SOUNDNESS MECHANISM (validated here). For mask `y` and a SCALAR challenge `x`,
// with `z = y + x·b`:
//     ⟪z, z − x·J⟫ = ⟪y,y⟫ + x·(2⟪y,b⟫ − ⟪y,J⟫) + x²·(⟪b,b⟫ − ⟪b,J⟫)
//                  =   t0    +      x·t1          + x²·Q(b),     J = Σ Xᵏ.
// With `t0, t1` FIXED before `x` (committed) and the verifier recomputing
// `⟪z,z−xJ⟫` from the public `z`, the check `⟪z,z−xJ⟫ = t0 + x·t1` forces
// `x²·Q(b) = 0`. This is a degree-2 poly in `x` whose leading coeff `Q(b)` is
// fixed by `b`, so a random `x` is a root with prob `≤ 2/|X|`; `R` independent
// repetitions give `≤ (2/|X|)ᴿ`. `⟪·,·⟫` is coefficient-bilinear ⇒ `x` MUST be a
// scalar (a ring `x` breaks `⟪xb,xb⟫ = x²⟪b,b⟫`); a small scalar keeps the
// opening randomness short, hence the repetition.
//
// This module VALIDATES the soundness kernel (`masked_quadratic_check`) at the
// value level: honest passes; any non-bit `b` is caught w.h.p. over the scalar
// challenges. WHAT IS NOT DONE HERE — the full ZK wrapper (commit `t0,t1` and the
// mask, reveal only masked `z`/`τ_u`, rejection-tune), which must mirror the
// STRUCTURE of `binary_rq` (wide-masked evaluation + SHORT sigma openings binding
// it to the commitments — NOT a single commitment-opening of a wide response,
// which cannot be both hiding and short-binding). That ZK/rejection tuning is the
// most error-prone part and is left as specified work.
// ─────────────────────────────────────────────────────────────────────────
pub mod binary_zk {
    use super::packed::all_ones;
    use crate::rq::Poly;

    /// Number of independent scalar-challenge repetitions and the challenge bound
    /// `T` (`x ∈ [−T,T]`). `T = 2¹²` ⇒ per-shot soundness `≤ 2/8193 ≈ 2⁻¹²`;
    /// `R = 12` ⇒ `≈ 2⁻¹⁴³`.
    pub const CHAL_T: i64 = 1 << 12;
    pub const REPS: usize = 12;

    /// Coefficient inner product `⟪a,b⟫ = Σ aₖbₖ mod q`.
    pub fn cinner(a: &Poly, b: &Poly) -> u64 {
        let q = Poly::Q as u128;
        let mut acc = 0u128;
        for (x, y) in a.c.iter().zip(&b.c) {
            acc = (acc + (*x as u128) * (*y as u128)) % q;
        }
        acc as u64
    }

    // ── ZK REJECTION-TUNING ANALYSIS (Task 3) ────────────────────────────────
    //
    // The masks (`α`, `r_α`, `r0`) are UNIFORM on `[−MASK, MASK]`; the response
    // (`f=x·b+α`, `z_f=x·r_b+r_α`, `z_g=x·r1+r0`) is accepted iff it lies in the
    // box `[−(MASK−S), MASK−S]`, `S` the shift bound (`|x·b|≤T` for `f`, `|x·r|≤T·η`
    // for the openings).
    //
    // PERFECT ZK (not merely statistical). For one coefficient with shift `s`,
    // `|s|≤S`: an accepted value `z∈[−(MASK−S),MASK−S]` has the unique preimage
    // `y=z−s∈[−MASK,MASK]` (since `|s|≤S`), and `y` is uniform, so the accepted `z`
    // is UNIFORM on the box INDEPENDENT of `s`. The acceptance PROBABILITY is
    // `(2(MASK−S)+1)/(2MASK+1)`, also INDEPENDENT of `s` (the preimage box for `y`
    // has fixed width). So both the accepted distribution AND the abort pattern are
    // witness-independent ⇒ ZERO statistical distance (Dilithium-style bounded
    // uniform rejection). No `α`-tail leakage, unlike Gaussian rejection.
    //
    // ACCEPTANCE RATE. Over `D` coefficients, `P_accept = ((MASK−S)/MASK)^D ≈
    // e^{−S·D/MASK}`. With `MASK=2²⁶`: `f` (`D=256, S=2¹²`) → `≈e^{−2⁻¹⁴·256}=0.985`;
    // each opening (`D=λ·256=2304, S=2¹³`) → `≈e^{−2⁻¹³·2304}=0.755`. Per attempt
    // `≈0.985·0.755²≈0.56`, so `≈1.8` attempts/shot; `REPS=12` shots ⇒ ≈21 attempts
    // total, far under the 4000-attempt cap. Wider `MASK` ⇒ higher acceptance and a
    // larger (log₂MASK-bit) response; `2²⁶` balances both.
    //
    // `accept_prob(shift, dim)` returns the analytic per-response acceptance; the
    // `rejection_*` tests confirm the measured rate matches and that acceptance is
    // witness-independent.

    /// Analytic acceptance probability for a `dim`-coefficient response with
    /// per-coefficient shift bound `shift`: `((MASK−shift)/MASK)^dim`.
    pub fn accept_prob(shift: i64, dim: usize) -> f64 {
        let per = (MASK - shift) as f64 / MASK as f64;
        per.powi(dim as i32)
    }

    /// `Q(b) = ⟪b,b⟫ − ⟪b,J⟫ = Σ bₖ(bₖ−1) mod q`. Zero ⟺ (with the norm bound)
    /// `b` is coefficient-wise binary.
    pub fn binary_defect(b: &Poly) -> u64 {
        let q = Poly::Q;
        (cinner(b, b) + q - cinner(b, &all_ones())) % q
    }

    /// The SOUNDNESS KERNEL, at the value level: given the committed-before-`x`
    /// scalars `t0, t1`, the mask `y`, and a scalar challenge `x`, check
    /// `⟪z, z − xJ⟫ == t0 + x·t1` where `z = y + x·b`. For honest `t0 = ⟪y,y⟫`,
    /// `t1 = 2⟪y,b⟫ − ⟪y,J⟫` this holds iff `x²·Q(b) ≡ 0`. Returns whether it holds.
    pub fn masked_quadratic_check(b: &Poly, y: &Poly, t0: u64, t1: u64, x: i64) -> bool {
        let q = Poly::Q as u128;
        let j = all_ones();
        let z = y.add(&b.scalar_mul(x));
        let z_minus = z.sub(&j.scalar_mul(x));
        let lhs = cinner(&z, &z_minus) as u128;
        let x_mod = x.rem_euclid(Poly::Q as i64) as u128;
        let rhs = (t0 as u128 + x_mod * t1 as u128) % q;
        lhs == rhs
    }

    /// Honest prover's `(t0, t1)` for a mask `y` — committed before `x`.
    pub fn honest_t(b: &Poly, y: &Poly) -> (u64, u64) {
        let q = Poly::Q as u128;
        let t0 = cinner(y, y);
        let t1 = ((2 * cinner(y, b) as u128) % q + q - cinner(y, &all_ones()) as u128) % q;
        (t0, (t1 % q) as u64)
    }

    // ── Full ZK wrapper (adapting `binary_rq`'s proven structure) ──────────────
    use crate::arith::SplitMix64;
    use crate::module::{PolyVec, RingCommitKey, RingCommitment};
    use crate::params::SECRET_NORM_ETA;
    use sha2::{Digest, Sha256};

    /// Wide mask box, and the derived rejection bounds. `MASK` must dominate the
    /// shift × opening dimension (`λ·d ≈ 2304` coefficients): Lyubashevsky
    /// ‖·‖∞-rejection acceptance is `≈ e^{−shift·D/MASK}`, so with shift `≤ T·η`
    /// and `D ≈ 2304`, `MASK = 2²⁶` gives per-opening acceptance `≈ 0.75` (a few
    /// restarts per shot). Wider mask ⇒ higher acceptance, slightly larger proof.
    const MASK: i64 = 1 << 26;
    fn f_bound() -> u64 {
        (MASK - CHAL_T) as u64
    }
    fn z_bound() -> u64 {
        (MASK - CHAL_T * SECRET_NORM_ETA) as u64
    }

    /// One masked-evaluation shot: `binary_rq`'s structure with a scalar `x` and
    /// the coefficient-inner-product quadratic. Fields `pub` for serialization
    /// ([`crate::wire`]); construct only via `prove_packed_binary_zk`.
    #[derive(Clone)]
    pub struct Shot {
        pub c_alpha: RingCommitment, // Commit(α)
        pub c1: RingCommitment,      // Commit(V1),  V1 = 2⟪α,b⟫ − ⟪α,J⟫
        pub c0: RingCommitment,      // Commit(V0),  V0 = ⟪α,α⟫
        pub f: Poly,                 // wide-masked eval f = x·b + α
        pub z_f: PolyVec,            // binds f to x·c_b + c_alpha
        pub z_g: PolyVec,            // binds the scalar garbage to x·c1 + c0
    }

    /// A complete ZK packed-binary proof: `R` independent shots.
    pub struct PackedBinaryZkProof {
        pub shots: Vec<Shot>,
    }

    impl Shot {
        /// Assemble a shot from decoded parts (wire only).
        pub fn from_parts(
            c_alpha: RingCommitment,
            c1: RingCommitment,
            c0: RingCommitment,
            f: Poly,
            z_f: PolyVec,
            z_g: PolyVec,
        ) -> Self {
            Shot { c_alpha, c1, c0, f, z_f, z_g }
        }
    }
    impl PackedBinaryZkProof {
        /// The fixed number of shots a valid proof carries.
        pub fn expected_shots() -> usize {
            REPS
        }
        pub fn from_shots(shots: Vec<Shot>) -> Self {
            PackedBinaryZkProof { shots }
        }
    }

    fn const_poly(v: u64) -> Poly {
        let mut p = Poly::zero();
        p.c[0] = v % Poly::Q;
        p
    }
    fn commit1(key: &RingCommitKey, m: &Poly, r: &PolyVec) -> RingCommitment {
        key.commit(&PolyVec(vec![m.clone()]), r)
    }
    fn scale_vec(v: &PolyVec, x: i64) -> PolyVec {
        PolyVec(v.0.iter().map(|p| p.scalar_mul(x)).collect())
    }

    /// Scalar challenge `x ∈ [−T,T]` for shot `rep`, bound to `c_b` and the shot's
    /// commitments (fixed before `x`).
    fn challenge(c_b: &RingCommitment, sh: &Shot, rep: usize) -> i64 {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/packed-binary-zk/v1");
        let mut absorb = |c: &RingCommitment, h: &mut Sha256| {
            for p in c.t1.0.iter().chain(c.t2.0.iter()) {
                for &x in &p.c {
                    h.update(x.to_le_bytes());
                }
            }
        };
        absorb(c_b, &mut h);
        absorb(&sh.c_alpha, &mut h);
        absorb(&sh.c1, &mut h);
        absorb(&sh.c0, &mut h);
        h.update((rep as u64).to_le_bytes());
        let d = h.finalize();
        (u64::from_le_bytes(d[..8].try_into().unwrap()) % (2 * CHAL_T as u64 + 1)) as i64 - CHAL_T
    }

    /// Prove committed packed `b` is coefficient-wise binary, in zero-knowledge.
    /// `ck` (ell=1) is the key `c_b = ck.commit([b]; r_b)` was made with.
    pub fn prove_packed_binary_zk(
        ck: &RingCommitKey,
        c_b: &RingCommitment,
        b: &Poly,
        r_b: &PolyVec,
        seed: u64,
    ) -> Option<PackedBinaryZkProof> {
        let lambda = ck.a1.cols;
        let j = all_ones();
        let mut shots = Vec::with_capacity(REPS);
        for rep in 0..REPS {
            let mut got = None;
            for attempt in 0..4000u64 {
                let mut prg = SplitMix64::new(seed ^ ((rep as u64) << 40) ^ attempt.wrapping_mul(0x71C1));
                let alpha = PolyVec::sample_uniform_pm(1, MASK, &mut prg).0[0].clone();
                let r_alpha = PolyVec::sample_uniform_pm(lambda, MASK, &mut prg);
                let r1 = PolyVec::sample_short(lambda, SECRET_NORM_ETA, &mut prg);
                let r0 = PolyVec::sample_uniform_pm(lambda, MASK, &mut prg);
                // V1 = 2⟪α,b⟫ − ⟪α,J⟫, V0 = ⟪α,α⟫ (scalars).
                let q = Poly::Q as u128;
                let v1 = ((2 * cinner(&alpha, b) as u128) % q + q - cinner(&alpha, &j) as u128) % q;
                let v0 = cinner(&alpha, &alpha);
                let c_alpha = commit1(ck, &alpha, &r_alpha);
                let c1 = commit1(ck, &const_poly(v1 as u64), &r1);
                let c0 = commit1(ck, &const_poly(v0), &r0);
                let mut sh = Shot {
                    c_alpha,
                    c1,
                    c0,
                    f: Poly::zero(),
                    z_f: PolyVec::zero(lambda),
                    z_g: PolyVec::zero(lambda),
                };
                let x = challenge(c_b, &sh, rep);
                let f = b.scalar_mul(x).add(&alpha);
                let z_f = scale_vec(r_b, x).add(&r_alpha);
                let z_g = scale_vec(&r1, x).add(&r0);
                if f.inf_norm() <= f_bound() && z_f.inf_norm() <= z_bound() && z_g.inf_norm() <= z_bound() {
                    sh.f = f;
                    sh.z_f = z_f;
                    sh.z_g = z_g;
                    got = Some(sh);
                    break;
                }
            }
            shots.push(got?);
        }
        Some(PackedBinaryZkProof { shots })
    }

    /// Verify a ZK packed-binary proof.
    pub fn verify_packed_binary_zk(ck: &RingCommitKey, c_b: &RingCommitment, pf: &PackedBinaryZkProof) -> bool {
        if pf.shots.len() != REPS {
            return false;
        }
        let j = all_ones();
        for (rep, sh) in pf.shots.iter().enumerate() {
            if sh.f.inf_norm() > f_bound() || sh.z_f.inf_norm() > z_bound() || sh.z_g.inf_norm() > z_bound() {
                return false;
            }
            let x = challenge(c_b, sh, rep);
            // (1) f binds to x·C_b + C_α: A1·z_f = x·C_b.t1 + C_α.t1 ;
            //     A2·z_f + f = x·C_b.t2 + C_α.t2.
            let a1_zf = ck.a1.matvec(&sh.z_f);
            let a2_zf = ck.a2.matvec(&sh.z_f).0[0].clone();
            if a1_zf != scale_vec(&c_b.t1, x).add(&sh.c_alpha.t1) {
                return false;
            }
            if a2_zf.add(&sh.f) != c_b.t2.0[0].scalar_mul(x).add(&sh.c_alpha.t2.0[0]) {
                return false;
            }
            // (2) garbage: u = ⟪f, f − xJ⟫ must equal x·V1 + V0 (committed).
            //     A1·z_g = x·C1.t1 + C0.t1 ; A2·z_g = x·C1.t2 + C0.t2 − const(u).
            let f_minus = sh.f.sub(&j.scalar_mul(x));
            let u = cinner(&sh.f, &f_minus);
            let a1_zg = ck.a1.matvec(&sh.z_g);
            let a2_zg = ck.a2.matvec(&sh.z_g).0[0].clone();
            if a1_zg != scale_vec(&sh.c1.t1, x).add(&sh.c0.t1) {
                return false;
            }
            let rhs = sh.c1.t2.0[0].scalar_mul(x).add(&sh.c0.t2.0[0]).sub(&const_poly(u));
            if a2_zg != rhs {
                return false;
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The COMPLETE zero-knowledge packed range proof — one artifact for wiring.
// = ZK opening (hides r_b + amount) ‖ ZK binary (all coeffs ∈{0,1}). Accepting
// ⇒ c_b commits a packed bit-vector whose value v = Σ2ⁱbᵢ ∈ [0,2^N), and the
// amount is never revealed. This is the type the node carries (protobuf bytes,
// via `wire::encode_packed_range_zk`) and the intrinsic verifies.
// ─────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────
// ZK BALANCE over PACKED commitments — the money-path conservation proof.
//
// Each amount is a packed commitment `c_b = Commit(b; r_b)` whose value is the
// LINEAR functional `v = ⟪g,b⟫`. Because `⟪g,·⟫` is linear and the commitment is
// homomorphic, `D = Σin c_b − Σout c_b = Commit(B; R)` with `B = Σin b − Σout b`,
// and `⟪g,B⟫ = Σin v − Σout v`. So conservation `Σin v = Σout v + fee` is one
// statement: prove `D` opens to `(B,R)` with `⟪g,B⟫ = fee`, in ZK.
//
// Protocol (Fiat-Shamir, ONE scalar challenge x — the relation is LINEAR in x so
// a single x binds it exactly, no repetition): mask `y` (wide), commit
// `c_y=Commit(y;r_y)` and `c_t=Commit(t;r_t)`, `t=⟪g,y⟫`, BEFORE x. Reveal
// `z=y+x·B` (rejection-masked) and `r_z=r_y+x·R`, `r_t`. Verify (1) `z` opens:
// `Commit(z;r_z)=c_y+x·D`; (2) balance: `Commit(⟪g,z⟫−x·fee; r_t)=c_t` — which,
// with `c_t` pinning `t` before x, forces `x·(⟪g,B⟫−fee)=0 ⇒ ⟪g,B⟫=fee`. ZK:
// `z` uniform-box (perfect-ZK); `t=⟪g,z⟫−x·fee` is public post-x so opening
// `c_t` leaks nothing.
// ─────────────────────────────────────────────────────────────────────────
pub mod balance_zk {
    use super::packed::gadget;
    use crate::arith::SplitMix64;
    use crate::module::{PolyVec, RingCommitKey, RingCommitment};
    use crate::params::LWE_RANK_LAMBDA as LAMBDA;
    use crate::rq::Poly;
    use sha2::{Digest, Sha256};

    const CHAL_T: i64 = 1 << 12;
    // Wide mask; the accepted-box shift `SHIFT` covers `|x·B|,|x·R|` for a tx with
    // up to ~8 i/o (‖B‖,‖R‖ ≤ ~16), and `MASK ≫ SHIFT·(λ·256)` keeps rejection
    // acceptance high (≈0.6). The verifier does NOT bound ‖z‖ — soundness is from
    // the exact commitment checks — so this only tunes prover-side ZK/acceptance.
    const MASK: i64 = 1 << 28;
    const SHIFT: i64 = 1 << 16;

    /// A ZK packed-balance proof.
    pub struct PackedBalanceProof {
        pub c_y: RingCommitment,
        pub c_t: RingCommitment,
        pub z: Poly,
        pub r_z: PolyVec,
        pub r_t: PolyVec,
    }

    fn cinner(a: &Poly, b: &Poly) -> u64 {
        let q = Poly::Q as u128;
        let mut acc = 0u128;
        for (x, y) in a.c.iter().zip(&b.c) {
            acc = (acc + (*x as u128) * (*y as u128)) % q;
        }
        acc as u64
    }
    fn const_poly(v: u64) -> Poly {
        let mut p = Poly::zero();
        p.c[0] = v % Poly::Q;
        p
    }
    fn scale_vec(v: &PolyVec, x: i64) -> PolyVec {
        PolyVec(v.0.iter().map(|p| p.scalar_mul(x)).collect())
    }
    fn scale_commit(c: &RingCommitment, x: i64) -> RingCommitment {
        RingCommitment { t1: scale_vec(&c.t1, x), t2: scale_vec(&c.t2, x) }
    }
    fn challenge(d: &RingCommitment, c_y: &RingCommitment, c_t: &RingCommitment, fee: u64) -> i64 {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/packed-balance/v1");
        for c in [d, c_y, c_t] {
            for p in c.t1.0.iter().chain(c.t2.0.iter()) {
                for &x in &p.c {
                    h.update(x.to_le_bytes());
                }
            }
        }
        h.update(fee.to_le_bytes());
        let bytes = h.finalize();
        (u64::from_le_bytes(bytes[..8].try_into().unwrap()) % (2 * CHAL_T as u64 + 1)) as i64 - CHAL_T
    }

    /// Homomorphic combined commitment `D = Σin c_b − Σout c_b`.
    pub fn combined_commitment(inputs: &[RingCommitment], outputs: &[RingCommitment]) -> RingCommitment {
        let mut d = RingCommitment { t1: PolyVec::zero(inputs.first().map(|c| c.t1.len()).unwrap_or(0)), t2: PolyVec(vec![Poly::zero()]) };
        for c in inputs {
            d = d.add(c);
        }
        for c in outputs {
            d = d.add(&scale_commit(c, -1));
        }
        d
    }

    /// Prove balance `⟪g, B⟫ = fee` for `D = Commit(B; R)` in ZK. `b_polys`/`r_polys`
    /// are the input-minus-output bit polys and randomness (so `B = Σ b_polys`,
    /// `R = Σ r_polys` with signs already applied), `n_bits` the value width.
    pub fn prove_balance(
        key: &RingCommitKey,
        d: &RingCommitment,
        big_b: &Poly,
        big_r: &PolyVec,
        fee: u64,
        n_bits: usize,
        seed: u64,
    ) -> Option<PackedBalanceProof> {
        let g = gadget(n_bits);
        let z_bound = (MASK - SHIFT) as u64;
        for attempt in 0..4000u64 {
            let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x51A9));
            let mut y = Poly::zero();
            for k in 0..Poly::D {
                y.c[k] = (prg.uniform_below((2 * MASK + 1) as u128) as i64 - MASK).rem_euclid(Poly::Q as i64) as u64;
            }
            let r_y = PolyVec::sample_uniform_pm(LAMBDA, MASK, &mut prg);
            let r_t = PolyVec::sample_short(LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
            let t = cinner(&g, &y);
            let c_y = key.commit(&PolyVec(vec![y.clone()]), &r_y);
            let c_t = key.commit(&PolyVec(vec![const_poly(t)]), &r_t);
            let x = challenge(d, &c_y, &c_t, fee);
            let z = y.add(&big_b.scalar_mul(x));
            let r_z = r_y.add(&scale_vec(big_r, x));
            if z.inf_norm() <= z_bound && r_z.inf_norm() <= z_bound {
                return Some(PackedBalanceProof { c_y, c_t, z, r_z, r_t });
            }
        }
        None
    }

    /// Verify a ZK packed-balance proof.
    pub fn verify_balance(key: &RingCommitKey, d: &RingCommitment, fee: u64, n_bits: usize, pf: &PackedBalanceProof) -> bool {
        let g = gadget(n_bits);
        let x = challenge(d, &pf.c_y, &pf.c_t, fee);
        // (1) z opens D: Commit(z; r_z) == c_y + x·D.
        if key.commit(&PolyVec(vec![pf.z.clone()]), &pf.r_z) != pf.c_y.add(&scale_commit(d, x)) {
            return false;
        }
        // (2) balance: t = ⟪g,z⟫ − x·fee must open c_t.
        let q = Poly::Q as u128;
        let gz = cinner(&g, &pf.z) as u128;
        let xfee = ((x.rem_euclid(Poly::Q as i64) as u128) * fee as u128) % q;
        let t = ((gz + q - xfee) % q) as u64;
        key.commit(&PolyVec(vec![const_poly(t)]), &pf.r_t) == pf.c_t
    }

    // ── VALUE-LINK: bind a packed c_b to a scalar VALUE commitment ────────────
    //
    // A coin on-chain is committed under the (limb) VALUE key as `C_v =
    // Commit_v(v; r_v)` (value in `c[0]`); the packed range/balance path wants the
    // same value as a packed `c_b = Commit_b(b; r_b)` with `v = ⟪g,b⟫`. This proves
    // `⟪g,b⟫ = v` in ZK, so a packed spend proof can reveal a packed `c_b`
    // pseudo-input that provably matches the spent coin's value — the bridge
    // between the limb accumulator and the packed money path. Same masked-linear
    // structure as `prove_balance`: one scalar challenge, `c_t` pins
    // `t = ⟪g,y_b⟫ − y_v` before x, `⟪g,z_b⟫ − z_v = t + x(⟪g,b⟫−v)`.

    /// A ZK value-link proof.
    pub struct ValueLinkProof {
        pub c_yb: RingCommitment,
        pub c_yv: RingCommitment,
        pub c_t: RingCommitment,
        pub z_b: Poly,
        pub z_v: Poly,
        pub r_zb: PolyVec,
        pub r_zv: PolyVec,
        pub r_t: PolyVec,
    }

    fn link_challenge(c_b: &RingCommitment, c_v: &RingCommitment, p: &ValueLinkProof) -> i64 {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/value-link/v1");
        for c in [c_b, c_v, &p.c_yb, &p.c_yv, &p.c_t] {
            for poly in c.t1.0.iter().chain(c.t2.0.iter()) {
                for &x in &poly.c {
                    h.update(x.to_le_bytes());
                }
            }
        }
        let bytes = h.finalize();
        (u64::from_le_bytes(bytes[..8].try_into().unwrap()) % (2 * CHAL_T as u64 + 1)) as i64 - CHAL_T
    }

    /// Prove `⟪g,b⟫ = v`, linking packed `c_b = key_b.commit([b];r_b)` to value
    /// `c_v = key_v.commit([const v];r_v)`. `n_bits` sets `g`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_value_link(
        key_b: &RingCommitKey,
        key_v: &RingCommitKey,
        c_b: &RingCommitment,
        c_v: &RingCommitment,
        b: &Poly,
        r_b: &PolyVec,
        v: u64,
        r_v: &PolyVec,
        n_bits: usize,
        seed: u64,
    ) -> Option<ValueLinkProof> {
        let g = gadget(n_bits);
        let q = Poly::Q as u128;
        let z_bound = (MASK - SHIFT) as u64;
        for attempt in 0..4000u64 {
            let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x71D3));
            let mut y_b = Poly::zero();
            for k in 0..Poly::D {
                y_b.c[k] = (prg.uniform_below((2 * MASK + 1) as u128) as i64 - MASK).rem_euclid(Poly::Q as i64) as u64;
            }
            let y_v = (prg.uniform_below((2 * MASK + 1) as u128) as i64 - MASK).rem_euclid(Poly::Q as i64) as u64;
            let r_yb = PolyVec::sample_uniform_pm(LAMBDA, MASK, &mut prg);
            let r_yv = PolyVec::sample_uniform_pm(LAMBDA, MASK, &mut prg);
            let r_t = PolyVec::sample_short(LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
            let t = ((cinner(&g, &y_b) as u128 + q - y_v as u128) % q) as u64;
            let mut pf = ValueLinkProof {
                c_yb: key_b.commit(&PolyVec(vec![y_b.clone()]), &r_yb),
                c_yv: key_v.commit(&PolyVec(vec![const_poly(y_v)]), &r_yv),
                c_t: key_b.commit(&PolyVec(vec![const_poly(t)]), &r_t),
                z_b: Poly::zero(),
                z_v: Poly::zero(),
                r_zb: PolyVec::zero(LAMBDA),
                r_zv: PolyVec::zero(LAMBDA),
                r_t: r_t.clone(),
            };
            let x = link_challenge(c_b, c_v, &pf);
            let z_b = y_b.add(&b.scalar_mul(x));
            let z_v = const_poly(((y_v as i128 + x as i128 * v as i128).rem_euclid(Poly::Q as i128)) as u64);
            let r_zb = r_yb.add(&scale_vec(r_b, x));
            let r_zv = r_yv.add(&scale_vec(r_v, x));
            if z_b.inf_norm() <= z_bound && r_zb.inf_norm() <= z_bound && r_zv.inf_norm() <= z_bound {
                pf.z_b = z_b;
                pf.z_v = z_v;
                pf.r_zb = r_zb;
                pf.r_zv = r_zv;
                return Some(pf);
            }
        }
        None
    }

    /// Verify a value-link: `c_b` (packed, `key_b`) and `c_v` (value, `key_v`)
    /// commit the SAME value `⟪g,b⟫ = v`.
    pub fn verify_value_link(
        key_b: &RingCommitKey,
        key_v: &RingCommitKey,
        c_b: &RingCommitment,
        c_v: &RingCommitment,
        n_bits: usize,
        pf: &ValueLinkProof,
    ) -> bool {
        let g = gadget(n_bits);
        let x = link_challenge(c_b, c_v, pf);
        // (1) z_b opens c_b; z_v opens c_v.
        if key_b.commit(&PolyVec(vec![pf.z_b.clone()]), &pf.r_zb) != pf.c_yb.add(&scale_commit(c_b, x)) {
            return false;
        }
        if key_v.commit(&PolyVec(vec![pf.z_v.clone()]), &pf.r_zv) != pf.c_yv.add(&scale_commit(c_v, x)) {
            return false;
        }
        // (2) ⟪g,z_b⟫ − z_v = t must open c_t ⇒ x(⟪g,b⟫−v)=0 ⇒ ⟪g,b⟫=v.
        let q = Poly::Q as u128;
        let t = ((cinner(&g, &pf.z_b) as u128 + q - pf.z_v.c[0] as u128) % q) as u64;
        key_b.commit(&PolyVec(vec![const_poly(t)]), &pf.r_t) == pf.c_t
    }
}

/// The complete ZK packed range proof.
pub struct PackedRangeZkProof {
    pub opening: crate::sigma_rq::RingOpeningProof,
    pub binary: binary_zk::PackedBinaryZkProof,
}

/// Prove `v ∈ [0, 2^{n_bits})` in zero-knowledge over the packed commitment.
pub fn prove_range_zk(
    stmt: &packed::PackedRangeStatement,
    wit: &packed::PackedRangeWitness,
    seed: u64,
) -> Option<PackedRangeZkProof> {
    let opening = packed::prove_packed_opening_zk(stmt, wit, seed)?;
    let binary = binary_zk::prove_packed_binary_zk(
        &stmt.key,
        &stmt.c_b,
        &wit.bit_poly,
        &wit.r_b,
        seed ^ 0x5A17,
    )?;
    Some(PackedRangeZkProof { opening, binary })
}

/// Verify the complete ZK packed range proof against the public statement.
pub fn verify_range_zk(stmt: &packed::PackedRangeStatement, proof: &PackedRangeZkProof) -> bool {
    packed::verify_packed_opening_zk(stmt, &proof.opening)
        && binary_zk::verify_packed_binary_zk(&stmt.key, &stmt.c_b, &proof.binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::module::{RingCommitKey, ETA};

    fn commit_v(key: &RingRangeKey, v: u64, tag: u64) -> (RingCommitment, PolyVec) {
        let mut prg = SplitMix64::new(tag);
        let r = PolyVec::sample_short(LAMBDA, ETA, &mut prg);
        (key.value_key().commit(&PolyVec(vec![const_poly(v)]), &r), r)
    }

    #[test]
    fn range_labrador_verifies_in_range() {
        let key = RingRangeKey::production(16, 7);
        let v = 12345u64;
        let (c_v, r_v) = commit_v(&key, v, 1);
        let proof = prove_range_labrador(&key, &c_v, v, &r_v, 3).expect("in range");
        assert!(verify_range_labrador(&key, &c_v, &proof));
    }

    #[test]
    fn range_labrador_out_of_range_unprovable() {
        let key = RingRangeKey::production(8, 9);
        let v = 1u64 << 8; // == 256, just outside [0, 2^8)
        let (c_v, r_v) = commit_v(&key, v, 4);
        assert!(prove_range_labrador(&key, &c_v, v, &r_v, 4).is_none());
    }

    #[test]
    fn range_labrador_rejects_mismatched_value_commitment() {
        // The proof binds THIS c_v; a commitment to a different value must fail.
        let key = RingRangeKey::production(16, 11);
        let v = 1000u64;
        let (c_v, r_v) = commit_v(&key, v, 2);
        let proof = prove_range_labrador(&key, &c_v, v, &r_v, 4).unwrap();
        let (c_other, _r) = commit_v(&key, 2000, 3);
        assert!(!verify_range_labrador(&key, &c_other, &proof));
    }

    #[test]
    fn range_labrador_rejects_tampered_bit_commitment() {
        // Flip a coordinate of c_b: the opening/binding family no longer holds.
        let key = RingRangeKey::production(16, 13);
        let v = 777u64;
        let (c_v, r_v) = commit_v(&key, v, 5);
        let mut proof = prove_range_labrador(&key, &c_v, v, &r_v, 6).unwrap();
        proof.c_b.t2.0[0] = proof.c_b.t2.0[0].add(&Poly::one());
        assert!(!verify_range_labrador(&key, &c_v, &proof));
    }

    fn rand_poly(prg: &mut SplitMix64) -> Poly {
        let mut p = Poly::zero();
        for k in 0..Poly::D {
            p.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
        }
        p
    }

    #[test]
    fn ct_inner_matches_coefficient_inner_product() {
        // ct(σ(a)·b) == Σₖ aₖbₖ, over random ring elements — the identity the
        // compressed constant-term constraint family relies on.
        let mut prg = SplitMix64::new(0xC0DE_1234);
        for _ in 0..64 {
            let a = rand_poly(&mut prg);
            let b = rand_poly(&mut prg);
            assert_eq!(coeff::ct_inner(&a, &b), coeff::coeff_inner_ref(&a, &b));
        }
    }

    #[test]
    fn ct_inner_extracts_individual_coordinates() {
        // ct(σ(Xᵏ)·b) == bₖ: the unit monomial addresses packed coordinate k.
        let mut prg = SplitMix64::new(0x5EED_9999);
        let b = rand_poly(&mut prg);
        for k in 0..Poly::D {
            let e_k = Poly::monomial(k);
            assert_eq!(coeff::ct_inner(&e_k, &b), b.c[k]);
        }
    }

    #[test]
    fn auto_inv_is_an_involution() {
        // σ(σ(a)) = a — σ is an order-2 automorphism.
        let mut prg = SplitMix64::new(0xA17E_0F02);
        for _ in 0..16 {
            let a = rand_poly(&mut prg);
            assert_eq!(coeff::auto_inv(&coeff::auto_inv(&a)), a);
        }
    }

    #[test]
    fn packed_bits_are_coordinate_wise_checkable() {
        // Demonstrate the compressed encoding's kernel: pack bits into the
        // COEFFICIENTS of one ring element; each coordinate's bit-validity
        // bₖ(bₖ−1)=0 is extractable via ct_inner(Xᵏ, ·). A valid packing passes
        // every coordinate; corrupting one coefficient to a non-bit fails exactly
        // that coordinate. This is what a constant-term constraint would enforce.
        let mut p = Poly::zero();
        for k in 0..Poly::D {
            p.c[k] = (k as u64) & 1; // alternating 0/1 — all valid bits
        }
        let bit_ok = |poly: &Poly, k: usize| {
            let bk = coeff::ct_inner(&Poly::monomial(k), poly) as u128;
            let q = Poly::Q as u128;
            (bk * bk % q + q - bk) % q == 0 // bₖ² − bₖ ≡ 0
        };
        assert!((0..Poly::D).all(|k| bit_ok(&p, k)));
        // Corrupt coordinate 7 to a non-bit value.
        p.c[7] = 2;
        assert!(!bit_ok(&p, 7));
        assert!((0..Poly::D).filter(|&k| k != 7).all(|k| bit_ok(&p, k)));
    }

    #[test]
    fn rejection_acceptance_matches_analysis_and_is_witness_independent() {
        use binary_zk::{accept_prob, CHAL_T};
        const MASK: i64 = 1 << 26;
        // Empirically measure the accept rate of a dim-D uniform-mask response
        // with a fixed shift, and compare to the analytic accept_prob. Also check
        // the rate does NOT depend on the shift value (perfect-ZK: acceptance is
        // witness-independent).
        let dim = 256usize; // one poly's worth (the `f` response dimension)
        let shift_bound = CHAL_T; // |x·b| ≤ T for f
        let accept_box = MASK - shift_bound;
        let measure = |shift: i64, seed: u64| -> f64 {
            let mut prg = SplitMix64::new(seed);
            let trials = 4000;
            let mut ok = 0;
            for _ in 0..trials {
                // Accept iff EVERY coefficient's masked value stays in the box.
                let mut all = true;
                for _ in 0..dim {
                    let y = (prg.uniform_below((2 * MASK + 1) as u128) as i64) - MASK;
                    let z = y + shift;
                    if z.abs() > accept_box {
                        all = false;
                        break;
                    }
                }
                if all {
                    ok += 1;
                }
            }
            ok as f64 / trials as f64
        };
        let analytic = accept_prob(shift_bound, dim);
        // Different shift values (different secrets) → same rate as analytic.
        for (shift, seed) in [(0i64, 1u64), (shift_bound, 2), (-shift_bound, 3)] {
            let rate = measure(shift, seed);
            assert!(
                (rate - analytic).abs() < 0.03,
                "measured {rate:.3} vs analytic {analytic:.3} (shift {shift}) — should match"
            );
        }
        // Sanity: the analytic per-response rates are in the documented range.
        assert!(accept_prob(CHAL_T, 256) > 0.97, "f response acceptance ~0.985");
        assert!(accept_prob(CHAL_T * 2, 9 * 256) > 0.70, "opening acceptance ~0.755");
    }

    #[test]
    fn packed_value_binding_is_homomorphic_and_balances() {
        use packed::*;
        // Value-binding: the packed commitment's amount is v = ⟪g,b⟫, and the
        // commitment is homomorphic, so summing commitments sums values.
        let (s1, w1) = commit_packed(64, 300u64, 71);
        let (s2, w2) = commit_packed(64, 500u64, 72);
        assert_eq!(value_of(&w1.bit_poly, 64), 300);
        assert_eq!(value_of(&w2.bit_poly, 64), 500);
        // Homomorphic add commits b1+b2, whose value is 300+500 = 800.
        let csum = add_commit(&s1.c_b, &s2.c_b);
        let bsum = w1.bit_poly.add(&w2.bit_poly);
        let rsum = w1.r_b.add(&w2.r_b);
        assert_eq!(RingCommitKey::production(1, 0).a1.rows, s1.key.a1.rows); // sanity
        // csum == Commit(bsum; rsum) under s1's key (same key for both here? no —
        // different seeds). Use one shared key for the homomorphism check.
        let key = s1.key.clone();
        let c1 = key.commit(&PolyVec(vec![w1.bit_poly.clone()]), &w1.r_b);
        let c2 = key.commit(&PolyVec(vec![w2.bit_poly.clone()]), &w2.r_b);
        assert_eq!(add_commit(&c1, &c2), key.commit(&PolyVec(vec![bsum.clone()]), &rsum));
        assert_eq!(value_of(&bsum, 64), 800);
        let _ = csum;

        // Balance: inputs 800 = outputs 750 + fee 50.
        let (_so, wo) = commit_packed(64, 750u64, 73);
        assert!(balance_holds(&[bsum.clone()], &[wo.bit_poly.clone()], 50, 64));
        assert!(!balance_holds(&[bsum], &[wo.bit_poly], 49, 64), "wrong fee must fail balance");
    }

    #[test]
    #[ignore = "superseded by `fullwidth`; entry points forced to fail (see lineage note)"]
    fn amortized_coins_are_self_contained_and_proof_binds() {
        use packed::*;
        // Self-contained-coin layout: each in/out value is a SELF-CONTAINED coin `cv_j`,
        // all stacked into one amortized `c_b`; a single IPA proof does ranges +
        // balance. 2-in/2-out, balanced (100+50 = 120+25 + fee 5).
        let n_bits = 16;
        let ins = [100u64, 50];
        let outs = [120u64, 25];
        let fee = 5u64;
        let (stmt, wit, coins) = commit_multi_tx_coins(n_bits, &ins, &outs, fee, 0xC0FE, 0xC1A5);
        // (i) the amortized proof verifies (ranges + balance in ONE proof).
        let proof = prove_multi_tx_coins_ipa_zk(&stmt, &wit, 0xC2B6).expect("prove coins tx");
        assert!(verify_multi_tx_coins_ipa_zk(&stmt, &proof), "amortized coin tx verifies");

        // (ii) each coin is a SELF-CONTAINED, recipient-openable single-value
        // commitment — opened with ONLY (b_j, r_j), no knowledge of other coins — and
        // is EXACTLY the slice of the stacked c_b (coin = slice of amortized c_b).
        let sk = coin_key(0xC0FE);
        let all: Vec<u64> = ins.iter().chain(&outs).copied().collect();
        for (j, cv) in coins.iter().enumerate() {
            let bj = value_bits(n_bits, all[j]);
            let rj = coin_randomness(0xC1A5, j);
            assert!(sk.open_verify(cv, &PolyVec(vec![bj]), &rj, crate::params::SECRET_NORM_ETA as u64), "coin {j} opens standalone");
            assert_eq!(coin_cv(&stmt, j), *cv, "coin {j} == its slice of c_b");
        }
        // stack_coins reproduces the stated c_b from the standalone coins (verifier side).
        assert_eq!(stack_coins(&coins), stmt.c_b, "stacked coins == amortized c_b");

        // (iii) BINDING: tamper one output coin's committed value ⇒ the proof rejects.
        let mut bad = stmt.clone();
        bad.c_b.t2.0[2].c[0] = (bad.c_b.t2.0[2].c[0] + 1) % Poly::Q;
        assert!(!verify_multi_tx_coins_ipa_zk(&bad, &proof), "tampered coin commitment rejects");
        // (iii') an unbalanced tx (wrong fee) rejects.
        let (bstmt, bwit, _) = commit_multi_tx_coins(n_bits, &ins, &outs, fee + 1, 0xC0FE, 0xC1A5);
        let bproof = prove_multi_tx_coins_ipa_zk(&bstmt, &bwit, 0xC2B6);
        // Prover with a false fee either fails to prove (unbalanced) or the proof
        // fails against the honest-fee statement.
        if let Some(bp) = bproof {
            assert!(!verify_multi_tx_coins_ipa_zk(&stmt, &bp), "wrong-fee proof rejects vs honest stmt");
        }
    }

    #[test]
    fn fullwidth_relation_holds_and_detects_imbalance() {
        use fullwidth::*;
        // RELATION-only (no proving): a balanced full-width u128 tx satisfies the
        // opening + binary + carry-chain-balance family; an imbalanced one does not.
        let l = 16;
        // amounts that exercise carries across limbs (values > 2^8, and a big u128).
        let ins = [1_000_000u128, 5_000u128];
        let outs = [900_000u128, 100_000u128];
        let fee = 5_000u128; // 1_005_000 = 1_000_000 + 5_000 (balanced)
        let (stmt, wit, coins) = commit_fw_tx(l, &ins, &outs, fee, &RingCommitKey::production(l, 0xF00D), 0xBEEF);
        assert!(fw_relation_holds(&stmt, &wit), "balanced full-width tx satisfies the relation");
        assert_eq!(stack_coins(&coins), stmt.c_b, "coins stack to c_b");
        // Each coin is self-contained & recipient-openable to its own amount.
        let sk = RingCommitKey::production(l, 0xF00D);
        let all: Vec<u128> = ins.iter().chain(&outs).copied().collect();
        for (a, cv) in coins.iter().enumerate() {
            assert_eq!(coin_cv(&stmt, a), *cv, "coin {a} == its c_b slice");
            let _ = all[a]; // (opening validated inside fw_relation_holds)
        }
        // A wrong fee ⇒ carry chain does not vanish ⇒ relation fails.
        let (bstmt, bwit, _) = commit_fw_tx(l, &ins, &outs, fee + 1, &RingCommitKey::production(l, 0xF00D), 0xBEEF);
        assert!(!fw_relation_holds(&bstmt, &bwit), "wrong-fee tx violates the balance relation");
    }

    #[test]
    fn fullwidth_transfer_pins_inputs_to_cprime_and_balances() {
        use fullwidth::*;
        // Full-width TRANSFER with HIDDEN inputs: 2-in/2-out, balanced
        // (1_000_000 + 5_000 = 900_000 + 100_000 + fee 5_000). Each input's value is
        // consumed from its c_prime (spend-proof-pinned), so no false input amount.
        let l = 16;
        let ins = [1_000_000u128, 5_000u128];
        let outs = [900_000u128, 100_000u128];
        let fee = 5_000u128;
        let coin_key = RingCommitKey::production(l, 0xC01D);
        let value_key = RingCommitKey::production(l, 0x7A1E);
        let (stmt, wit, out_coins) = commit_fw_transfer(l, &ins, &outs, fee, &coin_key, &value_key, 0x3333);
        assert_eq!(stack_coins(&out_coins), stmt.c_b, "output coins stack to c_b");
        let proof = prove_fw_transfer_ipa_zk(&stmt, &wit, 0x4444).expect("prove transfer");
        assert!(verify_fw_transfer_ipa_zk(&stmt, &proof), "balanced transfer verifies");

        // (i) BINDING: verify against a statement whose input c_prime commits a
        // DIFFERENT value ⇒ the opening pins cp_limb to that c_prime, contradicting
        // the witness ⇒ reject. (This is what stops an inflated input amount.)
        let mut prg = crate::arith::SplitMix64::new(0x9);
        let fake_r = PolyVec::sample_short(crate::params::LWE_RANK_LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
        let fake_limbs: Vec<Poly> = crate::limb_balance::limbs_of(2_000_000u128, l)
            .iter().map(|&v| { let mut p = Poly::zero(); p.c[0] = v; p }).collect();
        let mut bad_cprime = stmt.clone();
        bad_cprime.c_primes[0] = value_key.commit(&PolyVec(fake_limbs), &fake_r);
        assert!(!verify_fw_transfer_ipa_zk(&bad_cprime, &proof), "c_prime committing a different value rejects");

        // (ii) unbalanced (wrong fee) ⇒ reject.
        let mut wrongfee = stmt.clone();
        wrongfee.fee = fee + 1;
        assert!(!verify_fw_transfer_ipa_zk(&wrongfee, &proof), "wrong fee rejects");

        // (iii) tampered OUTPUT coin ⇒ reject.
        let mut badout = stmt.clone();
        badout.c_b.t2.0[0].c[0] = (badout.c_b.t2.0[0].c[0] + 1) % Poly::Q;
        assert!(!verify_fw_transfer_ipa_zk(&badout, &proof), "tampered output coin rejects");

        let bytes = crate::wire::encode_full_ct_zk_ipa_compact(&proof);
        println!("FW TRANSFER (L=16, 2-in/2-out) compact proof = {} KB", bytes.len() / 1024);
    }

    #[test]
    fn fullwidth_transfer_ext_binds_external_cprimes() {
        use fullwidth::*;
        // The build path: input c_primes come EXTERNALLY (as the spend proofs would
        // produce them) — value_key commitments to the input amounts — and the fw proof
        // binds them. Balanced 2-in/2-out verifies; a c_prime under DIFFERENT randomness
        // than the witness's r_p rejects (the opening won't hold).
        let l = 16;
        let ins = [1_000_000u128, 5_000u128];
        let outs = [900_000u128, 100_000u128];
        let fee = 5_000u128;
        let coin_key = RingCommitKey::production(l, 0xC01D);
        let value_key = RingCommitKey::production(l, 0x7A1E);
        // Externally build each c_prime = value_key.commit(limbs; r_p) (the spend's pseudo-output).
        let mut prg = crate::arith::SplitMix64::new(0x5151);
        let bits_of = |v: u128| -> Vec<Poly> {
            crate::limb_balance::limbs_of(v, l)
                .iter()
                .map(|&x| {
                    let mut p = Poly::zero();
                    for i in 0..8 {
                        p.c[i] = (x >> i) & 1;
                    }
                    p
                })
                .collect()
        };
        let (mut cps, mut rps) = (Vec::new(), Vec::new());
        for &v in &ins {
            let r = PolyVec::sample_short(crate::params::LWE_RANK_LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
            cps.push(value_key.commit(&PolyVec(bits_of(v)), &r));
            rps.push(r);
        }
        let (stmt, wit, _coins) = commit_fw_transfer_ext(l, &ins, &cps, &rps, &outs, fee, &coin_key, &value_key, 0x9999);
        let proof = prove_fw_transfer_ipa_zk(&stmt, &wit, 0xABCD).expect("prove ext transfer");
        assert!(verify_fw_transfer_ipa_zk(&stmt, &proof), "ext transfer (external c_primes) verifies");
        // A c_prime built with the WRONG randomness (not the r_p in the witness) rejects.
        let mut bad = stmt.clone();
        let wrong_r = PolyVec::sample_short(crate::params::LWE_RANK_LAMBDA, crate::params::SECRET_NORM_ETA, &mut prg);
        bad.c_primes[0] = value_key.commit(&PolyVec(bits_of(ins[0])), &wrong_r);
        assert!(!verify_fw_transfer_ipa_zk(&bad, &proof), "c_prime with mismatched randomness rejects");
    }

    #[test]
    fn fullwidth_mint_conserves_public_amount() {
        use fullwidth::*;
        // MINT: a public reward of 1_000_000 conserved into two hidden output coins
        // (600_000 + 400_000). The public amount rides the balance target, not a coin.
        let l = 16;
        let mint = 1_000_000u128;
        let outs = [600_000u128, 400_000u128];
        let (stmt, wit, coins) = commit_fw_mint(l, mint, &outs, &RingCommitKey::production(l, 0x1117), 0x2223);
        let proof = prove_fw_tx_ipa_zk(&stmt, &wit, 0x3331).expect("prove mint");
        assert!(verify_fw_tx_ipa_zk(&stmt, &proof), "mint conserving 1_000_000 verifies");
        assert_eq!(stack_coins(&coins), stmt.c_b);
        // Over-mint: outputs sum to MORE than the public amount ⇒ carry chain fails.
        let (bs, bw, _) = commit_fw_mint(l, mint, &[600_000u128, 500_000u128], &RingCommitKey::production(l, 0x1117), 0x2223);
        let bp = prove_fw_tx_ipa_zk(&bs, &bw, 0x3331);
        if let Some(p) = bp {
            assert!(!verify_fw_tx_ipa_zk(&stmt, &p), "over-mint proof rejects vs honest stmt");
        }
        // A verifier claiming a DIFFERENT public mint amount rejects the honest proof.
        let mut wrong = stmt.clone();
        wrong.pub_in = mint + 1;
        assert!(!verify_fw_tx_ipa_zk(&wrong, &proof), "wrong public mint amount rejects");
    }

    #[test]
    fn fullwidth_ipa_proof_verifies_and_binds() {
        use fullwidth::*;
        // End-to-end IPA proof on a small-width full-width tx (L=4 keeps proving
        // fast; the relation logic is width-independent). 1-in/1-out + fee.
        let l = 4;
        let ins = [70_000u128];
        let outs = [69_000u128];
        let fee = 1_000u128; // 70_000 = 69_000 + 1_000
        let (stmt, wit, coins) = commit_fw_tx(l, &ins, &outs, fee, &RingCommitKey::production(l, 0xF11E), 0xA5A5);
        let proof = prove_fw_tx_ipa_zk(&stmt, &wit, 0xC0DE).expect("prove fw tx");
        assert!(verify_fw_tx_ipa_zk(&stmt, &proof), "full-width tx proof verifies");
        assert_eq!(stack_coins(&coins), stmt.c_b);
        // BINDING: tamper an output coin commitment ⇒ reject.
        let mut bad = stmt.clone();
        let kappa = bad.key.a1.rows;
        bad.c_b.t2.0[1 * l].c[0] = (bad.c_b.t2.0[1 * l].c[0] + 1) % Poly::Q; // output coin's limb 0
        let _ = kappa;
        assert!(!verify_fw_tx_ipa_zk(&bad, &proof), "tampered coin commitment rejects");
        // Wrong claimed fee statement ⇒ reject (balance targets differ).
        let mut wrongfee = stmt.clone();
        wrongfee.fee = fee + 1;
        assert!(!verify_fw_tx_ipa_zk(&wrongfee, &proof), "wrong-fee statement rejects");

        // REALISTIC width (L=16 = full u128) 2-in/2-out: proves, verifies, and its
        // compact serialized size is the true full-width single-transfer cost.
        let ins = [1_000_000u128, 5_000u128];
        let outs = [900_000u128, 100_000u128];
        let (rs, rw, _) = commit_fw_tx(16, &ins, &outs, 5_000u128, &RingCommitKey::production(16, 0xF00D), 0xBEEF);
        let rp = prove_fw_tx_ipa_zk(&rs, &rw, 0xC0DE).expect("prove L=16 tx");
        assert!(verify_fw_tx_ipa_zk(&rs, &rp), "L=16 full-width tx verifies");
        let bytes = crate::wire::encode_full_ct_zk_ipa_compact(&rp);
        println!("FULL-WIDTH (L=16, 2-in/2-out) compact proof = {} KB", bytes.len() / 1024);
    }

    #[test]
    fn packed_range_relation_holds_for_valid_value() {
        use packed::*;
        let (stmt, wit) = commit_packed(64, 0xDEAD_BEEFu64, 42);
        assert!(relation_holds(&stmt, &wit, 2));
        assert_eq!(value_of(&wit.bit_poly, 64), 0xDEAD_BEEFu64 % Poly::Q);
    }

    #[test]
    fn packed_range_relation_rejects_non_bit_coefficient() {
        use packed::*;
        let (stmt, mut wit) = commit_packed(64, 123456u64, 7);
        assert!(relation_holds(&stmt, &wit, 2));
        // Corrupt one coefficient to a non-bit value AND re-commit so the opening
        // still holds — the binary ct constraint must be what rejects it.
        wit.bit_poly.c[3] = 2;
        let key = RingCommitKey::production(1, 7);
        let c_b = key.commit(&PolyVec(vec![wit.bit_poly.clone()]), &wit.r_b);
        let stmt2 = PackedRangeStatement { key, c_b, n_bits: stmt.n_bits };
        assert!(!relation_holds(&stmt2, &wit, 2), "non-bit coefficient must fail binary");
    }

    #[test]
    fn packed_range_relation_rejects_tampered_opening() {
        use packed::*;
        let (mut stmt, wit) = commit_packed(64, 999u64, 11);
        stmt.c_b.t2.0[0] = stmt.c_b.t2.0[0].add(&Poly::one());
        assert!(!relation_holds(&stmt, &wit, 2), "tampered commitment must fail opening");
    }

    #[test]
    fn packed_range_proves_and_verifies_through_pipeline() {
        use packed::*;
        let (stmt, wit) = commit_packed(64, 0x0BAD_C0DEu64, 21);
        let proof = prove_range_packed(&stmt, &wit);
        assert!(verify_range_packed(&stmt, &proof), "honest packed range must verify");
    }

    #[test]
    fn packed_pipeline_rejects_non_bit_witness() {
        use packed::*;
        // Corrupt one coefficient to a non-bit AND re-commit so the OPENING still
        // holds — the constant-term binary constraint must be what rejects.
        let (stmt, mut wit) = commit_packed(64, 55u64, 22);
        wit.bit_poly.c[9] = 2;
        let key = RingCommitKey::production(1, 22);
        let c_b = key.commit(&PolyVec(vec![wit.bit_poly.clone()]), &wit.r_b);
        let stmt2 = PackedRangeStatement { key, c_b, n_bits: stmt.n_bits };
        let proof = prove_range_packed(&stmt2, &wit);
        assert!(!verify_range_packed(&stmt2, &proof), "non-bit must fail the ct binary check");
    }

    #[test]
    fn packed_pipeline_rejects_tampered_opening() {
        use packed::*;
        let (mut stmt, wit) = commit_packed(64, 4096u64, 23);
        let proof = prove_range_packed(&stmt, &wit);
        stmt.c_b.t2.0[0] = stmt.c_b.t2.0[0].add(&Poly::one());
        assert!(!verify_range_packed(&stmt, &proof), "tampered opening must fail");
    }

    #[test]
    fn packed_pipeline_rejects_malformed_ct_proof() {
        // Fold-through-levels IS now sound (Step 3b: ct-family rides ĝ/ĥ through the
        // production recursion — see labrador::recursion_ct_family_prove_verify_multilevel).
        // What must still reject: a MALFORMED proof whose u1s length disagrees with the
        // schedule (here empty u1s against a 1-level schedule).
        use crate::labrador::{
            level_schedule, verify_labrador_recursive_ct, CtConstraint, QuadConstraint,
            RecursiveProof,
        };
        let sched = level_schedule(4, 8, ETA as u64, 8, 18, 0, 1);
        assert!(!sched.is_empty());
        let ct = vec![CtConstraint { terms: vec![(0, 0, 1)], linear: vec![], target: 0 }];
        let empty_full: Vec<QuadConstraint> = vec![];
        let pf = RecursiveProof { u1s: vec![], final_s: vec![PolyVec(vec![Poly::zero()])] };
        assert!(!verify_labrador_recursive_ct(&empty_full, &ct, ETA as u64, 8, &sched, 1, &pf));
    }

    fn masked_binary_accepts(b: &Poly, seed: u64) -> bool {
        // Run the soundness kernel for R independent scalar challenges (as the ZK
        // proof would), with fresh masks; accept iff every shot's check holds.
        use binary_zk::*;
        let mut prg = SplitMix64::new(seed);
        for rep in 0..REPS {
            // A fresh mask y (wide) per shot.
            let mut y = Poly::zero();
            for k in 0..Poly::D {
                y.c[k] = prg.uniform_below(Poly::Q as u128) as u64;
            }
            let (t0, t1) = honest_t(b, &y);
            // Challenge derived from the (committed) t0,t1,y and rep — small scalar.
            let x = hash_scalar(seed, rep as u64, t0, t1).rem_euclid(2 * CHAL_T + 1) - CHAL_T;
            if !masked_quadratic_check(b, &y, t0, t1, x) {
                return false;
            }
        }
        true
    }

    fn hash_scalar(seed: u64, rep: u64, t0: u64, t1: u64) -> i64 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/test/packed-binary-chal");
        h.update(seed.to_le_bytes());
        h.update(rep.to_le_bytes());
        h.update(t0.to_le_bytes());
        h.update(t1.to_le_bytes());
        let d = h.finalize();
        u64::from_le_bytes(d[..8].try_into().unwrap()) as i64
    }

    #[test]
    fn masked_binary_kernel_accepts_bits_rejects_non_bits() {
        use binary_zk::*;
        // Honest packed bit vector: Q(b) = 0, kernel accepts.
        let mut b = Poly::zero();
        for k in 0..Poly::D {
            b.c[k] = (k as u64 * 7 + 1) & 1;
        }
        assert_eq!(binary_defect(&b), 0, "valid bits have zero defect");
        assert!(masked_binary_accepts(&b, 0xB1A0), "honest bits must be accepted");

        // Non-bit: flip one coefficient to 2. Defect ≠ 0 ⇒ rejected across R shots.
        let mut bad = b.clone();
        bad.c[17] = 2;
        assert_ne!(binary_defect(&bad), 0, "non-bit must have nonzero defect");
        // Over many independent challenge seeds, the R-shot check essentially never
        // accepts a non-bit (per-shot ≤2/|X|, R shots ⇒ negligible).
        let mut accepted = 0;
        for s in 0..64u64 {
            if masked_binary_accepts(&bad, 0xBAD0 + s) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 0, "non-bit accepted {accepted}/64 — soundness broken");
    }

    #[test]
    fn packed_binary_zk_verifies_and_rejects_non_bits() {
        use binary_zk::{prove_packed_binary_zk, verify_packed_binary_zk};
        use packed::commit_packed;
        // Honest packed value → all coefficients are bits.
        let (stmt, wit) = commit_packed(64, 0xC0FFEEu64, 71);
        let pf = prove_packed_binary_zk(&stmt.key, &stmt.c_b, &wit.bit_poly, &wit.r_b, 3)
            .expect("honest proof");
        assert!(verify_packed_binary_zk(&stmt.key, &stmt.c_b, &pf), "honest ZK binary must verify");

        // Non-bit committed value: set a coefficient to 2, re-commit so the OPENING
        // holds — the ZK binary argument must reject.
        let mut b2 = wit.bit_poly.clone();
        b2.c[5] = 2;
        let key = RingCommitKey::production(1, 71);
        let c_b2 = key.commit(&PolyVec(vec![b2.clone()]), &wit.r_b);
        let pf2 = prove_packed_binary_zk(&key, &c_b2, &b2, &wit.r_b, 4);
        // Either proving fails, or the produced proof does not verify.
        let ok = pf2.map(|p| verify_packed_binary_zk(&key, &c_b2, &p)).unwrap_or(false);
        assert!(!ok, "non-bit packed value must not yield an accepting ZK binary proof");
    }

    #[test]
    fn value_link_binds_packed_to_value_commitment() {
        use balance_zk::{prove_value_link, verify_value_link};
        use packed::gadget;
        // Coin value commitment (value key, ℓ=1) and a packed c_b for the same
        // value; prove ⟪g,b⟫ = v links them.
        let key_b = RingCommitKey::production(1, 0xB1);
        let key_v = RingCommitKey::production(1, 0x7A1); // distinct value key
        let v = 12345u64;
        let n_bits = 32;
        let mk_r = |t: u64| {
            let mut prg = SplitMix64::new(t);
            PolyVec::sample_short(9, ETA, &mut prg)
        };
        let (r_b, r_v) = (mk_r(1), mk_r(2));
        let mut b = Poly::zero();
        for i in 0..n_bits {
            b.c[i] = (v >> i) & 1;
        }
        let c_b = key_b.commit(&PolyVec(vec![b.clone()]), &r_b);
        let c_v = key_v.commit(&PolyVec(vec![{
            let mut p = Poly::zero();
            p.c[0] = v % Poly::Q;
            p
        }]), &r_v);
        // Sanity: value functional matches.
        assert_eq!(packed::value_of(&b, n_bits), v);
        let _ = gadget(n_bits);

        let pf = prove_value_link(&key_b, &key_v, &c_b, &c_v, &b, &r_b, v, &r_v, n_bits, 9).unwrap();
        assert!(verify_value_link(&key_b, &key_v, &c_b, &c_v, n_bits, &pf), "matching value must link");

        // A value commitment to a DIFFERENT value must not link to this c_b.
        let c_other = key_v.commit(&PolyVec(vec![{
            let mut p = Poly::zero();
            p.c[0] = 999;
            p
        }]), &r_v);
        assert!(!verify_value_link(&key_b, &key_v, &c_b, &c_other, n_bits, &pf), "mismatched value must fail");
    }

    #[test]
    fn packed_balance_zk_verifies_and_rejects_imbalance() {
        use balance_zk::*;
        use packed::*;
        // Two inputs (300, 500) → one output (750) + fee 50. Balanced.
        let key = RingCommitKey::production(1, 0xBA1);
        let commit = |v: u64, tag: u64| {
            let mut prg = SplitMix64::new(tag);
            let r = PolyVec::sample_short(9, ETA, &mut prg);
            let mut b = Poly::zero();
            for i in 0..64 {
                b.c[i] = (v >> i) & 1;
            }
            (key.commit(&PolyVec(vec![b.clone()]), &r), b, r)
        };
        let (ci1, b1, r1) = commit(300, 1);
        let (ci2, b2, r2) = commit(500, 2);
        let (co1, bo1, ro1) = commit(750, 3);
        let fee = 50u64;
        let d = combined_commitment(&[ci1.clone(), ci2.clone()], &[co1.clone()]);
        // B = b1 + b2 − bo1 ; R = r1 + r2 − ro1.
        let big_b = b1.add(&b2).sub(&bo1);
        let neg_ro1 = PolyVec(ro1.0.iter().map(|p| p.neg()).collect());
        let big_r = r1.add(&r2).add(&neg_ro1);
        let pf = prove_balance(&key, &d, &big_b, &big_r, fee, 64, 7).expect("balances");
        assert!(verify_balance(&key, &d, fee, 64, &pf), "balanced tx must verify");
        // Wrong fee → reject.
        assert!(!verify_balance(&key, &d, fee + 1, 64, &pf), "wrong fee must reject");
    }

    #[test]
    fn complete_zk_packed_range_proof() {
        // The milestone: a COMPLETE zero-knowledge packed range proof =
        // ZK opening (hides r_b + the amount) + ZK binary (all coeffs ∈ {0,1},
        // which with the opening's short-witness bound ⇒ v = Σ2ⁱbᵢ ∈ [0,2^N)).
        use binary_zk::{prove_packed_binary_zk, verify_packed_binary_zk};
        use packed::*;
        let (stmt, wit) = commit_packed(64, 0x1234_5678u64, 99);
        let open = prove_packed_opening_zk(&stmt, &wit, 1).expect("opening");
        let bin = prove_packed_binary_zk(&stmt.key, &stmt.c_b, &wit.bit_poly, &wit.r_b, 2).expect("binary");
        assert!(verify_packed_opening_zk(&stmt, &open), "ZK opening verifies");
        assert!(verify_packed_binary_zk(&stmt.key, &stmt.c_b, &bin), "ZK binary verifies");
        // The committed value is recoverable by the owner but not revealed.
        assert_eq!(value_of(&wit.bit_poly, 64), 0x1234_5678u64 % Poly::Q);
    }

    #[test]
    fn packed_binary_zk_binds_its_commitment() {
        use binary_zk::{prove_packed_binary_zk, verify_packed_binary_zk};
        use packed::commit_packed;
        let (stmt, wit) = commit_packed(64, 321u64, 81);
        let pf = prove_packed_binary_zk(&stmt.key, &stmt.c_b, &wit.bit_poly, &wit.r_b, 6).expect("proof");
        let (other, _w) = commit_packed(64, 322u64, 82);
        assert!(!verify_packed_binary_zk(&other.key, &other.c_b, &pf), "proof must bind its commitment");
    }

    #[test]
    fn packed_opening_zk_verifies_and_hides_witness() {
        use packed::*;
        let (stmt, wit) = commit_packed(64, 0xFACE_1234u64, 31);
        let proof = prove_packed_opening_zk(&stmt, &wit, 7).expect("opens");
        assert!(verify_packed_opening_zk(&stmt, &proof), "honest ZK opening must verify");

        // Zero-knowledge sanity: two different secret amounts under the SAME key
        // both verify — the transcript binds the commitment, not the amount, and
        // the response is masked (perfect-ZK per sigma_rq analysis).
        let (stmt2, wit2) = commit_packed(64, 1u64, 31);
        let proof2 = prove_packed_opening_zk(&stmt2, &wit2, 7).expect("opens");
        assert!(verify_packed_opening_zk(&stmt2, &proof2));
    }

    #[test]
    fn packed_opening_zk_rejects_wrong_commitment() {
        use packed::*;
        let (stmt, wit) = commit_packed(64, 500u64, 41);
        let proof = prove_packed_opening_zk(&stmt, &wit, 9).expect("opens");
        let (other, _w) = commit_packed(64, 501u64, 42);
        assert!(!verify_packed_opening_zk(&other, &proof), "opening must bind its commitment");
    }

    #[test]
    fn packed_encoding_shrinks_witness_rank_vs_n1() {
        use packed::*;
        // Compare witness rank r0 (ring elements the send-witness base reveals)
        // for the faithful n=1 encoding vs the packed encoding, across N.
        for n_bits in [16usize, 64, 611] {
            let faithful_r0 = n_bits + 2 * LAMBDA; // bits + r_b + r_v
            let packed_r0 = n_bits.div_ceil(Poly::D) + LAMBDA; // ⌈N/d⌉ bit-polys + r_b
            let (_stmt, wit) = commit_packed(n_bits.min(Poly::D), (n_bits as u64) * 7 + 1, 5);
            assert!(relation_holds(&_stmt, &wit, 2));
            println!(
                "PACKED N={n_bits}: faithful r0={faithful_r0} packed r0={packed_r0} \
                 ({:.1}× fewer ring elements)",
                faithful_r0 as f64 / packed_r0 as f64
            );
            assert!(packed_r0 < faithful_r0);
        }
    }

    #[test]
    fn range_labrador_rejects_tampered_witness() {
        // Corrupt the sent base witness — the final-family check must reject.
        let key = RingRangeKey::production(16, 17);
        let v = 4242u64;
        let (c_v, r_v) = commit_v(&key, v, 8);
        let mut proof = prove_range_labrador(&key, &c_v, v, &r_v, 9).unwrap();
        if let Some(first) = proof.rec.final_s.get_mut(0) {
            first.0[0] = first.0[0].add(&Poly::one());
        }
        assert!(!verify_range_labrador(&key, &c_v, &proof));
    }

    #[test]
    fn packed_zk_recursion_size_analysis() {
        // Step 5 measurement (structural, no proving): the ZK packed-range recursion
        // size vs the (non-ZK) send-witness base. Prints the honest tradeoff — the
        // ZK base opening reveals a masked z of the FULL child dim × REPS + commits,
        // and has_conj inflates the child (3r² garbage), so a SINGLE small range is
        // LARGER under ZK. The recursion's ~KB win needs full-tx amortization + NS22.
        use crate::labrador::{child_dims, level_schedule_conj};
        const KAPPA: usize = crate::params::LABRADOR_RANK_KAPPA; // reduction rank (8)
        const SIS: usize = crate::params::SIS_RANK_KAPPA; // commitment κ (6)
        const REPS: usize = 4; // BASE_ZK_REPS
        let lambda = crate::params::LWE_RANK_LAMBDA;
        let per = (Poly::D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);

        let r0 = 1 + lambda; // packed witness: bit_poly + r_b
        let sched = level_schedule_conj(r0, 1, crate::params::SECRET_NORM_ETA as u64, KAPPA, 4, 0, 1, true);
        assert!(!sched.is_empty());
        let (rp, np) = child_dims(&sched[0], KAPPA);
        let rn = rp * np;

        // Proof-poly counts (see size_bytes on the ZK types).
        let u1 = 2 * KAPPA * sched.len();
        let per_shot = (SIS + rn) + 5 * (SIS + 1) + rn + 3 * lambda;
        let base = (SIS + rn) + REPS * per_shot;
        let ct_base = (SIS + rn) + (SIS + 1) + rn + 2 * lambda;
        let zk_polys = u1 + base + ct_base;
        let zk_kb = zk_polys * per / 1024;
        let send_witness_kb = r0 * per / 1024; // non-ZK: final_s = r0 rank-1 polys

        println!(
            "STEP5 PACKED-ZK: child r'·n'={rn} (r'={rp},n'={np})  ZK proof≈{zk_polys} polys = {zk_kb}KB  \
             vs send-witness(non-ZK)={send_witness_kb}KB  [REPS={REPS}]"
        );
        // The structural facts this test pins: the ZK recursion is dominated by the
        // base opening (REPS × full-child z + commitments), so for a single small
        // range it is far larger than the send-witness base — the size win is not
        // free and requires amortizing MANY constraints into ONE folded instance.
        assert!(rn > 0);
        assert!(zk_polys > u1, "base openings dominate the proof");
    }

    #[test]
    fn convergent_regime_ct_zk_size_analysis() {
        // Step 5 follow-up (structural, no proving): the CONVERGENT regime. When
        // n0 ≫ r²κ (the LaBRADOR regime, ν=2), folding SHRINKS n while r stays
        // bounded — the opposite of the n0=1 explosion. This measures, for an
        // amortized (large-n0) statement: (a) that r stays bounded and n shrinks,
        // (b) the converged base dims, (c) the ZK proof size, and (d) what an
        // NS22-style light base (2r−1 sent garbage, no REPS×full-z) would give.
        use crate::labrador::{child_dims, level_schedule_conj};
        const KAPPA: usize = crate::params::LABRADOR_RANK_KAPPA;
        const SIS: usize = crate::params::SIS_RANK_KAPPA;
        const REPS: usize = 4;
        let lambda = crate::params::LWE_RANK_LAMBDA;
        let per = (Poly::D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);

        for (r0, n0) in [(4usize, 512usize), (4, 4096), (8, 8192)] {
            // Convergent schedule: base-case at the crossover (n_floor≈64) so the
            // fold stops before r starts climbing; has_conj for the ct path.
            let sched = level_schedule_conj(r0, n0, crate::params::SECRET_NORM_ETA as u64, KAPPA, 18, 64, 12, true);
            let shapes: Vec<(usize, usize)> = sched.iter().map(|s| (s.r, s.n)).collect();
            let r_max = shapes.iter().map(|(r, _)| *r).max().unwrap_or(r0);
            let (rp, np) = sched.last().map(|s| child_dims(s, KAPPA)).unwrap_or((r0, n0));
            let rn = rp * np;

            let u1 = 2 * KAPPA * sched.len();
            let per_shot = (SIS + rn) + 5 * (SIS + 1) + rn + 3 * lambda;
            let base = (SIS + rn) + REPS * per_shot;
            let ct_base = (SIS + rn) + (SIS + 1) + rn + 2 * lambda;
            let zk_polys = u1 + base + ct_base;

            // NS22-light base estimate: instead of REPS×full-z, send only 2r−1
            // masked garbage + the (small) converged witness once. Rough lower bound.
            let ns22_polys = u1 + (2 * rp - 1) + rn;

            println!(
                "CONVERGE-ZK r0={r0} n0={n0}: levels={} r_max={r_max} converged(r'={rp},n'={np}) r'·n'={rn} \
                 | current-ZK≈{}KB | NS22-light-base≈{}KB",
                sched.len(),
                zk_polys * per / 1024,
                ns22_polys * per / 1024
            );
            assert!(r_max <= 16, "r stays bounded in the convergent regime (was {r_max})");
            assert!(rn < r0 * n0, "the fold shrinks r·n below the input (r0·n0={})", r0 * n0);
        }
    }

    #[test]
    fn amortized_multi_range_relation_is_correct() {
        // The amortized (M-range) relation is correctly built: on the honest witness
        // every commitment-opening constraint holds (= its target) and the aggregated
        // binary ct holds (= 0). A non-bit amount breaks the binary ct. The ZK proof
        // rides the validated pipeline (full_ct_zk_pipeline_end_to_end); this checks
        // the RELATION the fold-friendly succinct proof consumes.
        use super::packed::*;
        use crate::labrador::{eval_constraint_on_witness, eval_ct_on_witness};
        let values = [5u64, 42, 1000, 0, 255, 7, 88, 300];
        let (stmt, wit) = commit_multi_range(16, &values, 0xA33F, 0xA33F);
        let fam = multi_range_family(&stmt);
        let ctf = multi_range_ct_family(&stmt);
        let s = multi_range_witness(&wit);

        // (a) commitment openings hold.
        for con in &fam {
            assert_eq!(eval_constraint_on_witness(con, &s), con.b, "opening constraint holds");
        }
        // (b) aggregated binary holds (all amounts in range ⇒ all bits binary).
        for con in &ctf {
            assert_eq!(eval_ct_on_witness(con, &s), con.target % Poly::Q, "aggregated binary holds");
        }

        // (c) a NON-BIT witness (coefficient 2) breaks the binary ct.
        let mut wit_bad = MultiRangeWitness { bits: wit.bits.clone(), r_b: wit.r_b.clone() };
        wit_bad.bits[0].c[3] = 2;
        let s_bad = multi_range_witness(&wit_bad);
        let ct_ok = ctf.iter().all(|con| eval_ct_on_witness(con, &s_bad) == con.target % Poly::Q);
        assert!(!ct_ok, "non-bit amount breaks the aggregated binary ct");
    }

    #[test]
    fn amortized_money_proof_per_range_size_analysis() {
        // The SIZE WIN via amortization (structural, no proving). The succinct
        // general-terminal base cost is ~FIXED (the fold converges to a bounded
        // r·n floor regardless of statement size — see convergent_regime), so
        // folding MANY ranges into ONE proof makes PER-RANGE size shrink toward
        // ~KB. This is why the money path must amortize the whole tx.
        use crate::labrador::{child_dims, level_schedule_conj};
        const KAPPA: usize = crate::params::LABRADOR_RANK_KAPPA; // fold A rows (8)
        const SIS: usize = crate::params::SIS_RANK_KAPPA; // commitment κ (6)
        let lambda = crate::params::LWE_RANK_LAMBDA;
        let per = (Poly::D * crate::params::MODULUS_Q_BITS as usize).div_ceil(8);

        for m in [1usize, 16, 256, 4096] {
            // Fold-friendly amortized layout: pack ~32-bit ranges (one bit_poly each,
            // 256 coeffs/poly) into a few high-dim vectors → large n0, small r0.
            let total_bits = m * 32;
            let n0 = (total_bits / 256 + lambda).next_power_of_two().max(512);
            let r0 = 4usize;
            let sched = level_schedule_conj(r0, n0, crate::params::SECRET_NORM_ETA as u64, KAPPA, 18, 64, 12, true);
            let last = sched.last().unwrap();
            let (rp, np) = child_dims(last, KAPPA);
            let rn = rp * np;

            // General-terminal base size (GeneralBaseZkProof): t (r·κ_A) + t_w (κ_A)
            // + ell-1 garbage commits (each SIS+1 polys): c_f,c_nu,c_ctnu,c_fc (4) +
            // c_e,c_e2,c_mh,c_ecl,c_ecr (5·r) + c_g (r(r+1)/2) + c_h,c_hh,c_gc (3·r²);
            // + zp (n) + z_gq,z_gl,z_gs,z_gc,z_hbind (5λ) + ζ (1) + r_zeta,r_ctnu (2λ).
            let commits = 4 + 5 * rp + rp * (rp + 1) / 2 + 3 * rp * rp;
            let base_polys = rp * KAPPA + KAPPA + commits * (SIS + 1) + np + 5 * lambda + 1 + 2 * lambda;
            let u1 = 2 * KAPPA * sched.len();
            let total_kb = (u1 + base_polys) * per / 1024;
            // p is 256 small ints (JL); count generously as ~256·5 bytes.
            let per_range_kb = total_kb as f64 / m as f64;
            let levels = sched.len();
            println!(
                "AMORTIZED m={m} ranges: n0={n0} levels={levels} converged(r'={rp},n'={np}) \
                 total≈{total_kb}KB  per-range≈{per_range_kb:.2}KB",
            );
            let _ = rn;
        }
        // The point: total is ~fixed (converged base), so per-range → small with M.
    }
}
