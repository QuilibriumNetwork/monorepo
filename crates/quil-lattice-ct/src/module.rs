//! Module layer over `R_q`: vectors/matrices of [`Poly`], and the **ring-form
//! BDLOP commitment** instantiated at the estimator-validated production
//! parameters (`d=256`, `q≈2^28`, module ranks `κ=λ=6`, secret norm `η=2`).
//!
//! This is the point where [`crate::params`] stops being a specification and
//! runs: the commitment binds under M-SIS and hides under M-LWE *at the
//! dimensions the lattice-estimator signed off on* (M-LWE ≈ 159–185-bit).
//! The proof systems (`sigma`/`binary`/`range`/`linear`/`ring`) re-instantiate
//! over this same module layer next.
//!
//! Multiplication is schoolbook (via [`Poly::mul`]); production swaps in the NTT.

use crate::arith::SplitMix64;
use crate::params::{LWE_RANK_LAMBDA, MODULUS_Q, RING_DEGREE_D, SECRET_NORM_ETA, SIS_RANK_KAPPA};
use crate::rq::Poly;

/// A vector of ring elements.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolyVec(pub Vec<Poly>);

impl PolyVec {
    pub fn zero(len: usize) -> Self {
        PolyVec(vec![Poly::zero(); len])
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn add(&self, o: &PolyVec) -> PolyVec {
        PolyVec(self.0.iter().zip(&o.0).map(|(a, b)| a.add(b)).collect())
    }
    pub fn sub(&self, o: &PolyVec) -> PolyVec {
        PolyVec(self.0.iter().zip(&o.0).map(|(a, b)| a.sub(b)).collect())
    }
    /// Scale every entry by a ring element `c`: `c·v` (NTT hot path).
    pub fn mul_poly(&self, c: &Poly) -> PolyVec {
        PolyVec(self.0.iter().map(|v| c.mul_ntt(v)).collect())
    }
    /// Scale every entry by an integer scalar.
    pub fn scalar_mul(&self, s: i64) -> PolyVec {
        PolyVec(self.0.iter().map(|v| v.scalar_mul(s)).collect())
    }
    /// Concatenate two vectors (used to stack `(t1, t2)`).
    pub fn concat(&self, o: &PolyVec) -> PolyVec {
        let mut v = self.0.clone();
        v.extend(o.0.iter().cloned());
        PolyVec(v)
    }
    /// Sample a vector with coefficients uniform in `[-bound, bound]` (masking).
    pub fn sample_uniform_pm(len: usize, bound: i64, prg: &mut SplitMix64) -> PolyVec {
        let span = (2 * bound + 1) as u128;
        PolyVec(
            (0..len)
                .map(|_| {
                    let coeffs: Vec<i64> =
                        (0..RING_DEGREE_D).map(|_| prg.uniform_below(span) as i64 - bound).collect();
                    Poly::from_signed(&coeffs)
                })
                .collect(),
        )
    }
    /// Centered infinity norm over all coefficients of all entries.
    pub fn inf_norm(&self) -> u64 {
        self.0.iter().map(|p| p.inf_norm()).max().unwrap_or(0)
    }
    /// Sample a SHORT vector: each coefficient uniform in `[-η, η]`.
    pub fn sample_short(len: usize, eta: i64, prg: &mut SplitMix64) -> PolyVec {
        let span = (2 * eta + 1) as u128;
        PolyVec(
            (0..len)
                .map(|_| {
                    let coeffs: Vec<i64> =
                        (0..RING_DEGREE_D).map(|_| prg.uniform_below(span) as i64 - eta).collect();
                    Poly::from_signed(&coeffs)
                })
                .collect(),
        )
    }
}

/// A matrix of ring elements (`rows × cols`).
#[derive(Clone, Debug)]
pub struct PolyMatrix {
    pub rows: usize,
    pub cols: usize,
    pub m: Vec<Vec<Poly>>,
}

impl PolyMatrix {
    /// Deterministically expand a uniform `R_q` matrix from a seed (public
    /// commitment key material — a 32-byte seed on the wire, à la Dilithium).
    pub fn from_seed(rows: usize, cols: usize, seed: u64) -> Self {
        let mut prg = SplitMix64::new(seed);
        let m = (0..rows)
            .map(|_| {
                (0..cols)
                    .map(|_| {
                        Poly {
                            c: (0..RING_DEGREE_D).map(|_| prg.uniform_below(MODULUS_Q as u128) as u64).collect(),
                        }
                    })
                    .collect()
            })
            .collect();
        PolyMatrix { rows, cols, m }
    }

    /// Matrix product `self·o` over `R_q` (`(r×c)·(c×k) = r×k`), NTT hot path.
    pub fn matmul(&self, o: &PolyMatrix) -> PolyMatrix {
        assert_eq!(self.cols, o.rows, "matmul dimension mismatch");
        let m = (0..self.rows)
            .map(|i| {
                (0..o.cols)
                    .map(|k| {
                        let mut acc = Poly::zero();
                        for j in 0..self.cols {
                            acc = acc.add(&self.m[i][j].mul_ntt(&o.m[j][k]));
                        }
                        acc
                    })
                    .collect()
            })
            .collect();
        PolyMatrix { rows: self.rows, cols: o.cols, m }
    }

    /// Matrix-vector product `M·v` over `R_q`.
    pub fn matvec(&self, v: &PolyVec) -> PolyVec {
        assert_eq!(self.cols, v.len(), "matvec dimension mismatch");
        PolyVec(
            self.m
                .iter()
                .map(|row| {
                    let mut acc = Poly::zero();
                    for (a, x) in row.iter().zip(&v.0) {
                        acc = acc.add(&a.mul_ntt(x)); // NTT hot path
                    }
                    acc
                })
                .collect(),
        )
    }
}

/// A ring-form BDLOP commitment key `(A1, A2)` at the production ranks.
#[derive(Clone, Debug)]
pub struct RingCommitKey {
    /// `A1 ∈ R_q^{κ×λ}` — binding block.
    pub a1: PolyMatrix,
    /// `A2 ∈ R_q^{ℓ×λ}` — message block.
    pub a2: PolyMatrix,
    /// Message length `ℓ` (ring elements).
    pub ell: usize,
}

/// A ring commitment `(t1, t2)`. Homomorphic under [`RingCommitment::add`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingCommitment {
    pub t1: PolyVec,
    pub t2: PolyVec,
}

impl RingCommitment {
    /// `Commit(m;r) + Commit(m';r') = Commit(m+m'; r+r')` over `R_q`.
    pub fn add(&self, o: &RingCommitment) -> RingCommitment {
        RingCommitment { t1: self.t1.add(&o.t1), t2: self.t2.add(&o.t2) }
    }
    /// Stacked `(t1, t2)` as one vector.
    pub fn stacked(&self) -> PolyVec {
        self.t1.concat(&self.t2)
    }
}

impl RingCommitKey {
    /// Expand the key at the production ranks (`κ`, `λ` from [`crate::params`])
    /// for a message of length `ell` ring elements, from `seed`.
    pub fn production(ell: usize, seed: u64) -> Self {
        RingCommitKey {
            a1: PolyMatrix::from_seed(SIS_RANK_KAPPA, LWE_RANK_LAMBDA, seed),
            a2: PolyMatrix::from_seed(ell, LWE_RANK_LAMBDA, seed ^ 0xA2A2_A2A2),
            ell,
        }
    }

    /// The stacked matrix `M = [A1; A2]` (`(κ+ℓ) × λ`) a commitment
    /// `(t1, t2)` opens against: `M·r = (t1, t2 − msg)`.
    pub fn stacked_matrix(&self) -> PolyMatrix {
        let mut m = self.a1.m.clone();
        m.extend(self.a2.m.iter().cloned());
        PolyMatrix { rows: self.a1.rows + self.a2.rows, cols: self.a1.cols, m }
    }

    /// Commit to `msg ∈ R_q^ℓ` with short randomness `r ∈ R_q^λ`
    /// (`‖r‖∞ ≤ η`): `t1 = A1·r`, `t2 = A2·r + msg`.
    pub fn commit(&self, msg: &PolyVec, r: &PolyVec) -> RingCommitment {
        assert_eq!(msg.len(), self.ell, "message length != ℓ");
        RingCommitment { t1: self.a1.matvec(r), t2: self.a2.matvec(r).add(msg) }
    }

    /// Verify an opening: recompute and check equality, plus the randomness
    /// norm bound (M-SIS binding needs a SHORT opening).
    pub fn open_verify(&self, c: &RingCommitment, msg: &PolyVec, r: &PolyVec, norm_bound: u64) -> bool {
        r.inf_norm() <= norm_bound && &self.commit(msg, r) == c
    }
}

/// The default secret norm `η` for short sampling at production parameters.
pub const ETA: i64 = SECRET_NORM_ETA;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matvec_is_linear() {
        // M·(u+v) = M·u + M·v over R_q, at production ranks.
        let m = PolyMatrix::from_seed(SIS_RANK_KAPPA, LWE_RANK_LAMBDA, 1);
        let mut prg = SplitMix64::new(2);
        let u = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        let v = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        assert_eq!(m.matvec(&u.add(&v)), m.matvec(&u).add(&m.matvec(&v)));
    }

    #[test]
    fn ring_commitment_round_trip_at_production_params() {
        // Commit + open at d=256, κ=λ=6, η=2 — the estimator-validated sizes.
        let k = RingCommitKey::production(1, 42);
        let mut prg = SplitMix64::new(7);
        let msg = PolyVec(vec![Poly::from_signed(&(0..256).map(|i| (i % 11) as i64).collect::<Vec<_>>())]);
        let r = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        let c = k.commit(&msg, &r);
        assert_eq!(c.t1.len(), SIS_RANK_KAPPA);
        assert!(k.open_verify(&c, &msg, &r, ETA as u64));
        // A different message under the same randomness is a different commitment.
        let msg2 = PolyVec(vec![Poly::one()]);
        assert!(!k.open_verify(&c, &msg2, &r, ETA as u64));
    }

    #[test]
    fn ring_commitment_is_homomorphic() {
        let k = RingCommitKey::production(1, 99);
        let mut prg = SplitMix64::new(11);
        let m1 = PolyVec(vec![Poly::from_signed(&(0..256).map(|i| (i % 7) as i64 - 3).collect::<Vec<_>>())]);
        let m2 = PolyVec(vec![Poly::from_signed(&(0..256).map(|i| (i % 5) as i64 - 2).collect::<Vec<_>>())]);
        let r1 = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        let r2 = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        let c_sum = k.commit(&m1, &r1).add(&k.commit(&m2, &r2));
        let direct = k.commit(&m1.add(&m2), &r1.add(&r2));
        assert_eq!(c_sum, direct, "homomorphic add == commit of the sums, over R_q");
        // The summed randomness is still short (‖r1+r2‖∞ ≤ 2η).
        assert!(r1.add(&r2).inf_norm() <= 2 * ETA as u64);
    }

    #[test]
    fn short_sampling_respects_the_norm_bound() {
        let mut prg = SplitMix64::new(3);
        let r = PolyVec::sample_short(LWE_RANK_LAMBDA, ETA, &mut prg);
        assert!(r.inf_norm() <= ETA as u64);
    }
}
