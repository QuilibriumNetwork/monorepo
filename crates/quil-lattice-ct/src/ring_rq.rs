//! Ring-form linkable ring signature — spend authority + anonymity + the
//! key-image nullifier, at production parameters.
//!
//! # Why this is not the reference's N-branch CDS-OR
//!
//! CDS-OR needs an additive challenge split, which the structured ring
//! challenge lacks. Instead this is a **linear one-out-of-many**: commit the
//! witness `m = (sk ‖ δ)` where `δ` is a binary indicator (`δ_j = 1`), then
//! prove three linear relations on the committed `m` — each a
//! [`crate::sigma_rq`] short opening of `[A1; L·A2]·r = (t1, L·t2 − t)` — plus
//! [`crate::binary_rq`] on the `δ` coordinates:
//!
//! * **selection** `A·sk − Σ pkᵢ·δᵢ = 0` (the chosen key equals `A·sk`),
//! * **key image** `B·sk = T` (linkability),
//! * **sum** `Σ δᵢ = 1` (exactly one selection).
//!
//! Anonymity is the commitment's hiding (`δ` never revealed); soundness/
//! linkability are the relations' bindings; `O(N)` size (vs. GK's `O(log N)`,
//! the efficiency refinement). Message binding here mixes `H(μ)` into the
//! proof seeds — production folds `μ` into every Fiat-Shamir challenge, along
//! with the rejection tuning.

use sha2::{Digest, Sha256};

use crate::arith::SplitMix64;
use crate::binary_rq::{prove_bit_rq, verify_bit_rq, BinRqParams, BinaryProofRq};
use crate::module::{PolyMatrix, PolyVec, RingCommitKey, RingCommitment};
use crate::params::{CHALLENGE_WEIGHT_TAU, LWE_RANK_LAMBDA as LAMBDA, SIS_RANK_KAPPA as KAPPA};
use crate::rq::Poly;
use crate::sigma_rq::{prove_ring_opening, verify_ring_opening, RingOpeningProof, RingSigmaParams};

const N_B: usize = KAPPA; // key-image (tag) height

fn const1() -> Poly {
    let mut p = Poly::zero();
    p.c[0] = 1;
    p
}
fn stack_rows(top: &PolyMatrix, bot: &PolyMatrix) -> PolyMatrix {
    assert_eq!(top.cols, bot.cols);
    let mut m = top.m.clone();
    m.extend(bot.m.iter().cloned());
    PolyMatrix { rows: top.rows + bot.rows, cols: top.cols, m }
}

/// Public parameters: `A` (keys), `B` (tags), and a commitment key sized for
/// `ℓ = λ + N` (the message `(sk ‖ δ)`).
pub struct RingSigKeyRq {
    pub n_ring: usize,
    a: PolyMatrix,       // κ × λ (pk = A·sk)
    b: PolyMatrix,       // N_B × λ (tag = B·sk)
    c_key: RingCommitKey, // commitment key, ℓ = λ + N
    sigma: RingSigmaParams,
    bin: BinRqParams,
}

impl RingSigKeyRq {
    pub fn production(n_ring: usize, seed: u64) -> Self {
        let a = PolyMatrix::from_seed(KAPPA, LAMBDA, seed);
        let b = PolyMatrix::from_seed(N_B, LAMBDA, seed ^ 0xB0B);
        let ell = LAMBDA + n_ring;
        let c_key = RingCommitKey {
            a1: PolyMatrix::from_seed(KAPPA, LAMBDA, seed ^ 0xC1),
            a2: PolyMatrix::from_seed(ell, LAMBDA, seed ^ 0xC2),
            ell,
        };
        let sigma = RingSigmaParams { mask_bound: 1 << 17, eta: crate::module::ETA, tau: CHALLENGE_WEIGHT_TAU };
        let bin = BinRqParams::production();
        RingSigKeyRq { n_ring, a, b, c_key, sigma, bin }
    }

    pub fn keygen(&self, seed: u64) -> (PolyVec, PolyVec) {
        let mut prg = SplitMix64::new(seed);
        let sk = PolyVec::sample_short(LAMBDA, crate::module::ETA, &mut prg);
        let pk = self.a.matvec(&sk);
        (sk, pk)
    }
    pub fn key_image(&self, sk: &PolyVec) -> PolyVec {
        self.b.matvec(sk)
    }

    /// `PK = [pk_0 | … | pk_{N-1}]` (κ × N).
    fn pk_matrix(&self, ring: &[PolyVec]) -> PolyMatrix {
        let m = (0..KAPPA)
            .map(|i| ring.iter().map(|pk| pk.0[i].clone()).collect())
            .collect();
        PolyMatrix { rows: KAPPA, cols: self.n_ring, m }
    }
    /// Selection map `L_sel = [A | −PK]` (κ × (λ+N)).
    fn l_sel(&self, ring: &[PolyVec]) -> PolyMatrix {
        let pk = self.pk_matrix(ring);
        let mut m = Vec::with_capacity(KAPPA);
        for i in 0..KAPPA {
            let mut row = self.a.m[i].clone();
            row.extend(pk.m[i].iter().map(|p| p.neg()));
            m.push(row);
        }
        PolyMatrix { rows: KAPPA, cols: LAMBDA + self.n_ring, m }
    }
    /// Key-image map `L_ki = [B | 0]` (N_B × (λ+N)).
    fn l_ki(&self) -> PolyMatrix {
        let mut m = Vec::with_capacity(N_B);
        for i in 0..N_B {
            let mut row = self.b.m[i].clone();
            row.extend((0..self.n_ring).map(|_| Poly::zero()));
            m.push(row);
        }
        PolyMatrix { rows: N_B, cols: LAMBDA + self.n_ring, m }
    }
    /// Sum map `L_sum = [0 | 1…1]` (1 × (λ+N)).
    fn l_sum(&self) -> PolyMatrix {
        let mut row: Vec<Poly> = (0..LAMBDA).map(|_| Poly::zero()).collect();
        row.extend((0..self.n_ring).map(|_| const1()));
        PolyMatrix { rows: 1, cols: LAMBDA + self.n_ring, m: vec![row] }
    }
}

/// A linkable ring signature.
pub struct RingSigRq {
    pub tag: PolyVec, // key image
    pub c_m: RingCommitment,
    pub bit_proofs: Vec<BinaryProofRq>,
    pub sel: RingOpeningProof,
    pub ki: RingOpeningProof,
    pub sum: RingOpeningProof,
}

/// Short-opening of the linear relation `L·m = t` on `C_m` (randomness `r`):
/// prove `[A1; L·A2]·r = (t1, L·t2 − t)`. Public — reused by `membership`.
pub fn relation_prove(
    ck: &RingCommitKey,
    c_m: &RingCommitment,
    l: &PolyMatrix,
    t: &PolyVec,
    r: &PolyVec,
    p: &RingSigmaParams,
    aux: &[u8],
    seed: u64,
) -> Option<RingOpeningProof> {
    let m_l = stack_rows(&ck.a1, &l.matmul(&ck.a2));
    let d_l = c_m.t1.concat(&l.matvec(&c_m.t2).sub(t));
    prove_ring_opening(&m_l, &d_l, r, p, aux, seed)
}
pub fn relation_verify(
    ck: &RingCommitKey,
    c_m: &RingCommitment,
    l: &PolyMatrix,
    t: &PolyVec,
    proof: &RingOpeningProof,
    p: &RingSigmaParams,
    aux: &[u8],
) -> bool {
    let m_l = stack_rows(&ck.a1, &l.matmul(&ck.a2));
    let d_l = c_m.t1.concat(&l.matvec(&c_m.t2).sub(t));
    verify_ring_opening(&m_l, &d_l, proof, p, aux)
}

fn msg_seed(seed: u64, msg: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(seed.to_le_bytes());
    h.update(msg);
    u64::from_le_bytes(h.finalize()[..8].try_into().unwrap())
}

/// Sign `msg` as ring member `signer` (holding `sk`).
pub fn sign(
    key: &RingSigKeyRq,
    ring: &[PolyVec],
    signer: usize,
    sk: &PolyVec,
    msg: &[u8],
    seed: u64,
) -> Option<RingSigRq> {
    if signer >= ring.len() || ring.len() != key.n_ring {
        return None;
    }
    let seed = msg_seed(seed, msg);
    let mut prg = SplitMix64::new(seed ^ 0x5164);
    // Indicator δ and message m = (sk ‖ δ).
    let delta: Vec<Poly> = (0..key.n_ring)
        .map(|i| if i == signer { const1() } else { Poly::zero() })
        .collect();
    let mut m = sk.0.clone();
    m.extend(delta.iter().cloned());
    let r = PolyVec::sample_short(LAMBDA, crate::module::ETA, &mut prg);
    let c_m = key.c_key.commit(&PolyVec(m), &r);
    let tag = key.key_image(sk);

    // Bit validity on the δ coordinates (positions λ..λ+N of C_m).
    let mut bit_proofs = Vec::with_capacity(key.n_ring);
    for i in 0..key.n_ring {
        let ck = RingCommitKey {
            a1: key.c_key.a1.clone(),
            a2: PolyMatrix { rows: 1, cols: LAMBDA, m: vec![key.c_key.a2.m[LAMBDA + i].clone()] },
            ell: 1,
        };
        let view = RingCommitment {
            t1: c_m.t1.clone(),
            t2: PolyVec(vec![c_m.t2.0[LAMBDA + i].clone()]),
        };
        let b = if i == signer { 1u8 } else { 0u8 };
        bit_proofs.push(prove_bit_rq(&ck, &view, b, &r, &key.bin, msg, seed ^ (i as u64 + 1))?);
    }

    let sel = relation_prove(&key.c_key, &c_m, &key.l_sel(ring), &PolyVec::zero(KAPPA), &r, &key.sigma, msg, seed ^ 0xAA)?;
    let ki = relation_prove(&key.c_key, &c_m, &key.l_ki(), &tag, &r, &key.sigma, msg, seed ^ 0xBB)?;
    let sum = relation_prove(&key.c_key, &c_m, &key.l_sum(), &PolyVec(vec![const1()]), &r, &key.sigma, msg, seed ^ 0xCC)?;

    Some(RingSigRq { tag, c_m, bit_proofs, sel, ki, sum })
}

/// Verify a linkable ring signature.
pub fn verify(key: &RingSigKeyRq, ring: &[PolyVec], sig: &RingSigRq, msg: &[u8]) -> bool {
    if ring.len() != key.n_ring || sig.bit_proofs.len() != key.n_ring {
        return false;
    }
    for i in 0..key.n_ring {
        let ck = RingCommitKey {
            a1: key.c_key.a1.clone(),
            a2: PolyMatrix { rows: 1, cols: LAMBDA, m: vec![key.c_key.a2.m[LAMBDA + i].clone()] },
            ell: 1,
        };
        let view = RingCommitment {
            t1: sig.c_m.t1.clone(),
            t2: PolyVec(vec![sig.c_m.t2.0[LAMBDA + i].clone()]),
        };
        if !verify_bit_rq(&ck, &view, &sig.bit_proofs[i], &key.bin, msg) {
            return false;
        }
    }
    relation_verify(&key.c_key, &sig.c_m, &key.l_sel(ring), &PolyVec::zero(KAPPA), &sig.sel, &key.sigma, msg)
        && relation_verify(&key.c_key, &sig.c_m, &key.l_ki(), &sig.tag, &sig.ki, &key.sigma, msg)
        && relation_verify(&key.c_key, &sig.c_m, &key.l_sum(), &PolyVec(vec![const1()]), &sig.sum, &key.sigma, msg)
}

/// Linked (same signing key ⇒ double-spend) iff key images match.
pub fn linked(a: &RingSigRq, b: &RingSigRq) -> bool {
    a.tag == b.tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_of(key: &RingSigKeyRq) -> (Vec<PolyVec>, Vec<PolyVec>) {
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for i in 0..key.n_ring {
            let (sk, pk) = key.keygen(1000 + i as u64);
            sks.push(sk);
            pks.push(pk);
        }
        (pks, sks)
    }

    #[test]
    fn sign_and_verify_anonymously() {
        let key = RingSigKeyRq::production(4, 0x2146);
        let (ring, sks) = ring_of(&key);
        for signer in 0..key.n_ring {
            let sig = sign(&key, &ring, signer, &sks[signer], b"pay 10", 1).expect("signs");
            assert!(verify(&key, &ring, &sig, b"pay 10"), "member {signer} signs+verifies");
        }
    }

    #[test]
    fn key_image_links_same_signer() {
        let key = RingSigKeyRq::production(4, 0x77);
        let (ring, sks) = ring_of(&key);
        let s1 = sign(&key, &ring, 1, &sks[1], b"a", 3).unwrap();
        let s1b = sign(&key, &ring, 1, &sks[1], b"b", 4).unwrap();
        let s2 = sign(&key, &ring, 2, &sks[2], b"a", 5).unwrap();
        assert!(linked(&s1, &s1b), "same key ⇒ linked (double-spend)");
        assert!(!linked(&s1, &s2), "different keys ⇒ not linked");
    }

    #[test]
    fn signature_is_message_bound() {
        // μ now binds every Fiat-Shamir challenge: a sig for one message must
        // NOT verify against another.
        let key = RingSigKeyRq::production(4, 0x1234);
        let (ring, sks) = ring_of(&key);
        let sig = sign(&key, &ring, 2, &sks[2], b"pay Alice 10", 1).unwrap();
        assert!(verify(&key, &ring, &sig, b"pay Alice 10"));
        assert!(!verify(&key, &ring, &sig, b"pay Bob 10"), "signature must be message-bound");
    }

    #[test]
    fn non_member_cannot_sign() {
        // A key outside the ring: no ring pk equals A·sk, so the selection
        // relation A·sk = Σ pkᵢ·δᵢ cannot hold for any binary δ.
        let key = RingSigKeyRq::production(4, 0x9);
        let (ring, _sks) = ring_of(&key);
        let (outsider, _pk) = key.keygen(999_999);
        if let Some(sig) = sign(&key, &ring, 0, &outsider, b"m", 8) {
            assert!(!verify(&key, &ring, &sig, b"m"), "outsider must not verify");
        }
    }
}
