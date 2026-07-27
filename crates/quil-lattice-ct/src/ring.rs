//! Linkable ring signature (lattice / SIS) — spend authority + the key-image
//! nullifier that prevents double-spends without revealing which coin is spent.
//!
//! # Why SIS (MatRiCT-style), not Raptor
//!
//! Raptor builds an LRS on Falcon's NTRU trapdoor (assumption-aligned with the
//! Falcon signature layer), but it needs Falcon's Gaussian preimage sampling —
//! separate, delicate machinery. The confidential-transaction layer is already
//! committed to module-SIS/LWE (unavoidably, for the homomorphic commitment),
//! and this crate's Σ-engine + CDS-OR proof are exactly what a lattice LRS
//! needs. So the LRS reuses them: assumption-consistent with the amount half,
//! no new trapdoor.
//!
//! # Construction
//!
//! * **Keys.** Secret `sk` short (`‖sk‖∞ ≤ β`); public `pk = A·sk (mod q)` for a
//! public matrix `A`.
//! * **Key image (linking tag).** `T = B·sk (mod q)` for a second public matrix
//! `B`. Deterministic in `sk`, so two spends by the same key share `T` — that
//! is the double-spend link — while `T` hides `sk`.
//! * **Signature on message `μ` over ring `pk_0..pk_{N-1}`.** A **1-out-of-N**
//! CDS OR-proof (the N-branch generalization of [`crate::binary`]) that
//! `∃ j, short sk : pk_j = A·sk AND T = B·sk` — i.e. a short opening of the
//! stacked `M = [A; B]` to target `(pk_j, T)`. Only the real signer can
//! produce a real transcript for one branch; the others are simulated. `μ`
//! binds the Fiat-Shamir challenge.
//!
//! Anonymity: all branches are identically distributed. Linkability: `T` is
//! deterministic and the joint statement binds it to the spending key, so a
//! forged tag needs the secret. Unforgeability & soundness: `3^{-rounds}` (as
//! for the OR-proof).

use sha2::{Digest, Sha256};

use crate::arith::{inf_norm, matvec, signed_mod, SplitMix64};
use crate::sigma::SigmaParams;

/// Public parameters: the key matrix `A` and the tag matrix `B`, plus the
/// Σ-protocol parameters.
#[derive(Clone, Debug)]
pub struct RingParams {
    /// `A`: `n_a × m` (public keys `pk = A·sk`).
    a: Vec<Vec<u128>>,
    /// `B`: `n_b × m` (key images `T = B·sk`).
    b: Vec<Vec<u128>>,
    m: usize,
    pub sigma: SigmaParams,
}

impl RingParams {
    /// Deterministic illustrative parameters.
    pub fn from_seed(n_a: usize, n_b: usize, m: usize, sigma: SigmaParams, seed: u64) -> Self {
        let mut prg = SplitMix64::new(seed);
        let q = sigma.q;
        let a = (0..n_a).map(|_| (0..m).map(|_| prg.uniform_below(q)).collect()).collect();
        let b = (0..n_b).map(|_| (0..m).map(|_| prg.uniform_below(q)).collect()).collect();
        RingParams { a, b, m, sigma }
    }

    /// Generate a keypair: short ternary `sk`, `pk = A·sk`.
    pub fn keygen(&self, seed: u64) -> (Vec<i128>, Vec<u128>) {
        let mut prg = SplitMix64::new(seed);
        let sk: Vec<i128> = (0..self.m).map(|_| (prg.next_u64() % 3) as i128 - 1).collect();
        let pk = matvec(&self.a, &sk, self.sigma.q);
        (sk, pk)
    }

    /// The key image (linking tag) `T = B·sk`.
    pub fn key_image(&self, sk: &[i128]) -> Vec<u128> {
        matvec(&self.b, sk, self.sigma.q)
    }

    /// The public key matrix `A` (so stealth-address one-time keys `P = A·sk'`
    /// live in the same key space and are spendable by this ring signature).
    pub fn key_matrix(&self) -> &[Vec<u128>] {
        &self.a
    }
    /// Randomness/key width `m`.
    pub fn width(&self) -> usize {
        self.m
    }
    /// Modulus `q`.
    pub fn modulus(&self) -> u128 {
        self.sigma.q
    }
    /// Public key of a short secret: `pk = A·sk`.
    pub fn public_key(&self, sk: &[i128]) -> Vec<u128> {
        matvec(&self.a, sk, self.sigma.q)
    }

    /// The stacked matrix `M = [A; B]` the OR-proof opens.
    fn stacked(&self) -> Vec<Vec<u128>> {
        let mut m = self.a.clone();
        m.extend(self.b.iter().cloned());
        m
    }

    /// Branch `i`'s target `T_i = (pk_i, tag)`.
    fn target(&self, pk_i: &[u128], tag: &[u128]) -> Vec<u128> {
        let mut t = pk_i.to_vec();
        t.extend_from_slice(tag);
        t
    }

    fn z_bound(&self) -> i128 {
        self.sigma.mask_bound - 2 * self.sigma.r_bound
    }
}

/// A linkable ring signature. `w/c/z` are indexed `[branch][round]`.
#[derive(Clone, Debug)]
pub struct LinkableRingSig {
    /// The key image — equal across a signer's signatures (the link).
    pub tag: Vec<u128>,
    w: Vec<Vec<Vec<u128>>>,
    c: Vec<Vec<i128>>,
    z: Vec<Vec<Vec<i128>>>,
}

/// Fiat-Shamir challenge: `rounds` values in `{0,1,2}` binding `μ`, the ring,
/// the tag, and every branch's `w`.
fn challenges(msg: &[u8], ring: &[Vec<u128>], tag: &[u128], w: &[Vec<Vec<u128>>], rounds: usize) -> Vec<i128> {
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/ring/v1");
    h.update((msg.len() as u64).to_le_bytes());
    h.update(msg);
    for pk in ring {
        for &x in pk {
            h.update(x.to_le_bytes());
        }
    }
    for &x in tag {
        h.update(x.to_le_bytes());
    }
    for branch in w {
        for wk in branch {
            for &x in wk {
                h.update(x.to_le_bytes());
            }
        }
    }
    let mut out = Vec::with_capacity(rounds);
    let mut ctr = 0u32;
    while out.len() < rounds {
        let mut hi = h.clone();
        hi.update(ctr.to_le_bytes());
        for byte in hi.finalize() {
            if out.len() == rounds {
                break;
            }
            out.push((byte % 3) as i128);
        }
        ctr += 1;
    }
    out
}

/// `w + c·T mod q`.
fn rhs(w: &[u128], c: i128, t: &[u128], q: u128) -> Vec<u128> {
    w.iter().zip(t).map(|(wi, ti)| (wi + signed_mod(c * *ti as i128, q)) % q).collect()
}

/// Sign `msg` as ring member `signer` (holding `sk`), over `ring` of public keys.
pub fn sign(
    rp: &RingParams,
    ring: &[Vec<u128>],
    signer: usize,
    sk: &[i128],
    msg: &[u8],
    seed: u64,
) -> Option<LinkableRingSig> {
    let n = ring.len();
    if signer >= n {
        return None;
    }
    let q = rp.sigma.q;
    let rounds = rp.sigma.rounds;
    let zb = rp.z_bound();
    let mmat = rp.stacked();
    let tag = rp.key_image(sk);
    let targets: Vec<Vec<u128>> = ring.iter().map(|pk| rp.target(pk, &tag)).collect();

    for attempt in 0..10_000u64 {
        let mut prg = SplitMix64::new(seed ^ attempt.wrapping_mul(0x51ED));

        // Simulate every FALSE branch; commit the real branch.
        let mut w: Vec<Vec<Vec<u128>>> = vec![Vec::new(); n];
        let mut c: Vec<Vec<i128>> = vec![Vec::new(); n];
        let mut z: Vec<Vec<Vec<i128>>> = vec![Vec::new(); n];
        let mut y_real: Vec<Vec<i128>> = Vec::new();

        for i in 0..n {
            if i == signer {
                // Real branch: commit w = M·y (challenge forced later).
                let mut wj = Vec::with_capacity(rounds);
                let mut yj = Vec::with_capacity(rounds);
                for _ in 0..rounds {
                    let yk: Vec<i128> = (0..rp.m).map(|_| prg.uniform_pm(rp.sigma.mask_bound)).collect();
                    wj.push(matvec(&mmat, &yk, q));
                    yj.push(yk);
                }
                w[i] = wj;
                y_real = yj;
            } else {
                // Fake branch: pick c_i, z_i; derive w_i = M·z_i − c_i·T_i.
                let ci: Vec<i128> = (0..rounds).map(|_| (prg.next_u64() % 3) as i128).collect();
                let mut wi = Vec::with_capacity(rounds);
                let mut zi = Vec::with_capacity(rounds);
                for k in 0..rounds {
                    let zk: Vec<i128> = (0..rp.m).map(|_| prg.uniform_pm(zb)).collect();
                    let mz = matvec(&mmat, &zk, q);
                    let ct = rhs(&vec![0u128; mz.len()], ci[k], &targets[i], q);
                    let wk: Vec<u128> = mz.iter().zip(&ct).map(|(a, b)| (a + q - b) % q).collect();
                    wi.push(wk);
                    zi.push(zk);
                }
                w[i] = wi;
                c[i] = ci;
                z[i] = zi;
            }
        }

        // Forced real challenge: c_signer = c_total − Σ_{i≠signer} c_i (mod 3).
        let c_total = challenges(msg, ring, &tag, &w, rounds);
        let c_signer: Vec<i128> = (0..rounds)
            .map(|k| {
                let others: i128 = (0..n).filter(|&i| i != signer).map(|i| c[i][k]).sum();
                (c_total[k] - others).rem_euclid(3)
            })
            .collect();

        // z_signer = y + c_signer·sk, bounded rejection.
        let z_signer: Vec<Vec<i128>> = (0..rounds)
            .map(|k| y_real[k].iter().zip(sk).map(|(yi, si)| yi + c_signer[k] * si).collect())
            .collect();
        if !z_signer.iter().all(|zk| inf_norm(zk) <= zb) {
            continue;
        }
        c[signer] = c_signer;
        z[signer] = z_signer;
        return Some(LinkableRingSig { tag, w, c, z });
    }
    None
}

/// Verify a linkable ring signature.
pub fn verify(rp: &RingParams, ring: &[Vec<u128>], sig: &LinkableRingSig, msg: &[u8]) -> bool {
    let n = ring.len();
    let q = rp.sigma.q;
    let rounds = rp.sigma.rounds;
    let zb = rp.z_bound();
    let mmat = rp.stacked();
    if sig.w.len() != n || sig.c.len() != n || sig.z.len() != n {
        return false;
    }
    let targets: Vec<Vec<u128>> = ring.iter().map(|pk| rp.target(pk, &sig.tag)).collect();
    let c_total = challenges(msg, ring, &sig.tag, &sig.w, rounds);

    // Challenge split: Σ_i c_i ≡ c_total (mod 3).
    for k in 0..rounds {
        let s: i128 = (0..n).map(|i| sig.c[i][k]).sum();
        if s.rem_euclid(3) != c_total[k] {
            return false;
        }
    }
    // Each branch, each round: M·z ≡ w + c·T (mod q) and ‖z‖∞ ≤ B − 2β.
    for i in 0..n {
        if sig.w[i].len() != rounds || sig.c[i].len() != rounds || sig.z[i].len() != rounds {
            return false;
        }
        for k in 0..rounds {
            if inf_norm(&sig.z[i][k]) > zb {
                return false;
            }
            if matvec(&mmat, &sig.z[i][k], q) != rhs(&sig.w[i][k], sig.c[i][k], &targets[i], q) {
                return false;
            }
        }
    }
    true
}

/// Two signatures are **linked** (same signing key ⇒ double-spend) iff their
/// key images match.
pub fn linked(a: &LinkableRingSig, b: &LinkableRingSig) -> bool {
    a.tag == b.tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> RingParams {
        RingParams::from_seed(6, 6, 16, SigmaParams::illustrative((1u128 << 61) - 1), 0x21460)
    }

    /// A ring of `n` keys; returns (params, ring pubkeys, secret keys).
    fn ring_of(rp: &RingParams, n: usize) -> (Vec<Vec<u128>>, Vec<Vec<i128>>) {
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for i in 0..n {
            let (sk, pk) = rp.keygen(1000 + i as u64);
            sks.push(sk);
            pks.push(pk);
        }
        (pks, sks)
    }

    #[test]
    fn sign_and_verify() {
        let rp = setup();
        let (ring, sks) = ring_of(&rp, 5);
        let signer = 2;
        let sig = sign(&rp, &ring, signer, &sks[signer], b"pay 10 QUIL", 1).expect("signs");
        assert!(verify(&rp, &ring, &sig, b"pay 10 QUIL"));
    }

    #[test]
    fn any_ring_member_can_sign_anonymously() {
        let rp = setup();
        let (ring, sks) = ring_of(&rp, 4);
        for signer in 0..ring.len() {
            let sig = sign(&rp, &ring, signer, &sks[signer], b"m", 2).unwrap();
            assert!(verify(&rp, &ring, &sig, b"m"), "member {signer} signs & verifies");
            // The signature carries N full branches — it does not reveal `signer`.
            assert_eq!(sig.w.len(), ring.len());
        }
    }

    #[test]
    fn same_key_links_different_keys_do_not() {
        let rp = setup();
        let (ring, sks) = ring_of(&rp, 5);
        let s1 = sign(&rp, &ring, 1, &sks[1], b"a", 3).unwrap();
        let s1b = sign(&rp, &ring, 1, &sks[1], b"b", 4).unwrap(); // same key, diff msg
        let s3 = sign(&rp, &ring, 3, &sks[3], b"a", 5).unwrap(); // different key
        assert!(linked(&s1, &s1b), "same signing key ⇒ linked (double-spend)");
        assert!(!linked(&s1, &s3), "different keys ⇒ not linked");
    }

    #[test]
    fn wrong_message_is_rejected() {
        let rp = setup();
        let (ring, sks) = ring_of(&rp, 4);
        let sig = sign(&rp, &ring, 0, &sks[0], b"original", 6).unwrap();
        assert!(!verify(&rp, &ring, &sig, b"tampered"), "message-bound signature");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let rp = setup();
        let (ring, sks) = ring_of(&rp, 4);
        let mut sig = sign(&rp, &ring, 1, &sks[1], b"m", 7).unwrap();
        sig.z[0][0][0] += 1;
        assert!(!verify(&rp, &ring, &sig, b"m"));
    }

    #[test]
    fn non_member_cannot_sign() {
        // A key outside the ring cannot produce a verifying signature for the
        // ring: its pk is not among the targets, so no branch opens honestly.
        let rp = setup();
        let (ring, _sks) = ring_of(&rp, 4);
        let (outsider_sk, _outsider_pk) = rp.keygen(9999);
        // Best-effort forge as if we were member 0.
        if let Some(sig) = sign(&rp, &ring, 0, &outsider_sk, b"m", 8) {
            assert!(!verify(&rp, &ring, &sig, b"m"), "outsider key must not verify");
        }
    }
}
