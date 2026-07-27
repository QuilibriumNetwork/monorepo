//! Stealth addresses — recipient one-time keys, the post-quantum replacement
//! for the decaf448 DH-derived stealth address (`OneTimeKey`).
//!
//! # Where the shared secret comes from
//!
//! The decaf448 scheme derives a shared secret by ECDH between the sender's tx
//! key and the recipient's view key. The PQ version replaces that DH with the
//! **sntrup761 KEM** (the one the transport already uses): the sender
//! `encapsulate`s against the recipient's KEM public key, publishes the
//! ciphertext with the output, and the recipient `decapsulate`s to recover the
//! same shared secret `ss`. This module is the *derivation on top of `ss`* — it
//! is KEM-agnostic and takes `ss: &[u8]`.
//!
//! # Construction (lattice)
//!
//! A recipient publishes an address `(kem_pk, B)` where `B = A·b` is a spend
//! public key (short secret `b`) under the same matrix `A` the ring signature
//! uses. For an output:
//!
//! * **Sender** derives a short `offset = H(ss)` and the one-time public key
//! `P = A·offset + B (mod q)`, publishing `(ciphertext, P)`.
//! * **Recipient** recovers `ss`, recomputes `offset`, and checks
//! `P == A·offset + B`; if so the output is theirs and the one-time spend
//! secret is `sk' = offset + b` (short: `‖sk'‖ ≤ ‖offset‖ + ‖b‖`).
//!
//! Because `P = A·sk'`, the one-time key is a valid [`crate::ring`] public key,
//! so a received coin is spent directly by the linkable ring signature — no
//! separate machinery. `ss` also masks the amount memo (see verifiable
//! encryption, step 6).

use sha2::{Digest, Sha256};

use crate::arith::matvec;

/// Deterministically map a shared secret to a SHORT ternary offset vector of
/// length `m`. Both parties derive the same `offset` from the same `ss`.
pub fn hash_to_short(ss: &[u8], m: usize) -> Vec<i128> {
    let mut out = Vec::with_capacity(m);
    let mut ctr = 0u32;
    while out.len() < m {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/stealth/offset/v1");
        h.update(ss);
        h.update(ctr.to_le_bytes());
        for byte in h.finalize() {
            if out.len() == m {
                break;
            }
            out.push((byte % 3) as i128 - 1); // {-1,0,1}
        }
        ctr += 1;
    }
    out
}

/// Sender: the one-time public key `P = A·offset + B (mod q)`.
pub fn one_time_pubkey(a: &[Vec<u128>], offset: &[i128], b_pub: &[u128], q: u128) -> Vec<u128> {
    let ao = matvec(a, offset, q);
    ao.iter().zip(b_pub).map(|(x, y)| (x + y) % q).collect()
}

/// Recipient: does this output belong to me? `P == A·offset + B`.
pub fn owns(a: &[Vec<u128>], offset: &[i128], b_pub: &[u128], p: &[u128], q: u128) -> bool {
    &one_time_pubkey(a, offset, b_pub, q) == p
}

/// Recipient: the one-time spend secret `sk' = offset + b`.
pub fn one_time_secret(offset: &[i128], b_sec: &[i128]) -> Vec<i128> {
    offset.iter().zip(b_sec).map(|(o, b)| o + b).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Ring-form stealth (matches the coin's `membership` one-time key `P = A·sk`).
//
// The functions above operate in the SCALAR `ring`/`matvec` cryptosystem. A
// lattice COIN's one-time key is `P = a_otk·sk` in the RING form
// (`PolyMatrix`/`PolyVec`, `membership::MembershipParams::a_otk`) — a different
// representation, exactly as the ring memo differs from the scalar memo. These
// ring-form variants derive the stealth key in that representation so a received
// coin's `sk` opens its accumulator leaf directly.
// ─────────────────────────────────────────────────────────────────────────────

use crate::module::{PolyMatrix, PolyVec};
use crate::rq::Poly;

/// Deterministic short (ternary) `PolyVec` offset of `len` polynomials from the
/// shared secret — the ring-form analogue of [`hash_to_short`].
pub fn hash_to_short_polyvec(ss: &[u8], len: usize) -> PolyVec {
    let need = len * Poly::D;
    let mut buf: Vec<u8> = Vec::with_capacity(need + 32);
    let mut ctr = 0u32;
    while buf.len() < need {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/stealth-ring/offset/v1");
        h.update(ss);
        h.update(ctr.to_le_bytes());
        buf.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    let mut idx = 0usize;
    let polys = (0..len)
        .map(|_| {
            let coeffs: Vec<i64> = (0..Poly::D)
                .map(|_| {
                    let v = (buf[idx] % 3) as i64 - 1; // {-1,0,1}
                    idx += 1;
                    v
                })
                .collect();
            Poly::from_signed(&coeffs)
        })
        .collect();
    PolyVec(polys)
}

/// Sender: one-time public key `P = A·offset + B` (ring form).
pub fn one_time_pubkey_ring(a_otk: &PolyMatrix, offset: &PolyVec, b_pub: &PolyVec) -> PolyVec {
    a_otk.matvec(offset).add(b_pub)
}

/// Recipient: does this coin belong to me? `P == A·offset + B`.
pub fn owns_ring(a_otk: &PolyMatrix, offset: &PolyVec, b_pub: &PolyVec, p: &PolyVec) -> bool {
    &one_time_pubkey_ring(a_otk, offset, b_pub) == p
}

/// Recipient: the one-time spend secret `sk' = offset + b`. Because `A` is
/// linear, `A·sk' = A·offset + A·b = A·offset + B = P`, so `sk'` opens the
/// coin's accumulator leaf directly.
pub fn one_time_secret_ring(offset: &PolyVec, b_sec: &PolyVec) -> PolyVec {
    offset.add(b_sec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::{sign, verify, RingParams};
    use crate::sigma::SigmaParams;

    #[test]
    fn ring_stealth_derives_membership_one_time_key() {
        use crate::arith::SplitMix64;
        use crate::membership::MembershipParams;
        use crate::module::{PolyVec, ETA};

        let mp = MembershipParams::production(1); // a_otk is depth-independent
        let a = &mp.a_otk;
        let cols = a.cols;
        let mut prg = SplitMix64::new(0x5EED);

        // Wallet long-term spend base (b, B = A·b).
        let b = PolyVec::sample_short(cols, ETA, &mut prg);
        let big_b = a.matvec(&b);

        // Sender: derive the one-time key for this recipient.
        let ss = [0x11u8; 32];
        let offset = hash_to_short_polyvec(&ss, cols);
        let p = one_time_pubkey_ring(a, &offset, &big_b);

        // Recipient: recognizes the coin, recovers sk, and `A·sk == P` (so sk
        // opens the coin's accumulator leaf directly).
        assert!(owns_ring(a, &offset, &big_b, &p));
        let sk = one_time_secret_ring(&offset, &b);
        assert_eq!(a.matvec(&sk), p, "P must equal A·sk (the membership OTK)");

        // A different shared secret ⇒ not the recipient's coin.
        let offset2 = hash_to_short_polyvec(&[0u8; 32], cols);
        assert!(!owns_ring(a, &offset2, &big_b, &p));
    }

    /// Ring params with `r_bound = 2` so a stealth secret `sk' = offset + b`
    /// (each ternary → norm ≤ 2) is a valid spend key.
    fn ring() -> RingParams {
        let sigma = SigmaParams { q: (1u128 << 61) - 1, rounds: 16, mask_bound: 1 << 16, r_bound: 2 };
        RingParams::from_seed(6, 6, 16, sigma, 0x57EA1)
    }

    #[test]
    fn sender_recipient_round_trip() {
        let rp = ring();
        let a = rp.key_matrix();
        let q = rp.modulus();
        let m = rp.width();
        // Recipient spend key (b_sec, B = A·b_sec).
        let (b_sec, b_pub) = rp.keygen(1);
        // A shared secret both parties hold (from the sntrup761 KEM).
        let ss = b"sntrup761-shared-secret-bytes";

        // Sender side.
        let offset = hash_to_short(ss, m);
        let p = one_time_pubkey(a, &offset, &b_pub, q);

        // Recipient side: recomputes offset from the SAME ss, recognizes P.
        let offset_r = hash_to_short(ss, m);
        assert!(owns(a, &offset_r, &b_pub, &p, q), "recipient recognizes its output");
        let sk_prime = one_time_secret(&offset_r, &b_sec);
        // sk' actually opens P: A·sk' == P.
        assert_eq!(rp.public_key(&sk_prime), p, "one-time secret opens the one-time key");
    }

    #[test]
    fn a_different_recipient_does_not_own_it() {
        let rp = ring();
        let (a, q, m) = (rp.key_matrix(), rp.modulus(), rp.width());
        let (_b1, b_pub1) = rp.keygen(1);
        let (_b2, b_pub2) = rp.keygen(2); // a different recipient
        let ss = b"secret";
        let offset = hash_to_short(ss, m);
        let p = one_time_pubkey(a, &offset, &b_pub1, q); // sent to recipient 1
        assert!(owns(a, &offset, &b_pub1, &p, q));
        assert!(!owns(a, &offset, &b_pub2, &p, q), "recipient 2 must not own it");
    }

    #[test]
    fn stealth_key_is_spendable_by_the_ring_signature() {
        // End-to-end: the one-time key P becomes a ring member and the
        // recipient spends it with sk' = offset + b. This is the whole point —
        // no separate spend machinery for stealth outputs.
        let rp = ring();
        let (a, q, m) = (rp.key_matrix(), rp.modulus(), rp.width());
        let (b_sec, b_pub) = rp.keygen(10);
        let ss = b"kem-ss";
        let offset = hash_to_short(ss, m);
        let p = one_time_pubkey(a, &offset, &b_pub, q);
        let sk_prime = one_time_secret(&offset, &b_sec);

        // Build a ring containing P (plus decoys), sign as P's index, verify.
        let mut decoys = Vec::new();
        for i in 0..4 {
            let (_s, pk) = rp.keygen(100 + i);
            decoys.push(pk);
        }
        let signer_idx = 2;
        let mut ring_keys = decoys;
        ring_keys.insert(signer_idx, p.clone());

        let sig = sign(&rp, &ring_keys, signer_idx, &sk_prime, b"spend stealth output", 7)
            .expect("recipient signs with the one-time secret");
        assert!(verify(&rp, &ring_keys, &sig, b"spend stealth output"));
        assert_eq!(sig.tag, rp.key_image(&sk_prime), "key image is the one-time key's nullifier");
    }
}
