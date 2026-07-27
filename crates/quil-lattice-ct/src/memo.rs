//! Amount memo — the encrypted `(amount, blinding)` the recipient decrypts
//! once, the post-quantum replacement for the decaf448 `CoinBalance` / `Mask`
//! fields.
//!
//! # Role and "verifiability"
//!
//! The on-chain commitment `C_v = Commit([v]; r_v)` hides the amount from
//! everyone and carries the homomorphism; it is never decrypted. The memo is
//! how the *intended recipient* learns `(v, r_v)` — it is masked with the
//! sntrup761 KEM shared secret `ss` (the same secret that derives the stealth
//! key), so only the recipient can strip it. It is decrypted **once, off the
//! homomorphic path**, so — unlike an FHE ciphertext — it never accumulates
//! noise (see the crate discussion of why LWE homomorphism needs no
//! bootstrapping).
//!
//! **Verifiable by the recipient:** after decrypting, the recipient recomputes
//! `Commit([v]; r_v)` and checks it equals `C_v` ([`verify_and_open`]). A sender
//! who ships a garbage or lying memo (any `(v', r')` with `Commit ≠ C_v`) is
//! *detected* — the coin is rejected rather than silently unspendable. This is
//! the verification the transaction flow needs. A *third-party* verifiable
//! encryption (an auditor/view-key holder proving, without `ss`, that the memo
//! encrypts the committed value) is the fuller LNP construction and is a scoped
//! extension on top of this.
//!
//! The masking is a SHA-256 keystream XOR — a stand-in for a proper AEAD keyed
//! by a KDF over `ss`. Production uses an authenticated cipher; the *structure*
//! (KEM secret → keystream → mask amount+blinding → recipient re-derives and
//! checks the commitment) is the real thing.

use sha2::{Digest, Sha256};

use crate::commitment::{CommitKey, Commitment};

/// The masked `(amount, blinding)` carried alongside a coin output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmountMemo {
    /// Masked amount (16 bytes = one `u128`).
    pub enc_v: Vec<u8>,
    /// Masked blinding (`m` × 16 bytes = `m` `i128`s).
    pub enc_r: Vec<u8>,
}

/// Keystream of `len` bytes from `ss`, domain-separated by `label`.
/// Public so the ring-coin memo (which masks a `PolyVec` blinding rather than
/// the scalar `&[i128]` of [`encrypt_memo`]) can reuse the same construction.
pub fn keystream(ss: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut ctr = 0u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"quil-lattice-ct/memo/v1");
        h.update(label);
        h.update(ss);
        h.update(ctr.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    out.truncate(len);
    out
}

/// XOR `bytes` against keystream `ks` (public for the ring-coin memo).
pub fn xor(bytes: &[u8], ks: &[u8]) -> Vec<u8> {
    bytes.iter().zip(ks).map(|(b, k)| b ^ k).collect()
}

/// Sender: mask `(v, r_v)` with the shared secret `ss`.
pub fn encrypt_memo(ss: &[u8], v: u128, r_v: &[i128]) -> AmountMemo {
    let mut v_bytes = v.to_le_bytes().to_vec();
    let mut r_bytes = Vec::with_capacity(r_v.len() * 16);
    for x in r_v {
        r_bytes.extend_from_slice(&x.to_le_bytes());
    }
    let ks_v = keystream(ss, b"amount", v_bytes.len());
    let ks_r = keystream(ss, b"blinding", r_bytes.len());
    v_bytes = xor(&v_bytes, &ks_v);
    r_bytes = xor(&r_bytes, &ks_r);
    AmountMemo { enc_v: v_bytes, enc_r: r_bytes }
}

/// Recipient: strip the mask to recover `(v, r_v)`. Returns `None` on a
/// malformed memo (wrong lengths).
pub fn decrypt_memo(ss: &[u8], memo: &AmountMemo) -> Option<(u128, Vec<i128>)> {
    if memo.enc_v.len() != 16 || memo.enc_r.len() % 16 != 0 {
        return None;
    }
    let ks_v = keystream(ss, b"amount", memo.enc_v.len());
    let ks_r = keystream(ss, b"blinding", memo.enc_r.len());
    let v = u128::from_le_bytes(xor(&memo.enc_v, &ks_v).try_into().ok()?);
    let r_bytes = xor(&memo.enc_r, &ks_r);
    let r = r_bytes
        .chunks_exact(16)
        .map(|c| i128::from_le_bytes(c.try_into().unwrap()))
        .collect();
    Some((v, r))
}

/// Recipient's full validation: decrypt the memo and confirm it opens the
/// on-chain commitment (`Commit([v]; r_v) == C_v`). Returns the recovered
/// `(v, r_v)` iff valid — a lying/garbled memo, or the wrong `ss`, yields
/// `None`, and the coin is rejected.
pub fn verify_and_open(
    key: &CommitKey,
    c_v: &Commitment,
    ss: &[u8],
    memo: &AmountMemo,
) -> Option<(u128, Vec<i128>)> {
    let (v, r) = decrypt_memo(ss, memo)?;
    if r.len() != key.params.m {
        return None;
    }
    if &key.commit(&[v], &r) == c_v {
        Some((v, r))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::SplitMix64;
    use crate::commitment::{CommitKey, CommitParams};

    fn key() -> CommitKey {
        CommitKey::from_seed(CommitParams::illustrative_scalar(), 0x1E70)
    }
    fn ternary(m: usize, tag: u64) -> Vec<i128> {
        let mut prg = SplitMix64::new(tag);
        (0..m).map(|_| (prg.next_u64() % 3) as i128 - 1).collect()
    }

    #[test]
    fn memo_round_trip() {
        let ss = b"kem-shared-secret";
        let r = ternary(16, 1);
        let memo = encrypt_memo(ss, 123_456, &r);
        let (v2, r2) = decrypt_memo(ss, &memo).unwrap();
        assert_eq!(v2, 123_456);
        assert_eq!(r2, r);
    }

    #[test]
    fn recipient_verifies_memo_against_commitment() {
        let k = key();
        let ss = b"ss";
        let v = 42u128;
        let r = ternary(k.params.m, 2);
        let c = k.commit(&[v], &r);
        let memo = encrypt_memo(ss, v, &r);
        let opened = verify_and_open(&k, &c, ss, &memo).expect("valid memo opens");
        assert_eq!(opened, (v, r));
    }

    #[test]
    fn lying_memo_is_detected() {
        // A memo that decrypts to a value inconsistent with the commitment is
        // rejected — the sender cannot grief the recipient with a bad coin.
        let k = key();
        let ss = b"ss";
        let v = 42u128;
        let r = ternary(k.params.m, 3);
        let c = k.commit(&[v], &r);
        // Encrypt a DIFFERENT amount than the one committed.
        let bad = encrypt_memo(ss, 99, &r);
        assert!(verify_and_open(&k, &c, ss, &bad).is_none(), "inconsistent memo rejected");
    }

    #[test]
    fn wrong_shared_secret_cannot_open() {
        let k = key();
        let v = 7u128;
        let r = ternary(k.params.m, 4);
        let c = k.commit(&[v], &r);
        let memo = encrypt_memo(b"the-right-secret", v, &r);
        assert!(
            verify_and_open(&k, &c, b"the-wrong-secret", &memo).is_none(),
            "a party without the shared secret can't open the coin"
        );
    }
}
