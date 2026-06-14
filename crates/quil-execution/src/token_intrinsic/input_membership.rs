//! Per-input membership binding for token `Transaction` inputs — the
//! Rust port of Go `(*TransactionInput).verifyProof` plus the
//! data/indices/keys layout built in `(*TransactionInput).Verify`
//! (`token_intrinsic_transaction.go:488-762`).
//!
//! WHY THIS EXISTS: the tx-level traversal proof
//! (`verify_traversal_proof`) only proves "these leaves exist under the
//! shard root" — it never ties the proven leaf to *this input's* coin
//! data. Without the binding here, an attacker can fabricate an input
//! (the hidden-Schnorr check passes by construction) and attach any
//! valid traversal proof for any real leaf, minting from nothing. Go
//! closes this by proving, per input, that the leaf at the input's
//! subproof opens — at the input's field positions — to
//! `sha512(0x00 || key || data)` of the input's own commitment, key
//! image, coin/pending type marker, etc.
//!
//! Two layouts, selected exactly as Go does (by `Acceptable` behavior +
//! proof length):
//!   * coin-spend branch — non-`Acceptable` tokens.
//!   * pending-claim branch — `Acceptable` tokens (this is the LIVE
//!     QUIL path: QUIL is Mintable|Burnable|Divisible|Acceptable|
//!     Expirable|Tenderable).
//!
//! The `sha512(0x00 || key || data)` evaluation construction is
//! validated byte-for-byte against vectors dumped from the real Go
//! `verifyProof` (see the test at the bottom).

use sha2::{Digest, Sha512};

use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};

use super::constants::{ACCEPTABLE, DIVISIBLE, EXPIRABLE};
use super::materialize::{coin_type_hash, pending_type_hash};
use super::TransactionInput;
use crate::traversal_proof::TraversalSubProof;

const META_KEY: [u8; 32] = [0xFF; 32];

/// The data/indices the input must open to, plus (for the pending-claim
/// branch) the pending spent-marker key the caller must check absent.
struct Layout {
    /// Ordered field values to prove (matches Go `data`).
    data: Vec<Vec<u8>>,
    /// Vector-commitment positions for each field (matches Go `indices`).
    indices: Vec<u64>,
    /// Pending-claim branch: `poseidon(proofs[offset+2])`. The caller
    /// must reject the input if a vertex exists at `domain || this`
    /// (Go `token_intrinsic_transaction.go:644-649`). `None` for the
    /// coin branch.
    alt_spent_key: Option<[u8; 32]>,
}

fn sig_slice(sig: &[u8], a: usize, b: usize) -> Result<&[u8]> {
    sig.get(a..b).ok_or_else(|| {
        QuilError::InvalidArgument("input membership: signature too short".into())
    })
}

fn proof_at<'a>(proofs: &'a [Vec<u8>], i: usize) -> Result<&'a [u8]> {
    proofs
        .get(i)
        .map(|p| p.as_slice())
        .ok_or_else(|| QuilError::InvalidArgument(format!(
            "input membership: missing proof element {}", i
        )))
}

/// Build the membership layout for one input, mirroring Go
/// `(*TransactionInput).Verify` (lines 535-699). `behavior` is the
/// token's behavior flags, `frame_number` the current frame.
fn build_layout(
    input: &TransactionInput,
    domain: &[u8],
    behavior: u16,
    frame_number: u64,
) -> Result<Layout> {
    let sig = &input.signature;
    if sig.len() != 336 {
        return Err(QuilError::InvalidArgument(
            "input membership: signature must be 336 bytes".into(),
        ));
    }
    // sig[56*5..56*6] = commitment, sig[56*4..56*5] = key image.
    let commitment = sig_slice(sig, 56 * 5, 56 * 6)?.to_vec();
    let key_image = sig_slice(sig, 56 * 4, 56 * 5)?.to_vec();

    let divisible = behavior & DIVISIBLE != 0;
    let acceptable = behavior & ACCEPTABLE != 0;
    let expirable = behavior & EXPIRABLE != 0;

    // addRefDelta: non-divisible tokens carry an extra addref proof
    // element (Go lines 535-544).
    let add_ref_delta = if !divisible {
        let last = input.proofs.last().ok_or_else(|| {
            QuilError::InvalidArgument("input membership: no proofs".into())
        })?;
        if last.len() != 64 + 56 {
            return Err(QuilError::InvalidArgument(
                "input membership: bad addref proof length".into(),
            ));
        }
        1usize
    } else {
        0usize
    };

    if input.proofs.len() == 1 + add_ref_delta {
        // ---- COIN-SPEND branch (Go lines 546-587) ----
        if acceptable {
            return Err(QuilError::InvalidArgument(
                "input membership: coin-length proof on an Acceptable token".into(),
            ));
        }
        let mut data = vec![commitment, key_image];
        let mut indices: Vec<u64> = vec![1, 3];
        if !divisible {
            let p1 = proof_at(&input.proofs, 1)?;
            data.push(p1.get(..64).ok_or_else(|| QuilError::InvalidArgument(
                "input membership: addref proof < 64 bytes".into()))?.to_vec());
            data.push(p1.get(64..).unwrap().to_vec());
            indices.push(6);
            indices.push(7);
        }
        indices.push(63);
        data.push(coin_type_hash(domain)?.to_vec());
        Ok(Layout { data, indices, alt_spent_key: None })
    } else {
        // ---- PENDING-CLAIM branch (Go lines 588-698) ----
        if !acceptable {
            return Err(QuilError::InvalidArgument(
                "input membership: pending-length proof on a non-Acceptable token".into(),
            ));
        }
        let mut indices: Vec<u64> = vec![1, 4, 5];
        let mut data: Vec<Vec<u8>> = vec![commitment];

        let mut offset = 0usize;
        let mut expiration: u64 = 0;
        if expirable {
            offset = 1;
            let mut proof_index: u64 = 10;
            if input.proofs.len() != 4 + add_ref_delta {
                return Err(QuilError::InvalidArgument(
                    "input membership: bad pending(expirable) proof length".into(),
                ));
            }
            if !divisible {
                indices.extend_from_slice(&[10, 11, 12, 13]);
                proof_index = 14;
            }
            let exp_bytes = proof_at(&input.proofs, 1)?;
            let exp_arr: [u8; 8] = exp_bytes.try_into().map_err(|_| {
                QuilError::InvalidArgument("input membership: expiration not 8 bytes".into())
            })?;
            expiration = u64::from_be_bytes(exp_arr);
            indices.push(proof_index);
        } else if input.proofs.len() != 3 + add_ref_delta {
            return Err(QuilError::InvalidArgument(
                "input membership: bad pending proof length".into(),
            ));
        }

        // alt spend-check key: poseidon(proofs[offset+2]).
        let alt_ref = proof_at(&input.proofs, offset + 2)?;
        let alt_spent_key = quil_crypto::poseidon::hash_bytes_to_32(alt_ref)?;

        // isTo = proofs[offset+1] == [0x02].
        let is_to = proof_at(&input.proofs, offset + 1)? == [0x02u8];
        if is_to {
            data.push(key_image.clone());
            data.push(alt_ref.to_vec());
        } else {
            if frame_number < expiration {
                return Err(QuilError::InvalidArgument(
                    "input membership: refund claim before expiration".into(),
                ));
            }
            data.push(alt_ref.to_vec());
            data.push(key_image.clone());
        }

        if !divisible {
            let p = proof_at(&input.proofs, offset + 3)?;
            let lo = p.get(..64).ok_or_else(|| QuilError::InvalidArgument(
                "input membership: pending addref < 64 bytes".into()))?.to_vec();
            let hi = p.get(64..).unwrap().to_vec();
            data.push(lo.clone());
            data.push(hi.clone());
            data.push(lo);
            data.push(hi);
        }
        if expirable {
            data.push(proof_at(&input.proofs, 1)?.to_vec());
        }
        data.push(pending_type_hash(domain)?.to_vec());
        indices.push(63);

        // Guard the invariant Go relies on implicitly: one position per
        // field. A mismatch means a layout bug, not attacker input.
        if data.len() != indices.len() {
            return Err(QuilError::Internal(format!(
                "input membership: layout mismatch data={} indices={}",
                data.len(), indices.len()
            )));
        }
        Ok(Layout { data, indices, alt_spent_key: Some(alt_spent_key) })
    }
}

/// Compute `sha512(0x00 || key || data)` exactly as Go `verifyProof`.
/// The non-final fields use `[(index << 2) as u8]` as the key; the final
/// field uses the 0xFF*32 metadata key.
fn evaluation(index: u64, data: &[u8], is_last: bool) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update([0u8]);
    if is_last {
        h.update(META_KEY);
    } else {
        h.update([(index as u8) << 2]);
    }
    h.update(data);
    h.finalize().to_vec()
}

/// Parse a Go-serialized inner multiproof (`u32 d_len, [multicommitment],
/// u32 proof_len, [proof]`) out of an input's `proofs[0]`.
fn parse_inner_multiproof(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut c = 0usize;
    let read_u32 = |data: &[u8], c: &mut usize| -> Result<u32> {
        let b = data.get(*c..*c + 4).ok_or_else(|| {
            QuilError::InvalidArgument("input membership: EOF in multiproof".into())
        })?;
        *c += 4;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    };
    let d_len = read_u32(bytes, &mut c)? as usize;
    let multicommitment = bytes.get(c..c + d_len).ok_or_else(|| {
        QuilError::InvalidArgument("input membership: EOF in multicommitment".into())
    })?.to_vec();
    c += d_len;
    let proof_len = read_u32(bytes, &mut c)? as usize;
    let proof = bytes.get(c..c + proof_len).ok_or_else(|| {
        QuilError::InvalidArgument("input membership: EOF in proof".into())
    })?.to_vec();
    Ok((multicommitment, proof))
}

/// Verify that `input` is bound to its traversal subproof leaf — i.e.
/// the on-chain coin/pending leaf at `sub_proof` opens, at the input's
/// field positions, to this input's actual data. Returns the
/// pending-claim spent-marker key the caller must additionally check
/// absent (`None` for the coin branch).
///
/// Port of Go `(*TransactionInput).verifyProof` + the layout from
/// `Verify`. `sub_proof` is the tx-level traversal proof's subproof for
/// this input's index; its last `ys` entry is the leaf commitment.
pub fn verify_input_membership(
    input: &TransactionInput,
    domain: &[u8],
    behavior: u16,
    frame_number: u64,
    sub_proof: &TraversalSubProof,
    inclusion_prover: &dyn InclusionProver,
) -> Result<Option<[u8; 32]>> {
    let layout = build_layout(input, domain, behavior, frame_number)?;

    let leaf = sub_proof.ys.last().ok_or_else(|| {
        QuilError::InvalidArgument("input membership: subproof has no leaf commitment".into())
    })?;

    let n = layout.data.len();
    let evals: Vec<Vec<u8>> = layout
        .data
        .iter()
        .enumerate()
        .map(|(i, d)| evaluation(layout.indices[i], d, i == n - 1))
        .collect();

    let (multicommitment, proof) = parse_inner_multiproof(proof_at(&input.proofs, 0)?)?;

    // Every position opens against the same leaf commitment (Go repeats
    // `SubProofs[index].Ys[last]` for each field).
    let commit_refs: Vec<&[u8]> = std::iter::repeat(leaf.as_slice()).take(n).collect();
    let eval_refs: Vec<&[u8]> = evals.iter().map(|e| e.as_slice()).collect();

    let ok = inclusion_prover.verify_multiple(
        &commit_refs,
        &eval_refs,
        &layout.indices,
        64,
        &multicommitment,
        &proof,
    );
    if !ok {
        return Err(QuilError::InvalidArgument(
            "input membership: leaf does not open to this input's data \
             (input not bound to traversal proof)".into(),
        ));
    }

    Ok(layout.alt_spent_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth vectors dumped from the real Go `verifyProof`
    // (TestValidTransactionWithMocks, coin branch). These pin the
    // sha512(0x00 || key || data) evaluation construction byte-for-byte.
    // data[0]: idx=1, key=index-byte, data="valid-commitment"+zeros (56B)
    // data[1]: idx=3, key=index-byte, same data
    // data[2]: idx=63, key=0xFF*32,   data=coin-type hash (32B)
    fn commitment_data() -> Vec<u8> {
        let mut v = b"valid-commitment".to_vec();
        v.resize(56, 0);
        v
    }

    #[test]
    fn evaluation_matches_go_idx1() {
        let eval = evaluation(1, &commitment_data(), false);
        assert_eq!(
            hex::encode(eval),
            "a97a40b1f10357e1f24e5ce8fbdc41d0506b6326582eaa9ccf8ccf76f65c69a8\
             0d2a737dbdbacf0cf39ca2d3cbfb84e4551e8c4c07e4a8cf8ce8982d3cd05e8e"
        );
    }

    #[test]
    fn evaluation_matches_go_idx3() {
        let eval = evaluation(3, &commitment_data(), false);
        assert_eq!(
            hex::encode(eval),
            "1cef46f4db2fdedb31d854cef6f5ff04c8f8a08a9fbd0f4a99871fc2c13195fa\
             25857879704d8473811b27f661da858ebfe9078af070b14dcff4e3c3a7f9e000"
        );
    }

    #[test]
    fn evaluation_matches_go_idx63_meta_key() {
        let coin_type =
            hex::decode("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
                .unwrap();
        let eval = evaluation(63, &coin_type, true);
        assert_eq!(
            hex::encode(eval),
            "73d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd\
             961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94"
        );
    }

    #[test]
    fn inner_multiproof_roundtrip() {
        // u32 d_len=3, [aa bb cc], u32 proof_len=2, [dd ee]
        let bytes = [
            0, 0, 0, 3, 0xaa, 0xbb, 0xcc, 0, 0, 0, 2, 0xdd, 0xee,
        ];
        let (mc, pr) = parse_inner_multiproof(&bytes).unwrap();
        assert_eq!(mc, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(pr, vec![0xdd, 0xee]);
    }

    #[test]
    fn inner_multiproof_rejects_truncated_multicommitment() {
        // d_len=10 but only 2 bytes follow.
        let bytes = [0, 0, 0, 10, 0xaa, 0xbb];
        assert!(parse_inner_multiproof(&bytes).is_err());
    }

    #[test]
    fn inner_multiproof_rejects_eof_before_length() {
        let bytes = [0, 0, 0]; // < 4 bytes for first u32
        assert!(parse_inner_multiproof(&bytes).is_err());
    }

    #[test]
    fn evaluation_last_uses_meta_key_not_index() {
        // For the same data, the last-field eval (0xFF*32 key) must
        // differ from the non-last eval (index-byte key).
        let data = vec![0x09u8; 32];
        let last = evaluation(63, &data, true);
        let not_last = evaluation(63, &data, false);
        assert_ne!(last, not_last);
        assert_eq!(last.len(), 64);
    }

    // ---- build_layout / verify_input_membership ----

    use crate::traversal_proof::TraversalSubProof;
    use quil_types::crypto::{Multiproof, NoopInclusionProver};

    const DOMAIN: [u8; 32] = [0x77u8; 32];

    /// Build a minimal inner multiproof blob (`u32 d_len, mc, u32
    /// proof_len, proof`) for `proofs[0]`.
    fn inner_multiproof_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&3u32.to_be_bytes());
        v.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&[0xdd, 0xee]);
        v
    }

    /// Inclusion prover that returns a fixed `verify_multiple` result so
    /// we can drive the bound/not-bound branches of
    /// `verify_input_membership`.
    struct FixedVerify(bool);
    impl InclusionProver for FixedVerify {
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("n/a".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool {
            self.0
        }
    }

    fn sub_proof_with_leaf() -> TraversalSubProof {
        TraversalSubProof {
            commits: vec![],
            ys: vec![vec![0x11u8; 64], vec![0x22u8; 64]],
            paths: vec![],
        }
    }

    /// A divisible-coin input: proofs.len()==1, non-Acceptable token.
    fn coin_input() -> TransactionInput {
        TransactionInput {
            commitment: vec![0x01u8; 56],
            signature: vec![0x02u8; 336],
            proofs: vec![inner_multiproof_bytes()],
        }
    }

    #[test]
    fn build_layout_coin_branch_divisible() {
        // Divisible, non-Acceptable token → coin branch with indices [1,3,63].
        let behavior = DIVISIBLE; // not Acceptable
        let layout = build_layout(&coin_input(), &DOMAIN, behavior, 0).unwrap();
        assert_eq!(layout.indices, vec![1, 3, 63]);
        assert_eq!(layout.data.len(), 3);
        assert!(layout.alt_spent_key.is_none());
        // data[0] = commitment = signature[56*5..56*6]
        assert_eq!(layout.data[0], vec![0x02u8; 56]);
        // data[2] = coin_type_hash(domain)
        assert_eq!(layout.data[2], coin_type_hash(&DOMAIN).unwrap().to_vec());
    }

    #[test]
    fn build_layout_rejects_short_signature() {
        let mut input = coin_input();
        input.signature = vec![0u8; 100]; // != 336
        assert!(build_layout(&input, &DOMAIN, DIVISIBLE, 0).is_err());
    }

    #[test]
    fn build_layout_coin_on_acceptable_token_is_rejected() {
        // Coin-length proof (len 1) but token is Acceptable → error.
        let behavior = DIVISIBLE | ACCEPTABLE;
        let err = build_layout(&coin_input(), &DOMAIN, behavior, 0);
        assert!(err.is_err());
    }

    #[test]
    fn build_layout_pending_to_branch() {
        // Acceptable + divisible, non-expirable → 3 proofs.
        // offset=0. proofs[1]==[0x02] → isTo branch.
        let behavior = DIVISIBLE | ACCEPTABLE;
        let input = TransactionInput {
            commitment: vec![0x01u8; 56],
            signature: vec![0x02u8; 336],
            proofs: vec![
                inner_multiproof_bytes(),
                vec![0x02u8],              // proofs[offset+1] == [0x02] → isTo
                vec![0x33u8; 16],          // proofs[offset+2] = alt_ref
            ],
        };
        let layout = build_layout(&input, &DOMAIN, behavior, 0).unwrap();
        assert!(layout.alt_spent_key.is_some());
        // indices: [1,4,5,63]
        assert_eq!(layout.indices, vec![1, 4, 5, 63]);
        // alt_spent_key == poseidon(alt_ref)
        let expected = quil_crypto::poseidon::hash_bytes_to_32(&vec![0x33u8; 16]).unwrap();
        assert_eq!(layout.alt_spent_key.unwrap(), expected);
    }

    #[test]
    fn build_layout_pending_refund_before_expiration_is_rejected() {
        // Expirable + divisible, refund branch (proofs[offset+1] != [0x02]),
        // frame_number < expiration → reject.
        let behavior = DIVISIBLE | ACCEPTABLE | EXPIRABLE;
        let expiration = 100u64;
        let input = TransactionInput {
            commitment: vec![0x01u8; 56],
            signature: vec![0x02u8; 336],
            proofs: vec![
                inner_multiproof_bytes(),
                expiration.to_be_bytes().to_vec(), // proofs[1] = expiration (8 bytes)
                vec![0x01u8],                       // proofs[offset+1] != [0x02] → refund
                vec![0x33u8; 16],                   // proofs[offset+2] = alt_ref
            ],
        };
        // frame_number 50 < expiration 100 → reject.
        assert!(build_layout(&input, &DOMAIN, behavior, 50).is_err());
        // frame_number 100 >= expiration 100 → ok.
        assert!(build_layout(&input, &DOMAIN, behavior, 100).is_ok());
    }

    #[test]
    fn build_layout_pending_on_non_acceptable_token_is_rejected() {
        // Pending-length proof (3 elems) but token not Acceptable → error.
        let behavior = DIVISIBLE; // not Acceptable
        let input = TransactionInput {
            commitment: vec![0x01u8; 56],
            signature: vec![0x02u8; 336],
            proofs: vec![
                inner_multiproof_bytes(),
                vec![0x02u8],
                vec![0x33u8; 16],
            ],
        };
        assert!(build_layout(&input, &DOMAIN, behavior, 0).is_err());
    }

    #[test]
    fn verify_input_membership_ok_when_prover_accepts() {
        let behavior = DIVISIBLE; // coin branch
        let input = coin_input();
        let sub = sub_proof_with_leaf();
        let alt = verify_input_membership(
            &input, &DOMAIN, behavior, 0, &sub, &FixedVerify(true),
        )
        .unwrap();
        // Coin branch → no alt spent key.
        assert!(alt.is_none());
    }

    #[test]
    fn verify_input_membership_err_when_prover_rejects() {
        let behavior = DIVISIBLE;
        let input = coin_input();
        let sub = sub_proof_with_leaf();
        let err = verify_input_membership(
            &input, &DOMAIN, behavior, 0, &sub, &FixedVerify(false),
        );
        assert!(err.is_err(), "rejecting prover → input not bound");
    }

    #[test]
    fn verify_input_membership_err_when_subproof_has_no_leaf() {
        let behavior = DIVISIBLE;
        let input = coin_input();
        let empty_sub = TraversalSubProof { commits: vec![], ys: vec![], paths: vec![] };
        let err = verify_input_membership(
            &input, &DOMAIN, behavior, 0, &empty_sub, &NoopInclusionProver,
        );
        assert!(err.is_err());
    }
}
