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
}
