//! Iden3-compatible Poseidon hash over the BN254 scalar field.
//!
//! This module wraps the `poseidon-rs` + `ff_ce` crates with the same
//! sponge construction as the Iden3 Go library, producing byte-identical
//! output. Test vectors assert determinism against known outputs.
//!
//! Two entry points:
//!
//! - `hash_bytes_to_32(msg)` → 32-byte big-endian hash. Mirrors
//!   `poseidon.HashBytes(msg).FillBytes(make([]byte, 32))` from
//!   `node/execution/intrinsics/global/...` usages.
//! - `hash_elements(inputs)` → one 32-byte hash from at most 16
//!   field elements. Direct wrapper around `Poseidon::hash`.
//!
//! The sponge parameters match iden3 exactly:
//! - `SPONGE_CHUNK_SIZE = 31` — bytes per field element
//! - `FRAME_SIZE = 16` — Poseidon state width (minus the capacity)

use ff_ce::PrimeField;
use num_bigint::BigUint;
use poseidon_rs::{Fr, Poseidon};

use quil_types::error::{QuilError, Result};

const SPONGE_CHUNK_SIZE: usize = 31;
const FRAME_SIZE: usize = 16;

/// Hash an arbitrary byte slice using iden3's Poseidon sponge and return
/// the result as 32 big-endian bytes. Matches Go's
/// `poseidon.HashBytes(msg).FillBytes(make([]byte, 32))`.
pub fn hash_bytes_to_32(msg: &[u8]) -> Result<[u8; 32]> {
    let mut inputs: Vec<Fr> = vec![zero_fr(); FRAME_SIZE];
    let mut dirty = false;
    let mut hash: Option<Fr> = None;
    let mut k = 0usize;

    let poseidon = Poseidon::new();

    // Process complete 31-byte chunks first.
    let num_chunks = msg.len() / SPONGE_CHUNK_SIZE;
    for i in 0..num_chunks {
        dirty = true;
        let chunk = &msg[SPONGE_CHUNK_SIZE * i..SPONGE_CHUNK_SIZE * (i + 1)];
        inputs[k] = fr_from_be_bytes(chunk)?;

        if k == FRAME_SIZE - 1 {
            let h = poseidon
                .hash(inputs.clone())
                .map_err(|e| QuilError::Crypto(format!("poseidon hash: {}", e)))?;
            hash = Some(h);
            dirty = false;
            inputs = vec![zero_fr(); FRAME_SIZE];
            inputs[0] = h;
            k = 1;
        } else {
            k += 1;
        }
    }

    // Process remaining bytes with zero padding on the right to a full
    // 31-byte chunk, matching `HashBytesX` in Go.
    if msg.len() % SPONGE_CHUNK_SIZE != 0 {
        let mut buf = [0u8; SPONGE_CHUNK_SIZE];
        let start = num_chunks * SPONGE_CHUNK_SIZE;
        let rem = &msg[start..];
        buf[..rem.len()].copy_from_slice(rem);
        inputs[k] = fr_from_be_bytes(&buf)?;
        dirty = true;
    }

    if dirty {
        let h = poseidon
            .hash(inputs)
            .map_err(|e| QuilError::Crypto(format!("poseidon hash: {}", e)))?;
        hash = Some(h);
    }

    let final_hash = hash.ok_or_else(|| QuilError::Crypto("empty message".into()))?;
    Ok(fr_to_32_be(&final_hash))
}

/// Hash up to `FRAME_SIZE = 16` field elements directly. Each input
/// must already be a valid BN254 scalar (< p) — the caller is
/// responsible for field-reducing.
pub fn hash_elements(inputs: &[[u8; 32]]) -> Result<[u8; 32]> {
    if inputs.is_empty() {
        return Err(QuilError::InvalidArgument(
            "poseidon hash_elements requires ≥ 1 input".into(),
        ));
    }
    if inputs.len() > FRAME_SIZE {
        return Err(QuilError::InvalidArgument(format!(
            "poseidon hash_elements accepts at most {FRAME_SIZE} inputs, got {}",
            inputs.len()
        )));
    }
    let mut frs: Vec<Fr> = Vec::with_capacity(inputs.len());
    for bytes in inputs {
        frs.push(fr_from_be_bytes(bytes)?);
    }
    let poseidon = Poseidon::new();
    let h = poseidon
        .hash(frs)
        .map_err(|e| QuilError::Crypto(format!("poseidon hash: {}", e)))?;
    Ok(fr_to_32_be(&h))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn zero_fr() -> Fr {
    Fr::from_str("0").expect("'0' is a valid Fr literal")
}

/// Parse big-endian bytes as a `Fr`, going through a `BigUint`
/// decimal intermediate the same way iden3 does via `SetBytes` on
/// `big.Int`. This matches Go's byte-to-field-element conversion
/// exactly (both interpret the bytes as a non-negative big-endian
/// integer and then reduce mod p).
fn fr_from_be_bytes(bytes: &[u8]) -> Result<Fr> {
    let n = BigUint::from_bytes_be(bytes);
    Fr::from_str(&n.to_string())
        .ok_or_else(|| QuilError::Crypto("poseidon: invalid field element".into()))
}

/// Convert a `Fr` to 32 big-endian bytes the same way iden3's
/// `big.Int.FillBytes(make([]byte, 32))` does.
fn fr_to_32_be(fr: &Fr) -> [u8; 32] {
    // `Fr::into_repr()` gives 4 little-endian u64 limbs (BN254 is
    // 254 bits → fits in 4 × 64 = 256 bits). Reverse for big-endian.
    let repr = fr.into_repr();
    let mut le_bytes: Vec<u8> = repr.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
    le_bytes.reverse();
    let mut out = [0u8; 32];
    // Take the 32-byte tail (big-endian) — matches Go's
    // `FillBytes(make([]byte, 32))`.
    out.copy_from_slice(&le_bytes[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check one live mainnet type hash: the Poseidon hash of
    /// `GLOBAL_INTRINSIC_ADDRESS (32 × 0xFF) || "prover:Prover"`
    /// should equal `TYPE_HASH_PROVER` observed in the 2026-04-11
    /// mainnet census:
    ///
    /// `2799018a52e2a068998ed0cdad60e86012f32b8df0d305999f5367e1098bdaec`
    #[test]
    fn hash_bytes_computes_live_prover_type_hash() {
        let mut msg = vec![0xFFu8; 32];
        msg.extend_from_slice(b"prover:Prover");
        let h = hash_bytes_to_32(&msg).expect("hash");
        let expected: [u8; 32] = [
            0x27, 0x99, 0x01, 0x8a, 0x52, 0xe2, 0xa0, 0x68, 0x99, 0x8e, 0xd0, 0xcd, 0xad,
            0x60, 0xe8, 0x60, 0x12, 0xf3, 0x2b, 0x8d, 0xf0, 0xd3, 0x05, 0x99, 0x9f, 0x53,
            0x67, 0xe1, 0x09, 0x8b, 0xda, 0xec,
        ];
        assert_eq!(
            h, expected,
            "poseidon type hash for prover:Prover drifted from live mainnet observation"
        );
    }

    #[test]
    fn hash_bytes_computes_live_allocation_type_hash() {
        let mut msg = vec![0xFFu8; 32];
        msg.extend_from_slice(b"allocation:ProverAllocation");
        let h = hash_bytes_to_32(&msg).expect("hash");
        let expected: [u8; 32] = [
            0x17, 0xfa, 0x31, 0x02, 0x82, 0x87, 0x55, 0x19, 0x78, 0xab, 0xcb, 0xc3, 0x14,
            0x50, 0xb1, 0xb1, 0x4b, 0xe4, 0x3c, 0x09, 0xbe, 0xc9, 0x0d, 0x7d, 0x9f, 0xb0,
            0x0e, 0xcd, 0x59, 0x56, 0xcf, 0x38,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn hash_bytes_computes_live_reward_type_hash() {
        let mut msg = vec![0xFFu8; 32];
        msg.extend_from_slice(b"reward:ProverReward");
        let h = hash_bytes_to_32(&msg).expect("hash");
        let expected: [u8; 32] = [
            0x04, 0xb1, 0x0a, 0x01, 0x84, 0x44, 0x11, 0xbb, 0x0c, 0x39, 0x0f, 0x4c, 0xd2,
            0x62, 0x9b, 0x48, 0xcc, 0x7e, 0xf5, 0x61, 0x45, 0x5c, 0x3a, 0xda, 0xc5, 0xeb,
            0xcb, 0xad, 0x38, 0x34, 0xbf, 0xa4,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn hash_bytes_is_deterministic() {
        let msg = b"hello world";
        let a = hash_bytes_to_32(msg).unwrap();
        let b = hash_bytes_to_32(msg).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_bytes_different_input_different_output() {
        let a = hash_bytes_to_32(b"hello").unwrap();
        let b = hash_bytes_to_32(b"world").unwrap();
        assert_ne!(a, b);
    }
}
