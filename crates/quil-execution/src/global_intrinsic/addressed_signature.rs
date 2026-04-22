//! `BLS48581AddressedSignature` canonical-bytes envelope.
//!
//! Wire format:
//!
//! ```text
//! [u32 BE type_prefix = 0x011B]
//! [u32 BE sig_len]
//! [sig_len bytes signature]
//! [u32 BE addr_len]
//! [addr_len bytes address]
//! ```
//!
//! Validation rules (enforced on decode):
//!
//! - `sig_len` is either 74 (single signer) or 590 (74 + 516 for
//!   aggregation with one prover on an upgrade path). Go:
//!   `sigLen != 74 && sigLen != (74+516)`.
//! - `addr_len` must be exactly 32. Go: `addrLen != 32`.

use quil_types::error::{QuilError, Result};

/// `BLS48581AddressedSignatureType` from Go
/// `protobufs/canonical_types.go:21`.
pub const TYPE_BLS48581_ADDRESSED_SIGNATURE: u32 = 0x011B;

/// Maximum canonical-bytes length (sanity bound used by callers that
/// allocate `ProverLeave` / `ProverPause` / `ProverResume` signatures).
/// Go uses `sigLen > 118` as a cutoff on the outer wrapper around
/// `BLS48581AddressedSignature` canonical bytes — that 118 is not the
/// length of the signature itself but of the whole wrapped envelope:
/// 4 type + 4 sig_len + 74 sig + 4 addr_len + 32 addr = 118. We
/// surface it as a constant so the filter-op decoders can enforce
/// the same cap.
pub const MAX_ADDRESSED_SIG_LEN: usize = 4 + 4 + (74 + 516) + 4 + 32; // 634

// Re-export from the crate-wide canonical cursor module.
pub(crate) use crate::canonical_cursor::{put_u32, read_u32, read_bytes};

// =====================================================================
// AddressedSignature
// =====================================================================

/// Mirror of `protobufs.BLS48581AddressedSignature`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressedSignature {
    /// BLS48-581 signature bytes. Must be 74 bytes (single-sig) or 590
    /// bytes (74 + 516 for the one-extra-signer aggregate variant).
    pub signature: Vec<u8>,
    /// 32-byte address tag that identifies which prover this signature
    /// is attributed to. Strictly 32 bytes — the decoder rejects
    /// anything else.
    pub address: Vec<u8>,
}

impl AddressedSignature {
    /// Canonical signature length: single-signer BLS48-581 is 74 bytes.
    pub const SIG_LEN_SINGLE: usize = 74;
    /// One-extra-signer aggregate: 74 base + 516 per extra signer.
    pub const SIG_LEN_AGGREGATE_1: usize = 74 + 516;
    /// Required address length.
    pub const ADDRESS_LEN: usize = 32;

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + 4 + self.signature.len() + 4 + self.address.len());
        put_u32(&mut out, TYPE_BLS48581_ADDRESSED_SIGNATURE);
        put_u32(&mut out, self.signature.len() as u32);
        out.extend_from_slice(&self.signature);
        put_u32(&mut out, self.address.len() as u32);
        out.extend_from_slice(&self.address);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let type_prefix = read_u32(data, &mut cursor)?;
        if type_prefix != TYPE_BLS48581_ADDRESSED_SIGNATURE {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AddressedSignature: invalid type prefix 0x{:08x}",
                type_prefix
            )));
        }

        let sig_len = read_u32(data, &mut cursor)? as usize;
        if sig_len != Self::SIG_LEN_SINGLE && sig_len != Self::SIG_LEN_AGGREGATE_1 {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AddressedSignature: invalid signature length {}",
                sig_len
            )));
        }
        let signature = read_bytes(data, &mut cursor, sig_len)?;

        let addr_len = read_u32(data, &mut cursor)? as usize;
        if addr_len != Self::ADDRESS_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "BLS48581AddressedSignature: invalid address length {}",
                addr_len
            )));
        }
        let address = read_bytes(data, &mut cursor, addr_len)?;

        Ok(Self { signature, address })
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_single_sig() -> AddressedSignature {
        AddressedSignature {
            signature: vec![0xAAu8; AddressedSignature::SIG_LEN_SINGLE],
            address: vec![0xBBu8; AddressedSignature::ADDRESS_LEN],
        }
    }

    fn sample_aggregate_sig() -> AddressedSignature {
        AddressedSignature {
            signature: vec![0xCCu8; AddressedSignature::SIG_LEN_AGGREGATE_1],
            address: vec![0xDDu8; AddressedSignature::ADDRESS_LEN],
        }
    }

    #[test]
    fn addressed_signature_round_trip_single() {
        let sig = sample_single_sig();
        let bytes = sig.to_canonical_bytes().unwrap();
        // 4 type + 4 sig_len + 74 sig + 4 addr_len + 32 addr = 118
        assert_eq!(bytes.len(), 118);
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x01, 0x1B]);
        let restored = AddressedSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, sig);
    }

    #[test]
    fn addressed_signature_round_trip_aggregate_one_extra() {
        let sig = sample_aggregate_sig();
        let bytes = sig.to_canonical_bytes().unwrap();
        // 4 + 4 + 590 + 4 + 32 = 634
        assert_eq!(bytes.len(), MAX_ADDRESSED_SIG_LEN);
        let restored = AddressedSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, sig);
    }

    #[test]
    fn addressed_signature_decode_rejects_bad_type_prefix() {
        let mut bytes = sample_single_sig().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(AddressedSignature::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn addressed_signature_decode_rejects_bad_sig_length() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_ADDRESSED_SIGNATURE);
        put_u32(&mut out, 100); // neither 74 nor 590
        out.extend_from_slice(&[0u8; 100]);
        put_u32(&mut out, 32);
        out.extend_from_slice(&[0u8; 32]);
        assert!(AddressedSignature::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn addressed_signature_decode_rejects_bad_address_length() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_ADDRESSED_SIGNATURE);
        put_u32(&mut out, 74);
        out.extend_from_slice(&[0u8; 74]);
        put_u32(&mut out, 20); // must be exactly 32
        out.extend_from_slice(&[0u8; 20]);
        assert!(AddressedSignature::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn addressed_signature_decode_rejects_truncated_buffer() {
        let full = sample_single_sig().to_canonical_bytes().unwrap();
        for cut in 1..full.len() {
            let truncated = &full[..cut];
            assert!(
                AddressedSignature::from_canonical_bytes(truncated).is_err(),
                "expected error when cut to {} bytes",
                cut
            );
        }
    }

    #[test]
    fn addressed_signature_decode_ignores_trailing_garbage() {
        let mut bytes = sample_single_sig().to_canonical_bytes().unwrap();
        bytes.extend_from_slice(b"extra");
        // Decoder uses cursor-based reads, so trailing bytes are
        // silently ignored. Restored value still matches.
        let restored = AddressedSignature::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored.signature.len(), AddressedSignature::SIG_LEN_SINGLE);
    }

    #[test]
    fn addressed_signature_type_prefix_constant_matches_go() {
        assert_eq!(TYPE_BLS48581_ADDRESSED_SIGNATURE, 0x011B);
    }
}
