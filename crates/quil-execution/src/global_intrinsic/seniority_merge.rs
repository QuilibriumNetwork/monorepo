//! `SeniorityMerge` canonical-bytes envelope.
//!
//! Wire format (type 0x0310):
//!
//! ```text
//! [u32 BE type_prefix = 0x0310]
//! [u32 BE sig_len]         [sig_len bytes signature]
//! [u32 BE key_type]
//! [u32 BE pubkey_len]      [pubkey_len bytes prover_public_key]
//! ```
//!
//! Validation: sig_len <= 114, pubkey_len <= 585.

use quil_types::error::{QuilError, Result};
use crate::canonical_cursor::{put_u32, read_u32, read_bytes};

pub const TYPE_SENIORITY_MERGE: u32 = 0x0310;
pub const MAX_SENIORITY_SIG_LEN: u32 = 114;
pub const MAX_SENIORITY_KEY_LEN: u32 = 585;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeniorityMerge {
    pub signature: Vec<u8>,
    pub key_type: u32,
    pub prover_public_key: Vec<u8>,
}

impl SeniorityMerge {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_SENIORITY_MERGE);
        put_u32(&mut out, self.signature.len() as u32);
        out.extend_from_slice(&self.signature);
        put_u32(&mut out, self.key_type);
        put_u32(&mut out, self.prover_public_key.len() as u32);
        out.extend_from_slice(&self.prover_public_key);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        let tp = read_u32(data, &mut cursor)?;
        if tp != TYPE_SENIORITY_MERGE {
            return Err(QuilError::InvalidArgument(format!(
                "SeniorityMerge: invalid type prefix 0x{:08x}", tp
            )));
        }
        let sig_len = read_u32(data, &mut cursor)?;
        if sig_len > MAX_SENIORITY_SIG_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "SeniorityMerge: invalid signature length {}", sig_len
            )));
        }
        let signature = read_bytes(data, &mut cursor, sig_len as usize)?;
        let key_type = read_u32(data, &mut cursor)?;
        let key_len = read_u32(data, &mut cursor)?;
        if key_len > MAX_SENIORITY_KEY_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "SeniorityMerge: invalid key length {}", key_len
            )));
        }
        let prover_public_key = read_bytes(data, &mut cursor, key_len as usize)?;
        Ok(Self { signature, key_type, prover_public_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SeniorityMerge {
        SeniorityMerge {
            signature: vec![0xAAu8; 74],
            key_type: 2, // BLS48581
            prover_public_key: vec![0xBBu8; 585],
        }
    }

    #[test]
    fn round_trip() {
        let s = sample();
        let bytes = s.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &TYPE_SENIORITY_MERGE.to_be_bytes());
        let restored = SeniorityMerge::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, s);
    }

    #[test]
    fn round_trip_empty_fields() {
        let s = SeniorityMerge { signature: vec![], key_type: 0, prover_public_key: vec![] };
        let bytes = s.to_canonical_bytes().unwrap();
        let restored = SeniorityMerge::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, s);
    }

    #[test]
    fn decode_rejects_bad_type_prefix() {
        let mut bytes = sample().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&0xDEADu32.to_be_bytes());
        assert!(SeniorityMerge::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_oversized_sig() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_SENIORITY_MERGE);
        put_u32(&mut out, MAX_SENIORITY_SIG_LEN + 1);
        assert!(SeniorityMerge::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn decode_rejects_oversized_key() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_SENIORITY_MERGE);
        put_u32(&mut out, 0); // empty sig
        put_u32(&mut out, 0); // key_type
        put_u32(&mut out, MAX_SENIORITY_KEY_LEN + 1);
        assert!(SeniorityMerge::from_canonical_bytes(&out).is_err());
    }
}
