//! `ProverJoin` canonical-bytes envelope.
//!
//! Wire format (type 0x0301):
//!
//! ```text
//! [u32 BE type_prefix = 0x0301]
//! [u32 BE filters_count]
//!   for each filter:
//!     [u32 BE filter_len] [filter_len bytes]
//! [u64 BE frame_number]
//! [u32 BE sig_len] [sig_len bytes BLS48581SignatureWithProofOfPossession]
//! [u32 BE delegate_address_len] [delegate_address_len bytes]
//! [u32 BE merge_targets_count]
//!   for each:
//!     [u32 BE target_len] [target_len bytes SeniorityMerge]
//! [u32 BE proof_len] [proof_len bytes]
//! ```

use quil_types::error::{QuilError, Result};
use crate::canonical_cursor::{put_u32, put_u64, read_u32, read_u64, read_bytes};
use super::sig_with_pop::SignatureWithPop;
use super::seniority_merge::SeniorityMerge;

pub const TYPE_PROVER_JOIN: u32 = 0x0301;

const MAX_FILTERS: u32 = 100;
const MAX_FILTER_LEN: u32 = 64;
const MAX_SIG_LEN: u32 = 753;
const MAX_DELEGATE_ADDR_LEN: u32 = 32;
const MAX_MERGE_TARGET_LEN: u32 = 675;
const MAX_PROOF_LEN: u32 = 51600;

/// Mirror of `protobufs.ProverJoin`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverJoin {
    pub filters: Vec<Vec<u8>>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<SignatureWithPop>,
    pub delegate_address: Vec<u8>,
    pub merge_targets: Vec<SeniorityMerge>,
    pub proof: Vec<u8>,
}

impl ProverJoin {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_JOIN);

        // filters
        put_u32(&mut out, self.filters.len() as u32);
        for f in &self.filters {
            put_u32(&mut out, f.len() as u32);
            out.extend_from_slice(f);
        }

        // frame_number
        put_u64(&mut out, self.frame_number);

        // signature (nested canonical bytes)
        match &self.public_key_signature_bls48581 {
            Some(sig) => {
                let sb = sig.to_canonical_bytes()?;
                put_u32(&mut out, sb.len() as u32);
                out.extend_from_slice(&sb);
            }
            None => put_u32(&mut out, 0),
        }

        // delegate_address
        put_u32(&mut out, self.delegate_address.len() as u32);
        if !self.delegate_address.is_empty() {
            out.extend_from_slice(&self.delegate_address);
        }

        // merge_targets
        put_u32(&mut out, self.merge_targets.len() as u32);
        for mt in &self.merge_targets {
            let mb = mt.to_canonical_bytes()?;
            put_u32(&mut out, mb.len() as u32);
            out.extend_from_slice(&mb);
        }

        // proof
        put_u32(&mut out, self.proof.len() as u32);
        out.extend_from_slice(&self.proof);

        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let tp = read_u32(data, &mut cursor)?;
        if tp != TYPE_PROVER_JOIN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin: invalid type prefix 0x{:08x}", tp
            )));
        }

        // filters
        let fc = read_u32(data, &mut cursor)?;
        if fc > MAX_FILTERS {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin: invalid filter count {}", fc
            )));
        }
        let mut filters = Vec::with_capacity(fc as usize);
        for _ in 0..fc {
            let fl = read_u32(data, &mut cursor)?;
            if fl > MAX_FILTER_LEN {
                return Err(QuilError::InvalidArgument(format!(
                    "ProverJoin: invalid filter length {}", fl
                )));
            }
            filters.push(read_bytes(data, &mut cursor, fl as usize)?);
        }

        let frame_number = read_u64(data, &mut cursor)?;

        // signature
        let sl = read_u32(data, &mut cursor)?;
        if sl > MAX_SIG_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin: invalid signature length {}", sl
            )));
        }
        let public_key_signature_bls48581 = if sl > 0 {
            let sb = read_bytes(data, &mut cursor, sl as usize)?;
            Some(SignatureWithPop::from_canonical_bytes(&sb)?)
        } else {
            None
        };

        // delegate_address
        let dal = read_u32(data, &mut cursor)?;
        if dal > MAX_DELEGATE_ADDR_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin: invalid delegate address length {}", dal
            )));
        }
        let delegate_address = read_bytes(data, &mut cursor, dal as usize)?;

        // merge_targets
        let mtc = read_u32(data, &mut cursor)?;
        let mut merge_targets = Vec::with_capacity(mtc as usize);
        for _ in 0..mtc {
            let mtl = read_u32(data, &mut cursor)?;
            if mtl > MAX_MERGE_TARGET_LEN {
                return Err(QuilError::InvalidArgument(format!(
                    "ProverJoin: invalid merge target length {}", mtl
                )));
            }
            let mb = read_bytes(data, &mut cursor, mtl as usize)?;
            merge_targets.push(SeniorityMerge::from_canonical_bytes(&mb)?);
        }

        // proof
        let pl = read_u32(data, &mut cursor)?;
        if pl > MAX_PROOF_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverJoin: invalid proof length {}", pl
            )));
        }
        let proof = read_bytes(data, &mut cursor, pl as usize)?;

        Ok(Self {
            filters,
            frame_number,
            public_key_signature_bls48581,
            delegate_address,
            merge_targets,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sig_with_pop() -> SignatureWithPop {
        SignatureWithPop {
            signature: vec![0xAAu8; 74],
            public_key: Some(vec![0xBBu8; 585]),
            pop_signature: vec![0xCCu8; 74],
        }
    }

    fn sample_merge_target() -> SeniorityMerge {
        SeniorityMerge {
            signature: vec![0x11u8; 74],
            key_type: 2,
            prover_public_key: vec![0x22u8; 585],
        }
    }

    fn sample_prover_join() -> ProverJoin {
        ProverJoin {
            filters: vec![vec![0x01u8; 32], vec![0x02u8; 48]],
            frame_number: 0xCAFEBABE_DEADBEEF,
            public_key_signature_bls48581: Some(sample_sig_with_pop()),
            delegate_address: vec![0xDDu8; 32],
            merge_targets: vec![sample_merge_target()],
            proof: vec![0xEEu8; 128],
        }
    }

    #[test]
    fn round_trip_full() {
        let j = sample_prover_join();
        let bytes = j.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &TYPE_PROVER_JOIN.to_be_bytes());
        let restored = ProverJoin::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, j);
    }

    #[test]
    fn round_trip_minimal() {
        let j = ProverJoin {
            filters: vec![],
            frame_number: 0,
            public_key_signature_bls48581: None,
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![],
        };
        let bytes = j.to_canonical_bytes().unwrap();
        let restored = ProverJoin::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, j);
    }

    #[test]
    fn round_trip_no_sig_no_merge() {
        let j = ProverJoin {
            filters: vec![vec![0x01u8; 32]],
            frame_number: 42,
            public_key_signature_bls48581: None,
            delegate_address: vec![0xAAu8; 32],
            merge_targets: vec![],
            proof: vec![0xBBu8; 64],
        };
        let bytes = j.to_canonical_bytes().unwrap();
        let restored = ProverJoin::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, j);
    }

    #[test]
    fn round_trip_multiple_merge_targets() {
        let j = ProverJoin {
            filters: vec![],
            frame_number: 1,
            public_key_signature_bls48581: Some(sample_sig_with_pop()),
            delegate_address: vec![],
            merge_targets: vec![
                sample_merge_target(),
                SeniorityMerge {
                    signature: vec![0x33u8; 57],
                    key_type: 1, // Ed448
                    prover_public_key: vec![0x44u8; 57],
                },
            ],
            proof: vec![],
        };
        let bytes = j.to_canonical_bytes().unwrap();
        let restored = ProverJoin::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, j);
    }

    #[test]
    fn decode_rejects_bad_type_prefix() {
        let mut bytes = sample_prover_join().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&0xDEADu32.to_be_bytes());
        assert!(ProverJoin::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_too_many_filters() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_JOIN);
        put_u32(&mut out, MAX_FILTERS + 1);
        assert!(ProverJoin::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn decode_rejects_oversized_filter() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_JOIN);
        put_u32(&mut out, 1); // 1 filter
        put_u32(&mut out, MAX_FILTER_LEN + 1);
        assert!(ProverJoin::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn decode_rejects_oversized_proof() {
        // Build a valid prefix up to the proof field, then set proof
        // length too large.
        let j = ProverJoin {
            filters: vec![],
            frame_number: 0,
            public_key_signature_bls48581: None,
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![],
        };
        let mut bytes = j.to_canonical_bytes().unwrap();
        // The last 4 bytes are the proof length (0) — overwrite with MAX+1.
        let len = bytes.len();
        bytes[len - 4..].copy_from_slice(&(MAX_PROOF_LEN + 1).to_be_bytes());
        assert!(ProverJoin::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn frame_number_is_u64_be() {
        let j = ProverJoin {
            filters: vec![],
            frame_number: 0x0102030405060708,
            public_key_signature_bls48581: None,
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![],
        };
        let bytes = j.to_canonical_bytes().unwrap();
        // After type(4) + filter_count(4) → frame_number starts at byte 8
        assert_eq!(
            &bytes[8..16],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
