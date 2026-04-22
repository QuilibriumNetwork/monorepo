//! GlobalFrameHeader (0x0309) and FrameHeader (0x030A) canonical bytes.

use quil_types::error::Result;
use crate::canonical_cursor::{
    put_u32, put_u64, put_i64, put_lp, read_u32, read_u64, read_i64,
    read_lp, read_array, write_array,
};

pub const TYPE_GLOBAL_FRAME_HEADER: u32 = 0x0309;
pub const TYPE_FRAME_HEADER: u32 = 0x030A;
fn read_opt_sig(buf: &[u8], c: &mut usize) -> Result<Vec<u8>> {
    read_lp(buf, c) // 0-length = absent, otherwise nested canonical bytes
}

// =====================================================================
// GlobalFrameHeader (0x0309)
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalFrameHeader {
    pub frame_number: u64,
    pub rank: u64,
    pub timestamp: i64,
    pub difficulty: u32,
    pub output: Vec<u8>,
    pub parent_selector: Vec<u8>,
    pub global_commitments: Vec<Vec<u8>>,
    pub prover_tree_commitment: Vec<u8>,
    pub requests_root: Vec<u8>,
    pub prover: Vec<u8>,
    pub public_key_signature_bls48581: Vec<u8>,
}

impl GlobalFrameHeader {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_GLOBAL_FRAME_HEADER);
        put_u64(&mut out, self.frame_number);
        put_u64(&mut out, self.rank);
        put_i64(&mut out, self.timestamp);
        put_u32(&mut out, self.difficulty);
        put_lp(&mut out, &self.output);
        put_lp(&mut out, &self.parent_selector);
        write_array(&mut out, &self.global_commitments);
        put_lp(&mut out, &self.prover_tree_commitment);
        put_lp(&mut out, &self.requests_root);
        put_lp(&mut out, &self.prover);
        put_lp(&mut out, &self.public_key_signature_bls48581);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_GLOBAL_FRAME_HEADER {
            return Err(quil_types::error::QuilError::InvalidArgument(
                format!("GlobalFrameHeader: bad type 0x{:08x}", tp),
            ));
        }
        Ok(Self {
            frame_number: read_u64(data, &mut c)?,
            rank: read_u64(data, &mut c)?,
            timestamp: read_i64(data, &mut c)?,
            difficulty: read_u32(data, &mut c)?,
            output: read_lp(data, &mut c)?,
            parent_selector: read_lp(data, &mut c)?,
            global_commitments: read_array(data, &mut c)?,
            prover_tree_commitment: read_lp(data, &mut c)?,
            requests_root: read_lp(data, &mut c)?,
            prover: read_lp(data, &mut c)?,
            public_key_signature_bls48581: read_opt_sig(data, &mut c)?,
        })
    }
}

// =====================================================================
// FrameHeader (0x030A) — app shard frame header
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameHeader {
    pub address: Vec<u8>,
    pub frame_number: u64,
    pub rank: u64,
    pub timestamp: i64,
    pub difficulty: u32,
    pub output: Vec<u8>,
    pub parent_selector: Vec<u8>,
    pub requests_root: Vec<u8>,
    pub state_roots: Vec<Vec<u8>>,
    pub prover: Vec<u8>,
    pub fee_multiplier_vote: i64,
    pub public_key_signature_bls48581: Vec<u8>,
}

impl FrameHeader {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_FRAME_HEADER);
        put_lp(&mut out, &self.address);
        put_u64(&mut out, self.frame_number);
        put_u64(&mut out, self.rank);
        put_i64(&mut out, self.timestamp);
        put_u32(&mut out, self.difficulty);
        put_lp(&mut out, &self.output);
        put_lp(&mut out, &self.parent_selector);
        put_lp(&mut out, &self.requests_root);
        write_array(&mut out, &self.state_roots);
        put_lp(&mut out, &self.prover);
        put_i64(&mut out, self.fee_multiplier_vote);
        put_lp(&mut out, &self.public_key_signature_bls48581);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_FRAME_HEADER {
            return Err(quil_types::error::QuilError::InvalidArgument(
                format!("FrameHeader: bad type 0x{:08x}", tp),
            ));
        }
        Ok(Self {
            address: read_lp(data, &mut c)?,
            frame_number: read_u64(data, &mut c)?,
            rank: read_u64(data, &mut c)?,
            timestamp: read_i64(data, &mut c)?,
            difficulty: read_u32(data, &mut c)?,
            output: read_lp(data, &mut c)?,
            parent_selector: read_lp(data, &mut c)?,
            requests_root: read_lp(data, &mut c)?,
            state_roots: read_array(data, &mut c)?,
            prover: read_lp(data, &mut c)?,
            fee_multiplier_vote: read_i64(data, &mut c)?,
            public_key_signature_bls48581: read_opt_sig(data, &mut c)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_frame_header_round_trip() {
        let h = GlobalFrameHeader {
            frame_number: 100, rank: 0, timestamp: 1234567890, difficulty: 200000,
            output: vec![0xAAu8; 516], parent_selector: vec![0xBBu8; 32],
            global_commitments: vec![vec![0xCCu8; 64], vec![0xDDu8; 64]],
            prover_tree_commitment: vec![0xEEu8; 64],
            requests_root: vec![0xFFu8; 64],
            prover: vec![0x11u8; 585],
            public_key_signature_bls48581: vec![0x22u8; 74],
        };
        let b = h.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_GLOBAL_FRAME_HEADER.to_be_bytes());
        assert_eq!(GlobalFrameHeader::from_canonical_bytes(&b).unwrap(), h);
    }

    #[test]
    fn global_frame_header_empty() {
        let h = GlobalFrameHeader::default();
        let b = h.to_canonical_bytes().unwrap();
        assert_eq!(GlobalFrameHeader::from_canonical_bytes(&b).unwrap(), h);
    }

    #[test]
    fn frame_header_round_trip() {
        let f = FrameHeader {
            address: vec![0x01u8; 32], frame_number: 50, rank: 1,
            timestamp: -999, difficulty: 100000,
            output: vec![0xAAu8; 516], parent_selector: vec![0xBBu8; 32],
            requests_root: vec![0xCCu8; 64],
            state_roots: vec![vec![0xDDu8; 64], vec![0xEEu8; 64]],
            prover: vec![0xFFu8; 585],
            fee_multiplier_vote: 42,
            public_key_signature_bls48581: vec![0x11u8; 74],
        };
        let b = f.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_FRAME_HEADER.to_be_bytes());
        assert_eq!(FrameHeader::from_canonical_bytes(&b).unwrap(), f);
    }

    #[test]
    fn frame_header_empty() {
        let f = FrameHeader::default();
        let b = f.to_canonical_bytes().unwrap();
        assert_eq!(FrameHeader::from_canonical_bytes(&b).unwrap(), f);
    }

    #[test]
    fn frame_header_negative_timestamp_and_vote() {
        let f = FrameHeader { timestamp: -42, fee_multiplier_vote: -100, ..Default::default() };
        let b = f.to_canonical_bytes().unwrap();
        let r = FrameHeader::from_canonical_bytes(&b).unwrap();
        assert_eq!(r.timestamp, -42);
        assert_eq!(r.fee_multiplier_vote, -100);
    }

    #[test]
    fn type_prefixes_distinct() {
        assert_ne!(TYPE_GLOBAL_FRAME_HEADER, TYPE_FRAME_HEADER);
    }
}
