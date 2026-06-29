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
    /// Committee digest over the per-member proof-of-storage openings carried
    /// with the frame (committed into the VDF challenge).
    pub storage_attestation_root: Vec<u8>,
    /// The global frame whose VDF output anchors the storage beacon rho_N.
    pub global_frame_number: u64,
    /// Serialized `proto::global::StorageAttestation` — the per-member PoRep
    /// openings the committee voted with, assembled at QC. Carried on the
    /// reward proof so the global frame can recompute the attestation root and
    /// run the ρ_N-sampled possession audit. Empty pre-activation (and then
    /// byte-identical to the legacy layout, since it's a tolerant trailing field).
    pub storage_attestation: Vec<u8>,
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
        // Appended storage-attestation binding (new fields after the legacy
        // layout, so older positional readers stop cleanly before them).
        put_lp(&mut out, &self.storage_attestation_root);
        put_u64(&mut out, self.global_frame_number);
        // Tolerant trailing field (after the storage-root + global-frame fields):
        // the full openings blob for the global audit. Length-prefixed, so an
        // empty attestation appends a 4-byte zero length — and to keep the
        // pre-activation bytes byte-identical to the legacy layout we omit it
        // entirely when empty (decoders stop cleanly at the prior field).
        if !self.storage_attestation.is_empty() {
            put_lp(&mut out, &self.storage_attestation);
        }
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
        let mut h = Self {
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
            storage_attestation_root: Vec::new(),
            global_frame_number: 0,
            storage_attestation: Vec::new(),
        };
        // The storage-attestation fields are appended; tolerate their absence so
        // pre-attestation canonical bytes still decode (the bytes are then empty).
        if c < data.len() {
            h.storage_attestation_root = read_lp(data, &mut c)?;
            h.global_frame_number = read_u64(data, &mut c)?;
            // The full openings blob is itself a tolerant trailing field —
            // present only when the committee attested (post-activation).
            if c < data.len() {
                h.storage_attestation = read_lp(data, &mut c)?;
            }
        }
        Ok(h)
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
            storage_attestation_root: vec![0x33u8; 32],
            global_frame_number: 777,
            storage_attestation: vec![0x44u8; 96],
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
    fn frame_header_storage_attestation_is_tolerant_trailing() {
        // A header with root + global frame but NO openings blob must encode
        // byte-identically to the legacy layout (the field is omitted when
        // empty), and a legacy-shaped buffer must decode with empty openings.
        let mut legacy = FrameHeader {
            address: vec![0x01u8; 32],
            frame_number: 9,
            global_frame_number: 1_000,
            storage_attestation_root: vec![0x33u8; 74],
            ..Default::default()
        };
        let with_empty = legacy.to_canonical_bytes().unwrap();
        // Now attach openings; the bytes must grow (trailing field present).
        legacy.storage_attestation = vec![0xABu8; 120];
        let with_att = legacy.to_canonical_bytes().unwrap();
        assert!(with_att.len() > with_empty.len());
        // Both round-trip.
        let back_empty = FrameHeader::from_canonical_bytes(&with_empty).unwrap();
        assert!(back_empty.storage_attestation.is_empty());
        assert_eq!(back_empty.storage_attestation_root, vec![0x33u8; 74]);
        let back_att = FrameHeader::from_canonical_bytes(&with_att).unwrap();
        assert_eq!(back_att.storage_attestation, vec![0xABu8; 120]);
        assert_eq!(back_att, legacy);
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
