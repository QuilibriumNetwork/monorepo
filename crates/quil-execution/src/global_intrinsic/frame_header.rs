//! GlobalFrameHeader (0x0309) and FrameHeader (0x030A) canonical bytes.

use quil_types::error::Result;
use crate::canonical_cursor::{
    put_u32, put_u64, put_i64, put_lp, read_u32, read_u64, read_i64,
    read_lp, read_array, write_array,
};

pub const TYPE_GLOBAL_FRAME_HEADER: u32 = 0x0309;
pub const TYPE_FRAME_HEADER: u32 = 0x030A;

/// Freshness/liveness window for the storage-attestation ρ_N anchor. A storage
/// shard frame anchored to global frame `G` (`global_frame_number = G`) may be
/// packed into any global frame in `[G+1, G+1+W]` rather than strictly `G+1`.
///
/// Why a window (and not strict `== frame-1`): app-shard committees are
/// multi-member, and members' synced global heads differ by a few frames, so a
/// proposer anchors to `latest − K` (a frame every member has) — which then can
/// never equal the *packing* global frame minus one. `W` absorbs that `K` plus
/// the app-production → global-pack transit + inter-node sync skew.
///
/// SECURITY: `W` bounds ρ_N staleness — a prover has at most ~`W` global frames
/// (~`W`×frame-time) to respond to a revealed beacon before its attestation can
/// no longer be packed, so `W` is the storage-freshness knob. Keep it as small
/// as liveness allows. CONSENSUS-CRITICAL: the leader's
/// `bundle_shard_frames_in_lockstep` and the materializer's
/// `audit_storage_attestation` MUST use this exact value or nodes fork.
pub const STORAGE_ANCHOR_LOCKSTEP_WINDOW: u64 = 12;
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
    /// Prover shard phase 1/2/3 roots. Same canonical position as the
    /// proto/consensus-wire codec: after `requests_root`, before `prover`.
    pub prover_tree_aux_roots: Vec<Vec<u8>>,
    pub requests_root: Vec<u8>,
    pub prover: Vec<u8>,
    pub public_key_signature_bls48581: Vec<u8>,
    /// Certified network world-state size at the end of the parent frame.
    /// Trailing field, written only when non-zero (older bytes are unchanged).
    pub world_state_size: u64,
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
        write_array(&mut out, &self.prover_tree_aux_roots);
        put_lp(&mut out, &self.prover);
        put_lp(&mut out, &self.public_key_signature_bls48581);
        if self.world_state_size != 0 {
            put_u64(&mut out, self.world_state_size);
        }
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
            prover_tree_aux_roots: read_array(data, &mut c)?,
            prover: read_lp(data, &mut c)?,
            public_key_signature_bls48581: read_opt_sig(data, &mut c)?,
            world_state_size: if c < data.len() { read_u64(data, &mut c)? } else { 0 },
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
    /// Fee total of the previous shard frame (16-byte big-endian QUIL base
    /// units; empty means zero). Credited to the shard's provers by the global
    /// materializer. Fixed-width trailing field after `global_frame_number`.
    pub fee_total: Vec<u8>,
    /// Settlement relay window (`settlement_record::encode_relay`): entries of
    /// settlements this QUIL shard executed in the previous 32 frames. Always
    /// encoded (length-prefixed) after `fee_total`.
    pub settlements: Vec<u8>,
    /// This shard's accumulator report (see `FrameHeader.accumulator`).
    pub accumulator: Vec<u8>,
    /// Spend entries relayed for the global commit (see `FrameHeader.spends`).
    pub spends: Vec<u8>,
}

impl FrameHeader {
    /// The previous-frame fee total as an integer (empty or short → 0).
    pub fn fee_total_value(&self) -> u128 {
        fee_total_from_bytes(&self.fee_total)
    }
}

/// Decode a 16-byte big-endian fee total; empty or malformed → 0.
pub fn fee_total_from_bytes(bytes: &[u8]) -> u128 {
    match <[u8; 16]>::try_from(bytes) {
        Ok(array) => u128::from_be_bytes(array),
        Err(_) => 0,
    }
}

/// Encode a fee total as 16 big-endian bytes.
pub fn fee_total_to_bytes(total: u128) -> Vec<u8> {
    total.to_be_bytes().to_vec()
}

/// Canonical header field for a fee total: empty for zero, 16 bytes otherwise.
pub fn fee_total_field(total: u128) -> Vec<u8> {
    if total == 0 {
        Vec::new()
    } else {
        fee_total_to_bytes(total)
    }
}

/// Leads a shard frame header's relay block. It cannot begin the attestation
/// trailer, whose u32 length would have to reach 0xFF000000.
const RELAY_BLOCK_TAG: u8 = 0xFF;

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
        // Relay block: the 16-byte previous-frame fee total, the settlement
        // relay window, the accumulator report and the spend relay. Written,
        // behind its tag, only when one of them is set. A header without
        // relays — every header the previous mainnet build made — then keeps
        // that build's bytes exactly, so the GLOBAL bodies embedding it still
        // recompute to their requests roots.
        let fee_total = self.fee_total_value();
        if fee_total != 0 || !self.settlements.is_empty() || !self.accumulator.is_empty() || !self.spends.is_empty() {
            out.push(RELAY_BLOCK_TAG);
            out.extend_from_slice(&fee_total_to_bytes(fee_total));
            put_lp(&mut out, &self.settlements);
            put_lp(&mut out, &self.accumulator);
            put_lp(&mut out, &self.spends);
        }
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
            fee_total: Vec::new(),
            settlements: Vec::new(),
            accumulator: Vec::new(),
            spends: Vec::new(),
        };
        // The storage-attestation fields are appended; tolerate their absence so
        // pre-attestation canonical bytes still decode (the bytes are then empty).
        if c < data.len() {
            h.storage_attestation_root = read_lp(data, &mut c)?;
            h.global_frame_number = read_u64(data, &mut c)?;
            if data.get(c) == Some(&RELAY_BLOCK_TAG) {
                c += 1;
                // Canonical form: a zero total is the empty vector, so
                // encode/decode round-trips headers built without fees.
                let total = data.get(c..c + 16).ok_or_else(|| quil_types::error::QuilError::InvalidArgument(
                    "FrameHeader: truncated relay block".into()))?;
                if total.iter().any(|b| *b != 0) {
                    h.fee_total = total.to_vec();
                }
                c += 16;
                h.settlements = read_lp(data, &mut c)?;
                h.accumulator = read_lp(data, &mut c)?;
                h.spends = read_lp(data, &mut c)?;
                // Written only when one of them is set: one encoding per header.
                if h.fee_total.is_empty() && h.settlements.is_empty() && h.accumulator.is_empty() && h.spends.is_empty() {
                    return Err(quil_types::error::QuilError::InvalidArgument(
                        "FrameHeader: empty relay block".into()));
                }
            }
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
            prover_tree_aux_roots: vec![vec![0x33u8; 64], vec![0x44u8; 64], vec![0x55u8; 64]],
            world_state_size: 0,
            requests_root: vec![0xFFu8; 64],
            prover: vec![0x11u8; 585],
            public_key_signature_bls48581: vec![0x22u8; 74],
        };
        let b = h.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_GLOBAL_FRAME_HEADER.to_be_bytes());
        assert_eq!(GlobalFrameHeader::from_canonical_bytes(&b).unwrap(), h);
    }

    #[test]
    fn global_frame_header_world_state_size_is_a_trailing_field() {
        let mut h = GlobalFrameHeader { frame_number: 5, output: vec![1; 516], ..Default::default() };
        let legacy = h.to_canonical_bytes().unwrap();
        assert_eq!(GlobalFrameHeader::from_canonical_bytes(&legacy).unwrap().world_state_size, 0);
        h.world_state_size = u64::MAX - 1;
        let sized = h.to_canonical_bytes().unwrap();
        assert_eq!(&sized[..legacy.len()], legacy.as_slice());
        assert_eq!(GlobalFrameHeader::from_canonical_bytes(&sized).unwrap(), h);
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
            fee_total: fee_total_to_bytes(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128),
            settlements: vec![0x66u8; 152],
            // Non-empty, with the attestation trailer after it: the report must
            // never be read as the trailer or the trailer as the report.
            accumulator: vec![0x77u8; 200],
            spends: vec![0x88u8; 120],
        };
        let b = f.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_FRAME_HEADER.to_be_bytes());
        assert_eq!(FrameHeader::from_canonical_bytes(&b).unwrap(), f);
    }

    #[test]
    fn frame_header_fee_total_round_trip() {
        let mut f = FrameHeader::default();
        f.fee_total = fee_total_field(0);
        assert!(f.fee_total.is_empty());
        let b = f.to_canonical_bytes().unwrap();
        let d = FrameHeader::from_canonical_bytes(&b).unwrap();
        assert_eq!(d, f);
        assert_eq!(d.fee_total_value(), 0);

        f.fee_total = fee_total_field(u128::MAX - 7);
        let b = f.to_canonical_bytes().unwrap();
        let d = FrameHeader::from_canonical_bytes(&b).unwrap();
        assert_eq!(d, f);
        assert_eq!(d.fee_total_value(), u128::MAX - 7);
        // The total sits after `global_frame_number` and before the
        // trailing attestation blob.
        let mut with_att = f.clone();
        with_att.storage_attestation = vec![0x55u8; 40];
        let b = with_att.to_canonical_bytes().unwrap();
        let d = FrameHeader::from_canonical_bytes(&b).unwrap();
        assert_eq!(d, with_att);
        // Settlements sit between the total and the attestation blob.
        with_att.settlements = vec![0x77u8; 152];
        let b = with_att.to_canonical_bytes().unwrap();
        assert_eq!(FrameHeader::from_canonical_bytes(&b).unwrap(), with_att);
        assert_eq!(fee_total_from_bytes(&[1u8; 5]), 0);
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

    /// A header without relays encodes exactly as the mainnet build encoded it,
    /// so GLOBAL bodies that embed its headers still recompute to their roots;
    /// a header with relays carries them behind the tag, and an empty relay
    /// block is not a second encoding of the same header.
    #[test]
    fn a_header_without_relays_keeps_the_mainnet_layout() {
        let mut f = FrameHeader {
            address: vec![0x01u8; 35], frame_number: 7, rank: 3, timestamp: 11, difficulty: 5,
            output: vec![0xAAu8; 516], parent_selector: vec![0xBBu8; 32], requests_root: vec![0xCCu8; 64],
            state_roots: vec![vec![0xDDu8; 32]; 4], prover: vec![0x11u8; 32], fee_multiplier_vote: 2,
            public_key_signature_bls48581: vec![0x22u8; 74], storage_attestation_root: vec![0x33u8; 32],
            global_frame_number: 900, storage_attestation: vec![0x44u8; 40],
            ..Default::default()
        };
        // The mainnet build's encoder (monorepo global_intrinsic/frame_header.rs).
        let mainnet = |f: &FrameHeader| {
            let mut out = Vec::new();
            put_u32(&mut out, TYPE_FRAME_HEADER);
            put_lp(&mut out, &f.address);
            put_u64(&mut out, f.frame_number);
            put_u64(&mut out, f.rank);
            put_i64(&mut out, f.timestamp);
            put_u32(&mut out, f.difficulty);
            put_lp(&mut out, &f.output);
            put_lp(&mut out, &f.parent_selector);
            put_lp(&mut out, &f.requests_root);
            write_array(&mut out, &f.state_roots);
            put_lp(&mut out, &f.prover);
            put_i64(&mut out, f.fee_multiplier_vote);
            put_lp(&mut out, &f.public_key_signature_bls48581);
            put_lp(&mut out, &f.storage_attestation_root);
            put_u64(&mut out, f.global_frame_number);
            if !f.storage_attestation.is_empty() {
                put_lp(&mut out, &f.storage_attestation);
            }
            out
        };
        assert_eq!(f.to_canonical_bytes().unwrap(), mainnet(&f));
        f.storage_attestation.clear();
        assert_eq!(f.to_canonical_bytes().unwrap(), mainnet(&f));
        assert_eq!(FrameHeader::from_canonical_bytes(&mainnet(&f)).unwrap(), f);

        f.spends = vec![0x55u8; 8];
        f.storage_attestation = vec![0x44u8; 40];
        let relayed = f.to_canonical_bytes().unwrap();
        assert_ne!(relayed, mainnet(&f));
        assert_eq!(FrameHeader::from_canonical_bytes(&relayed).unwrap(), f);

        f.spends.clear();
        let mut empty_block = mainnet(&FrameHeader { storage_attestation: Vec::new(), ..f.clone() });
        empty_block.push(RELAY_BLOCK_TAG);
        empty_block.extend_from_slice(&[0u8; 16]);
        for _ in 0..3 {
            put_lp(&mut empty_block, &[]);
        }
        assert!(FrameHeader::from_canonical_bytes(&empty_block).is_err());
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
