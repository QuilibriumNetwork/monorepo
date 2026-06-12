//! Canonical-bytes port for the three "filter" prover ops:
//! `ProverLeave` (0x0302), `ProverPause` (0x0303), `ProverResume`
//! (0x0304).
//!
//! These three share the same shape except for their top-level type
//! prefix and the `filter(s)` field multiplicity:
//!
//! - `ProverLeave`: has `filters: Vec<Vec<u8>>` (multiple filters)
//! - `ProverPause` / `ProverResume`: have `filter: Vec<u8>` (single)
//!
//! Both sub-shapes then carry `frame_number: u64` and
//! `public_key_signature_bls48581: Option<AddressedSignature>`.
//!
//! Byte-exact port of the three `ToCanonicalBytes`/`FromCanonicalBytes`
//! method pairs in `protobufs/global.go:1073-1402`.
//!
//! Go validation bounds enforced on decode:
//!
//! - `ProverLeave::filtersCount <= 100`
//! - `ProverLeave::filterLen[i] <= 64`
//! - `ProverPause/Resume::filterLen <= 64`
//! - `sigLen <= 118` for all three — i.e. the signature payload
//!   must fit in a single-signer envelope; no aggregation on
//!   filter ops.

use quil_types::error::{QuilError, Result};

use super::addressed_signature::AddressedSignature;
use crate::canonical_cursor::{put_u32, put_u64, put_lp as put_len_prefixed, read_u32, read_u64, read_bytes};

// =====================================================================
// Type-prefix constants (from protobufs/canonical_types.go)
// =====================================================================

pub const TYPE_PROVER_LEAVE: u32 = 0x0302;
pub const TYPE_PROVER_PAUSE: u32 = 0x0303;
pub const TYPE_PROVER_RESUME: u32 = 0x0304;

/// Upper bound on the number of filters in a `ProverLeave`. Go:
/// `filtersCount > 100` is rejected at decode time.
pub const MAX_PROVER_FILTERS_COUNT: u32 = 100;
/// Upper bound on any single filter's length. Go: `filterLen > 64`
/// is rejected for all three filter ops.
pub const MAX_PROVER_FILTER_LEN: u32 = 64;
/// Upper bound on the inner canonical-bytes payload for the
/// `BLS48581AddressedSignature` — the single-signer envelope is
/// exactly 118 bytes, which Go uses as the decoder cap via
/// `sigLen > 118`.
pub const MAX_FILTER_OP_SIG_LEN: u32 = 118;

/// Read an optional `AddressedSignature` — a length prefix followed
/// by that many bytes of nested canonical-bytes. Length 0 → `None`.
/// Lengths above [`MAX_FILTER_OP_SIG_LEN`] are rejected (matches Go's
/// `sigLen > 118` guard in each filter-op decoder).
fn read_optional_addressed_sig(
    buf: &[u8],
    cursor: &mut usize,
) -> Result<Option<AddressedSignature>> {
    let sig_len = read_u32(buf, cursor)?;
    if sig_len > MAX_FILTER_OP_SIG_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "prover filter op: invalid signature length {}",
            sig_len
        )));
    }
    if sig_len == 0 {
        return Ok(None);
    }
    let sig_bytes = read_bytes(buf, cursor, sig_len as usize)?;
    let sig = AddressedSignature::from_canonical_bytes(&sig_bytes)?;
    Ok(Some(sig))
}

/// Write an optional `AddressedSignature` with the length prefix.
fn write_optional_addressed_sig(
    out: &mut Vec<u8>,
    sig: Option<&AddressedSignature>,
) -> Result<()> {
    match sig {
        Some(s) => {
            let bytes = s.to_canonical_bytes()?;
            put_len_prefixed(out, &bytes);
        }
        None => put_u32(out, 0),
    }
    Ok(())
}

// =====================================================================
// ProverLeave — multi-filter op
// =====================================================================

/// Mirror of `protobufs.ProverLeave`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverLeave {
    /// Bloom filters describing which shards this prover is leaving.
    /// Up to 100 entries, each up to 64 bytes. Go rejects anything
    /// beyond those bounds at decode time.
    pub filters: Vec<Vec<u8>>,
    /// Frame at which this leave operation is submitted.
    pub frame_number: u64,
    /// Optional BLS48-581 signature over the operation.
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ProverLeave {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_LEAVE);

        // Filter count + each filter (length-prefixed).
        put_u32(&mut out, self.filters.len() as u32);
        for filter in &self.filters {
            put_len_prefixed(&mut out, filter);
        }

        // Frame number.
        put_u64(&mut out, self.frame_number);

        // Optional signature.
        write_optional_addressed_sig(
            &mut out,
            self.public_key_signature_bls48581.as_ref(),
        )?;

        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let type_prefix = read_u32(data, &mut cursor)?;
        if type_prefix != TYPE_PROVER_LEAVE {
            return Err(QuilError::InvalidArgument(format!(
                "ProverLeave: invalid type prefix 0x{:08x}",
                type_prefix
            )));
        }

        let filters_count = read_u32(data, &mut cursor)?;
        if filters_count > MAX_PROVER_FILTERS_COUNT {
            return Err(QuilError::InvalidArgument(format!(
                "ProverLeave: invalid filters count {}",
                filters_count
            )));
        }
        let mut filters = Vec::with_capacity(filters_count as usize);
        for _ in 0..filters_count {
            let filter_len = read_u32(data, &mut cursor)?;
            if filter_len > MAX_PROVER_FILTER_LEN {
                return Err(QuilError::InvalidArgument(format!(
                    "ProverLeave: invalid filter length {}",
                    filter_len
                )));
            }
            filters.push(read_bytes(data, &mut cursor, filter_len as usize)?);
        }

        let frame_number = read_u64(data, &mut cursor)?;
        let public_key_signature_bls48581 = read_optional_addressed_sig(data, &mut cursor)?;

        Ok(Self {
            filters,
            frame_number,
            public_key_signature_bls48581,
        })
    }
}

// =====================================================================
// ProverPause — single-filter op
// =====================================================================

/// Mirror of `protobufs.ProverPause`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverPause {
    /// The single filter identifying which shard this prover is
    /// pausing on. Up to 64 bytes.
    pub filter: Vec<u8>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ProverPause {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_PAUSE);
        put_len_prefixed(&mut out, &self.filter);
        put_u64(&mut out, self.frame_number);
        write_optional_addressed_sig(
            &mut out,
            self.public_key_signature_bls48581.as_ref(),
        )?;
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let type_prefix = read_u32(data, &mut cursor)?;
        if type_prefix != TYPE_PROVER_PAUSE {
            return Err(QuilError::InvalidArgument(format!(
                "ProverPause: invalid type prefix 0x{:08x}",
                type_prefix
            )));
        }

        let filter_len = read_u32(data, &mut cursor)?;
        if filter_len > MAX_PROVER_FILTER_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverPause: invalid filter length {}",
                filter_len
            )));
        }
        let filter = read_bytes(data, &mut cursor, filter_len as usize)?;

        let frame_number = read_u64(data, &mut cursor)?;
        let public_key_signature_bls48581 = read_optional_addressed_sig(data, &mut cursor)?;

        Ok(Self {
            filter,
            frame_number,
            public_key_signature_bls48581,
        })
    }
}

// =====================================================================
// ProverResume — single-filter op
// =====================================================================

/// Mirror of `protobufs.ProverResume`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverResume {
    pub filter: Vec<u8>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ProverResume {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_RESUME);
        put_len_prefixed(&mut out, &self.filter);
        put_u64(&mut out, self.frame_number);
        write_optional_addressed_sig(
            &mut out,
            self.public_key_signature_bls48581.as_ref(),
        )?;
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let type_prefix = read_u32(data, &mut cursor)?;
        if type_prefix != TYPE_PROVER_RESUME {
            return Err(QuilError::InvalidArgument(format!(
                "ProverResume: invalid type prefix 0x{:08x}",
                type_prefix
            )));
        }

        let filter_len = read_u32(data, &mut cursor)?;
        if filter_len > MAX_PROVER_FILTER_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "ProverResume: invalid filter length {}",
                filter_len
            )));
        }
        let filter = read_bytes(data, &mut cursor, filter_len as usize)?;

        let frame_number = read_u64(data, &mut cursor)?;
        let public_key_signature_bls48581 = read_optional_addressed_sig(data, &mut cursor)?;

        Ok(Self {
            filter,
            frame_number,
            public_key_signature_bls48581,
        })
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addressed_sig() -> AddressedSignature {
        AddressedSignature {
            signature: vec![0xAAu8; AddressedSignature::SIG_LEN_SINGLE],
            address: vec![0xBBu8; AddressedSignature::ADDRESS_LEN],
        }
    }

    // -----------------------------------------------------------------
    // ProverLeave
    // -----------------------------------------------------------------

    fn sample_leave() -> ProverLeave {
        ProverLeave {
            filters: vec![
                vec![0x11u8; 32],
                vec![0x22u8; 24],
                vec![0x33u8; 1],
            ],
            frame_number: 0xCAFEBABE_DEADBEEF,
            public_key_signature_bls48581: Some(sample_addressed_sig()),
        }
    }

    #[test]
    fn prover_leave_round_trip_with_sig() {
        let op = sample_leave();
        let bytes = op.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x03, 0x02]);
        let restored = ProverLeave::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_leave_round_trip_no_sig() {
        let op = ProverLeave {
            filters: vec![vec![0x44u8; 8]],
            frame_number: 42,
            public_key_signature_bls48581: None,
        };
        let bytes = op.to_canonical_bytes().unwrap();
        let restored = ProverLeave::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_leave_round_trip_empty_filters() {
        let op = ProverLeave {
            filters: Vec::new(),
            frame_number: 0,
            public_key_signature_bls48581: None,
        };
        let bytes = op.to_canonical_bytes().unwrap();
        let restored = ProverLeave::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_leave_decode_rejects_too_many_filters() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_LEAVE);
        put_u32(&mut out, MAX_PROVER_FILTERS_COUNT + 1);
        assert!(ProverLeave::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn prover_leave_decode_rejects_oversized_filter() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_LEAVE);
        put_u32(&mut out, 1); // 1 filter
        put_u32(&mut out, MAX_PROVER_FILTER_LEN + 1); // too large
        assert!(ProverLeave::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn prover_leave_decode_rejects_bad_type_prefix() {
        let mut bytes = sample_leave().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(ProverLeave::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn prover_leave_accepts_exactly_100_filters_at_64_bytes() {
        let filters: Vec<Vec<u8>> = (0..MAX_PROVER_FILTERS_COUNT)
            .map(|_| vec![0u8; MAX_PROVER_FILTER_LEN as usize])
            .collect();
        let op = ProverLeave {
            filters,
            frame_number: 1,
            public_key_signature_bls48581: None,
        };
        let bytes = op.to_canonical_bytes().unwrap();
        let restored = ProverLeave::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored.filters.len(), MAX_PROVER_FILTERS_COUNT as usize);
    }

    // -----------------------------------------------------------------
    // ProverPause
    // -----------------------------------------------------------------

    fn sample_pause() -> ProverPause {
        ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 100,
            public_key_signature_bls48581: Some(sample_addressed_sig()),
        }
    }

    #[test]
    fn prover_pause_round_trip_with_sig() {
        let op = sample_pause();
        let bytes = op.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x03, 0x03]);
        let restored = ProverPause::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_pause_round_trip_no_sig() {
        let op = ProverPause {
            filter: vec![0xBBu8; 1],
            frame_number: 7,
            public_key_signature_bls48581: None,
        };
        let bytes = op.to_canonical_bytes().unwrap();
        let restored = ProverPause::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_pause_decode_rejects_oversized_filter() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_PAUSE);
        put_u32(&mut out, MAX_PROVER_FILTER_LEN + 1);
        assert!(ProverPause::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn prover_pause_decode_rejects_bad_type_prefix() {
        let mut bytes = sample_pause().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&TYPE_PROVER_LEAVE.to_be_bytes());
        assert!(ProverPause::from_canonical_bytes(&bytes).is_err());
    }

    // -----------------------------------------------------------------
    // ProverResume
    // -----------------------------------------------------------------

    fn sample_resume() -> ProverResume {
        ProverResume {
            filter: vec![0xCCu8; 16],
            frame_number: 42,
            public_key_signature_bls48581: Some(sample_addressed_sig()),
        }
    }

    #[test]
    fn prover_resume_round_trip_with_sig() {
        let op = sample_resume();
        let bytes = op.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x03, 0x04]);
        let restored = ProverResume::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_resume_round_trip_no_sig() {
        let op = ProverResume {
            filter: vec![],
            frame_number: 0,
            public_key_signature_bls48581: None,
        };
        let bytes = op.to_canonical_bytes().unwrap();
        let restored = ProverResume::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, op);
    }

    #[test]
    fn prover_resume_decode_rejects_bad_type_prefix() {
        let mut bytes = sample_resume().to_canonical_bytes().unwrap();
        bytes[..4].copy_from_slice(&TYPE_PROVER_PAUSE.to_be_bytes());
        assert!(ProverResume::from_canonical_bytes(&bytes).is_err());
    }

    // -----------------------------------------------------------------
    // Cross-type distinctness
    // -----------------------------------------------------------------

    #[test]
    fn pause_bytes_cannot_decode_as_resume_or_leave() {
        let b = sample_pause().to_canonical_bytes().unwrap();
        assert!(ProverLeave::from_canonical_bytes(&b).is_err());
        assert!(ProverResume::from_canonical_bytes(&b).is_err());
    }

    #[test]
    fn type_prefixes_distinct() {
        assert_ne!(TYPE_PROVER_LEAVE, TYPE_PROVER_PAUSE);
        assert_ne!(TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME);
        assert_ne!(TYPE_PROVER_LEAVE, TYPE_PROVER_RESUME);
    }
}
