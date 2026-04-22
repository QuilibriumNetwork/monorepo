//! Raw bitmask utilities. Port of the bitmask helpers in
//! `node/consensus/time/utils.go` — little-endian bit packing
//! semantics that match the Go implementation byte-for-byte.
//!
//! The packer module ([`crate::packer`]) decodes bitmasks against a
//! known committee; this module provides raw bit-level operations
//! used by equivocation detection and signature bookkeeping:
//!
//! - [`count_bits`] — population count (number of set bits)
//! - [`has_overlapping_bits`] — detect whether two bitmasks share any
//!   set bit positions (fast equivocation check)
//! - [`bit_is_set`] / [`set_bit`] — individual bit access
//! - [`intersect`] / [`union`] — set operations on equal-length
//!   bitmasks
//!
//! All functions treat missing trailing bytes as zero — e.g. a
//! length-4 bitmask is equivalent to a length-8 bitmask padded with
//! four zero bytes. This matches Go's behavior where bitmask lengths
//! are "at least `ceil(n/8)`" rather than a strict equality.

/// Count the number of set bits in a bitmask. Mirror of Go's
/// `countBits` applied to a raw byte slice.
///
/// Uses `u8::count_ones()` which compiles to `popcnt` on x86_64 /
/// `cnt` on aarch64.
pub fn count_bits(bitmask: &[u8]) -> u32 {
    bitmask.iter().map(|b| b.count_ones()).sum()
}

/// Return `true` iff the two bitmasks share at least one set bit
/// position. Mirror of Go's `hasOverlappingBits` / `hasOverlappingAppBits`.
///
/// Used as a fast equivocation check: if two frames signed at the
/// same rank have overlapping signer bitmasks, at least one voter
/// signed both — direct Byzantine evidence.
///
/// Missing trailing bytes in either slice are treated as zero.
pub fn has_overlapping_bits(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let a_byte = *a.get(i).unwrap_or(&0);
        let b_byte = *b.get(i).unwrap_or(&0);
        if a_byte & b_byte != 0 {
            return true;
        }
    }
    false
}

/// Test whether bit `index` is set in `bitmask`. Bits are packed
/// little-endian within each byte: bit 0 is the lowest-order bit
/// of byte 0, bit 7 is the highest-order bit of byte 0, bit 8 is
/// the lowest-order bit of byte 1. Matches
/// `signer_indices[i/8] >> (i%8) & 1` in Go.
pub fn bit_is_set(bitmask: &[u8], index: usize) -> bool {
    let byte_idx = index / 8;
    let bit_idx = index % 8;
    bitmask.get(byte_idx).is_some_and(|b| (b >> bit_idx) & 1 == 1)
}

/// Set bit `index` in `bitmask`. Grows the bitmask if `index` would
/// fall past the current end.
pub fn set_bit(bitmask: &mut Vec<u8>, index: usize) {
    let byte_idx = index / 8;
    let bit_idx = index % 8;
    if byte_idx >= bitmask.len() {
        bitmask.resize(byte_idx + 1, 0);
    }
    bitmask[byte_idx] |= 1 << bit_idx;
}

/// Bitwise AND of two bitmasks. Result length matches the shorter
/// input (bits beyond the shorter input would be zero either way).
pub fn intersect(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().min(b.len());
    (0..len).map(|i| a[i] & b[i]).collect()
}

/// Bitwise OR of two bitmasks. Result length matches the longer
/// input; the shorter input's missing bytes are treated as zero.
pub fn union(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| {
            let av = *a.get(i).unwrap_or(&0);
            let bv = *b.get(i).unwrap_or(&0);
            av | bv
        })
        .collect()
}

/// Iterate the indices of all set bits in a bitmask. Useful for
/// enumerating the committee members that contributed to a QC/TC
/// without materializing the full index set.
pub fn set_bit_indices(bitmask: &[u8]) -> impl Iterator<Item = usize> + '_ {
    bitmask.iter().enumerate().flat_map(|(byte_idx, byte)| {
        (0..8u8)
            .filter(move |bit| byte & (1 << bit) != 0)
            .map(move |bit| byte_idx * 8 + bit as usize)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // count_bits
    // =================================================================

    #[test]
    fn count_bits_empty_slice() {
        assert_eq!(count_bits(&[]), 0);
    }

    #[test]
    fn count_bits_all_zero_bytes() {
        assert_eq!(count_bits(&[0u8; 32]), 0);
    }

    #[test]
    fn count_bits_all_set_bytes() {
        assert_eq!(count_bits(&[0xFFu8; 4]), 32);
    }

    #[test]
    fn count_bits_single_bit_per_byte() {
        // 0x01 has 1 bit set; 4 bytes → 4 total.
        assert_eq!(count_bits(&[0x01, 0x01, 0x01, 0x01]), 4);
    }

    #[test]
    fn count_bits_mixed_bytes() {
        // 0xFF (8) + 0x0F (4) + 0x10 (1) = 13
        assert_eq!(count_bits(&[0xFF, 0x0F, 0x10]), 13);
    }

    // =================================================================
    // has_overlapping_bits
    // =================================================================

    #[test]
    fn overlapping_bits_disjoint_returns_false() {
        // a has low nibble set, b has high nibble set → no overlap
        let a = [0x0Fu8];
        let b = [0xF0u8];
        assert!(!has_overlapping_bits(&a, &b));
    }

    #[test]
    fn overlapping_bits_identical_returns_true() {
        let a = [0x55u8, 0x55];
        let b = [0x55u8, 0x55];
        assert!(has_overlapping_bits(&a, &b));
    }

    #[test]
    fn overlapping_bits_single_shared_bit_returns_true() {
        // Only bit 0 of byte 0 is shared.
        let a = [0x01u8, 0x00];
        let b = [0x01u8, 0x00];
        assert!(has_overlapping_bits(&a, &b));
    }

    #[test]
    fn overlapping_bits_empty_inputs_returns_false() {
        assert!(!has_overlapping_bits(&[], &[]));
    }

    #[test]
    fn overlapping_bits_one_empty_returns_false() {
        assert!(!has_overlapping_bits(&[], &[0xFFu8; 4]));
        assert!(!has_overlapping_bits(&[0xFFu8; 4], &[]));
    }

    #[test]
    fn overlapping_bits_different_lengths_pad_shorter_with_zero() {
        // a has bit set in byte 3; b has only 1 byte with nothing
        // set → no overlap regardless of length difference.
        let a = [0x00u8, 0x00, 0x00, 0x08];
        let b = [0x00u8];
        assert!(!has_overlapping_bits(&a, &b));
    }

    // =================================================================
    // bit_is_set / set_bit
    // =================================================================

    #[test]
    fn bit_is_set_matches_go_packing() {
        // Bit layout: byte 0 bit 0 → least significant bit of first byte.
        // 0b1010_0110 = 0xA6 → bits 1, 2, 5, 7 are set (within byte 0).
        let bitmask = vec![0xA6u8];
        assert!(!bit_is_set(&bitmask, 0));
        assert!(bit_is_set(&bitmask, 1));
        assert!(bit_is_set(&bitmask, 2));
        assert!(!bit_is_set(&bitmask, 3));
        assert!(!bit_is_set(&bitmask, 4));
        assert!(bit_is_set(&bitmask, 5));
        assert!(!bit_is_set(&bitmask, 6));
        assert!(bit_is_set(&bitmask, 7));
    }

    #[test]
    fn bit_is_set_crosses_byte_boundaries() {
        // Bit 8 is the lowest bit of byte 1; bit 15 is the highest bit of byte 1.
        let bitmask = vec![0x00, 0x80]; // bit 15 set
        assert!(!bit_is_set(&bitmask, 14));
        assert!(bit_is_set(&bitmask, 15));
    }

    #[test]
    fn bit_is_set_beyond_bitmask_returns_false() {
        let bitmask = vec![0xFF];
        assert!(!bit_is_set(&bitmask, 100));
    }

    #[test]
    fn set_bit_grows_bitmask_when_needed() {
        let mut bitmask: Vec<u8> = vec![];
        set_bit(&mut bitmask, 10);
        // Byte 1 should now exist with bit 2 set.
        assert_eq!(bitmask.len(), 2);
        assert_eq!(bitmask[1], 0b0000_0100);
        assert!(bit_is_set(&bitmask, 10));
    }

    #[test]
    fn set_bit_idempotent() {
        let mut bitmask: Vec<u8> = vec![];
        set_bit(&mut bitmask, 5);
        set_bit(&mut bitmask, 5);
        assert_eq!(count_bits(&bitmask), 1);
    }

    // =================================================================
    // intersect / union
    // =================================================================

    #[test]
    fn intersect_returns_common_bits() {
        let a = vec![0b1111_0000u8, 0b0000_1111];
        let b = vec![0b1010_1010u8, 0b1010_1010];
        let isect = intersect(&a, &b);
        assert_eq!(isect, vec![0b1010_0000u8, 0b0000_1010]);
    }

    #[test]
    fn intersect_truncates_to_shorter() {
        let a = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let b = vec![0xFF, 0xFF];
        assert_eq!(intersect(&a, &b), vec![0xFF, 0xFF]);
    }

    #[test]
    fn union_joins_set_bits() {
        let a = vec![0b1111_0000u8];
        let b = vec![0b0000_1111u8];
        assert_eq!(union(&a, &b), vec![0xFFu8]);
    }

    #[test]
    fn union_preserves_longer_length() {
        let a = vec![0b0000_0001u8];
        let b = vec![0x00, 0x00, 0x00, 0b1000_0000u8];
        let u = union(&a, &b);
        assert_eq!(u.len(), 4);
        assert_eq!(u[0], 0b0000_0001);
        assert_eq!(u[3], 0b1000_0000);
    }

    #[test]
    fn union_commutative() {
        let a = vec![0x5A, 0x3C, 0xF0];
        let b = vec![0xA5, 0xC3, 0x0F];
        assert_eq!(union(&a, &b), union(&b, &a));
    }

    // =================================================================
    // set_bit_indices iteration
    // =================================================================

    #[test]
    fn set_bit_indices_empty_bitmask() {
        let bitmask: Vec<u8> = vec![];
        let indices: Vec<usize> = set_bit_indices(&bitmask).collect();
        assert!(indices.is_empty());
    }

    #[test]
    fn set_bit_indices_matches_bit_layout() {
        let bitmask = vec![0b0000_0101, 0b1000_0000]; // bits 0, 2, and 15
        let indices: Vec<usize> = set_bit_indices(&bitmask).collect();
        assert_eq!(indices, vec![0, 2, 15]);
    }

    #[test]
    fn set_bit_indices_count_matches_count_bits() {
        let bitmask = vec![0xAB, 0xCD, 0xEF];
        let iter_count = set_bit_indices(&bitmask).count();
        let popcnt = count_bits(&bitmask) as usize;
        assert_eq!(iter_count, popcnt);
    }

    // =================================================================
    // Cross-property: set_bit then bit_is_set round-trips
    // =================================================================

    #[test]
    fn set_bit_and_bit_is_set_round_trip() {
        let mut bitmask: Vec<u8> = vec![];
        let indices = [0, 1, 7, 8, 15, 16, 31, 63, 100];
        for &idx in &indices {
            set_bit(&mut bitmask, idx);
        }
        for &idx in &indices {
            assert!(bit_is_set(&bitmask, idx), "bit {} should be set", idx);
        }
        // A bit we didn't set should still be unset.
        assert!(!bit_is_set(&bitmask, 50));
    }

    #[test]
    fn equivocation_check_against_go_shape() {
        // Byzantine scenario: two distinct frames at the same rank
        // share 2 signers (bits 3 and 12). Both bitmasks also have
        // other signers contributing. The equivocation check should
        // return true.
        let frame_a = vec![0b0000_1000, 0b0001_0011]; // bits 3, 8, 9, 12
        let frame_b = vec![0b0110_1000, 0b0001_0010]; // bits 3, 5, 6, 12, 9
        assert!(has_overlapping_bits(&frame_a, &frame_b));

        // Sanity: neither bitmask is empty.
        assert!(count_bits(&frame_a) > 0);
        assert!(count_bits(&frame_b) > 0);
    }
}
