/// Slice a bitmask into individual per-bit bitmasks.
///
/// Each bit in the bitmask produces a separate "slice" — a bitmask with only
/// that single bit set. This determines the per-slice mesh structure.
///
/// An all-zero bitmask is treated as a single slice (special case).
///
/// This function must produce identical output to the Go implementation
/// for wire compatibility.
pub fn slice_bitmask(bitmask: &[u8]) -> Vec<Vec<u8>> {
    if bitmask.is_empty() {
        return vec![vec![]];
    }

    // Check if all zeros
    if bitmask.iter().all(|&b| b == 0) {
        return vec![bitmask.to_vec()];
    }

    let mut slices = Vec::new();
    for (byte_idx, &byte_val) in bitmask.iter().enumerate() {
        for bit_idx in 0..8 {
            if byte_val & (1 << (7 - bit_idx)) != 0 {
                let mut slice = vec![0u8; bitmask.len()];
                slice[byte_idx] = 1 << (7 - bit_idx);
                slices.push(slice);
            }
        }
    }

    if slices.is_empty() {
        vec![bitmask.to_vec()]
    } else {
        slices
    }
}

/// Check if a peer's subscription bitmask covers all slices of a composite.
pub fn covers_all_slices(peer_bitmask: &[u8], slices: &[Vec<u8>]) -> bool {
    slices.iter().all(|slice| {
        if peer_bitmask.len() != slice.len() {
            return false;
        }
        peer_bitmask
            .iter()
            .zip(slice.iter())
            .all(|(&p, &s)| p & s == s)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_single_bit() {
        let bitmask = vec![0x80]; // 10000000
        let slices = slice_bitmask(&bitmask);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0], vec![0x80]);
    }

    #[test]
    fn test_slice_two_bits() {
        let bitmask = vec![0xC0]; // 11000000
        let slices = slice_bitmask(&bitmask);
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0], vec![0x80]);
        assert_eq!(slices[1], vec![0x40]);
    }

    #[test]
    fn test_slice_all_zeros() {
        let bitmask = vec![0x00, 0x00];
        let slices = slice_bitmask(&bitmask);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0], vec![0x00, 0x00]);
    }

    #[test]
    fn test_slice_multi_byte() {
        let bitmask = vec![0xFF, 0x00]; // 8 bits set in first byte
        let slices = slice_bitmask(&bitmask);
        assert_eq!(slices.len(), 8);
    }

    #[test]
    fn test_covers_all() {
        let peer = vec![0xFF];
        let slices = vec![vec![0x80], vec![0x40]];
        assert!(covers_all_slices(&peer, &slices));
    }

    #[test]
    fn test_covers_partial() {
        let peer = vec![0x80];
        let slices = vec![vec![0x80], vec![0x40]];
        assert!(!covers_all_slices(&peer, &slices));
    }
}
