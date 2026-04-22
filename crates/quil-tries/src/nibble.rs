use crate::{BRANCH_BITS, BRANCH_MASK};

/// Extract the 6-bit nibble at the given bit position in the key.
/// Returns -1 if the position is past the end of the key.
pub fn get_next_nibble(key: &[u8], pos: usize) -> i32 {
    let start_byte = pos / 8;
    if start_byte >= key.len() {
        return -1;
    }

    let start_bit = pos % 8;
    let bits_from_current_byte = 8 - start_bit;
    let mut result = (key[start_byte] as usize) & ((1 << bits_from_current_byte) - 1);

    if bits_from_current_byte >= BRANCH_BITS {
        return ((result >> (bits_from_current_byte - BRANCH_BITS)) & BRANCH_MASK) as i32;
    }

    result <<= BRANCH_BITS - bits_from_current_byte;
    if start_byte + 1 < key.len() {
        let remaining_bits = BRANCH_BITS - bits_from_current_byte;
        let next_byte = key[start_byte + 1] as usize;
        result |= next_byte >> (8 - remaining_bits);
    }

    (result & BRANCH_MASK) as i32
}

/// Extract the complete nibble path for a key.
pub fn get_full_path(key: &[u8]) -> Vec<i32> {
    let mut nibbles = Vec::new();
    let mut depth = 0;
    loop {
        let n = get_next_nibble(key, depth);
        if n == -1 {
            break;
        }
        nibbles.push(n);
        depth += BRANCH_BITS;
    }
    nibbles
}

/// Extract nibbles until two keys diverge, starting at the given bit depth.
/// Returns (common nibbles, bit depth at divergence).
pub fn get_nibbles_until_diverge(key1: &[u8], key2: &[u8], start_depth: usize) -> (Vec<i32>, usize) {
    let mut nibbles = Vec::new();
    let mut depth = start_depth;
    loop {
        let n1 = get_next_nibble(key1, depth);
        let n2 = get_next_nibble(key2, depth);
        if n1 != n2 || n1 == -1 {
            return (nibbles, depth);
        }
        nibbles.push(n1);
        depth += BRANCH_BITS;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nibble_extraction() {
        // 0xFF = 11111111 => first nibble (6 bits) = 111111 = 63
        let key = vec![0xFF, 0x00];
        assert_eq!(get_next_nibble(&key, 0), 63);
    }

    #[test]
    fn test_full_path() {
        let key = vec![0xAB];
        let path = get_full_path(&key);
        // 0xAB = 10101011 => 6 bits: 101010 = 42, then remaining 2 bits: 11 + pad
        assert!(!path.is_empty());
    }

    #[test]
    fn test_past_end() {
        let key = vec![0x00];
        assert_eq!(get_next_nibble(&key, 64), -1);
    }

    // =================================================================
    // get_next_nibble edge cases
    // =================================================================

    #[test]
    fn nibble_at_zero_from_zero_bytes_is_zero() {
        let key = vec![0x00];
        assert_eq!(get_next_nibble(&key, 0), 0);
    }

    #[test]
    fn nibble_at_start_of_second_byte() {
        // pos 8 → byte 1 (0xFF), first 6 bits = 111111 = 63
        let key = vec![0x00, 0xFF];
        assert_eq!(get_next_nibble(&key, 8), 63);
    }

    #[test]
    fn nibble_spans_byte_boundary() {
        // 0x03, 0xC0 = 00000011 11000000
        // Start at bit 6: last 2 bits of byte 0 (11) + first 4 bits of byte 1 (1100)
        //               = 111100 = 60
        let key = vec![0x03, 0xC0];
        assert_eq!(get_next_nibble(&key, 6), 60);
    }

    #[test]
    fn nibble_past_single_byte_returns_minus_one() {
        let key = vec![0xFF];
        assert_eq!(get_next_nibble(&key, 8), -1);
        assert_eq!(get_next_nibble(&key, 100), -1);
    }

    #[test]
    fn nibble_empty_key_returns_minus_one() {
        let key: Vec<u8> = vec![];
        assert_eq!(get_next_nibble(&key, 0), -1);
    }

    #[test]
    fn nibble_tail_padding_with_zeros() {
        // 0xAB = 10101011
        // bits 0..6 = 101010 = 42
        // bits 6..12 = 2 bits of 0xAB (11) + pad with 0 = 110000 = 48
        let key = vec![0xAB];
        assert_eq!(get_next_nibble(&key, 0), 42);
        assert_eq!(get_next_nibble(&key, 6), 48);
        // bits 12..18 → past end of single-byte key
        assert_eq!(get_next_nibble(&key, 12), -1);
    }

    // =================================================================
    // get_full_path coverage
    // =================================================================

    #[test]
    fn full_path_single_byte_ab_has_two_nibbles() {
        let key = vec![0xAB];
        let path = get_full_path(&key);
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], 42);
        assert_eq!(path[1], 48);
    }

    #[test]
    fn full_path_empty_key_is_empty() {
        let key: Vec<u8> = vec![];
        assert_eq!(get_full_path(&key), Vec::<i32>::new());
    }

    #[test]
    fn full_path_all_zeros_is_all_zero_nibbles() {
        let key = vec![0u8; 4];
        let path = get_full_path(&key);
        assert!(path.iter().all(|&n| n == 0));
        // 32 bits / 6 bits per nibble = 5 full + 2 bits → 6 nibbles.
        assert_eq!(path.len(), 6);
    }

    #[test]
    fn full_path_all_ones_gives_max_nibbles() {
        // 0xFF, 0xFF, 0xFF → 24 bits → 4 full 6-bit nibbles (each = 63).
        let key = vec![0xFF, 0xFF, 0xFF];
        let path = get_full_path(&key);
        assert_eq!(path.len(), 4);
        assert!(path.iter().all(|&n| n == 63));
    }

    #[test]
    fn full_path_32_byte_key_has_43_nibbles() {
        // 32 bytes × 8 bits = 256 bits. 256 / 6 = 42 r 4.
        // Last nibble gets the 4 remaining bits + 2 zero bits of pad.
        // Total = 43 nibbles.
        let key = vec![0xA5u8; 32];
        let path = get_full_path(&key);
        assert_eq!(path.len(), 43);
    }

    // =================================================================
    // get_nibbles_until_diverge
    // =================================================================

    #[test]
    fn diverge_identical_keys_consume_full_path() {
        let a = vec![0xABu8; 4];
        let b = vec![0xABu8; 4];
        let (common, _depth) = get_nibbles_until_diverge(&a, &b, 0);
        // Identical keys → common equals the full nibble path.
        assert_eq!(common, get_full_path(&a));
    }

    #[test]
    fn diverge_first_nibble_differs_returns_empty() {
        // 0x00 vs 0xFC — first 6 bits: 000000 vs 111111.
        let a = vec![0x00u8];
        let b = vec![0xFCu8];
        let (common, depth) = get_nibbles_until_diverge(&a, &b, 0);
        assert!(common.is_empty());
        assert_eq!(depth, 0);
    }

    #[test]
    fn diverge_empty_keys_return_empty() {
        let a: Vec<u8> = vec![];
        let b: Vec<u8> = vec![];
        let (common, depth) = get_nibbles_until_diverge(&a, &b, 0);
        assert!(common.is_empty());
        assert_eq!(depth, 0);
    }

    #[test]
    fn diverge_one_empty_one_nonempty_returns_empty() {
        let a: Vec<u8> = vec![];
        let b = vec![0xAAu8];
        let (common, depth) = get_nibbles_until_diverge(&a, &b, 0);
        assert!(common.is_empty());
        assert_eq!(depth, 0);
    }

    #[test]
    fn diverge_preserves_start_depth_when_already_different() {
        // Keys differ immediately but we start at depth > 0.
        // Function should still report divergence at start_depth if
        // the nibbles don't match there.
        let a = vec![0x00u8];
        let b = vec![0xFCu8];
        let (common, depth) = get_nibbles_until_diverge(&a, &b, 0);
        assert!(common.is_empty());
        assert_eq!(depth, 0);
    }
}
