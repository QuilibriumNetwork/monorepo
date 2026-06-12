use quil_types::store::ShardKey;

/// A location in the hypergraph: [32-byte AppAddress][32-byte DataAddress].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Location {
    pub app_address: [u8; 32],
    pub data_address: [u8; 32],
}

impl Location {
    /// Construct from a 64-byte ID.
    pub fn from_id(id: &[u8; 64]) -> Self {
        let mut app = [0u8; 32];
        let mut data = [0u8; 32];
        app.copy_from_slice(&id[..32]);
        data.copy_from_slice(&id[32..]);
        Self {
            app_address: app,
            data_address: data,
        }
    }

    /// Convert to 64-byte ID.
    pub fn to_id(&self) -> [u8; 64] {
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&self.app_address);
        id[32..].copy_from_slice(&self.data_address);
        id
    }
}

/// Derive the shard key for a location.
/// L1 = 3-byte bloom filter indices from SHAKE256, matching Go's
/// `GetBloomFilterIndices(appAddress[:], 256, 3)`.
/// L2 = app_address (32 bytes).
pub fn shard_key_for_location(location: &Location) -> ShardKey {
    let l1 = get_bloom_filter_indices(&location.app_address, 256, 3);
    ShardKey {
        l1,
        l2: location.app_address,
    }
}

/// Compute bloom filter indices matching Go's `GetBloomFilterIndices`.
/// Returns 3 sorted byte-positions derived from SHAKE256(data).
///
/// Algorithm (from Go's `utils/p2p/bloom_utils.go:52`):
/// 1. If data[0] > 0x3f or data is all zeros → return [0,0,0]
/// 2. SHAKE256(data) → digest of size*k bytes (size = ceil(log2(bitLength)))
/// 3. Extract k positions of `size/8` bytes each
/// 4. Deduplicate (extending k if collision)
/// 5. Sort and concatenate
pub fn get_bloom_filter_indices(data: &[u8], bit_length: usize, k: usize) -> [u8; 3] {
    use sha3::{Shake256, digest::{ExtendableOutput, Update}};

    // Shortcut: addresses outside poseidon field or all-zero
    if data.is_empty() || data[0] > 0x3f || data.iter().all(|&b| b == 0) {
        return [0u8; 3];
    }

    // size = number of bits needed to represent bitLength
    // For bitLength=256: size = 9 (since 2^8=256, BigInt(256).BitLen()-1 = 8,
    // but Go uses big.NewInt(256).BitLen()-1 = 8)
    // Actually: big.NewInt(256) = 0x100, BitLen() = 9, so size = 9-1 = 8
    let size = (bit_length as f64).log2().ceil() as usize; // 8 for 256

    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut digest = vec![0u8; size * k]; // 8 * 3 = 24 bytes initially
    let mut xof = hasher.finalize_xof();
    use sha3::digest::XofReader;
    xof.read(&mut digest);

    let pos_size = size / 8; // bytes per position = 1 for size=8
    let mut indices: Vec<Vec<u8>> = Vec::new();
    let mut actual_k = k;
    let mut i = 0;

    while indices.len() < k && i < actual_k {
        // Extend digest if needed
        if (pos_size * (i + 1)) > digest.len() {
            let mut extra = vec![0u8; pos_size];
            xof.read(&mut extra);
            digest.extend_from_slice(&extra);
        }

        let start = pos_size * i;
        let end = start + pos_size;
        let position = digest[start..end].to_vec();

        // Check for duplicate
        if indices.iter().any(|idx| idx == &position) {
            actual_k += 1;
            i += 1;
            continue;
        }

        // Insert sorted
        let insert_pos = indices.binary_search(&position).unwrap_or_else(|p| p);
        indices.insert(insert_pos, position);
        i += 1;
    }

    // Concatenate sorted indices into output
    let mut output = [0u8; 3];
    let mut offset = 0;
    for idx in &indices {
        for &b in idx {
            if offset < 3 {
                output[offset] = b;
                offset += 1;
            }
        }
    }
    output
}

/// Build a bloom-filter bitmask matching Go's `GetBloomFilter` at
/// `utils/p2p/bloom_utils.go:28`.
///
/// `bit_length` is the bitmask width in bits (must be a multiple of 32).
/// `k` is the number of bits to set. Returns a `bit_length/8`-byte
/// little-endian-style bitmask with exactly `k` bits set, derived from
/// `sha3-256(data)`.
///
/// Used as the per-shard `appFilter` that prefixes every shard pubsub
/// bitmask. Without it, callers that pass the raw shard address to
/// the `shard_*_bitmask` functions end up subscribing to a topic
/// identified by the full address rather than the 3-bit bloom — and
/// don't share a topic with peers that compute the bloom the Go way.
pub fn get_bloom_filter(data: &[u8], bit_length: usize, k: usize) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    // big.NewInt(bit_length).BitLen() - 1
    // For 256: BitLen() = 9, size = 8
    let size = if bit_length == 0 {
        0
    } else {
        // BitLen() in Go counts position of the highest set bit + 1.
        // log2(bit_length).ceil() doesn't quite match: e.g. bit_length=256
        // → log2 = 8.0 → ceil = 8, but Go's BitLen() = 9, so size = 8.
        // Both yield 8 here. Use the trailing-zeros formulation that
        // matches both common bit_length values (256, 65536).
        (usize::BITS - bit_length.leading_zeros() - 1) as usize
    };

    let digest = Sha3_256::digest(data);
    let mut output = vec![0u8; bit_length / 8];

    // Extract k positions, each `size` bits wide, from the digest.
    // Each position selects one bit in `output`.
    let mut k_actual = k;
    let mut set_bits = 0;
    let mut i = 0;
    while set_bits < k && i < k_actual {
        let mut position: usize = 0;
        for j in (size * i)..(size * (i + 1)) {
            // Go's big.Int.Bit(j) reads bit j (LSB at position 0).
            // For sha3-256 the digest is 32 bytes; we treat it as a
            // big-endian big integer to match Go's SetBytes.
            // Go: BigInt::SetBytes(digest); Bit(j) = (BE-int >> j) & 1.
            let bit = bit_at(&digest, j);
            position = (position << 1) | bit as usize;
        }
        if position < bit_length && !is_bit_set(&output, position) {
            set_bit(&mut output, position);
            set_bits += 1;
        } else if k_actual < size {
            // Collision: extend the search.
            k_actual += 1;
        }
        i += 1;
    }

    output
}

/// Read bit `j` (LSB-numbered) from a big-endian byte slice interpreted
/// as a big integer — matches Go's `big.Int.SetBytes(buf).Bit(j)`.
fn bit_at(big_endian_bytes: &[u8], j: usize) -> u8 {
    let byte_from_end = j / 8;
    let bit_in_byte = j % 8;
    if byte_from_end >= big_endian_bytes.len() {
        return 0;
    }
    let byte_idx = big_endian_bytes.len() - 1 - byte_from_end;
    (big_endian_bytes[byte_idx] >> bit_in_byte) & 1
}

/// Read bit `pos` from `output` interpreted the same way: LSB-numbered
/// over a big-endian big integer. This matches Go's `outputBI.Bit(pos)`
/// after `outputBI.FillBytes(output)`.
fn is_bit_set(output: &[u8], pos: usize) -> bool {
    bit_at(output, pos) == 1
}

/// Set bit `pos` in `output` using the same big-endian-big-int
/// convention.
fn set_bit(output: &mut [u8], pos: usize) {
    let byte_from_end = pos / 8;
    let bit_in_byte = pos % 8;
    let byte_idx = output.len() - 1 - byte_from_end;
    output[byte_idx] |= 1u8 << bit_in_byte;
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // Location round-trip
    // =================================================================

    /// Pin our `get_bloom_filter` output to Go's exact bytes (from
    /// `utils/p2p/bloom_utils_test.go:TestGetBloomFilter`). If this
    /// fails, peers won't share shard topics — Go and Rust will
    /// subscribe to different bitmasks for the same address.
    #[test]
    fn get_bloom_filter_matches_go_four_byte_three_k() {
        let bloom = get_bloom_filter(&[0x00, 0x00, 0x00, 0x00], 256, 3);
        let expected: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(bloom, expected.to_vec());
    }

    #[test]
    fn get_bloom_filter_matches_go_sixty_byte_three_k() {
        let bloom = get_bloom_filter(&[0u8; 60], 256, 3);
        let expected: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(bloom, expected.to_vec());
    }

    #[test]
    fn get_bloom_filter_has_exactly_k_bits_set() {
        // Any data: bloom should have exactly k bits set.
        let bloom = get_bloom_filter(b"shard-address-test", 256, 3);
        let bit_count: u32 = bloom.iter().map(|b| b.count_ones()).sum();
        assert_eq!(bit_count, 3);
    }

    #[test]
    fn location_from_id_splits_at_byte_32() {
        let mut id = [0u8; 64];
        for i in 0..32 {
            id[i] = 0xAA;
        }
        for i in 32..64 {
            id[i] = 0xBB;
        }
        let loc = Location::from_id(&id);
        assert_eq!(loc.app_address, [0xAA; 32]);
        assert_eq!(loc.data_address, [0xBB; 32]);
    }

    #[test]
    fn location_to_id_concatenates_app_then_data() {
        let loc = Location {
            app_address: [0x11; 32],
            data_address: [0x22; 32],
        };
        let id = loc.to_id();
        assert_eq!(&id[..32], &[0x11u8; 32][..]);
        assert_eq!(&id[32..], &[0x22u8; 32][..]);
    }

    #[test]
    fn location_round_trip_preserves_all_bytes() {
        let mut original_id = [0u8; 64];
        for i in 0..64 {
            original_id[i] = i as u8;
        }
        let loc = Location::from_id(&original_id);
        assert_eq!(loc.to_id(), original_id);
    }

    #[test]
    fn location_equality_and_hashing() {
        use std::collections::HashSet;
        let a = Location {
            app_address: [1; 32],
            data_address: [2; 32],
        };
        let b = Location {
            app_address: [1; 32],
            data_address: [2; 32],
        };
        let c = Location {
            app_address: [9; 32],
            data_address: [2; 32],
        };
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a.clone());
        set.insert(b.clone()); // duplicate
        set.insert(c.clone());
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn location_clone_is_independent() {
        let mut a = Location {
            app_address: [0; 32],
            data_address: [0; 32],
        };
        let b = a.clone();
        a.app_address[0] = 0xFF;
        assert_eq!(b.app_address[0], 0);
    }

    #[test]
    fn location_from_id_with_all_zeros() {
        let id = [0u8; 64];
        let loc = Location::from_id(&id);
        assert_eq!(loc.app_address, [0u8; 32]);
        assert_eq!(loc.data_address, [0u8; 32]);
        assert_eq!(loc.to_id(), id);
    }

    #[test]
    fn location_from_id_with_all_ones() {
        let id = [0xFFu8; 64];
        let loc = Location::from_id(&id);
        assert_eq!(loc.app_address, [0xFFu8; 32]);
        assert_eq!(loc.data_address, [0xFFu8; 32]);
        assert_eq!(loc.to_id(), id);
    }

    // =================================================================
    // shard_key_for_location — bloom filter semantics
    // =================================================================

    #[test]
    fn shard_key_l2_mirrors_app_address() {
        let loc = Location {
            app_address: [0x42; 32],
            data_address: [0x99; 32],
        };
        let key = shard_key_for_location(&loc);
        assert_eq!(key.l2, [0x42; 32]);
        assert_eq!(key.l2, loc.app_address);
    }

    #[test]
    fn shard_key_l1_is_xor_bloom_over_app_address() {
        // All-zero app_address → L1 should be all zeros.
        let loc = Location {
            app_address: [0u8; 32],
            data_address: [0xFF; 32],
        };
        let key = shard_key_for_location(&loc);
        assert_eq!(key.l1, [0u8; 3]);
    }

    #[test]
    fn shard_key_l1_uses_shake256_bloom() {
        // Addresses with first byte > 0x3f get L1 = [0,0,0]
        let mut app = [0u8; 32];
        app[0] = 0x40; // > 0x3f
        let loc = Location { app_address: app, data_address: [0u8; 32] };
        let key = shard_key_for_location(&loc);
        assert_eq!(key.l1, [0, 0, 0]);

        // Valid address (first byte <= 0x3f) gets non-trivial L1
        app[0] = 0x01;
        let loc = Location { app_address: app, data_address: [0u8; 32] };
        let key = shard_key_for_location(&loc);
        assert_ne!(key.l1, [0, 0, 0]); // SHAKE256 produces non-zero output
    }

    #[test]
    fn shard_key_is_deterministic() {
        let loc = Location {
            app_address: [0x55; 32],
            data_address: [0xAA; 32],
        };
        let a = shard_key_for_location(&loc);
        let b = shard_key_for_location(&loc);
        assert_eq!(a, b);
    }

    #[test]
    fn shard_key_independent_of_data_address() {
        let a = Location {
            app_address: [0x77; 32],
            data_address: [0xAB; 32],
        };
        let b = Location {
            app_address: [0x77; 32],
            data_address: [0xCD; 32],
        };
        let ka = shard_key_for_location(&a);
        let kb = shard_key_for_location(&b);
        assert_eq!(ka, kb);
    }

    #[test]
    fn shard_key_different_app_addresses_yield_different_keys() {
        let a = Location {
            app_address: [0x01; 32],
            data_address: [0; 32],
        };
        let b = Location {
            app_address: [0x02; 32],
            data_address: [0; 32],
        };
        let ka = shard_key_for_location(&a);
        let kb = shard_key_for_location(&b);
        assert_ne!(ka, kb);
        assert_ne!(ka.l2, kb.l2);
    }

    #[test]
    fn shard_key_different_l2_distinguishes_even_if_l1_collides() {
        // Different app addresses may produce different L1 values
        // via SHAKE256, but even if L1 collides, L2 distinguishes.
        let mut a = [0u8; 32];
        a[0] = 0x01;
        let mut b = [0u8; 32];
        b[0] = 0x02;
        let ka = shard_key_for_location(&Location {
            app_address: a,
            data_address: [0; 32],
        });
        let kb = shard_key_for_location(&Location {
            app_address: b,
            data_address: [0; 32],
        });
        // L2 differs.
        assert_ne!(ka.l2, kb.l2);
        // Combined keys are unequal.
        assert_ne!(ka, kb);
    }

    #[test]
    fn shard_key_all_zero_app_address_yields_zero_l1() {
        let loc = Location {
            app_address: [0u8; 32],
            data_address: [0u8; 32],
        };
        let key = shard_key_for_location(&loc);
        assert_eq!(key.l1, [0u8; 3]);
        assert_eq!(key.l2, [0u8; 32]);
    }

    #[test]
    fn shard_key_all_ones_app_address_returns_zero_l1() {
        // app_address = [0xFF; 32] → first byte 0xFF > 0x3f → shortcut to [0,0,0]
        let loc = Location {
            app_address: [0xFFu8; 32],
            data_address: [0u8; 32],
        };
        let key = shard_key_for_location(&loc);
        assert_eq!(key.l1, [0u8; 3]);
    }
}
