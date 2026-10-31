use core::ops::Index;

use mirai_annotations::*;

pub trait Bytes32Ext: Index<usize> + Sized {
    /// Returns the `index`-th nibble.
    fn get_nibble(&self, index: usize) -> crate::types::nibble::Nibble;
    /// Returns the length of common prefix of `self` and `other` in bits.
    fn common_prefix_bits_len(&self, other: &[u8; 32]) -> usize;
    /// Returns a `HashValueBitIterator` over all the bits that represent this hash value.
    fn iter_bits(&self) -> HashValueBitIterator<'_>;
    /// Returns the `index`-th nibble in the bytes.
    fn nibble(&self, index: usize) -> u8;
    /// Returns the length of common prefix of `self` and `other` in nibbles.
    fn common_prefix_nibbles_len(&self, other: &[u8; 32]) -> usize {
        self.common_prefix_bits_len(other) / 4
    }
    /// Constructs a `HashValue` from an iterator of bits.
    fn from_bit_iter(iter: impl ExactSizeIterator<Item = bool>) -> Option<Self>;
}

impl Bytes32Ext for [u8; 32] {
    fn get_nibble(&self, index: usize) -> crate::types::nibble::Nibble {
        crate::types::nibble::Nibble::from(if index % 2 == 0 {
            self[index / 2] >> 4
        } else {
            self[index / 2] & 0x0F
        })
    }

    fn common_prefix_bits_len(&self, other: &[u8; 32]) -> usize {
        self.iter_bits()
            .zip(other.iter_bits())
            .take_while(|(x, y)| x == y)
            .count()
    }

    fn iter_bits(&self) -> HashValueBitIterator<'_> {
        HashValueBitIterator::new(self)
    }

    fn nibble(&self, index: usize) -> u8 {
        assume!(index < 32 * 2); // assumed precondition
        let pos = index / 2;
        let shift = if index % 2 == 0 { 4 } else { 0 };
        (self[pos] >> shift) & 0x0f
    }

    /// Constructs a `HashValue` from an iterator of bits.
    fn from_bit_iter(iter: impl ExactSizeIterator<Item = bool>) -> Option<Self> {
        if iter.len() != 256 {
            return None;
        }

        let mut buf = [0; 32];
        for (i, bit) in iter.enumerate() {
            if bit {
                buf[i / 8] |= 1 << (7 - i % 8);
            }
        }
        Some(buf)
    }
}

/// An iterator over a hash value that generates one bit for each iteration.
pub struct HashValueBitIterator<'a> {
    /// The reference to the bytes that represent the `HashValue`.
    hash_bytes: &'a [u8],
    pos: core::ops::Range<usize>,
    // invariant hash_bytes.len() == HashValue::LENGTH;
    // invariant pos.end == hash_bytes.len() * 8;
}

impl<'a> HashValueBitIterator<'a> {
    /// Constructs a new `HashValueBitIterator` using given `HashValue`.
    fn new(hash_value: &'a [u8; 32]) -> Self {
        HashValueBitIterator {
            hash_bytes: hash_value.as_ref(),
            pos: (0..32 * 8),
        }
    }

    /// Returns the `index`-th bit in the bytes.
    fn get_bit(&self, index: usize) -> bool {
        assume!(index < self.pos.end); // assumed precondition
        assume!(self.hash_bytes.len() == 32); // invariant
        assume!(self.pos.end == self.hash_bytes.len() * 8); // invariant
        let pos = index / 8;
        let bit = 7 - index % 8;
        (self.hash_bytes[pos] >> bit) & 1 != 0
    }
}

impl<'a> core::iter::Iterator for HashValueBitIterator<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        self.pos.next().map(|x| self.get_bit(x))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pos.size_hint()
    }
}

impl<'a> core::iter::DoubleEndedIterator for HashValueBitIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.pos.next_back().map(|x| self.get_bit(x))
    }
}

impl<'a> core::iter::ExactSizeIterator for HashValueBitIterator<'a> {}
