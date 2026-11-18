// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `Nibble` represents a four-bit unsigned integer.

pub mod nibble_path;

use core::fmt;

#[cfg(any(test))]
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{Bytes32Ext, KeyHash, ValueHash};

/// The hardcoded maximum height of a state merkle tree in nibbles.
pub const ROOT_NIBBLE_HEIGHT: usize = 32 * 2;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Nibble(u8);

impl From<u8> for Nibble {
    fn from(nibble: u8) -> Self {
        assert!(nibble < 16, "Nibble out of range: {}", nibble);
        Self(nibble)
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> Self {
        nibble.0
    }
}

impl fmt::LowerHex for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl Nibble {
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// An iterator that iterates the index range (inclusive) of each different nibble at given
/// `nibble_idx` of all the keys in a sorted key-value pairs.
pub(crate) struct NibbleRangeIterator<'a> {
    sorted_kvs: &'a [(KeyHash, ValueHash)],
    nibble_idx: usize,
    pos: usize,
}

impl<'a> NibbleRangeIterator<'a> {
    pub fn new(sorted_kvs: &'a [(KeyHash, ValueHash)], nibble_idx: usize) -> Self {
        assert!(nibble_idx < ROOT_NIBBLE_HEIGHT);
        NibbleRangeIterator {
            sorted_kvs,
            nibble_idx,
            pos: 0,
        }
    }
}

impl<'a> core::iter::Iterator for NibbleRangeIterator<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let left = self.pos;
        if self.pos < self.sorted_kvs.len() {
            let cur_nibble: u8 = self.sorted_kvs[left].0 .0.nibble(self.nibble_idx);
            let (mut i, mut j) = (left, self.sorted_kvs.len() - 1);
            // Find the last index of the cur_nibble.
            while i < j {
                let mid = j - (j - i) / 2;
                if self.sorted_kvs[mid].0 .0.nibble(self.nibble_idx) > cur_nibble {
                    j = mid - 1;
                } else {
                    i = mid;
                }
            }
            self.pos = i + 1;
            Some((left, i))
        } else {
            None
        }
    }
}

#[cfg(any(test))]
impl Arbitrary for Nibble {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0..16u8).prop_map(Self::from).boxed()
    }
}
