//! Composite same/broker overlap mesh primitives for BlossomSub.
//!
//! In BlossomSub a "topic" is a **bitmask**. A message tagged with a multi-bit
//! bitmask `M` is decomposed into per-bit *slices* (`slice_bitmask`). Rather
//! than maintaining a mesh of `D` peers per slice (which multiplies fan-out by
//! the number of set bits), BlossomSub maintains a single COMPOSITE mesh of `D`
//! total peers for the whole bitmask, classified as:
//!
//! - **same**: peers whose advertised subscription(s) cover EVERY slice of the
//!   composite.
//! - **broker**: peers covering SOME (but not all) slices — they intentionally
//!   bridge non-subscribed slices, because a message carries the full bitmask
//!   which overlaps the broker's actual subscription.
//!
//! The per-slice `mesh` entries are *derived* from composite membership
//! (`rebuild_slice_meshes` in `behaviour.rs`): every composite member (same or
//! broker) is placed into every slice mesh. This is what lets a COVERING peer
//! (e.g. an archive that advertised an all-ones bulk relay bitmask) relay a
//! specific shard's traffic it never subscribed to by exact bitmask.
//!
//! `slice_bitmask` / `bitmask_covers` / `covers_all_slices` are ported verbatim
//! from `quil-p2p`'s `bitmask.rs`; they are the wire-correct Go-parity
//! primitives and MUST produce identical output to the Go implementation.

use std::collections::HashSet;

use libp2p_identity::PeerId;

use crate::topic::TopicHash;

/// Slice a bitmask into individual per-bit bitmasks.
///
/// Each bit set in the bitmask produces a separate "slice" — a bitmask with
/// only that single bit set. An all-zero (or empty) bitmask is treated as a
/// single slice (special case): slice == whole, so it routes exactly like a
/// plain single-topic mesh.
///
/// This function must produce identical output to the Go implementation for
/// wire compatibility.
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

/// True iff `haystack`'s set bits are a superset of `needle`'s — every bit set
/// in `needle` is also set in `haystack` (same length required). This is the
/// composite-mesh slice-matching primitive: a peer that advertised a BULK
/// bitmask (e.g. an archive's all-ones relay subscription) COVERS a specific
/// shard's single-bit slice even though it never advertised that exact slice.
/// Exact equality is the special case `haystack == needle`, so coverage is a
/// strict superset of exact matching.
pub fn bitmask_covers(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() == needle.len()
        && haystack
            .iter()
            .zip(needle.iter())
            .all(|(&h, &n)| h & n == n)
}

/// Check if a peer's subscription bitmask covers all slices of a composite.
///
/// Ported verbatim from `quil-p2p`'s `bitmask.rs` for parity; the behaviour
/// uses the per-slice `bitmask_covers` form, so this convenience wrapper is
/// currently exercised only by tests.
#[allow(dead_code)]
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

/// Convenience: slice a [`TopicHash`] into its per-bit slice [`TopicHash`]es.
pub fn topic_slices(topic: &TopicHash) -> Vec<TopicHash> {
    slice_bitmask(topic.as_bytes())
        .into_iter()
        .map(TopicHash::from_raw)
        .collect()
}

/// Classification of a composite-mesh peer. `Same` peers cover every slice of
/// the composite; `Broker` peers cover at least one but not all — they
/// intentionally bridge non-subscribed slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerClass {
    Same,
    Broker,
}

/// A composite mesh entry for a multi-bit bitmask subscription.
///
/// Maintains `D` TOTAL peers (not `D` per slice), classified into `same` and
/// `broker` sets. Ported from `quil-p2p`'s `CompositeMeshEntry`, with `slices`
/// stored as [`TopicHash`] (rather than `Vec<u8>`) so they can index the
/// `TopicHash`-keyed slice `mesh` directly.
#[derive(Debug, Clone)]
pub(crate) struct CompositeMeshEntry {
    /// The full (unspliced) bitmask. Retained for parity/diagnostics; slice
    /// lookups use `slices` (as `TopicHash`).
    #[allow(dead_code)]
    pub bitmask: Vec<u8>,
    /// Cached result of `slice_bitmask(bitmask)`, as slice topics.
    pub slices: Vec<TopicHash>,
    /// Peers covering ALL slices.
    pub same: HashSet<PeerId>,
    /// Peers covering SOME (but not all) slices.
    pub broker: HashSet<PeerId>,
}

impl CompositeMeshEntry {
    pub fn new(topic: &TopicHash) -> Self {
        Self {
            bitmask: topic.as_bytes().to_vec(),
            slices: topic_slices(topic),
            same: HashSet::new(),
            broker: HashSet::new(),
        }
    }

    pub fn total_peers(&self) -> usize {
        self.same.len() + self.broker.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_single_bit() {
        assert_eq!(slice_bitmask(&[0x80]), vec![vec![0x80]]);
    }

    #[test]
    fn slice_two_bits() {
        assert_eq!(slice_bitmask(&[0xC0]), vec![vec![0x80], vec![0x40]]);
    }

    #[test]
    fn slice_all_zeros_is_single_slice() {
        assert_eq!(slice_bitmask(&[0x00, 0x00]), vec![vec![0x00, 0x00]]);
    }

    #[test]
    fn slice_empty_is_single_empty_slice() {
        assert_eq!(slice_bitmask(&[]), vec![Vec::<u8>::new()]);
    }

    #[test]
    fn covers_superset() {
        assert!(bitmask_covers(&[0xFF], &[0x80]));
        assert!(bitmask_covers(&[0xC0], &[0x40]));
        assert!(!bitmask_covers(&[0x80], &[0x40]));
        // length mismatch never covers
        assert!(!bitmask_covers(&[0xFF, 0x00], &[0x80]));
    }

    #[test]
    fn covers_all() {
        assert!(covers_all_slices(&[0xFF], &[vec![0x80], vec![0x40]]));
        assert!(!covers_all_slices(&[0x80], &[vec![0x80], vec![0x40]]));
    }
}
