//! Which region of the coin accumulator a coin belongs to, and how positions
//! are allocated inside it.
//!
//! The accumulator's index space is `position = (block << SUBTREE_BITS) | local`.
//! A block is a contiguous subtree that ONE shard appends to, so a shard
//! advances the accumulator without coordinating with any other; the
//! application root is the fold of the block roots, which is just the top
//! levels of the same tree, so a membership proof stays a single leaf-to-root
//! path.
//!
//! # Growth without re-indexing
//!
//! The number of blocks is not fixed. Capacity grows the way an append-only
//! tree always grows — at the TOP: raise the depth by one, and the existing
//! root becomes the left child of the new root. Every existing position keeps
//! its exact numeric value, every existing block keeps its id, new block ids
//! simply begin above the old ones, and each proof gains one sibling. No coin
//! is re-indexed, which matters because `position` is part of a coin's
//! committed content: re-indexing would rewrite every coin address alive.
//!
//! # Ownership without a map
//!
//! A block's owner is derived from the BLOCK ID, never from the coin address.
//! Deriving it from the address would reassign existing coins when the width
//! grows — the address's top bits select a different block at a wider width,
//! while the coins' committed positions say otherwise.
//!
//! Block ids are never reused across widths: growth only adds ids above the
//! existing ones. So a block's id determines the width it was created at
//! ([`creation_width`]), and its owner is the shard whose bit-path prefixes
//! the block id read at THAT width. A block created at width 6 is read as six
//! bits forever, whatever the tree grows to, so no block is ever reassigned
//! and no committed allocation map is needed. A shard that splits hands each
//! child the blocks whose paths extend that child's prefix, which is again
//! derivation rather than bookkeeping.
use quil_lattice_ct::confidential::{
    relation::membership::MAX_DEPTH,
    sharded_tree::{position_of, split_position, Shape},
};
use quil_types::error::{QuilError, Result};

/// Widest the block field may grow: ids carry a sentinel bit, so a width-15
/// id still fits the 16 index bits the accumulator's depth leaves.
pub const MAX_BLOCK_BITS: u8 = 15;

/// Levels below a block: coins addressable within one append region (65,536).
/// Fixed, because it is the low half of every position — a block is the unit
/// of ALLOCATION, so a shard needing more room is granted further blocks
/// rather than a deeper region. Deliberately modest: capacity grows by adding
/// blocks, which is free, rather than by reserving depth up front, which every
/// proof would pay for.
pub const SUBTREE_BITS: u8 = 16;

/// Block levels an application starts with: 64 regions, matching QUIL's
/// genesis grid. This is the STARTING width, not a ceiling — see [`grown`].
/// The tree's DEPTH does not change with it: block ids are sentinel-encoded
/// into a fixed 16-bit field, so widening adds blocks without reshaping
/// anything already written.
pub const INITIAL_BLOCK_BITS: u8 = 6;

/// Index bits reserved for the block, holding a sentinel-encoded id up to
/// `MAX_BLOCK_BITS`. Fixed, so every position keeps its meaning forever.
pub const BLOCK_INDEX_BITS: u8 = MAX_BLOCK_BITS + 1;

/// Total accumulator depth: the block index above, the block's own coin
/// levels below. Fixed for the life of an application — widening allocates
/// more blocks inside the same index field rather than adding levels — so a
/// membership path is always this long and every proof is sized the same.
pub const DEPTH: u8 = BLOCK_INDEX_BITS + SUBTREE_BITS;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("coin block: {message}"))
}

/// The accumulator shape. The tree is one fixed shape — sentinel-encoded
/// block ids in `BLOCK_INDEX_BITS`, coins in `SUBTREE_BITS` — so a position
/// means the same thing for the life of the application.
pub fn shape(block_bits: u8) -> Result<Shape> {
    if block_bits < INITIAL_BLOCK_BITS || block_bits > MAX_BLOCK_BITS {
        return Err(invalid("block width outside the accumulator's range"));
    }
    Ok(Shape { shard_bits: BLOCK_INDEX_BITS, subtree_bits: SUBTREE_BITS })
}

/// Blocks available at `block_bits`.
pub fn blocks(block_bits: u8) -> u64 {
    1u64 << block_bits
}

/// One level of growth: the same tree with its old root as the left child of a
/// new root. Existing positions, block ids and coins are untouched; the new
/// block ids are `blocks(block_bits)..blocks(block_bits + 1)`.
pub fn grown(block_bits: u8) -> Result<u8> {
    let wider = block_bits
        .checked_add(1)
        .ok_or_else(|| invalid("block levels overflow"))?;
    shape(wider)?;
    Ok(wider)
}

/// Positions addressable in the accumulator, for bounds checks.
pub fn max_position() -> u64 {
    1u64 << (u32::from(BLOCK_INDEX_BITS) + u32::from(SUBTREE_BITS))
}

/// A block id carries its own width: `id = (1 << width) | path`. The leading
/// sentinel bit is what makes the width self-describing — without it a 6-bit
/// path and a 7-bit path with a leading zero share an id, and widening the
/// tree would silently re-read every existing block's path (prepending a zero)
/// and hand it to a different shard. The sentinel costs one bit of index space
/// and buys ownership that never moves.
pub fn block_id(width: u8, path_value: u64) -> Result<u64> {
    if width < INITIAL_BLOCK_BITS || width > MAX_BLOCK_BITS || path_value >= (1u64 << width) {
        return Err(invalid("block path does not fit its width"));
    }
    Ok((1u64 << width) | path_value)
}

/// The width a block was created at, read from its sentinel bit.
pub fn creation_width(block: u64) -> u8 {
    (63 - block.leading_zeros().min(63)) as u8
}

/// The block's bit-path: its id below the sentinel, most-significant bit
/// first. This is the path the owning shard's prefix must match, and it never
/// changes however wide the tree becomes.
pub fn block_path(block: u64) -> Vec<bool> {
    let width = creation_width(block);
    let path = block & ((1u64 << width) - 1);
    (0..u32::from(width))
        .map(|bit| {
            let shift = u32::from(width) - 1 - bit;
            (path >> shift) & 1 == 1
        })
        .collect()
}

/// The block a coin belongs to at the current width: the top `width` bits of
/// its address, which is the path of the shard that covers — and therefore
/// stores — that coin. Legacy blocks keep their own narrower paths, so this
/// never reassigns anything already written.
pub fn block_for_address(width: u8, address: &[u8; 32]) -> Result<u64> {
    let mut path = 0u64;
    for bit in 0..u32::from(width) {
        let byte = (bit / 8) as usize;
        let in_byte = 7 - (bit % 8);
        path = (path << 1) | u64::from((address[byte] >> in_byte) & 1 == 1);
    }
    block_id(width, path)
}

/// Whether the shard whose grid bit-path is `prefix` owns `block`. A shard at
/// depth `d` owns every block whose path begins with its `d` bits, so a split
/// hands each child a disjoint subset with no coin moving.
pub fn shard_owns_block(prefix: &[bool], block: u64) -> bool {
    let path = block_path(block);
    prefix.len() <= path.len() && prefix.iter().zip(&path).all(|(a, b)| a == b)
}

/// Every block id a shard owns at widths `INITIAL_BLOCK_BITS..=max_width`,
/// narrowest first: exactly the ids whose path extends the shard's own. A width
/// narrower than the shard is skipped, since the shard owns no whole block
/// there. Walking only these (rather than every id of a width) is what keeps a
/// whole-application holder at the widest setting from visiting 32,768 ids.
pub fn owned_blocks(shard: &[bool], max_width: u8) -> impl Iterator<Item = u64> + '_ {
    let prefix = shard.iter().fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit));
    (INITIAL_BLOCK_BITS..=max_width.min(MAX_BLOCK_BITS))
        .filter(move |width| shard.len() <= usize::from(*width))
        .flat_map(move |width| {
            let free = u32::from(width) - shard.len() as u32;
            (0..1u64 << free).map(move |rest| (1u64 << width) | (prefix << free) | rest)
        })
}

/// Whether `block` is a well-formed id no wider than the current width.
pub fn is_allocated_width(block_bits: u8, block: u64) -> bool {
    let width = creation_width(block);
    block > 0 && width >= INITIAL_BLOCK_BITS && width <= block_bits
}

/// The position of the `local`-th coin of `block`.
pub fn position(block_bits: u8, block: u64, local: u64) -> Result<u64> {
    if !is_allocated_width(block_bits, block) {
        return Err(invalid("block beyond the accumulator's current width"));
    }
    position_of(block, local, SUBTREE_BITS)
        .map_err(|_| invalid("block is full: grant the shard another block"))
}

/// The `(block, local)` a position addresses. Independent of the current
/// width, which is what makes growth free: a position decoded today decodes
/// identically after the tree has grown.
pub fn locate(position: u64) -> (u64, u64) {
    split_position(position, SUBTREE_BITS)
}

/// A coin's position must sit in a block the staging shard owns, so one shard
/// cannot append into another's append region.
pub fn check_position(shard_prefix: &[bool], position: u64) -> Result<()> {
    let (block, _) = locate(position);
    if !shard_owns_block(shard_prefix, block) {
        return Err(invalid("position is not in a block this shard owns"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(first: u8, second: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = first;
        a[1] = second;
        a
    }

    #[test]
    fn positions_stay_inside_their_block_and_round_trip() {
        let width = INITIAL_BLOCK_BITS;
        let block = block_id(width, 5).unwrap();
        let p = position(width, block, 9).unwrap();
        assert_eq!(locate(p), (block, 9));
        assert!(position(width, 0, 0).is_err(), "id 0 carries no sentinel");
        assert!(position(width, block, 1u64 << SUBTREE_BITS).is_err(), "a full block is refused");
        // A block wider than the committed width does not exist yet.
        let wider = block_id(width + 1, 5).unwrap();
        assert!(position(width, wider, 0).is_err());
        // A shard may only append into blocks its prefix covers: block path
        // 000101 belongs to `0,0,0`, not to `1`.
        check_position(&[false, false, false], p).unwrap();
        assert!(check_position(&[true], p).is_err());
    }

    /// The property the sentinel exists for: widening the tree must not
    /// re-read an existing block's path. Without it, a 6-bit path and a 7-bit
    /// path with a leading zero share an id, and every legacy block silently
    /// changes owner the moment the width grows.
    #[test]
    fn widening_never_reinterprets_an_existing_block() {
        let narrow = block_id(INITIAL_BLOCK_BITS, 0b101011).unwrap();
        let path = block_path(narrow);
        assert_eq!(path, vec![true, false, true, false, true, true]);
        assert_eq!(creation_width(narrow), INITIAL_BLOCK_BITS);
        // A block created at the next width with the SAME numeric path is a
        // different id, and keeps its own longer path.
        let wide = block_id(INITIAL_BLOCK_BITS + 1, 0b101011).unwrap();
        assert_ne!(narrow, wide);
        assert_eq!(creation_width(wide), INITIAL_BLOCK_BITS + 1);
        assert_eq!(block_path(wide), vec![false, true, false, true, false, true, true]);
        // Growing to the maximum never changes the narrow block's path, its
        // owner, or the position of a coin inside it.
        let before = position(INITIAL_BLOCK_BITS, narrow, 7).unwrap();
        let mut width = INITIAL_BLOCK_BITS;
        while let Ok(w) = grown(width) {
            width = w;
            assert_eq!(block_path(narrow), path, "reinterpreted at width {width}");
            assert!(shard_owns_block(&[true, false, true], narrow));
            assert_eq!(position(width, narrow, 7).unwrap(), before);
        }
        assert_eq!(width, MAX_BLOCK_BITS);
        assert!(grown(width).is_err(), "growth stops explicitly at the index width");
        // Every id in use fits the reserved index field.
        assert!(block_id(MAX_BLOCK_BITS, (1u64 << MAX_BLOCK_BITS) - 1).unwrap() < (1u64 << BLOCK_INDEX_BITS));
        assert!(position(MAX_BLOCK_BITS, block_id(MAX_BLOCK_BITS, 1).unwrap(), 1).unwrap() < max_position());
    }

    /// A coin's block follows from its address, so the shard that stores the
    /// coin is the shard that owns its append region.
    #[test]
    fn a_coin_lands_in_a_block_its_own_shard_owns() {
        let width = INITIAL_BLOCK_BITS;
        // Address beginning 1010 1011 -> path 101010 at width 6.
        let address = addr(0b1010_1011, 0);
        let block = block_for_address(width, &address).unwrap();
        assert_eq!(block_path(block), vec![true, false, true, false, true, false]);
        assert!(shard_owns_block(&[true, false, true], block));
        assert!(!shard_owns_block(&[false], block));
        // Only the leading bits matter.
        assert_eq!(block_for_address(width, &addr(0b1010_1011, 0xFF)).unwrap(), block);
        // At a wider width the SAME address selects a new, deeper block,
        // leaving the old one exactly as it was.
        let deeper = block_for_address(width + 1, &address).unwrap();
        assert_ne!(deeper, block);
        assert_eq!(block_path(block), vec![true, false, true, false, true, false]);
        assert_eq!(block_path(deeper).len(), usize::from(width) + 1);
    }

    /// A split hands each child a disjoint subset of the parent's blocks.
    #[test]
    fn a_split_partitions_the_parent_blocks_between_children() {
        let parent = vec![false, true];
        let left = vec![false, true, false];
        let right = vec![false, true, true];
        let covered: Vec<u64> = (0..blocks(INITIAL_BLOCK_BITS))
            .map(|path| block_id(INITIAL_BLOCK_BITS, path).unwrap())
            .filter(|b| shard_owns_block(&parent, *b))
            .collect();
        assert_eq!(covered.len() as u64, blocks(INITIAL_BLOCK_BITS) >> 2);
        for block in covered {
            assert_ne!(
                shard_owns_block(&left, block),
                shard_owns_block(&right, block),
                "block {block} must fall to exactly one child"
            );
        }
    }

    #[test]
    fn a_shape_is_refused_outside_the_accumulator_range() {
        assert!(shape(0).is_err());
        assert!(shape(INITIAL_BLOCK_BITS - 1).is_err());
        assert!(shape(INITIAL_BLOCK_BITS).is_ok());
        assert!(shape(MAX_BLOCK_BITS).is_ok());
        assert!(shape(MAX_BLOCK_BITS + 1).is_err());
        assert_eq!(shape(INITIAL_BLOCK_BITS).unwrap().depth(), usize::from(BLOCK_INDEX_BITS + SUBTREE_BITS));
        assert_eq!(shape(INITIAL_BLOCK_BITS).unwrap().depth(), MAX_DEPTH);
    }
}
