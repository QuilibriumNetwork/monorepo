mod compare;
mod go_format;
mod lazy_tree;
mod nibble;
mod node;
mod serialize;
mod tree;

pub use compare::compare_trees_at_height;
pub use go_format::{deserialize_go_tree, serialize_go_tree};
pub use lazy_tree::{LazyVectorCommitmentTree, NodeMetadata};
pub use nibble::{get_full_path, get_next_nibble};
pub use node::{BranchNode, LeafNode, VectorCommitmentNode};
pub use serialize::{
    deserialize_node_solo, deserialize_tree, serialize_node_solo, serialize_tree,
};
pub use tree::{MultiKeyTraversalProof, TraversalSubProof, VectorCommitmentTree};

/// 64-way branching factor (6 bits per nibble).
pub const BRANCH_NODES: usize = 64;
/// Bits per nibble in the trie.
pub const BRANCH_BITS: usize = 6;
/// Mask for extracting a nibble (0x3F).
pub const BRANCH_MASK: usize = 63;

/// Type discriminators for serialization.
pub const TYPE_NIL: u8 = 0;
pub const TYPE_LEAF: u8 = 1;
pub const TYPE_BRANCH: u8 = 2;
