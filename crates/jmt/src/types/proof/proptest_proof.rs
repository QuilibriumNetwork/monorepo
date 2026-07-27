// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! All proofs generated in this module are not valid proofs. They are only for the purpose of
//! testing conversion between Rust and Protobuf.

use alloc::vec::Vec;
use proptest::{collection::vec, prelude::*};

use crate::{
    types::proof::{SparseMerkleLeafNode, SparseMerkleProof, SparseMerkleRangeProof},
    SimpleHasher,
};

use super::SparseMerkleNode;

fn arb_non_placeholder_sparse_merkle_sibling() -> impl Strategy<Value = SparseMerkleNode> {
    any::<SparseMerkleNode>().prop_filter("Filter out placeholder sibling.", |x| {
        *x != SparseMerkleNode::Null
    })
}

fn arb_sparse_merkle_sibling() -> impl Strategy<Value = SparseMerkleNode> {
    prop_oneof![
        arb_non_placeholder_sparse_merkle_sibling(),
        Just(SparseMerkleNode::Null),
    ]
}

impl<H: SimpleHasher + 'static> Arbitrary for SparseMerkleProof<H> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<Option<SparseMerkleLeafNode>>(),
            (0..=256usize).prop_flat_map(|len| {
                if len == 0 {
                    Just(Vec::new()).boxed()
                } else {
                    (
                        arb_non_placeholder_sparse_merkle_sibling(),
                        vec(arb_sparse_merkle_sibling(), len),
                    )
                        .prop_map(|(first_sibling, mut siblings)| {
                            siblings[0] = first_sibling;
                            siblings
                        })
                        .boxed()
                }
            }),
        )
            .prop_map(|(leaf, siblings)| SparseMerkleProof::new(leaf, siblings))
            .boxed()
    }
}

impl<H: SimpleHasher + 'static> Arbitrary for SparseMerkleRangeProof<H> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        vec(arb_sparse_merkle_sibling(), 0..=256)
            .prop_map(Self::new)
            .boxed()
    }
}
