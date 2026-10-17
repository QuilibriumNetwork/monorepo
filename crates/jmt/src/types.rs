// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod nibble;
pub mod proof;

/// Specifies a particular version of the [`JellyfishMerkleTree`](crate::JellyfishMerkleTree) state.
pub type Version = u64; // Height - also used for MVCC in StateDB

/// The version before the genesis state. This version should always be empty.
pub const PRE_GENESIS_VERSION: Version = u64::max_value();
