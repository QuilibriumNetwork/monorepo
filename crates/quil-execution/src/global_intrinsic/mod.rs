//! Global intrinsic. Partial port of
//! `node/execution/intrinsics/global/`.
//!
//! Scope notes:
//!
//! The full Go global intrinsic is ~7,000 LOC spread across twelve
//! operation files (`global_prover_*.go`, `global_shard_*.go`,
//! `global_prover_seniority_merge.go`) plus `global_intrinsic.go`
//! itself. The state-transition side of that work touches the prover
//! registry, frame prover, clock store, BLS constructor, RDF
//! multiprover, and the lazy-vector-commitment tree — none of which
//! have stable Rust trait surfaces yet.
//!
//! This module instead captures the **pure-data layer** that the
//! dispatcher in `global_engine.rs` can route to today:
//!
//! - [`addressed_signature`] — the `BLS48581AddressedSignature`
//!   canonical-bytes envelope (type 0x011B).
//! - [`prover_filter_ops`] — canonical-bytes for `ProverLeave`,
//!   `ProverPause`, `ProverResume`. All three share a
//!   filter(s) + frame_number + addressed-signature layout.
//!
//! Further ops (`ProverJoin`, `ProverConfirm`, `ProverReject`,
//! `ProverKick`, `ProverUpdate`, `SeniorityMerge`, `ShardSplit`,
//! `ShardMerge`) are left as follow-up work. Each one needs its own
//! canonical-bytes module plus the per-op state-transition logic.

pub mod addressed_signature;
pub mod alt_shard_update_materialize;
pub mod consensus_types;
pub mod conversions;
pub mod frame_header;
pub mod intrinsic;
pub mod kick_verify;
pub mod materialize;
pub mod proof_types;
pub mod prover_filter_ops;
pub mod prover_join;
pub mod prover_ops;
pub mod prover_shard_update;
pub mod prover_update_materialize;
pub mod prover_verify;
pub mod seniority_merge;
pub mod sig_with_pop;
pub mod verify;

pub use addressed_signature::{
    AddressedSignature, TYPE_BLS48581_ADDRESSED_SIGNATURE, MAX_ADDRESSED_SIG_LEN,
};
pub use prover_filter_ops::{
    ProverLeave, ProverPause, ProverResume, MAX_PROVER_FILTERS_COUNT,
    MAX_PROVER_FILTER_LEN, TYPE_PROVER_LEAVE, TYPE_PROVER_PAUSE, TYPE_PROVER_RESUME,
};
pub use prover_join::{ProverJoin, TYPE_PROVER_JOIN};
pub use seniority_merge::{SeniorityMerge, TYPE_SENIORITY_MERGE};
pub use sig_with_pop::{SignatureWithPop, TYPE_BLS48581_SIG_WITH_POP};
pub use frame_header::{
    FrameHeader, GlobalFrameHeader, TYPE_FRAME_HEADER, TYPE_GLOBAL_FRAME_HEADER,
};
pub use prover_ops::{
    ProverConfirm, ProverReject, ProverKick, ProverUpdate, ProverSeniorityMerge,
    ShardSplit, ShardMerge, TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT, TYPE_PROVER_KICK,
    TYPE_PROVER_UPDATE, TYPE_PROVER_SENIORITY_MERGE, TYPE_SHARD_SPLIT, TYPE_SHARD_MERGE,
};
