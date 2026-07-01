//! Shared library for the devnet integration-test harness.
//!
//! This exposes the pure, dependency-light pieces that are reused by both the
//! `devnet` orchestrator binary and (in phase 2) the `devnet-proxy` binary:
//! the wire types exchanged between them ([`shared`]) and the partition-schedule
//! algorithm ([`rankpartitions`]).

pub mod rankpartitions;
pub mod shared;
