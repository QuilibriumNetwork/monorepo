//! Shared library for the devnet integration-test harness.
//!
//! This exposes the pure, dependency-light pieces that are reused by both the
//! `devnet` orchestrator binary and the `devnet-proxy` binary:
//! the wire types exchanged between them ([`shared`]) and the partition-schedule
//! algorithm ([`viewpartitions`]).

pub mod shared;
pub mod viewpartitions;
