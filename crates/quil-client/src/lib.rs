//! `quil-client` — the Rust port of the Quilibrium `qclient` CLI.
//!
//! The binary lives in `main.rs`; this library exposes the reusable
//! pieces (config, node-config resolution, key manager, gRPC connection,
//! and the `Send` helper) so they can be unit- and integration-tested
//! independently of `clap` argument parsing.

pub mod alias_store;
pub mod config;
pub mod context;
pub mod keys;
pub mod nodeconfig;
pub mod release;
pub mod rpc;
pub mod send;
pub mod system;
pub mod util;
pub mod vertex_write;

pub mod commands;
