//! Transport abstraction for `ProverPipeline`.
//!
//! The pipeline turns `LifecycleAction`s into signed canonical-bytes
//! `MessageBundle`s and ships them on `GLOBAL_PROVER`. In production
//! that ship-it path fans out via BlossomSub *and* gRPC to known
//! archive endpoints. Both pieces (the BlossomSub handle and the
//! archive endpoint pool) live in crates `quil-engine` doesn't depend
//! on (`quil-p2p` is fine, but `quil-rpc` already depends on
//! `quil-engine` — circular). This trait lets the pipeline take the
//! transport behind a `dyn` boundary so the production wiring stays in
//! `quil-node` while tests can inject an in-memory mock.

use async_trait::async_trait;

use quil_types::error::Result;
use quil_types::proto::global::GlobalFrameHeader;

/// Pluggable transport for prover-admin messages on `GLOBAL_PROVER`.
///
/// Implementations are responsible for both:
///   1. Fetching the latest global frame header — used by `submit_join`
///      to stamp the join with a frame_number that the recipient
///      archive's verifier will accept (Go rejects joins where
///      `frame_number < head - 10`).
///   2. Broadcasting a fully-encoded `CanonicalMessageBundle` so every
///      archive sees it (fan out via gRPC + pubsub in production; a
///      single in-memory network broadcast in tests).
#[async_trait]
pub trait ProverMessageTransport: Send + Sync {
    /// Returns the latest global frame header. Used by `submit_join`.
    /// Implementations may consult a live archive or fall back to a
    /// local store snapshot. Errors propagate so the caller can decide
    /// whether to retry or fail the action.
    async fn latest_global_frame_header(&self) -> Result<GlobalFrameHeader>;

    /// Broadcast the bundle on `GLOBAL_PROVER`. Implementations should
    /// treat "no peers / empty archive set" as success (matching Go's
    /// BlossomSub semantics where an empty mesh silently buffers).
    /// Return `Err` only on a hard failure — channel closed, signer
    /// missing, etc.
    async fn publish_prover_bundle(&self, bundle_bytes: Vec<u8>) -> Result<()>;
}
