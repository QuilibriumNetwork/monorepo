//! Commonware **simplex** consensus backend for Quilibrium.
//!
//! Replaces the in-house `quil-consensus` (Jolteon/HotStuff) engine on the
//! GLOBAL consensus path with commonware's `simplex`, using **Falcon-512**
//! (post-quantum) signatures and **equal votes** (count-based quorum, no
//! seniority weighting). Seniority is retained elsewhere (eviction / rewards /
//! committee eligibility); only vote weight is dropped.
//!
//! Layers (built bottom-up; the first three are validated + tested, and were
//! the P1 feasibility spike):
//! - [`falcon_base`]: Falcon types implementing commonware's base crypto traits
//!   (`Signature` / `PublicKey` / `Verifier` / `Signer`).
//! - [`falcon_scheme`]: the multi-party `certificate::Scheme` (attestations →
//!   quorum certificates), non-batchable + attributable.
//! - [`falcon_simplex`]: binds the scheme to simplex's vote subject and proves
//!   (at compile time) that `simplex::Engine` accepts Falcon signatures.
//!
//! P2 (in progress) adds the Automaton / Relay / Reporter adapters and the
//! Engine host that drives global consensus over the existing `:8340` mTLS
//! transport. See memory `commonware_p2_global_cutover_design`.

// Reference the commonware crates so the dependency graph resolves and any
// version conflict with the workspace surfaces at build time.
pub use commonware_consensus as _consensus;
pub use commonware_cryptography as _crypto;
pub use commonware_runtime as _runtime;
pub use commonware_codec as _codec;
pub use commonware_utils as _utils;

/// Falcon-512 base crypto types implementing commonware's `Signature` /
/// `PublicKey` / `Verifier` / `Signer` traits.
pub mod falcon_base;

/// Falcon-512 `certificate::Scheme` — the multi-party quorum-certificate layer.
pub mod falcon_scheme;

/// Binds the Falcon scheme to commonware simplex's vote subject; includes the
/// compile-time proof that `simplex::Engine` accepts it.
pub mod falcon_simplex;
pub mod app_cert;

/// Quilibrium adapters (Automaton / Relay / Reporter) over three narrow seam
/// traits, plus the shared block store — the P2 global-consensus glue.
pub mod adapters;

/// `build_global_engine` — assembles a simplex `Engine` for global consensus
/// from the seams + runtime context (hides the large simplex `Config`).
pub mod engine_host;

/// Channel-backed commonware-p2p `Sender`/`Receiver` bridging simplex's 3
/// channels onto the node's `:8340` transport.
pub mod p2p_bridge;

/// Assemble the global-consensus committee (`Set<FalconPublicKey>` + this node's
/// `SimplexFalconScheme`) from `q-consensus-key` material.
pub mod committee;
