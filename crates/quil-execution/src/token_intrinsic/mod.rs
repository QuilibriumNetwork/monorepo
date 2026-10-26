//! QCT3 token operations, configuration, state adapters and transparent migration.

#[cfg(feature = "confidential-tokens")]
pub mod cost;
pub mod wire;

pub mod accumulator_header;
#[cfg(feature = "confidential-tokens")]
pub mod coin_blocks;
#[cfg(all(feature = "confidential-tokens", feature = "native-proof"))]
pub mod commit_apply;
#[cfg(feature = "native-proof")]
pub mod commit_verify;
pub mod config;
pub mod config_resolver;
pub mod constants;
pub mod conversions;
#[cfg(feature = "native-proof")]
pub mod custom_mint;
#[cfg(feature = "native-proof")]
pub mod delivery;
pub mod deploy;
#[cfg(feature = "native-proof")]
pub mod dispatch;
pub mod entitlement;
#[cfg(feature = "confidential-tokens")]
pub mod escrow;
#[cfg(feature = "confidential-tokens")]
pub mod global_accumulator;
#[cfg(feature = "confidential-tokens")]
pub mod global_commit;
pub mod legacy_migration;
pub mod materialize;
pub mod metadata_schema;
#[cfg(feature = "native-proof")]
pub mod mint;
#[cfg(feature = "confidential-tokens")]
pub mod mint_authorization;
pub mod mint_authorization_witness;
#[cfg(feature = "native-proof")]
pub mod mint_claim;
#[cfg(feature = "native-proof")]
pub mod pending_claim;
pub mod rdf_schema;
pub mod reward_witness;
#[cfg(feature = "confidential-tokens")]
pub mod roots;
#[cfg(feature = "confidential-tokens")]
pub mod scan;
#[cfg(feature = "confidential-tokens")]
pub mod settlement_claim;
pub mod settlement_record;
#[cfg(feature = "confidential-tokens")]
pub mod shard_accumulator;
#[cfg(feature = "native-proof")]
pub mod shield;
pub mod signature;
#[cfg(feature = "native-proof")]
pub mod spend_entries;
pub mod spend_relay;
#[cfg(feature = "confidential-tokens")]
pub mod spent;
pub mod spent_check;
#[cfg(feature = "confidential-tokens")]
pub mod state;
#[cfg(feature = "confidential-tokens")]
pub mod summary_tree;
#[cfg(feature = "confidential-tokens")]
pub mod witness_index;
#[cfg(feature = "confidential-tokens")]
pub mod witnesses;

// Re-export all types for convenience
pub use config::{
    Authority, FeeBasisStruct, TokenConfiguration, TokenMintStrategy, TYPE_AUTHORITY,
    TYPE_FEE_BASIS_STRUCT, TYPE_TOKEN_CONFIGURATION, TYPE_TOKEN_MINT_STRATEGY,
};
pub use deploy::{TokenDeploy, TokenUpdate, TYPE_TOKEN_DEPLOY, TYPE_TOKEN_UPDATE};

pub use constants::{
    TYPE_LATTICE_MINT, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM,
    TYPE_LATTICE_SETTLEMENT, TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION,
};

// Re-export the crate-wide canonical cursor helpers.
pub(crate) mod cursor {
    pub use crate::canonical_cursor::*;
}

// Retired operation codes remain recognizable so execution rejects them.
pub use constants::{TYPE_MINT_TRANSACTION, TYPE_PENDING_TRANSACTION, TYPE_TRANSACTION};

/// Whether operations of type `tp` commit through the global frame; false in
/// builds without native proofs, which relay nothing.
pub fn spend_entries_relayed(tp: u32) -> bool {
    #[cfg(feature = "native-proof")]
    {
        spend_entries::is_relayed(tp)
    }
    #[cfg(not(feature = "native-proof"))]
    {
        let _ = tp;
        false
    }
}

/// The error of a verification refused for want of a free proof-worker slot:
/// local contention, neither a verdict nor a fault of the operation or of the
/// frame carrying it.
pub const PROOF_WORKER_BUSY: &str = "token proof worker: Busy";

/// Whether `error` is [`PROOF_WORKER_BUSY`].
pub fn is_proof_worker_busy(error: &quil_types::error::QuilError) -> bool {
    matches!(error, quil_types::error::QuilError::ExecutionUnavailable(message) if message == PROOF_WORKER_BUSY)
}

/// SHA3-256 of an operation's bytes: the id the global commit decides it by.
pub fn global_commit_tx_id(operation: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Sha3_256::digest(operation).into()
}
