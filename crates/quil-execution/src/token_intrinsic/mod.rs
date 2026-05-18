//! Token intrinsic canonical-bytes. Port of
//! `protobufs/token.go` ToCanonicalBytes/FromCanonicalBytes for all 16
//! token types (0x0500–0x050F).
//!
//! Split into:
//! - `config` — Authority, FeeBasisStruct, TokenMintStrategy, TokenConfiguration
//! - `deploy` — TokenDeploy, TokenUpdate
//! - `transaction` — RecipientBundle, TransactionInput, TransactionOutput, Transaction
//! - `pending` — PendingTransactionInput, PendingTransactionOutput, PendingTransaction
//! - `mint` — MintTransactionInput, MintTransactionOutput, MintTransaction

pub mod config;
pub mod config_resolver;
pub mod constants;
pub mod conversions;
pub mod deploy;
pub mod materialize;
pub mod metadata_schema;
pub mod mint;
pub mod pending;
pub mod spent_check;
pub mod transaction;
pub mod verify;

// Re-export all types for convenience
pub use config::{
    Authority, FeeBasisStruct, TokenMintStrategy, TokenConfiguration,
    TYPE_AUTHORITY, TYPE_FEE_BASIS_STRUCT, TYPE_TOKEN_MINT_STRATEGY,
    TYPE_TOKEN_CONFIGURATION,
};
pub use deploy::{TokenDeploy, TokenUpdate, TYPE_TOKEN_DEPLOY, TYPE_TOKEN_UPDATE};
pub use transaction::{
    RecipientBundle, TransactionInput, TransactionOutput, Transaction,
    TYPE_RECIPIENT_BUNDLE, TYPE_TRANSACTION_INPUT, TYPE_TRANSACTION_OUTPUT,
    TYPE_TRANSACTION,
};
pub use pending::{
    PendingTransactionInput, PendingTransactionOutput, PendingTransaction,
    TYPE_PENDING_TRANSACTION_INPUT, TYPE_PENDING_TRANSACTION_OUTPUT,
    TYPE_PENDING_TRANSACTION,
};
pub use mint::{
    MintTransactionInput, MintTransactionOutput, MintTransaction,
    TYPE_MINT_TRANSACTION_INPUT, TYPE_MINT_TRANSACTION_OUTPUT,
    TYPE_MINT_TRANSACTION,
};

// Re-export the crate-wide canonical cursor helpers.
pub(crate) mod cursor {
    pub use crate::canonical_cursor::*;
}
