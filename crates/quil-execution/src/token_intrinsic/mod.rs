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

/// The error of a materialization put off while its frame's confidential
/// proofs verify on a background thread: the frame is fine, the engine keeps
/// running, and the materialization is retried once the verdicts are cached.
pub const PROOF_VERIFICATION_PENDING: &str =
    "token proofs of this frame are verifying in the background";

/// Whether `error` is [`PROOF_VERIFICATION_PENDING`].
pub fn is_proof_verification_pending(error: &quil_types::error::QuilError) -> bool {
    matches!(error, quil_types::error::QuilError::ExecutionUnavailable(message) if message == PROOF_VERIFICATION_PENDING)
}

/// SHA3-256 of an operation's bytes: the id the global commit decides it by.
pub fn global_commit_tx_id(operation: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Sha3_256::digest(operation).into()
}

/// Poseidon type markers of one family, by the 32-byte context or domain each
/// binds. A marker costs about 0.66 ms and depends on nothing else, and a coin
/// scan decodes every vertex of an application: rehashing one marker for each
/// of an archive's QUIL vertices held GLOBAL 945,000 for hours (2026-10-28).
/// Only successful results are kept, as for the state discriminators.
pub(crate) struct MarkerCache(std::sync::Mutex<Vec<([u8; 32], [u8; 32])>>);

/// Contexts one family keeps: one per network and application in use.
const MARKER_CONTEXTS: usize = 64;

impl MarkerCache {
    pub(crate) const fn new() -> Self {
        Self(std::sync::Mutex::new(Vec::new()))
    }

    /// `poseidon(preimage())`, the marker of `context`: computed once per
    /// 32-byte context, and every time for any other length.
    pub(crate) fn get(
        &self,
        context: &[u8],
        preimage: impl FnOnce() -> Vec<u8>,
    ) -> quil_types::error::Result<[u8; 32]> {
        let Ok(key) = <[u8; 32]>::try_from(context) else {
            return quil_crypto::poseidon::hash_bytes_to_32(&preimage());
        };
        if let Some((_, marker)) = self.entries().iter().find(|(held, _)| *held == key) {
            return Ok(*marker);
        }
        let marker = quil_crypto::poseidon::hash_bytes_to_32(&preimage())?;
        let mut entries = self.entries();
        if !entries.iter().any(|(held, _)| *held == key) {
            if entries.len() >= MARKER_CONTEXTS {
                entries.remove(0);
            }
            entries.push((key, marker));
        }
        Ok(marker)
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, Vec<([u8; 32], [u8; 32])>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::MarkerCache;

    /// A cached marker is the Poseidon hash of its preimage, per context, for
    /// contexts of other lengths and after older contexts are dropped.
    #[test]
    fn a_cached_marker_is_its_hash() {
        static MARKERS: MarkerCache = MarkerCache::new();
        let preimage = |context: &[u8]| {
            let mut bytes = b"marker\0".to_vec();
            bytes.extend_from_slice(context);
            bytes
        };
        let direct =
            |context: &[u8]| quil_crypto::poseidon::hash_bytes_to_32(&preimage(context)).unwrap();
        let contexts: Vec<[u8; 32]> = (0..=super::MARKER_CONTEXTS as u8)
            .map(|i| [i; 32])
            .collect();
        for _ in 0..2 {
            for context in &contexts {
                assert_eq!(
                    MARKERS.get(context, || preimage(context)).unwrap(),
                    direct(context)
                );
            }
        }
        assert_ne!(direct(&contexts[0]), direct(&contexts[1]));
        let short = [5u8; 7];
        assert_eq!(
            MARKERS.get(&short, || preimage(&short)).unwrap(),
            direct(&short)
        );
        assert!(MARKERS.entries().len() <= super::MARKER_CONTEXTS);
    }
}
