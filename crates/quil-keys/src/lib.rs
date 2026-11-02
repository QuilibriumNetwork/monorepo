mod file_key_manager;
mod identity_guard;
mod keystore_path;

pub use file_key_manager::{stored_prover_address, FileKeyManager, KeyEntry};
pub use identity_guard::{
    record_identity, refuse_new_peer_key, refuse_prover_key_change, refuse_recreated_config,
    StoreEvidence,
};
pub use keystore_path::{resolve_existing_keystore_path, resolve_keystore_path};

use quil_types::crypto::{KeyType, Signer};
use quil_types::error::Result;

/// Key manager trait for creating and loading cryptographic keys.
pub trait KeyManager: Send + Sync {
    /// Get the proving key ID configured for this node.
    fn get_proving_key_id(&self) -> &str;

    /// Get the signer for the given key type.
    fn get_signer(&self, key_type: KeyType) -> Result<Box<dyn Signer>>;

    /// Get the raw public key bytes for the given key type.
    fn get_public_key(&self, key_type: KeyType) -> Result<Vec<u8>>;

    /// Get the raw private key bytes for the given key type.
    fn get_private_key(&self, key_type: KeyType) -> Result<Vec<u8>>;

    /// Get the Ed448-derived peer ID.
    fn get_peer_id(&self) -> Result<Vec<u8>>;
}
