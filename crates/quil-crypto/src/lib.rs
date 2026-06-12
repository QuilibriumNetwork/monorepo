mod bls;
mod bulletproof_adapter;
mod ed25519;
mod ed448;
#[cfg(feature = "vdf-prover")]
mod frame_prover;
mod inclusion;
mod key_manager;
pub mod poseidon;
mod secp256k1;

pub use bls::{Bls48581KeyConstructor, Bls48581Signer};
pub use bulletproof_adapter::Decaf448BulletproofProver;
pub use ed25519::{ed25519_verify, Ed25519Signer};
pub use ed448::{
    ed448_verify, peer_id_multihash_from_ed448_pubkey, Ed448Signer,
};
pub use secp256k1::{secp256k1_sha256_verify, secp256k1_sha3_verify, Secp256k1Signer};
#[cfg(feature = "vdf-prover")]
pub use frame_prover::WesolowskiFrameProver;
pub use inclusion::KzgInclusionProver;
pub use key_manager::DefaultKeyManager;
pub use poseidon::{hash_bytes_to_32, hash_elements};

/// Initialize the crypto subsystem. Must be called before any BLS operations.
pub fn init() {
    bls48581::init();
}
