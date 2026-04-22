mod bls;
mod bulletproof_adapter;
#[cfg(feature = "vdf-prover")]
mod frame_prover;
mod inclusion;
mod key_manager;
pub mod poseidon;

pub use bls::{Bls48581KeyConstructor, Bls48581Signer};
pub use bulletproof_adapter::Decaf448BulletproofProver;
#[cfg(feature = "vdf-prover")]
pub use frame_prover::WesolowskiFrameProver;
pub use inclusion::KzgInclusionProver;
pub use key_manager::DefaultKeyManager;
pub use poseidon::{hash_bytes_to_32, hash_elements};

/// Initialize the crypto subsystem. Must be called before any BLS operations.
pub fn init() {
    bls48581::init();
}
