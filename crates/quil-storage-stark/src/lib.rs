//! STARK proofs over the hash storage proofs of
//! [`quil_crypto::storage_proof`]: a member proves its seals (and, later,
//! its possession openings) once per epoch, and GLOBAL verifies one short
//! proof instead of every opening. Plonky3 over KoalaBear with Poseidon2;
//! hash-based throughout, so post-quantum up to generic attacks.

pub mod config;
mod poseidon;
pub mod seal;

#[cfg(test)]
mod tests;
