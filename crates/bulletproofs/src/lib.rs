extern crate alloc;

#[macro_use]
extern crate serde_derive;

// Curve adaptation layer (Ed448 replacement for Ristretto/Ed25519)
pub mod curve_adapter;

mod util;

mod notes {
    mod inner_product_proof {}
    mod range_proof {}
}

mod errors;
mod generators;
mod inner_product_proof;
mod linear_proof;
mod range_proof;
mod transcript;

pub use crate::errors::ProofError;
pub use crate::generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use crate::linear_proof::LinearProof;
pub use crate::range_proof::RangeProof;

pub mod range_proof_mpc {
    pub use crate::errors::MPCError;
    pub use crate::range_proof::dealer;
    pub use crate::range_proof::messages;
    pub use crate::range_proof::party;
}

pub mod uniffi_bulletproofs;

pub use crate::uniffi_bulletproofs::{
    alt_generator, generate_input_commitments, generate_range_proof, hash_to_scalar, keygen,
    point_addition, point_subtraction, scalar_addition, scalar_inverse, scalar_mult,
    scalar_mult_hash_to_scalar, scalar_mult_point, scalar_subtraction, scalar_to_point,
    sign_hidden, sign_simple, sum_check, verify_hidden, verify_range_proof, verify_simple,
    RangeProofResult,
};

// UniFFI bindings - exclude for WASM targets
#[cfg(all(feature = "uniffi-bindings", not(target_arch = "wasm32")))]
uniffi::include_scaffolding!("lib");
