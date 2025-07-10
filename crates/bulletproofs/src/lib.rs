extern crate alloc;

#[macro_use]
extern crate serde_derive;

// Curve adaptation layer (Ed448 replacement for Ristretto/Ed25519)
pub mod curve_adapter;

mod util;

mod notes {
    mod inner_product_proof {}
    mod range_proof {}
    mod r1cs_proof {}
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

#[cfg(feature = "yoloproofs")]
pub mod r1cs;

pub mod uniffi_bulletproofs;

pub use crate::uniffi_bulletproofs::{RangeProofResult, generate_input_commitments, generate_range_proof, verify_range_proof, sum_check, scalar_mult_point, scalar_mult, scalar_inverse, keygen, scalar_mult_hash_to_scalar, hash_to_scalar, scalar_addition, scalar_subtraction, scalar_to_point, alt_generator, point_addition, point_subtraction, sign_hidden, verify_hidden, sign_simple, verify_simple};

// UniFFI bindings - exclude for WASM targets
#[cfg(not(target_arch = "wasm32"))]
uniffi::include_scaffolding!("lib");
