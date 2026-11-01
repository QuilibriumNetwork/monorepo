// Copyright 2021 Lolo_32
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(feature = "docinclude", feature(external_doc))]
// Vendored from lolo32/ed448-rust 0.1.2. Its 2021 lint lists name clippy
// lints renamed or removed since, and its pedantic and nursery denies now
// catch newer lints. Allow those instead of restyling third-party code;
// this allow must precede the lists it covers.
#![allow(renamed_and_removed_lints)]
#![deny(
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unused_extern_crates,
    unused_qualifications,
    single_use_lifetimes,
    unused_import_braces,
    unused_lifetimes,
    unused_results,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![doc(
    test(no_crate_inject, attr(deny(warnings))),
    test(attr(allow(unused_variables))),
    html_no_source
)]
#![deny(
    clippy::absurd_extreme_comparisons,
    clippy::almost_swapped,
    clippy::approx_constant,
    clippy::async_yields_async,
    clippy::bad_bit_mask,
    clippy::cast_ref_to_mut,
    clippy::clone_double_ref,
    clippy::cmp_nan,
    clippy::deprecated_semver,
    clippy::derive_hash_xor_eq,
    clippy::derive_ord_xor_partial_ord,
    clippy::drop_copy,
    clippy::drop_ref,
    clippy::enum_clike_unportable_variant,
    clippy::eq_op,
    clippy::erasing_op,
    clippy::float_cmp,
    clippy::float_equality_without_abs,
    clippy::fn_address_comparisons,
    clippy::for_loops_over_fallibles,
    clippy::forget_copy,
    clippy::forget_ref,
    clippy::if_let_mutex,
    clippy::if_same_then_else,
    clippy::ifs_same_cond,
    clippy::ineffective_bit_mask,
    clippy::infinite_iter,
    clippy::inherent_to_string_shadow_display,
    clippy::inline_fn_without_body,
    clippy::invalid_atomic_ordering,
    clippy::invalid_regex,
    clippy::invisible_characters,
    clippy::iter_next_loop,
    clippy::iterator_step_by_zero,
    clippy::let_underscore_lock,
    clippy::logic_bug,
    clippy::mem_discriminant_non_enum,
    clippy::mem_replace_with_uninit,
    clippy::min_max,
    clippy::mismatched_target_os,
    clippy::mistyped_literal_suffixes,
    clippy::modulo_one,
    clippy::mut_from_ref,
    clippy::mutable_key_type,
    clippy::never_loop,
    clippy::nonsensical_open_options,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::option_env_unwrap,
    clippy::out_of_bounds_indexing,
    clippy::panicking_unwrap,
    clippy::possible_missing_comma,
    clippy::reversed_empty_ranges,
    clippy::self_assignment,
    clippy::serde_api_misuse,
    clippy::size_of_in_element_count,
    clippy::suspicious_arithmetic_impl,
    clippy::suspicious_op_assign_impl,
    clippy::to_string_in_display,
    clippy::transmuting_null,
    clippy::undropped_manually_drops,
    clippy::uninit_assumed_init,
    clippy::unit_cmp,
    clippy::unit_return_expecting_ord,
    clippy::unsound_collection_transmute,
    clippy::unused_io_amount,
    clippy::useless_attribute,
    clippy::vec_resize_to_zero,
    clippy::vtable_address_comparisons,
    clippy::while_immutable_condition,
    clippy::wrong_transmute,
    clippy::zst_offset
)]
#![allow(
    non_snake_case,
    non_upper_case_globals,
    clippy::similar_names,
    clippy::module_name_repetitions
)]
// Newer clippy lints escalated by the denies above (see the note there).
#![allow(
    clippy::doc_markdown,
    clippy::needless_borrows_for_generic_args,
    clippy::non_std_lazy_statics
)]

//! # EdDSA implementation for ed448
//!
//! This is a Edwards-Curve Digital Signature Algorithm (EdDSA) for ed448 only
//! in pure rust.
//!
//! # Usage
//!
//! There is two variants that can be combined to sign/verify:
//!
//! 1. [`PrivateKey::sign`](crate::PrivateKey::sign) to sign all the content
//!    as-it and [`PrivateKey::sign_ph`](crate::PrivateKey::sign_ph) to
//!    pre-hash the message internaly before signing it. It will be hashed
//!    using Shake256 and the result of 64 byte will be signed/verified.
//!    
//!    Note: use the same variant for verifying the signature.
//!
//! 2. The second parameter of [`sign`](crate::PrivateKey::sign)/
//!    [`sign_ph`](crate::PrivateKey::sign_ph) and the third of
//!    [`verify`](crate::PublicKey::verify)/
//!    [`verify_ph`](crate::PublicKey::verify_ph) if an optional context
//!    of 255 byte length max.
//!    
//!    The context can be used to facilitate different signature over
//!    different protocol, but it must be immuable over the protocol.
//!    More information about this can be found at
//!    [RFC 8032 Use of Contexts](https://tools.ietf.org/html/rfc8032#section-8.3).
//!
//! # Examples
//!
//! ## Generating a new key pair
//!
//! ```
//! use rand_core::OsRng;
//! use ed448_rust::{PrivateKey, PublicKey};
//! let private_key = PrivateKey::new(&mut OsRng);
//! let public_key = PublicKey::from(&private_key);
//! ```
//!
//! ## Sign a message
//!
//! ```
//! # use rand_core::OsRng;
//! use ed448_rust::{PrivateKey, Ed448Error};
//! # let retrieve_pkey = || PrivateKey::new(&mut OsRng);
//! let message = b"Message to sign";
//! let private_key = retrieve_pkey();
//! match private_key.sign(message, None) {
//!     Ok(signature) => {
//!         // Signature OK, use it
//!         // This is a slice of 144 byte length
//!     }
//!     Err(Ed448Error::ContextTooLong) => {
//!         // The used context is more than 255 bytes length
//!     }
//!     Err(_) => unreachable!()
//! }
//! ```
//!
//! ## Verify a signature
//!
//! ```
//! # use rand_core::OsRng;
//! use ed448_rust::{PublicKey, Ed448Error};
//! # let private_key = ed448_rust::PrivateKey::new(&mut OsRng);
//! let message = b"Signed message to verify";
//! # let retrieve_signature = || private_key.sign(message, None).unwrap();
//! # let retrieve_pubkey = || PublicKey::from(&private_key);
//! let public_key = retrieve_pubkey(); // A slice or array of KEY_LENGTH byte length
//! let signature = retrieve_signature(); // A slice or array of SIG_LENGTH byte length
//! match public_key.verify(message, &signature, None) {
//!     Ok(()) => {
//!         // Signature OK, use the message
//!     }
//!     Err(Ed448Error::InvalidSignature) => {
//!         // The verification of the signature is invalid
//!     }
//!     Err(Ed448Error::ContextTooLong) => {
//!         // The used context is more than 255 bytes length
//!     }
//!     Err(Ed448Error::WrongSignatureLength) => {
//!         // The signature is not 144 bytes length
//!     }
//!     Err(_) => unreachable!()
//! }
//! ```

use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

pub use crate::error::Ed448Error;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
use std::borrow::Cow;

mod error;
mod point;
mod private_key;
mod public_key;

#[allow(
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations
)]
#[doc(hidden)]
#[cfg_attr(feature = "docinclude", doc(include = "../README.md"))]
pub struct ReadmeDoctests;

/// Specialized [`Result`](core::result::Result) for this crate.
pub type Result<T> = core::result::Result<T, Ed448Error>;

/// Length of either a public or a private key length in byte.
pub const KEY_LENGTH: usize = 57;
/// Length of the signature length in byte.
pub const SIG_LENGTH: usize = 114;

/// Indicate if the message need to be pre-hashed before being signed/verified
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum PreHash {
    /// Pre-hash the message
    True,
    /// Leave the message unchanged
    False,
}

impl From<PreHash> for u8 {
    #[inline]
    fn from(hash: PreHash) -> Self {
        match hash {
            PreHash::False => 0,
            PreHash::True => 1,
        }
    }
}

/// Produce a Shake256 for signing/verifying signatures
fn shake256(items: Vec<&[u8]>, ctx: &[u8], pre_hash: PreHash) -> Box<[u8]> {
    #[allow(clippy::cast_possible_truncation)]
    let mut shake = Shake256::default()
        .chain(b"SigEd448")
        .chain(&[pre_hash.into(), ctx.len() as u8])
        .chain(ctx);
    for item in items {
        shake.update(item);
    }
    shake.finalize_boxed(114)
}

/// Common tasks for signing/verifying
#[allow(clippy::type_complexity)]
fn init_sig<'a, 'b>(
    ctx: Option<&'b [u8]>,
    pre_hash: PreHash,
    msg: &'a [u8],
) -> Result<(Cow<'b, [u8]>, Cow<'a, [u8]>)> {
    let ctx = ctx.unwrap_or(b"");
    if ctx.len() > 255 {
        return Err(Ed448Error::ContextTooLong);
    }
    let ctx = Cow::Borrowed(ctx);

    let msg = match pre_hash {
        PreHash::False => Cow::Borrowed(msg),
        PreHash::True => {
            let hash = Shake256::default().chain(msg).finalize_boxed(64).to_vec();
            Cow::Owned(hash)
        }
    };

    Ok((ctx, msg))
}
