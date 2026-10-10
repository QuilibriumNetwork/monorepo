// Copyright 2019 Parity Technologies (UK) Ltd.
// Copyright 2023 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! A node's network identity keys.
//!
//! Such identity keys can be randomly generated on every startup,
//! but using already existing, fixed keys is usually required.
//! Though libp2p uses other crates (e.g. `ed25519_dalek`) internally,
//! such details are not exposed as part of libp2p's public interface
//! to keep them easily upgradable or replaceable (e.g. to `ed25519_zebra`).
//! Consequently, keys of external ed25519 or secp256k1 crates cannot be
//! directly converted into libp2p network identities.
//! Instead, loading fixed keys must use the standard, thus more portable
//! binary representation of the specific key type
//! (e.g. [ed25519 binary format](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5)).
//! All key types have functions to enable conversion to/from their binary representations.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(unreachable_pub)]

// Quilibrium REQUIRES the Falcon (FN-DSA-512, libp2p `KeyType = 5`) key type:
// it is the network peer identity (the `q-prover-key`). This fork is only ever
// built as part of the Quilibrium workspace, where Falcon must always be
// present — otherwise `KeyType = 5` peer keys silently fail to decode (the
// match arm below is `#[cfg]`'d out) and the node cannot parse any peer.
//
// `falcon` is a DEFAULT feature (see Cargo.toml), so it is on unless a consumer
// explicitly passes `default-features = false` without re-enabling it. This
// tripwire converts that mistake — or a feature-unification / patch-resolution
// slip that drops `falcon` — from a silent, confusing runtime failure into a
// loud, actionable build failure. Do NOT relax it: if you hit this, add
// `falcon` back to the `libp2p-identity` dependency's feature list.
#[cfg(not(feature = "falcon"))]
compile_error!(
    "libp2p-identity was built WITHOUT the `falcon` feature, but Quilibrium \
     mandates the Falcon (KeyType=5) network identity. Enable it on the \
     `libp2p-identity` dependency (`features = [\"falcon\", ...]`) or keep \
     default features enabled — do not build with `default-features = false` \
     unless you re-add `falcon`."
);

#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "ed448",
    feature = "falcon",
    feature = "rsa"
))]
mod proto {
    include!("generated/mod.rs");
    pub(crate) use self::keys_proto::*;
}

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "ed448")]
pub mod ed448;

#[cfg(feature = "falcon")]
pub mod falcon;

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
pub mod rsa;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

mod error;
mod keypair;
#[cfg(feature = "peerid")]
mod peer_id;

#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "ed448",
    feature = "falcon",
    feature = "rsa"
))]
impl zeroize::Zeroize for proto::PrivateKey {
    fn zeroize(&mut self) {
        self.Data.zeroize();
    }
}

#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "ed448",
    feature = "falcon",
    feature = "rsa"
))]
impl From<&PublicKey> for proto::PublicKey {
    fn from(key: &PublicKey) -> Self {
        match &key.publickey {
            #[cfg(feature = "ed25519")]
            keypair::PublicKeyInner::Ed25519(key) => proto::PublicKey {
                Type: proto::KeyType::Ed25519,
                Data: key.to_bytes().to_vec(),
            },
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            keypair::PublicKeyInner::Rsa(key) => proto::PublicKey {
                Type: proto::KeyType::RSA,
                Data: key.encode_x509(),
            },
            #[cfg(feature = "secp256k1")]
            keypair::PublicKeyInner::Secp256k1(key) => proto::PublicKey {
                Type: proto::KeyType::Secp256k1,
                Data: key.to_bytes().to_vec(),
            },
            #[cfg(feature = "ecdsa")]
            keypair::PublicKeyInner::Ecdsa(key) => proto::PublicKey {
                Type: proto::KeyType::ECDSA,
                Data: key.encode_der(),
            },
            #[cfg(feature = "ed448")]
            keypair::PublicKeyInner::Ed448(key) => proto::PublicKey {
                Type: proto::KeyType::Ed448,
                Data: key.to_bytes(),
            },
            #[cfg(feature = "falcon")]
            keypair::PublicKeyInner::Falcon(key) => proto::PublicKey {
                Type: proto::KeyType::Falcon,
                Data: key.to_bytes(),
            },
        }
    }
}

pub use error::{DecodingError, OtherVariantError, SigningError};
pub use keypair::{Keypair, PublicKey};
#[cfg(feature = "peerid")]
pub use peer_id::{ParseError, PeerId};

/// The type of key a `KeyPair` is holding.
#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum KeyType {
    Ed25519,
    RSA,
    Secp256k1,
    Ecdsa,
    Ed448,
    Falcon,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => f.write_str("Ed25519"),
            KeyType::RSA => f.write_str("RSA"),
            KeyType::Secp256k1 => f.write_str("Secp256k1"),
            KeyType::Ecdsa => f.write_str("Ecdsa"),
            KeyType::Ed448 => f.write_str("Ed448"),
            KeyType::Falcon => f.write_str("Falcon"),
        }
    }
}
