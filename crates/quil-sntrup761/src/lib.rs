//! Streamlined NTRU Prime (sntrup761), and the one place the workspace reaches
//! its KEM backend.
//!
//! These bytes reach the wire (QUIC key exchange, PQNoise, onion cells), the
//! chain (coin memos, confidential fields, read keys) and wallets (the recipient
//! seed hashes the raw secret key), so a backend change must be byte-exact.
//! `tests/kat.rs` pins keygen, encapsulation, decapsulation, implicit rejection
//! and the secret-key layout to vectors frozen from the current backend and to
//! published ones.
//!
//! The backend is `pqcrypto-ntruprime` 0.1.6, a PQClean snapshot of
//! supercop-20210604 with AVX2 selected at run time. That crate and PQClean are
//! unmaintained, and no independent audit of this code is known.
//!
//! Secret keys and shared secrets live in [`Zeroizing`] buffers here. The
//! backend's own temporaries and return values are not erased.

use pqcrypto_ntruprime::sntrup761 as backend;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
pub use zeroize::Zeroizing;

/// Encoded public-key length.
pub const PUBLIC_KEY_LEN: usize = 1158;
/// Encoded secret-key length.
pub const SECRET_KEY_LEN: usize = 1763;
/// Encoded ciphertext length.
pub const CIPHERTEXT_LEN: usize = 1039;
/// Shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32;

const _: () = assert!(PUBLIC_KEY_LEN == backend::public_key_bytes());
const _: () = assert!(SECRET_KEY_LEN == backend::secret_key_bytes());
const _: () = assert!(CIPHERTEXT_LEN == backend::ciphertext_bytes());
const _: () = assert!(SHARED_SECRET_LEN == backend::shared_secret_bytes());

/// An input of the wrong length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadLength {
                name,
                actual,
                expected,
            } => write!(f, "sntrup761 {name}: {actual} bytes, expected {expected}"),
        }
    }
}

impl std::error::Error for Error {}

fn bad_length(name: &'static str, actual: usize, expected: usize) -> Error {
    Error::BadLength {
        name,
        actual,
        expected,
    }
}

/// An encoded public key. Any bytes of the right length are accepted, as the
/// scheme's decoding is total.
#[derive(Clone)]
pub struct PublicKey(backend::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        backend::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| bad_length("PublicKey", bytes.len(), PUBLIC_KEY_LEN))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// An encoded ciphertext. Any bytes of the right length are accepted: one that
/// was not made for this key decapsulates to an unrelated secret (implicit
/// rejection), never to an error.
#[derive(Clone)]
pub struct Ciphertext(backend::Ciphertext);

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        backend::Ciphertext::from_bytes(bytes)
            .map(Self)
            .map_err(|_| bad_length("Ciphertext", bytes.len(), CIPHERTEXT_LEN))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// An encoded secret key, erased on drop. Always [`SECRET_KEY_LEN`] bytes.
pub struct SecretKey(Zeroizing<Vec<u8>>);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(bad_length("SecretKey", bytes.len(), SECRET_KEY_LEN));
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A shared secret, erased on drop.
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl SharedSecret {
    fn from_backend(secret: &backend::SharedSecret) -> Self {
        let mut bytes = Zeroizing::new([0; SHARED_SECRET_LEN]);
        bytes.copy_from_slice(secret.as_bytes());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Generate a keypair from the system's randomness.
pub fn keypair() -> (PublicKey, SecretKey) {
    let (public, secret) = backend::keypair();
    (
        PublicKey(public),
        SecretKey(Zeroizing::new(secret.as_bytes().to_vec())),
    )
}

/// Encapsulate to `public` with the system's randomness.
pub fn encapsulate(public: &PublicKey) -> (SharedSecret, Ciphertext) {
    let (shared, ciphertext) = backend::encapsulate(&public.0);
    (SharedSecret::from_backend(&shared), Ciphertext(ciphertext))
}

/// Decapsulate `ciphertext`. The result is always a secret; only a ciphertext
/// made for this key gives the sender's.
pub fn decapsulate(ciphertext: &Ciphertext, secret: &SecretKey) -> SharedSecret {
    let secret = backend::SecretKey::from_bytes(secret.as_bytes())
        .expect("SecretKey holds exactly SECRET_KEY_LEN bytes");
    SharedSecret::from_backend(&backend::decapsulate(&ciphertext.0, &secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This binary links the real randomness, unlike `tests/kat.rs`.
    #[test]
    fn round_trip_draws_fresh_randomness() {
        let (public_a, secret_a) = keypair();
        let (public_b, _) = keypair();
        assert_ne!(public_a.as_bytes(), public_b.as_bytes());
        let (shared_a, ciphertext_a) = encapsulate(&public_a);
        let (_, ciphertext_b) = encapsulate(&public_a);
        assert_ne!(ciphertext_a.as_bytes(), ciphertext_b.as_bytes());
        assert_eq!(
            decapsulate(&ciphertext_a, &secret_a).as_bytes(),
            shared_a.as_bytes()
        );
    }
}
