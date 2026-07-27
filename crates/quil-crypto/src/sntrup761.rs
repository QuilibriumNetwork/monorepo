//! sntrup761 (Streamlined NTRU Prime) KEM — post-quantum config read/encryption
//! keys, replacing X448.
//!
//! swaps the classical X448 config *read key* (the
//! key third parties encapsulate to when writing owner-readable data) for the
//! NTRU-Prime KEM `sntrup761`. NTRU-family (the assumption already trusted for
//! the Falcon signature primitive and the QUIC transport key-exchange), CPU-fast,
//! no proving. This module is just the keygen/encapsulate/decapsulate primitive;
//! the node stores the public key as config metadata and validates its length,
//! while wallet/config tooling generates the keypair and encapsulates to it.
//!
//! Sizes (PQClean, via `pqcrypto-ntruprime`): public key 1158 B, ciphertext
//! 1039 B, secret key 1763 B, shared secret 32 B.

use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

use quil_types::error::{QuilError, Result};

/// Encoded sntrup761 public-key length (1158 bytes) — the config read-key width.
pub const SNTRUP761_PUBLIC_KEY_LEN: usize = 1158;
/// Encoded sntrup761 secret-key length (1763 bytes).
pub const SNTRUP761_SECRET_KEY_LEN: usize = 1763;
/// Encoded sntrup761 ciphertext length (1039 bytes).
pub const SNTRUP761_CIPHERTEXT_LEN: usize = 1039;
/// KEM shared-secret length (32 bytes).
pub const SNTRUP761_SHARED_SECRET_LEN: usize = 32;

/// An sntrup761 keypair as raw encoded bytes (the config read key is `public`).
#[derive(Clone)]
pub struct Sntrup761KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Sntrup761KeyPair {
    /// Generate a fresh sntrup761 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = sntrup761::keypair();
        Sntrup761KeyPair { public: pk.as_bytes().to_vec(), secret: sk.as_bytes().to_vec() }
    }
}

/// Encapsulate to a config read key: returns `(shared_secret, ciphertext)`. The
/// writer derives an AEAD key from `shared_secret` and publishes `ciphertext`;
/// the owner recovers the same secret via [`decapsulate`].
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = sntrup761::PublicKey::from_bytes(public_key)
        .map_err(|_| QuilError::InvalidArgument("sntrup761: bad public key".into()))?;
    let (ss, ct) = sntrup761::encapsulate(&pk);
    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// Decapsulate a ciphertext with the owner's secret key, recovering the shared
/// secret the writer used.
pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let ct = sntrup761::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| QuilError::InvalidArgument("sntrup761: bad ciphertext".into()))?;
    let sk = sntrup761::SecretKey::from_bytes(secret_key)
        .map_err(|_| QuilError::InvalidArgument("sntrup761: bad secret key".into()))?;
    Ok(sntrup761::decapsulate(&ct, &sk).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_the_scheme() {
        assert_eq!(sntrup761::public_key_bytes(), SNTRUP761_PUBLIC_KEY_LEN);
        assert_eq!(sntrup761::secret_key_bytes(), SNTRUP761_SECRET_KEY_LEN);
        assert_eq!(sntrup761::ciphertext_bytes(), SNTRUP761_CIPHERTEXT_LEN);
        assert_eq!(sntrup761::shared_secret_bytes(), SNTRUP761_SHARED_SECRET_LEN);
    }

    #[test]
    fn encapsulate_then_decapsulate_agrees() {
        let kp = Sntrup761KeyPair::generate();
        assert_eq!(kp.public.len(), SNTRUP761_PUBLIC_KEY_LEN);
        assert_eq!(kp.secret.len(), SNTRUP761_SECRET_KEY_LEN);
        let (ss_a, ct) = encapsulate(&kp.public).unwrap();
        assert_eq!(ct.len(), SNTRUP761_CIPHERTEXT_LEN);
        assert_eq!(ss_a.len(), SNTRUP761_SHARED_SECRET_LEN);
        let ss_b = decapsulate(&ct, &kp.secret).unwrap();
        assert_eq!(ss_a, ss_b, "KEM round-trip yields the same shared secret");
    }

    #[test]
    fn wrong_key_rejected_cleanly() {
        assert!(encapsulate(&[0u8; 10]).is_err(), "malformed public key errors, not panics");
        assert!(decapsulate(&[0u8; 10], &[0u8; 10]).is_err(), "malformed inputs error");
    }
}
