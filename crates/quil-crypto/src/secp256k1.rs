//! Secp256k1 ECDSA signer wrapping the `k256` crate. Two variants
//! per Quilibrium's KeyType enum:
//!
//! - `Secp256k1Sha256`: ECDSA-secp256k1 with SHA-256 pre-hash (the
//!   standard Bitcoin-style ECDSA).
//! - `Secp256k1Sha3`: same curve, but pre-hash with SHA3-256.
//!
//! Both produce 64-byte fixed-length raw signatures (r || s, big
//! endian, 32 bytes each).

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use quil_types::crypto::{KeyType, Signer};
use quil_types::error::{QuilError, Result};
use sha2::Digest as _;

/// Pre-hash variant a `Secp256k1Signer` runs on the message before ECDSA.
#[derive(Clone, Copy)]
enum Hash {
    Sha256,
    Sha3,
}

/// Secp256k1 ECDSA signer. 32-byte secret, 33-byte compressed pubkey,
/// 64-byte raw signature.
pub struct Secp256k1Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    hash: Hash,
    key_type: KeyType,
}

impl Secp256k1Signer {
    /// Construct a SHA-256-prehash secp256k1 signer.
    pub fn sha256(private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        Self::new(private_key, public_key, Hash::Sha256, KeyType::Secp256k1Sha256)
    }

    /// Construct a SHA3-256-prehash secp256k1 signer.
    pub fn sha3(private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        Self::new(private_key, public_key, Hash::Sha3, KeyType::Secp256k1Sha3)
    }

    fn new(
        private_key: &[u8],
        public_key: &[u8],
        hash: Hash,
        key_type: KeyType,
    ) -> Result<Self> {
        if private_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "Secp256k1: invalid private key length {}",
                private_key.len()
            )));
        }
        // Accept compressed (33) and uncompressed (65) pubkeys; store
        // whatever was provided so callers see what they handed us.
        if public_key.len() != 33 && public_key.len() != 65 {
            return Err(QuilError::Crypto(format!(
                "Secp256k1: invalid public key length {} (expected 33 or 65)",
                public_key.len()
            )));
        }
        Ok(Self {
            secret_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            hash,
            key_type,
        })
    }

    /// Derive the 33-byte compressed public key from a 32-byte private key.
    pub fn derive_public(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "Secp256k1: invalid private key length {}",
                private_key.len()
            )));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(private_key);
        let sk = SigningKey::from_bytes(&sk_bytes.into())
            .map_err(|e| QuilError::Crypto(format!("Secp256k1: invalid private key: {}", e)))?;
        Ok(sk.verifying_key().to_encoded_point(true).as_bytes().to_vec())
    }

    fn prehash(&self, domain: &[u8], message: &[u8]) -> [u8; 32] {
        match self.hash {
            Hash::Sha256 => {
                let mut h = sha2::Sha256::new();
                if !domain.is_empty() {
                    h.update(domain);
                }
                h.update(message);
                let out = h.finalize();
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&out);
                buf
            }
            Hash::Sha3 => {
                let mut h = sha3::Sha3_256::new();
                if !domain.is_empty() {
                    h.update(domain);
                }
                h.update(message);
                let out = h.finalize();
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&out);
                buf
            }
        }
    }
}

impl Signer for Secp256k1Signer {
    fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn private_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_domain(message, &[])
    }

    fn sign_with_domain(&self, message: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&self.secret_key);
        let sk = SigningKey::from_bytes(&sk_bytes.into())
            .map_err(|e| QuilError::Crypto(format!("Secp256k1: invalid private key: {}", e)))?;
        let digest = self.prehash(domain, message);
        let sig: Signature = sk
            .sign_prehash(&digest)
            .map_err(|e| QuilError::Crypto(format!("Secp256k1 sign failed: {}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }
}

/// Verify a secp256k1 ECDSA signature with the given pre-hash variant.
/// `pubkey` may be 33 (compressed) or 65 (uncompressed) bytes;
/// `signature` must be 64 bytes (r || s).
fn verify(
    pubkey: &[u8],
    message: &[u8],
    domain: &[u8],
    signature: &[u8],
    use_sha3: bool,
) -> bool {
    if signature.len() != 64 {
        return false;
    }
    if pubkey.len() != 33 && pubkey.len() != 65 {
        return false;
    }
    let vk = match VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let digest: [u8; 32] = if use_sha3 {
        let mut h = sha3::Sha3_256::new();
        if !domain.is_empty() {
            h.update(domain);
        }
        h.update(message);
        h.finalize().into()
    } else {
        let mut h = sha2::Sha256::new();
        if !domain.is_empty() {
            h.update(domain);
        }
        h.update(message);
        h.finalize().into()
    };
    vk.verify_prehash(&digest, &sig).is_ok()
}

/// Verify a SHA-256-prehash ECDSA signature.
pub fn secp256k1_sha256_verify(
    pubkey: &[u8],
    message: &[u8],
    domain: &[u8],
    signature: &[u8],
) -> bool {
    verify(pubkey, message, domain, signature, false)
}

/// Verify a SHA3-256-prehash ECDSA signature.
pub fn secp256k1_sha3_verify(
    pubkey: &[u8],
    message: &[u8],
    domain: &[u8],
    signature: &[u8],
) -> bool {
    verify(pubkey, message, domain, signature, true)
}
