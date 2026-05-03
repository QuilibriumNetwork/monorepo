//! Ed25519 signer wrapping the `ed25519-dalek` crate. Used for
//! qclient/admin operations that sign with non-prover keys.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use quil_types::crypto::{KeyType, Signer};
use quil_types::error::{QuilError, Result};

/// Ed25519 signer. 32-byte secret seed, 32-byte public, 64-byte signature.
pub struct Ed25519Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Ed25519Signer {
    /// Construct from a stored 32-byte private seed and matching 32-byte
    /// public key.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        if private_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "Ed25519: invalid private key length {}",
                private_key.len()
            )));
        }
        if public_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "Ed25519: invalid public key length {}",
                public_key.len()
            )));
        }
        Ok(Self {
            secret_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        })
    }

    /// Derive the 32-byte public key from a 32-byte private seed.
    /// Useful when the keystore only carries the secret half.
    pub fn derive_public(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "Ed25519: invalid private key length {}",
                private_key.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(private_key);
        let sk = SigningKey::from_bytes(&seed);
        Ok(sk.verifying_key().to_bytes().to_vec())
    }
}

impl Signer for Ed25519Signer {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
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
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.secret_key);
        let sk = SigningKey::from_bytes(&seed);
        // Ed25519 has no native context parameter; we prefix the
        // message with the domain so signatures over the same payload
        // under different domains are distinct.
        let mut buf = Vec::with_capacity(domain.len() + message.len());
        buf.extend_from_slice(domain);
        buf.extend_from_slice(message);
        let sig = sk.sign(&buf);
        Ok(sig.to_bytes().to_vec())
    }
}

/// Verify an Ed25519 signature, with the same domain-prefixing
/// convention used by `Ed25519Signer::sign_with_domain`. Pass `&[]` for
/// the domain to verify a signature produced with `sign`.
pub fn ed25519_verify(pubkey: &[u8], message: &[u8], domain: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(pubkey);
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let mut buf = Vec::with_capacity(domain.len() + message.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(message);
    vk.verify(&buf, &sig).is_ok()
}
