//! Ed448 key support for libp2p identity (KeyType=4).

use crate::error::{DecodingError, SigningError};
use crate::KeyType;

/// An Ed448 keypair.
#[derive(Clone)]
pub struct Keypair {
    private: ed448_rust::PrivateKey,
    public: PublicKey,
}

/// An Ed448 public key (wrapper to impl Eq/Hash/Ord).
#[derive(Clone)]
pub struct PublicKey {
    inner: ed448_rust::PublicKey,
    bytes: [u8; 57],
}

impl Keypair {
    /// Generate a new random Ed448 keypair.
    pub fn generate() -> Self {
        let private = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
        let public = PublicKey::from_inner(ed448_rust::PublicKey::from(&private));
        Self { private, public }
    }

    /// Construct from raw private key bytes (57 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodingError> {
        let private = ed448_rust::PrivateKey::try_from(bytes)
            .map_err(|_| DecodingError::missing_feature("ed448"))?;
        let public = PublicKey::from_inner(ed448_rust::PublicKey::from(&private));
        Ok(Self { private, public })
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.private
            .sign(msg, None)
            .map(|sig| sig.to_vec())
            .map_err(|_| SigningError::new("Ed448 signing failed"))
    }

    /// Get the public key.
    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    /// Get raw private key bytes (57 bytes).
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.private.as_bytes().to_vec()
    }
}

impl PublicKey {
    fn from_inner(inner: ed448_rust::PublicKey) -> Self {
        let bytes = inner.as_byte();
        Self { inner, bytes }
    }

    /// Verify a signature.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.inner.verify(msg, sig, None).is_ok()
    }

    /// Encode to raw bytes (57 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Decode from raw bytes (57 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodingError> {
        if bytes.len() != 57 {
            return Err(DecodingError::missing_feature("ed448"));
        }
        let mut arr = [0u8; 57];
        arr.copy_from_slice(bytes);
        // `PublicKey::from([u8;57])` PANICS on any 57 bytes that aren't a valid
        // curve point — and this decodes an attacker-supplied protobuf wire key,
        // so a panic here is a remote DoS. Use the fallible `TryFrom` instead.
        let inner = ed448_rust::PublicKey::try_from(&arr[..])
            .map_err(|_| DecodingError::missing_feature("ed448"))?;
        // Signatures nobody made verify under a key of small order, so anyone
        // could speak as its peer ID.
        if inner.has_small_order() {
            return Err(DecodingError::missing_feature("ed448"));
        }
        Ok(Self { inner, bytes: arr })
    }

    /// Get the key type.
    pub fn key_type(&self) -> KeyType {
        KeyType::Ed448
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed448Keypair").finish()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed448PublicKey(57 bytes)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The neutral element as an identity key: under the cofactored check
    /// `R = O`, `S = 0` verifies every message, so anyone could sign as its
    /// peer ID.
    #[test]
    fn reproduces_small_order_identity_key_signed_by_anyone() {
        let mut neutral = [0u8; 57];
        neutral[0] = 1;
        let mut forged = [0u8; 114];
        forged[0] = 1;
        let decoded = PublicKey::from_bytes(&neutral);
        let forged_verifies = decoded
            .as_ref()
            .is_ok_and(|key| key.verify(b"any message", &forged));
        assert!(
            decoded.is_err() && !forged_verifies,
            "a small-order Ed448 identity key was accepted; a signature nobody made verifies \
             under it: {forged_verifies}"
        );
        let keypair = Keypair::generate();
        assert!(PublicKey::from_bytes(&keypair.public().to_bytes()).is_ok());
    }
}
