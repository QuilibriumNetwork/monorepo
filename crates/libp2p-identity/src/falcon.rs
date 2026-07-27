//! Falcon (FN-DSA-512) key support for libp2p identity (KeyType=5).
//!
//! Post-quantum peer identities based on the NTRU-lattice Falcon / FN-DSA
//! scheme (Pornin's `fn-dsa` crate, pure Rust). Falcon-512 sizes: signing key
//! 1281 B, verifying (public) key 897 B, signature 666 B. Verification is
//! CPU-fast and constant-time; the floating-point risk is confined to signing.
//!
//! Wire format: the protobuf `PublicKey.Data` carries the 897-byte encoded
//! verifying key; `PrivateKey.Data` carries the 1281-byte encoded signing key.

use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};

use crate::error::{DecodingError, SigningError};
use crate::KeyType;

/// Falcon degree we use everywhere: FN-DSA-512 (897 B public / 666 B sig).
const LOGN: u32 = FN_DSA_LOGN_512;

/// Encoded signing-key length for FN-DSA-512 (1281 bytes).
pub const SIGNING_KEY_LEN: usize = sign_key_size(FN_DSA_LOGN_512);
/// Encoded verifying-key length for FN-DSA-512 (897 bytes).
pub const PUBLIC_KEY_LEN: usize = vrfy_key_size(FN_DSA_LOGN_512);

/// A Falcon (FN-DSA-512) keypair.
#[derive(Clone)]
pub struct Keypair {
    /// Encoded signing key (1281 bytes).
    signing_key: Vec<u8>,
    public: PublicKey,
}

/// A Falcon (FN-DSA-512) public key (encoded verifying key, 897 bytes).
#[derive(Clone)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl Keypair {
    /// Generate a new random Falcon-512 keypair.
    pub fn generate() -> Self {
        let mut kg = KeyPairGeneratorStandard::default();
        let mut signing_key = vec![0u8; sign_key_size(LOGN)];
        let mut vrfy_key = vec![0u8; vrfy_key_size(LOGN)];
        kg.keygen(LOGN, &mut rand::thread_rng(), &mut signing_key, &mut vrfy_key);
        Self {
            signing_key,
            public: PublicKey { bytes: vrfy_key },
        }
    }

    /// Construct from raw encoded signing-key bytes (1281 bytes). The public
    /// key is recomputed from the signing key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodingError> {
        let sk = SigningKeyStandard::decode(bytes)
            .ok_or_else(|| DecodingError::missing_feature("falcon"))?;
        let mut vrfy_key = vec![0u8; vrfy_key_size(sk.get_logn())];
        sk.to_verifying_key(&mut vrfy_key);
        Ok(Self {
            signing_key: bytes.to_vec(),
            public: PublicKey { bytes: vrfy_key },
        })
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut sk = SigningKeyStandard::decode(&self.signing_key)
            .ok_or_else(|| SigningError::new("Falcon signing key decode failed"))?;
        let mut sig = vec![0u8; signature_size(sk.get_logn())];
        sk.sign(&mut rand::thread_rng(), &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig);
        Ok(sig)
    }

    /// Get the public key.
    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    /// Get raw encoded signing-key bytes (1281 bytes).
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing_key.clone()
    }
}

impl PublicKey {
    /// Verify a signature.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match VerifyingKeyStandard::decode(&self.bytes) {
            Some(vk) => vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
            None => false,
        }
    }

    /// Encode to raw bytes (897 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Decode from raw bytes (897 bytes). Validates by decoding the key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodingError> {
        VerifyingKeyStandard::decode(bytes)
            .ok_or_else(|| DecodingError::missing_feature("falcon"))?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get the key type.
    pub fn key_type(&self) -> KeyType {
        KeyType::Falcon
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
        f.debug_struct("FalconKeypair").finish()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconPublicKey({} bytes)", self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_sizes_are_falcon_512() {
        assert_eq!(SIGNING_KEY_LEN, 1281);
        assert_eq!(PUBLIC_KEY_LEN, 897);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"quilibrium falcon identity";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), signature_size(LOGN));
        assert!(kp.public().verify(msg, &sig));
        // Wrong message fails.
        assert!(!kp.public().verify(b"tampered", &sig));
        // Garbage signature fails, doesn't panic.
        assert!(!kp.public().verify(msg, &[0u8; 666]));
    }

    #[test]
    fn signing_key_roundtrip_recovers_public() {
        let kp = Keypair::generate();
        let sk_bytes = kp.secret_bytes();
        assert_eq!(sk_bytes.len(), SIGNING_KEY_LEN);
        let kp2 = Keypair::from_bytes(&sk_bytes).unwrap();
        // Recovered public key matches.
        assert_eq!(kp.public().to_bytes(), kp2.public().to_bytes());
        // And still verifies signatures made by the original.
        let sig = kp.sign(b"x").unwrap();
        assert!(kp2.public().verify(b"x", &sig));
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public();
        let pk2 = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(pk2.key_type(), KeyType::Falcon);
    }
}
