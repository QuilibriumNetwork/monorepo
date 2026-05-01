//! Ed448 signer wrapping the `ed448-rust` crate, used for peer
//! identity and KeyRegistry cross-signatures. Mirrors Go's
//! `crypto.KeyTypeEd448` path.
//!
//! `domain` is passed through as the Ed448 context parameter (per
//! RFC 8032 §8.3), matching how `DefaultKeyManager` verifies these
//! signatures in `key_manager.rs`.

use ed448_rust::{PrivateKey, PublicKey};
use quil_types::crypto::{KeyType, Signer};
use quil_types::error::{QuilError, Result};

/// Ed448 signer. 57-byte secret, 57-byte public, 114-byte signature.
pub struct Ed448Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Ed448Signer {
    /// Construct an Ed448 signer from a stored 57-byte private key and
    /// its matching 57-byte public key.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        if private_key.len() != 57 {
            return Err(QuilError::Crypto(format!(
                "Ed448: invalid private key length {}",
                private_key.len()
            )));
        }
        if public_key.len() != 57 {
            return Err(QuilError::Crypto(format!(
                "Ed448: invalid public key length {}",
                public_key.len()
            )));
        }
        Ok(Self {
            secret_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        })
    }

    /// Derive the 57-byte Ed448 public key from a 57-byte private key
    /// by running SHAKE-256 expansion per RFC 8032. Useful when the
    /// keystore only has the private half.
    pub fn derive_public(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != 57 {
            return Err(QuilError::Crypto(format!(
                "Ed448: invalid private key length {}",
                private_key.len()
            )));
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(private_key);
        let sk = PrivateKey::from(seed);
        let pk: PublicKey = (&sk).into();
        Ok(pk.as_byte().to_vec())
    }
}

impl Signer for Ed448Signer {
    fn key_type(&self) -> KeyType {
        KeyType::Ed448
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
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&self.secret_key);
        let sk = PrivateKey::from(seed);
        let ctx = if domain.is_empty() { None } else { Some(domain) };
        let sig = sk
            .sign(message, ctx)
            .map_err(|e| QuilError::Crypto(format!("Ed448 sign failed: {:?}", e)))?;
        Ok(sig.to_vec())
    }
}

/// Verify an Ed448 signature with an empty context (RFC 8032 Ed448 pure,
/// ctx = ""). Matches Go `ed448.Verify(pubkey, msg, sig, "")` used by the
/// legacy pre-2.1 pending-transaction verifier.
///
/// `pubkey` must be 57 bytes; `signature` must be 114 bytes. Any other
/// length — or a pubkey that doesn't deserialize to a valid curve point —
/// returns `false`.
pub fn ed448_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != 57 || signature.len() != 114 {
        return false;
    }
    let pk = match PublicKey::try_from(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    pk.verify(message, signature, None).is_ok()
}

/// Derive the libp2p multihash peer-id bytes for an Ed448 public key.
/// Returns a 34-byte vector: `[0x12, 0x20, sha256(pb)..32]`, where `pb`
/// is the libp2p `PublicKey` protobuf with `Type = KeyType_Ed448 (4)` and
/// `Data = pubkey_bytes`.
///
/// This mirrors `peer.IDFromPublicKey` for Ed448 keys in the Go node.
/// The 57-byte Ed448 pubkey is above the 42-byte identity-hash threshold,
/// so libp2p emits a sha256 multihash rather than embedding the pubkey.
///
/// Used by the legacy pre-2.1 pending-transaction verifier to compute
/// `poseidon(peerId)` for the address-equivalence fallback check.
pub fn peer_id_multihash_from_ed448_pubkey(pubkey: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    // libp2p PublicKey protobuf:
    //   field 1 (Type, varint): tag 0x08, value 4 (Ed448)
    //   field 2 (Data, length-delimited): tag 0x12, length, data
    let mut pb = Vec::with_capacity(4 + pubkey.len());
    pb.push(0x08);
    pb.push(4u8);
    pb.push(0x12);
    pb.push(pubkey.len() as u8);
    pb.extend_from_slice(pubkey);

    let digest = Sha256::digest(&pb);
    let mut mh = Vec::with_capacity(2 + digest.len());
    mh.push(0x12); // sha2-256 multihash code
    mh.push(0x20); // digest length (32)
    mh.extend_from_slice(&digest);
    mh
}
