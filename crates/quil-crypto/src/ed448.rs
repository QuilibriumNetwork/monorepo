//! Ed448 signer wrapping the `ed448-rust` crate, used for peer
//! identity and KeyRegistry cross-signatures. Mirrors Go's
//! `crypto.KeyTypeEd448` path.
//!
//! `sign_with_domain(message, domain)` matches Go's
//! `Ed448Key.SignWithDomain`: it signs `concat(domain, message)`
//! under pure Ed448 with an empty RFC 8032 ctx. Verifiers must
//! reconstruct the same `concat(domain, message)` digest.

use ed448_rust::{PrivateKey, PublicKey};
use quil_types::crypto::{KeyType, Signer};
use quil_types::error::{QuilError, Result};

/// Ed448 signer. 57-byte secret, 57-byte public, 114-byte signature.
pub struct Ed448Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Ed448Signer {
    /// Accepts both encodings of the private key:
    ///   * 57 bytes — raw seed.
    ///   * 114 bytes — circl/Go layout: `seed(57) || pubkey(57)`. The
    ///     trailing pubkey is dropped; the seed is what `ed448-rust`
    ///     consumes.
    /// `public_key` must be 57 bytes.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        let seed = normalize_ed448_seed(private_key)?;
        if public_key.len() != 57 {
            return Err(QuilError::Crypto(format!(
                "Ed448: invalid public key length {}",
                public_key.len()
            )));
        }
        Ok(Self {
            secret_key: seed,
            public_key: public_key.to_vec(),
        })
    }

    /// Accepts the same 57- or 114-byte forms as `from_bytes` and
    /// derives the matching 57-byte public key.
    pub fn derive_public(private_key: &[u8]) -> Result<Vec<u8>> {
        let seed_vec = normalize_ed448_seed(private_key)?;
        let mut seed = [0u8; 57];
        seed.copy_from_slice(&seed_vec);
        let sk = PrivateKey::from(seed);
        let pk: PublicKey = (&sk).into();
        Ok(pk.as_byte().to_vec())
    }
}

fn normalize_ed448_seed(private_key: &[u8]) -> Result<Vec<u8>> {
    match private_key.len() {
        57 => Ok(private_key.to_vec()),
        114 => Ok(private_key[..57].to_vec()),
        n => Err(QuilError::Crypto(format!(
            "Ed448: invalid private key length {}",
            n
        ))),
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
        // Go's `Ed448Key.SignWithDomain` signs `concat(domain, message)`
        // with an empty Ed448 context (`ed448.PrivateKey.Sign` with
        // `crypto.Hash(0)` opts maps to pure Ed448, ctx=""). Mirror
        // that exactly — passing `domain` as the RFC 8032 ctx
        // parameter would produce a mathematically different (and
        // Go-incompatible) signature.
        let mut digest = Vec::with_capacity(domain.len() + message.len());
        digest.extend_from_slice(domain);
        digest.extend_from_slice(message);
        let sig = sk
            .sign(&digest, None)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_seed() -> [u8; 57] {
        let mut s = [0u8; 57];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        s
    }

    #[test]
    fn from_bytes_accepts_57_byte_seed() {
        let seed = fresh_seed();
        let pk = Ed448Signer::derive_public(&seed).unwrap();
        let signer = Ed448Signer::from_bytes(&seed, &pk).unwrap();
        assert_eq!(signer.private_key().len(), 57);
    }

    #[test]
    fn from_bytes_accepts_114_byte_circl_form() {
        let seed = fresh_seed();
        let pk = Ed448Signer::derive_public(&seed).unwrap();
        let mut circl = Vec::with_capacity(114);
        circl.extend_from_slice(&seed);
        circl.extend_from_slice(&pk);
        let signer = Ed448Signer::from_bytes(&circl, &pk).unwrap();
        assert_eq!(signer.private_key().len(), 57);
        assert_eq!(signer.private_key(), &seed[..]);
    }

    #[test]
    fn derive_public_accepts_114_byte_circl_form() {
        let seed = fresh_seed();
        let pk_from_seed = Ed448Signer::derive_public(&seed).unwrap();
        let mut circl = Vec::with_capacity(114);
        circl.extend_from_slice(&seed);
        circl.extend_from_slice(&pk_from_seed);
        let pk_from_circl = Ed448Signer::derive_public(&circl).unwrap();
        assert_eq!(pk_from_seed, pk_from_circl);
    }

    #[test]
    fn from_bytes_rejects_other_lengths() {
        let pk = vec![0u8; 57];
        assert!(Ed448Signer::from_bytes(&[0u8; 32], &pk).is_err());
        assert!(Ed448Signer::from_bytes(&[0u8; 64], &pk).is_err());
        assert!(Ed448Signer::from_bytes(&[0u8; 113], &pk).is_err());
        assert!(Ed448Signer::from_bytes(&[0u8; 115], &pk).is_err());
    }

    #[test]
    fn signing_with_57_and_114_seed_inputs_is_equivalent() {
        let seed = fresh_seed();
        let pk = Ed448Signer::derive_public(&seed).unwrap();
        let mut circl = Vec::with_capacity(114);
        circl.extend_from_slice(&seed);
        circl.extend_from_slice(&pk);

        let s57 = Ed448Signer::from_bytes(&seed, &pk).unwrap();
        let s114 = Ed448Signer::from_bytes(&circl, &pk).unwrap();

        let msg = b"test message";
        let sig57 = s57.sign_with_domain(msg, b"ctx").unwrap();
        let sig114 = s114.sign_with_domain(msg, b"ctx").unwrap();
        assert_eq!(sig57, sig114);
    }
}
