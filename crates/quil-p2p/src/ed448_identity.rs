//! Ed448 peer identity derivation compatible with Quilibrium's go-libp2p fork.
//!
//! The Go node uses Ed448 (KeyType=4) for peer identity. Peer IDs are derived
//! as: `PeerId = multihash(SHA2-256, protobuf(PublicKey{Type:4, Data:pubkey}))`
//!
//! ## Compatibility Status
//!
//! **Peer ID derivation**: Implemented here — produces byte-identical peer IDs
//! to Go nodes.
//!
//! **Transport (noise handshake)**: NOT YET COMPATIBLE. Stock rust-libp2p uses
//! Ed25519 for noise. To connect to Go nodes, we need to fork rust-libp2p's
//! noise implementation to support Ed448. Until then, the Rust node can only
//! connect to other Rust nodes using Ed25519 transport.
//!
//! **Message signing (BlossomSub)**: NOT YET COMPATIBLE. BlossomSub messages
//! are signed with Ed448. Need custom signing in the BlossomSub port.

use sha2::{Digest, Sha256};

use quil_types::error::{QuilError, Result};

/// libp2p protobuf KeyType for Ed448 (matches Go fork's crypto.proto).
const KEY_TYPE_ED448: i32 = 4;

/// An Ed448 identity keypair for the Quilibrium network.
#[derive(Clone)]
pub struct Ed448Identity {
    /// 57-byte Ed448 private key (seed).
    pub private_key: Vec<u8>,
    /// 57-byte Ed448 public key.
    pub public_key: Vec<u8>,
    /// Derived peer ID bytes (multihash).
    pub peer_id_bytes: Vec<u8>,
}

impl Ed448Identity {
    /// Load an Ed448 identity from the hex-encoded config private key.
    /// The config stores 114 bytes: [57-byte seed][57-byte public key].
    pub fn from_config_hex(hex_key: &str) -> Result<Self> {
        let raw = hex::decode(hex_key)
            .map_err(|e| QuilError::P2p(format!("invalid hex peer key: {}", e)))?;

        if raw.len() != 114 {
            return Err(QuilError::P2p(format!(
                "ed448 key must be 114 bytes (57 seed + 57 pub), got {}",
                raw.len()
            )));
        }

        let private_key = raw[..57].to_vec();
        let public_key = raw[57..].to_vec();
        let peer_id_bytes = derive_peer_id_bytes(&public_key);

        Ok(Self {
            private_key,
            public_key,
            peer_id_bytes,
        })
    }

    /// Generate a new random Ed448 identity.
    pub fn generate() -> Result<Self> {
        let private = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
        let public = ed448_rust::PublicKey::from(&private);

        let private_bytes = private.as_bytes().to_vec();
        let public_bytes = public.as_byte().to_vec();
        let peer_id_bytes = derive_peer_id_bytes(&public_bytes);

        Ok(Self {
            private_key: private_bytes,
            public_key: public_bytes,
            peer_id_bytes,
        })
    }

    /// Get the peer ID as a hex string (for logging).
    pub fn peer_id_hex(&self) -> String {
        hex::encode(&self.peer_id_bytes)
    }

    /// Get the peer ID as a base58 string — the canonical libp2p
    /// `QmX...` form, identical to Go's `peer.ID(...).String()`.
    pub fn peer_id_base58(&self) -> String {
        bs58::encode(&self.peer_id_bytes).into_string()
    }

    /// Get the config-format hex string (114 bytes: seed + public).
    pub fn to_config_hex(&self) -> String {
        let mut combined = Vec::with_capacity(114);
        combined.extend_from_slice(&self.private_key);
        combined.extend_from_slice(&self.public_key);
        hex::encode(combined)
    }

    /// Sign a message with this Ed448 key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let private = ed448_rust::PrivateKey::try_from(self.private_key.as_slice())
            .map_err(|e| QuilError::P2p(format!("invalid ed448 private key: {:?}", e)))?;
        let sig = private
            .sign(message, None)
            .map_err(|e| QuilError::P2p(format!("ed448 sign failed: {:?}", e)))?;
        Ok(sig.to_vec())
    }

    /// Verify a message signature with a public key.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        if public_key.len() != 57 {
            return Ok(false);
        }
        let mut pk_bytes = [0u8; 57];
        pk_bytes.copy_from_slice(public_key);
        let pk = ed448_rust::PublicKey::from(pk_bytes);
        Ok(pk.verify(message, signature, None).is_ok())
    }
}

/// Derive the Ed448 public key from a 57-byte seed.
pub fn derive_public_key(seed: &[u8; 57]) -> Vec<u8> {
    let privkey = ed448_rust::PrivateKey::from(*seed);
    let pubkey = ed448_rust::PublicKey::from(&privkey);
    pubkey.as_byte().to_vec()
}

/// Derive a deterministic worker Ed448 identity from a real prover
/// private key and a core ID. Each (real_priv, core_id) pair yields a
/// stable synthetic identity across restarts.
///
/// Mirrors Go's `node/p2p/blossomsub.go:473-496`:
///
/// ```text
/// seed = SHAKE256(real_priv || "/worker/<core_id>")[:64]
/// key  = Ed448(seed)
/// ```
///
/// The synthetic key is used as the worker's libp2p host identity
/// (peer ID for connection / peerstore), so a master + N workers all
/// running off the same prover key do not collide on a single peer
/// ID. Pubsub messages are signed separately with the REAL prover
/// key so `msg.from` carries the prover's true peer ID — see
/// `P2PNode::new_for_worker`.
pub fn derive_worker_identity(
    real_priv: &[u8; 57],
    core_id: u32,
) -> Result<Ed448Identity> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut shake = sha3::Shake256::default();
    shake.update(real_priv);
    shake.update(format!("/worker/{}", core_id).as_bytes());
    let mut reader = shake.finalize_xof();
    let mut seed_64 = [0u8; 64];
    reader.read(&mut seed_64);
    // Ed448 takes a 57-byte seed; truncate the 64-byte SHAKE output.
    let mut seed_57 = [0u8; 57];
    seed_57.copy_from_slice(&seed_64[..57]);

    let priv_key = ed448_rust::PrivateKey::from(seed_57);
    let pub_key = ed448_rust::PublicKey::from(&priv_key);
    let private_key = seed_57.to_vec();
    let public_key = pub_key.as_byte().to_vec();
    let peer_id_bytes = derive_peer_id_bytes(&public_key);
    Ok(Ed448Identity {
        private_key,
        public_key,
        peer_id_bytes,
    })
}

/// Derive a libp2p peer ID from an Ed448 public key.
///
/// Process:
/// 1. Serialize public key as protobuf: `PublicKey { Type: 4, Data: pubkey }`
/// 2. SHA2-256 hash the protobuf bytes (since >42 bytes, uses SHA256 not identity)
/// 3. Encode as multihash: `[hash_code=0x12][digest_size=0x20][32-byte SHA256]`
fn derive_peer_id_bytes(public_key: &[u8]) -> Vec<u8> {
    // Step 1: Protobuf-encode the public key
    // Field 1 (Type): varint, tag = 0x08, value = 4
    // Field 2 (Data): length-delimited, tag = 0x12, length = 57, data = pubkey
    let mut proto = Vec::with_capacity(64);
    proto.push(0x08); // field 1 tag (varint)
    proto.push(KEY_TYPE_ED448 as u8); // value = 4
    proto.push(0x12); // field 2 tag (length-delimited)
    proto.push(public_key.len() as u8); // length = 57
    proto.extend_from_slice(public_key);

    // Step 2: SHA2-256 hash
    let hash = Sha256::digest(&proto);

    // Step 3: Encode as multihash
    // SHA2-256 code = 0x12, digest length = 0x20 (32 bytes)
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12); // SHA2-256 function code
    multihash.push(0x20); // digest length (32)
    multihash.extend_from_slice(&hash);

    multihash
}

/// Derive a libp2p PeerId from an Ed448 public key (for display/comparison).
pub fn peer_id_from_ed448_pubkey(public_key: &[u8]) -> Vec<u8> {
    derive_peer_id_bytes(public_key)
}

impl std::fmt::Debug for Ed448Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed448Identity")
            .field("peer_id", &self.peer_id_hex())
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = Ed448Identity::generate().unwrap();
        assert_eq!(id.private_key.len(), 57);
        assert_eq!(id.public_key.len(), 57);
        assert_eq!(id.peer_id_bytes.len(), 34); // 2-byte header + 32-byte hash
        assert_eq!(id.peer_id_bytes[0], 0x12); // SHA2-256
        assert_eq!(id.peer_id_bytes[1], 0x20); // 32 bytes
    }

    #[test]
    fn test_roundtrip_config_hex() {
        let id = Ed448Identity::generate().unwrap();
        let hex_key = id.to_config_hex();
        assert_eq!(hex_key.len(), 228); // 114 bytes * 2

        let id2 = Ed448Identity::from_config_hex(&hex_key).unwrap();
        assert_eq!(id.public_key, id2.public_key);
        assert_eq!(id.private_key, id2.private_key);
        assert_eq!(id.peer_id_bytes, id2.peer_id_bytes);
    }

    #[test]
    fn test_sign_verify() {
        let id = Ed448Identity::generate().unwrap();
        let msg = b"test message";
        let sig = id.sign(msg).unwrap();
        assert!(Ed448Identity::verify(&id.public_key, msg, &sig).unwrap());
        assert!(!Ed448Identity::verify(&id.public_key, b"wrong", &sig).unwrap());
    }

    #[test]
    fn test_peer_id_deterministic() {
        let id = Ed448Identity::generate().unwrap();
        let pid1 = derive_peer_id_bytes(&id.public_key);
        let pid2 = derive_peer_id_bytes(&id.public_key);
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn test_invalid_config_hex() {
        assert!(Ed448Identity::from_config_hex("deadbeef").is_err());
        assert!(Ed448Identity::from_config_hex("not hex").is_err());
    }
}
