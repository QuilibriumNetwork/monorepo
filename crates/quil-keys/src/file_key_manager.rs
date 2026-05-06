use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};

use quil_types::crypto::{BlsConstructor, KeyType, Signer};
use quil_types::error::{QuilError, Result};

use crate::KeyManager;

/// A key entry in the YAML keystore file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: String,
    /// Key type: 0=Ed448, 1=X448, 2=BLS48581G1, 3=BLS48581G2, 4=Decaf448
    #[serde(rename = "type")]
    pub key_type: u8,
    /// Hex-encoded public key (plaintext).
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Hex-encoded encrypted private key: [12-byte IV][AES-GCM ciphertext].
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

/// File-based key manager that stores AES-GCM encrypted keys in YAML.
pub struct FileKeyManager {
    keys_path: PathBuf,
    encryption_key: Vec<u8>,
    proving_key_id: String,
    stored_keys: RwLock<HashMap<String, StoredKey>>,
    signers: RwLock<HashMap<KeyType, Box<dyn Signer>>>,
    bls_constructor: Box<dyn BlsConstructor>,
    /// Hex-encoded `config.p2p.peer_priv_key`. Go's
    /// `FileKeyManager.GetSigningKey("q-peer-key")` special-cases this
    /// id and constructs the Ed448 signer from this config field
    /// rather than reading `keys.yml`. Mirroring that lets a Go-style
    /// config (where keys.yml has no `q-peer-key` entry) still serve
    /// the Send RPC and other peer-key consumers.
    peer_priv_key_hex: RwLock<Option<String>>,
}

impl FileKeyManager {
    pub fn new(
        keys_path: PathBuf,
        encryption_key_hex: &str,
        proving_key_id: String,
        bls_constructor: Box<dyn BlsConstructor>,
    ) -> Result<Self> {
        let encryption_key = if encryption_key_hex.is_empty() {
            vec![0u8; 32] // Default key (insecure, for development)
        } else {
            hex::decode(encryption_key_hex)
                .map_err(|e| QuilError::Crypto(format!("invalid encryption key hex: {}", e)))?
        };

        if encryption_key.len() != 32 {
            return Err(QuilError::Crypto(format!(
                "encryption key must be 32 bytes, got {}",
                encryption_key.len()
            )));
        }

        let mut manager = Self {
            keys_path,
            encryption_key,
            proving_key_id,
            stored_keys: RwLock::new(HashMap::new()),
            signers: RwLock::new(HashMap::new()),
            bls_constructor,
            peer_priv_key_hex: RwLock::new(None),
        };

        // Load existing keys from disk
        if manager.keys_path.exists() {
            manager.load_from_file()?;
        }

        Ok(manager)
    }

    /// Load keys from the YAML keystore file.
    fn load_from_file(&mut self) -> Result<()> {
        let contents = std::fs::read_to_string(&self.keys_path)
            .map_err(|e| QuilError::Crypto(format!("failed to read keystore: {}", e)))?;

        let keys: HashMap<String, StoredKey> = serde_yaml::from_str(&contents)
            .map_err(|e| QuilError::Crypto(format!("failed to parse keystore: {}", e)))?;

        tracing::info!(
            count = keys.len(),
            path = %self.keys_path.display(),
            "loaded keystore"
        );

        // Decrypt and populate signers
        for (id, stored) in &keys {
            if let Err(e) = self.load_signer(stored) {
                // Legacy keys.yml from Go nodes can carry an entry
                // with `id: ""` and no payload (an old bootstrap
                // bug). Drop the warn for that one — it's expected
                // and otherwise spams every startup.
                if id.is_empty() {
                    tracing::debug!(error = %e, "skipping empty-id legacy key entry");
                } else {
                    tracing::warn!(key_id = %id, error = %e, "failed to load key");
                }
            }
        }

        *self.stored_keys.write().unwrap() = keys;
        Ok(())
    }

    /// Decrypt a stored key and create a signer.
    fn load_signer(&self, stored: &StoredKey) -> Result<()> {
        let private_bytes = self.decrypt_private_key(&stored.private_key)?;
        let public_bytes = hex::decode(&stored.public_key)
            .map_err(|e| QuilError::Crypto(format!("invalid public key hex: {}", e)))?;

        let key_type = match stored.key_type {
            0 => KeyType::Ed448,
            1 => KeyType::X448,
            2 => KeyType::Bls48581G1,
            3 => KeyType::Bls48581G2,
            4 => KeyType::Decaf448,
            _ => return Err(QuilError::Crypto(format!("unknown key type: {}", stored.key_type))),
        };

        match key_type {
            // Go uses BLS48581G1 (type 2) for prover keys, Rust uses
            // BLS48581G2 (type 3). Both map to the same underlying
            // BLS48-581 implementation.  Store the signer under both
            // variants so callers find it regardless of which enum
            // value they request.
            KeyType::Bls48581G1 | KeyType::Bls48581G2 => {
                let signer_g1 = self.bls_constructor.from_bytes(&private_bytes, &public_bytes)?;
                let signer_g2 = self.bls_constructor.from_bytes(&private_bytes, &public_bytes)?;
                let mut signers = self.signers.write().unwrap();
                signers.insert(KeyType::Bls48581G1, signer_g1);
                signers.insert(KeyType::Bls48581G2, signer_g2);
                tracing::info!(key_id = %stored.id, key_type = ?key_type, "loaded BLS48581 key");
            }
            KeyType::Ed448 => {
                // Ed448 peer key used for KeyRegistry cross-signatures
                // and (derived → Ed25519) for the quil mTLS cert.
                // Keystore may carry a 57-byte seed without the matching
                // public half; derive it if the stored value is empty.
                let pk = if public_bytes.is_empty() {
                    quil_crypto::Ed448Signer::derive_public(&private_bytes)?
                } else {
                    public_bytes
                };
                let signer = quil_crypto::Ed448Signer::from_bytes(&private_bytes, &pk)?;
                let mut signers = self.signers.write().unwrap();
                signers.insert(KeyType::Ed448, Box::new(signer));
                tracing::info!(key_id = %stored.id, "loaded Ed448 key");
            }
            KeyType::X448 | KeyType::Decaf448 => {
                // Agreement keys (onion / view / spend). These are
                // stored for KeyRegistry publication but don't need a
                // Signer trait — they produce shared secrets, not
                // signatures. Keep them in the raw-bytes table only.
                tracing::debug!(
                    key_id = %stored.id,
                    key_type = ?key_type,
                    "loaded agreement key (signing not applicable)"
                );
            }
            KeyType::Ed25519 => {
                let pk = if public_bytes.is_empty() {
                    quil_crypto::Ed25519Signer::derive_public(&private_bytes)?
                } else {
                    public_bytes
                };
                let signer = quil_crypto::Ed25519Signer::from_bytes(&private_bytes, &pk)?;
                let mut signers = self.signers.write().unwrap();
                signers.insert(KeyType::Ed25519, Box::new(signer));
                tracing::info!(key_id = %stored.id, "loaded Ed25519 key");
            }
            KeyType::Secp256k1Sha256 => {
                let pk = if public_bytes.is_empty() {
                    quil_crypto::Secp256k1Signer::derive_public(&private_bytes)?
                } else {
                    public_bytes
                };
                let signer = quil_crypto::Secp256k1Signer::sha256(&private_bytes, &pk)?;
                let mut signers = self.signers.write().unwrap();
                signers.insert(KeyType::Secp256k1Sha256, Box::new(signer));
                tracing::info!(key_id = %stored.id, "loaded Secp256k1Sha256 key");
            }
            KeyType::Secp256k1Sha3 => {
                let pk = if public_bytes.is_empty() {
                    quil_crypto::Secp256k1Signer::derive_public(&private_bytes)?
                } else {
                    public_bytes
                };
                let signer = quil_crypto::Secp256k1Signer::sha3(&private_bytes, &pk)?;
                let mut signers = self.signers.write().unwrap();
                signers.insert(KeyType::Secp256k1Sha3, Box::new(signer));
                tracing::info!(key_id = %stored.id, "loaded Secp256k1Sha3 key");
            }
        }

        Ok(())
    }

    /// Decrypt a hex-encoded encrypted private key.
    /// Format: [12-byte IV][AES-256-GCM ciphertext], all hex-encoded.
    fn decrypt_private_key(&self, encrypted_hex: &str) -> Result<Vec<u8>> {
        let encrypted = hex::decode(encrypted_hex)
            .map_err(|e| QuilError::Crypto(format!("invalid encrypted key hex: {}", e)))?;

        if encrypted.len() < 12 {
            return Err(QuilError::Crypto("encrypted key too short".into()));
        }

        let (iv_bytes, ciphertext) = encrypted.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| QuilError::Crypto(format!("invalid AES key: {}", e)))?;
        let nonce = Nonce::from_slice(iv_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| QuilError::Crypto(format!("decryption failed: {}", e)))
    }

    /// Encrypt a private key and return hex-encoded [IV][ciphertext].
    fn encrypt_private_key(&self, plaintext: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| QuilError::Crypto(format!("invalid AES key: {}", e)))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| QuilError::Crypto(format!("encryption failed: {}", e)))?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(hex::encode(result))
    }

    /// Save the keystore to disk.
    fn save_to_file(&self) -> Result<()> {
        let keys = self.stored_keys.read().unwrap();
        let contents = serde_yaml::to_string(&*keys)
            .map_err(|e| QuilError::Crypto(format!("failed to serialize keystore: {}", e)))?;

        // Ensure parent directory exists
        if let Some(parent) = self.keys_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| QuilError::Crypto(format!("failed to create keystore directory: {}", e)))?;
        }

        // Atomic write: temp file + rename
        let tmp_path = self.keys_path.with_extension("tmp");
        std::fs::write(&tmp_path, &contents)
            .map_err(|e| QuilError::Crypto(format!("failed to write keystore: {}", e)))?;
        std::fs::rename(&tmp_path, &self.keys_path)
            .map_err(|e| QuilError::Crypto(format!("failed to rename keystore: {}", e)))?;

        Ok(())
    }

    /// Create a new BLS key pair, encrypt, and save to disk.
    pub fn create_bls_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let (signer, public_key) = self.bls_constructor.new_key()?;
        let private_key = signer.private_key().to_vec();
        let pub_bytes = signer.public_key().to_vec();

        let encrypted = self.encrypt_private_key(&private_key)?;
        let stored = StoredKey {
            id: key_id.to_string(),
            key_type: 2, // BLS48581G1 — matches Go's file.go:102
            public_key: hex::encode(&public_key),
            private_key: encrypted,
        };

        self.stored_keys
            .write()
            .unwrap()
            .insert(key_id.to_string(), stored);

        // Store signer under both G1 and G2 so callers find it
        // regardless of which variant they request.
        let signer_g1 = self.bls_constructor.from_bytes(&private_key, &pub_bytes)?;
        {
            let mut signers = self.signers.write().unwrap();
            signers.insert(KeyType::Bls48581G2, signer);
            signers.insert(KeyType::Bls48581G1, signer_g1);
        }

        self.save_to_file()?;
        tracing::info!(key_id, "created and saved new BLS key");

        Ok(public_key)
    }

    /// Create a key pair for agreement-type keys (X448, Decaf448).
    /// Generates a random scalar and derives the public key via
    /// elliptic curve point multiplication.
    ///
    /// Key formats match what qclient/Go expects:
    ///   - key_type=1 (X448): 57-byte seed → 57-byte Ed448-shaped pubkey
    ///     (X448 isn't yet used by qclient read paths; Ed448 shape
    ///     is adequate for storage and future port).
    ///   - key_type=4 (Decaf448): 56-byte scalar → 56-byte compressed
    ///     Decaf448 point. Go qclient's `Concat(vk.Public(), sk.Public())`
    ///     produces a 112-byte token-address prefix that Rust's
    ///     `GetTokensByAccount` validates against.
    pub fn create_agreement_key(&self, key_id: &str, key_type: u8) -> Result<()> {
        use rand::RngCore;
        use ed448_goldilocks_plus::{DecafPoint, Scalar};

        let (public_key, private_key) = match key_type {
            4 => {
                // Decaf448: 56-byte compressed point public key,
                // 57-byte RFC 8032 private scalar (matches qclient).
                let mut wide = [0u8; 114];
                rand::thread_rng().fill_bytes(&mut wide);
                let scalar = Scalar::from_bytes_mod_order_wide(
                    &ed448_goldilocks_plus::WideScalarBytes::clone_from_slice(&wide),
                );
                let point = DecafPoint::GENERATOR * scalar;
                let compressed = point.compress();
                let pubkey = compressed.0.to_vec(); // 56 bytes
                let scalar_buf = scalar.to_bytes_rfc_8032().to_vec(); // 57 bytes
                (pubkey, scalar_buf)
            }
            _ => {
                // X448 / other: keep existing Ed448-shape derivation.
                let mut seed = [0u8; 57];
                rand::thread_rng().fill_bytes(&mut seed);
                let ed_priv = ed448_rust::PrivateKey::from(seed);
                let ed_pub = ed448_rust::PublicKey::from(&ed_priv);
                (ed_pub.as_byte().to_vec(), seed.to_vec())
            }
        };

        let encrypted = self.encrypt_private_key(&private_key)?;
        let stored = StoredKey {
            id: key_id.to_string(),
            key_type,
            public_key: hex::encode(&public_key),
            private_key: encrypted,
        };

        self.stored_keys
            .write()
            .unwrap()
            .insert(key_id.to_string(), stored);
        self.save_to_file()?;
        tracing::info!(key_id, key_type, pubkey_len = public_key.len(), "created agreement key");
        Ok(())
    }

    /// Ensure all standard keys exist, creating any that are missing.
    pub fn ensure_standard_keys(&self) -> Result<()> {
        let keys = self.stored_keys.read().unwrap();
        let needs_prover = !keys.contains_key("q-prover-key");
        let needs_onion = !keys.contains_key("q-onion-key");
        let needs_view = !keys.contains_key("q-view-key");
        let needs_spend = !keys.contains_key("q-spend-key");
        let needs_device = !keys.contains_key("q-device-key");
        let needs_device_pre = !keys.contains_key("q-device-pre-key");
        drop(keys);

        if needs_prover {
            self.create_bls_key("q-prover-key")?;
        }
        if needs_onion {
            self.create_agreement_key("q-onion-key", 1)?; // X448
        }
        if needs_view {
            self.create_agreement_key("q-view-key", 4)?; // Decaf448
        }
        if needs_spend {
            self.create_agreement_key("q-spend-key", 4)?; // Decaf448
        }
        if needs_device {
            self.create_agreement_key("q-device-key", 4)?; // Decaf448
        }
        if needs_device_pre {
            self.create_agreement_key("q-device-pre-key", 4)?; // Decaf448
        }
        Ok(())
    }

    /// Wire up the hex `config.p2p.peer_priv_key`. After this is
    /// called, `q-peer-key` lookups (`get_signer_by_id`, `get_peer_key`,
    /// `get_peer_id`) resolve from the config field, mirroring Go's
    /// `FileKeyManager.GetSigningKey("q-peer-key")` special case.
    /// Empty input is treated as "unset".
    pub fn set_peer_priv_key_hex(&self, hex_str: &str) {
        let mut guard = self.peer_priv_key_hex.write().unwrap();
        *guard = if hex_str.is_empty() {
            None
        } else {
            Some(hex_str.to_string())
        };
    }

    /// Decode `config.p2p.peer_priv_key` into the canonical
    /// `(seed[57], pubkey[57])` pair. Mirrors Go's `GetSigningKey`
    /// at `node/keys/file.go:306-315`: the hex blob is `seed || pubkey`
    /// (114 bytes total), and the seed is what we pass to the Ed448
    /// signer constructor. Returns `None` when no peer key has been
    /// wired up.
    fn decoded_peer_priv_key(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let guard = self.peer_priv_key_hex.read().unwrap();
        let Some(hex_str) = guard.as_deref() else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_str)
            .map_err(|e| QuilError::Crypto(format!("peer_priv_key invalid hex: {}", e)))?;
        if bytes.len() < 114 {
            return Err(QuilError::Crypto(format!(
                "peer_priv_key too short: {} bytes, expected ≥114",
                bytes.len()
            )));
        }
        let seed = bytes[..57].to_vec();
        let pub_key = bytes[57..114].to_vec();
        Ok(Some((seed, pub_key)))
    }

    /// Get the peer private key bytes for P2P identity (Ed448).
    pub fn get_peer_key(&self) -> Result<Vec<u8>> {
        if let Some((seed, _)) = self.decoded_peer_priv_key()? {
            return Ok(seed);
        }
        let keys = self.stored_keys.read().unwrap();
        let stored = keys
            .get("q-peer-key")
            .ok_or_else(|| QuilError::NotFound("q-peer-key not found".into()))?;
        self.decrypt_private_key(&stored.private_key)
    }

    /// Decrypt and return a signer for a specific key id from the
    /// keystore. Disambiguates entries that share a `KeyType` (e.g.
    /// multiple Ed448 keys), which `get_signer(KeyType)` cannot.
    pub fn get_signer_by_id(&self, id: &str) -> Result<Box<dyn Signer>> {
        // Special case: "q-peer-key" comes from config.p2p.peer_priv_key,
        // not the keystore. Mirrors Go's `FileKeyManager.GetSigningKey`
        // at node/keys/file.go:306. Fall back to the keystore lookup
        // only if the config field hasn't been wired up.
        if id == "q-peer-key" {
            if let Some((seed, pub_key)) = self.decoded_peer_priv_key()? {
                let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &pub_key)?;
                return Ok(Box::new(signer));
            }
        }

        let stored = {
            let map = self.stored_keys.read().unwrap();
            map.get(id).cloned().ok_or_else(|| {
                QuilError::NotFound(format!("no key with id {:?}", id))
            })?
        };

        let private_bytes = self.decrypt_private_key(&stored.private_key)?;
        let public_bytes = hex::decode(&stored.public_key)
            .map_err(|e| QuilError::Crypto(format!("invalid public key hex: {}", e)))?;

        let key_type = match stored.key_type {
            0 => KeyType::Ed448,
            1 => KeyType::X448,
            2 => KeyType::Bls48581G1,
            3 => KeyType::Bls48581G2,
            4 => KeyType::Decaf448,
            _ => {
                return Err(QuilError::Crypto(format!(
                    "unknown key type for id {:?}: {}",
                    id, stored.key_type
                )))
            }
        };

        match key_type {
            KeyType::Bls48581G1 | KeyType::Bls48581G2 => {
                self.bls_constructor.from_bytes(&private_bytes, &public_bytes)
            }
            KeyType::Ed448 => {
                let pk = if public_bytes.is_empty() {
                    quil_crypto::Ed448Signer::derive_public(&private_bytes)?
                } else {
                    public_bytes
                };
                Ok(Box::new(quil_crypto::Ed448Signer::from_bytes(
                    &private_bytes,
                    &pk,
                )?))
            }
            KeyType::Ed25519 => Ok(Box::new(quil_crypto::Ed25519Signer::from_bytes(
                &private_bytes,
                &public_bytes,
            )?)),
            KeyType::Secp256k1Sha256 => Ok(Box::new(quil_crypto::Secp256k1Signer::sha256(
                &private_bytes,
                &public_bytes,
            )?)),
            KeyType::Secp256k1Sha3 => Ok(Box::new(quil_crypto::Secp256k1Signer::sha3(
                &private_bytes,
                &public_bytes,
            )?)),
            KeyType::X448 | KeyType::Decaf448 => Err(QuilError::Crypto(format!(
                "no signer for agreement-only key type {:?}",
                key_type
            ))),
        }
    }
}

impl KeyManager for FileKeyManager {
    fn get_proving_key_id(&self) -> &str {
        &self.proving_key_id
    }

    fn get_signer(&self, key_type: KeyType) -> Result<Box<dyn Signer>> {
        let signers = self.signers.read().unwrap();
        match signers.get(&key_type) {
            Some(signer) => {
                let private = signer.private_key().to_vec();
                let public = signer.public_key().to_vec();
                match key_type {
                    KeyType::Bls48581G1 | KeyType::Bls48581G2 => {
                        self.bls_constructor.from_bytes(&private, &public)
                    }
                    KeyType::Ed448 => {
                        let s = quil_crypto::Ed448Signer::from_bytes(&private, &public)?;
                        Ok(Box::new(s))
                    }
                    KeyType::Ed25519 => {
                        let s = quil_crypto::Ed25519Signer::from_bytes(&private, &public)?;
                        Ok(Box::new(s))
                    }
                    KeyType::Secp256k1Sha256 => {
                        let s = quil_crypto::Secp256k1Signer::sha256(&private, &public)?;
                        Ok(Box::new(s))
                    }
                    KeyType::Secp256k1Sha3 => {
                        let s = quil_crypto::Secp256k1Signer::sha3(&private, &public)?;
                        Ok(Box::new(s))
                    }
                    KeyType::X448 | KeyType::Decaf448 => Err(QuilError::Crypto(format!(
                        "no signer for agreement-only key type {:?}",
                        key_type
                    ))),
                }
            }
            None => Err(QuilError::NotFound(format!(
                "no key loaded for type {:?}",
                key_type
            ))),
        }
    }

    fn get_public_key(&self, key_type: KeyType) -> Result<Vec<u8>> {
        let signers = self.signers.read().unwrap();
        signers
            .get(&key_type)
            .map(|s| s.public_key().to_vec())
            .ok_or_else(|| QuilError::NotFound(format!("no key for {:?}", key_type)))
    }

    fn get_private_key(&self, key_type: KeyType) -> Result<Vec<u8>> {
        let signers = self.signers.read().unwrap();
        signers
            .get(&key_type)
            .map(|s| s.private_key().to_vec())
            .ok_or_else(|| QuilError::NotFound(format!("no key for {:?}", key_type)))
    }

    fn get_peer_id(&self) -> Result<Vec<u8>> {
        if let Some((_, pub_key)) = self.decoded_peer_priv_key()? {
            return Ok(peer_id_from_ed448(&pub_key));
        }
        let keys = self.stored_keys.read().unwrap();
        let stored = keys
            .get("q-peer-key")
            .ok_or_else(|| QuilError::NotFound("q-peer-key not found".into()))?;
        let public_bytes = hex::decode(&stored.public_key)
            .map_err(|e| QuilError::Crypto(format!("invalid public key: {}", e)))?;
        Ok(peer_id_from_ed448(&public_bytes))
    }
}

/// Derive a peer ID from Ed448 public key bytes (for use without P2P crate).
fn peer_id_from_ed448(public_key: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    // Protobuf: field 1 (varint, tag=0x08, value=4), field 2 (bytes, tag=0x12, len, data)
    let mut proto = Vec::with_capacity(64);
    proto.push(0x08);
    proto.push(4); // KeyType::Ed448
    proto.push(0x12);
    proto.push(public_key.len() as u8);
    proto.extend_from_slice(public_key);

    let hash = Sha256::digest(&proto);

    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12); // SHA2-256
    multihash.push(0x20); // 32 bytes
    multihash.extend_from_slice(&hash);
    multihash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use quil_crypto::Bls48581KeyConstructor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir(name: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "quil-keys-test-{}-{}-{}",
            name,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Test encryption key: 32 bytes encoded as hex.
    const TEST_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn bls_constructor() -> Box<dyn BlsConstructor> {
        Box::new(Bls48581KeyConstructor)
    }

    fn make_manager(name: &str) -> (FileKeyManager, PathBuf) {
        let dir = tempdir(name);
        let keys_path = dir.join("keys.yml");
        let m = FileKeyManager::new(
            keys_path,
            TEST_KEY_HEX,
            "test-key-id".into(),
            bls_constructor(),
        )
        .unwrap();
        (m, dir)
    }

    // =================================================================
    // Constructor
    // =================================================================

    #[test]
    fn constructor_with_empty_path_and_default_key() {
        let dir = tempdir("empty_path_default_key");
        let m = FileKeyManager::new(
            dir.join("nonexistent.yml"),
            "",
            "default".into(),
            bls_constructor(),
        );
        assert!(m.is_ok(), "constructor failed: {:?}", m.err());
        cleanup(&dir);
    }

    #[test]
    fn constructor_with_invalid_hex_is_error() {
        let dir = tempdir("invalid_hex");
        let m = FileKeyManager::new(
            dir.join("keys.yml"),
            "not-valid-hex",
            "id".into(),
            bls_constructor(),
        );
        assert!(m.is_err());
        cleanup(&dir);
    }

    #[test]
    fn constructor_with_wrong_length_key_is_error() {
        let dir = tempdir("wrong_length_key");
        let m = FileKeyManager::new(
            dir.join("keys.yml"),
            "0102030405060708090a0b0c0d0e0f10", // 16 bytes, not 32
            "id".into(),
            bls_constructor(),
        );
        assert!(m.is_err());
        cleanup(&dir);
    }

    #[test]
    fn constructor_stores_proving_key_id() {
        let (m, dir) = make_manager("stores_id");
        assert_eq!(m.get_proving_key_id(), "test-key-id");
        cleanup(&dir);
    }

    // =================================================================
    // AES-GCM round-trip
    // =================================================================

    #[test]
    fn encrypt_decrypt_round_trip_short_payload() {
        let (m, dir) = make_manager("round_trip_short");
        let plaintext = b"hello world";
        let encrypted_hex = m.encrypt_private_key(plaintext).unwrap();
        let encrypted_bytes = hex::decode(&encrypted_hex).unwrap();
        // At minimum: 12-byte IV + plaintext + 16-byte AES-GCM tag.
        assert!(
            encrypted_bytes.len() >= 12 + plaintext.len() + 16,
            "encrypted output too short: {} bytes",
            encrypted_bytes.len()
        );
        let decrypted = m.decrypt_private_key(&encrypted_hex).unwrap();
        assert_eq!(decrypted, plaintext);
        cleanup(&dir);
    }

    #[test]
    fn encrypt_decrypt_round_trip_large_payload() {
        let (m, dir) = make_manager("round_trip_large");
        let plaintext: Vec<u8> = (0..=255u8).collect();
        let encrypted_hex = m.encrypt_private_key(&plaintext).unwrap();
        let decrypted = m.decrypt_private_key(&encrypted_hex).unwrap();
        assert_eq!(decrypted, plaintext);
        cleanup(&dir);
    }

    #[test]
    fn encrypt_twice_produces_different_ciphertexts_due_to_random_nonce() {
        let (m, dir) = make_manager("random_nonce");
        let plaintext = b"same-input";
        let c1 = m.encrypt_private_key(plaintext).unwrap();
        let c2 = m.encrypt_private_key(plaintext).unwrap();
        assert_ne!(c1, c2);
        assert_eq!(m.decrypt_private_key(&c1).unwrap(), plaintext);
        assert_eq!(m.decrypt_private_key(&c2).unwrap(), plaintext);
        cleanup(&dir);
    }

    #[test]
    fn decrypt_with_invalid_hex_errors() {
        let (m, dir) = make_manager("decrypt_invalid_hex");
        let err = m.decrypt_private_key("not-hex").unwrap_err();
        assert!(matches!(err, QuilError::Crypto(_)));
        cleanup(&dir);
    }

    #[test]
    fn decrypt_too_short_errors() {
        let (m, dir) = make_manager("decrypt_too_short");
        let err = m.decrypt_private_key("0102030405060708").unwrap_err();
        assert!(matches!(err, QuilError::Crypto(_)));
        cleanup(&dir);
    }

    #[test]
    fn decrypt_with_wrong_key_errors() {
        let dir = tempdir("wrong_key_decrypt");
        let m_a = FileKeyManager::new(
            dir.join("a.yml"),
            TEST_KEY_HEX,
            "a".into(),
            bls_constructor(),
        )
        .unwrap();
        let other_key =
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let m_b = FileKeyManager::new(
            dir.join("b.yml"),
            other_key,
            "b".into(),
            bls_constructor(),
        )
        .unwrap();

        let plaintext = b"confidential";
        let encrypted = m_a.encrypt_private_key(plaintext).unwrap();
        let err = m_b.decrypt_private_key(&encrypted).unwrap_err();
        assert!(matches!(err, QuilError::Crypto(_)));
        cleanup(&dir);
    }

    // =================================================================
    // BLS key creation and persistence
    // =================================================================

    #[test]
    fn create_bls_key_persists_to_disk() {
        let (m, dir) = make_manager("create_bls_persists");
        let pubkey = m.create_bls_key("my-bls-key").unwrap();
        assert!(!pubkey.is_empty());
        assert!(m.keys_path.exists());

        let loaded_pub = m.get_public_key(KeyType::Bls48581G2).unwrap();
        assert_eq!(loaded_pub, pubkey);

        cleanup(&dir);
    }

    #[test]
    fn create_bls_key_and_reload_from_disk_preserves_identity() {
        let dir = tempdir("reload_from_disk");
        let keys_path = dir.join("keys.yml");

        let pubkey = {
            let m = FileKeyManager::new(
                keys_path.clone(),
                TEST_KEY_HEX,
                "reload-test".into(),
                bls_constructor(),
            )
            .unwrap();
            m.create_bls_key("my-bls-key").unwrap()
        };

        let m2 = FileKeyManager::new(
            keys_path,
            TEST_KEY_HEX,
            "reload-test".into(),
            bls_constructor(),
        )
        .unwrap();
        let pubkey2 = m2.get_public_key(KeyType::Bls48581G2).unwrap();
        assert_eq!(pubkey, pubkey2, "reloaded public key must match");

        let priv_bytes = m2.get_private_key(KeyType::Bls48581G2).unwrap();
        assert!(!priv_bytes.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn get_signer_returns_functional_signer_after_create() {
        let (m, dir) = make_manager("functional_signer");
        m.create_bls_key("sign-test").unwrap();
        let signer = m.get_signer(KeyType::Bls48581G2).unwrap();
        let sig = signer.sign_with_domain(b"test-message", b"domain").unwrap();
        assert!(!sig.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn get_signer_for_missing_key_type_errors() {
        let (m, dir) = make_manager("missing_key_type");
        match m.get_signer(KeyType::Ed448) {
            Ok(_) => panic!("expected NotFound for missing key"),
            Err(QuilError::NotFound(_)) => {}
            Err(e) => panic!("expected NotFound, got {:?}", e),
        }
        cleanup(&dir);
    }

    #[test]
    fn create_bls_key_writes_atomically_via_tmp_rename() {
        let (m, dir) = make_manager("atomic_write");
        m.create_bls_key("atomic").unwrap();
        let tmp_path = m.keys_path.with_extension("tmp");
        assert!(!tmp_path.exists(), "temp file should have been renamed away");
        assert!(m.keys_path.exists());
        cleanup(&dir);
    }

    #[test]
    fn create_bls_key_produces_valid_signatures_cross_verified() {
        let (m, dir) = make_manager("cross_verify");
        let pubkey = m.create_bls_key("verify-test").unwrap();
        let signer = m.get_signer(KeyType::Bls48581G2).unwrap();
        let message = b"cross-verification-message";
        let domain = b"test-domain";
        let sig = signer.sign_with_domain(message, domain).unwrap();

        let verifier = Bls48581KeyConstructor;
        assert!(verifier.verify_signature_raw(&pubkey, &sig, message, domain));
        assert!(!verifier.verify_signature_raw(&pubkey, &sig, b"tampered", domain));

        cleanup(&dir);
    }

    // =================================================================
    // Keystore loading edge cases
    // =================================================================

    #[test]
    fn load_corrupted_yaml_returns_error() {
        let dir = tempdir("corrupted_yaml");
        let keys_path = dir.join("keys.yml");
        std::fs::write(&keys_path, "this: is: not: valid: yaml:").unwrap();
        let result = FileKeyManager::new(
            keys_path,
            TEST_KEY_HEX,
            "id".into(),
            bls_constructor(),
        );
        assert!(result.is_err());
        cleanup(&dir);
    }

    // =================================================================
    // Peer ID derivation
    // =================================================================

    #[test]
    fn peer_id_from_ed448_is_34_bytes_multihash() {
        let fake_pub = vec![0xAAu8; 57];
        let pid = peer_id_from_ed448(&fake_pub);
        assert_eq!(pid.len(), 34);
        assert_eq!(pid[0], 0x12); // SHA2-256 multihash code
        assert_eq!(pid[1], 0x20); // 32-byte digest length
    }

    #[test]
    fn peer_id_from_ed448_is_deterministic() {
        let pub_key = vec![0x42u8; 57];
        let pid1 = peer_id_from_ed448(&pub_key);
        let pid2 = peer_id_from_ed448(&pub_key);
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn peer_id_from_ed448_different_inputs_yield_different_outputs() {
        let a = vec![0x01u8; 57];
        let b = vec![0x02u8; 57];
        assert_ne!(peer_id_from_ed448(&a), peer_id_from_ed448(&b));
    }

    #[test]
    fn peer_id_from_ed448_handles_empty_public_key() {
        let pid = peer_id_from_ed448(&[]);
        assert_eq!(pid.len(), 34);
    }

    #[test]
    fn get_peer_id_without_q_peer_key_errors() {
        let (m, dir) = make_manager("no_peer_key");
        let err = m.get_peer_id().unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
        cleanup(&dir);
    }

    // =================================================================
    // Stored key serialization
    // =================================================================

    #[test]
    fn stored_key_yaml_round_trip() {
        let original = StoredKey {
            id: "test-id".into(),
            key_type: 3,
            public_key: "deadbeef".into(),
            private_key: "cafebabe".into(),
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let parsed: StoredKey = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.key_type, original.key_type);
        assert_eq!(parsed.public_key, original.public_key);
        assert_eq!(parsed.private_key, original.private_key);
    }

    #[test]
    fn stored_key_uses_serde_renames_for_compat() {
        let k = StoredKey {
            id: "x".into(),
            key_type: 3,
            public_key: "pk".into(),
            private_key: "sk".into(),
        };
        let yaml = serde_yaml::to_string(&k).unwrap();
        // Match Go's JSON field shapes.
        assert!(yaml.contains("publicKey"), "yaml: {}", yaml);
        assert!(yaml.contains("privateKey"), "yaml: {}", yaml);
        assert!(yaml.contains("type:"), "yaml: {}", yaml);
    }

    // =================================================================
    // Go keys.yml compatibility
    // =================================================================

    /// Test that the Rust FileKeyManager can load a keys.yml file
    /// produced by the Go node.
    ///
    /// Go creates prover keys with KeyTypeBLS48581G1 (type: 2) while
    /// Rust historically used KeyTypeBLS48581G2 (type: 3).  Both map
    /// to the same underlying BLS48-581 implementation.
    ///
    /// The Go YAML format (from gopkg.in/yaml.v2 serializing
    /// map[string]keys.Key with ByteString hex encoding) looks like:
    ///
    /// ```yaml
    /// q-prover-key:
    ///   id: q-prover-key
    ///   type: 2
    ///   privateKey: <hex of [12-byte IV][AES-GCM ciphertext]>
    ///   publicKey: <hex of raw public key>
    /// ```
    #[test]
    fn load_go_format_keys_yml_with_bls_g1_type() {
        // Step 1: Generate a real BLS key pair and encrypt the private
        // key using Rust (the AES-256-GCM scheme is identical).
        let bls = Bls48581KeyConstructor;
        let (signer, _pop_key) = bls.new_key().unwrap();
        let private_bytes = signer.private_key().to_vec();
        let public_bytes = signer.public_key().to_vec();

        let dir = tempdir("go_compat");
        let keys_path = dir.join("keys.yml");

        // We need a temporary manager just to access encrypt_private_key.
        let tmp_mgr = FileKeyManager::new(
            dir.join("tmp.yml"),
            TEST_KEY_HEX,
            "tmp".into(),
            bls_constructor(),
        )
        .unwrap();

        let encrypted_hex = tmp_mgr.encrypt_private_key(&private_bytes).unwrap();
        let public_hex = hex::encode(&public_bytes);

        // Step 2: Write a Go-formatted keys.yml.
        //
        // Go's yaml.v2 serializes map[string]Key as:
        //   <map-key>:
        //     id: <string>
        //     type: <int>
        //     privateKey: <hex>
        //     publicKey: <hex>
        //
        // Critical difference: type is 2 (BLS48581G1), not 3.
        let go_yaml = format!(
            r#"q-prover-key:
  id: q-prover-key
  type: 2
  privateKey: {encrypted}
  publicKey: {public}
"#,
            encrypted = encrypted_hex,
            public = public_hex,
        );

        std::fs::write(&keys_path, &go_yaml).unwrap();

        // Step 3: Load the file with a fresh FileKeyManager.
        let mgr = FileKeyManager::new(
            keys_path,
            TEST_KEY_HEX,
            "q-prover-key".into(),
            bls_constructor(),
        )
        .unwrap();

        // Step 4: Verify the key is accessible via BOTH G1 and G2.
        let loaded_pub_g1 = mgr.get_public_key(KeyType::Bls48581G1).unwrap();
        assert_eq!(
            loaded_pub_g1, public_bytes,
            "public key via Bls48581G1 must match"
        );

        let loaded_pub_g2 = mgr.get_public_key(KeyType::Bls48581G2).unwrap();
        assert_eq!(
            loaded_pub_g2, public_bytes,
            "public key via Bls48581G2 must match"
        );

        // Step 5: Verify the signer works (can sign and verify).
        let signer_g2 = mgr.get_signer(KeyType::Bls48581G2).unwrap();
        let message = b"go-compat-test-message";
        let domain = b"test-domain";
        let sig = signer_g2.sign_with_domain(message, domain).unwrap();
        assert!(
            bls.verify_signature_raw(&public_bytes, &sig, message, domain),
            "signature from Go-loaded key must verify"
        );

        let signer_g1 = mgr.get_signer(KeyType::Bls48581G1).unwrap();
        let sig_g1 = signer_g1.sign_with_domain(message, domain).unwrap();
        assert!(
            bls.verify_signature_raw(&public_bytes, &sig_g1, message, domain),
            "signature from Go-loaded key via G1 must verify"
        );

        cleanup(&dir);
    }

    /// Test that a Go-formatted keystore with multiple keys (prover +
    /// agreement keys) can be loaded.  Go creates:
    ///   - q-prover-key with type 2 (BLS48581G1)
    ///   - q-onion-key with type 1 (X448)
    ///   - q-view-key with type 4 (Decaf448)
    #[test]
    fn load_go_format_multi_key_keystore() {
        let dir = tempdir("go_multi_key");
        let keys_path = dir.join("keys.yml");

        let tmp_mgr = FileKeyManager::new(
            dir.join("tmp.yml"),
            TEST_KEY_HEX,
            "tmp".into(),
            bls_constructor(),
        )
        .unwrap();

        // Generate a BLS key for the prover entry.
        let bls = Bls48581KeyConstructor;
        let (signer, _) = bls.new_key().unwrap();
        let prover_priv_enc = tmp_mgr.encrypt_private_key(signer.private_key()).unwrap();
        let prover_pub = hex::encode(signer.public_key());

        // Fake agreement keys (we just need valid encrypted blobs).
        let fake_priv = vec![0xABu8; 57];
        let fake_pub = hex::encode(&vec![0xCDu8; 57]);
        let onion_enc = tmp_mgr.encrypt_private_key(&fake_priv).unwrap();
        let view_enc = tmp_mgr.encrypt_private_key(&fake_priv).unwrap();

        let go_yaml = format!(
            r#"q-onion-key:
  id: q-onion-key
  type: 1
  privateKey: {onion_enc}
  publicKey: {fake_pub}
q-prover-key:
  id: q-prover-key
  type: 2
  privateKey: {prover_enc}
  publicKey: {prover_pub}
q-view-key:
  id: q-view-key
  type: 4
  privateKey: {view_enc}
  publicKey: {fake_pub}
"#,
            onion_enc = onion_enc,
            prover_enc = prover_priv_enc,
            prover_pub = prover_pub,
            view_enc = view_enc,
            fake_pub = fake_pub,
        );

        std::fs::write(&keys_path, &go_yaml).unwrap();

        let mgr = FileKeyManager::new(
            keys_path,
            TEST_KEY_HEX,
            "q-prover-key".into(),
            bls_constructor(),
        )
        .unwrap();

        // The prover key (type 2) must be loadable.
        let pub_bytes = mgr.get_public_key(KeyType::Bls48581G2).unwrap();
        assert_eq!(pub_bytes, signer.public_key());

        // Non-BLS keys are skipped by load_signer (expected), but the
        // stored_keys map should contain all three entries.
        let keys = mgr.stored_keys.read().unwrap();
        assert!(keys.contains_key("q-prover-key"), "missing q-prover-key");
        assert!(keys.contains_key("q-onion-key"), "missing q-onion-key");
        assert!(keys.contains_key("q-view-key"), "missing q-view-key");

        cleanup(&dir);
    }
}
