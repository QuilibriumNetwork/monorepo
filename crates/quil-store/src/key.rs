use std::sync::Arc;

use prost::Message;

use quil_types::error::{QuilError, Result};
use quil_types::proto::keys;
use quil_types::store;

// ---------------------------------------------------------------------------
// Key store prefix constants
// ---------------------------------------------------------------------------

/// Top-level store discriminator for all key-bundle data.
const KEY_BUNDLE: u8 = 0x03;

// Sub-type discriminators within KEY_BUNDLE.
const KEY_IDENTITY: u8 = 0x30;
const KEY_PROVING: u8 = 0x31;
const KEY_CROSS_SIGNATURE: u8 = 0x40;
const KEY_X448_SIGNED_KEY_BY_ID: u8 = 0x50;
const KEY_X448_SIGNED_KEY_BY_PARENT: u8 = 0x51;
const KEY_X448_SIGNED_KEY_BY_PURPOSE: u8 = 0x52;
const KEY_X448_SIGNED_KEY_BY_EXPIRY: u8 = 0x53;
const KEY_DECAF448_SIGNED_KEY_BY_ID: u8 = 0x54;
const KEY_DECAF448_SIGNED_KEY_BY_PARENT: u8 = 0x55;
#[allow(dead_code)]
const KEY_DECAF448_SIGNED_KEY_BY_PURPOSE: u8 = 0x56;
#[allow(dead_code)]
const KEY_DECAF448_SIGNED_KEY_BY_EXPIRY: u8 = 0x57;

// ---------------------------------------------------------------------------
// Key builders (match Go byte-for-byte)
// ---------------------------------------------------------------------------

fn identity_key_key(address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_IDENTITY];
    k.extend_from_slice(address);
    k
}

fn proving_key_key(address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_PROVING];
    k.extend_from_slice(address);
    k
}

fn cross_signature_key(signing_address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_CROSS_SIGNATURE];
    k.extend_from_slice(signing_address);
    k
}

fn signed_x448_key_key(address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_ID];
    k.extend_from_slice(address);
    k
}

/// Index key: [KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT, parent_addr..., purpose(8 bytes), key_addr...]
fn signed_x448_key_by_parent_key(
    parent_key_address: &[u8],
    key_purpose: &str,
    key_address: &[u8],
) -> Vec<u8> {
    let mut purpose = [0u8; 8];
    let bytes = key_purpose.as_bytes();
    let copy_len = bytes.len().min(8);
    purpose[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let mut k = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT];
    k.extend_from_slice(parent_key_address);
    k.extend_from_slice(&purpose);
    k.extend_from_slice(key_address);
    k
}

fn signed_x448_key_by_purpose_key(key_purpose: &str, key_address: &[u8]) -> Vec<u8> {
    let mut purpose = [0u8; 8];
    let bytes = key_purpose.as_bytes();
    let copy_len = bytes.len().min(8);
    purpose[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let mut k = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PURPOSE];
    k.extend_from_slice(&purpose);
    k.extend_from_slice(key_address);
    k
}

fn signed_x448_key_expiry_key(expires_at: u64, key_address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_EXPIRY];
    k.extend_from_slice(&expires_at.to_be_bytes());
    k.extend_from_slice(key_address);
    k
}

fn signed_decaf448_key_key(address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_ID];
    k.extend_from_slice(address);
    k
}

#[allow(dead_code)]
fn signed_decaf448_key_by_parent_key(
    parent_key_address: &[u8],
    key_purpose: &str,
    key_address: &[u8],
) -> Vec<u8> {
    let mut purpose = [0u8; 8];
    let bytes = key_purpose.as_bytes();
    let copy_len = bytes.len().min(8);
    purpose[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let mut k = vec![KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT];
    k.extend_from_slice(parent_key_address);
    k.extend_from_slice(&purpose);
    k.extend_from_slice(key_address);
    k
}

#[allow(dead_code)]
fn signed_decaf448_key_by_purpose_key(key_purpose: &str, key_address: &[u8]) -> Vec<u8> {
    let mut purpose = [0u8; 8];
    let bytes = key_purpose.as_bytes();
    let copy_len = bytes.len().min(8);
    purpose[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let mut k = vec![KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PURPOSE];
    k.extend_from_slice(&purpose);
    k.extend_from_slice(key_address);
    k
}

#[allow(dead_code)]
fn signed_decaf448_key_expiry_key(expires_at: u64, key_address: &[u8]) -> Vec<u8> {
    let mut k = vec![KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_EXPIRY];
    k.extend_from_slice(&expires_at.to_be_bytes());
    k.extend_from_slice(key_address);
    k
}

/// Increment a byte slice by 1 (big-endian), for use as an exclusive upper
/// bound when iterating a prefix range.
fn increment_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return out;
        }
        *byte = 0x00;
    }
    // All 0xFF — extend with a trailing 0x00 (unreachable in practice).
    out.push(0x00);
    out
}

// ---------------------------------------------------------------------------
// RocksKeyStore
// ---------------------------------------------------------------------------

/// RocksDB-backed key registry store.
pub struct RocksKeyStore {
    db: Arc<rocksdb::DB>,
}

impl RocksKeyStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    fn db_get(&self, key: &[u8]) -> Result<Vec<u8>> {
        self.db
            .get(key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("key not found".into()))
    }

    // ---------------------------------------------------------------
    // Signed X448 key helpers (internal)
    // ---------------------------------------------------------------

    /// Get a signed X448 key by address (used by both the public API and
    /// internal iteration).
    pub fn get_signed_x448_key_internal(
        &self,
        address: &[u8],
    ) -> Result<keys::SignedX448Key> {
        let data = self.db_get(&signed_x448_key_key(address))?;
        keys::SignedX448Key::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(format!("decode signed x448 key: {}", e)))
    }

    /// Get all signed X448 keys whose parent-index key starts with the
    /// given prefix.
    fn get_signed_x448_keys_by_parent_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<keys::SignedX448Key>> {
        let mut result = Vec::new();
        let end = increment_prefix(prefix);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(prefix.to_vec());
        read_opts.set_iterate_upper_bound(end);

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            let (k, _v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            // The last 32 bytes of the index key are the key address.
            if k.len() < 32 {
                continue;
            }
            let key_address = &k[k.len() - 32..];
            if let Ok(signed_key) = self.get_signed_x448_key_internal(key_address) {
                result.push(signed_key);
            }
        }
        Ok(result)
    }

    // ---------------------------------------------------------------
    // Signed Decaf448 key helpers (internal)
    // ---------------------------------------------------------------

    pub fn get_signed_decaf448_key_internal(
        &self,
        address: &[u8],
    ) -> Result<keys::SignedDecaf448Key> {
        let data = self.db_get(&signed_decaf448_key_key(address))?;
        keys::SignedDecaf448Key::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(format!("decode signed decaf448 key: {}", e)))
    }

    fn get_signed_decaf448_keys_by_parent_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<keys::SignedDecaf448Key>> {
        let mut result = Vec::new();
        let end = increment_prefix(prefix);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(prefix.to_vec());
        read_opts.set_iterate_upper_bound(end);

        let iter = self
            .db
            .iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        for item in iter {
            let (k, _v) = item.map_err(|e| QuilError::Store(e.to_string()))?;
            if k.len() < 32 {
                continue;
            }
            let key_address = &k[k.len() - 32..];
            if let Ok(signed_key) = self.get_signed_decaf448_key_internal(key_address) {
                result.push(signed_key);
            }
        }
        Ok(result)
    }

    // ---------------------------------------------------------------
    // Key registry assembly helpers
    // ---------------------------------------------------------------

    /// Collect all signed X448 keys parented by `parent_address` into the
    /// registry's `keys_by_purpose` map, updating `last_updated`.
    fn collect_x448_keys(
        &self,
        parent_address: &[u8],
        registry: &mut keys::KeyRegistry,
    ) {
        let prefix = {
            let mut p = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT];
            p.extend_from_slice(parent_address);
            p
        };
        if let Ok(all_keys) = self.get_signed_x448_keys_by_parent_prefix(&prefix) {
            for key in all_keys {
                let coll = registry
                    .keys_by_purpose
                    .entry(key.key_purpose.clone())
                    .or_insert_with(|| keys::KeyCollection {
                        key_purpose: key.key_purpose.clone(),
                        x448_keys: Vec::new(),
                        decaf448_keys: Vec::new(),
                    });
                if registry.last_updated < key.created_at {
                    registry.last_updated = key.created_at;
                }
                coll.x448_keys.push(key);
            }
        }
    }

    /// Collect all signed Decaf448 keys parented by `parent_address`.
    fn collect_decaf448_keys(
        &self,
        parent_address: &[u8],
        registry: &mut keys::KeyRegistry,
    ) {
        let prefix = {
            let mut p = vec![KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT];
            p.extend_from_slice(parent_address);
            p
        };
        if let Ok(all_keys) = self.get_signed_decaf448_keys_by_parent_prefix(&prefix) {
            for key in all_keys {
                let coll = registry
                    .keys_by_purpose
                    .entry(key.key_purpose.clone())
                    .or_insert_with(|| keys::KeyCollection {
                        key_purpose: key.key_purpose.clone(),
                        x448_keys: Vec::new(),
                        decaf448_keys: Vec::new(),
                    });
                if registry.last_updated < key.created_at {
                    registry.last_updated = key.created_at;
                }
                coll.decaf448_keys.push(key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KeyStore trait implementation
// ---------------------------------------------------------------------------

impl store::KeyStore for RocksKeyStore {
    fn new_transaction(&self) -> Result<Box<dyn store::Transaction>> {
        Ok(Box::new(crate::RocksTransaction {
            db: self.db.clone(),
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
        }))
    }

    // ---------------------------------------------------------------
    // Identity keys
    // ---------------------------------------------------------------

    fn put_identity_key(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        key: &keys::Ed448PublicKey,
    ) -> Result<()> {
        let data = key.encode_to_vec();
        txn.set(&identity_key_key(address), &data)
    }

    fn get_identity_key(&self, address: &[u8]) -> Result<keys::Ed448PublicKey> {
        let data = self.db_get(&identity_key_key(address))?;
        keys::Ed448PublicKey::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(format!("decode identity key: {}", e)))
    }

    // ---------------------------------------------------------------
    // Proving keys
    // ---------------------------------------------------------------

    fn put_proving_key(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        key: &keys::Bls48581SignatureWithProofOfPossession,
    ) -> Result<()> {
        let data = key.encode_to_vec();
        txn.set(&proving_key_key(address), &data)
    }

    fn get_proving_key(
        &self,
        address: &[u8],
    ) -> Result<keys::Bls48581SignatureWithProofOfPossession> {
        let data = self.db_get(&proving_key_key(address))?;
        keys::Bls48581SignatureWithProofOfPossession::decode(data.as_slice())
            .map_err(|e| QuilError::Serialization(format!("decode proving key: {}", e)))
    }

    // ---------------------------------------------------------------
    // Cross signatures
    // ---------------------------------------------------------------

    fn put_cross_signature(
        &self,
        txn: &dyn store::Transaction,
        identity_key_address: &[u8],
        proving_key_address: &[u8],
        identity_sig_of_proving: &[u8],
        proving_sig_of_identity: &[u8],
    ) -> Result<()> {
        // Identity -> prover: value = [proving_key_address, identity_sig_of_proving]
        let mut id_value = Vec::with_capacity(
            proving_key_address.len() + identity_sig_of_proving.len(),
        );
        id_value.extend_from_slice(proving_key_address);
        id_value.extend_from_slice(identity_sig_of_proving);
        txn.set(&cross_signature_key(identity_key_address), &id_value)?;

        // Prover -> identity: value = [identity_key_address, proving_sig_of_identity]
        let mut prov_value = Vec::with_capacity(
            identity_key_address.len() + proving_sig_of_identity.len(),
        );
        prov_value.extend_from_slice(identity_key_address);
        prov_value.extend_from_slice(proving_sig_of_identity);
        txn.set(&cross_signature_key(proving_key_address), &prov_value)?;

        Ok(())
    }

    fn get_cross_signature_by_identity_key(
        &self,
        identity_key_address: &[u8],
    ) -> Result<Vec<u8>> {
        self.db_get(&cross_signature_key(identity_key_address))
    }

    fn get_cross_signature_by_proving_key(
        &self,
        proving_key_address: &[u8],
    ) -> Result<Vec<u8>> {
        self.db_get(&cross_signature_key(proving_key_address))
    }

    // ---------------------------------------------------------------
    // Signed X448 keys
    // ---------------------------------------------------------------

    fn put_signed_x448_key(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        key: &keys::SignedX448Key,
    ) -> Result<()> {
        let data = key.encode_to_vec();

        // Store by address
        txn.set(&signed_x448_key_key(address), &data)?;

        // Store parent-key index (marker value)
        txn.set(
            &signed_x448_key_by_parent_key(
                &key.parent_key_address,
                &key.key_purpose,
                address,
            ),
            &[0x01],
        )?;

        // Store purpose index (marker value)
        txn.set(
            &signed_x448_key_by_purpose_key(&key.key_purpose, address),
            &[0x01],
        )?;

        // Store expiry index if set
        if key.expires_at > 0 {
            txn.set(
                &signed_x448_key_expiry_key(key.expires_at, address),
                &[0x01],
            )?;
        }

        Ok(())
    }

    fn get_signed_x448_key(&self, address: &[u8]) -> Result<keys::SignedX448Key> {
        self.get_signed_x448_key_internal(address)
    }

    fn get_signed_x448_keys_by_parent(
        &self,
        parent_key_address: &[u8],
        key_purpose: &str,
    ) -> Result<Vec<keys::SignedX448Key>> {
        let prefix = if !key_purpose.is_empty() {
            let mut purpose = [0u8; 8];
            let bytes = key_purpose.as_bytes();
            let copy_len = bytes.len().min(8);
            purpose[..copy_len].copy_from_slice(&bytes[..copy_len]);

            let mut p = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT];
            p.extend_from_slice(parent_key_address);
            p.extend_from_slice(&purpose);
            p
        } else {
            let mut p = vec![KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT];
            p.extend_from_slice(parent_key_address);
            p
        };

        self.get_signed_x448_keys_by_parent_prefix(&prefix)
    }

    // ---------------------------------------------------------------
    // Key registry
    // ---------------------------------------------------------------

    fn get_key_registry(
        &self,
        identity_key_address: &[u8],
    ) -> Result<keys::KeyRegistry> {
        let mut registry = keys::KeyRegistry {
            keys_by_purpose: std::collections::HashMap::new(),
            ..Default::default()
        };

        // Get identity key
        let identity_key = self.get_identity_key(identity_key_address)?;
        registry.identity_key = Some(identity_key);

        // Find prover key via cross signatures
        let mut prover_key_address: Option<Vec<u8>> = None;
        if let Ok(cross_sig_data) = self.get_cross_signature_by_identity_key(identity_key_address) {
            if cross_sig_data.len() > 32 {
                let pka = cross_sig_data[..32].to_vec();

                if let Ok(proving_key) = self.get_proving_key(&pka) {
                    registry.prover_key = proving_key.public_key;

                    registry.identity_to_prover = Some(keys::Ed448Signature {
                        signature: cross_sig_data[32..].to_vec(),
                        ..Default::default()
                    });

                    // Get reverse signature
                    if let Ok(prover_sig_data) = self.get_cross_signature_by_proving_key(&pka) {
                        if prover_sig_data.len() > 32 {
                            registry.prover_to_identity = Some(keys::Bls48581Signature {
                                signature: prover_sig_data[32..].to_vec(),
                                ..Default::default()
                            });
                        }
                    }
                }

                prover_key_address = Some(pka);
            }
        }

        // Collect X448 and Decaf448 keys parented by identity key
        self.collect_x448_keys(identity_key_address, &mut registry);
        self.collect_decaf448_keys(identity_key_address, &mut registry);

        // Also collect keys parented by prover key
        if let Some(ref pka) = prover_key_address {
            self.collect_x448_keys(pka, &mut registry);
            self.collect_decaf448_keys(pka, &mut registry);
        }

        Ok(registry)
    }

    fn get_key_registry_by_prover(
        &self,
        prover_key_address: &[u8],
    ) -> Result<keys::KeyRegistry> {
        let mut registry = keys::KeyRegistry {
            keys_by_purpose: std::collections::HashMap::new(),
            ..Default::default()
        };

        // Get proving key
        let proving_key = self.get_proving_key(prover_key_address)?;
        registry.prover_key = proving_key.public_key;

        // Find identity key via cross signatures
        let mut identity_key_address: Option<Vec<u8>> = None;
        if let Ok(cross_sig_data) = self.get_cross_signature_by_proving_key(prover_key_address) {
            // Prover cross-sig value: [identity_key_address, bls_signature(74 bytes)]
            if cross_sig_data.len() > 74 {
                let ika = cross_sig_data[..cross_sig_data.len() - 74].to_vec();

                if let Ok(identity_key) = self.get_identity_key(&ika) {
                    registry.identity_key = Some(identity_key);

                    registry.prover_to_identity = Some(keys::Bls48581Signature {
                        signature: cross_sig_data[cross_sig_data.len() - 74..].to_vec(),
                        ..Default::default()
                    });

                    // Get reverse signature
                    if let Ok(id_sig_data) = self.get_cross_signature_by_proving_key(&ika) {
                        if id_sig_data.len() > 32 {
                            registry.identity_to_prover = Some(keys::Ed448Signature {
                                signature: id_sig_data[32..].to_vec(),
                                ..Default::default()
                            });
                        }
                    }
                }

                identity_key_address = Some(ika);
            }
        }

        // Collect keys parented by prover key
        self.collect_x448_keys(prover_key_address, &mut registry);
        self.collect_decaf448_keys(prover_key_address, &mut registry);

        // Also collect keys parented by identity key
        if let Some(ref ika) = identity_key_address {
            self.collect_x448_keys(ika, &mut registry);
            self.collect_decaf448_keys(ika, &mut registry);
        }

        Ok(registry)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::store::KeyStore;

    /// Create an in-memory RocksDB and return the store.
    fn test_store() -> RocksKeyStore {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, tmp.path()).unwrap();
        // Leak so the directory persists while db is open.
        std::mem::forget(tmp);
        RocksKeyStore::new(Arc::new(db))
    }

    fn make_txn(store: &RocksKeyStore) -> Box<dyn store::Transaction> {
        store.new_transaction().unwrap()
    }

    // ---------------------------------------------------------------
    // Identity keys
    // ---------------------------------------------------------------

    #[test]
    fn test_identity_key_round_trip() {
        let store = test_store();
        let address = vec![0xAA; 32];
        let key = keys::Ed448PublicKey {
            key_value: vec![0x42; 57],
        };

        let txn = make_txn(&store);
        store.put_identity_key(txn.as_ref(), &address, &key).unwrap();
        txn.commit().unwrap();

        let got = store.get_identity_key(&address).unwrap();
        assert_eq!(got.key_value, key.key_value);
    }

    #[test]
    fn test_identity_key_not_found() {
        let store = test_store();
        let result = store.get_identity_key(&[0x00; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), QuilError::NotFound(_)));
    }

    // ---------------------------------------------------------------
    // Proving keys
    // ---------------------------------------------------------------

    #[test]
    fn test_proving_key_round_trip() {
        let store = test_store();
        let address = vec![0xBB; 32];
        let key = keys::Bls48581SignatureWithProofOfPossession {
            signature: vec![0x11; 74],
            public_key: Some(keys::Bls48581g2PublicKey {
                key_value: vec![0x22; 585],
            }),
            pop_signature: vec![0x33; 74],
        };

        let txn = make_txn(&store);
        store.put_proving_key(txn.as_ref(), &address, &key).unwrap();
        txn.commit().unwrap();

        let got = store.get_proving_key(&address).unwrap();
        assert_eq!(got.signature, key.signature);
        assert_eq!(got.pop_signature, key.pop_signature);
        assert_eq!(
            got.public_key.as_ref().unwrap().key_value,
            key.public_key.as_ref().unwrap().key_value
        );
    }

    #[test]
    fn test_proving_key_not_found() {
        let store = test_store();
        let result = store.get_proving_key(&[0xFF; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), QuilError::NotFound(_)));
    }

    // ---------------------------------------------------------------
    // Cross signatures
    // ---------------------------------------------------------------

    #[test]
    fn test_cross_signature_round_trip() {
        let store = test_store();
        let id_addr = vec![0x01; 32];
        let prov_addr = vec![0x02; 32];
        let id_sig = vec![0xAA; 114]; // Ed448 signature
        let prov_sig = vec![0xBB; 74]; // BLS signature

        let txn = make_txn(&store);
        store
            .put_cross_signature(txn.as_ref(), &id_addr, &prov_addr, &id_sig, &prov_sig)
            .unwrap();
        txn.commit().unwrap();

        // By identity key
        let got_by_id = store
            .get_cross_signature_by_identity_key(&id_addr)
            .unwrap();
        assert_eq!(&got_by_id[..32], &prov_addr[..]);
        assert_eq!(&got_by_id[32..], &id_sig[..]);

        // By proving key
        let got_by_prov = store
            .get_cross_signature_by_proving_key(&prov_addr)
            .unwrap();
        assert_eq!(&got_by_prov[..32], &id_addr[..]);
        assert_eq!(&got_by_prov[32..], &prov_sig[..]);
    }

    // ---------------------------------------------------------------
    // Signed X448 keys
    // ---------------------------------------------------------------

    #[test]
    fn test_signed_x448_key_round_trip() {
        let store = test_store();
        let address = vec![0xCC; 32];
        let key = keys::SignedX448Key {
            key: Some(keys::X448PublicKey {
                key_value: vec![0x55; 57],
            }),
            parent_key_address: vec![0xDD; 32],
            created_at: 1000,
            expires_at: 2000,
            key_purpose: "inbox".to_string(),
            signature: Some(keys::signed_x448_key::Signature::Ed448Signature(
                keys::Ed448Signature {
                    signature: vec![0xEE; 114],
                    ..Default::default()
                },
            )),
        };

        let txn = make_txn(&store);
        store
            .put_signed_x448_key(txn.as_ref(), &address, &key)
            .unwrap();
        txn.commit().unwrap();

        let got = store.get_signed_x448_key(&address).unwrap();
        assert_eq!(got.key_purpose, "inbox");
        assert_eq!(got.created_at, 1000);
        assert_eq!(got.expires_at, 2000);
        assert_eq!(
            got.key.as_ref().unwrap().key_value,
            key.key.as_ref().unwrap().key_value
        );
    }

    #[test]
    fn test_signed_x448_keys_by_parent() {
        let store = test_store();
        let parent = vec![0xAA; 32];

        // Insert two keys with same parent, different purposes
        let addr1 = vec![0x01; 32];
        let key1 = keys::SignedX448Key {
            key: Some(keys::X448PublicKey {
                key_value: vec![0x10; 57],
            }),
            parent_key_address: parent.clone(),
            created_at: 100,
            expires_at: 0,
            key_purpose: "inbox".to_string(),
            signature: None,
        };

        let addr2 = vec![0x02; 32];
        let key2 = keys::SignedX448Key {
            key: Some(keys::X448PublicKey {
                key_value: vec![0x20; 57],
            }),
            parent_key_address: parent.clone(),
            created_at: 200,
            expires_at: 0,
            key_purpose: "view".to_string(),
            signature: None,
        };

        let txn = make_txn(&store);
        store.put_signed_x448_key(txn.as_ref(), &addr1, &key1).unwrap();
        store.put_signed_x448_key(txn.as_ref(), &addr2, &key2).unwrap();
        txn.commit().unwrap();

        // Get all by parent (empty purpose = all)
        let all = store
            .get_signed_x448_keys_by_parent(&parent, "")
            .unwrap();
        assert_eq!(all.len(), 2);

        // Get filtered by purpose
        let inbox_only = store
            .get_signed_x448_keys_by_parent(&parent, "inbox")
            .unwrap();
        assert_eq!(inbox_only.len(), 1);
        assert_eq!(inbox_only[0].key_purpose, "inbox");

        let view_only = store
            .get_signed_x448_keys_by_parent(&parent, "view")
            .unwrap();
        assert_eq!(view_only.len(), 1);
        assert_eq!(view_only[0].key_purpose, "view");
    }

    // ---------------------------------------------------------------
    // Key registry
    // ---------------------------------------------------------------

    #[test]
    fn test_key_registry_assembly() {
        let store = test_store();

        let id_addr = vec![0x01; 32];
        let prov_addr = vec![0x02; 32];

        // Store identity key
        let id_key = keys::Ed448PublicKey {
            key_value: vec![0xAA; 57],
        };
        let txn = make_txn(&store);
        store.put_identity_key(txn.as_ref(), &id_addr, &id_key).unwrap();
        txn.commit().unwrap();

        // Store proving key
        let prov_key = keys::Bls48581SignatureWithProofOfPossession {
            signature: vec![0xBB; 74],
            public_key: Some(keys::Bls48581g2PublicKey {
                key_value: vec![0xCC; 585],
            }),
            pop_signature: vec![0xDD; 74],
        };
        let txn = make_txn(&store);
        store.put_proving_key(txn.as_ref(), &prov_addr, &prov_key).unwrap();
        txn.commit().unwrap();

        // Store cross signatures
        let id_sig = vec![0xEE; 114];
        let prov_sig = vec![0xFF; 74];
        let txn = make_txn(&store);
        store
            .put_cross_signature(txn.as_ref(), &id_addr, &prov_addr, &id_sig, &prov_sig)
            .unwrap();
        txn.commit().unwrap();

        // Store a signed X448 key under the identity key
        let x448_addr = vec![0x03; 32];
        let x448_key = keys::SignedX448Key {
            key: Some(keys::X448PublicKey {
                key_value: vec![0x44; 57],
            }),
            parent_key_address: id_addr.clone(),
            created_at: 500,
            expires_at: 0,
            key_purpose: "inbox".to_string(),
            signature: None,
        };
        let txn = make_txn(&store);
        store
            .put_signed_x448_key(txn.as_ref(), &x448_addr, &x448_key)
            .unwrap();
        txn.commit().unwrap();

        // Retrieve the full registry
        let registry = store.get_key_registry(&id_addr).unwrap();

        // Should have identity key
        assert!(registry.identity_key.is_some());
        assert_eq!(registry.identity_key.as_ref().unwrap().key_value, id_key.key_value);

        // Should have prover key
        assert!(registry.prover_key.is_some());
        assert_eq!(
            registry.prover_key.as_ref().unwrap().key_value,
            prov_key.public_key.as_ref().unwrap().key_value
        );

        // Should have cross signatures
        assert!(registry.identity_to_prover.is_some());
        assert!(registry.prover_to_identity.is_some());

        // Should have the X448 key under "inbox"
        assert!(registry.keys_by_purpose.contains_key("inbox"));
        let inbox_coll = registry.keys_by_purpose.get("inbox").unwrap();
        assert_eq!(inbox_coll.x448_keys.len(), 1);

        // last_updated should reflect the X448 key's created_at
        assert_eq!(registry.last_updated, 500);
    }

    #[test]
    fn test_key_registry_by_prover() {
        let store = test_store();

        let id_addr = vec![0x10; 32];
        let prov_addr = vec![0x20; 32];

        // Store proving key
        let prov_key = keys::Bls48581SignatureWithProofOfPossession {
            signature: vec![0xBB; 74],
            public_key: Some(keys::Bls48581g2PublicKey {
                key_value: vec![0xCC; 585],
            }),
            pop_signature: vec![0xDD; 74],
        };
        let txn = make_txn(&store);
        store.put_proving_key(txn.as_ref(), &prov_addr, &prov_key).unwrap();
        txn.commit().unwrap();

        // Store identity key
        let id_key = keys::Ed448PublicKey {
            key_value: vec![0xAA; 57],
        };
        let txn = make_txn(&store);
        store.put_identity_key(txn.as_ref(), &id_addr, &id_key).unwrap();
        txn.commit().unwrap();

        // Store cross signatures
        let id_sig = vec![0xEE; 114];
        let prov_sig = vec![0xFF; 74];
        let txn = make_txn(&store);
        store
            .put_cross_signature(txn.as_ref(), &id_addr, &prov_addr, &id_sig, &prov_sig)
            .unwrap();
        txn.commit().unwrap();

        // Retrieve registry by prover
        let registry = store.get_key_registry_by_prover(&prov_addr).unwrap();

        assert!(registry.prover_key.is_some());
        assert!(registry.identity_key.is_some());
        assert!(registry.prover_to_identity.is_some());
    }

    // ---------------------------------------------------------------
    // Key encoding correctness
    // ---------------------------------------------------------------

    #[test]
    fn test_key_encoding_identity() {
        let addr = vec![0x42; 16];
        let k = identity_key_key(&addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_IDENTITY);
        assert_eq!(&k[2..], &addr[..]);
    }

    #[test]
    fn test_key_encoding_proving() {
        let addr = vec![0x42; 16];
        let k = proving_key_key(&addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_PROVING);
        assert_eq!(&k[2..], &addr[..]);
    }

    #[test]
    fn test_key_encoding_cross_sig() {
        let addr = vec![0x42; 16];
        let k = cross_signature_key(&addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_CROSS_SIGNATURE);
        assert_eq!(&k[2..], &addr[..]);
    }

    #[test]
    fn test_key_encoding_x448_by_parent() {
        let parent = vec![0xAA; 32];
        let key_addr = vec![0xBB; 32];
        let k = signed_x448_key_by_parent_key(&parent, "inbox", &key_addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_X448_SIGNED_KEY_BY_PARENT);
        assert_eq!(&k[2..34], &parent[..]);
        // purpose is 8 bytes, zero-padded
        assert_eq!(&k[34..39], b"inbox");
        assert_eq!(&k[39..42], &[0, 0, 0]); // zero-pad
        assert_eq!(&k[42..74], &key_addr[..]);
    }

    #[test]
    fn test_key_encoding_x448_by_expiry() {
        let addr = vec![0xCC; 32];
        let k = signed_x448_key_expiry_key(12345, &addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_X448_SIGNED_KEY_BY_EXPIRY);
        assert_eq!(&k[2..10], &12345u64.to_be_bytes());
        assert_eq!(&k[10..], &addr[..]);
    }

    #[test]
    fn test_key_encoding_decaf448() {
        let addr = vec![0xDD; 32];
        let k = signed_decaf448_key_key(&addr);
        assert_eq!(k[0], KEY_BUNDLE);
        assert_eq!(k[1], KEY_DECAF448_SIGNED_KEY_BY_ID);
        assert_eq!(&k[2..], &addr[..]);
    }

    #[test]
    fn test_increment_prefix() {
        assert_eq!(increment_prefix(&[0x03, 0x50]), vec![0x03, 0x51]);
        assert_eq!(increment_prefix(&[0x03, 0xFF]), vec![0x04, 0x00]);
        assert_eq!(increment_prefix(&[0xFF, 0xFF]), vec![0x00, 0x00, 0x00]);
    }
}
