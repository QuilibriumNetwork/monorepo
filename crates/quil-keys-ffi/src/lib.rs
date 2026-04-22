// Handle-based FFI wrapper for quil-keys::FileKeyManager.
//
// UniFFI cannot pass trait objects across FFI, so we use u64 handles
// into a global HashMap<u64, FileKeyManager>.  The Go side calls
// create_key_manager() to obtain a handle and destroy_key_manager()
// to release it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use quil_crypto::Bls48581KeyConstructor;
use quil_keys::{FileKeyManager, KeyManager};
use quil_types::crypto::KeyType;

uniffi::include_scaffolding!("lib");

// ---------------------------------------------------------------------------
// Global handle table
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

static MANAGERS: Mutex<Option<HashMap<u64, FileKeyManager>>> = Mutex::new(None);

fn with_managers<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<u64, FileKeyManager>) -> R,
{
    let mut guard = MANAGERS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key_type_from_u8(v: u8) -> KeyType {
    match v {
        0 => KeyType::Ed448,
        1 => KeyType::X448,
        2 => KeyType::Bls48581G1,
        3 => KeyType::Bls48581G2,
        4 => KeyType::Decaf448,
        5 => KeyType::Secp256k1Sha256,
        6 => KeyType::Secp256k1Sha3,
        7 => KeyType::Ed25519,
        _ => panic!("unknown key type: {}", v),
    }
}

// ---------------------------------------------------------------------------
// FFI functions (match lib.udl)
// ---------------------------------------------------------------------------

/// Create a FileKeyManager and return its handle.
///
/// * `path`           - filesystem path to the YAML keystore file
/// * `encryption_key` - hex-encoded 32-byte AES-256-GCM key (empty = insecure default)
/// * `proving_key_id` - opaque proving key identifier
pub fn create_key_manager(path: String, encryption_key: String, proving_key_id: String) -> u64 {
    let bls = Box::new(Bls48581KeyConstructor);
    let mgr = FileKeyManager::new(PathBuf::from(&path), &encryption_key, proving_key_id, bls)
        .unwrap_or_else(|e| panic!("create_key_manager failed: {}", e));

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    with_managers(|m| m.insert(handle, mgr));
    handle
}

/// Destroy a previously created key manager, releasing its resources.
pub fn destroy_key_manager(handle: u64) {
    with_managers(|m| {
        m.remove(&handle);
    });
}

/// Ensure all standard keys (prover, onion, view, spend, device, device-pre)
/// exist in the keystore, creating any that are missing.
pub fn ensure_standard_keys(handle: u64) {
    with_managers(|m| {
        let mgr = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));
        mgr.ensure_standard_keys()
            .unwrap_or_else(|e| panic!("ensure_standard_keys failed: {}", e));
    });
}

/// Get the raw public key bytes for the given key type.
///
/// `key_type` uses the same encoding as `quil_types::crypto::KeyType`:
///   0=Ed448, 1=X448, 2=BLS48581G1, 3=BLS48581G2, 4=Decaf448, ...
pub fn get_public_key(handle: u64, key_type: u8) -> Vec<u8> {
    with_managers(|m| {
        let mgr = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));
        mgr.get_public_key(key_type_from_u8(key_type))
            .unwrap_or_else(|e| panic!("get_public_key failed: {}", e))
    })
}

/// Sign a message using the signer for `key_type`.
pub fn sign(handle: u64, key_type: u8, message: Vec<u8>) -> Vec<u8> {
    with_managers(|m| {
        let mgr = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));
        let signer = mgr
            .get_signer(key_type_from_u8(key_type))
            .unwrap_or_else(|e| panic!("get_signer failed: {}", e));
        signer
            .sign(&message)
            .unwrap_or_else(|e| panic!("sign failed: {}", e))
    })
}

/// Sign a message with an explicit domain separator.
pub fn sign_with_domain(handle: u64, key_type: u8, message: Vec<u8>, domain: Vec<u8>) -> Vec<u8> {
    with_managers(|m| {
        let mgr = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));
        let signer = mgr
            .get_signer(key_type_from_u8(key_type))
            .unwrap_or_else(|e| panic!("get_signer failed: {}", e));
        signer
            .sign_with_domain(&message, &domain)
            .unwrap_or_else(|e| panic!("sign_with_domain failed: {}", e))
    })
}

/// Convenience: create a temporary FileKeyManager, generate standard keys,
/// and return the BLS48581G2 public key.  The keystore is discarded afterward.
pub fn create_temp_key_manager_and_get_pubkey(encryption_key: String) -> Vec<u8> {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let keys_path = tmp_dir.path().join("keys.yml");

    let bls = Box::new(Bls48581KeyConstructor);
    let mgr = FileKeyManager::new(keys_path, &encryption_key, "temp".into(), bls)
        .expect("create temp key manager failed");

    mgr.ensure_standard_keys()
        .expect("ensure_standard_keys failed");

    mgr.get_public_key(KeyType::Bls48581G2)
        .expect("get_public_key failed")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn create_and_destroy_manager() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("keys.yml").to_string_lossy().to_string();
        let h = create_key_manager(path, TEST_KEY_HEX.into(), "test-id".into());
        assert!(h > 0);
        destroy_key_manager(h);
    }

    #[test]
    fn ensure_keys_and_get_pubkey() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("keys.yml").to_string_lossy().to_string();
        let h = create_key_manager(path, TEST_KEY_HEX.into(), "test-id".into());
        ensure_standard_keys(h);
        let pk = get_public_key(h, 3); // BLS48581G2
        assert!(!pk.is_empty());
        destroy_key_manager(h);
    }

    #[test]
    fn sign_and_sign_with_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("keys.yml").to_string_lossy().to_string();
        let h = create_key_manager(path, TEST_KEY_HEX.into(), "test-id".into());
        ensure_standard_keys(h);

        let sig = sign(h, 3, b"hello".to_vec());
        assert!(!sig.is_empty());

        let sig2 = sign_with_domain(h, 3, b"hello".to_vec(), b"domain".to_vec());
        assert!(!sig2.is_empty());

        destroy_key_manager(h);
    }

    #[test]
    fn temp_manager_returns_pubkey() {
        let pk = create_temp_key_manager_and_get_pubkey(TEST_KEY_HEX.into());
        assert!(!pk.is_empty());
    }

    #[test]
    #[should_panic(expected = "invalid handle")]
    fn invalid_handle_panics() {
        get_public_key(999999, 3);
    }
}
