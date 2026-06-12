//! Ed448 noise handshake payload signing/verification.
//!
//! The noise XX handshake exchanges a payload containing the peer's
//! identity public key and a signature over the DH static key.
//! Go uses Ed448 (KeyType=4) for this; stock rust-libp2p uses Ed25519.
//!
//! This module provides the payload generation and verification
//! functions compatible with Go's noise implementation, so the Rust
//! node can authenticate with Go nodes.
//!
//! **Wire format**:
//! ```text
//! NoiseHandshakePayload (protobuf):
//!   bytes identity_key = 1;   // protobuf(PublicKey{Type:4, Data:ed448_pubkey_57})
//!   bytes identity_sig = 2;   // ed448_sign(seed, "noise-libp2p-static-key:" || dh_pubkey)
//!   NoiseExtensions extensions = 4;
//! ```

use quil_types::error::{QuilError, Result};

/// Prefix for the noise static key signature domain separation.
/// Must match Go's `payloadSigPrefix`.
pub const PAYLOAD_SIG_PREFIX: &[u8] = b"noise-libp2p-static-key:";

/// Protobuf KeyType for Ed448 (matches Go's `crypto.proto`).
const KEY_TYPE_ED448: u32 = 4;

/// Generate the noise handshake payload for an Ed448 identity.
///
/// - `ed448_seed`: 57-byte Ed448 private key seed
/// - `ed448_pubkey`: 57-byte Ed448 public key
/// - `dh_public_key`: the X25519 DH public key from the noise handshake
///
/// Returns the serialized `NoiseHandshakePayload` protobuf.
pub fn generate_ed448_payload(
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
    dh_public_key: &[u8],
) -> Result<Vec<u8>> {
    // 1. Marshal the Ed448 public key as protobuf PublicKey{Type:4, Data:pubkey}
    let identity_key = encode_ed448_public_key(ed448_pubkey);

    // 2. Sign: ed448_sign(seed, "noise-libp2p-static-key:" || dh_public_key)
    let mut to_sign = Vec::with_capacity(PAYLOAD_SIG_PREFIX.len() + dh_public_key.len());
    to_sign.extend_from_slice(PAYLOAD_SIG_PREFIX);
    to_sign.extend_from_slice(dh_public_key);

    let private_key = ed448_rust::PrivateKey::from(*ed448_seed);
    let signature = private_key.sign(&to_sign, None)
        .map_err(|e| QuilError::Crypto(format!("Ed448 sign failed: {:?}", e)))?;

    // 3. Encode as NoiseHandshakePayload protobuf
    // Field 1 (identity_key): tag=0x0a, len, data
    // Field 2 (identity_sig): tag=0x12, len, data
    let mut payload = Vec::new();
    // field 1
    payload.push(0x0a);
    encode_varint(&mut payload, identity_key.len() as u64);
    payload.extend_from_slice(&identity_key);
    // field 2
    payload.push(0x12);
    encode_varint(&mut payload, signature.len() as u64);
    payload.extend_from_slice(&signature);

    Ok(payload)
}

/// Verify a remote peer's noise handshake payload using Ed448.
///
/// - `payload_bytes`: serialized `NoiseHandshakePayload` protobuf
/// - `remote_dh_public`: the remote's X25519 DH public key
///
/// Returns the remote's 57-byte Ed448 public key on success.
pub fn verify_ed448_payload(
    payload_bytes: &[u8],
    remote_dh_public: &[u8],
) -> Result<Vec<u8>> {
    // Decode protobuf fields
    let (identity_key, identity_sig) = decode_noise_payload(payload_bytes)?;

    // Extract Ed448 public key from the protobuf-encoded PublicKey
    let ed448_pubkey = decode_ed448_public_key(&identity_key)?;

    // Verify signature
    let mut to_verify = Vec::with_capacity(PAYLOAD_SIG_PREFIX.len() + remote_dh_public.len());
    to_verify.extend_from_slice(PAYLOAD_SIG_PREFIX);
    to_verify.extend_from_slice(remote_dh_public);

    let pubkey = ed448_rust::PublicKey::try_from(ed448_pubkey.as_slice())
        .map_err(|e| QuilError::Crypto(format!("invalid Ed448 pubkey: {:?}", e)))?;

    pubkey.verify(&to_verify, &identity_sig, None)
        .map_err(|_| QuilError::Crypto("Ed448 noise signature verification failed".into()))?;

    Ok(ed448_pubkey)
}

/// Encode an Ed448 public key as protobuf PublicKey{Type:4, Data:pubkey}.
fn encode_ed448_public_key(pubkey: &[u8]) -> Vec<u8> {
    // PublicKey { Type type = 1; bytes data = 2; }
    // field 1 (type): tag=0x08, varint=4
    // field 2 (data): tag=0x12, len, data
    let mut buf = Vec::new();
    buf.push(0x08); // field 1, varint
    buf.push(KEY_TYPE_ED448 as u8);
    buf.push(0x12); // field 2, length-delimited
    encode_varint(&mut buf, pubkey.len() as u64);
    buf.extend_from_slice(pubkey);
    buf
}

/// Decode an Ed448 public key from protobuf PublicKey{Type:4, Data:pubkey}.
fn decode_ed448_public_key(data: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0;
    let mut key_type: Option<u32> = None;
    let mut key_data: Option<Vec<u8>> = None;

    while cursor < data.len() {
        let tag = data[cursor];
        cursor += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match (field_number, wire_type) {
            (1, 0) => {
                // varint
                let (val, consumed) = decode_varint(&data[cursor..])?;
                cursor += consumed;
                key_type = Some(val as u32);
            }
            (2, 2) => {
                // length-delimited
                let (len, consumed) = decode_varint(&data[cursor..])?;
                cursor += consumed;
                let len = len as usize;
                if cursor + len > data.len() {
                    return Err(QuilError::Crypto("truncated public key data".into()));
                }
                key_data = Some(data[cursor..cursor + len].to_vec());
                cursor += len;
            }
            _ => {
                return Err(QuilError::Crypto(format!("unexpected protobuf field {}/{}", field_number, wire_type)));
            }
        }
    }

    let kt = key_type.ok_or_else(|| QuilError::Crypto("missing key type".into()))?;
    if kt != KEY_TYPE_ED448 {
        return Err(QuilError::Crypto(format!("expected KeyType=4, got {}", kt)));
    }
    key_data.ok_or_else(|| QuilError::Crypto("missing key data".into()))
}

/// Decode NoiseHandshakePayload protobuf → (identity_key, identity_sig).
fn decode_noise_payload(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cursor = 0;
    let mut identity_key: Option<Vec<u8>> = None;
    let mut identity_sig: Option<Vec<u8>> = None;

    while cursor < data.len() {
        let tag = data[cursor];
        cursor += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        if wire_type != 2 {
            return Err(QuilError::Crypto(format!("unexpected wire type {}", wire_type)));
        }

        let (len, consumed) = decode_varint(&data[cursor..])?;
        cursor += consumed;
        let len = len as usize;
        if cursor + len > data.len() {
            return Err(QuilError::Crypto("truncated payload field".into()));
        }
        let field_data = data[cursor..cursor + len].to_vec();
        cursor += len;

        match field_number {
            1 => identity_key = Some(field_data),
            2 => identity_sig = Some(field_data),
            _ => {} // skip extensions and unknown fields
        }
    }

    Ok((
        identity_key.ok_or_else(|| QuilError::Crypto("missing identity_key".into()))?,
        identity_sig.ok_or_else(|| QuilError::Crypto("missing identity_sig".into()))?,
    ))
}

fn encode_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(QuilError::Crypto("varint overflow".into()));
        }
    }
    Err(QuilError::Crypto("truncated varint".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_generate_and_verify_round_trip() {
        // Generate an Ed448 keypair
        let privkey = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
        let seed = *privkey.as_bytes();
        // Derive public key by signing a dummy message and extracting
        // the public key from the Ed448 identity module
        let pubkey_bytes = crate::ed448_identity::derive_public_key(&seed);

        let dh_pubkey = [0xAAu8; 32];

        let payload = generate_ed448_payload(&seed, &pubkey_bytes, &dh_pubkey).unwrap();
        assert!(!payload.is_empty());

        let recovered_pubkey = verify_ed448_payload(&payload, &dh_pubkey).unwrap();
        assert_eq!(recovered_pubkey, pubkey_bytes);
    }

    #[test]
    fn payload_verify_rejects_wrong_dh_key() {
        let privkey = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
        let seed = *privkey.as_bytes();
        let pubkey_bytes = crate::ed448_identity::derive_public_key(&seed);

        let dh_pubkey = [0xAAu8; 32];
        let payload = generate_ed448_payload(&seed, &pubkey_bytes, &dh_pubkey).unwrap();

        let wrong_dh = [0xBBu8; 32];
        assert!(verify_ed448_payload(&payload, &wrong_dh).is_err());
    }

    #[test]
    fn encode_decode_ed448_public_key_round_trip() {
        let pubkey = vec![0x42u8; 57];
        let encoded = encode_ed448_public_key(&pubkey);
        let decoded = decode_ed448_public_key(&encoded).unwrap();
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn decode_rejects_wrong_key_type() {
        // Encode with KeyType=1 (Ed25519)
        let mut buf = Vec::new();
        buf.push(0x08);
        buf.push(1); // Ed25519
        buf.push(0x12);
        buf.push(32);
        buf.extend_from_slice(&[0u8; 32]);
        assert!(decode_ed448_public_key(&buf).is_err());
    }
}
