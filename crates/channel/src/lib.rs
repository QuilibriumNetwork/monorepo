use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;
use ed448_rust::Ed448Error;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::{collections::HashMap, error::Error};

use ed448_goldilocks_plus::{
    elliptic_curve::group::GroupEncoding, elliptic_curve::Group, CompressedEdwardsY, EdwardsPoint,
    Scalar,
};
use protocols::{
    doubleratchet::{DoubleRatchetParticipant, P2PChannelEnvelope},
    tripleratchet::{PeerInfo, TripleRatchetParticipant},
    x3dh,
};

pub(crate) mod protocols;

uniffi::include_scaffolding!("lib");

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DoubleRatchetStateAndEnvelope {
    pub ratchet_state: String,
    pub envelope: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DoubleRatchetStateAndMessage {
    pub ratchet_state: String,
    pub message: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TripleRatchetStateAndMetadata {
    pub ratchet_state: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TripleRatchetStateAndEnvelope {
    pub ratchet_state: String,
    pub envelope: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TripleRatchetStateAndMessage {
    pub ratchet_state: String,
    pub message: Vec<u8>,
}

// ============ Keypair Types ============

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageCiphertext {
    pub ciphertext: String,
    pub initialization_vector: String,
    pub associated_data: Option<String>,
}

/// Deserialize a byte array from either a base64-encoded string OR
/// the legacy JSON-integer-array shape. Same on-disk type
/// (`Vec<u8>`) — only the input wire format changes. Mobile clients
/// (iOS Swift / Android Kotlin) now base64-encode their byte inputs
/// to avoid the per-byte `JSONArray.put(int)` boxing that previously
/// pushed Android heap into OOM territory.
fn deserialize_bytes_b64_or_array<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct BytesVisitor;
    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("base64 string or array of byte values")
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<Vec<u8>, E> {
            BASE64_STANDARD.decode(v).map_err(Error::custom)
        }
        fn visit_string<E: Error>(self, v: String) -> Result<Vec<u8>, E> {
            self.visit_str(&v)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(n) = seq.next_element::<i32>()? {
                out.push(n as u8);
            }
            Ok(out)
        }
    }
    d.deserialize_any(BytesVisitor)
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedInboxMessageEncryptRequest {
    #[serde(deserialize_with = "deserialize_bytes_b64_or_array")]
    pub inbox_public_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bytes_b64_or_array")]
    pub ephemeral_private_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bytes_b64_or_array")]
    pub plaintext: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedInboxMessageDecryptRequest {
    #[serde(deserialize_with = "deserialize_bytes_b64_or_array")]
    pub inbox_private_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bytes_b64_or_array")]
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: MessageCiphertext,
}

// ============ Encryption Helpers ============

fn encrypt_aead(plaintext: &[u8], key: &[u8]) -> Result<MessageCiphertext, String> {
    use aes_gcm::KeyInit;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;
    let nonce = Nonce::from_slice(&iv);

    let mut aad = [0u8; 32];
    OsRng.fill_bytes(&mut aad);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(MessageCiphertext {
        ciphertext: BASE64_STANDARD.encode(ciphertext),
        initialization_vector: BASE64_STANDARD.encode(iv.to_vec()),
        associated_data: Some(BASE64_STANDARD.encode(aad.to_vec())),
    })
}

fn decrypt_aead(ciphertext: &MessageCiphertext, key: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::KeyInit;
    if key.len() != 32 {
        return Err("Invalid key length".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;

    let iv = BASE64_STANDARD
        .decode(&ciphertext.initialization_vector)
        .map_err(|e| format!("Invalid IV: {}", e))?;
    if iv.len() != 12 {
        return Err("Invalid IV length".to_string());
    }
    let nonce = Nonce::from_slice(&iv);

    let associated_data = match &ciphertext.associated_data {
        Some(aad) => BASE64_STANDARD
            .decode(aad)
            .map_err(|e| format!("Invalid AAD: {}", e))?,
        None => Vec::new(),
    };

    let ct = BASE64_STANDARD
        .decode(&ciphertext.ciphertext)
        .map_err(|e| format!("Invalid ciphertext: {}", e))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: &associated_data,
            },
        )
        .map_err(|e| format!("Decryption failed: {}", e))
}

// ============ Key Generation ============

pub fn generate_x448() -> String {
    let priv_key = Scalar::random(&mut rand::thread_rng());
    let pub_key = EdwardsPoint::generator() * priv_key;

    match serde_json::to_string(&EncryptionKeyPair {
        public_key: pub_key.compress().to_bytes().to_vec(),
        private_key: priv_key.to_bytes().to_vec(),
    }) {
        Ok(result) => result,
        Err(e) => e.to_string(),
    }
}

pub fn generate_ed448() -> String {
    let priv_key = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
    let pub_key = ed448_rust::PublicKey::from(&priv_key);

    match serde_json::to_string(&EncryptionKeyPair {
        public_key: pub_key.as_byte().to_vec(),
        private_key: priv_key.as_bytes().to_vec(),
    }) {
        Ok(result) => result,
        Err(e) => e.to_string(),
    }
}

pub fn get_pubkey_x448(key: String) -> String {
    let maybe_key = BASE64_STANDARD.decode(&key);
    if maybe_key.is_err() {
        return maybe_key.unwrap_err().to_string();
    }

    let key_bytes = maybe_key.unwrap();
    if key_bytes.len() != 56 {
        return "invalid key length".to_string();
    }

    let mut priv_key_bytes = [0u8; 56];
    priv_key_bytes.copy_from_slice(&key_bytes);

    let priv_key = Scalar::from_bytes(&priv_key_bytes);
    let pub_key = EdwardsPoint::generator() * priv_key;

    format!(
        "\"{}\"",
        BASE64_STANDARD.encode(pub_key.compress().to_bytes().to_vec())
    )
}

pub fn get_pubkey_ed448(key: String) -> String {
    let maybe_key = BASE64_STANDARD.decode(&key);
    if maybe_key.is_err() {
        return maybe_key.unwrap_err().to_string();
    }

    let key_bytes = maybe_key.unwrap();
    if key_bytes.len() != 57 {
        return "invalid key length".to_string();
    }

    let key_arr: [u8; 57] = key_bytes.try_into().unwrap();
    let priv_key = ed448_rust::PrivateKey::from(key_arr);
    let pub_key = ed448_rust::PublicKey::from(&priv_key);

    format!("\"{}\"", BASE64_STANDARD.encode(pub_key.as_byte()))
}

// ============ Signing ============

pub fn sign_ed448(key: String, message: String) -> String {
    let maybe_key = BASE64_STANDARD.decode(&key);
    if maybe_key.is_err() {
        return maybe_key.unwrap_err().to_string();
    }

    let maybe_message = BASE64_STANDARD.decode(&message);
    if maybe_message.is_err() {
        return maybe_message.unwrap_err().to_string();
    }

    let key_bytes = maybe_key.unwrap();
    if key_bytes.len() != 57 {
        return "invalid key length".to_string();
    }

    let key_arr: [u8; 57] = key_bytes.try_into().unwrap();
    let priv_key = ed448_rust::PrivateKey::from(key_arr);
    let signature = priv_key.sign(&maybe_message.unwrap(), None);

    match signature {
        Ok(output) => format!("\"{}\"", BASE64_STANDARD.encode(output)),
        Err(Ed448Error::WrongKeyLength) => "invalid key length".to_string(),
        Err(Ed448Error::WrongPublicKeyLength) => "invalid public key length".to_string(),
        Err(Ed448Error::WrongSignatureLength) => "invalid signature length".to_string(),
        Err(Ed448Error::InvalidPoint) => "invalid point".to_string(),
        Err(Ed448Error::InvalidSignature) => "invalid signature".to_string(),
        Err(Ed448Error::ContextTooLong) => "context too long".to_string(),
    }
}

pub fn verify_ed448(public_key: String, message: String, signature: String) -> String {
    let maybe_key = BASE64_STANDARD.decode(&public_key);
    if maybe_key.is_err() {
        return maybe_key.unwrap_err().to_string();
    }

    let maybe_message = BASE64_STANDARD.decode(&message);
    if maybe_message.is_err() {
        return maybe_message.unwrap_err().to_string();
    }

    let maybe_signature = BASE64_STANDARD.decode(&signature);
    if maybe_signature.is_err() {
        return maybe_signature.unwrap_err().to_string();
    }

    let key_bytes = maybe_key.unwrap();
    if key_bytes.len() != 57 {
        return "invalid key length".to_string();
    }

    let pub_arr: [u8; 57] = key_bytes.try_into().unwrap();
    // `PublicKey::from` panics on a non-point key; this verifies untrusted input,
    // so fail with an error string instead of crashing.
    let pub_key = match ed448_rust::PublicKey::try_from(&pub_arr[..]) {
        Ok(k) => k,
        Err(_) => return "invalid public key".to_string(),
    };
    let result = pub_key.verify(&maybe_message.unwrap(), &maybe_signature.unwrap(), None);

    match result {
        Ok(()) => "true".to_string(),
        Err(Ed448Error::WrongKeyLength) => "invalid key length".to_string(),
        Err(Ed448Error::WrongPublicKeyLength) => "invalid public key length".to_string(),
        Err(Ed448Error::WrongSignatureLength) => "invalid signature length".to_string(),
        Err(Ed448Error::InvalidPoint) => "invalid point".to_string(),
        Err(Ed448Error::InvalidSignature) => "invalid signature".to_string(),
        Err(Ed448Error::ContextTooLong) => "context too long".to_string(),
    }
}

// ============ Inbox Message Encryption ============

pub fn encrypt_inbox_message(input: String) -> String {
    let json: Result<SealedInboxMessageEncryptRequest, serde_json::Error> =
        serde_json::from_str(&input);
    match json {
        Ok(params) => {
            let key = params.ephemeral_private_key;
            if key.len() != 56 {
                return "invalid ephemeral key length".to_string();
            }

            let inbox_key = params.inbox_public_key;
            if inbox_key.len() != 57 {
                return "invalid inbox key length".to_string();
            }

            let key_bytes: [u8; 56] = key.try_into().unwrap();
            let inbox_key_bytes: [u8; 57] = inbox_key.try_into().unwrap();
            let priv_key = Scalar::from_bytes(&key_bytes);
            let maybe_pub_key = CompressedEdwardsY(inbox_key_bytes).decompress();

            if maybe_pub_key.is_none().into() {
                return "invalid inbox key".to_string();
            }

            let dh_output = priv_key * maybe_pub_key.unwrap();
            let hkdf = Hkdf::<Sha512>::new(None, &dh_output.compress().to_bytes());
            let mut derived = [0u8; 32];
            if hkdf
                .expand(b"quilibrium-sealed-sender", &mut derived)
                .is_err()
            {
                return "invalid length".to_string();
            }

            match encrypt_aead(&params.plaintext, &derived) {
                Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| e.to_string()),
                Err(e) => e,
            }
        }
        Err(e) => e.to_string(),
    }
}

pub fn decrypt_inbox_message(input: String) -> String {
    let json: Result<SealedInboxMessageDecryptRequest, serde_json::Error> =
        serde_json::from_str(&input);
    match json {
        Ok(params) => {
            let ephemeral_key = params.ephemeral_public_key;
            if ephemeral_key.len() != 57 {
                return "invalid ephemeral key length".to_string();
            }

            let inbox_key = params.inbox_private_key;
            if inbox_key.len() != 56 {
                return "invalid inbox key length".to_string();
            }

            let ephemeral_key_bytes: [u8; 57] = ephemeral_key.try_into().unwrap();
            let inbox_key_bytes: [u8; 56] = inbox_key.try_into().unwrap();
            let priv_key = Scalar::from_bytes(&inbox_key_bytes);
            let maybe_eph_key = CompressedEdwardsY(ephemeral_key_bytes).decompress();

            if maybe_eph_key.is_none().into() {
                return "invalid ephemeral key".to_string();
            }

            let dh_output = priv_key * maybe_eph_key.unwrap();
            let hkdf = Hkdf::<Sha512>::new(None, &dh_output.compress().to_bytes());
            let mut derived = [0u8; 32];
            if hkdf
                .expand(b"quilibrium-sealed-sender", &mut derived)
                .is_err()
            {
                return "invalid length".to_string();
            }

            match decrypt_aead(&params.ciphertext, &derived) {
                // Return the decrypted bytes as a base64-encoded string
                // instead of a JSON array of integers. Same `String`
                // wire type (so UniFFI bindings stay byte-identical),
                // but the payload is ~3x smaller AND the receiver does
                // an O(n) base64 decode instead of allocating a boxed
                // Integer per byte through `org.json.JSONArray`. That
                // was the source of OOM crashes on Android for large
                // messages — see project_rust_binding_bytes_format
                // memory for context. Errors continue to flow back as
                // plain-text strings; receivers distinguish success
                // from error by attempting a base64 decode (errors
                // aren't valid base64).
                Ok(result) => BASE64_STANDARD.encode(&result),
                Err(e) => e,
            }
        }
        Err(e) => e.to_string(),
    }
}

// ============ X3DH Key Agreement ============

pub fn sender_x3dh(
    sending_identity_private_key: &Vec<u8>,
    sending_ephemeral_private_key: &Vec<u8>,
    receiving_identity_key: &Vec<u8>,
    receiving_signed_pre_key: &Vec<u8>,
    session_key_length: u64,
) -> String {
    if sending_identity_private_key.len() != 56 {
        return "invalid sending identity private key length".to_string();
    }

    if sending_ephemeral_private_key.len() != 56 {
        return "invalid sending ephemeral private key length".to_string();
    }

    if receiving_identity_key.len() != 57 {
        return "invalid receiving identity public key length".to_string();
    }

    if receiving_signed_pre_key.len() != 57 {
        return "invalid receiving signed public key length".to_string();
    }

    let sidk = Scalar::from_bytes(sending_identity_private_key.as_slice().try_into().unwrap());
    let sepk = Scalar::from_bytes(sending_ephemeral_private_key.as_slice().try_into().unwrap());
    let ridk =
        CompressedEdwardsY(receiving_identity_key.as_slice().try_into().unwrap()).decompress();
    let rspk =
        CompressedEdwardsY(receiving_signed_pre_key.as_slice().try_into().unwrap()).decompress();

    if ridk.is_none().into() {
        return "invalid receiving identity public key".to_string();
    }

    if rspk.is_none().into() {
        return "invalid receiving signed public key".to_string();
    }

    match x3dh::sender_x3dh(
        &sidk,
        &sepk,
        &ridk.unwrap(),
        &rspk.unwrap(),
        session_key_length,
    ) {
        Some(result) => {
            return format!("\"{}\"", BASE64_STANDARD.encode(result));
        }
        None => {
            return "could not perform key agreement".to_string();
        }
    }
}

pub fn receiver_x3dh(
    sending_identity_private_key: &Vec<u8>,
    sending_signed_private_key: &Vec<u8>,
    receiving_identity_key: &Vec<u8>,
    receiving_ephemeral_key: &Vec<u8>,
    session_key_length: u64,
) -> String {
    if sending_identity_private_key.len() != 56 {
        return "invalid sending identity private key length".to_string();
    }

    if sending_signed_private_key.len() != 56 {
        return "invalid sending signed private key length".to_string();
    }

    if receiving_identity_key.len() != 57 {
        return "invalid receiving identity public key length".to_string();
    }

    if receiving_ephemeral_key.len() != 57 {
        return "invalid receiving ephemeral public key length".to_string();
    }

    let sidk = Scalar::from_bytes(sending_identity_private_key.as_slice().try_into().unwrap());
    let sspk = Scalar::from_bytes(sending_signed_private_key.as_slice().try_into().unwrap());
    let ridk =
        CompressedEdwardsY(receiving_identity_key.as_slice().try_into().unwrap()).decompress();
    let repk =
        CompressedEdwardsY(receiving_ephemeral_key.as_slice().try_into().unwrap()).decompress();

    if ridk.is_none().into() {
        return "invalid receiving identity public key".to_string();
    }

    if repk.is_none().into() {
        return "invalid receiving signed public key".to_string();
    }

    match x3dh::receiver_x3dh(
        &sidk,
        &sspk,
        &ridk.unwrap(),
        &repk.unwrap(),
        session_key_length,
    ) {
        Some(result) => {
            return format!("\"{}\"", BASE64_STANDARD.encode(result));
        }
        None => {
            return "could not perform key agreement".to_string();
        }
    }
}

pub fn new_double_ratchet(
    session_key: &Vec<u8>,
    sending_header_key: &Vec<u8>,
    next_receiving_header_key: &Vec<u8>,
    is_sender: bool,
    sending_ephemeral_private_key: &Vec<u8>,
    receiving_ephemeral_key: &Vec<u8>,
) -> String {
    if sending_ephemeral_private_key.len() != 56 {
        return "invalid private key length".to_string();
    }

    if receiving_ephemeral_key.len() != 57 {
        return "invalid public key length".to_string();
    }

    let mut sending_ephemeral_private_key_bytes = [0u8; 56];
    sending_ephemeral_private_key_bytes.copy_from_slice(&sending_ephemeral_private_key);

    let mut receiving_ephemeral_key_bytes = [0u8; 57];
    receiving_ephemeral_key_bytes.copy_from_slice(&receiving_ephemeral_key);

    let sending_key = Scalar::from_bytes(&sending_ephemeral_private_key_bytes.into());
    let receiving_key =
        EdwardsPoint::from_bytes(&receiving_ephemeral_key_bytes.into()).into_option();
    if receiving_key.is_none() {
        return "invalid receiving key".to_string();
    }

    let participant = DoubleRatchetParticipant::new(
        &session_key,
        &sending_header_key,
        &next_receiving_header_key,
        is_sender,
        sending_key,
        receiving_key.unwrap(),
    );

    if participant.is_err() {
        return participant.unwrap_err().to_string();
    }

    let json = participant.unwrap().to_json();
    if json.is_err() {
        return json.unwrap_err().to_string();
    }

    return json.unwrap();
}

pub fn double_ratchet_encrypt(
    ratchet_state_and_message: DoubleRatchetStateAndMessage,
) -> Result<DoubleRatchetStateAndEnvelope, CryptoError> {
    let ratchet_state = ratchet_state_and_message.ratchet_state.clone();
    let participant = DoubleRatchetParticipant::from_json(ratchet_state.clone())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let mut dr = participant;
    let envelope = dr
        .ratchet_encrypt(&ratchet_state_and_message.message)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let participant_json = dr
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    let envelope_json = envelope
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(DoubleRatchetStateAndEnvelope {
        ratchet_state: participant_json,
        envelope: envelope_json,
    })
}

pub fn double_ratchet_decrypt(
    ratchet_state_and_envelope: DoubleRatchetStateAndEnvelope,
) -> Result<DoubleRatchetStateAndMessage, CryptoError> {
    let ratchet_state = ratchet_state_and_envelope.ratchet_state.clone();
    let participant = DoubleRatchetParticipant::from_json(ratchet_state.clone())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    let envelope = P2PChannelEnvelope::from_json(ratchet_state_and_envelope.envelope)
        .map_err(|e| CryptoError::InvalidEnvelope(e.to_string()))?;

    let mut dr = participant;
    let message = dr
        .ratchet_decrypt(&envelope)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let participant_json = dr
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(DoubleRatchetStateAndMessage {
        ratchet_state: participant_json,
        message: message,
    })
}

pub fn new_triple_ratchet(
    peers: &Vec<Vec<u8>>,
    peer_key: &Vec<u8>,
    identity_key: &Vec<u8>,
    signed_pre_key: &Vec<u8>,
    threshold: u64,
    async_dkg_ratchet: bool,
) -> TripleRatchetStateAndMetadata {
    if peer_key.len() != 56 {
        return TripleRatchetStateAndMetadata {
            ratchet_state: "invalid peerkey".to_string(),
            metadata: HashMap::new(),
        };
    }

    if identity_key.len() != 56 {
        return TripleRatchetStateAndMetadata {
            ratchet_state: "invalid identity key".to_string(),
            metadata: HashMap::new(),
        };
    }

    if signed_pre_key.len() != 56 {
        return TripleRatchetStateAndMetadata {
            ratchet_state: "invalid signed pre key".to_string(),
            metadata: HashMap::new(),
        };
    }

    if peers.len() < 3 {
        return TripleRatchetStateAndMetadata {
            ratchet_state: "invalid peer count".to_string(),
            metadata: HashMap::new(),
        };
    }

    if threshold > peers.len() as u64 {
        return TripleRatchetStateAndMetadata {
            ratchet_state: "invalid threshold".to_string(),
            metadata: HashMap::new(),
        };
    }

    let mut peer_key_bytes = [0u8; 56];
    peer_key_bytes.copy_from_slice(&peer_key);

    let mut identity_key_bytes = [0u8; 56];
    identity_key_bytes.copy_from_slice(&identity_key);

    let mut signed_pre_key_bytes = [0u8; 56];
    signed_pre_key_bytes.copy_from_slice(&signed_pre_key);

    let peer_key_scalar = Scalar::from_bytes(&peer_key_bytes.into());
    let identity_key_scalar = Scalar::from_bytes(&identity_key_bytes.into());
    let signed_pre_key_scalar = Scalar::from_bytes(&signed_pre_key_bytes.into());
    let mut peerinfos = Vec::<PeerInfo>::new();
    for pk in peers.iter() {
        if pk.len() != 171 {
            return TripleRatchetStateAndMetadata {
                ratchet_state: "invalid peer key size".to_string(),
                metadata: HashMap::new(),
            };
        }

        peerinfos.push(PeerInfo {
            public_key: pk[..57].into(),
            identity_public_key: pk[57..114].into(),
            signed_pre_public_key: pk[114..].into(),
        });
    }

    let participant = TripleRatchetParticipant::new(
        &peerinfos,
        peer_key_scalar,
        identity_key_scalar,
        signed_pre_key_scalar,
        threshold as usize,
        async_dkg_ratchet,
    );

    if participant.is_err() {
        return TripleRatchetStateAndMetadata {
            ratchet_state: participant.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let (tr, metadata) = participant.unwrap();

    let participant_json = tr.to_json();

    if participant_json.is_err() {
        return TripleRatchetStateAndMetadata {
            ratchet_state: participant_json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata_json = match metadata_to_json(&String::from(""), metadata) {
        Ok(value) => value,
        Err(value) => return value,
    };

    return TripleRatchetStateAndMetadata {
        ratchet_state: participant_json.unwrap(),
        metadata: metadata_json,
    };
}

fn metadata_to_json(
    _ratchet_state: &String,
    metadata: HashMap<Vec<u8>, P2PChannelEnvelope>,
) -> Result<HashMap<String, String>, TripleRatchetStateAndMetadata> {
    let mut metadata_json = HashMap::<String, String>::new();
    for (k, v) in metadata {
        let env = v.to_json();
        if env.is_err() {
            return Err(TripleRatchetStateAndMetadata {
                ratchet_state: env.err().unwrap().to_string(),
                metadata: HashMap::new(),
            });
        }

        metadata_json.insert(BASE64_STANDARD.encode(k), env.unwrap());
    }
    Ok(metadata_json)
}

// Inverse of `metadata_to_json`, kept so the JSON state format stays
// round-trippable; only the serializing half has a caller today.
#[allow(dead_code)]
fn json_to_metadata(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
    _ratchet_state: &String,
) -> Result<HashMap<Vec<u8>, P2PChannelEnvelope>, TripleRatchetStateAndMetadata> {
    let mut metadata = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in ratchet_state_and_metadata.metadata {
        let env = P2PChannelEnvelope::from_json(v);
        let kb = BASE64_STANDARD.decode(k);
        if env.is_err() {
            return Err(TripleRatchetStateAndMetadata {
                ratchet_state: env.err().unwrap().to_string(),
                metadata: HashMap::new(),
            });
        }
        if kb.is_err() {
            return Err(TripleRatchetStateAndMetadata {
                ratchet_state: kb.err().unwrap().to_string(),
                metadata: HashMap::new(),
            });
        }

        metadata.insert(kb.unwrap(), env.unwrap());
    }
    Ok(metadata)
}

fn json_to_metadata_result(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
    _ratchet_state: &String,
) -> Result<HashMap<Vec<u8>, P2PChannelEnvelope>, CryptoError> {
    let mut metadata = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in ratchet_state_and_metadata.metadata {
        let env = P2PChannelEnvelope::from_json(v)
            .map_err(|e| CryptoError::InvalidEnvelope(e.to_string()))?;
        let kb = BASE64_STANDARD
            .decode(k)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
        metadata.insert(kb, env);
    }
    Ok(metadata)
}

fn metadata_to_json_result(
    _ratchet_state: &String,
    metadata: HashMap<Vec<u8>, P2PChannelEnvelope>,
) -> Result<HashMap<String, String>, CryptoError> {
    let mut metadata_json = HashMap::<String, String>::new();
    for (k, v) in metadata {
        let env = v
            .to_json()
            .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;
        metadata_json.insert(BASE64_STANDARD.encode(k), env);
    }
    Ok(metadata_json)
}

pub fn triple_ratchet_init_round_1(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
) -> Result<TripleRatchetStateAndMetadata, CryptoError> {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let metadata = json_to_metadata_result(ratchet_state_and_metadata, &ratchet_state)?;

    let mut trp = tr;
    let result = trp
        .initialize(&metadata)
        .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

    let metadata_json = metadata_to_json_result(&ratchet_state, result)?;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndMetadata {
        ratchet_state: json,
        metadata: metadata_json,
    })
}

pub fn triple_ratchet_init_round_2(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
) -> Result<TripleRatchetStateAndMetadata, CryptoError> {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let metadata = json_to_metadata_result(ratchet_state_and_metadata, &ratchet_state)?;

    let mut trp = tr;
    let mut result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        let r = trp
            .receive_poly_frag(&k, &v)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        if let Some(out) = r {
            result = out;
        }
    }

    let metadata_json = metadata_to_json_result(&ratchet_state, result)?;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndMetadata {
        ratchet_state: json,
        metadata: metadata_json,
    })
}

pub fn triple_ratchet_init_round_3(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
) -> Result<TripleRatchetStateAndMetadata, CryptoError> {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let metadata = json_to_metadata_result(ratchet_state_and_metadata, &ratchet_state)?;

    let mut trp = tr;
    let mut result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        let r = trp
            .receive_commitment(&k, &v)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        if let Some(out) = r {
            result = out;
        }
    }

    let metadata_json = metadata_to_json_result(&ratchet_state, result)?;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndMetadata {
        ratchet_state: json,
        metadata: metadata_json,
    })
}

pub fn triple_ratchet_init_round_4(
    ratchet_state_and_metadata: TripleRatchetStateAndMetadata,
) -> Result<TripleRatchetStateAndMetadata, CryptoError> {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let metadata = json_to_metadata_result(ratchet_state_and_metadata, &ratchet_state)?;

    let mut trp = tr;
    let result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        trp.recombine(&k, &v)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
    }

    let metadata_json = metadata_to_json_result(&ratchet_state, result)?;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndMetadata {
        ratchet_state: json,
        metadata: metadata_json,
    })
}

pub fn triple_ratchet_encrypt(
    ratchet_state_and_message: TripleRatchetStateAndMessage,
) -> Result<TripleRatchetStateAndEnvelope, CryptoError> {
    let ratchet_state = ratchet_state_and_message.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let mut trp = tr;
    let envelope = trp
        .ratchet_encrypt(&ratchet_state_and_message.message)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let envelope_json = envelope
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndEnvelope {
        ratchet_state: json,
        envelope: envelope_json,
    })
}

pub fn triple_ratchet_decrypt(
    ratchet_state_and_envelope: TripleRatchetStateAndEnvelope,
) -> Result<TripleRatchetStateAndMessage, CryptoError> {
    let ratchet_state = ratchet_state_and_envelope.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state)
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;

    let mut trp = tr;
    let env = P2PChannelEnvelope::from_json(ratchet_state_and_envelope.envelope)
        .map_err(|e| CryptoError::InvalidEnvelope(e.to_string()))?;

    let result = trp
        .ratchet_decrypt(&env)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let message = result.0;

    let json = trp
        .to_json()
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;

    Ok(TripleRatchetStateAndMessage {
        ratchet_state: json,
        message: message,
    })
}

pub fn triple_ratchet_resize(
    ratchet_state: String,
    other: String,
    id: u64,
    total: u64,
) -> Vec<Vec<u8>> {
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return vec![vec![1]];
    }

    let other_bytes = hex::decode(other);
    if other_bytes.is_err() {
        return vec![other_bytes.unwrap_err().to_string().as_bytes().to_vec()];
    }

    let result = tr
        .unwrap()
        .ratchet_resize(other_bytes.unwrap(), id as usize, total as usize);
    if result.is_err() {
        return vec![result.unwrap_err().to_string().as_bytes().to_vec()];
    }

    return result.unwrap();
}

pub fn triple_ratchet_verify_point(
    ratchet_state: String,
    point: String,
    id: usize,
) -> Result<bool, Box<dyn Error>> {
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return Err(tr.unwrap_err());
    }

    let point_bytes = hex::decode(point);
    if point_bytes.is_err() {
        return Err(Box::new(point_bytes.unwrap_err()));
    }

    let result = tr.unwrap().point_verify(point_bytes.unwrap(), id);
    if result.is_err() {
        return Err(result.unwrap_err());
    }

    return Ok(result.unwrap());
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use ed448_goldilocks_plus::{elliptic_curve::Group, EdwardsPoint, Scalar};
    use protocols::{
        doubleratchet::P2PChannelEnvelope,
        tripleratchet::{PeerInfo, TripleRatchetParticipant},
    };

    #[test]
    fn test_four_party_triple_ratchet_communication() {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| {
                (
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                )
            })
            .collect();

        keys.sort_by(|a, b| {
            (a.0 * EdwardsPoint::generator())
                .compress()
                .to_bytes()
                .cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes())
        });

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, peer)| peer.clone())
                .collect();

            let (participant, init_msg) = TripleRatchetParticipant::new(
                &other_peers,
                keys[i].0.clone(),
                keys[i].1.clone(),
                keys[i].2.clone(),
                3,
                false,
            )
            .unwrap();

            participants.push(participant);

            for (j, env) in init_msg.iter() {
                init_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i]
                .initialize(&init_messages[&peer_infos[i].public_key.clone()])
                .unwrap();
            for (j, env) in result.iter() {
                frag_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap()
                {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Collect reveals and confirm zkpoks are valid, produce group key:
        for i in 0..4 {
            for (j, env) in reveal_messages[&peer_infos[i].public_key.clone()].iter() {
                participants[i].recombine(j, &env.clone()).unwrap();
            }
        }

        // Test sending and receiving messages
        let test_messages = [
            "hello there",
            "general kenobi",
            "you are a bold one",
            "*mechanical laughter*",
        ];

        for (i, message) in test_messages.iter().enumerate() {
            let encrypted = participants[i].ratchet_encrypt(message.as_bytes()).unwrap();
            for j in 0..4 {
                if i != j {
                    let decrypted = participants[j].ratchet_decrypt(&encrypted).unwrap();
                    assert_eq!(
                        message.as_bytes(),
                        decrypted.0.as_slice(),
                        "Message decryption failed for Participant {}",
                        j
                    );
                }
            }
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i]
                    .ratchet_encrypt(message1.as_bytes())
                    .unwrap();
                let encrypted2 = participants[i]
                    .ratchet_encrypt(message2.as_bytes())
                    .unwrap();

                for j in 0..4 {
                    if i != j {
                        let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                        assert_eq!(
                            message1.as_bytes(),
                            decrypted1.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                        let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                        assert_eq!(
                            message2.as_bytes(),
                            decrypted2.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_four_party_triple_ratchet_communication_with_serialization_each_step() {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| {
                (
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                )
            })
            .collect();

        keys.sort_by(|a, b| {
            (a.0 * EdwardsPoint::generator())
                .compress()
                .to_bytes()
                .cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes())
        });

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, peer)| peer.clone())
                .collect();

            let (participant, init_msg) = TripleRatchetParticipant::new(
                &other_peers,
                keys[i].0.clone(),
                keys[i].1.clone(),
                keys[i].2.clone(),
                3,
                false,
            )
            .unwrap();

            for (j, env) in init_msg.iter() {
                init_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }

            let participant_json = participant.to_json();
            if participant_json.is_err() {
                panic!("bad json");
            }
            participants
                .push(TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap());
        }

        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i]
                .initialize(&init_messages[&peer_infos[i].public_key.clone()])
                .unwrap();
            for (j, env) in result.iter() {
                frag_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }

            let participant_json = participants[i].to_json();
            participants[i] =
                TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] =
                TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap()
                {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] =
                TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Collect reveals and confirm zkpoks are valid, produce group key:
        for i in 0..4 {
            for (j, env) in reveal_messages[&peer_infos[i].public_key.clone()].iter() {
                participants[i].recombine(j, &env.clone()).unwrap();

                let participant_json = participants[i].to_json();
                participants[i] =
                    TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
            }
        }

        // Test sending and receiving messages
        let test_messages = [
            "hello there",
            "general kenobi",
            "you are a bold one",
            "*mechanical laughter*",
        ];

        for (i, message) in test_messages.iter().enumerate() {
            let encrypted = participants[i].ratchet_encrypt(message.as_bytes()).unwrap();
            for j in 0..4 {
                if i != j {
                    let decrypted = participants[j].ratchet_decrypt(&encrypted).unwrap();
                    assert_eq!(
                        message.as_bytes(),
                        decrypted.0.as_slice(),
                        "Message decryption failed for Participant {}",
                        j
                    );
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] =
                TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i]
                    .ratchet_encrypt(message1.as_bytes())
                    .unwrap();
                let encrypted2 = participants[i]
                    .ratchet_encrypt(message2.as_bytes())
                    .unwrap();

                for j in 0..4 {
                    if i != j {
                        let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                        assert_eq!(
                            message1.as_bytes(),
                            decrypted1.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                        let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                        assert_eq!(
                            message2.as_bytes(),
                            decrypted2.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                    }
                }

                let participant_json = participants[i].to_json();
                participants[i] =
                    TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
            }
        }
    }

    #[test]
    fn test_four_party_async_triple_ratchet_communication() {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| {
                (
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                    Scalar::random(&mut rng),
                )
            })
            .collect();

        keys.sort_by(|a, b| {
            (a.0 * EdwardsPoint::generator())
                .compress()
                .to_bytes()
                .cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes())
        });

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> =
            HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, peer)| peer.clone())
                .collect();

            let (participant, init_msg) = TripleRatchetParticipant::new(
                &other_peers,
                keys[i].0.clone(),
                keys[i].1.clone(),
                keys[i].2.clone(),
                2,
                true,
            )
            .unwrap();

            participants.push(participant);

            for (j, env) in init_msg.iter() {
                init_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i]
                .initialize(&init_messages[&peer_infos[i].public_key.clone()])
                .unwrap();
            for (j, env) in result.iter() {
                frag_messages
                    .get_mut(j)
                    .unwrap()
                    .insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap()
                {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages
                            .get_mut(j)
                            .unwrap()
                            .insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Collect reveals and confirm zkpoks are valid, produce group key:
        for i in 0..4 {
            for (j, env) in reveal_messages[&peer_infos[i].public_key.clone()].iter() {
                participants[i].recombine(j, &env.clone()).unwrap();
            }
        }

        // Test sending and receiving messages
        let test_messages = [
            "hello there",
            "general kenobi",
            "you are a bold one",
            "*mechanical laughter*",
        ];

        for (i, message) in test_messages.iter().enumerate() {
            let encrypted = participants[i].ratchet_encrypt(message.as_bytes()).unwrap();
            for j in 0..4 {
                if i != j {
                    let decrypted = participants[j].ratchet_decrypt(&encrypted).unwrap();
                    assert_eq!(
                        message.as_bytes(),
                        decrypted.0.as_slice(),
                        "Message decryption failed for Participant {}",
                        j
                    );
                }
            }
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i]
                    .ratchet_encrypt(message1.as_bytes())
                    .unwrap();
                let encrypted2 = participants[i]
                    .ratchet_encrypt(message2.as_bytes())
                    .unwrap();

                for j in 0..4 {
                    if i != j {
                        let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                        assert_eq!(
                            message1.as_bytes(),
                            decrypted1.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                        let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                        assert_eq!(
                            message2.as_bytes(),
                            decrypted2.0.as_slice(),
                            "Round message decryption failed for Participant {}",
                            j
                        );
                    }
                }
            }
        }
    }

    type Inbox = HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>>;

    /// Delivers `out`, sent by `from`, into each recipient's inbox.
    fn deliver(inbox: &mut Inbox, from: &[u8], out: HashMap<Vec<u8>, P2PChannelEnvelope>) {
        for (to, env) in out {
            inbox.entry(to).or_default().insert(from.to_vec(), env);
        }
    }

    /// Four members of an async triple ratchet group with threshold two,
    /// after the DKG, in the order of their public keys.
    fn async_group() -> Vec<TripleRatchetParticipant> {
        let mut rng = rand::thread_rng();
        let public = |k: &Scalar| {
            (k * EdwardsPoint::generator())
                .compress()
                .to_bytes()
                .to_vec()
        };
        let mut keys: Vec<[Scalar; 3]> = (0..4)
            .map(|_| [(); 3].map(|_| Scalar::random(&mut rng)))
            .collect();
        keys.sort_by_key(|k| public(&k[0]));
        let infos: Vec<PeerInfo> = keys
            .iter()
            .map(|k| PeerInfo {
                public_key: public(&k[0]),
                identity_public_key: public(&k[1]),
                signed_pre_public_key: public(&k[2]),
            })
            .collect();

        // Every member gets an inbox, empty or not: members send init
        // messages only to peers whose keys sort after their own, so the
        // first member receives none.
        let inbox = || -> Inbox {
            infos
                .iter()
                .map(|p| (p.public_key.clone(), HashMap::new()))
                .collect()
        };
        let mut members = Vec::new();
        let mut inits = inbox();
        for (i, k) in keys.iter().enumerate() {
            let others: Vec<PeerInfo> = (0..4)
                .filter(|&j| j != i)
                .map(|j| infos[j].clone())
                .collect();
            let (member, out) =
                TripleRatchetParticipant::new(&others, k[0], k[1], k[2], 2, true).unwrap();
            members.push(member);
            deliver(&mut inits, &infos[i].public_key, out);
        }
        let mut frags = inbox();
        for (i, member) in members.iter_mut().enumerate() {
            let out = member.initialize(&inits[&infos[i].public_key]).unwrap();
            deliver(&mut frags, &infos[i].public_key, out);
        }
        let mut commitments = inbox();
        for (i, member) in members.iter_mut().enumerate() {
            for (from, env) in &frags[&infos[i].public_key] {
                if let Some(out) = member.receive_poly_frag(from, env).unwrap() {
                    deliver(&mut commitments, &infos[i].public_key, out);
                }
            }
        }
        let mut reveals = inbox();
        for (i, member) in members.iter_mut().enumerate() {
            for (from, env) in &commitments[&infos[i].public_key] {
                if let Some(out) = member.receive_commitment(from, env).unwrap() {
                    deliver(&mut reveals, &infos[i].public_key, out);
                }
            }
        }
        for (i, member) in members.iter_mut().enumerate() {
            for (from, env) in &reveals[&infos[i].public_key] {
                member.recombine(from, env).unwrap();
            }
        }
        members
    }

    #[test]
    fn a_member_share_verifies_against_the_group_key() {
        let mut group = async_group();
        let (id, share) = group[1].dkg_share();
        assert!(group[0].point_verify(share, id).unwrap());
    }

    #[test]
    fn a_point_off_the_group_key_never_verifies() {
        let mut group = async_group();
        let (id, _) = group[1].dkg_share();
        let stranger = (Scalar::random(&mut rand::thread_rng()) * EdwardsPoint::generator())
            .compress()
            .to_bytes()
            .to_vec();
        assert!(
            !group[0].point_verify(stranger, id).unwrap(),
            "point_verify accepted a point off the group key"
        );
    }

    /// [`async_group`] after each member has sent one message to the
    /// others: each first message carries a DKG ratchet step, which moves
    /// every receiver's group key off the key the DKG produced.
    fn ratcheted_group() -> Vec<TripleRatchetParticipant> {
        let mut group = async_group();
        let before = group[0].dkg_group_key();
        for i in 0..group.len() {
            let sealed = group[i].ratchet_encrypt(b"hello").unwrap();
            for j in (0..group.len()).filter(|&j| j != i) {
                group[j].ratchet_decrypt(&sealed).unwrap();
            }
        }
        assert_ne!(
            group[0].dkg_group_key(),
            before,
            "no DKG ratchet step moved the group key"
        );
        group
    }

    #[test]
    fn point_verify_holds_past_a_dkg_ratchet_step() {
        let mut group = ratcheted_group();
        let (id, share) = group[1].dkg_share();
        assert!(
            group[0].point_verify(share, id).unwrap(),
            "a member share did not verify after a DKG ratchet step"
        );
        let stranger = (Scalar::random(&mut rand::thread_rng()) * EdwardsPoint::generator())
            .compress()
            .to_bytes()
            .to_vec();
        assert!(
            !group[0].point_verify(stranger, id).unwrap(),
            "point_verify accepted a point off the group key"
        );
    }

    /// Whether `decrypt` returned an error rather than panicking or
    /// succeeding.
    fn refused<T, E>(decrypt: impl FnOnce() -> Result<T, E>) -> bool {
        matches!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(decrypt)),
            Ok(Err(_))
        )
    }

    #[test]
    fn aead_decryption_refuses_a_malformed_nonce() {
        let key = [7u8; 32];
        let mut sealed = encrypt_aead(b"hello", &key).unwrap();
        // Five zero bytes; AES-GCM takes twelve.
        sealed.initialization_vector = "AAAAAAA=".to_string();
        assert!(
            refused(|| decrypt_aead(&sealed, &key)),
            "decryption did not refuse a malformed nonce"
        );
    }

    /// `envelope` with its header's nonce cut short, and with its header's
    /// associated data removed.
    fn malformed_headers(envelope: &P2PChannelEnvelope) -> [P2PChannelEnvelope; 2] {
        let mut short_nonce = envelope.clone();
        short_nonce.message_header.initialization_vector.truncate(5);
        let mut no_associated_data = envelope.clone();
        no_associated_data.message_header.associated_data = None;
        [short_nonce, no_associated_data]
    }

    #[test]
    fn a_double_ratchet_refuses_a_malformed_header() {
        use protocols::doubleratchet::{DoubleRatchetParticipant, MessageCiphertext};
        let mut rng = rand::thread_rng();
        let mut receiver = DoubleRatchetParticipant::new(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            false,
            Scalar::random(&mut rng),
            Scalar::random(&mut rng) * EdwardsPoint::generator(),
        )
        .unwrap();
        let sealed = |bytes: usize| MessageCiphertext {
            ciphertext: vec![9u8; bytes],
            initialization_vector: vec![0u8; 12],
            associated_data: Some(vec![0u8; 32]),
        };
        let envelope = P2PChannelEnvelope {
            protocol_identifier: 0x0100,
            message_header: sealed(96),
            message_body: sealed(32),
        };
        for malformed in malformed_headers(&envelope) {
            assert!(
                refused(|| receiver.ratchet_decrypt(&malformed)),
                "the double ratchet did not refuse a malformed header"
            );
        }
    }

    #[test]
    fn a_triple_ratchet_refuses_a_malformed_header() {
        let mut group = async_group();
        let envelope = group[0].ratchet_encrypt(b"hello").unwrap();
        for malformed in malformed_headers(&envelope) {
            assert!(
                refused(|| group[1].ratchet_decrypt(&malformed)),
                "the triple ratchet did not refuse a malformed header"
            );
        }
    }

    #[test]
    fn point_verify_refuses_a_point_of_the_wrong_length() {
        let mut group = async_group();
        let (id, mut share) = group[1].dkg_share();
        share.pop();
        assert!(
            refused(|| group[0].point_verify(share, id)),
            "point_verify did not refuse a point of the wrong length"
        );
    }

    /// A well-formed reveal no DKG round produced: two points and a
    /// 56-byte proof.
    fn stray_reveal() -> Vec<u8> {
        let point = || {
            (Scalar::random(&mut rand::thread_rng()) * EdwardsPoint::generator())
                .compress()
                .to_bytes()
                .to_vec()
        };
        let proof = Scalar::random(&mut rand::thread_rng()).to_bytes().to_vec();
        serde_json::to_vec(&serde_json::json!({
            "point": point(),
            "random_commitment_point": point(),
            "zk_pok": proof,
        }))
        .unwrap()
    }

    #[test]
    fn a_dkg_reveal_that_is_not_json_is_refused() {
        let mut group = async_group();
        let (to, from) = (group[0].member_key(), group[1].member_key());
        let sealed = group[1].seal_dkg_message(&to, b"not a reveal");
        assert!(
            refused(|| group[0].recombine(&from, &sealed)),
            "a malformed DKG reveal was not refused"
        );
    }

    #[test]
    fn a_late_dkg_reveal_is_refused() {
        let mut group = async_group();
        let (to, from) = (group[0].member_key(), group[1].member_key());
        let sealed = group[1].seal_dkg_message(&to, &stray_reveal());
        assert!(
            refused(|| group[0].recombine(&from, &sealed)),
            "a DKG reveal after the DKG was not refused"
        );
    }

    #[test]
    fn a_late_dkg_commitment_is_refused() {
        let mut group = async_group();
        let (to, from) = (group[0].member_key(), group[1].member_key());
        let sealed = group[1].seal_dkg_message(&to, &[7u8; 56]);
        assert!(
            refused(|| group[0].receive_commitment(&from, &sealed)),
            "a DKG commitment after the DKG was not refused"
        );
    }

    /// 57 bytes that decode to no point.
    fn invalid_point() -> [u8; 57] {
        (0u8..=255)
            .map(|b| {
                let mut p = [0u8; 57];
                p[0] = b;
                p
            })
            .find(|p| bool::from(EdwardsPoint::from_bytes(p[..].into()).is_none()))
            .expect("every candidate decoded to a point")
    }

    #[test]
    fn a_triple_ratchet_refuses_a_header_with_an_invalid_sender_key() {
        let mut group = async_group();
        // An invalid sender key, then a zero ephemeral key and chain
        // lengths: a header any member can seal under the group header key.
        let mut header = invalid_point().to_vec();
        header.extend_from_slice(&[0u8; 64]);
        let sealed = group[1].seal_header(&header);
        assert!(
            refused(|| group[0].ratchet_decrypt(&sealed)),
            "the triple ratchet did not refuse a header with an invalid sender key"
        );
    }

    #[test]
    fn a_double_ratchet_refuses_a_short_header() {
        use protocols::doubleratchet::DoubleRatchetParticipant;
        let mut rng = rand::thread_rng();
        let (sender_key, receiver_key) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let mut sender = DoubleRatchetParticipant::new(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            true,
            sender_key,
            receiver_key * EdwardsPoint::generator(),
        )
        .unwrap();
        let receiver = DoubleRatchetParticipant::new(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            false,
            receiver_key,
            sender_key * EdwardsPoint::generator(),
        )
        .unwrap();
        let hello = sender.ratchet_encrypt(b"hello").unwrap();
        assert_eq!(
            receiver.clone().ratchet_decrypt(&hello).unwrap(),
            b"hello",
            "the receiver did not open its correspondent's message"
        );
        // A valid point and three of the eight chain-length bytes.
        let mut header = (sender_key * EdwardsPoint::generator())
            .compress()
            .to_bytes()
            .to_vec();
        header.extend_from_slice(&[0u8; 3]);
        let sealed = sender.seal_header(&header);
        let mut receiver = receiver;
        assert!(
            refused(|| receiver.ratchet_decrypt(&sealed)),
            "the double ratchet did not refuse a short header"
        );
    }

    #[test]
    fn a_triple_ratchet_resize_refuses_a_share_of_the_wrong_length() {
        let mut group = async_group();
        let (id, _) = group[1].dkg_share();
        let share = Scalar::random(&mut rand::thread_rng()).to_bytes().to_vec();
        assert!(
            group[0].ratchet_resize(share.clone(), id, 4).is_ok(),
            "resize refused a well-formed share"
        );
        assert!(
            refused(|| group[0].ratchet_resize(share[..55].to_vec(), id, 4)),
            "resize did not refuse a share of the wrong length"
        );
    }

    #[test]
    fn a_triple_ratchet_refuses_a_peer_key_that_is_not_a_point() {
        let mut rng = rand::thread_rng();
        let ours: Vec<Vec<u8>> = (0..3)
            .map(|_| Scalar::random(&mut rng).to_bytes().to_vec())
            .collect();
        // Each peer as new_triple_ratchet takes it: public key, identity
        // key and signed pre-key, 57 bytes each.
        let peers: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                (0..3)
                    .flat_map(|_| {
                        (Scalar::random(&mut rng) * EdwardsPoint::generator())
                            .compress()
                            .to_bytes()
                    })
                    .collect()
            })
            .collect();
        // Some(whether a group was created), or None on a panic.
        let create = |peers: &Vec<Vec<u8>>| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                new_triple_ratchet(peers, &ours[0], &ours[1], &ours[2], 2, true)
            }))
            .ok()
            .map(|state| TripleRatchetParticipant::from_json(&state.ratchet_state).is_ok())
        };
        assert_eq!(
            create(&peers),
            Some(true),
            "a group of well-formed peer keys was not created"
        );
        let mut pre_key = peers.clone();
        pre_key[1][114..].copy_from_slice(&invalid_point());
        assert_eq!(
            create(&pre_key),
            Some(false),
            "group creation did not refuse a peer signed pre-key that is not a point"
        );
        let mut identity = peers.clone();
        identity[1][57..114].copy_from_slice(&invalid_point());
        assert_eq!(
            create(&identity),
            Some(false),
            "group creation did not refuse a peer identity key that is not a point"
        );
    }

    /// The exported resize, as the wasm and mobile bindings call it.
    mod resize {
        use super::*;

        type Inbox = HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>>;

        fn deliver(inbox: &mut Inbox, from: &[u8], out: HashMap<Vec<u8>, P2PChannelEnvelope>) {
            for (to, env) in out {
                inbox.entry(to).or_default().insert(from.to_vec(), env);
            }
        }

        /// Four members of an async triple ratchet group with threshold
        /// two, after the DKG, in the order of their public keys, and
        /// those keys.
        fn group() -> (Vec<TripleRatchetParticipant>, Vec<Vec<u8>>) {
            let mut rng = rand::thread_rng();
            let public = |k: &Scalar| {
                (k * EdwardsPoint::generator())
                    .compress()
                    .to_bytes()
                    .to_vec()
            };
            let mut keys: Vec<[Scalar; 3]> = (0..4)
                .map(|_| [(); 3].map(|_| Scalar::random(&mut rng)))
                .collect();
            keys.sort_by_key(|k| public(&k[0]));
            let infos: Vec<PeerInfo> = keys
                .iter()
                .map(|k| PeerInfo {
                    public_key: public(&k[0]),
                    identity_public_key: public(&k[1]),
                    signed_pre_public_key: public(&k[2]),
                })
                .collect();
            let inbox = || -> Inbox {
                infos
                    .iter()
                    .map(|p| (p.public_key.clone(), HashMap::new()))
                    .collect()
            };
            let mut members = Vec::new();
            let mut inits = inbox();
            for (i, k) in keys.iter().enumerate() {
                let others: Vec<PeerInfo> = (0..4)
                    .filter(|&j| j != i)
                    .map(|j| infos[j].clone())
                    .collect();
                let (member, out) =
                    TripleRatchetParticipant::new(&others, k[0], k[1], k[2], 2, true).unwrap();
                members.push(member);
                deliver(&mut inits, &infos[i].public_key, out);
            }
            let mut frags = inbox();
            for (i, member) in members.iter_mut().enumerate() {
                let out = member.initialize(&inits[&infos[i].public_key]).unwrap();
                deliver(&mut frags, &infos[i].public_key, out);
            }
            let mut commitments = inbox();
            for (i, member) in members.iter_mut().enumerate() {
                for (from, env) in &frags[&infos[i].public_key] {
                    if let Some(out) = member.receive_poly_frag(from, env).unwrap() {
                        deliver(&mut commitments, &infos[i].public_key, out);
                    }
                }
            }
            let mut reveals = inbox();
            for (i, member) in members.iter_mut().enumerate() {
                for (from, env) in &commitments[&infos[i].public_key] {
                    if let Some(out) = member.receive_commitment(from, env).unwrap() {
                        deliver(&mut reveals, &infos[i].public_key, out);
                    }
                }
            }
            for (i, member) in members.iter_mut().enumerate() {
                for (from, env) in &reveals[&infos[i].public_key] {
                    member.recombine(from, env).unwrap();
                }
            }
            (members, infos.into_iter().map(|p| p.public_key).collect())
        }

        /// The other member's share arrives as hex. A share of the wrong
        /// length must come back as an error, not a panic.
        #[test]
        fn triple_ratchet_resize_refuses_a_share_of_the_wrong_length() {
            let (members, public_keys) = group();
            let state = members[0].to_json().unwrap();
            let id = members[0].get_peer_id_map()[&public_keys[1]] as u64;
            let share = Scalar::random(&mut rand::thread_rng()).to_bytes();
            let resized = triple_ratchet_resize(state.clone(), hex::encode(share), id, 4);
            assert!(
                resized.len() == 4 && resized.iter().all(|s| s.len() == 56),
                "resize refused a well-formed share: {resized:?}"
            );
            println!("REACH resize returned {} shares", resized.len());
            let refused = std::panic::catch_unwind(move || {
                triple_ratchet_resize(state, hex::encode(&share[..55]), id, 4)
            })
            .expect("resize panicked on a share of the wrong length");
            assert_eq!(
                refused.len(),
                1,
                "resize accepted a share of the wrong length"
            );
        }
    }
}
