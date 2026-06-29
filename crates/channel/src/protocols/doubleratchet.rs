use base64::prelude::*;
use ed448_goldilocks_plus::elliptic_curve::group::GroupEncoding;
use ed448_goldilocks_plus::elliptic_curve::ops::MulByGenerator;
use ed448_goldilocks_plus::{subtle, CompressedEdwardsY, EdwardsPoint, Scalar};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, Payload};
use std::collections::HashMap;
use std::error;
use subtle::ConstantTimeEq;
use serde::{Serialize, Deserialize};

const DOUBLE_RATCHET_PROTOCOL_VERSION: u16 = 1;
const DOUBLE_RATCHET_PROTOCOL: u16 = 1 << 8 + DOUBLE_RATCHET_PROTOCOL_VERSION;

const CHAIN_KEY: u8 = 0x01;
const MESSAGE_KEY: u8 = 0x02;
const AEAD_KEY: u8 = 0x03;

/// Per-call forward-skip ceiling (a single message may not jump more
/// than this many chain steps ahead). Shared with the triple ratchet.
pub(crate) const MAX_SKIP: u32 = 100;
/// Global ceiling on retained skipped message keys. Bounds memory even
/// across many legitimately-out-of-order messages; an attacker can't
/// grow this past the cap (and, post-fix, can't grow it at all without
/// an authenticated body — see `ratchet_decrypt`).
pub(crate) const MAX_SKIPPED_KEYS: usize = 2000;

#[derive(Debug, Clone)]
pub struct DoubleRatchetParticipant {
    sending_ephemeral_private_key: Scalar,
    receiving_ephemeral_key: EdwardsPoint,
    root_key: Vec<u8>,
    sending_chain_key: Vec<u8>,
    current_sending_header_key: Vec<u8>,
    current_receiving_header_key: Vec<u8>,
    next_sending_header_key: Vec<u8>,
    next_receiving_header_key: Vec<u8>,
    receiving_chain_key: Vec<u8>,
    current_sending_chain_length: u32,
    previous_sending_chain_length: u32,
    current_receiving_chain_length: u32,
    previous_receiving_chain_length: u32,
    skipped_keys_map: HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>,
}

#[derive(Serialize, Deserialize)]
pub struct DoubleRatchetParticipantJson {
    pub sending_ephemeral_private_key: String,
    pub receiving_ephemeral_key: String,
    pub root_key: String,
    pub sending_chain_key: String,
    pub current_sending_header_key: String,
    pub current_receiving_header_key: String,
    pub next_sending_header_key: String,
    pub next_receiving_header_key: String,
    pub receiving_chain_key: String,
    pub current_sending_chain_length: u32,
    pub previous_sending_chain_length: u32,
    pub current_receiving_chain_length: u32,
    pub previous_receiving_chain_length: u32,
    pub skipped_keys_map: HashMap<String, HashMap<u32, String>>,
}

#[derive(Clone, Debug)]
pub struct MessageCiphertext {
    pub ciphertext: Vec<u8>,
    pub initialization_vector: Vec<u8>,
    pub associated_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct P2PChannelEnvelope {
    pub protocol_identifier: u16,
    pub message_header: MessageCiphertext,
    pub message_body: MessageCiphertext,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct P2PChannelEnvelopeJson {
    pub protocol_identifier: u16,
    pub message_header: MessageCiphertextJson,
    pub message_body: MessageCiphertextJson,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageCiphertextJson {
    pub ciphertext: String,
    pub initialization_vector: String,
    pub associated_data: Option<String>,
}

impl P2PChannelEnvelope {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let envelope = P2PChannelEnvelopeJson{
            protocol_identifier: self.protocol_identifier,
            message_header: MessageCiphertextJson{
                ciphertext: BASE64_STANDARD.encode(&self.message_header.ciphertext),
                initialization_vector: BASE64_STANDARD.encode(&self.message_header.initialization_vector),
                associated_data: self.message_header.associated_data.clone().map(|a| BASE64_STANDARD.encode(a)),
            },
            message_body: MessageCiphertextJson{
                ciphertext: BASE64_STANDARD.encode(&self.message_body.ciphertext),
                initialization_vector: BASE64_STANDARD.encode(&self.message_body.initialization_vector),
                associated_data: self.message_body.associated_data.clone().map(|a| BASE64_STANDARD.encode(a)),
            },
        };

        serde_json::to_string(&envelope)
    }

    pub fn from_json(envelope_json: String) -> Result<P2PChannelEnvelope, Box<dyn std::error::Error>> {
        let envelope: Result<P2PChannelEnvelopeJson, serde_json::Error> = serde_json::from_str(&envelope_json);
        if envelope.is_err() {
           return Err(Box::new(envelope.unwrap_err()));
        }

        let e = envelope.unwrap();
        let header_ciphertext = BASE64_STANDARD.decode(e.message_header.ciphertext)?;
        let header_initialization_vector = BASE64_STANDARD.decode(e.message_header.initialization_vector)?;
        let header_associated_data = e.message_header.associated_data.map(|a| BASE64_STANDARD.decode(a)).transpose()?;
        let ciphertext = BASE64_STANDARD.decode(e.message_body.ciphertext)?;
        let initialization_vector = BASE64_STANDARD.decode(e.message_body.initialization_vector)?;
        let associated_data = e.message_body.associated_data.map(|a| BASE64_STANDARD.decode(a)).transpose()?;

        Ok(P2PChannelEnvelope{
            protocol_identifier: e.protocol_identifier,
            message_header: MessageCiphertext{
                ciphertext: header_ciphertext,
                initialization_vector: header_initialization_vector,
                associated_data: header_associated_data,
            },
            message_body: MessageCiphertext{
                ciphertext: ciphertext,
                initialization_vector: initialization_vector,
                associated_data: associated_data,
            },
        })
    }
}

impl DoubleRatchetParticipant {
    pub fn new(
        session_key: &[u8],
        sending_header_key: &[u8],
        next_receiving_header_key: &[u8],
        is_sender: bool,
        sending_ephemeral_private_key: Scalar,
        receiving_ephemeral_key: EdwardsPoint,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut participant = DoubleRatchetParticipant {
            sending_ephemeral_private_key,
            receiving_ephemeral_key,
            root_key: vec![],
            sending_chain_key: vec![],
            current_sending_header_key: sending_header_key.to_vec(),
            current_receiving_header_key: vec![],
            next_sending_header_key: vec![],
            next_receiving_header_key: next_receiving_header_key.to_vec(),
            receiving_chain_key: vec![],
            current_sending_chain_length: 0,
            previous_sending_chain_length: 0,
            current_receiving_chain_length: 0,
            previous_receiving_chain_length: 0,
            skipped_keys_map: HashMap::new(),
        };

        if is_sender {
            let dh_output = receiving_ephemeral_key * sending_ephemeral_private_key;
            let hkdf = Hkdf::<Sha512>::new(Some(session_key), &dh_output.compress().to_bytes());
            let mut rkck = [0u8; 96];
            let err = hkdf.expand(b"quilibrium-double-ratchet", &mut rkck);
            if err.is_err() {
              return Err("invalid length".into());
            }

            participant.root_key = rkck[..32].to_vec();
            participant.sending_chain_key = rkck[32..64].to_vec();
            participant.next_sending_header_key = rkck[64..].to_vec();
        } else {
            participant.root_key = session_key.to_vec();
            participant.next_sending_header_key = next_receiving_header_key.to_vec();
            participant.next_receiving_header_key = sending_header_key.to_vec();
        }
  
        Ok(participant)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut skipped_keys_map = HashMap::<String, HashMap<u32, String>>::new();
        for (k, v) in &self.skipped_keys_map {
            let kb = BASE64_STANDARD.encode(k);
            let mut val = HashMap::<u32, String>::new();
            for (kk, vv) in v {
                let vvb = BASE64_STANDARD.encode(vv);
                val.insert(*kk, vvb);
            }
            skipped_keys_map.insert(kb, val);
        }

        let participant = DoubleRatchetParticipantJson{
            sending_ephemeral_private_key: BASE64_STANDARD.encode(self.sending_ephemeral_private_key.to_bytes()),
            receiving_ephemeral_key: BASE64_STANDARD.encode(self.receiving_ephemeral_key.compress().to_bytes()),
            root_key: BASE64_STANDARD.encode(&self.root_key),
            sending_chain_key: BASE64_STANDARD.encode(&self.sending_chain_key),
            current_sending_header_key: BASE64_STANDARD.encode(&self.current_sending_header_key),
            current_receiving_header_key: BASE64_STANDARD.encode(&self.current_receiving_header_key),
            next_sending_header_key: BASE64_STANDARD.encode(&self.next_sending_header_key),
            next_receiving_header_key: BASE64_STANDARD.encode(&self.next_receiving_header_key),
            receiving_chain_key: BASE64_STANDARD.encode(&self.receiving_chain_key),
            current_sending_chain_length: self.current_sending_chain_length,
            previous_sending_chain_length: self.previous_sending_chain_length,
            current_receiving_chain_length: self.current_receiving_chain_length,
            previous_receiving_chain_length: self.previous_receiving_chain_length,
            skipped_keys_map: skipped_keys_map,
        };

        serde_json::to_string(&participant)
    }

    pub fn from_json(participant_json: String) -> Result<DoubleRatchetParticipant, Box<dyn std::error::Error>> {
        let json: Result<DoubleRatchetParticipantJson, serde_json::Error> = serde_json::from_str(&participant_json);
        match json {
            Ok(participant) => {
                let sending_ephemeral_private_key_bytes = BASE64_STANDARD.decode(participant.sending_ephemeral_private_key)?;
                let receiving_ephemeral_key_bytes = BASE64_STANDARD.decode(participant.receiving_ephemeral_key)?;
                let root_key = BASE64_STANDARD.decode(participant.root_key)?;
                let sending_chain_key = BASE64_STANDARD.decode(participant.sending_chain_key)?;
                let current_sending_header_key = BASE64_STANDARD.decode(participant.current_sending_header_key)?;
                let current_receiving_header_key = BASE64_STANDARD.decode(participant.current_receiving_header_key)?;
                let next_sending_header_key = BASE64_STANDARD.decode(participant.next_sending_header_key)?;
                let next_receiving_header_key = BASE64_STANDARD.decode(participant.next_receiving_header_key)?;
                let receiving_chain_key = BASE64_STANDARD.decode(participant.receiving_chain_key)?;
                let current_sending_chain_length = participant.current_sending_chain_length;
                let previous_sending_chain_length = participant.previous_sending_chain_length;
                let current_receiving_chain_length = participant.current_receiving_chain_length;
                let previous_receiving_chain_length = participant.previous_receiving_chain_length;
                let mut skipped_keys_map = HashMap::<Vec<u8>, HashMap<u32, Vec<u8>>>::new();
                for (k, v) in participant.skipped_keys_map {
                    let kb = BASE64_STANDARD.decode(k)?;
                    let mut val = HashMap::<u32, Vec<u8>>::new();
                    for (kk, vv) in v {
                        let vvb = BASE64_STANDARD.decode(vv)?;
                        val.insert(kk, vvb);
                    }
                    skipped_keys_map.insert(kb, val);
                }

                if sending_ephemeral_private_key_bytes.len() != 56 || receiving_ephemeral_key_bytes.len() != 57 {
                    Err("invalid data".into())
                } else {
                    let mut sending_ephemeral_private_key = [0u8; 56];
                    sending_ephemeral_private_key.copy_from_slice(&sending_ephemeral_private_key_bytes);

                    let mut receiving_ephemeral_key = [0u8; 57];
                    receiving_ephemeral_key.copy_from_slice(&receiving_ephemeral_key_bytes);

                    let receiving_ephemeral_ct = EdwardsPoint::from_bytes(&receiving_ephemeral_key.into());
                    if receiving_ephemeral_ct.is_none().into() {
                        Err("invalid data".into())
                    } else {
                        Ok(DoubleRatchetParticipant{
                            sending_ephemeral_private_key: Scalar::from_bytes(&sending_ephemeral_private_key),
                            receiving_ephemeral_key: receiving_ephemeral_ct.unwrap(),
                            root_key: root_key,
                            sending_chain_key: sending_chain_key,
                            current_sending_header_key: current_sending_header_key,
                            current_receiving_header_key: current_receiving_header_key,
                            next_sending_header_key: next_sending_header_key,
                            next_receiving_header_key: next_receiving_header_key,
                            receiving_chain_key: receiving_chain_key,
                            current_sending_chain_length: current_sending_chain_length,
                            previous_sending_chain_length: previous_sending_chain_length,
                            current_receiving_chain_length: current_receiving_chain_length,
                            previous_receiving_chain_length: previous_receiving_chain_length,
                            skipped_keys_map: skipped_keys_map,
                        })
                    }
                }
            }
            Err(e) => {
                Err(Box::new(e))
            }
        }
    }

    pub fn ratchet_encrypt(&mut self, message: &[u8]) -> Result<P2PChannelEnvelope, Box<dyn std::error::Error>> {
        let mut envelope = P2PChannelEnvelope {
            protocol_identifier: DOUBLE_RATCHET_PROTOCOL,
            message_header: MessageCiphertext::default(),
            message_body: MessageCiphertext::default(),
        };

        let (new_chain_key, message_key, aead_key) = ratchet_keys(&self.sending_chain_key);
        self.sending_chain_key = new_chain_key;

        let header = self.encode_header();
        envelope.message_header = self.encrypt(&header, &self.current_sending_header_key, None)?;

        envelope.message_body = self.encrypt(
            message,
            &message_key,
            Some(&[&aead_key[..], &envelope.message_header.ciphertext[..]].concat()),
        )?;

        self.current_sending_chain_length += 1;

        Ok(envelope)
    }

    pub fn ratchet_decrypt(&mut self, envelope: &P2PChannelEnvelope) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(plaintext) = self.try_skipped_message_keys(envelope)? {
            return Ok(plaintext);
        }

        // SECURITY: advance the ratchet on a throwaway clone and only
        // commit (`*self = work`) once the message BODY authenticates.
        // Previously `skip_message_keys` / `ratchet_ephemeral_keys` ran
        // directly on `self` *before* the AEAD body was verified, so a
        // forged header (decryptable under a header key but with a junk
        // body) would advance the receiving chain and stuff up to ~99
        // derived keys into `skipped_keys_map` — an unauthenticated DoS
        // and skipped-key over-retention. Mutating a clone makes any
        // such failure a no-op on real state, since `work` is dropped
        // when `advance_and_decrypt` returns `Err`.
        let mut work = self.clone();
        let plaintext = work.advance_and_decrypt(envelope)?;
        *self = work;
        Ok(plaintext)
    }

    /// Advance the receiving chain (skipping/ratcheting as the header
    /// dictates), decrypt+authenticate the body, and on success commit
    /// the chain advance. Intended to run on a clone so a failed body
    /// auth leaves no persistent state change (see `ratchet_decrypt`).
    fn advance_and_decrypt(&mut self, envelope: &P2PChannelEnvelope) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (header, should_ratchet) = self.decrypt_header(&envelope.message_header, &self.current_receiving_header_key)?;
        let (receiving_ephemeral_key, previous_receiving_chain_length, current_receiving_chain_length) =
            self.decode_header(&header)?;

        if should_ratchet {
            self.skip_message_keys(previous_receiving_chain_length)?;
            self.ratchet_ephemeral_keys(&receiving_ephemeral_key)?;
        }

        self.skip_message_keys(current_receiving_chain_length)?;

        let (new_chain_key, message_key, aead_key) = ratchet_keys(&self.receiving_chain_key);

        // This is the authentication gate. Until it returns Ok, none of
        // the mutations above are visible to the caller (clone is
        // discarded on Err).
        let plaintext = self.decrypt(
            &envelope.message_body,
            &message_key,
            Some(&[&aead_key[..], &envelope.message_header.ciphertext[..]].concat()),
        )?;

        self.receiving_chain_key = new_chain_key;
        self.current_receiving_chain_length += 1;

        Ok(plaintext)
    }

    fn ratchet_ephemeral_keys(&mut self, new_receiving_ephemeral_key: &EdwardsPoint) -> Result<(), Box<dyn std::error::Error>> {
        self.previous_sending_chain_length = self.current_sending_chain_length;
        self.current_sending_chain_length = 0;
        self.current_receiving_chain_length = 0;
        self.current_sending_header_key = self.next_sending_header_key.clone();
        self.current_receiving_header_key = self.next_receiving_header_key.clone();
        self.receiving_ephemeral_key = *new_receiving_ephemeral_key;
    
        // Perform DH and KDF to get new root key and receiving chain key
        let dh_output = new_receiving_ephemeral_key * self.sending_ephemeral_private_key;
        let hkdf = Hkdf::<Sha512>::new(Some(&self.root_key), &dh_output.compress().to_bytes());
        let mut rkck = [0u8; 96];
        hkdf.expand(b"quilibrium-double-ratchet", &mut rkck);
    
        self.root_key = rkck[..32].to_vec();
        self.receiving_chain_key = rkck[32..64].to_vec();
        self.next_receiving_header_key = rkck[64..].to_vec();
    
        // Generate new sending ephemeral key
        self.sending_ephemeral_private_key = Scalar::random(&mut OsRng);
    
        // Perform DH and KDF to get new root key and sending chain key
        let dh_output = new_receiving_ephemeral_key * self.sending_ephemeral_private_key;
        let hkdf = Hkdf::<Sha512>::new(Some(&self.root_key), &dh_output.compress().to_bytes());
        let mut rkck2 = [0u8; 96];
        hkdf.expand(b"quilibrium-double-ratchet", &mut rkck2);
    
        self.root_key = rkck2[..32].to_vec();
        self.sending_chain_key = rkck2[32..64].to_vec();
        self.next_sending_header_key = rkck2[64..].to_vec();
        
        Ok(())
    }

    fn try_skipped_message_keys(&mut self, envelope: &P2PChannelEnvelope) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        // Locate a stored key whose header key decrypts this header and
        // whose index matches. Collect the match (clones) before
        // mutating, to keep the borrow checker happy.
        let mut matched: Option<(Vec<u8>, u32, Vec<u8>)> = None;
        for (receiving_header_key, skipped_keys) in &self.skipped_keys_map {
            if let Ok((header, _)) = self.decrypt_header(&envelope.message_header, receiving_header_key) {
                let (_, _, current) = self.decode_header(&header)?;
                if let Some(key_pair) = skipped_keys.get(&current) {
                    matched = Some((receiving_header_key.clone(), current, key_pair.clone()));
                    break;
                }
            }
        }

        let Some((header_key, index, key_pair)) = matched else {
            return Ok(None);
        };

        let message_key = &key_pair[..32];
        let aead_key = &key_pair[32..];
        let plaintext = self.decrypt(
            &envelope.message_body,
            message_key,
            Some(&[aead_key, &envelope.message_header.ciphertext[..]].concat()),
        )?;

        // Delete the key after successful use (Double Ratchet spec): a
        // one-time skipped key must not be retained — keeping it both
        // widens the compromise window and would allow trivial replay of
        // the same ciphertext. Only reached on successful auth.
        if let Some(sub) = self.skipped_keys_map.get_mut(&header_key) {
            sub.remove(&index);
            if sub.is_empty() {
                self.skipped_keys_map.remove(&header_key);
            }
        }

        Ok(Some(plaintext))
    }

    fn skipped_keys_total(&self) -> usize {
        self.skipped_keys_map.values().map(|m| m.len()).sum()
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), Box<dyn std::error::Error>> {
        if self.current_receiving_chain_length + MAX_SKIP < until {
            return Err("Skip limit exceeded".into());
        }

        if !self.receiving_chain_key.is_empty() {
            let mut total = self.skipped_keys_total();
            while self.current_receiving_chain_length < until {
                // Global retention cap — defends memory even against a
                // sender who legitimately skips a great deal over time.
                if total >= MAX_SKIPPED_KEYS {
                    return Err("Skipped-key store full".into());
                }
                let (new_chain_key, message_key, aead_key) = ratchet_keys(&self.receiving_chain_key);
                self.skipped_keys_map
                    .entry(self.current_receiving_header_key.clone())
                    .or_insert_with(HashMap::new)
                    .insert(self.current_receiving_chain_length, [&message_key[..], &aead_key[..]].concat());
                self.receiving_chain_key = new_chain_key;
                self.current_receiving_chain_length += 1;
                total += 1;
            }
        }

        Ok(())
    }

    fn encode_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&EdwardsPoint::mul_by_generator(&self.sending_ephemeral_private_key).compress().to_bytes());
        header.extend_from_slice(&self.previous_sending_chain_length.to_be_bytes());
        header.extend_from_slice(&self.current_sending_chain_length.to_be_bytes());
        header
    }

    fn decrypt_header(&self, ciphertext: &MessageCiphertext, receiving_header_key: &[u8]) 
        -> Result<(Vec<u8>, bool), Box<dyn std::error::Error>> {
        match self.decrypt(ciphertext, receiving_header_key, None) {
            Ok(header) => Ok((header, false)),
            Err(_) if receiving_header_key.ct_eq(self.current_receiving_header_key.as_slice()).into() => {
                self.decrypt(ciphertext, &self.next_receiving_header_key, None)
                    .map(|header| (header, true))
            },
            Err(e) => Err(e),
        }
    }

    fn decode_header(&self, header: &[u8]) -> Result<(EdwardsPoint, u32, u32), Box<dyn std::error::Error>> {
        if header.len() < 57 {  // 57 bytes for EdwardsPoint + 8 bytes for two u32
            return Err("Malformed header".into());
        }

        let receiving_ephemeral_key = CompressedEdwardsY(header[..57].try_into().unwrap()).decompress();
        if receiving_ephemeral_key.is_none().into() {
            return Err("Malformed point".into());
        }
        let previous_receiving_chain_length = u32::from_be_bytes(header[57..61].try_into()?);
        let current_receiving_chain_length = u32::from_be_bytes(header[61..65].try_into()?);

        Ok((receiving_ephemeral_key.unwrap(), previous_receiving_chain_length, current_receiving_chain_length))
    }

    fn encrypt(&self, plaintext: &[u8], key: &[u8], associated_data: Option<&[u8]>) 
      -> Result<MessageCiphertext, Box<dyn std::error::Error>> {
        use aes_gcm::KeyInit;
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);

        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = Nonce::from_slice(&iv);
        
        let mut associated_data = associated_data.unwrap_or(&[]);
        let mut aad = [0u8; 32];
        if associated_data.len() == 0 {
          OsRng.fill_bytes(&mut aad);
          associated_data = &aad
        }
        
        let ciphertext = cipher.encrypt(nonce, Payload{
            msg: plaintext,
            aad: associated_data,
        }).map_err(|e| format!("Encryption failed: {}", e))?;
      
      Ok(MessageCiphertext {
        ciphertext,
        initialization_vector: iv.to_vec(),
        associated_data: Some(associated_data.to_vec()),
      })
    }
    
    fn decrypt(&self, ciphertext: &MessageCiphertext, key: &[u8], associated_data: Option<&[u8]>) 
      -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use aes_gcm::KeyInit;
        if key.len() != 32 {
          return Err(format!("Invalid key length").into());
        }
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = Nonce::from_slice(&ciphertext.initialization_vector);

        let associated_data = associated_data.unwrap_or_else(|| ciphertext.associated_data.as_ref().unwrap());

        cipher.decrypt(nonce, Payload{
            msg: ciphertext.ciphertext.as_slice(),
            aad: associated_data,
        }).map_err(|e| format!("Decryption failed: {}", e).into())
    }

    pub fn rotate_sending_key(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.sending_ephemeral_private_key = Scalar::random(&mut OsRng);
        self.ratchet_ephemeral_keys(&self.receiving_ephemeral_key.clone())
    }

    pub fn get_public_key(&self) -> EdwardsPoint {
        EdwardsPoint::mul_by_generator(&self.sending_ephemeral_private_key)
    }
}

/// Wipe long-lived secret key material on drop so root/chain/message
/// keys and the sending ephemeral scalar don't linger in freed heap
/// (swap, core dump, allocator reuse). Public points and chain-length
/// counters are not secret and are left alone.
impl Drop for DoubleRatchetParticipant {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sending_ephemeral_private_key.zeroize();
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.current_sending_header_key.zeroize();
        self.current_receiving_header_key.zeroize();
        self.next_sending_header_key.zeroize();
        self.next_receiving_header_key.zeroize();
        self.receiving_chain_key.zeroize();
        for sub in self.skipped_keys_map.values_mut() {
            for v in sub.values_mut() {
                v.zeroize();
            }
        }
    }
}

fn ratchet_keys(input_key: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
  use hmac::Mac;
  let mut aead_key = [0u8; 64];
  let mut message_key = [0u8; 64];
  let mut chain_key = [0u8; 64];

  let mut hmac_aead = hmac::Hmac::<Sha512>::new_from_slice(input_key).unwrap();
  hmac_aead.update(&[AEAD_KEY]);
  aead_key.copy_from_slice(&hmac_aead.finalize().into_bytes());

  let mut hmac_message = hmac::Hmac::<Sha512>::new_from_slice(input_key).unwrap();
  hmac_message.update(&[MESSAGE_KEY]);
  message_key.copy_from_slice(&hmac_message.finalize().into_bytes());

  let mut hmac_chain = hmac::Hmac::<Sha512>::new_from_slice(input_key).unwrap();
  hmac_chain.update(&[CHAIN_KEY]);
  chain_key.copy_from_slice(&hmac_chain.finalize().into_bytes());

  (chain_key[..32].to_vec(), message_key[..32].to_vec(), aead_key[..32].to_vec())
}

// Implementation for MessageCiphertext
impl Default for MessageCiphertext {
  fn default() -> Self {
      MessageCiphertext {
          ciphertext: Vec::new(),
          initialization_vector: Vec::new(),
          associated_data: None,
      }
  }
}

// Implementation for P2PChannelEnvelope
impl P2PChannelEnvelope {
  pub fn new(protocol_identifier: u16) -> Self {
      P2PChannelEnvelope {
          protocol_identifier,
          message_header: MessageCiphertext::default(),
          message_body: MessageCiphertext::default(),
      }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ed448_goldilocks_plus::Scalar;

  #[test]
  fn test_double_ratchet_communication() {
      let session_key = [0u8; 32];
      let sending_header_key = [1u8; 32];
      let next_receiving_header_key = [2u8; 32];

      let alice_ephemeral = Scalar::random(&mut OsRng);
      let bob_ephemeral = Scalar::random(&mut OsRng);

      let alice_public = EdwardsPoint::mul_by_generator(&alice_ephemeral);
      let bob_public = EdwardsPoint::mul_by_generator(&bob_ephemeral);

      let mut alice = DoubleRatchetParticipant::new(
          &session_key,
          &sending_header_key,
          &next_receiving_header_key,
          true,
          alice_ephemeral,
          bob_public,
      ).unwrap();

      let mut bob = DoubleRatchetParticipant::new(
          &session_key,
          &sending_header_key,
          &next_receiving_header_key,
          false,
          bob_ephemeral,
          alice_public,
      ).unwrap();

      // Test message exchange
      let message = b"Hello, Bob!";
      let envelope = alice.ratchet_encrypt(message).unwrap();

      let decrypted = bob.ratchet_decrypt(&envelope).unwrap();
      assert_eq!(message, decrypted.as_slice());

      let response = b"Hello, Alice!";
      let envelope = bob.ratchet_encrypt(response).unwrap();
      let delayed = alice.ratchet_encrypt(b"force another step").unwrap();
      let decrypted = alice.ratchet_decrypt(&envelope).unwrap();
      assert_eq!(response, decrypted.as_slice());

      // Test multiple messages
      for _ in 0..5 {
          let message = b"Secure communication test";
          let envelope = alice.ratchet_encrypt(message).unwrap();
          let decrypted = bob.ratchet_decrypt(&envelope).unwrap();
          assert_eq!(message, decrypted.as_slice());

          let response = b"Acknowledged";
          let envelope = bob.ratchet_encrypt(response).unwrap();
          let decrypted = alice.ratchet_decrypt(&envelope).unwrap();
          assert_eq!(response, decrypted.as_slice());
      }

      let alice_json = alice.to_json().unwrap();
      let bob_json = bob.to_json().unwrap();

      let mut new_alice = DoubleRatchetParticipant::from_json(alice_json).unwrap();
      let mut new_bob = DoubleRatchetParticipant::from_json(bob_json).unwrap();

      // Test multiple messages
      for _ in 0..5 {
        let message = b"Secure communication test";
        let envelope = new_alice.ratchet_encrypt(message).unwrap();
        let decrypted = new_bob.ratchet_decrypt(&envelope).unwrap();
        assert_eq!(message, decrypted.as_slice());

        let response = b"Acknowledged";
        let envelope = new_bob.ratchet_encrypt(response).unwrap();
        let decrypted = new_alice.ratchet_decrypt(&envelope).unwrap();
        assert_eq!(response, decrypted.as_slice());
    }
      let decrypted = new_bob.ratchet_decrypt(&delayed).unwrap();
      assert_eq!(b"force another step", decrypted.as_slice());
  }
}