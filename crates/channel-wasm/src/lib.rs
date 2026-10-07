use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, Payload};
use ed448_rust::Ed448Error;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha512;
use wasm_bindgen::prelude::*;
use base64::prelude::*;
use channel::*;
use serde::{Deserialize, Serialize};
use ed448_goldilocks_plus::{elliptic_curve::Group, CompressedEdwardsY, EdwardsPoint, Scalar};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NewDoubleRatchetParameters {
  pub session_key: Vec<u8>,
  pub sending_header_key: Vec<u8>,
  pub next_receiving_header_key: Vec<u8>,
  pub is_sender: bool,
  pub sending_ephemeral_private_key: Vec<u8>,
  pub receiving_ephemeral_key: Vec<u8>
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NewTripleRatchetParameters {
  pub peers: Vec<Vec<u8>>,
  pub peer_key: Vec<u8>,
  pub identity_key: Vec<u8>,
  pub signed_pre_key: Vec<u8>,
  pub threshold: u64,
  pub async_dkg_ratchet: bool
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionKeyPair {
  pub public_key: Vec<u8>,
  pub private_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningKeyPair {
  pub public_key: Vec<u8>,
  pub private_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SenderX3DH {
  pub sending_identity_private_key: Vec<u8>,
  pub sending_ephemeral_private_key: Vec<u8>,
  pub receiving_identity_key: Vec<u8>,
  pub receiving_signed_pre_key: Vec<u8>,
  pub session_key_length: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiverX3DH {
  pub sending_identity_private_key: Vec<u8>,
  pub sending_signed_private_key: Vec<u8>,
  pub receiving_identity_key: Vec<u8>,
  pub receiving_ephemeral_key: Vec<u8>,
  pub session_key_length: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct MessageCiphertext {
    pub ciphertext: String,
    pub initialization_vector: String,
    pub associated_data: Option<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedInboxMessageDecryptRequest {
  pub inbox_private_key: Vec<u8>,
  pub ephemeral_public_key: Vec<u8>,
  pub ciphertext: MessageCiphertext,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedInboxMessageEncryptRequest {
  pub inbox_public_key: Vec<u8>,
  pub ephemeral_private_key: Vec<u8>,
  pub plaintext: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ResizeRequest {
  pub ratchet_state: String,
  pub other: String,
  pub id: u64,
  pub total: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TripleRatchetStateAndPoint {
    pub ratchet_state: String,
    pub point: String,
    pub index: usize,
}


/// Render a fallible `channel` call for the JS side.
///
/// `CryptoError` is a uniffi error enum and deliberately isn't `Serialize`,
/// so the `Result` can't be JSON-encoded as a whole. Report success as the
/// serialized payload and failure as the plain error text — the same shape
/// the `serde_json::from_str` arms in every `js_*` wrapper already return.
fn result_to_json<T: Serialize>(result: Result<T, CryptoError>) -> String {
  match result {
    Ok(value) => serde_json::to_string(&value).unwrap_or_else(|e| e.to_string()),
    Err(e) => e.to_string(),
  }
}

fn encrypt(plaintext: &[u8], key: &[u8])
  -> Result<MessageCiphertext, Box<dyn std::error::Error>> {
    use aes_gcm::KeyInit;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(&iv);
    
    let mut aad = [0u8; 32];
    OsRng.fill_bytes(&mut aad);
    
    let ciphertext = cipher.encrypt(nonce, Payload{
        msg: plaintext,
        aad: &aad,
    }).map_err(|e| format!("Encryption failed: {}", e))?;
  
  Ok(MessageCiphertext {
    ciphertext: BASE64_STANDARD.encode(ciphertext),
    initialization_vector: BASE64_STANDARD.encode(iv.to_vec()),
    associated_data: Some(BASE64_STANDARD.encode(aad.to_vec())),
  })
}

fn decrypt(ciphertext: &MessageCiphertext, key: &[u8]) 
  -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes_gcm::KeyInit;
    if key.len() != 32 {
      return Err(format!("Invalid key length").into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let maybe_iv = BASE64_STANDARD.decode(&ciphertext.initialization_vector);
    if maybe_iv.is_err() {
      return Err(format!("Decryption failed: {}", maybe_iv.unwrap_err()).into());
    }

    let iv = maybe_iv.unwrap();
    let nonce = Nonce::from_slice(&iv);

    let ad = &ciphertext.associated_data;
    let mut associated_data = Vec::<u8>::new();
    if ad.is_some() {
      let aad = BASE64_STANDARD.decode(&ad.clone().unwrap());
      if aad.is_err() {
        return Err(format!("Decryption failed: {}", aad.unwrap_err()).into());
      }

      associated_data = aad.unwrap();
    }

    let ciphertext = BASE64_STANDARD.decode(&ciphertext.ciphertext);
    if ciphertext.is_err() {
      return Err(format!("Decryption failed: {}", ciphertext.unwrap_err()).into());
    }

    cipher.decrypt(nonce, Payload{
        msg: &ciphertext.unwrap(),
        aad: &associated_data,
    }).map_err(|e| format!("Decryption failed: {}", e).into())
}

#[wasm_bindgen]
pub fn js_decrypt_inbox_message(input: &str) -> String {
  let json: Result<SealedInboxMessageDecryptRequest, serde_json::Error> = serde_json::from_str(input);
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
      // TODO: To support authorized inbox sending, change None to Some when an authorization_key is present.
      let hkdf = Hkdf::<Sha512>::new(None, &dh_output.compress().to_bytes());
      let mut derived = [0u8; 32];
      let err = hkdf.expand(b"quilibrium-sealed-sender", &mut derived);
      if err.is_err() {
        return "invalid length".into();
      }

      let result = decrypt(&params.ciphertext, &derived);
      if result.is_err() {
        return result.unwrap_err().to_string();
      }
      
      match serde_json::to_string(&result.unwrap()) {
        Ok(result) => result,
        Err(e) => e.to_string(),
      }
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_encrypt_inbox_message(input: &str) -> String {
  let json: Result<SealedInboxMessageEncryptRequest, serde_json::Error> = serde_json::from_str(input);
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
      // TODO: To support authorized inbox sending, change None to Some when an authorization_key is present.
      let hkdf = Hkdf::<Sha512>::new(None, &dh_output.compress().to_bytes());
      let mut derived = [0u8; 32];
      let err = hkdf.expand(b"quilibrium-sealed-sender", &mut derived);
      if err.is_err() {
        return "invalid length".into();
      }

      let result = encrypt(&params.plaintext, &derived);
      if result.is_err() {
        return result.unwrap_err().to_string();
      }
      
      match serde_json::to_string(&result.unwrap()) {
        Ok(result) => result,
        Err(e) => e.to_string(),
      }
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_sender_x3dh(input: &str) -> String {
  let json: Result<SenderX3DH, serde_json::Error> = serde_json::from_str(input);
  match json {
    Ok(params) => {
      return sender_x3dh(&params.sending_identity_private_key, &params.sending_ephemeral_private_key, &params.receiving_identity_key, &params.receiving_signed_pre_key, params.session_key_length);
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_receiver_x3dh(input: &str) -> String {
  let json: Result<ReceiverX3DH, serde_json::Error> = serde_json::from_str(input);
  match json {
    Ok(params) => {
      return receiver_x3dh(&params.sending_identity_private_key, &params.sending_signed_private_key, &params.receiving_identity_key, &params.receiving_ephemeral_key, params.session_key_length);
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_generate_x448() -> String {
  let priv_key = Scalar::random(&mut rand::thread_rng());
  let pub_key = EdwardsPoint::generator() * priv_key;
  let output = serde_json::to_string(&EncryptionKeyPair{
    public_key: pub_key.compress().to_bytes().to_vec(),
    private_key: priv_key.to_bytes().to_vec(),
  });

  match output {
    Ok(result) => {
      result
    }
    Err(e) => {
      e.to_string()
    }
  }
}

#[wasm_bindgen]
pub fn js_generate_ed448() -> String {
  let priv_key = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
  let pub_key = ed448_rust::PublicKey::from(&priv_key);
  let output = serde_json::to_string(&EncryptionKeyPair{
    public_key: pub_key.as_byte().to_vec(),
    private_key: priv_key.as_bytes().to_vec(),
  });

  match output {
    Ok(result) => {
      result
    }
    Err(e) => {
      e.to_string()
    }
  }
}

#[wasm_bindgen]
pub fn js_get_pubkey_ed448(key: &str) -> String {
  let maybe_key = BASE64_STANDARD.decode(key);
  if maybe_key.is_err() {
    return maybe_key.unwrap_err().to_string();
  }

  let key = maybe_key.unwrap();
  if key.len() != 57 {
    return "invalid key length".to_string();
  }
  
  let key_bytes: [u8; 57] = key.try_into().unwrap();
  let priv_key = ed448_rust::PrivateKey::from(key_bytes);
  let pub_key = ed448_rust::PublicKey::from(&priv_key);
  
  return format!("\"{}\"", BASE64_STANDARD.encode(pub_key.as_byte()));
}

#[wasm_bindgen]
pub fn js_get_pubkey_x448(key: &str) -> String {
  let maybe_key = BASE64_STANDARD.decode(key);
  if maybe_key.is_err() {
    return maybe_key.unwrap_err().to_string();
  }

  let key = maybe_key.unwrap();
  if key.len() != 56 {
    return "invalid key length".to_string();
  }

  let mut priv_key_bytes = [0u8; 56];
  priv_key_bytes.copy_from_slice(&key);
  
  let priv_key = Scalar::from_bytes(&priv_key_bytes);
  let pub_key = EdwardsPoint::generator() * priv_key;

  return format!("\"{}\"", BASE64_STANDARD.encode(pub_key.compress().to_bytes().to_vec()));
}

#[wasm_bindgen]
pub fn js_sign_ed448(key: &str, message: &str) -> String {
  let maybe_key = BASE64_STANDARD.decode(key);
  if maybe_key.is_err() {
    return maybe_key.unwrap_err().to_string();
  }

  let maybe_message = BASE64_STANDARD.decode(message);
  if maybe_message.is_err() {
    return maybe_message.unwrap_err().to_string();
  }

  let key = maybe_key.unwrap();
  if key.len() != 57 {
    return "invalid key length".to_string();
  }
  
  let key_bytes: [u8; 57] = key.try_into().unwrap();
  let priv_key = ed448_rust::PrivateKey::from(key_bytes);
  let signature = priv_key.sign(&maybe_message.unwrap(), None);
  
  match signature {
    Ok(output) => {
      return format!("\"{}\"", BASE64_STANDARD.encode(output));
    }
    Err(Ed448Error::WrongKeyLength) => {
      return "invalid key length".to_string();
    }
    Err(Ed448Error::WrongPublicKeyLength) => {
      return "invalid public key length".to_string();
    }
    Err(Ed448Error::WrongSignatureLength) => {
      return "invalid signature length".to_string();
    }
    Err(Ed448Error::InvalidPoint) => {
      return "invalid point".to_string();
    }
    Err(Ed448Error::InvalidSignature) => {
      return "invalid signature".to_string();
    }
    Err(Ed448Error::ContextTooLong) => {
      return "context too long".to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_verify_ed448(public_key: &str, message: &str, signature: &str) -> String {
  let maybe_key = BASE64_STANDARD.decode(public_key);
  if maybe_key.is_err() {
    return maybe_key.unwrap_err().to_string();
  }

  let maybe_message = BASE64_STANDARD.decode(message);
  if maybe_message.is_err() {
    return maybe_message.unwrap_err().to_string();
  }

  let maybe_signature = BASE64_STANDARD.decode(signature);
  if maybe_signature.is_err() {
    return maybe_signature.unwrap_err().to_string();
  }

  let key = maybe_key.unwrap();
  if key.len() != 57 {
    return "invalid key length".to_string();
  }
  
  let pub_bytes: [u8; 57] = key.try_into().unwrap();
  // `PublicKey::from` panics on a non-point key; fail with an error string.
  let pub_key = match ed448_rust::PublicKey::try_from(&pub_bytes[..]) {
    Ok(k) => k,
    Err(_) => return "invalid public key".to_string(),
  };
  let signature = pub_key.verify(&maybe_message.unwrap(), &maybe_signature.unwrap(), None);
  
  match signature {
    Ok(()) => {
      return "true".to_string();
    }
    Err(Ed448Error::WrongKeyLength) => {
      return "invalid key length".to_string();
    }
    Err(Ed448Error::WrongPublicKeyLength) => {
      return "invalid public key length".to_string();
    }
    Err(Ed448Error::WrongSignatureLength) => {
      return "invalid signature length".to_string();
    }
    Err(Ed448Error::InvalidPoint) => {
      return "invalid point".to_string();
    }
    Err(Ed448Error::InvalidSignature) => {
      return "invalid signature".to_string();
    }
    Err(Ed448Error::ContextTooLong) => {
      return "context too long".to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_new_double_ratchet(params: &str) -> String {
  let json: Result<NewDoubleRatchetParameters, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(inputs) => {
      return new_double_ratchet(&inputs.session_key, &inputs.sending_header_key, &inputs.next_receiving_header_key, inputs.is_sender, &inputs.sending_ephemeral_private_key, &inputs.receiving_ephemeral_key);
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_double_ratchet_encrypt(params: &str) -> String {
  let json: Result<DoubleRatchetStateAndMessage, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_message) => {
      return result_to_json(double_ratchet_encrypt(ratchet_state_and_message));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_double_ratchet_decrypt(params: &str) -> String {
  let json: Result<DoubleRatchetStateAndEnvelope, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_envelope) => {
      return result_to_json(double_ratchet_decrypt(ratchet_state_and_envelope));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_new_triple_ratchet(params: &str) -> String {
  let json: Result<NewTripleRatchetParameters, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(input) => {
      return serde_json::to_string(&new_triple_ratchet(&input.peers, &input.peer_key, &input.identity_key, &input.signed_pre_key, input.threshold, input.async_dkg_ratchet)).unwrap_or_else(|e| e.to_string());
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_init_round_1(params: &str) -> String {
  let json: Result<TripleRatchetStateAndMetadata, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_metadata) => {
      return result_to_json(triple_ratchet_init_round_1(ratchet_state_and_metadata));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_init_round_2(params: &str) -> String {
  let json: Result<TripleRatchetStateAndMetadata, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_metadata) => {
      return result_to_json(triple_ratchet_init_round_2(ratchet_state_and_metadata));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_init_round_3(params: &str) -> String {
  let json: Result<TripleRatchetStateAndMetadata, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_metadata) => {
      return result_to_json(triple_ratchet_init_round_3(ratchet_state_and_metadata));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_init_round_4(params: &str) -> String {
  let json: Result<TripleRatchetStateAndMetadata, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_metadata) => {
      return result_to_json(triple_ratchet_init_round_4(ratchet_state_and_metadata));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_encrypt(params: &str) -> String {
  let json: Result<TripleRatchetStateAndMessage, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_message) => {
      return result_to_json(triple_ratchet_encrypt(ratchet_state_and_message));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_decrypt(params: &str) -> String {
  let json: Result<TripleRatchetStateAndEnvelope, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(ratchet_state_and_envelope) => {
      return result_to_json(triple_ratchet_decrypt(ratchet_state_and_envelope));
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_triple_ratchet_resize(params: &str) -> String {
  let json: Result<ResizeRequest, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(request) => {
      return serde_json::to_string(&triple_ratchet_resize(request.ratchet_state, request.other, request.id, request.total)).unwrap_or_else(|e| e.to_string());
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[wasm_bindgen]
pub fn js_verify_point(params: &str) -> String {
  let json: Result<TripleRatchetStateAndPoint, serde_json::Error> = serde_json::from_str(params);
  match json {
    Ok(request) => {
      let verify = triple_ratchet_verify_point(request.ratchet_state, request.point, request.index);
      return match verify {
        Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| e.to_string()),
        Err(e) => serde_json::to_string(&e.to_string()).unwrap_or_else(|e| e.to_string())
      }
    }
    Err(e) => {
      return e.to_string();
    }
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {    
      let priv_key = ed448_rust::PrivateKey::new(&mut rand::thread_rng());
      let pub_key = ed448_rust::PublicKey::from(&priv_key);
      let sig = js_sign_ed448(&BASE64_STANDARD.encode(priv_key.as_bytes()).to_string(), "AQAB");
      assert_eq!(js_verify_ed448(&BASE64_STANDARD.encode(pub_key.as_byte()).to_string(), "AQAB", &serde_json::from_str::<String>(&sig.to_string()).unwrap()), "true")
    }
}