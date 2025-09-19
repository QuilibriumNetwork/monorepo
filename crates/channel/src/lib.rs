use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, io::Read};
use hex;

use ed448_goldilocks_plus::{elliptic_curve::group::GroupEncoding, CompressedEdwardsY, EdwardsPoint, Scalar};
use protocols::{doubleratchet::{DoubleRatchetParticipant, P2PChannelEnvelope}, tripleratchet::{PeerInfo, TripleRatchetParticipant}, x3dh};

pub(crate) mod protocols;

uniffi::include_scaffolding!("lib");

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

pub fn sender_x3dh(sending_identity_private_key: &Vec<u8>, sending_ephemeral_private_key: &Vec<u8>, receiving_identity_key: &Vec<u8>, receiving_signed_pre_key: &Vec<u8>, session_key_length: u64) -> String {
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
  let ridk = CompressedEdwardsY(receiving_identity_key.as_slice().try_into().unwrap()).decompress();
  let rspk = CompressedEdwardsY(receiving_signed_pre_key.as_slice().try_into().unwrap()).decompress();

  if ridk.is_none().into() {
    return "invalid receiving identity public key".to_string();
  }

  if rspk.is_none().into() {
    return "invalid receiving signed public key".to_string();
  }

  match x3dh::sender_x3dh(&sidk, &sepk, &ridk.unwrap(), &rspk.unwrap(), session_key_length) {
    Some(result) => {
      return format!("\"{}\"", BASE64_STANDARD.encode(result));
    }
    None => {
      return "could not perform key agreement".to_string();
    }
  }
}

pub fn receiver_x3dh(sending_identity_private_key: &Vec<u8>, sending_signed_private_key: &Vec<u8>, receiving_identity_key: &Vec<u8>, receiving_ephemeral_key: &Vec<u8>, session_key_length: u64) -> String {
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
  let ridk = CompressedEdwardsY(receiving_identity_key.as_slice().try_into().unwrap()).decompress();
  let repk = CompressedEdwardsY(receiving_ephemeral_key.as_slice().try_into().unwrap()).decompress();

  if ridk.is_none().into() {
    return "invalid receiving identity public key".to_string();
  }

  if repk.is_none().into() {
    return "invalid receiving signed public key".to_string();
  }

  match x3dh::receiver_x3dh(&sidk, &sspk, &ridk.unwrap(), &repk.unwrap(), session_key_length) {
    Some(result) => {
      return format!("\"{}\"", BASE64_STANDARD.encode(result));
    }
    None => {
      return "could not perform key agreement".to_string();
    }
  }
}

pub fn new_double_ratchet(session_key: &Vec<u8>, sending_header_key: &Vec<u8>, next_receiving_header_key: &Vec<u8>, is_sender: bool, sending_ephemeral_private_key: &Vec<u8>, receiving_ephemeral_key: &Vec<u8>) -> String {
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
    let receiving_key = EdwardsPoint::from_bytes(&receiving_ephemeral_key_bytes.into()).into_option();
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

pub fn double_ratchet_encrypt(ratchet_state_and_message: DoubleRatchetStateAndMessage) -> DoubleRatchetStateAndEnvelope {
    let ratchet_state = ratchet_state_and_message.ratchet_state.clone();
    let participant = DoubleRatchetParticipant::from_json(ratchet_state.clone());

    if participant.is_err() {
        return DoubleRatchetStateAndEnvelope{
            ratchet_state: participant.unwrap_err().to_string(),
            envelope: "".to_string(),
        };
    }

    let mut dr = participant.unwrap();
    let envelope = dr.ratchet_encrypt(&ratchet_state_and_message.message);

    if envelope.is_err() {
        return DoubleRatchetStateAndEnvelope{
            ratchet_state: ratchet_state,
            envelope: envelope.unwrap_err().to_string(),
        };
    }


    let participant_json = dr.to_json();
    if participant_json.is_err() {
        return DoubleRatchetStateAndEnvelope{
            ratchet_state: participant_json.unwrap_err().to_string(),
            envelope: "".to_string(),
        };
    }

    let envelope_json = envelope.unwrap().to_json();
    if envelope_json.is_err() {
        return DoubleRatchetStateAndEnvelope{
            ratchet_state: ratchet_state,
            envelope: envelope_json.unwrap_err().to_string(),
        };
    }

    return DoubleRatchetStateAndEnvelope{
        ratchet_state: participant_json.unwrap(),
        envelope: envelope_json.unwrap(),
    };
}

pub fn double_ratchet_decrypt(ratchet_state_and_envelope: DoubleRatchetStateAndEnvelope) -> DoubleRatchetStateAndMessage {
    let ratchet_state = ratchet_state_and_envelope.ratchet_state.clone();
    let participant = DoubleRatchetParticipant::from_json(ratchet_state.clone());
    let envelope = P2PChannelEnvelope::from_json(ratchet_state_and_envelope.envelope);

    if participant.is_err() || envelope.is_err() {
        return DoubleRatchetStateAndMessage{
            ratchet_state: ratchet_state,
            message: vec![],
        };
    }

    let mut dr = participant.unwrap();
    let message = dr.ratchet_decrypt(&envelope.unwrap());

    if message.is_err() {
        return DoubleRatchetStateAndMessage{
            ratchet_state: ratchet_state,
            message: message.unwrap_err().to_string().as_bytes().to_vec(),
        };
    }

    let participant_json = dr.to_json();
    if participant_json.is_err() {
        return DoubleRatchetStateAndMessage{
            ratchet_state: participant_json.unwrap_err().to_string(),
            message: vec![],
        };
    }

    return DoubleRatchetStateAndMessage{
        ratchet_state: participant_json.unwrap(),
        message: message.unwrap(),
    };
}

pub fn new_triple_ratchet(peers: &Vec<Vec<u8>>, peer_key: &Vec<u8>, identity_key: &Vec<u8>, signed_pre_key: &Vec<u8>, threshold: u64, async_dkg_ratchet: bool) -> TripleRatchetStateAndMetadata {
    if peer_key.len() != 56 {
        return TripleRatchetStateAndMetadata{
            ratchet_state: "invalid peerkey".to_string(),
            metadata: HashMap::new(),
        };
    }

    if identity_key.len() != 56 {
        return TripleRatchetStateAndMetadata{
            ratchet_state: "invalid identity key".to_string(),
            metadata: HashMap::new(),
        };
    }

    if signed_pre_key.len() != 56 {
        return TripleRatchetStateAndMetadata{
            ratchet_state: "invalid signed pre key".to_string(),
            metadata: HashMap::new(),
        };
    }

    if peers.len() < 3 {
        return TripleRatchetStateAndMetadata{
            ratchet_state: "invalid peer count".to_string(),
            metadata: HashMap::new(),
        };
    }

    if threshold > peers.len() as u64 {
        return TripleRatchetStateAndMetadata{
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
            return TripleRatchetStateAndMetadata{
                ratchet_state: "invalid peer key size".to_string(),
                metadata: HashMap::new(),
            };
        }

        peerinfos.push(PeerInfo{
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
        return TripleRatchetStateAndMetadata{
            ratchet_state: participant.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let (tr, metadata) = participant.unwrap();

    let participant_json = tr.to_json();

    if participant_json.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: participant_json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata_json = match metadata_to_json(&String::from(""), metadata) {
        Ok(value) => value,
        Err(value) => return value,
    };

    return TripleRatchetStateAndMetadata{
        ratchet_state: participant_json.unwrap(),
        metadata: metadata_json,
    };
}

fn metadata_to_json(ratchet_state: &String, metadata: HashMap<Vec<u8>, P2PChannelEnvelope>) -> Result<HashMap<String, String>, TripleRatchetStateAndMetadata> {
    let mut metadata_json = HashMap::<String, String>::new();
    for (k,v) in metadata {
        let env = v.to_json();
        if env.is_err() {
            return Err(TripleRatchetStateAndMetadata{
                ratchet_state: env.err().unwrap().to_string(),
                metadata: HashMap::new(),
            });
        }

        metadata_json.insert(BASE64_STANDARD.encode(k), env.unwrap());
    }
    Ok(metadata_json)
}

fn json_to_metadata(ratchet_state_and_metadata: TripleRatchetStateAndMetadata, ratchet_state: &String) -> Result<HashMap<Vec<u8>, P2PChannelEnvelope>, TripleRatchetStateAndMetadata> {
  let mut metadata = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
  for (k,v) in ratchet_state_and_metadata.metadata {
      let env = P2PChannelEnvelope::from_json(v);
      let kb = BASE64_STANDARD.decode(k);
      if env.is_err() {
          return Err(TripleRatchetStateAndMetadata{
              ratchet_state: env.err().unwrap().to_string(),
              metadata: HashMap::new(),
          });
      }
      if kb.is_err() {
          return Err(TripleRatchetStateAndMetadata{
              ratchet_state: kb.err().unwrap().to_string(),
              metadata: HashMap::new(),
          });
      }

      metadata.insert(kb.unwrap(), env.unwrap());
  }
  Ok(metadata)
}

pub fn triple_ratchet_init_round_1(ratchet_state_and_metadata: TripleRatchetStateAndMetadata) -> TripleRatchetStateAndMetadata {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: tr.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata = match json_to_metadata(ratchet_state_and_metadata, &ratchet_state) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let mut trp = tr.unwrap();
    let result = trp.initialize(&metadata);
    if result.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: result.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata = result.unwrap();
    let metadata_json = match metadata_to_json(&ratchet_state, metadata) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    return TripleRatchetStateAndMetadata{
        ratchet_state: json.unwrap(),
        metadata: metadata_json,
    };
}

pub fn triple_ratchet_init_round_2(ratchet_state_and_metadata: TripleRatchetStateAndMetadata) -> TripleRatchetStateAndMetadata {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: tr.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata = match json_to_metadata(ratchet_state_and_metadata, &ratchet_state) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let mut trp = tr.unwrap();
    let mut result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        let r = trp.receive_poly_frag(&k, &v);
        if r.is_err() {
            return TripleRatchetStateAndMetadata{
                ratchet_state: r.err().unwrap().to_string(),
                metadata: HashMap::new(),
            };
        }

        let opt = r.unwrap();
        if opt.is_some() {
          result = opt.unwrap();
        }
    }

    let metadata_json = match metadata_to_json(&ratchet_state, result) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    return TripleRatchetStateAndMetadata{
        ratchet_state: json.unwrap(),
        metadata: metadata_json,
    };
}

pub fn triple_ratchet_init_round_3(ratchet_state_and_metadata: TripleRatchetStateAndMetadata) -> TripleRatchetStateAndMetadata {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: tr.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata = match json_to_metadata(ratchet_state_and_metadata, &ratchet_state) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let mut trp = tr.unwrap();
    let mut result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        let r = trp.receive_commitment(&k, &v);
        if r.is_err() {
            return TripleRatchetStateAndMetadata{
                ratchet_state: r.err().unwrap().to_string(),
                metadata: HashMap::new(),
            };
        }

        let opt = r.unwrap();
        if opt.is_some() {
          result = opt.unwrap();
        }
    }

    let metadata_json = match metadata_to_json(&ratchet_state, result) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    return TripleRatchetStateAndMetadata{
        ratchet_state: json.unwrap(),
        metadata: metadata_json,
    };
}

pub fn triple_ratchet_init_round_4(ratchet_state_and_metadata: TripleRatchetStateAndMetadata) -> TripleRatchetStateAndMetadata {
    let ratchet_state = ratchet_state_and_metadata.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: tr.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    let metadata = match json_to_metadata(ratchet_state_and_metadata, &ratchet_state) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let mut trp = tr.unwrap();
    let mut result = HashMap::<Vec<u8>, P2PChannelEnvelope>::new();
    for (k, v) in metadata {
        let r = trp.recombine(&k, &v);
        if r.is_err() {
            return TripleRatchetStateAndMetadata{
                ratchet_state: r.err().unwrap().to_string(),
                metadata: HashMap::new(),
            };
        }
    }

    let metadata_json = match metadata_to_json(&ratchet_state, result) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndMetadata{
            ratchet_state: json.err().unwrap().to_string(),
            metadata: HashMap::new(),
        };
    }

    return TripleRatchetStateAndMetadata{
        ratchet_state: json.unwrap(),
        metadata: metadata_json,
    };
}

pub fn triple_ratchet_encrypt(ratchet_state_and_message: TripleRatchetStateAndMessage) -> TripleRatchetStateAndEnvelope {
    let ratchet_state = ratchet_state_and_message.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndEnvelope{
            ratchet_state: tr.err().unwrap().to_string(),
            envelope: "".to_string(),
        };
    }

    let mut trp = tr.unwrap();
    let result = trp.ratchet_encrypt(&ratchet_state_and_message.message);

    if result.is_err() {
        return TripleRatchetStateAndEnvelope{
            ratchet_state: result.err().unwrap().to_string(),
            envelope: "".to_string(),
        };
    }

    let envelope = result.unwrap();
    let envelope_json = envelope.to_json();

    if envelope_json.is_err() {
        return TripleRatchetStateAndEnvelope{
            ratchet_state: envelope_json.err().unwrap().to_string(),
            envelope: "".to_string(),
        };
    }

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndEnvelope{
            ratchet_state: json.err().unwrap().to_string(),
            envelope: "".to_string(),
        };
    }

    return TripleRatchetStateAndEnvelope{
        ratchet_state: json.unwrap(),
        envelope: envelope_json.unwrap(),
    };
}

pub fn triple_ratchet_decrypt(ratchet_state_and_envelope: TripleRatchetStateAndEnvelope) -> TripleRatchetStateAndMessage {
    let ratchet_state = ratchet_state_and_envelope.ratchet_state.clone();
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return TripleRatchetStateAndMessage{
            ratchet_state: tr.err().unwrap().to_string(),
            message: vec![],
        };
    }

    let mut trp = tr.unwrap();
    let env = P2PChannelEnvelope::from_json(ratchet_state_and_envelope.envelope);
    if env.is_err() {
        return TripleRatchetStateAndMessage{
            ratchet_state: env.err().unwrap().to_string(),
            message: vec![],
        };
    }

    let result = trp.ratchet_decrypt(&env.unwrap());

    if result.is_err() {
        return TripleRatchetStateAndMessage{
            ratchet_state: result.err().unwrap().to_string(),
            message: vec![],
        };
    }

    let message = result.unwrap().0;

    let json = trp.to_json();
    if json.is_err() {
        return TripleRatchetStateAndMessage{
            ratchet_state: json.err().unwrap().to_string(),
            message: vec![],
        };
    }

    return TripleRatchetStateAndMessage{
        ratchet_state: json.unwrap(),
        message: message,
    };
}

pub fn triple_ratchet_resize(ratchet_state: String, other: String, id: usize, total: usize) -> Vec<Vec<u8>> {
    let tr = TripleRatchetParticipant::from_json(&ratchet_state);
    if tr.is_err() {
        return vec![vec![1]];
    }

    let other_bytes = hex::decode(other);
    if other_bytes.is_err() {
        return vec![other_bytes.unwrap_err().to_string().as_bytes().to_vec()];
    }

    let result = tr.unwrap().ratchet_resize(other_bytes.unwrap(), id, total);
    if result.is_err() {
        return vec![result.unwrap_err().to_string().as_bytes().to_vec()];
    }

    return result.unwrap();
}

pub fn triple_ratchet_verify_point(ratchet_state: String, point: String, id: usize) -> Result<bool, Box<dyn Error>> {
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
    use ed448_goldilocks_plus::{Scalar, elliptic_curve::Group, EdwardsPoint};
    use protocols::{doubleratchet::P2PChannelEnvelope, tripleratchet::{PeerInfo, TripleRatchetParticipant}};

    #[test]
    fn test_four_party_triple_ratchet_communication() {    
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();

        keys.sort_by(|a, b| (a.0 * EdwardsPoint::generator()).compress().to_bytes().cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes()));

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos.iter().enumerate()
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
            ).unwrap();
            
            participants.push(participant);

            for (j, env) in init_msg.iter() {
                init_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }
    
        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i].initialize(&init_messages[&peer_infos[i].public_key.clone()]).unwrap();
            for (j, env) in result.iter() {
                frag_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap() {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
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
                    assert_eq!(message.as_bytes(), decrypted.0.as_slice(), "Message decryption failed for Participant {}", j);
                }
            }
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i].ratchet_encrypt(message1.as_bytes()).unwrap();
                let encrypted2 = participants[i].ratchet_encrypt(message2.as_bytes()).unwrap();

                for j in 0..4 {
                    if i != j {
                      let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                      assert_eq!(message1.as_bytes(), decrypted1.0.as_slice(), "Round message decryption failed for Participant {}", j);
                      let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                      assert_eq!(message2.as_bytes(), decrypted2.0.as_slice(), "Round message decryption failed for Participant {}", j);
                    }
                }
            }
        }
    }


    #[test]
    fn test_four_party_triple_ratchet_communication_with_serialization_each_step() {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();

        keys.sort_by(|a, b| (a.0 * EdwardsPoint::generator()).compress().to_bytes().cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes()));

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos.iter().enumerate()
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
            ).unwrap();

            for (j, env) in init_msg.iter() {
                init_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }

            let participant_json = participant.to_json();
            if participant_json.is_err() {
                panic!("bad json");
            }
            participants.push(TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap());
        }
    
        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i].initialize(&init_messages[&peer_infos[i].public_key.clone()]).unwrap();
            for (j, env) in result.iter() {
                frag_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }

            let participant_json = participants[i].to_json();
            participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap() {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        // Collect reveals and confirm zkpoks are valid, produce group key:
        for i in 0..4 {
            for (j, env) in reveal_messages[&peer_infos[i].public_key.clone()].iter() {
                participants[i].recombine(j, &env.clone()).unwrap();

                let participant_json = participants[i].to_json();
                participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
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
                    assert_eq!(message.as_bytes(), decrypted.0.as_slice(), "Message decryption failed for Participant {}", j);
                }
            }

            let participant_json = participants[i].to_json();
            participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i].ratchet_encrypt(message1.as_bytes()).unwrap();
                let encrypted2 = participants[i].ratchet_encrypt(message2.as_bytes()).unwrap();

                for j in 0..4 {
                    if i != j {
                      let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                      assert_eq!(message1.as_bytes(), decrypted1.0.as_slice(), "Round message decryption failed for Participant {}", j);
                      let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                      assert_eq!(message2.as_bytes(), decrypted2.0.as_slice(), "Round message decryption failed for Participant {}", j);
                    }
                }

                let participant_json = participants[i].to_json();
                participants[i] = TripleRatchetParticipant::from_json(&participant_json.unwrap()).unwrap();
            }
        }
    }

    #[test]
    fn test_four_party_async_triple_ratchet_communication() {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<(Scalar, Scalar, Scalar)> = (0..4)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();

        keys.sort_by(|a, b| (a.0 * EdwardsPoint::generator()).compress().to_bytes().cmp(&(b.0 * EdwardsPoint::generator()).compress().to_bytes()));

        let mut peer_infos: Vec<PeerInfo> = keys
            .iter()
            .map(|(peer_key, identity_key, signed_pre_key)| PeerInfo {
                public_key: (peer_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                identity_public_key: (identity_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
                signed_pre_public_key: (signed_pre_key * EdwardsPoint::generator()).compress().to_bytes().to_vec(),
            })
            .collect();

        // mirror the internal order so we can use by index:
        peer_infos.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut participants: Vec<TripleRatchetParticipant> = Vec::new();
        let mut init_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut frag_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut commitment_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();
        let mut reveal_messages: HashMap<Vec<u8>, HashMap<Vec<u8>, P2PChannelEnvelope>> = HashMap::new();

        for i in 0..4 {
            init_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            frag_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            commitment_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
            reveal_messages.insert(peer_infos[i].public_key.clone(), HashMap::new());
        }

        for i in 0..4 {
            let other_peers: Vec<PeerInfo> = peer_infos.iter().enumerate()
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
            ).unwrap();
            
            participants.push(participant);

            for (j, env) in init_msg.iter() {
                init_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange initial messages and get frags:
        for i in 0..4 {
            let result = participants[i].initialize(&init_messages[&peer_infos[i].public_key.clone()]).unwrap();
            for (j, env) in result.iter() {
                frag_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
            }
        }

        // Exchange frags and receive commitments once all frags have been distributed:
        for i in 0..4 {
            for (p, envelope) in frag_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(out) = participants[i].receive_poly_frag(&p, envelope).unwrap() {
                    for (j, env) in out.iter() {
                        commitment_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
                    }
                }
            }
        }

        // Exchange commitments and produce reveals:
        for i in 0..4 {
            for (p, envelope) in commitment_messages[&peer_infos[i].public_key.clone()].iter() {
                if let Some(reveal_msg) = participants[i].receive_commitment(&p, envelope).unwrap() {
                    for (j, env) in reveal_msg.iter() {
                        reveal_messages.get_mut(j).unwrap().insert(peer_infos[i].public_key.clone(), env.clone());
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
                    assert_eq!(message.as_bytes(), decrypted.0.as_slice(), "Message decryption failed for Participant {}", j);
                }
            }
        }

        for _ in 0..5 {
            for i in 0..4 {
                let message1 = format!("test 1 {}", i + 1);
                let message2 = format!("test 2 {}", i + 1);
                let encrypted1 = participants[i].ratchet_encrypt(message1.as_bytes()).unwrap();
                let encrypted2 = participants[i].ratchet_encrypt(message2.as_bytes()).unwrap();

                for j in 0..4 {
                    if i != j {
                      let decrypted1 = participants[j].ratchet_decrypt(&encrypted1).unwrap();
                      assert_eq!(message1.as_bytes(), decrypted1.0.as_slice(), "Round message decryption failed for Participant {}", j);
                      let decrypted2 = participants[j].ratchet_decrypt(&encrypted2).unwrap();
                      assert_eq!(message2.as_bytes(), decrypted2.0.as_slice(), "Round message decryption failed for Participant {}", j);
                    }
                }
            }
        }
    }
}
