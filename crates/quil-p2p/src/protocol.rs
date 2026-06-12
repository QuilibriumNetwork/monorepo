//! BlossomSub wire protocol: protobuf RPC messages over libp2p streams.

use prost::Message;

/// Generated protobuf types for BlossomSub RPC.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/blossomsub.pb.rs"));
}

/// Protocol ID for BlossomSub v2.1.0 on mainnet (`network = 0`).
pub const PROTOCOL_ID: &str = "/blossomsub/2.1.0";

/// Protocol ID for `network`. Mainnet (`0`) keeps the bare ID; every
/// other network suffixes `-network-N` so isolated chains never see
/// each other's traffic at the libp2p stream-negotiation layer.
pub fn protocol_id_for_network(network: u8) -> String {
    if network == 0 {
        PROTOCOL_ID.to_string()
    } else {
        format!("{}-network-{}", PROTOCOL_ID, network)
    }
}

/// Same as [`protocol_id_for_network`] but returns a `StreamProtocol`.
pub fn stream_protocol_for_network(network: u8) -> libp2p::StreamProtocol {
    if network == 0 {
        libp2p::StreamProtocol::new(PROTOCOL_ID)
    } else {
        libp2p::StreamProtocol::try_from_owned(protocol_id_for_network(network))
            .expect("network-suffixed BlossomSub protocol ID is well-formed")
    }
}

/// Maximum RPC message size (16 MiB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Encode an RPC message to bytes with a length prefix (unsigned varint).
pub fn encode_rpc(rpc: &pb::Rpc) -> Vec<u8> {
    let msg_bytes = rpc.encode_to_vec();
    let mut buf = Vec::with_capacity(msg_bytes.len() + 10);
    encode_varint(msg_bytes.len() as u64, &mut buf);
    buf.extend_from_slice(&msg_bytes);
    buf
}

/// Decode a length-prefixed RPC message from bytes.
/// Returns (rpc, bytes_consumed) or error.
pub fn decode_rpc(data: &[u8]) -> Result<(pb::Rpc, usize), DecodeError> {
    let (msg_len, varint_len) = decode_varint(data)?;

    if msg_len as usize > MAX_MESSAGE_SIZE {
        return Err(DecodeError::TooLarge(msg_len as usize));
    }

    let total = varint_len + msg_len as usize;
    if data.len() < total {
        return Err(DecodeError::Incomplete {
            need: total,
            have: data.len(),
        });
    }

    let rpc = pb::Rpc::decode(&data[varint_len..total])
        .map_err(|e| DecodeError::Proto(e.to_string()))?;

    Ok((rpc, total))
}

/// Build an RPC with subscription messages.
pub fn subscribe_rpc(bitmasks: &[Vec<u8>]) -> pb::Rpc {
    pb::Rpc {
        subscriptions: bitmasks
            .iter()
            .map(|b| pb::rpc::SubOpts {
                subscribe: true,
                bitmask: b.clone(),
            })
            .collect(),
        publish: Vec::new(),
        control: None,
    }
}

/// Build an RPC with unsubscription messages.
pub fn unsubscribe_rpc(bitmasks: &[Vec<u8>]) -> pb::Rpc {
    pb::Rpc {
        subscriptions: bitmasks
            .iter()
            .map(|b| pb::rpc::SubOpts {
                subscribe: false,
                bitmask: b.clone(),
            })
            .collect(),
        publish: Vec::new(),
        control: None,
    }
}

/// Build an RPC with GRAFT control messages.
pub fn graft_rpc(bitmasks: &[Vec<u8>]) -> pb::Rpc {
    pb::Rpc {
        subscriptions: Vec::new(),
        publish: Vec::new(),
        control: Some(pb::ControlMessage {
            ihave: Vec::new(),
            iwant: Vec::new(),
            graft: bitmasks
                .iter()
                .map(|b| pb::ControlGraft {
                    bitmask: b.clone(),
                })
                .collect(),
            prune: Vec::new(),
            idontwant: Vec::new(),
        }),
    }
}

/// Build an RPC with PRUNE control messages.
pub fn prune_rpc(bitmasks: &[Vec<u8>], backoff_secs: u64) -> pb::Rpc {
    pb::Rpc {
        subscriptions: Vec::new(),
        publish: Vec::new(),
        control: Some(pb::ControlMessage {
            ihave: Vec::new(),
            iwant: Vec::new(),
            graft: Vec::new(),
            prune: bitmasks
                .iter()
                .map(|b| pb::ControlPrune {
                    bitmask: b.clone(),
                    peers: Vec::new(),
                    backoff: backoff_secs,
                })
                .collect(),
            idontwant: Vec::new(),
        }),
    }
}

/// Build an RPC with IHAVE control messages (gossip).
pub fn ihave_rpc(bitmask: &[u8], message_ids: &[Vec<u8>]) -> pb::Rpc {
    pb::Rpc {
        subscriptions: Vec::new(),
        publish: Vec::new(),
        control: Some(pb::ControlMessage {
            ihave: vec![pb::ControlIHave {
                bitmask: bitmask.to_vec(),
                message_i_ds: message_ids.to_vec(),
            }],
            iwant: Vec::new(),
            graft: Vec::new(),
            prune: Vec::new(),
            idontwant: Vec::new(),
        }),
    }
}

/// Build an RPC containing published messages.
pub fn publish_rpc(messages: Vec<pb::Message>) -> pb::Rpc {
    pb::Rpc {
        subscriptions: Vec::new(),
        publish: messages,
        control: None,
    }
}

// ---------------------------------------------------------------------------
// Varint encoding (unsigned LEB128 protobuf varint)
// ---------------------------------------------------------------------------

fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_varint(data: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(DecodeError::Proto("varint too long".into()));
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(DecodeError::Incomplete {
        need: 1,
        have: 0,
    })
}

#[derive(Debug)]
pub enum DecodeError {
    Incomplete { need: usize, have: usize },
    TooLarge(usize),
    Proto(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Incomplete { need, have } => {
                write!(f, "incomplete: need {} bytes, have {}", need, have)
            }
            DecodeError::TooLarge(size) => write!(f, "message too large: {} bytes", size),
            DecodeError::Proto(msg) => write!(f, "protobuf error: {}", msg),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 300, 16384, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let (decoded, len) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn test_rpc_roundtrip() {
        let rpc = subscribe_rpc(&[vec![0x00], vec![0x00, 0x00]]);
        let encoded = encode_rpc(&rpc);
        let (decoded, consumed) = decode_rpc(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.subscriptions.len(), 2);
        assert!(decoded.subscriptions[0].subscribe);
        assert_eq!(decoded.subscriptions[0].bitmask, vec![0x00]);
    }

    #[test]
    fn test_graft_prune_rpc() {
        let graft = graft_rpc(&[vec![0x00]]);
        assert!(graft.control.as_ref().unwrap().graft.len() == 1);

        let prune = prune_rpc(&[vec![0x00]], 60);
        assert!(prune.control.as_ref().unwrap().prune.len() == 1);
        assert_eq!(prune.control.as_ref().unwrap().prune[0].backoff, 60);
    }
}
