//! Onion link-cell codec + the sntrup761 CREATE/CREATED handshake payloads.
//!
//! Link cell (mirrors Go `onion` `| Cmd(1) | Length(2 BE) | payload |`; Go pads
//! to a fixed 512 B at the link, we keep variable-length since the sntrup761
//! ciphertext (1039 B) already exceeds Go's X448-sized 512 B cell and both ends
//! are Rust):
//!
//! ```text
//! | Cmd (1) | Length (2, big-endian) | payload (Length bytes) |
//! ```
//!
//! CREATE / CREATED — the per-hop handshake. FORWARD-SECRET post-quantum
//! (KEM-based ntor): the initiator encapsulates to the relay's STATIC onion key
//! (authenticating the relay) AND ships a fresh EPHEMERAL sntrup761 public key;
//! the relay encapsulates back to that ephemeral key. The hop secret is
//! `KDF(ss_static ‖ ss_ephemeral)`. Because the initiator discards the ephemeral
//! secret after the handshake, a later compromise of the relay's static onion key
//! recovers `ss_static` but NOT `ss_ephemeral` → past sessions stay secret
//! (forward secrecy).
//!
//! ```text
//! CREATE | outbound_circ_id (4 BE) | next_hop_len (2 BE) | next_hop
//! | eph_public_key (ONION_PUBLIC_KEY_LEN) | ct_static (rest) |
//! CREATED | ct_ephemeral (ONION_CIPHERTEXT_LEN) | confirmation (32) |
//! ```
//!
//! `confirmation = created_confirmation(final_secret)` lets the initiator verify
//! the relay derived the same forward-secret hop key before sending data.

use sha2::{Digest, Sha256};

use super::{ONION_CIPHERTEXT_LEN, ONION_PUBLIC_KEY_LEN};

/// Link command: open a circuit hop (Go `CmdCreate`).
pub const CMD_CREATE: u8 = 0xA0;
/// Link command: circuit-hop established (Go `CmdCreated`).
pub const CMD_CREATED: u8 = 0xA1;
/// Link command: a layered onion (RELAY) cell — payload is AES-GCM ciphertext.
pub const CMD_RELAY: u8 = 0xA2;

/// Post-peel inner-cell type: the body is the next hop's ciphertext — FORWARD it.
pub const INNER_FORWARD: u8 = 0x00;
/// Post-peel inner-cell type: the body is a relay command FOR this hop.
pub const INNER_RELAY: u8 = 0x01;

/// Relay command: application payload for the exit (Go `CmdData`).
pub const RCMD_DATA: u8 = 0x02;
/// Relay command: extend the circuit one hop (Go `CmdExtend`).
pub const RCMD_EXTEND: u8 = 0x05;
/// Relay command: hop extended — carries the new hop's CREATED (Go `CmdExtended`).
pub const RCMD_EXTENDED: u8 = 0x06;

/// A peeled inner cell: either forward the inner ciphertext, or act on a relay
/// command destined for this hop.
#[derive(Debug, PartialEq, Eq)]
pub enum Inner<'a> {
    Forward(&'a [u8]),
    Relay { rcmd: u8, data: &'a [u8] },
}

/// Build a FORWARD inner cell: `| INNER_FORWARD | next_ciphertext |`.
pub fn build_forward_inner(next_ciphertext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + next_ciphertext.len());
    v.push(INNER_FORWARD);
    v.extend_from_slice(next_ciphertext);
    v
}

/// Prefix a DATA payload with an 8-byte big-endian per-circuit sequence number.
/// The seq rides INSIDE the innermost AEAD-encrypted layer, so it is
/// authenticated and unforgeable; the endpoint rejects a non-increasing seq,
/// which stops a malicious relay from replaying a DATA cell (duplicate delivery /
/// duplicate side effect). Ordered transport ⇒ strict-monotonic is sufficient;
/// gaps (dropped cells) are fine, only replays (`seq <= last_seen`) are rejected.
pub fn seq_data(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Split a sequenced DATA body into `(seq, payload)`. `None` if too short.
pub fn parse_seq_data(data: &[u8]) -> Option<(u64, &[u8])> {
    if data.len() < 8 {
        return None;
    }
    let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
    Some((seq, &data[8..]))
}

/// Build a RELAY inner cell: `| INNER_RELAY | rcmd | data |`.
pub fn build_relay_inner(rcmd: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + data.len());
    v.push(INNER_RELAY);
    v.push(rcmd);
    v.extend_from_slice(data);
    v
}

/// Parse a peeled inner cell. `None` if empty or an unknown type.
pub fn parse_inner(plain: &[u8]) -> Option<Inner<'_>> {
    match *plain.first()? {
        INNER_FORWARD => Some(Inner::Forward(&plain[1..])),
        INNER_RELAY => {
            if plain.len() < 2 {
                return None;
            }
            Some(Inner::Relay {
                rcmd: plain[1],
                data: &plain[2..],
            })
        }
        _ => None,
    }
}

/// Build an EXTEND relay-command body: `| next_peer_len(2 BE) | next_peer |
/// eph_public_key(ONION_PUBLIC_KEY_LEN) | ct_static(rest) |` — the CREATE material
/// the extending relay forwards to `next_peer` (initiator's ephemeral key + the
/// ciphertext to the next hop's static onion key).
pub fn build_extend_data(next_peer: &[u8], eph_public_key: &[u8], ct_static: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + next_peer.len() + eph_public_key.len() + ct_static.len());
    v.extend_from_slice(&(next_peer.len() as u16).to_be_bytes());
    v.extend_from_slice(next_peer);
    v.extend_from_slice(eph_public_key);
    v.extend_from_slice(ct_static);
    v
}

/// Parse an EXTEND body into `(next_peer, eph_public_key, ct_static)`.
pub fn parse_extend_data(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let eph_start = 2 + n;
    let ct_start = eph_start + ONION_PUBLIC_KEY_LEN;
    if ct_start > data.len() {
        return None;
    }
    let next_peer = &data[2..eph_start];
    let eph_public_key = &data[eph_start..ct_start];
    let ct_static = &data[ct_start..];
    if ct_static.len() != ONION_CIPHERTEXT_LEN {
        return None;
    }
    Some((next_peer, eph_public_key, ct_static))
}

/// Maximum application payload accepted into a single onion message. The 2-byte
/// link length prefix (and the per-hop layering overhead on top) must fit in
/// `u16`; this cap leaves generous headroom for many hops of AES-GCM layers so an
/// outer cell can never overflow/truncate its length field. Callers at the app
/// boundary (`send_message`, `build_data_reply`) reject larger payloads.
pub const MAX_ONION_PAYLOAD: usize = 60_000;

/// Build a link cell `| Cmd(1) | Length(2 BE) | payload |`. The payload is
/// bounded by [`MAX_ONION_PAYLOAD`] at the app boundary and by fixed-size KEM
/// material everywhere else, so it always fits the `u16` length prefix; the
/// assert catches any future caller that violates that invariant.
pub fn build_cell(cmd: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(
        payload.len() <= u16::MAX as usize,
        "onion cell payload {} exceeds u16 length prefix",
        payload.len()
    );
    let mut buf = Vec::with_capacity(3 + payload.len());
    buf.push(cmd);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Parse a link cell into `(cmd, payload)`. `None` if truncated or the declared
/// length overflows the buffer.
pub fn parse_cell(cell: &[u8]) -> Option<(u8, &[u8])> {
    if cell.len() < 3 {
        return None;
    }
    let cmd = cell[0];
    let len = u16::from_be_bytes([cell[1], cell[2]]) as usize;
    if 3 + len > cell.len() {
        return None;
    }
    Some((cmd, &cell[3..3 + len]))
}

/// Build a CREATE payload: `| outbound_circ(4 BE) | next_hop_len(2 BE) | next_hop
/// | eph_public_key(ONION_PUBLIC_KEY_LEN) | ct_static(rest) |`. `eph_public_key`
/// is the initiator's fresh ephemeral sntrup761 key (for forward secrecy);
/// `ct_static` is the KEM ciphertext encapsulated to the relay's static onion key.
pub fn build_create_payload(
    outbound_circ_id: u32,
    next_hop: &[u8],
    eph_public_key: &[u8],
    ct_static: &[u8],
) -> Vec<u8> {
    let mut p =
        Vec::with_capacity(6 + next_hop.len() + eph_public_key.len() + ct_static.len());
    p.extend_from_slice(&outbound_circ_id.to_be_bytes());
    p.extend_from_slice(&(next_hop.len() as u16).to_be_bytes());
    p.extend_from_slice(next_hop);
    p.extend_from_slice(eph_public_key);
    p.extend_from_slice(ct_static);
    p
}

/// Parse a CREATE payload into `(outbound_circ_id, next_hop, eph_public_key,
/// ct_static)`. `None` if truncated or the fixed-length key/ciphertext don't fit.
pub fn parse_create_payload(payload: &[u8]) -> Option<(u32, &[u8], &[u8], &[u8])> {
    if payload.len() < 6 {
        return None;
    }
    let outbound_circ_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let next_hop_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let hop_start = 6;
    let eph_start = hop_start + next_hop_len;
    let ct_start = eph_start + ONION_PUBLIC_KEY_LEN;
    if ct_start > payload.len() {
        return None;
    }
    let next_hop = &payload[hop_start..eph_start];
    let eph_public_key = &payload[eph_start..ct_start];
    let ct_static = &payload[ct_start..];
    if ct_static.len() != ONION_CIPHERTEXT_LEN {
        return None;
    }
    Some((outbound_circ_id, next_hop, eph_public_key, ct_static))
}

/// Build a CREATED payload: `| ct_ephemeral(ONION_CIPHERTEXT_LEN) |
/// confirmation(32) |`.
pub fn build_created_payload(ct_ephemeral: &[u8], confirmation: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(ct_ephemeral.len() + 32);
    p.extend_from_slice(ct_ephemeral);
    p.extend_from_slice(confirmation);
    p
}

/// Parse a CREATED payload into `(ct_ephemeral, confirmation)`. `None` if it
/// isn't exactly a ciphertext + 32-byte confirmation.
pub fn parse_created_payload(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    if payload.len() != ONION_CIPHERTEXT_LEN + 32 {
        return None;
    }
    Some(payload.split_at(ONION_CIPHERTEXT_LEN))
}

/// KEM-ntor key derivation. Binds BOTH shared secrets (the ephemeral half gives
/// forward secrecy) AND the full handshake transcript — the initiator's ephemeral
/// public key and both KEM ciphertexts — into the hop key:
/// `SHA256("QOR-NTOR-v2" || ss_static || ss_eph || eph_pub || ct_static ||
/// ct_eph)`. Transcript binding prevents any mix-and-match / unknown-key-share
/// confusion: both sides derive the same key only if they agree on every wire
/// value, so a tampered handshake yields a mismatched key and the confirmation
/// fails. (Lengths are fixed by the scheme, so no length prefixes are needed.)
pub fn kdf_ntor(
    ss_static: &[u8],
    ss_ephemeral: &[u8],
    eph_public_key: &[u8],
    ct_static: &[u8],
    ct_ephemeral: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"QOR-NTOR-v2");
    h.update(ss_static);
    h.update(ss_ephemeral);
    h.update(eph_public_key);
    h.update(ct_static);
    h.update(ct_ephemeral);
    h.finalize().into()
}

/// Domain-separated confirmation the relay returns in CREATED and the initiator
/// checks: `SHA256("QOR-CREATED-v2" || hop_secret)`, where `hop_secret` is the
/// forward-secret [`kdf_ntor`] output. Proves the relay derived the same key
/// without revealing it.
pub fn created_confirmation(hop_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"QOR-CREATED-v2");
    h.update(hop_secret);
    h.finalize().into()
}

/// Constant-time equality for authentication tags (e.g. the CREATED
/// confirmation). Runs in time independent of the first differing byte so a
/// network attacker cannot forge a confirmation byte-by-byte via timing.
/// Unequal lengths compare false without early return.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_round_trips() {
        let cell = build_cell(CMD_CREATE, b"payload-bytes");
        let (cmd, payload) = parse_cell(&cell).unwrap();
        assert_eq!(cmd, CMD_CREATE);
        assert_eq!(payload, b"payload-bytes");
    }

    #[test]
    fn short_and_overflowing_cells_are_none() {
        assert!(parse_cell(&[0xA0, 0x00]).is_none()); // < 3 bytes
        // declares 10-byte payload but only 2 present
        assert!(parse_cell(&[0xA0, 0x00, 0x0A, 0x01, 0x02]).is_none());
    }

    #[test]
    fn create_payload_round_trips() {
        let eph = vec![7u8; ONION_PUBLIC_KEY_LEN];
        let ct = vec![9u8; ONION_CIPHERTEXT_LEN];
        let p = build_create_payload(100, b"next-peer", &eph, &ct);
        let (circ, hop, eph_out, ct_out) = parse_create_payload(&p).unwrap();
        assert_eq!(circ, 100);
        assert_eq!(hop, b"next-peer");
        assert_eq!(eph_out, &eph[..]);
        assert_eq!(ct_out, &ct[..]);
    }

    #[test]
    fn create_payload_with_empty_next_hop() {
        let eph = vec![1u8; ONION_PUBLIC_KEY_LEN];
        let ct = vec![3u8; ONION_CIPHERTEXT_LEN];
        let p = build_create_payload(5, b"", &eph, &ct);
        let (circ, hop, eph_out, ct_out) = parse_create_payload(&p).unwrap();
        assert_eq!(circ, 5);
        assert!(hop.is_empty());
        assert_eq!(eph_out, &eph[..]);
        assert_eq!(ct_out, &ct[..]);
    }

    #[test]
    fn truncated_create_payload_is_none() {
        assert!(parse_create_payload(&[0, 0, 0]).is_none());
        // next_hop_len says 50 but no bytes follow
        assert!(parse_create_payload(&[0, 0, 0, 1, 0, 50]).is_none());
        // header + hop but too short for the fixed-length eph key + ciphertext
        assert!(parse_create_payload(&[0, 0, 0, 1, 0, 0]).is_none());
    }

    #[test]
    fn created_payload_round_trips() {
        let ct = vec![4u8; ONION_CIPHERTEXT_LEN];
        let conf = [5u8; 32];
        let p = build_created_payload(&ct, &conf);
        let (ct_out, conf_out) = parse_created_payload(&p).unwrap();
        assert_eq!(ct_out, &ct[..]);
        assert_eq!(conf_out, &conf[..]);
        assert!(parse_created_payload(&[0u8; 10]).is_none()); // wrong size
    }

    #[test]
    fn kdf_ntor_binds_secrets_and_transcript() {
        let base = || kdf_ntor(b"ss_s", b"ss_e", b"eph", b"cts", b"cte");
        assert_eq!(base(), base());
        // Every input is bound — changing any one changes the hop key.
        assert_ne!(base(), kdf_ntor(b"SS_S", b"ss_e", b"eph", b"cts", b"cte"));
        assert_ne!(base(), kdf_ntor(b"ss_s", b"SS_E", b"eph", b"cts", b"cte"));
        assert_ne!(base(), kdf_ntor(b"ss_s", b"ss_e", b"EPH", b"cts", b"cte"));
        assert_ne!(base(), kdf_ntor(b"ss_s", b"ss_e", b"eph", b"CTS", b"cte"));
        assert_ne!(base(), kdf_ntor(b"ss_s", b"ss_e", b"eph", b"cts", b"CTE"));
    }

    #[test]
    fn confirmation_is_deterministic_and_secret_dependent() {
        assert_eq!(created_confirmation(b"secretA"), created_confirmation(b"secretA"));
        assert_ne!(created_confirmation(b"secretA"), created_confirmation(b"secretB"));
    }

    #[test]
    fn forward_inner_round_trips() {
        let inner = build_forward_inner(b"next-hop-ciphertext");
        match parse_inner(&inner).unwrap() {
            Inner::Forward(ct) => assert_eq!(ct, b"next-hop-ciphertext"),
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn relay_inner_round_trips() {
        let inner = build_relay_inner(RCMD_DATA, b"payload");
        match parse_inner(&inner).unwrap() {
            Inner::Relay { rcmd, data } => {
                assert_eq!(rcmd, RCMD_DATA);
                assert_eq!(data, b"payload");
            }
            _ => panic!("expected Relay"),
        }
    }

    #[test]
    fn parse_inner_rejects_empty_and_unknown() {
        assert!(parse_inner(&[]).is_none());
        assert!(parse_inner(&[0x7F]).is_none()); // unknown type
        assert!(parse_inner(&[INNER_RELAY]).is_none()); // relay w/o rcmd
    }

    #[test]
    fn extend_data_round_trips() {
        let eph = vec![2u8; ONION_PUBLIC_KEY_LEN];
        let ct = vec![9u8; ONION_CIPHERTEXT_LEN];
        let d = build_extend_data(b"relayC", &eph, &ct);
        let (peer, eph_out, ct_out) = parse_extend_data(&d).unwrap();
        assert_eq!(peer, b"relayC");
        assert_eq!(eph_out, &eph[..]);
        assert_eq!(ct_out, &ct[..]);
    }

    #[test]
    fn extend_data_truncated_is_none() {
        assert!(parse_extend_data(&[0]).is_none());
        assert!(parse_extend_data(&[0, 9, 1, 2]).is_none()); // len 9, too few
        assert!(parse_extend_data(&[0, 0]).is_none()); // no ciphertext
    }
}
