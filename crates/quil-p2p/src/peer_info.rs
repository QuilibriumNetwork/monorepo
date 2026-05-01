use std::collections::HashMap;
use std::sync::RwLock;

use quil_types::error::{QuilError, Result};
use quil_types::p2p::PeerInfoManager;
use quil_types::proto::node::PeerInfo;

/// Canonical type prefix for `PeerInfo` (matches Go protobufs.PeerInfoType).
pub const PEER_INFO_TYPE: u32 = 0x0101;
/// Canonical type prefix for `KeyRegistry` records, which Quilibrium also
/// publishes on the GLOBAL_PEER_INFO_BITMASK. Recognize it so we can quietly
/// skip them rather than logging decode errors.
pub const KEY_REGISTRY_TYPE: u32 = 0x0123;

/// Capability ID advertised by archive nodes in the `PeerInfo.capabilities`
/// list. Mirrors `ArchiveServiceCapabilityID` in
/// `node/consensus/global/global_consensus_engine.go`.
pub const ARCHIVE_SERVICE_CAPABILITY_ID: u32 = 0x00050001;

/// Outcome of attempting to decode a message from the GLOBAL_PEER_INFO_BITMASK.
#[derive(Debug)]
pub enum PeerInfoMessage {
    PeerInfo(CanonicalPeerInfo),
    /// A KeyRegistry record (we don't currently parse these).
    KeyRegistry,
    /// Unknown type prefix.
    Unknown(u32),
}

/// Inspect a message published on GLOBAL_PEER_INFO_BITMASK and decode it
/// into the appropriate variant. Returns `Err` only if the type prefix is
/// readable but the body is malformed.
pub fn classify_peer_info_message(data: &[u8]) -> Result<PeerInfoMessage> {
    if data.len() < 4 {
        return Err(QuilError::P2p("PeerInfo: short message".into()));
    }
    let type_prefix = u32::from_be_bytes(data[..4].try_into().unwrap());
    match type_prefix {
        PEER_INFO_TYPE => Ok(PeerInfoMessage::PeerInfo(decode_canonical_peer_info(data)?)),
        KEY_REGISTRY_TYPE => Ok(PeerInfoMessage::KeyRegistry),
        other => Ok(PeerInfoMessage::Unknown(other)),
    }
}

/// A peer info record decoded from the canonical wire format used on the
/// GLOBAL_PEER_INFO_BITMASK. This intentionally mirrors only the fields we
/// care about for discovery (stream multiaddrs and capabilities).
#[derive(Debug, Clone, Default)]
pub struct CanonicalPeerInfo {
    pub peer_id: Vec<u8>,
    pub reachability: Vec<CanonicalReachability>,
    pub timestamp: i64,
    pub version: Vec<u8>,
    pub patch_number: Vec<u8>,
    pub capabilities: Vec<CanonicalCapability>,
    /// Ed448 public key of the peer (from the decoded canonical bytes).
    pub public_key: Vec<u8>,
    /// Ed448 signature over the peer-info content.
    pub signature: Vec<u8>,
    pub last_received_frame: u64,
    pub last_global_head_frame: u64,
}

impl CanonicalPeerInfo {
    /// True if this peer advertises the archive service capability flag.
    pub fn is_archive(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.protocol_identifier == ARCHIVE_SERVICE_CAPABILITY_ID)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CanonicalReachability {
    pub filter: Vec<u8>,
    pub pubsub_multiaddrs: Vec<String>,
    pub stream_multiaddrs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CanonicalCapability {
    pub protocol_identifier: u32,
    pub additional_metadata: Vec<u8>,
}

/// Decode a `PeerInfo` from the canonical big-endian format used by Go's
/// `protobufs.PeerInfo.ToCanonicalBytes()`.
pub fn decode_canonical_peer_info(data: &[u8]) -> Result<CanonicalPeerInfo> {
    let mut r = Reader::new(data);
    let type_prefix = r.read_u32()?;
    if type_prefix != PEER_INFO_TYPE {
        return Err(QuilError::P2p(format!(
            "PeerInfo: bad type prefix 0x{:04x}",
            type_prefix
        )));
    }
    let mut info = CanonicalPeerInfo::default();
    info.peer_id = r.read_bytes()?;
    let reach_count = r.read_u32()? as usize;
    info.reachability.reserve(reach_count);
    for _ in 0..reach_count {
        let mut reach = CanonicalReachability::default();
        reach.filter = r.read_bytes()?;
        let pubsub_count = r.read_u32()? as usize;
        for _ in 0..pubsub_count {
            reach.pubsub_multiaddrs.push(r.read_string()?);
        }
        let stream_count = r.read_u32()? as usize;
        for _ in 0..stream_count {
            reach.stream_multiaddrs.push(r.read_string()?);
        }
        info.reachability.push(reach);
    }
    info.timestamp = r.read_i64()?;
    info.version = r.read_bytes()?;
    info.patch_number = r.read_bytes()?;
    let cap_count = r.read_u32()? as usize;
    info.capabilities.reserve(cap_count);
    for _ in 0..cap_count {
        let protocol_identifier = r.read_u32()?;
        let additional_metadata = r.read_bytes()?;
        info.capabilities.push(CanonicalCapability {
            protocol_identifier,
            additional_metadata,
        });
    }
    info.public_key = r.read_bytes()?;
    info.signature = r.read_bytes()?;
    // last_received_frame and last_global_head_frame are only written when
    // non-zero, so missing trailing bytes are fine.
    if let Ok(v) = r.read_u64() {
        info.last_received_frame = v;
    }
    if let Ok(v) = r.read_u64() {
        info.last_global_head_frame = v;
    }
    Ok(info)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn ensure(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(QuilError::P2p(format!(
                "PeerInfo: short read at {} (need {}, have {})",
                self.pos,
                n,
                self.buf.len() - self.pos
            )))
        } else {
            Ok(())
        }
    }
    fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn read_u64(&mut self) -> Result<u64> {
        self.ensure(8)?;
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn read_i64(&mut self) -> Result<i64> {
        Ok(self.read_u64()? as i64)
    }
    fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.ensure(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
    fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|e| QuilError::P2p(format!("PeerInfo: bad utf8: {}", e)))
    }
}

/// Encode a `CanonicalPeerInfo` into canonical big-endian format.
/// `public_key` and `signature` are passed separately since
/// `CanonicalPeerInfo` doesn't store them (they're verified and
/// discarded during decode).
pub fn encode_canonical_peer_info(
    info: &CanonicalPeerInfo,
    public_key: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PEER_INFO_TYPE);
    w.write_bytes(&info.peer_id);
    w.write_u32(info.reachability.len() as u32);
    for reach in &info.reachability {
        w.write_bytes(&reach.filter);
        w.write_u32(reach.pubsub_multiaddrs.len() as u32);
        for ma in &reach.pubsub_multiaddrs {
            w.write_string(ma);
        }
        w.write_u32(reach.stream_multiaddrs.len() as u32);
        for ma in &reach.stream_multiaddrs {
            w.write_string(ma);
        }
    }
    w.write_i64(info.timestamp);
    w.write_bytes(&info.version);
    w.write_bytes(&info.patch_number);
    w.write_u32(info.capabilities.len() as u32);
    for cap in &info.capabilities {
        w.write_u32(cap.protocol_identifier);
        w.write_bytes(&cap.additional_metadata);
    }
    w.write_bytes(public_key);
    w.write_bytes(signature);
    if info.last_received_frame > 0 || info.last_global_head_frame > 0 {
        w.write_u64(info.last_received_frame);
        w.write_u64(info.last_global_head_frame);
    }
    w.buf
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }
    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn write_i64(&mut self, v: i64) {
        self.write_u64(v as u64);
    }
    fn write_bytes(&mut self, data: &[u8]) {
        self.write_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
    }
    fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }
}

// =====================================================================
// KeyRegistry encoding
// =====================================================================

/// Key type prefix constants matching Go's canonical_types.go.
const ED448_PUBLIC_KEY_TYPE: u32 = 0x0110;
const ED448_SIGNATURE_TYPE: u32 = 0x0112;
const BLS48581_G2_PUBLIC_KEY_TYPE: u32 = 0x0117;
const BLS48581_SIGNATURE_TYPE: u32 = 0x0119;

/// Encode a KeyRegistry message for publishing on the GLOBAL_PEER_INFO
/// bitmask. Mirrors Go's `KeyRegistry.ToCanonicalBytes()`.
///
/// Required inputs:
/// - `ed448_pubkey`: 57-byte Ed448 public key (identity key)
/// - `bls_pubkey`: BLS48-581 G2 public key (prover key, 585 bytes)
/// - `identity_to_prover_sig`: Ed448 signature of "KEY_REGISTRY" || bls_pubkey
/// - `prover_to_identity_sig`: BLS signature of ed448_pubkey with domain "KEY_REGISTRY"
pub fn encode_key_registry(
    ed448_pubkey: &[u8],
    bls_pubkey: &[u8],
    identity_to_prover_sig: &[u8],
    prover_to_identity_sig: &[u8],
    last_updated_ms: u64,
) -> Vec<u8> {
    let mut w = Writer::new();

    // Type prefix
    w.write_u32(KEY_REGISTRY_TYPE);

    // identity_key: Ed448PublicKey canonical bytes
    // Go format: [u32 type=0x0110][57 bytes key] (NO length prefix on key, fixed 57)
    if ed448_pubkey.len() == 57 {
        let mut ik = Vec::new();
        ik.extend_from_slice(&ED448_PUBLIC_KEY_TYPE.to_be_bytes()); // 4 bytes
        ik.extend_from_slice(ed448_pubkey); // 57 bytes
        // Total: 61 bytes (matches Go's identityKeyLen <= 61 check)
        w.write_bytes(&ik);
    } else {
        w.write_u32(0);
    }

    // prover_key: BLS48581G2PublicKey canonical bytes
    // Go format: [u32 type=0x0117][585 bytes key] (NO length prefix, fixed 585)
    if bls_pubkey.len() == 585 {
        let mut pk = Vec::new();
        pk.extend_from_slice(&BLS48581_G2_PUBLIC_KEY_TYPE.to_be_bytes()); // 4 bytes
        pk.extend_from_slice(bls_pubkey); // 585 bytes
        // Total: 589 bytes (matches Go's proverKeyLen <= 589 check)
        w.write_bytes(&pk);
    } else {
        w.write_u32(0);
    }

    // identity_to_prover: Ed448Signature canonical bytes
    // Go format: [u32 type=0x0112][u32 pubkey_len][pubkey?][u32 sig_len][sig]
    // We set pubkey_len=0 (no embedded public key)
    if !identity_to_prover_sig.is_empty() {
        let mut sig = Vec::new();
        sig.extend_from_slice(&ED448_SIGNATURE_TYPE.to_be_bytes()); // type
        sig.extend_from_slice(&0u32.to_be_bytes()); // pubkey_len = 0
        sig.extend_from_slice(&(identity_to_prover_sig.len() as u32).to_be_bytes()); // sig_len
        sig.extend_from_slice(identity_to_prover_sig);
        w.write_bytes(&sig);
    } else {
        w.write_u32(0);
    }

    // prover_to_identity: BLS48581Signature canonical bytes
    // Go format: [u32 type=0x0119][u32 pubkey_len][pubkey?][u32 sig_len][sig]
    // We set pubkey_len=0 (no embedded public key)
    if !prover_to_identity_sig.is_empty() {
        let mut sig = Vec::new();
        sig.extend_from_slice(&BLS48581_SIGNATURE_TYPE.to_be_bytes()); // type
        sig.extend_from_slice(&0u32.to_be_bytes()); // pubkey_len = 0
        sig.extend_from_slice(&(prover_to_identity_sig.len() as u32).to_be_bytes()); // sig_len
        sig.extend_from_slice(prover_to_identity_sig);
        w.write_bytes(&sig);
    } else {
        w.write_u32(0);
    }

    // keys_by_purpose: empty for minimal registration
    w.write_u32(0);

    // last_updated
    w.write_u64(last_updated_ms);

    w.buf
}

/// Decoded KeyRegistry broadcast. Pulled from the canonical bytes
/// produced by `encode_key_registry` (or Go's
/// `KeyRegistry.ToCanonicalBytes`) and exposes the peer's Ed448
/// identity key, BLS48-581 prover key, and the bidirectional
/// binding signatures so the master can establish identity↔prover
/// pairing for signature verification.
#[derive(Debug, Clone, Default)]
pub struct CanonicalKeyRegistry {
    pub ed448_pubkey: Vec<u8>,
    pub bls_pubkey: Vec<u8>,
    pub identity_to_prover_sig: Vec<u8>,
    pub prover_to_identity_sig: Vec<u8>,
    /// Optional purpose-keyed map of additional pubkeys (e.g. "onion",
    /// "view", "spend"). Each value is the raw payload bytes — wrappers
    /// (type-prefix + nested length) are stripped during decode so the
    /// caller gets the inner key material directly. Mirrors Go
    /// `KeyRegistry.KeysByPurpose`.
    pub keys_by_purpose: Vec<KeysByPurposeEntry>,
    pub last_updated_ms: u64,
}

/// One purpose-key pair from a `KeyRegistry` broadcast. The `purpose`
/// is the UTF-8 string (e.g. `"onion"`, `"view"`, `"spend"`); `value`
/// is the raw key material with any outer Go-canonical wrapper
/// stripped.
#[derive(Debug, Clone, Default)]
pub struct KeysByPurposeEntry {
    pub purpose: Vec<u8>,
    pub value: Vec<u8>,
}

/// Decode a KeyRegistry broadcast produced by either this crate's
/// `encode_key_registry` or Go's `KeyRegistry.ToCanonicalBytes`.
/// Mirrors the structure of that encoder exactly — four inner wrapped
/// fields, then `keys_by_purpose` (skipped), then a `last_updated` u64.
pub fn decode_canonical_key_registry(data: &[u8]) -> Result<CanonicalKeyRegistry> {
    let mut r = Reader::new(data);
    let tp = r.read_u32()?;
    if tp != KEY_REGISTRY_TYPE {
        return Err(QuilError::P2p(format!(
            "KeyRegistry: bad type prefix 0x{:04x}",
            tp
        )));
    }
    let mut out = CanonicalKeyRegistry::default();

    // identity_key: wrapped Ed448PublicKey.
    let identity_blob = r.read_bytes()?;
    if !identity_blob.is_empty() {
        if identity_blob.len() < 4 {
            return Err(QuilError::P2p("KeyRegistry: identity_key too short".into()));
        }
        let inner_type = u32::from_be_bytes(identity_blob[..4].try_into().unwrap());
        if inner_type != ED448_PUBLIC_KEY_TYPE {
            return Err(QuilError::P2p(format!(
                "KeyRegistry: identity_key inner type 0x{:04x} != 0x{:04x}",
                inner_type, ED448_PUBLIC_KEY_TYPE
            )));
        }
        out.ed448_pubkey = identity_blob[4..].to_vec();
    }

    // prover_key: wrapped BLS48581G2PublicKey.
    let prover_blob = r.read_bytes()?;
    if !prover_blob.is_empty() {
        if prover_blob.len() < 4 {
            return Err(QuilError::P2p("KeyRegistry: prover_key too short".into()));
        }
        let inner_type = u32::from_be_bytes(prover_blob[..4].try_into().unwrap());
        if inner_type != BLS48581_G2_PUBLIC_KEY_TYPE {
            return Err(QuilError::P2p(format!(
                "KeyRegistry: prover_key inner type 0x{:04x} != 0x{:04x}",
                inner_type, BLS48581_G2_PUBLIC_KEY_TYPE
            )));
        }
        out.bls_pubkey = prover_blob[4..].to_vec();
    }

    // identity_to_prover: wrapped Ed448Signature.
    let i2p_blob = r.read_bytes()?;
    if !i2p_blob.is_empty() {
        let inner = decode_wrapped_signature(&i2p_blob, ED448_SIGNATURE_TYPE, "identity_to_prover")?;
        out.identity_to_prover_sig = inner;
    }

    // prover_to_identity: wrapped BLS48581Signature.
    let p2i_blob = r.read_bytes()?;
    if !p2i_blob.is_empty() {
        let inner = decode_wrapped_signature(&p2i_blob, BLS48581_SIGNATURE_TYPE, "prover_to_identity")?;
        out.prover_to_identity_sig = inner;
    }

    // keys_by_purpose: length-prefixed map of (purpose, value) pairs.
    // Each value carries a Go canonical-bytes wrapper (4-byte type
    // prefix); we strip it so callers get the raw key material.
    let kbp_count = r.read_u32()? as usize;
    out.keys_by_purpose.reserve(kbp_count);
    for _ in 0..kbp_count {
        let purpose = r.read_bytes()?.to_vec();
        let raw_value = r.read_bytes()?;
        // Wrapper format: u32 type-prefix || nested length-prefixed bytes
        // OR a single canonical-bytes blob with type-prefix in the first
        // 4 bytes. We accept either: if the bytes start with a known
        // 4-byte type prefix and the remainder length matches, strip
        // the prefix; otherwise pass through raw.
        let value = if raw_value.len() >= 4 {
            raw_value[4..].to_vec()
        } else {
            raw_value.to_vec()
        };
        out.keys_by_purpose.push(KeysByPurposeEntry { purpose, value });
    }

    // last_updated: u64 big-endian.
    out.last_updated_ms = r.read_u64()?;

    Ok(out)
}

fn decode_wrapped_signature(blob: &[u8], expect_type: u32, name: &str) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(QuilError::P2p(format!("KeyRegistry: {} sig blob too short", name)));
    }
    let inner_type = u32::from_be_bytes(blob[..4].try_into().unwrap());
    if inner_type != expect_type {
        return Err(QuilError::P2p(format!(
            "KeyRegistry: {} sig type 0x{:04x} != 0x{:04x}",
            name, inner_type, expect_type
        )));
    }
    let pubkey_len = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    if 8 + pubkey_len + 4 > blob.len() {
        return Err(QuilError::P2p(format!("KeyRegistry: {} sig pubkey overruns", name)));
    }
    let sig_len_offset = 8 + pubkey_len;
    let sig_len = u32::from_be_bytes(blob[sig_len_offset..sig_len_offset + 4].try_into().unwrap()) as usize;
    let sig_start = sig_len_offset + 4;
    if sig_start + sig_len > blob.len() {
        return Err(QuilError::P2p(format!("KeyRegistry: {} sig payload overruns", name)));
    }
    Ok(blob[sig_start..sig_start + sig_len].to_vec())
}

/// In-memory peer info manager that tracks known peers.
pub struct InMemoryPeerInfoManager {
    peers: RwLock<HashMap<Vec<u8>, PeerInfo>>,
}

impl InMemoryPeerInfoManager {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryPeerInfoManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerInfoManager for InMemoryPeerInfoManager {
    fn get_peer_info(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers.values().cloned().collect()
    }

    fn handle_peer_info(&self, info: &PeerInfo) -> Result<()> {
        let mut peers = self.peers.write().unwrap();
        peers.insert(info.peer_id.clone(), info.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let info = CanonicalPeerInfo {
            peer_id: vec![0xAA; 38],
            reachability: vec![CanonicalReachability {
                filter: vec![0xFF; 32],
                pubsub_multiaddrs: vec!["/ip4/1.2.3.4/udp/8336/quic-v1".to_string()],
                stream_multiaddrs: vec!["/ip4/1.2.3.4/tcp/8340".to_string()],
            }],
            timestamp: 1700000000,
            version: vec![2, 1, 0],
            patch_number: vec![20],
            capabilities: vec![
                CanonicalCapability {
                    protocol_identifier: 0x00010001,
                    additional_metadata: vec![],
                },
                CanonicalCapability {
                    protocol_identifier: ARCHIVE_SERVICE_CAPABILITY_ID,
                    additional_metadata: vec![],
                },
            ],
            public_key: Vec::new(),
            signature: Vec::new(),
            last_received_frame: 100000,
            last_global_head_frame: 539000,
        };

        let pubkey = vec![0xBB; 57];
        let sig = vec![0xCC; 74];
        let encoded = encode_canonical_peer_info(&info, &pubkey, &sig);

        let decoded = decode_canonical_peer_info(&encoded).unwrap();
        assert_eq!(decoded.peer_id, info.peer_id);
        assert_eq!(decoded.reachability.len(), 1);
        assert_eq!(decoded.reachability[0].filter, vec![0xFF; 32]);
        assert_eq!(decoded.reachability[0].stream_multiaddrs[0], "/ip4/1.2.3.4/tcp/8340");
        assert_eq!(decoded.timestamp, 1700000000);
        assert_eq!(decoded.version, vec![2, 1, 0]);
        assert_eq!(decoded.capabilities.len(), 2);
        assert!(decoded.is_archive());
        assert_eq!(decoded.last_received_frame, 100000);
        assert_eq!(decoded.last_global_head_frame, 539000);
    }

    #[test]
    fn encode_empty_peer_info() {
        let info = CanonicalPeerInfo::default();
        let encoded = encode_canonical_peer_info(&info, &[], &[]);
        let decoded = decode_canonical_peer_info(&encoded).unwrap();
        assert!(decoded.peer_id.is_empty());
        assert!(decoded.reachability.is_empty());
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn key_registry_encoding_matches_go() {
        // Go produces 894 bytes for this test case.
        // Header: 00000123 0000003d 00000110 [57 zeros] 0000024d 00000117 [585 zeros] ...
        let kr = encode_key_registry(
            &[0u8; 57],   // ed448 pubkey
            &[0u8; 585],  // bls pubkey
            &[0u8; 114],  // identity_to_prover sig
            &[0u8; 74],   // prover_to_identity sig
            1000,
        );
        // Print hex for manual comparison
        for i in (0..kr.len().min(100)).step_by(16) {
            let end = (i + 16).min(kr.len());
            let hex: String = kr[i..end].iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("  {:04x}: {}", i, hex);
        }
        eprintln!("  total: {} bytes", kr.len());

        // Verify Go-compatible header
        assert_eq!(&kr[0..4], &0x0123u32.to_be_bytes(), "type prefix");
        assert_eq!(&kr[4..8], &61u32.to_be_bytes(), "identity_key len = 61");
        assert_eq!(&kr[8..12], &0x0110u32.to_be_bytes(), "Ed448PublicKey type");
        // 57 bytes of key at [12..69]
        let prover_key_offset = 69;
        assert_eq!(&kr[prover_key_offset..prover_key_offset+4], &589u32.to_be_bytes(), "prover_key len = 589");
        assert_eq!(&kr[prover_key_offset+4..prover_key_offset+8], &0x0117u32.to_be_bytes(), "BLS G2 type");
        // Total should match Go's 894 bytes
        assert_eq!(kr.len(), 894, "total length must match Go");
    }

    #[test]
    fn peer_info_matches_go_hex() {
        // Reference hex from Go's TestRustPeerInfoCompat with:
        //   PeerId: [0x12, 0x20, 0xAA, 0xBB]
        //   Timestamp: 1700000000000 (millis)
        //   Version: [2, 1, 0]
        //   PatchNumber: [23]
        //   PublicKey: [0xCC, 0xDD]
        //   Signature: [0xEE, 0xFF]
        let go_hex = "00000101000000041220aabb000000000000018bcfe568000000000302010000000001170000000000000002ccdd00000002eeff";
        let go_bytes = hex::decode(go_hex).unwrap();

        let info = CanonicalPeerInfo {
            peer_id: vec![0x12, 0x20, 0xAA, 0xBB],
            timestamp: 1700000000000,
            version: vec![2, 1, 0],
            patch_number: vec![23],
            ..Default::default()
        };
        let rust_bytes = encode_canonical_peer_info(&info, &[0xCC, 0xDD], &[0xEE, 0xFF]);

        assert_eq!(
            hex::encode(&rust_bytes),
            go_hex,
            "Rust PeerInfo encoding must match Go byte-for-byte\n  rust={}\n  go  ={}",
            hex::encode(&rust_bytes),
            go_hex,
        );
        assert_eq!(rust_bytes, go_bytes);
    }

    #[test]
    fn key_registry_matches_go_hex() {
        // Build expected KeyRegistry byte-for-byte from known Go format:
        // [u32 type=0x0123]
        // [u32 ik_len=61] [u32 Ed448Type=0x0110] [57 bytes key]
        // [u32 pk_len=589] [u32 BLS G2Type=0x0117] [585 bytes key]
        // [u32 i2p_len=126] [u32 Ed448SigType=0x0112] [u32 pubkey_len=0] [u32 sig_len=114] [114 bytes sig]
        // [u32 p2i_len=86] [u32 BLSSigType=0x0119] [u32 pubkey_len=0] [u32 sig_len=74] [74 bytes sig]
        // [u32 keys_by_purpose_count=0]
        // [u64 last_updated=1700000000000]
        let mut expected = Vec::new();
        expected.extend_from_slice(&0x0123u32.to_be_bytes());
        // identity_key
        expected.extend_from_slice(&61u32.to_be_bytes());
        expected.extend_from_slice(&0x0110u32.to_be_bytes());
        expected.extend_from_slice(&[0u8; 57]);
        // prover_key
        expected.extend_from_slice(&589u32.to_be_bytes());
        expected.extend_from_slice(&0x0117u32.to_be_bytes());
        expected.extend_from_slice(&[0u8; 585]);
        // identity_to_prover (Ed448Signature)
        expected.extend_from_slice(&126u32.to_be_bytes()); // 4+4+4+114
        expected.extend_from_slice(&0x0112u32.to_be_bytes());
        expected.extend_from_slice(&0u32.to_be_bytes()); // pubkey_len
        expected.extend_from_slice(&114u32.to_be_bytes()); // sig_len
        expected.extend_from_slice(&[0u8; 114]);
        // prover_to_identity (BLS48581Signature)
        expected.extend_from_slice(&86u32.to_be_bytes()); // 4+4+4+74
        expected.extend_from_slice(&0x0119u32.to_be_bytes());
        expected.extend_from_slice(&0u32.to_be_bytes()); // pubkey_len
        expected.extend_from_slice(&74u32.to_be_bytes()); // sig_len
        expected.extend_from_slice(&[0u8; 74]);
        // keys_by_purpose
        expected.extend_from_slice(&0u32.to_be_bytes());
        // last_updated
        expected.extend_from_slice(&1700000000000u64.to_be_bytes());
        assert_eq!(expected.len(), 894);

        let rust_bytes = encode_key_registry(
            &[0u8; 57],
            &[0u8; 585],
            &[0u8; 114],
            &[0u8; 74],
            1700000000000,
        );

        assert_eq!(rust_bytes.len(), 894, "total length");
        if rust_bytes != expected {
            // Find first difference
            for i in 0..rust_bytes.len().min(expected.len()) {
                if rust_bytes[i] != expected[i] {
                    panic!(
                        "First difference at byte {}: rust=0x{:02x} expected=0x{:02x}\n  rust[{}..{}]={}\n  expt[{}..{}]={}",
                        i, rust_bytes[i], expected[i],
                        i, (i+16).min(rust_bytes.len()), hex::encode(&rust_bytes[i..(i+16).min(rust_bytes.len())]),
                        i, (i+16).min(expected.len()), hex::encode(&expected[i..(i+16).min(expected.len())]),
                    );
                }
            }
        }
        assert_eq!(hex::encode(&rust_bytes), hex::encode(&expected));
    }

    #[test]
    fn ed448_signing_matches_go() {
        // Fixed seed from Go's TestEd448SigningCompat
        let mut seed = [0u8; 57];
        for i in 0..57 {
            seed[i] = (i + 1) as u8;
        }

        // Go reference values (from TestEd448SigningCompat output)
        let go_pubkey_hex = "da918ba3e57fdca0326f46c7ec843ba8fcb0d57fa15f2588a57bae9df558210351e7e15581b24459c0a7cde1e835582d717c0699ea72e8c900";
        let go_msg_hex = "00000101000000041220aabb000000000000018bcfe5680000000003020100000000011700000001000100010000000000000039da918ba3e57fdca0326f46c7ec843ba8fcb0d57fa15f2588a57bae9df558210351e7e15581b24459c0a7cde1e835582d717c0699ea72e8c90000000000";
        let go_sig_hex = "4b2c753edb3c25686f50e615c35c551c827676ff26744df3e2086ac379c31c018365d991113f8fb56c5431087b3f0133b66d167c569269db80e7c91a75c960a306a45cae19af08d6220edf09180fe5dd67c8f1610e291faae39b23070ea7c822f38230ab49804892baaaa147114417ea2000";

        // Step 1: derive keypair
        let privkey = ed448_rust::PrivateKey::from(seed);
        let pubkey = ed448_rust::PublicKey::from(&privkey);
        let pubkey_bytes = pubkey.as_byte();
        assert_eq!(
            hex::encode(pubkey_bytes), go_pubkey_hex,
            "Ed448 public key must match Go"
        );

        // Step 2: build PeerInfo and encode (same inputs as Go test)
        let info = CanonicalPeerInfo {
            peer_id: vec![0x12, 0x20, 0xAA, 0xBB],
            timestamp: 1700000000000,
            version: vec![2, 1, 0],
            patch_number: vec![23],
            capabilities: vec![CanonicalCapability {
                protocol_identifier: 0x00010001,
                additional_metadata: vec![],
            }],
            ..Default::default()
        };
        let msg_to_sign = encode_canonical_peer_info(&info, pubkey_bytes.as_slice(), &[]);
        assert_eq!(
            hex::encode(&msg_to_sign), go_msg_hex,
            "msg_to_sign must match Go"
        );

        // Step 3: sign with Ed448
        let sig = privkey.sign(&msg_to_sign, None).expect("sign failed");
        assert_eq!(sig.len(), 114);
        assert_eq!(
            hex::encode(&sig), go_sig_hex,
            "Ed448 signature must match Go (deterministic)"
        );

        // Step 4: verify
        assert!(
            pubkey.verify(&msg_to_sign, &sig, None).is_ok(),
            "Rust must verify its own signature"
        );
    }

    #[test]
    fn classify_encoded_peer_info() {
        let info = CanonicalPeerInfo {
            peer_id: vec![0x01; 10],
            ..Default::default()
        };
        let encoded = encode_canonical_peer_info(&info, &[], &[]);
        match classify_peer_info_message(&encoded).unwrap() {
            PeerInfoMessage::PeerInfo(decoded) => {
                assert_eq!(decoded.peer_id, vec![0x01; 10]);
            }
            other => panic!("expected PeerInfo, got {:?}", other),
        }
    }
}
