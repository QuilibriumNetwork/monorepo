//! Consensus wire format — canonical bytes serialization matching Go's
//! protobuf types on GLOBAL_CONSENSUS and GLOBAL_FRAME bitmasks.
//!
//! Type prefixes from `protobufs/canonical_types.go`:
//!   0x030C = ProposalVote
//!   0x030D = QuorumCertificate
//!   0x030E = GlobalFrame (header + requests)
//!   0x0317 = GlobalProposal
//!   0x031C = TimeoutState
//!   0x031D = TimeoutCertificate

use std::sync::Arc;

use quil_types::error::{QuilError, Result};

// Type prefixes matching Go's canonical_types.go
pub const PROPOSAL_VOTE_TYPE: u32 = 0x030C;
pub const QUORUM_CERTIFICATE_TYPE: u32 = 0x030D;
pub const GLOBAL_FRAME_TYPE: u32 = 0x030E;
pub const GLOBAL_PROPOSAL_TYPE: u32 = 0x0317;
pub const TIMEOUT_STATE_TYPE: u32 = 0x031C;
pub const TIMEOUT_CERTIFICATE_TYPE: u32 = 0x031D;

fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > data.len() { return Err(QuilError::InvalidArgument("short read u32".into())); }
    let v = u32::from_be_bytes(data[*cursor..*cursor+4].try_into().unwrap());
    *cursor += 4;
    Ok(v)
}
fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64> {
    if *cursor + 8 > data.len() { return Err(QuilError::InvalidArgument("short read u64".into())); }
    let v = u64::from_be_bytes(data[*cursor..*cursor+8].try_into().unwrap());
    *cursor += 8;
    Ok(v)
}
fn read_i64(data: &[u8], cursor: &mut usize) -> Result<i64> {
    Ok(read_u64(data, cursor)? as i64)
}
fn read_bytes(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let len = read_u32(data, cursor)? as usize;
    if *cursor + len > data.len() {
        return Err(QuilError::InvalidArgument(format!(
            "short read bytes: need {} at offset {}, have {}",
            len, *cursor, data.len()
        )));
    }
    let v = data[*cursor..*cursor+len].to_vec();
    *cursor += len;
    Ok(v)
}

// =====================================================================
// BLS48581AggregateSignature (nested in QC/TC)
// =====================================================================

/// BLS48-581 aggregate signature with public key and bitmask.
#[derive(Debug, Clone, Default)]
pub struct AggregateSignature {
    pub public_key: Vec<u8>,  // 585 bytes
    pub signature: Vec<u8>,   // 74 bytes
    pub bitmask: Vec<u8>,     // 32 bytes
}

impl AggregateSignature {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Go writes: type_prefix, signature(LP), public_key(LP), bitmask(LP)
        put_u32(&mut out, 0x011C); // BLS48581AggregateSignatureType
        // Signature
        put_bytes(&mut out, &self.signature);
        // BLS48581G2PublicKey: [type=0x0117][key]
        let mut pk = Vec::new();
        put_u32(&mut pk, 0x0117);
        pk.extend_from_slice(&self.public_key);
        put_bytes(&mut out, &pk);
        // Bitmask
        put_bytes(&mut out, &self.bitmask);
        out
    }

    pub fn from_canonical_bytes(data: &[u8], cursor: &mut usize) -> Result<Self> {
        // Go writes: type_prefix(u32), signature(LP), public_key(LP), bitmask(LP)
        let _type_prefix = read_u32(data, cursor)?; // BLS48581AggregateSignatureType
        let signature = read_bytes(data, cursor)?;
        let pk_bytes = read_bytes(data, cursor)?;
        // pk_bytes contains the canonical encoding of BLS48581G2PublicKey
        // which has its own type prefix (4 bytes) + key_value
        let public_key = if pk_bytes.len() > 4 {
            pk_bytes[4..].to_vec() // skip BLS48581G2PublicKeyType prefix
        } else {
            pk_bytes
        };
        let bitmask = read_bytes(data, cursor)?;
        Ok(Self { public_key, signature, bitmask })
    }

    /// Empty aggregate signature for genesis QC.
    pub fn empty() -> Self {
        Self {
            public_key: vec![0u8; 585],
            signature: vec![0u8; 74],
            bitmask: vec![0xffu8; 32],
        }
    }
}

// =====================================================================
// ProposalVote (0x030C) — sent on GLOBAL_CONSENSUS
// =====================================================================

/// A vote for a proposal. Mirrors `protobufs.ProposalVote`.
#[derive(Debug, Clone)]
pub struct ProposalVote {
    pub filter: Vec<u8>,
    pub rank: u64,
    pub frame_number: u64,
    pub selector: Vec<u8>,    // 32 bytes — frame identity
    pub timestamp: u64,
    pub signature: Vec<u8>,   // BLS48581AddressedSignature bytes
    pub address: Vec<u8>,     // 32 bytes — prover address
}

impl ProposalVote {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, PROPOSAL_VOTE_TYPE);
        put_bytes(&mut out, &self.filter);
        put_u64(&mut out, self.rank);
        put_u64(&mut out, self.frame_number);
        put_bytes(&mut out, &self.selector);
        put_u64(&mut out, self.timestamp);
        // Go writes u32(0) for nil PublicKeySignatureBls48581 (see
        // protobufs/global.go:ProposalVote.ToCanonicalBytes line ~3795).
        // We treat an empty signature + empty address as "absent"
        // to preserve byte-identical round-tripping.
        if self.signature.is_empty() && self.address.is_empty() {
            put_u32(&mut out, 0);
        } else {
            // BLS48581AddressedSignature: [type=0x011B][len sig][sig][len addr][addr]
            let mut sig = Vec::new();
            put_u32(&mut sig, 0x011B);
            put_bytes(&mut sig, &self.signature);
            put_bytes(&mut sig, &self.address);
            put_bytes(&mut out, &sig);
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != PROPOSAL_VOTE_TYPE {
            return Err(QuilError::InvalidArgument(format!("bad vote type 0x{:08x}", tp)));
        }
        let filter = read_bytes(data, &mut c)?;
        let rank = read_u64(data, &mut c)?;
        let frame_number = read_u64(data, &mut c)?;
        let selector = read_bytes(data, &mut c)?;
        let timestamp = read_u64(data, &mut c)?;
        let sig_bytes = read_bytes(data, &mut c)?;
        // Absent signature on the wire: u32(0) → empty inner bytes.
        // Matches Go's nil-pointer serialization.
        let (signature, address) = if sig_bytes.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let mut sc = 0usize;
            let _sig_type = read_u32(&sig_bytes, &mut sc)?;
            let signature = read_bytes(&sig_bytes, &mut sc)?;
            let address = read_bytes(&sig_bytes, &mut sc)?;
            (signature, address)
        };
        Ok(Self { filter, rank, frame_number, selector, timestamp, signature, address })
    }
}

// =====================================================================
// QuorumCertificate (0x030D) — nested in proposals/timeouts
// =====================================================================

/// Quorum certificate. Mirrors `protobufs.QuorumCertificate`.
#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    pub filter: Vec<u8>,
    pub rank: u64,
    pub frame_number: u64,
    pub selector: Vec<u8>,    // 32 bytes
    pub timestamp: u64,
    pub aggregate_signature: AggregateSignature,
}

impl QuorumCertificate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, QUORUM_CERTIFICATE_TYPE);
        put_bytes(&mut out, &self.filter);
        put_u64(&mut out, self.rank);
        put_u64(&mut out, self.frame_number);
        put_bytes(&mut out, &self.selector);
        put_u64(&mut out, self.timestamp);
        let agg = self.aggregate_signature.to_canonical_bytes();
        put_bytes(&mut out, &agg);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != QUORUM_CERTIFICATE_TYPE {
            return Err(QuilError::InvalidArgument(format!("bad QC type 0x{:08x}", tp)));
        }
        let filter = read_bytes(data, &mut c)?;
        let rank = read_u64(data, &mut c)?;
        let frame_number = read_u64(data, &mut c)?;
        let selector = read_bytes(data, &mut c)?;
        let timestamp = read_u64(data, &mut c)?;
        let agg_bytes = read_bytes(data, &mut c)?;
        let mut ac = 0usize;
        let aggregate_signature = AggregateSignature::from_canonical_bytes(&agg_bytes, &mut ac)?;
        Ok(Self { filter, rank, frame_number, selector, timestamp, aggregate_signature })
    }

    /// Genesis QC for bootstrapping the consensus loop.
    pub fn genesis(frame_number: u64, frame_identity: Vec<u8>) -> Self {
        Self {
            filter: Vec::new(),
            rank: 0,
            frame_number,
            selector: frame_identity,
            timestamp: 0,
            aggregate_signature: AggregateSignature::empty(),
        }
    }
}

// =====================================================================
// TimeoutCertificate (0x031D) — nested in proposals/timeouts
// =====================================================================

/// Timeout certificate. Mirrors `protobufs.TimeoutCertificate`.
#[derive(Debug, Clone)]
pub struct TimeoutCertificate {
    pub filter: Vec<u8>,
    pub rank: u64,
    pub latest_ranks: Vec<u64>,
    pub latest_quorum_certificate: Option<QuorumCertificate>,
    pub timestamp: u64,
    pub aggregate_signature: AggregateSignature,
}

impl TimeoutCertificate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TIMEOUT_CERTIFICATE_TYPE);
        put_bytes(&mut out, &self.filter);
        put_u64(&mut out, self.rank);
        put_u32(&mut out, self.latest_ranks.len() as u32);
        for &r in &self.latest_ranks { put_u64(&mut out, r); }
        match &self.latest_quorum_certificate {
            Some(qc) => {
                let qc_bytes = qc.to_canonical_bytes()?;
                put_bytes(&mut out, &qc_bytes);
            }
            None => put_u32(&mut out, 0),
        }
        put_u64(&mut out, self.timestamp);
        let agg = self.aggregate_signature.to_canonical_bytes();
        put_bytes(&mut out, &agg);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != TIMEOUT_CERTIFICATE_TYPE {
            return Err(QuilError::InvalidArgument(format!("bad TC type 0x{:08x}", tp)));
        }
        let filter = read_bytes(data, &mut c)?;
        let rank = read_u64(data, &mut c)?;
        let count = read_u32(data, &mut c)? as usize;
        let mut latest_ranks = Vec::with_capacity(count);
        for _ in 0..count { latest_ranks.push(read_u64(data, &mut c)?); }
        let qc_bytes = read_bytes(data, &mut c)?;
        let latest_quorum_certificate = if qc_bytes.is_empty() {
            None
        } else {
            Some(QuorumCertificate::from_canonical_bytes(&qc_bytes)?)
        };
        let timestamp = read_u64(data, &mut c)?;
        let agg_bytes = read_bytes(data, &mut c)?;
        let mut ac = 0usize;
        let aggregate_signature = AggregateSignature::from_canonical_bytes(&agg_bytes, &mut ac)?;
        Ok(Self { filter, rank, latest_ranks, latest_quorum_certificate, timestamp, aggregate_signature })
    }
}

// =====================================================================
// Trait bridge — wire types → quil_consensus trait objects
// =====================================================================

/// Bridge aggregate signature for wire types.
#[derive(Debug)]
struct WireAggregateSignature {
    public_key: Vec<u8>,
    signature: Vec<u8>,
    bitmask: Vec<u8>,
}

impl quil_consensus::models::AggregatedSignature for WireAggregateSignature {
    fn signature(&self) -> &[u8] { &self.signature }
    fn public_key(&self) -> &[u8] { &self.public_key }
    fn bitmask(&self) -> &[u8] { &self.bitmask }
}

impl QuorumCertificate {
    /// Convert this wire QC into a `dyn quil_consensus::models::QuorumCertificate`
    /// trait object suitable for submission to the event loop handle.
    pub fn into_trait_object(self) -> Arc<dyn quil_consensus::models::QuorumCertificate> {
        Arc::new(WireQcAdapter {
            filter: self.filter,
            rank: self.rank,
            frame_number: self.frame_number,
            identity: hex::encode(&self.selector),
            timestamp: self.timestamp,
            agg_sig: Arc::new(WireAggregateSignature {
                public_key: self.aggregate_signature.public_key,
                signature: self.aggregate_signature.signature,
                bitmask: self.aggregate_signature.bitmask,
            }),
        })
    }
}

impl TimeoutCertificate {
    /// Convert this wire TC into a `dyn quil_consensus::models::TimeoutCertificate`
    /// trait object suitable for submission to the event loop handle.
    pub fn into_trait_object(self) -> Arc<dyn quil_consensus::models::TimeoutCertificate> {
        let latest_qc: Arc<dyn quil_consensus::models::QuorumCertificate> =
            match self.latest_quorum_certificate {
                Some(qc) => qc.into_trait_object(),
                None => QuorumCertificate::genesis(0, Vec::new()).into_trait_object(),
            };
        Arc::new(WireTcAdapter {
            filter: self.filter,
            rank: self.rank,
            latest_ranks: self.latest_ranks,
            latest_qc,
            agg_sig: Arc::new(WireAggregateSignature {
                public_key: self.aggregate_signature.public_key,
                signature: self.aggregate_signature.signature,
                bitmask: self.aggregate_signature.bitmask,
            }),
        })
    }
}

#[derive(Debug)]
struct WireQcAdapter {
    filter: Vec<u8>,
    rank: u64,
    frame_number: u64,
    identity: quil_consensus::models::Identity,
    timestamp: u64,
    agg_sig: Arc<dyn quil_consensus::models::AggregatedSignature>,
}

impl quil_consensus::models::QuorumCertificate for WireQcAdapter {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn frame_number(&self) -> u64 { self.frame_number }
    fn identity(&self) -> &quil_consensus::models::Identity { &self.identity }
    fn timestamp(&self) -> u64 { self.timestamp }
    fn aggregated_signature(&self) -> &dyn quil_consensus::models::AggregatedSignature {
        self.agg_sig.as_ref()
    }
    fn equals(&self, other: &dyn quil_consensus::models::QuorumCertificate) -> bool {
        self.rank == other.rank() && self.identity == *other.identity()
    }
}

#[derive(Debug)]
struct WireTcAdapter {
    filter: Vec<u8>,
    rank: u64,
    latest_ranks: Vec<u64>,
    latest_qc: Arc<dyn quil_consensus::models::QuorumCertificate>,
    agg_sig: Arc<dyn quil_consensus::models::AggregatedSignature>,
}

impl quil_consensus::models::TimeoutCertificate for WireTcAdapter {
    fn filter(&self) -> &[u8] { &self.filter }
    fn rank(&self) -> u64 { self.rank }
    fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
    fn latest_quorum_cert(&self) -> &dyn quil_consensus::models::QuorumCertificate {
        self.latest_qc.as_ref()
    }
    fn aggregated_signature(&self) -> &dyn quil_consensus::models::AggregatedSignature {
        self.agg_sig.as_ref()
    }
    fn equals(&self, other: &dyn quil_consensus::models::TimeoutCertificate) -> bool {
        self.rank == other.rank()
    }
}

// =====================================================================
// GlobalProposal (0x0317) — sent on GLOBAL_CONSENSUS
// =====================================================================

/// A global frame proposal. Mirrors `protobufs.GlobalProposal`.
#[derive(Debug, Clone)]
pub struct GlobalProposal {
    /// The proposed frame (serialized GlobalFrame canonical bytes).
    pub state: Vec<u8>,
    pub parent_quorum_certificate: QuorumCertificate,
    pub prior_rank_timeout_certificate: Option<TimeoutCertificate>,
    pub vote: ProposalVote,
}

impl GlobalProposal {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, GLOBAL_PROPOSAL_TYPE);
        put_bytes(&mut out, &self.state);
        let qc = self.parent_quorum_certificate.to_canonical_bytes()?;
        put_bytes(&mut out, &qc);
        match &self.prior_rank_timeout_certificate {
            Some(tc) => {
                let tc_bytes = tc.to_canonical_bytes()?;
                put_bytes(&mut out, &tc_bytes);
            }
            None => put_u32(&mut out, 0),
        }
        let vote = self.vote.to_canonical_bytes()?;
        put_bytes(&mut out, &vote);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != GLOBAL_PROPOSAL_TYPE {
            return Err(QuilError::InvalidArgument(format!("bad proposal type 0x{:08x}", tp)));
        }
        let state = read_bytes(data, &mut c)?;
        let qc_bytes = read_bytes(data, &mut c)?;
        let parent_quorum_certificate = QuorumCertificate::from_canonical_bytes(&qc_bytes)?;
        let tc_bytes = read_bytes(data, &mut c)?;
        let prior_rank_timeout_certificate = if tc_bytes.is_empty() {
            None
        } else {
            Some(TimeoutCertificate::from_canonical_bytes(&tc_bytes)?)
        };
        let vote_bytes = read_bytes(data, &mut c)?;
        let vote = ProposalVote::from_canonical_bytes(&vote_bytes)?;
        Ok(Self { state, parent_quorum_certificate, prior_rank_timeout_certificate, vote })
    }
}

// =====================================================================
// TimeoutState (0x031C) — sent on GLOBAL_CONSENSUS
// =====================================================================

/// Timeout vote state. Mirrors `protobufs.TimeoutState`.
#[derive(Debug, Clone)]
pub struct TimeoutState {
    pub latest_quorum_certificate: QuorumCertificate,
    pub prior_rank_timeout_certificate: Option<TimeoutCertificate>,
    pub vote: ProposalVote,
    pub timeout_tick: u64,
    pub timestamp: u64,
}

impl TimeoutState {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TIMEOUT_STATE_TYPE);
        let qc = self.latest_quorum_certificate.to_canonical_bytes()?;
        put_bytes(&mut out, &qc);
        match &self.prior_rank_timeout_certificate {
            Some(tc) => {
                let tc_bytes = tc.to_canonical_bytes()?;
                put_bytes(&mut out, &tc_bytes);
            }
            None => put_u32(&mut out, 0),
        }
        let vote = self.vote.to_canonical_bytes()?;
        put_bytes(&mut out, &vote);
        put_u64(&mut out, self.timeout_tick);
        put_u64(&mut out, self.timestamp);
        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;
        let tp = read_u32(data, &mut c)?;
        if tp != TIMEOUT_STATE_TYPE {
            return Err(QuilError::InvalidArgument(format!("bad timeout type 0x{:08x}", tp)));
        }
        let qc_bytes = read_bytes(data, &mut c)?;
        let latest_quorum_certificate = QuorumCertificate::from_canonical_bytes(&qc_bytes)?;
        let tc_bytes = read_bytes(data, &mut c)?;
        let prior_rank_timeout_certificate = if tc_bytes.is_empty() {
            None
        } else {
            Some(TimeoutCertificate::from_canonical_bytes(&tc_bytes)?)
        };
        let vote_bytes = read_bytes(data, &mut c)?;
        let vote = ProposalVote::from_canonical_bytes(&vote_bytes)?;
        let timeout_tick = read_u64(data, &mut c)?;
        let timestamp = read_u64(data, &mut c)?;
        Ok(Self { latest_quorum_certificate, prior_rank_timeout_certificate, vote, timeout_tick, timestamp })
    }
}

// =====================================================================
// GlobalFrame canonical bytes decode (0x030E)
// =====================================================================

/// Decode a GlobalFrame from canonical bytes into the prost protobuf type.
///
/// Wire format:
/// [u32 type=0x030E][u32 header_len][header_bytes][u32 requests_count]
///   [for each: u32 request_len, request_bytes (MessageBundle canonical)]
///
/// Header format (0x0309):
/// [u32 type=0x0309][u64 frame_number][u64 rank][i64 timestamp][u32 difficulty]
/// [u32 output_len][output][u32 parent_selector_len][parent_selector]
/// [u32 commitments_count][for each: u32 len, commitment]
/// [u32 prover_tree_commitment_len][prover_tree_commitment]
/// [u32 requests_root_len][requests_root]
/// [u32 prover_len][prover]
/// [u32 signature_len][signature]
pub fn decode_global_frame(
    data: &[u8],
) -> Result<quil_types::proto::global::GlobalFrame> {
    let mut c = 0usize;
    let tp = read_u32(data, &mut c)?;
    if tp != GLOBAL_FRAME_TYPE {
        return Err(QuilError::InvalidArgument(format!(
            "GlobalFrame: bad type prefix 0x{:08x}", tp
        )));
    }

    // Header
    let header_bytes = read_bytes(data, &mut c)?;
    let header = decode_frame_header(&header_bytes)?;

    // Requests are MessageBundle canonical bytes. Skip them for header-only
    // decode — the execution pipeline processes requests separately via
    // frame_processor::process_global_frame which reads from the stored frame.
    // We include request count for validation but leave the proto requests empty
    // since converting canonical bytes → proto MessageBundle is complex.
    let _req_count = read_u32(data, &mut c)?;

    Ok(quil_types::proto::global::GlobalFrame {
        header: Some(header),
        requests: Vec::new(), // populated separately by execution pipeline
    })
}

const GLOBAL_FRAME_HEADER_TYPE: u32 = 0x0309;

fn decode_frame_header(
    data: &[u8],
) -> Result<quil_types::proto::global::GlobalFrameHeader> {
    let mut c = 0usize;
    let total = data.len();
    let tp = read_u32(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("header type_prefix at 0/{}: {}", total, e)))?;
    if tp != GLOBAL_FRAME_HEADER_TYPE {
        return Err(QuilError::InvalidArgument(format!(
            "GlobalFrameHeader: bad type prefix 0x{:08x}", tp
        )));
    }

    let frame_number = read_u64(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("frame_number at {}/{}: {}", c, total, e)))?;
    let rank = read_u64(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("rank at {}/{}: {}", c, total, e)))?;
    let timestamp = read_i64(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("timestamp at {}/{}: {}", c, total, e)))?;
    let difficulty = read_u32(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("difficulty at {}/{}: {}", c, total, e)))?;
    let output = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("output at {}/{}: {}", c, total, e)))?;
    let parent_selector = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("parent_selector at {}/{}: {}", c, total, e)))?;

    let commit_count = read_u32(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("commit_count at {}/{}: {}", c, total, e)))? as usize;
    let mut global_commitments = Vec::with_capacity(commit_count);
    for i in 0..commit_count {
        global_commitments.push(read_bytes(data, &mut c)
            .map_err(|e| QuilError::InvalidArgument(format!("commitment[{}] at {}/{}: {}", i, c, total, e)))?);
    }

    let prover_tree_commitment = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("prover_tree_commit at {}/{}: {}", c, total, e)))?;
    let requests_root = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("requests_root at {}/{}: {}", c, total, e)))?;
    let prover = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("prover at {}/{}: {}", c, total, e)))?;

    // Signature (BLS48581AggregateSignature — variable length)
    let sig_bytes = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("signature at {}/{}: {}", c, total, e)))?;
    let public_key_signature_bls48581 = if sig_bytes.is_empty() {
        None
    } else {
        let mut sc = 0usize;
        let agg = AggregateSignature::from_canonical_bytes(&sig_bytes, &mut sc)?;
        Some(quil_types::proto::keys::Bls48581AggregateSignature {
            signature: agg.signature,
            public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                key_value: agg.public_key,
            }),
            bitmask: agg.bitmask,
        })
    };

    Ok(quil_types::proto::global::GlobalFrameHeader {
        frame_number,
        rank,
        timestamp,
        difficulty,
        output,
        parent_selector,
        global_commitments,
        prover_tree_commitment,
        requests_root,
        prover,
        public_key_signature_bls48581,
    })
}

// =====================================================================
// Inbound message type detection
// =====================================================================

/// Peek at the type prefix of a GLOBAL_CONSENSUS message.
pub fn peek_consensus_type(data: &[u8]) -> Option<u32> {
    if data.len() < 4 { return None; }
    Some(u32::from_be_bytes(data[..4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_vote_roundtrip() {
        let vote = ProposalVote {
            filter: vec![0xFF; 32],
            rank: 42,
            frame_number: 1000,
            selector: vec![0xAA; 32],
            timestamp: 1700000000,
            signature: vec![0xBB; 74],
            address: vec![0xCC; 32],
        };
        let bytes = vote.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &PROPOSAL_VOTE_TYPE.to_be_bytes());
        let decoded = ProposalVote::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.rank, 42);
        assert_eq!(decoded.frame_number, 1000);
        assert_eq!(decoded.filter, vec![0xFF; 32]);
    }

    #[test]
    fn quorum_certificate_roundtrip() {
        let qc = QuorumCertificate {
            filter: vec![],
            rank: 5,
            frame_number: 500,
            selector: vec![0xDD; 32],
            timestamp: 1234,
            aggregate_signature: AggregateSignature::empty(),
        };
        let bytes = qc.to_canonical_bytes().unwrap();
        let decoded = QuorumCertificate::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.rank, 5);
        assert_eq!(decoded.frame_number, 500);
    }

    #[test]
    fn genesis_qc_has_correct_structure() {
        let qc = QuorumCertificate::genesis(0, vec![0xAA; 32]);
        assert_eq!(qc.rank, 0);
        assert_eq!(qc.frame_number, 0);
        assert_eq!(qc.aggregate_signature.public_key.len(), 585);
        assert_eq!(qc.aggregate_signature.signature.len(), 74);
        assert_eq!(qc.aggregate_signature.bitmask.len(), 32);
        assert!(qc.aggregate_signature.bitmask.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn timeout_state_roundtrip() {
        let ts = TimeoutState {
            latest_quorum_certificate: QuorumCertificate::genesis(0, vec![0; 32]),
            prior_rank_timeout_certificate: None,
            vote: ProposalVote {
                filter: vec![], rank: 1, frame_number: 1,
                selector: vec![0; 32], timestamp: 0,
                signature: vec![0; 74], address: vec![0; 32],
            },
            timeout_tick: 10,
            timestamp: 5000,
        };
        let bytes = ts.to_canonical_bytes().unwrap();
        let decoded = TimeoutState::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.timeout_tick, 10);
        assert_eq!(decoded.timestamp, 5000);
    }

    #[test]
    fn peek_type_prefix() {
        let mut data = Vec::new();
        put_u32(&mut data, GLOBAL_PROPOSAL_TYPE);
        data.extend_from_slice(&[0; 100]);
        assert_eq!(peek_consensus_type(&data), Some(GLOBAL_PROPOSAL_TYPE));
    }
}
