//! Consensus wire format — canonical bytes serialization matching Go's
//! protobuf types on GLOBAL_CONSENSUS and GLOBAL_FRAME bitmasks.
//!
//! Type prefixes from `protobufs/canonical_types.go`:
//! 0x030C = ProposalVote
//! 0x030D = QuorumCertificate
//! 0x030E = GlobalFrame (header + requests)
//! 0x0317 = GlobalProposal
//! 0x031C = TimeoutState
//! 0x031D = TimeoutCertificate

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
            public_key: vec![0u8; 897],
            signature: vec![0u8; 666],
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
    /// PoRep storage openings this voter attaches to its app-shard vote
    /// (a serialized `global::StorageAttestation`). The vote-aggregator
    /// collects these and assembles the frame's `StorageAttestation` +
    /// 74-byte aggregate `storage_attestation_root` when the QC forms.
    /// Empty for global / timeout votes and pre-activation app votes — and
    /// when empty it is NOT written, so the encoding is byte-identical to
    /// the legacy `ProposalVote`. Trailing + tolerant-decoded; safe because
    /// the only embedded use (`TimeoutState.vote`) is length-prefixed.
    pub openings: Vec<u8>,
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
        // PoRep openings — appended ONLY when present, so an empty-openings
        // vote serializes byte-identically to the legacy wire form.
        if !self.openings.is_empty() {
            put_bytes(&mut out, &self.openings);
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
        // Tolerant trailing field: PoRep openings, present only on post-
        // activation app-shard votes. Absent on legacy / global / timeout
        // votes — the cursor is already at the end, so this reads nothing.
        let openings = if c < data.len() {
            read_bytes(data, &mut c)?
        } else {
            Vec::new()
        };
        Ok(Self { filter, rank, frame_number, selector, timestamp, signature, address, openings })
    }

    /// Build a wire `ProposalVote` from the proto representation (as returned by
    /// `GlobalService.GetGlobalProposal`). Inverse of the proto produced by the
    /// engine; lets the catch-up sync client reconstruct a `SignedProposal`.
    pub fn from_proto(v: &quil_types::proto::global::ProposalVote) -> Self {
        let (signature, address) = match v.public_key_signature_bls48581.as_ref() {
            Some(s) => (s.signature.clone(), s.address.clone()),
            None => (Vec::new(), Vec::new()),
        };
        Self {
            filter: v.filter.clone(),
            rank: v.rank,
            frame_number: v.frame_number,
            selector: v.selector.clone(),
            timestamp: v.timestamp,
            signature,
            address,
            // The proto ProposalVote has no openings field; reconstructed
            // votes (catch-up sync) carry none.
            openings: Vec::new(),
        }
    }

    /// Convert to the proto representation for persistence
    /// (`ClockStore::put_proposal_vote`), so it can later be served by
    /// `GetGlobalProposal`. Inverse of [`Self::from_proto`].
    pub fn to_proto(&self) -> quil_types::proto::global::ProposalVote {
        let public_key_signature_bls48581 =
            if self.signature.is_empty() && self.address.is_empty() {
                None
            } else {
                Some(quil_types::proto::keys::Bls48581AddressedSignature {
                    signature: self.signature.clone(),
                    address: self.address.clone(),
                })
            };
        quil_types::proto::global::ProposalVote {
            filter: self.filter.clone(),
            rank: self.rank,
            frame_number: self.frame_number,
            selector: self.selector.clone(),
            timestamp: self.timestamp,
            public_key_signature_bls48581,
        }
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

    /// Build a wire `QuorumCertificate` from the proto representation
    /// stored in the clock store (the form produced by
    /// `RocksClockStore::get_quorum_certificate`). Used by the
    /// activation path to feed a real BLS-aggregated QC into the
    /// pacemaker on restart so the loop boots with a verifiable
    /// previous-round QC rather than a zero-signature stub.
    pub fn from_proto(qc: &quil_types::proto::global::QuorumCertificate) -> Self {
        let (public_key, signature, bitmask) = match qc.aggregate_signature.as_ref() {
            Some(agg) => (
                agg.public_key.as_ref().map(|pk| pk.key_value.clone()).unwrap_or_default(),
                agg.signature.clone(),
                agg.bitmask.clone(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        Self {
            filter: qc.filter.clone(),
            rank: qc.rank,
            frame_number: qc.frame_number,
            selector: qc.selector.clone(),
            timestamp: qc.timestamp,
            aggregate_signature: AggregateSignature {
                public_key,
                signature,
                bitmask,
            },
        }
    }

    /// Build a wire `QuorumCertificate` from a `dyn quil_consensus::models::
    /// QuorumCertificate` trait object. Used by producer paths that need to
    /// embed a previously-aggregated QC (e.g. the latest QC inside a
    /// `TimeoutState`) into wire bytes.
    pub fn from_trait_object(qc: &dyn quil_consensus::models::QuorumCertificate) -> Self {
        let agg = qc.aggregated_signature();
        Self {
            filter: qc.filter().to_vec(),
            rank: qc.rank(),
            frame_number: qc.frame_number(),
            selector: qc.identity().clone(),
            timestamp: qc.timestamp(),
            aggregate_signature: AggregateSignature {
                public_key: agg.public_key().to_vec(),
                signature: agg.signature().to_vec(),
                bitmask: agg.bitmask().to_vec(),
            },
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
    /// Build a wire `TimeoutCertificate` from the proto representation (as
    /// returned by `GlobalService.GetGlobalProposal` in a proposal's
    /// `prior_rank_timeout_certificate`). Lets the catch-up sync client
    /// reconstruct a `SignedProposal`.
    pub fn from_proto(tc: &quil_types::proto::global::TimeoutCertificate) -> Self {
        let (public_key, signature, bitmask) = match tc.aggregate_signature.as_ref() {
            Some(agg) => (
                agg.public_key.as_ref().map(|pk| pk.key_value.clone()).unwrap_or_default(),
                agg.signature.clone(),
                agg.bitmask.clone(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        Self {
            filter: tc.filter.clone(),
            rank: tc.rank,
            latest_ranks: tc.latest_ranks.clone(),
            latest_quorum_certificate: tc
                .latest_quorum_certificate
                .as_ref()
                .map(QuorumCertificate::from_proto),
            timestamp: tc.timestamp,
            aggregate_signature: AggregateSignature {
                public_key,
                signature,
                bitmask,
            },
        }
    }

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
        // Allocation-bomb guard: each entry is a u64 (8 bytes), so a count above
        // `remaining / 8` is impossible — reject before `Vec::with_capacity`.
        if count > data.len().saturating_sub(c) / 8 {
            return Err(QuilError::InvalidArgument(format!(
                "TimeoutCertificate: latest_ranks count {} exceeds remaining bytes", count
            )));
        }
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

    /// Build a wire `TimeoutCertificate` from a `dyn quil_consensus::models::
    /// TimeoutCertificate` trait object. The embedded QC is converted via
    /// [`QuorumCertificate::from_trait_object`].
    pub fn from_trait_object(tc: &dyn quil_consensus::models::TimeoutCertificate) -> Self {
        let agg = tc.aggregated_signature();
        let latest_quorum_certificate =
            Some(QuorumCertificate::from_trait_object(tc.latest_quorum_cert()));
        Self {
            filter: tc.filter().to_vec(),
            rank: tc.rank(),
            latest_ranks: tc.latest_ranks().to_vec(),
            latest_quorum_certificate,
            // Go's TC embeds no separate timestamp on the trait surface;
            // wire field defaults to 0 (matches Go behavior — the per-replica
            // timestamps live inside the embedded QC and signers).
            timestamp: 0,
            aggregate_signature: AggregateSignature {
                public_key: agg.public_key().to_vec(),
                signature: agg.signature().to_vec(),
                bitmask: agg.bitmask().to_vec(),
            },
        }
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
            identity: self.selector.clone(),
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
/// [for each: u32 request_len, request_bytes (MessageBundle canonical)]
///
/// Header format (0x0309):
/// [u32 type=0x0309][u64 frame_number][u64 rank][i64 timestamp][u32 difficulty]
/// [u32 output_len][output][u32 parent_selector_len][parent_selector]
/// [u32 commitments_count][for each: u32 len, commitment]
/// [u32 prover_tree_commitment_len][prover_tree_commitment]
/// [u32 requests_root_len][requests_root]
/// [u32 prover_len][prover]
/// [u32 signature_len][signature]
/// Encode a `GlobalFrame` proto into Quilibrium canonical bytes.
/// Mirror of `decode_global_frame` — the wire format is documented
/// in the doc-comment of `decode_global_frame`. Used by
/// `GlobalConsumer::on_own_proposal` to produce the proposal's
/// embedded frame bytes that go into `GlobalProposal.state`.
pub fn encode_global_frame(
    frame: &quil_types::proto::global::GlobalFrame,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_u32(&mut out, GLOBAL_FRAME_TYPE);
    let header = frame
        .header
        .as_ref()
        .ok_or_else(|| QuilError::InvalidArgument("GlobalFrame: missing header".into()))?;
    let header_bytes = encode_frame_header(header)?;
    put_bytes(&mut out, &header_bytes);
    // For now we publish a frame with no inline requests — the
    // bundle list grows in `make_state_proposal` once the message
    // collector → leader provider hand-off is fully wired. Receivers
    // tolerate `req_count = 0`.
    put_u32(&mut out, frame.requests.len() as u32);
    for bundle in &frame.requests {
        let bundle_bytes = proto_message_bundle_to_canonical_bytes(bundle)?;
        put_bytes(&mut out, &bundle_bytes);
    }
    Ok(out)
}

/// Encode a `GlobalFrameHeader` proto into Quilibrium canonical bytes
/// (type prefix `0x0309`). Mirror of `decode_frame_header`.
fn encode_frame_header(
    header: &quil_types::proto::global::GlobalFrameHeader,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_u32(&mut out, GLOBAL_FRAME_HEADER_TYPE);
    put_u64(&mut out, header.frame_number);
    put_u64(&mut out, header.rank);
    out.extend_from_slice(&header.timestamp.to_be_bytes());
    put_u32(&mut out, header.difficulty);
    put_bytes(&mut out, &header.output);
    put_bytes(&mut out, &header.parent_selector);
    put_u32(&mut out, header.global_commitments.len() as u32);
    for c in &header.global_commitments {
        put_bytes(&mut out, c);
    }
    put_bytes(&mut out, &header.prover_tree_commitment);
    put_bytes(&mut out, &header.requests_root);
    // Prover shard phase 1/2/3 roots (audit #5). Count-prefixed like
    // global_commitments; decode mirrors this position.
    put_u32(&mut out, header.prover_tree_aux_roots.len() as u32);
    for r in &header.prover_tree_aux_roots {
        put_bytes(&mut out, r);
    }
    put_bytes(&mut out, &header.prover);
    let sig_bytes: Vec<u8> = match header.public_key_signature_bls48581.as_ref() {
        None => Vec::new(),
        Some(sig) => {
            let agg = AggregateSignature {
                signature: sig.signature.clone(),
                public_key: sig
                    .public_key
                    .as_ref()
                    .map(|p| p.key_value.clone())
                    .unwrap_or_default(),
                bitmask: sig.bitmask.clone(),
            };
            agg.to_canonical_bytes()
        }
    };
    put_bytes(&mut out, &sig_bytes);
    Ok(out)
}

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

    // Requests: each entry is a length-prefixed MessageBundle in canonical
    // bytes form (see Go: protobufs/global.go GlobalFrame.FromCanonicalBytes).
    let req_count = read_u32(data, &mut c)? as usize;
    // No fixed per-frame request cap: a global frame carries every pending
    // request (a coverage proof from every shard), delivered over the
    // direct :8340 transport which has no gossip size ceiling. Guard only
    // against an allocation bomb — each request is length-prefixed (>= 4
    // bytes), so a valid count can't exceed the remaining bytes / 4. The
    // read loop below still validates each entry against the actual data.
    let remaining = data.len().saturating_sub(c);
    if req_count > remaining / 4 {
        return Err(QuilError::InvalidArgument(format!(
            "GlobalFrame: requests count {} exceeds what {} remaining bytes can hold",
            req_count, remaining
        )));
    }
    let mut requests = Vec::with_capacity(req_count);
    for _ in 0..req_count {
        let bundle_bytes = read_bytes(data, &mut c)?;
        let bundle = decode_message_bundle(&bundle_bytes)?;
        requests.push(bundle);
    }

    Ok(quil_types::proto::global::GlobalFrame {
        header: Some(header),
        requests,
    })
}

/// Decode canonical-bytes MessageBundle into the prost proto type.
///
/// Inner request payloads are routed by their type discriminator and
/// converted to proto via existing canonical→proto converters in
/// `quil_execution::global_intrinsic`. Variants without converters
/// (token, hypergraph, compute, frame_header, kick, seniority_merge,
/// alt_shard_update, shard_split, shard_merge) are preserved as
/// length-correct `MessageRequest::default()` entries so downstream
/// consumers see the right bundle structure even when the inner oneof
/// cannot yet be reconstructed. The bundle `timestamp` is always
/// populated.
pub fn decode_message_bundle(
    data: &[u8],
) -> Result<quil_types::proto::global::MessageBundle> {
    use quil_execution::message_envelope::CanonicalMessageBundle;
    use quil_types::proto::global as pb;

    let canonical = CanonicalMessageBundle::from_canonical_bytes(data)?;
    let mut requests = Vec::with_capacity(canonical.requests.len());
    for entry in &canonical.requests {
        match entry {
            None => requests.push(pb::MessageRequest::default()),
            Some(req) => requests.push(canonical_request_to_proto(req)),
        }
    }
    Ok(pb::MessageBundle {
        requests,
        timestamp: canonical.timestamp,
    })
}

/// Route a CanonicalMessageRequest's inner bytes to the appropriate
/// proto variant via inner_type_prefix. Returns a default (`request:
/// None`) `MessageRequest` for variants whose canonical→proto
/// converters are not yet ported.
fn canonical_request_to_proto(
    req: &quil_execution::message_envelope::CanonicalMessageRequest,
) -> quil_types::proto::global::MessageRequest {
    use quil_execution::global_intrinsic::{conversions, prover_filter_ops, prover_join, prover_ops};
    use quil_execution::global_intrinsic::consensus_types::{AltShardUpdate, TYPE_ALT_SHARD_UPDATE};
    use quil_execution::hypergraph_intrinsic::canonical::{
        TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE, TYPE_HYPERGRAPH_DEPLOYMENT,
        TYPE_HYPERGRAPH_UPDATE, TYPE_VERTEX_ADD, TYPE_VERTEX_REMOVE,
    };
    use quil_execution::hypergraph_intrinsic::types as hg_types;
    use quil_execution::token_intrinsic::{
        conversions as token_conv, MintTransaction, PendingTransaction, TokenDeploy, TokenUpdate,
        Transaction, TYPE_MINT_TRANSACTION, TYPE_PENDING_TRANSACTION, TYPE_TOKEN_DEPLOY,
        TYPE_TOKEN_UPDATE, TYPE_TRANSACTION,
    };
    use quil_execution::compute_intrinsic::conversions as compute_conv;
    use quil_execution::compute_intrinsic::config::{
        ComputeDeploy, ComputeUpdate, TYPE_COMPUTE_DEPLOY, TYPE_COMPUTE_UPDATE,
    };
    use quil_execution::compute_intrinsic::ops::{
        CodeDeployment, CodeExecute, CodeFinalize, TYPE_CODE_DEPLOYMENT, TYPE_CODE_EXECUTE,
        TYPE_CODE_FINALIZE,
    };
    use quil_types::proto::global::{message_request::Request, MessageRequest};

    let inner = &req.inner_bytes;
    let request: Option<Request> = match req.inner_type_prefix {
        prover_join::TYPE_PROVER_JOIN => prover_join::ProverJoin::from_canonical_bytes(inner)
            .ok()
            .map(|j| Request::Join(conversions::prover_join_to_proto(&j))),
        prover_filter_ops::TYPE_PROVER_LEAVE => prover_filter_ops::ProverLeave::from_canonical_bytes(inner)
            .ok()
            .map(|l| Request::Leave(conversions::prover_leave_to_proto(&l))),
        prover_filter_ops::TYPE_PROVER_PAUSE => prover_filter_ops::ProverPause::from_canonical_bytes(inner)
            .ok()
            .map(|p| Request::Pause(conversions::prover_pause_to_proto(&p))),
        prover_filter_ops::TYPE_PROVER_RESUME => prover_filter_ops::ProverResume::from_canonical_bytes(inner)
            .ok()
            .map(|r| Request::Resume(conversions::prover_resume_to_proto(&r))),
        prover_ops::TYPE_PROVER_CONFIRM => prover_ops::ProverConfirm::from_canonical_bytes(inner)
            .ok()
            .map(|c| Request::Confirm(conversions::prover_confirm_to_proto(&c))),
        prover_ops::TYPE_PROVER_REJECT => prover_ops::ProverReject::from_canonical_bytes(inner)
            .ok()
            .map(|r| Request::Reject(conversions::prover_reject_to_proto(&r))),
        prover_ops::TYPE_PROVER_UPDATE => prover_ops::ProverUpdate::from_canonical_bytes(inner)
            .ok()
            .map(|u| Request::Update(conversions::prover_update_to_proto(&u))),
        // Global lifecycle ops (kick / shard split / shard merge). Previously
        // `_ => None` dropped these: a global frame carrying one showed an empty
        // request in the explorer AND was skipped by the materializer (the
        // re-encode below produced nothing), diverging the prover-registry /
        // shard-lifecycle state consensus depends on.
        prover_ops::TYPE_PROVER_KICK => prover_ops::ProverKick::from_canonical_bytes(inner)
            .ok()
            .map(|k| Request::Kick(conversions::prover_kick_to_proto(&k))),
        prover_ops::TYPE_SHARD_SPLIT => prover_ops::ShardSplit::from_canonical_bytes(inner)
            .ok()
            .map(|s| Request::ShardSplit(conversions::shard_split_to_proto(&s))),
        prover_ops::TYPE_SHARD_MERGE => prover_ops::ShardMerge::from_canonical_bytes(inner)
            .ok()
            .map(|s| Request::ShardMerge(conversions::shard_merge_to_proto(&s))),
        prover_ops::TYPE_PROVER_SENIORITY_MERGE => {
            prover_ops::ProverSeniorityMerge::from_canonical_bytes(inner)
                .ok()
                .map(|s| Request::SeniorityMerge(conversions::prover_seniority_merge_to_proto(&s)))
        }
        quil_execution::global_intrinsic::TYPE_FRAME_HEADER => {
            quil_execution::global_intrinsic::FrameHeader::from_canonical_bytes(inner)
                .ok()
                .map(|h| Request::Shard(conversions::frame_header_to_proto(&h)))
        }
        // Hypergraph ops — decode canonical → proto so an app-shard frame's
        // `requests` carry them (and `materialize_app_shard_requests` can then
        // re-encode via `proto_message_request_to_canonical` below). Without
        // this, a VertexAdd/Hyperedge dispatch rides `requests_root` but is
        // dropped from `frame.requests` and never materializes.
        TYPE_HYPERGRAPH_DEPLOYMENT => hg_types::HypergraphDeploy::from_canonical_bytes(inner)
            .ok()
            .map(|d| Request::HypergraphDeploy(d.to_proto())),
        TYPE_HYPERGRAPH_UPDATE => hg_types::HypergraphUpdate::from_canonical_bytes(inner)
            .ok()
            .map(|u| Request::HypergraphUpdate(u.to_proto())),
        TYPE_VERTEX_ADD => hg_types::VertexAdd::from_canonical_bytes(inner)
            .ok()
            .map(|v| Request::VertexAdd(v.to_proto())),
        TYPE_VERTEX_REMOVE => hg_types::VertexRemove::from_canonical_bytes(inner)
            .ok()
            .map(|v| Request::VertexRemove(v.to_proto())),
        TYPE_HYPEREDGE_ADD => hg_types::HyperedgeAdd::from_canonical_bytes(inner)
            .ok()
            .map(|h| Request::HyperedgeAdd(h.to_proto())),
        TYPE_HYPEREDGE_REMOVE => hg_types::HyperedgeRemove::from_canonical_bytes(inner)
            .ok()
            .map(|h| Request::HyperedgeRemove(h.to_proto())),
        // Token ops — decode canonical → proto so an app-shard frame's
        // `requests` carry them and `materialize_app_shard_requests` can
        // re-encode via `proto_message_request_to_canonical`. Without this
        // they rode `requests_root` but were dropped from `frame.requests`.
        TYPE_TOKEN_DEPLOY => TokenDeploy::from_canonical_bytes(inner)
            .ok()
            .and_then(|d| token_conv::token_deploy_to_proto(&d).ok())
            .map(Request::TokenDeploy),
        TYPE_TOKEN_UPDATE => TokenUpdate::from_canonical_bytes(inner)
            .ok()
            .and_then(|u| token_conv::token_update_to_proto(&u).ok())
            .map(Request::TokenUpdate),
        TYPE_TRANSACTION => Transaction::from_canonical_bytes(inner)
            .ok()
            .and_then(|t| token_conv::transaction_to_proto(&t).ok())
            .map(Request::Transaction),
        TYPE_PENDING_TRANSACTION => PendingTransaction::from_canonical_bytes(inner)
            .ok()
            .and_then(|t| token_conv::pending_transaction_to_proto(&t).ok())
            .map(Request::PendingTransaction),
        TYPE_MINT_TRANSACTION => MintTransaction::from_canonical_bytes(inner)
            .ok()
            .and_then(|t| token_conv::mint_transaction_to_proto(&t).ok())
            .map(Request::MintTransaction),
        // Compute ops — same rationale as the token ops above.
        TYPE_COMPUTE_DEPLOY => ComputeDeploy::from_canonical_bytes(inner)
            .ok()
            .and_then(|d| compute_conv::compute_deploy_to_proto(&d).ok())
            .map(Request::ComputeDeploy),
        TYPE_COMPUTE_UPDATE => ComputeUpdate::from_canonical_bytes(inner)
            .ok()
            .and_then(|u| compute_conv::compute_update_to_proto(&u).ok())
            .map(Request::ComputeUpdate),
        TYPE_CODE_DEPLOYMENT => CodeDeployment::from_canonical_bytes(inner)
            .ok()
            .map(|d| Request::CodeDeploy(compute_conv::code_deployment_to_proto(&d))),
        TYPE_CODE_EXECUTE => CodeExecute::from_canonical_bytes(inner)
            .ok()
            .and_then(|e| compute_conv::code_execute_to_proto(&e).ok())
            .map(Request::CodeExecute),
        TYPE_CODE_FINALIZE => CodeFinalize::from_canonical_bytes(inner)
            .ok()
            .and_then(|f| compute_conv::code_finalize_to_proto(&f).ok())
            .map(Request::CodeFinalize),
        // AltShardUpdate — non-consensus application address space (the
        // network only holds the roots); still surfaced + round-tripped for
        // completeness.
        TYPE_ALT_SHARD_UPDATE => AltShardUpdate::from_canonical_bytes(inner)
            .ok()
            .map(|a| Request::AltShardUpdate(conversions::alt_shard_update_to_proto(&a))),
        // Any variant without a specialized protobuf (including post-quantum
        // lattice-CT transactions: TYPE_LATTICE_MINT, TYPE_LATTICE_TRANSACTION, etc.)
        // is preserved verbatim as RawCanonicalPayload.
        _ => Some(Request::RawCanonicalPayload(req.inner_bytes.clone())),
    };
    MessageRequest {
        timestamp: 0,
        request,
    }
}

// =====================================================================
// Proto MessageBundle → canonical bytes
// =====================================================================
//
// The `decode_global_frame` path turns canonical-bytes bundles into prost
// proto types (losing the original wire bytes). When a downstream consumer
// — most importantly the frame materializer — needs to feed bundles to the
// execution engines (which expect canonical bytes per Go's
// `req.ToCanonicalBytes()`), we re-serialize from proto.
//
// Only the variants whose canonical→proto and proto→canonical converters
// are both ported survive the round-trip. Unsupported variants in a bundle
// are skipped with a `None` slot so the bundle structure (count +
// timestamp) is preserved.

/// Re-encode a proto `MessageBundle` as canonical bytes (type prefix
/// `0x0312`). Used by the frame materializer to feed bundles to the
/// execution engines, which expect canonical-bytes input matching Go's
/// `req.ToCanonicalBytes()`.
///
/// Variants without a `_to_canonical_bytes` ↔ `_from_proto` round-trip
/// are emitted as empty (`None`) slots.
pub fn proto_message_bundle_to_canonical_bytes(
    bundle: &quil_types::proto::global::MessageBundle,
) -> Result<Vec<u8>> {
    use quil_execution::message_envelope::{
        CanonicalMessageBundle, CanonicalMessageRequest,
    };

    let mut requests: Vec<Option<CanonicalMessageRequest>> = Vec::with_capacity(bundle.requests.len());
    for req in &bundle.requests {
        match proto_message_request_to_canonical(req) {
            Some(canon_req) => requests.push(Some(canon_req)),
            None => requests.push(None),
        }
    }

    CanonicalMessageBundle {
        requests,
        timestamp: bundle.timestamp,
    }
    .to_canonical_bytes()
}

/// Build a `CanonicalMessageRequest` from a proto `MessageRequest`.
/// Returns `None` if the proto's oneof variant has no inverse converter
/// yet (alongside the other 22 variants the canonical→proto path drops).
fn proto_message_request_to_canonical(
    req: &quil_types::proto::global::MessageRequest,
) -> Option<quil_execution::message_envelope::CanonicalMessageRequest> {
    use quil_execution::global_intrinsic::conversions;
    use quil_execution::token_intrinsic::conversions as token_conv;
    use quil_execution::compute_intrinsic::conversions as compute_conv;
    use quil_execution::message_envelope::CanonicalMessageRequest;
    use quil_types::proto::global::message_request::Request;

    let inner = req.request.as_ref()?;
    let inner_bytes = match inner {
        Request::Join(p) => conversions::prover_join_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Leave(p) => conversions::prover_leave_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Pause(p) => conversions::prover_pause_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Resume(p) => conversions::prover_resume_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Confirm(p) => conversions::prover_confirm_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Reject(p) => conversions::prover_reject_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Update(p) => conversions::prover_update_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::Shard(p) => conversions::frame_header_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        // Global lifecycle ops — symmetric with `canonical_request_to_proto` so
        // the materializer re-encodes them into `process_message` instead of
        // silently dropping them.
        Request::Kick(p) => conversions::prover_kick_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::ShardSplit(p) => conversions::shard_split_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::ShardMerge(p) => conversions::shard_merge_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::SeniorityMerge(p) => conversions::prover_seniority_merge_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        // Hypergraph ops (deploy/update, vertex add/remove, hyperedge
        // add/remove): `request_to_payload` handles all six proto→canonical.
        // This is what lets `materialize_app_shard_requests` carry a hypergraph
        // write from `frame.requests` into `process_message`.
        Request::HypergraphDeploy(_)
        | Request::HypergraphUpdate(_)
        | Request::VertexAdd(_)
        | Request::VertexRemove(_)
        | Request::HyperedgeAdd(_)
        | Request::HyperedgeRemove(_) => {
            quil_execution::hypergraph_engine::request_to_payload(req).ok()?
        }
        // Token ops — symmetric with `canonical_request_to_proto` so the
        // materializer re-encodes them into `process_message` rather than
        // dropping them.
        Request::TokenDeploy(p) => token_conv::token_deploy_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::TokenUpdate(p) => token_conv::token_update_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::Transaction(p) => token_conv::transaction_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::PendingTransaction(p) => token_conv::pending_transaction_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::MintTransaction(p) => token_conv::mint_transaction_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        // Compute ops — same rationale.
        Request::ComputeDeploy(p) => compute_conv::compute_deploy_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::ComputeUpdate(p) => compute_conv::compute_update_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::CodeDeploy(p) => compute_conv::code_deployment_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::CodeExecute(p) => compute_conv::code_execute_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::CodeFinalize(p) => compute_conv::code_finalize_from_proto(p)
            .ok()?
            .to_canonical_bytes()
            .ok()?,
        Request::AltShardUpdate(p) => conversions::alt_shard_update_from_proto(p)
            .to_canonical_bytes()
            .ok()?,
        Request::RawCanonicalPayload(p) => p.clone(),
    };

    CanonicalMessageRequest::wrap(inner_bytes).ok()
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
    // Bound the count against remaining bytes BEFORE pre-allocating: each entry
    // is a length-prefixed blob (>= 4 bytes), so a claimed count larger than
    // `remaining / 4` is impossible — reject it instead of letting an
    // attacker-chosen u32 drive a huge `Vec::with_capacity` (a ~100GB alloc =
    // OOM/abort from a tiny frame, reachable pre-auth on the gossip path).
    if commit_count > data.len().saturating_sub(c) / 4 {
        return Err(QuilError::InvalidArgument(format!(
            "GlobalFrame: commit_count {} exceeds what remaining bytes can hold", commit_count
        )));
    }
    let mut global_commitments = Vec::with_capacity(commit_count);
    for i in 0..commit_count {
        global_commitments.push(read_bytes(data, &mut c)
            .map_err(|e| QuilError::InvalidArgument(format!("commitment[{}] at {}/{}: {}", i, c, total, e)))?);
    }

    let prover_tree_commitment = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("prover_tree_commit at {}/{}: {}", c, total, e)))?;
    let requests_root = read_bytes(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("requests_root at {}/{}: {}", c, total, e)))?;
    let aux_count = read_u32(data, &mut c)
        .map_err(|e| QuilError::InvalidArgument(format!("aux_root_count at {}/{}: {}", c, total, e)))? as usize;
    // Same allocation-bomb guard as commit_count (entries are length-prefixed).
    if aux_count > data.len().saturating_sub(c) / 4 {
        return Err(QuilError::InvalidArgument(format!(
            "GlobalFrame: aux_count {} exceeds what remaining bytes can hold", aux_count
        )));
    }
    let mut prover_tree_aux_roots = Vec::with_capacity(aux_count);
    for i in 0..aux_count {
        prover_tree_aux_roots.push(read_bytes(data, &mut c)
            .map_err(|e| QuilError::InvalidArgument(format!("aux_root[{}] at {}/{}: {}", i, c, total, e)))?);
    }
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
        prover_tree_aux_roots,
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
    fn header_decode_rejects_alloc_bomb_counts() {
        // A tiny header claiming a huge commit_count/aux_count must be REJECTED
        // by the remaining-bytes bound, not drive a ~100GB `Vec::with_capacity`
        // (OOM/abort). Reachable pre-auth on the gossip decode path.
        let build = |commit_count: u32, aux_count: u32| {
            let mut b = Vec::new();
            put_u32(&mut b, GLOBAL_FRAME_HEADER_TYPE);
            b.extend_from_slice(&0u64.to_be_bytes()); // frame_number
            b.extend_from_slice(&0u64.to_be_bytes()); // rank
            b.extend_from_slice(&0i64.to_be_bytes()); // timestamp
            put_u32(&mut b, 0); // difficulty
            put_u32(&mut b, 0); // output (empty LP)
            put_u32(&mut b, 0); // parent_selector (empty LP)
            put_u32(&mut b, commit_count);
            // For the aux-count case we need a valid (empty) commitments list +
            // the intervening fields so the cursor reaches aux_count.
            if commit_count == 0 {
                put_u32(&mut b, 0); // prover_tree_commitment (empty LP)
                put_u32(&mut b, 0); // requests_root (empty LP)
                put_u32(&mut b, aux_count);
            }
            b
        };
        let r = decode_frame_header(&build(u32::MAX, 0));
        assert!(r.is_err(), "huge commit_count must be rejected");
        assert!(r.unwrap_err().to_string().contains("commit_count"));

        let r = decode_frame_header(&build(0, u32::MAX));
        assert!(r.is_err(), "huge aux_count must be rejected");
        assert!(r.unwrap_err().to_string().contains("aux_count"));
    }

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
            openings: Vec::new(),
        };
        let bytes = vote.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &PROPOSAL_VOTE_TYPE.to_be_bytes());
        let decoded = ProposalVote::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.rank, 42);
        assert_eq!(decoded.frame_number, 1000);
        assert_eq!(decoded.filter, vec![0xFF; 32]);
    }

    #[test]
    fn proposal_vote_openings_roundtrip_and_backcompat() {
        let base = ProposalVote {
            filter: vec![0xFF; 32],
            rank: 7,
            frame_number: 9,
            selector: vec![0xAA; 32],
            timestamp: 5,
            signature: vec![0xBB; 74],
            address: vec![0xCC; 32],
            openings: Vec::new(),
        };
        // Empty openings → nothing appended → decodes back to empty.
        let empty_bytes = base.to_canonical_bytes().unwrap();
        assert!(ProposalVote::from_canonical_bytes(&empty_bytes).unwrap().openings.is_empty());

        // Non-empty openings → appended (longer) and round-trips, with the
        // legacy fields intact.
        let with = ProposalVote { openings: vec![0x11, 0x22, 0x33, 0x44], ..base.clone() };
        let with_bytes = with.to_canonical_bytes().unwrap();
        assert!(
            with_bytes.len() > empty_bytes.len(),
            "openings must be appended after the legacy fields"
        );
        let d = ProposalVote::from_canonical_bytes(&with_bytes).unwrap();
        assert_eq!(d.openings, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(d.rank, 7);
        assert_eq!(d.signature, vec![0xBB; 74]);
        assert_eq!(d.address, vec![0xCC; 32]);
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
        assert_eq!(qc.aggregate_signature.public_key.len(), 897);
        assert_eq!(qc.aggregate_signature.signature.len(), 666);
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
                openings: Vec::new(),
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

    #[test]
    fn decode_global_frame_round_trips_two_bundles() {
        use quil_execution::global_intrinsic::frame_header::GlobalFrameHeader as CanonicalGlobalHeader;
        use quil_execution::global_intrinsic::prover_filter_ops::ProverPause;
        use quil_execution::global_intrinsic::AddressedSignature;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

        // Build two MessageBundles in canonical-bytes form. One bundle
        // carries a routable ProverPause (we expect a populated oneof
        // after decode), the other has an opaque inner type to exercise
        // the fallback `request: None` path.
        let pause_bytes = ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 7,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: vec![0xBBu8; 666],
                address: vec![0xCCu8; 32],
            }),
        }
        .to_canonical_bytes()
        .unwrap();

        let bundle1 = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(pause_bytes).unwrap())],
            timestamp: 1_700_000_000,
        };
        // Opaque inner type 0xDEAD with non-empty payload — routes via
        // the unknown-variant fallback (request stays None).
        let mut opaque_inner = Vec::new();
        put_u32(&mut opaque_inner, 0xDEAD);
        opaque_inner.extend_from_slice(&[0xEEu8; 16]);
        let bundle2 = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(opaque_inner).unwrap())],
            timestamp: -42,
        };

        let bundle1_bytes = bundle1.to_canonical_bytes().unwrap();
        let bundle2_bytes = bundle2.to_canonical_bytes().unwrap();

        // Build a GlobalFrameHeader in canonical bytes form.
        let header = CanonicalGlobalHeader {
            frame_number: 12345,
            rank: 1,
            timestamp: 1_700_000_001,
            difficulty: 100_000,
            output: vec![0x01; 32],
            parent_selector: vec![0x02; 32],
            global_commitments: vec![vec![0x03; 32]],
            prover_tree_commitment: vec![0x04; 32],
            prover_tree_aux_roots: vec![vec![0x07; 32], vec![0x08; 32], vec![0x09; 32]],
            requests_root: vec![0x05; 32],
            prover: vec![0x06; 32],
            public_key_signature_bls48581: Vec::new(),
        };
        let header_bytes = header.to_canonical_bytes().unwrap();

        // Frame wire format: [u32 type][u32 hdr_len][hdr][u32 req_count]
        //   [for each req: u32 len, bytes].
        let mut frame = Vec::new();
        put_u32(&mut frame, GLOBAL_FRAME_TYPE);
        put_bytes(&mut frame, &header_bytes);
        put_u32(&mut frame, 2);
        put_bytes(&mut frame, &bundle1_bytes);
        put_bytes(&mut frame, &bundle2_bytes);

        let decoded = decode_global_frame(&frame).expect("decode");
        let h = decoded.header.as_ref().expect("header");
        assert_eq!(h.frame_number, 12345);
        assert_eq!(h.rank, 1);
        // Prover shard aux roots (audit #5) survive the canonical round-trip.
        assert_eq!(
            h.prover_tree_aux_roots,
            vec![vec![0x07; 32], vec![0x08; 32], vec![0x09; 32]]
        );

        assert_eq!(decoded.requests.len(), 2);
        assert_eq!(decoded.requests[0].timestamp, 1_700_000_000);
        assert_eq!(decoded.requests[1].timestamp, -42);

        // Bundle 1 has a single request that should decode into a
        // populated `Pause` variant.
        assert_eq!(decoded.requests[0].requests.len(), 1);
        let req0 = &decoded.requests[0].requests[0];
        match &req0.request {
            Some(quil_types::proto::global::message_request::Request::Pause(p)) => {
                assert_eq!(p.frame_number, 7);
                assert_eq!(p.filter, vec![0xAAu8; 32]);
            }
            other => panic!("expected Pause variant, got {:?}", other.is_some()),
        }

        // Bundle 2 has a single request whose inner type is unknown to
        // the router — it should be a default-shaped MessageRequest
        // (request: None) so the bundle structure is preserved.
        assert_eq!(decoded.requests[1].requests.len(), 1);
        let req1 = &decoded.requests[1].requests[0];
        assert!(req1.request.is_none());
    }

    #[test]
    fn decode_global_frame_rejects_too_many_requests() {
        // header_len=0 (still bogus header — but we never get to header
        // parsing because count check fires first... actually we do
        // parse the header. Use a minimal valid header.)
        use quil_execution::global_intrinsic::frame_header::GlobalFrameHeader as CanonicalGlobalHeader;
        let header = CanonicalGlobalHeader::default();
        let header_bytes = header.to_canonical_bytes().unwrap();

        let mut frame = Vec::new();
        put_u32(&mut frame, GLOBAL_FRAME_TYPE);
        put_bytes(&mut frame, &header_bytes);
        put_u32(&mut frame, 101); // exceeds the 100 cap mirror'd from Go
        assert!(decode_global_frame(&frame).is_err());
    }

    /// A hypergraph VertexAdd must survive the app-shard frame's request
    /// round-trip: canonical → proto (`decode_message_bundle`, which builds
    /// `frame.requests`) → canonical (`proto_message_bundle_to_canonical_bytes`,
    /// used by `materialize_app_shard_requests`). Before both conversions learned
    /// the hypergraph ops, the VertexAdd was dropped to `None` in each direction —
    /// so a real write rode `requests_root` but never reached materialize.
    #[test]
    fn hypergraph_vertex_add_survives_bundle_round_trip() {
        use quil_execution::hypergraph_intrinsic::types::VertexAdd;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_types::proto::global::message_request::Request;

        let vadd = VertexAdd {
            domain: vec![0x11u8; 32],
            data_address: vec![0x22u8; 32],
            data: vec![0u8; 8],
            signature: vec![0xCCu8; 114],
        };
        let vadd_canon = vadd.to_canonical_bytes().unwrap();
        let canon_bundle = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(vadd_canon).unwrap())],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();

        // canonical → proto: the VertexAdd must be PRESERVED (not dropped to None).
        let proto_bundle = decode_message_bundle(&canon_bundle).unwrap();
        assert_eq!(proto_bundle.requests.len(), 1);
        assert!(
            matches!(proto_bundle.requests[0].request, Some(Request::VertexAdd(_))),
            "canonical→proto must preserve the VertexAdd, got {:?}",
            proto_bundle.requests[0].request
        );

        // proto → canonical: byte-exact round-trip back to the original bundle.
        let re_canon = proto_message_bundle_to_canonical_bytes(&proto_bundle).unwrap();
        assert_eq!(
            re_canon, canon_bundle,
            "proto→canonical round-trip must reproduce the original canonical bundle"
        );
    }

    #[test]
    fn global_lifecycle_ops_survive_bundle_round_trip() {
        use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
        use quil_execution::global_intrinsic::prover_ops::{
            ProverKick, ProverSeniorityMerge, ShardMerge, ShardSplit,
        };
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_types::proto::global::message_request::Request;

        let sig = || AddressedSignature {
            signature: vec![0x66u8; AddressedSignature::SIG_LEN_SINGLE],
            address: vec![0x77u8; 32],
        };
        let kick = ProverKick {
            frame_number: 100,
            kicked_prover_public_key: vec![0xCCu8; 585],
            conflicting_frame_1: vec![1u8; 100],
            conflicting_frame_2: vec![2u8; 100],
            commitment: vec![3u8; 74],
            proof: vec![4u8; 64],
            // Empty → None; a populated TraversalProof round-trips via prost.
            traversal_proof: Vec::new(),
        };
        let split = ShardSplit {
            shard_address: vec![0x33u8; 32],
            proposed_shards: vec![vec![0x44u8; 32], vec![0x55u8; 32]],
            frame_number: 101,
            public_key_signature_bls48581: Some(sig()),
        };
        let merge = ShardMerge {
            shard_addresses: vec![vec![0x88u8; 32]],
            parent_address: vec![0x99u8; 32],
            frame_number: 102,
            public_key_signature_bls48581: Some(sig()),
        };
        let seniority = ProverSeniorityMerge {
            frame_number: 103,
            public_key_signature_bls48581: Some(sig()),
            merge_targets: Vec::new(),
        };

        let cases: Vec<(Vec<u8>, &str)> = vec![
            (kick.to_canonical_bytes().unwrap(), "kick"),
            (split.to_canonical_bytes().unwrap(), "split"),
            (merge.to_canonical_bytes().unwrap(), "merge"),
            (seniority.to_canonical_bytes().unwrap(), "seniority"),
        ];
        for (canon, want) in cases {
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(CanonicalMessageRequest::wrap(canon).unwrap())],
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap();

            // canonical → proto: the op must be PRESERVED (not dropped to None).
            let proto = decode_message_bundle(&bundle).unwrap();
            assert_eq!(proto.requests.len(), 1);
            let ok = matches!(
                (&proto.requests[0].request, want),
                (Some(Request::Kick(_)), "kick")
                    | (Some(Request::ShardSplit(_)), "split")
                    | (Some(Request::ShardMerge(_)), "merge")
                    | (Some(Request::SeniorityMerge(_)), "seniority")
            );
            assert!(
                ok,
                "canonical→proto must preserve {want}, got {:?}",
                proto.requests[0].request
            );

            // proto → canonical: byte-exact round-trip.
            let re = proto_message_bundle_to_canonical_bytes(&proto).unwrap();
            assert_eq!(re, bundle, "byte-exact round-trip for {want}");
        }
    }

    #[test]
    fn token_compute_altshard_ops_survive_bundle_round_trip() {
        use quil_execution::compute_intrinsic::ops::{
            CodeDeployment, CodeExecute, CodeFinalize, ExecuteOperation, ExecutionResult,
            StateTransition,
        };
        use quil_execution::compute_intrinsic::config::{ComputeDeploy, ComputeUpdate};
        use quil_execution::global_intrinsic::consensus_types::AltShardUpdate;
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        use quil_execution::token_intrinsic::deploy::{TokenDeploy, TokenUpdate};
        use quil_execution::token_intrinsic::mint::{
            MintTransaction, MintTransactionInput, MintTransactionOutput,
        };
        use quil_execution::token_intrinsic::pending::{
            PendingTransaction, PendingTransactionInput, PendingTransactionOutput,
        };
        use quil_execution::token_intrinsic::transaction::{
            Transaction, TransactionInput, TransactionOutput,
        };
        use quil_types::proto::global::message_request::Request;

        // --- token ---
        let token_deploy = TokenDeploy { config: Vec::new(), rdf_schema: b"schema".to_vec() };
        let token_update = TokenUpdate {
            config: Vec::new(),
            rdf_schema: b"schema".to_vec(),
            public_key_signature_bls48581: vec![0x66u8; 74],
        };
        let tx = Transaction {
            domain: vec![0x11u8; 32],
            inputs: vec![TransactionInput {
                commitment: vec![1u8; 74],
                signature: vec![2u8; 74],
                proofs: vec![vec![3u8; 32]],
            }
            .to_canonical_bytes()
            .unwrap()],
            outputs: vec![TransactionOutput {
                frame_number: vec![0u8; 8],
                commitment: vec![4u8; 74],
                recipient_output: Vec::new(),
            }
            .to_canonical_bytes()
            .unwrap()],
            fees: vec![vec![0u8, 5]],
            range_proof: vec![6u8; 32],
            traversal_proof: Vec::new(),
        };
        let pending = PendingTransaction {
            domain: vec![0x12u8; 32],
            inputs: vec![PendingTransactionInput {
                commitment: vec![1u8; 74],
                signature: vec![2u8; 74],
                proofs: vec![vec![3u8; 32]],
            }
            .to_canonical_bytes()
            .unwrap()],
            outputs: vec![PendingTransactionOutput {
                frame_number: vec![0u8; 8],
                commitment: vec![4u8; 74],
                to: Vec::new(),
                refund: Vec::new(),
                expiration: 42,
            }
            .to_canonical_bytes()
            .unwrap()],
            fees: vec![vec![0u8, 5]],
            range_proof: vec![6u8; 32],
            traversal_proof: Vec::new(),
        };
        let mint = MintTransaction {
            domain: vec![0x13u8; 32],
            inputs: vec![MintTransactionInput {
                value: vec![0u8, 9],
                commitment: vec![1u8; 74],
                signature: vec![2u8; 74],
                proofs: vec![vec![3u8; 32]],
                additional_reference: vec![7u8; 64],
                additional_reference_key: vec![8u8; 57],
            }
            .to_canonical_bytes()
            .unwrap()],
            outputs: vec![MintTransactionOutput {
                frame_number: vec![0u8; 8],
                commitment: vec![4u8; 74],
                recipient_output: Vec::new(),
            }
            .to_canonical_bytes()
            .unwrap()],
            fees: vec![vec![0u8, 5]],
            range_proof: vec![6u8; 32],
        };

        // --- compute ---
        let compute_deploy = ComputeDeploy { config: Vec::new(), rdf_schema: b"schema".to_vec() };
        let compute_update = ComputeUpdate {
            config: Vec::new(),
            rdf_schema: b"schema".to_vec(),
            public_key_signature_bls48581: vec![0x66u8; 74],
        };
        // input/output types round-trip through String → must be valid UTF-8.
        let code_deploy = CodeDeployment {
            circuit: vec![0xAAu8; 40],
            input_types: vec![b"uint64".to_vec()],
            output_types: vec![b"bool".to_vec()],
            domain: [0x11u8; 32],
        };
        let code_execute = CodeExecute {
            proof_of_payment: vec![vec![1u8; 2]],
            domain: [0x22u8; 32],
            rendezvous: [0x33u8; 32],
            execute_operations: vec![ExecuteOperation {
                application: Vec::new(),
                identifier: vec![9u8; 16],
                dependencies: vec![vec![0xAu8; 16]],
            }
            .to_canonical_bytes()
            .unwrap()],
        };
        let code_finalize = CodeFinalize {
            rendezvous: [0x44u8; 32],
            results: vec![ExecutionResult {
                operation_id: vec![9u8; 16],
                success: true,
                output: vec![1u8; 8],
                error: Vec::new(),
            }
            .to_canonical_bytes()
            .unwrap()],
            state_changes: vec![StateTransition {
                domain: [0x55u8; 32],
                address: vec![2u8; 32],
                old_value: vec![3u8; 8],
                new_value: vec![4u8; 8],
                proof: vec![5u8; 32],
            }
            .to_canonical_bytes()
            .unwrap()],
            proof_of_execution: vec![6u8; 32],
            message_output: vec![7u8; 8],
        };

        // --- altshard ---
        let alt = AltShardUpdate {
            public_key: vec![0xCCu8; 585],
            frame_number: 200,
            vertex_adds_root: vec![1u8; 74],
            vertex_removes_root: vec![2u8; 74],
            hyperedge_adds_root: vec![3u8; 74],
            hyperedge_removes_root: vec![4u8; 74],
            signature: vec![5u8; 74],
        };

        let cases: Vec<(Vec<u8>, &str)> = vec![
            (token_deploy.to_canonical_bytes().unwrap(), "token_deploy"),
            (token_update.to_canonical_bytes().unwrap(), "token_update"),
            (tx.to_canonical_bytes().unwrap(), "transaction"),
            (pending.to_canonical_bytes().unwrap(), "pending"),
            (mint.to_canonical_bytes().unwrap(), "mint"),
            (compute_deploy.to_canonical_bytes().unwrap(), "compute_deploy"),
            (compute_update.to_canonical_bytes().unwrap(), "compute_update"),
            (code_deploy.to_canonical_bytes().unwrap(), "code_deploy"),
            (code_execute.to_canonical_bytes().unwrap(), "code_execute"),
            (code_finalize.to_canonical_bytes().unwrap(), "code_finalize"),
            (alt.to_canonical_bytes().unwrap(), "alt_shard_update"),
        ];
        for (canon, want) in cases {
            let bundle = CanonicalMessageBundle {
                requests: vec![Some(CanonicalMessageRequest::wrap(canon).unwrap())],
                timestamp: 0,
            }
            .to_canonical_bytes()
            .unwrap();

            // canonical → proto: the op must be PRESERVED (not dropped to None).
            let proto = decode_message_bundle(&bundle).unwrap();
            assert_eq!(proto.requests.len(), 1);
            let ok = matches!(
                (&proto.requests[0].request, want),
                (Some(Request::TokenDeploy(_)), "token_deploy")
                    | (Some(Request::TokenUpdate(_)), "token_update")
                    | (Some(Request::Transaction(_)), "transaction")
                    | (Some(Request::PendingTransaction(_)), "pending")
                    | (Some(Request::MintTransaction(_)), "mint")
                    | (Some(Request::ComputeDeploy(_)), "compute_deploy")
                    | (Some(Request::ComputeUpdate(_)), "compute_update")
                    | (Some(Request::CodeDeploy(_)), "code_deploy")
                    | (Some(Request::CodeExecute(_)), "code_execute")
                    | (Some(Request::CodeFinalize(_)), "code_finalize")
                    | (Some(Request::AltShardUpdate(_)), "alt_shard_update")
            );
            assert!(
                ok,
                "canonical→proto must preserve {want}, got {:?}",
                proto.requests[0].request
            );

            // proto → canonical: byte-exact round-trip.
            let re = proto_message_bundle_to_canonical_bytes(&proto).unwrap();
            assert_eq!(re, bundle, "byte-exact round-trip for {want}");
        }
    }
}
