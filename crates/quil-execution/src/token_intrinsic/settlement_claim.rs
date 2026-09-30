//! Consumer side of a cross-domain QUIL settlement: the claim that spends a
//! GLOBAL settlement record inside the destination application's bundle, the
//! binding of that record to the bundle, the consumption marker, and the
//! dynamic charge the settlement must cover.
//!
//! A hypergraph or compute bundle whose operations grow world state must open
//! with exactly one `SettlementClaim`. The claim proves a GLOBAL settlement
//! record at a canonical global root no later than the executing frame's
//! finalized global anchor; the record's destination must be the bundle's
//! application and its context the SHA3-256 of the rest of the bundle; its
//! amount must cover `multiplier × Σ cost`. The destination tree then records a
//! consumption marker, so a record funds exactly one bundle.
use super::settlement_record::{self, SettlementEntry};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use num_bigint::BigInt;
use quil_lattice_ct::confidential::transfer::parameter_context;
use quil_types::error::{QuilError, Result};
use sha3::{Digest, Sha3_256};

pub const TYPE_SETTLEMENT_CLAIM: u32 = 0x0519;
pub const VERSION: &[u8; 8] = b"QCT3SC\0\x02";
/// prefix ‖ version ‖ network ‖ application ‖ cited frame ‖ global root ‖
/// receipt ‖ settlement ‖ context ‖ payment address ‖ payment ‖ claimant key
/// type ‖ claimant key length ‖ claimant signature length ‖ proof length
const FIXED_BYTES: usize = 4 + 8 + 32 + 32 + 8 + 32 + 32 + 16 + 32 + 32 + 16 + 4 + 2 + 2 + 4;
/// Longest claimant signature a claim may carry (Falcon-512 is 666 bytes).
pub const MAX_CLAIMANT_SIGNATURE_BYTES: usize = 1024;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("settlement claim: {message}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementClaim {
    pub network: [u8; 32],
    /// The consuming application: the settlement's destination.
    pub application: [u8; 32],
    pub cited_global_frame: u64,
    pub global_root: [u8; 32],
    pub receipt: [u8; 32],
    pub settlement: u128,
    pub context: [u8; 32],
    /// The record's public payment (payee payment address and value), zero
    /// when the settlement carried none.
    pub payment_address: [u8; 32],
    pub payment: u128,
    /// The pre-funded settlement's claimant key and its signature over
    /// [`claimant_message`], both empty when the record names a `context`.
    pub claimant_key_type: u32,
    pub claimant_public_key: Vec<u8>,
    pub claimant_signature: Vec<u8>,
    /// Forest membership proof of the GLOBAL record at `global_root`.
    pub forest_proof: Vec<u8>,
}

/// What a pre-funded settlement's claimant signs to name the bundle its
/// settlement funds: the settlement's own receipt on its network, the
/// consuming application, and the bundle's context. The signature authorizes
/// exactly this settlement for exactly this bundle.
pub fn claimant_message(network: &[u8; 32], application: &[u8; 32], receipt: &[u8; 32], context: &[u8; 32]) -> Vec<u8> {
    let mut bytes = b"quil/settlement/claimant-authorization/v1\0".to_vec();
    bytes.extend_from_slice(network);
    bytes.extend_from_slice(application);
    bytes.extend_from_slice(receipt);
    bytes.extend_from_slice(context);
    bytes
}

impl SettlementClaim {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.forest_proof.len() > super::reward_witness::MAX_REWARD_PROOF_BYTES || self.settlement == 0 {
            return Err(invalid("oversized proof or zero settlement"));
        }
        if self.claimant_public_key.len() > quil_lattice_ct::confidential::settlement::MAX_CLAIMANT_KEY_BYTES
            || self.claimant_signature.len() > MAX_CLAIMANT_SIGNATURE_BYTES
        {
            return Err(invalid("oversized claimant"));
        }
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.forest_proof.len());
        bytes.extend_from_slice(&TYPE_SETTLEMENT_CLAIM.to_be_bytes());
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.cited_global_frame.to_le_bytes());
        bytes.extend_from_slice(&self.global_root);
        bytes.extend_from_slice(&self.receipt);
        bytes.extend_from_slice(&self.settlement.to_le_bytes());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.payment_address);
        bytes.extend_from_slice(&self.payment.to_le_bytes());
        bytes.extend_from_slice(&self.claimant_key_type.to_le_bytes());
        bytes.extend_from_slice(&(self.claimant_public_key.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.claimant_signature.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.forest_proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.claimant_public_key);
        bytes.extend_from_slice(&self.claimant_signature);
        bytes.extend_from_slice(&self.forest_proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_BYTES || bytes[..4] != TYPE_SETTLEMENT_CLAIM.to_be_bytes() || &bytes[4..12] != VERSION {
            return Err(invalid("invalid envelope"));
        }
        let array = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().unwrap() };
        let claimant_key_type = u32::from_le_bytes(bytes[244..248].try_into().unwrap());
        let key_len = u16::from_le_bytes(bytes[248..250].try_into().unwrap()) as usize;
        let signature_len = u16::from_le_bytes(bytes[250..252].try_into().unwrap()) as usize;
        let proof_len = u32::from_le_bytes(bytes[FIXED_BYTES - 4..FIXED_BYTES].try_into().unwrap()) as usize;
        if proof_len > super::reward_witness::MAX_REWARD_PROOF_BYTES
            || key_len > quil_lattice_ct::confidential::settlement::MAX_CLAIMANT_KEY_BYTES
            || signature_len > MAX_CLAIMANT_SIGNATURE_BYTES
            || bytes.len() != FIXED_BYTES + key_len + signature_len + proof_len
        {
            return Err(invalid("invalid proof length"));
        }
        let key_at = FIXED_BYTES;
        let signature_at = key_at + key_len;
        let proof_at = signature_at + signature_len;
        let claim = Self {
            network: array(12),
            application: array(44),
            cited_global_frame: u64::from_le_bytes(bytes[76..84].try_into().unwrap()),
            global_root: array(84),
            receipt: array(116),
            settlement: u128::from_le_bytes(bytes[148..164].try_into().unwrap()),
            context: array(164),
            payment_address: array(196),
            payment: u128::from_le_bytes(bytes[228..244].try_into().unwrap()),
            claimant_key_type,
            claimant_public_key: bytes[key_at..signature_at].to_vec(),
            claimant_signature: bytes[signature_at..proof_at].to_vec(),
            forest_proof: bytes[proof_at..].to_vec(),
        };
        if claim.settlement == 0
            || claim.application == crate::domains::QUIL_TOKEN
            || claim.application == crate::domains::GLOBAL
            || (claim.payment == 0) != (claim.payment_address == [0; 32])
        {
            return Err(invalid("zero settlement or invalid destination"));
        }
        // Exactly one binding, matching the record: a bundle context, or a
        // claimant who names one with a signature.
        // Zero is a real key type (Ed448), so presence is the key bytes; an
        // absent claimant carries neither a type nor a signature.
        if (claim.context == [0; 32]) != claim.is_prefunded()
            || (claim.is_prefunded() && claim.claimant_signature.is_empty())
            || (!claim.is_prefunded() && (claim.claimant_key_type != 0 || !claim.claimant_signature.is_empty()))
        {
            return Err(invalid("a claim binds either a context or a claimant"));
        }
        Ok(claim)
    }

    /// Whether this claim names a pre-funded settlement's claimant key.
    pub fn is_prefunded(&self) -> bool {
        !self.claimant_public_key.is_empty()
    }

    /// The GLOBAL record this claim asserts.
    pub fn entry(&self) -> Result<SettlementEntry> {
        Ok(SettlementEntry {
            receipt: self.receipt,
            parameter_context: parameter_context(&self.network, &crate::domains::QUIL_TOKEN),
            destination: self.application,
            context: self.context,
            settlement: self.settlement,
            payment_address: self.payment_address,
            payment: self.payment,
            claimant: if self.is_prefunded() {
                settlement_record::claimant_address(self.claimant_key_type, &self.claimant_public_key)?
            } else {
                [0; 32]
            },
        })
    }

    /// Check the claim's binding to `context`, the bundle it opens: either the
    /// record names that context, or it names a claimant whose signature does.
    /// The record's claimant address is the key's, so only that key authorizes.
    pub fn check_binding(&self, context: &[u8; 32]) -> Result<()> {
        if !self.is_prefunded() {
            return (self.context == *context)
                .then_some(())
                .ok_or_else(|| invalid("settlement context does not bind this bundle"));
        }
        super::signature::verify_authority_signature(
            self.claimant_key_type,
            &self.claimant_public_key,
            &claimant_message(&self.network, &self.application, &self.receipt, context),
            &parameter_context(&self.network, &self.application),
            &self.claimant_signature,
        )
        .map_err(|_| invalid("claimant did not authorize this bundle"))
    }
}

/// Address of the marker recording that `destination` consumed `receipt`.
pub fn consumption_marker(destination: &[u8; 32], receipt: &[u8; 32]) -> Result<[u8; 32]> {
    let mut bytes = b"quil/settlement/consumed/v1\0".to_vec();
    bytes.extend_from_slice(destination);
    bytes.extend_from_slice(receipt);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

fn marker_kind() -> Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(b"quil/settlement/consumed-marker/v1\0")
}

/// Vertex written at the consumption marker. Its single field sits at key
/// `[0xff; 32]`, which no hypergraph vertex (8-byte field indices) can hold.
pub fn marker_record() -> Result<Vec<u8>> {
    let kind = marker_kind()?;
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0xff; 32], &kind, &[], &BigInt::from(kind.len()))?;
    Ok(crate::prover_registry::vertex_tree_to_blob(&tree))
}

/// Whether a stored vertex blob is a consumption marker. Hypergraph writes
/// must not overwrite or remove one, or a record could fund a second bundle.
pub fn is_consumption_marker(blob: &[u8]) -> bool {
    if blob.is_empty() {
        return false;
    }
    let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(blob);
    match (tree.get(&[0xff; 32]), marker_kind()) {
        (Some(value), Ok(kind)) => value == kind.as_slice(),
        _ => false,
    }
}

/// SHA3-256 binding of a consumer bundle: the canonical bytes of the bundle
/// with its first request (the claim) removed.
pub fn bundle_context(bundle: &CanonicalMessageBundle) -> Result<[u8; 32]> {
    let rest = CanonicalMessageBundle {
        requests: bundle.requests.iter().skip(1).cloned().collect(),
        timestamp: bundle.timestamp,
    };
    Ok(Sha3_256::digest(rest.to_canonical_bytes()?).into())
}

/// World-state growth (bytes) a consumer request adds, the unit its charge is
/// priced in. Removals carry the Go constant; types other engines own cost zero
/// here.
pub fn request_cost(request: &CanonicalMessageRequest) -> Result<u64> {
    use crate::hypergraph_intrinsic::canonical::{
        TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE, TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE,
        TYPE_VERTEX_ADD, TYPE_VERTEX_REMOVE,
    };
    let bytes = &request.inner_bytes;
    Ok(match request.inner_type_prefix {
        TYPE_VERTEX_ADD => {
            let add = crate::hypergraph_intrinsic::VertexAdd::from_canonical_bytes(bytes)?;
            let chunks = crate::hypergraph_intrinsic::split_vertex_add_proof_chunks(&add.data)?;
            let tree = crate::hypergraph_intrinsic::encrypted_to_vertex_tree(&chunks)?;
            crate::prover_registry::vertex_tree_to_blob(&tree).len() as u64
        }
        TYPE_HYPEREDGE_ADD => match crate::hypergraph_intrinsic::dispatch::decode_message(bytes)? {
            crate::hypergraph_intrinsic::dispatch::DispatchedMessage::HyperedgeAdd(add) => add.value.len() as u64,
            _ => return Err(invalid("malformed hyperedge add")),
        },
        TYPE_VERTEX_REMOVE => crate::hypergraph_intrinsic::VERTEX_REMOVE_COST as u64,
        TYPE_HYPEREDGE_REMOVE => crate::hypergraph_intrinsic::HYPEREDGE_REMOVE_COST as u64,
        TYPE_HYPERGRAPH_DEPLOYMENT | TYPE_HYPERGRAPH_UPDATE => bytes.len() as u64,
        // A token deploy or update writes its configuration. Priced here, with
        // every other request type, so the paying wallet and the admitting
        // engine compute the same charge from the same function; the token
        // engine's `extra_cost` covers only its confidential operations.
        crate::token_intrinsic::TYPE_TOKEN_DEPLOY => {
            crate::token_intrinsic::TokenDeploy::from_canonical_bytes(bytes)?.config.len() as u64
        }
        crate::token_intrinsic::TYPE_TOKEN_UPDATE => {
            crate::token_intrinsic::TokenUpdate::from_canonical_bytes(bytes)?.config.len() as u64
        }
        tp if crate::compute_engine::is_compute_type_prefix(tp) => bytes.len() as u64,
        TYPE_SETTLEMENT_CLAIM => marker_record()?.len() as u64,
        _ => 0,
    })
}

/// Total world-state growth of a message (request or bundle), including the
/// consumption marker of a claim.
pub fn message_cost(message: &[u8]) -> Result<u64> {
    use crate::message_envelope::{TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};
    let add = |total: u64, cost: u64| total.checked_add(cost).ok_or_else(|| invalid("cost overflow"));
    match message.get(..4).map(|p| u32::from_be_bytes(p.try_into().unwrap())) {
        Some(TYPE_MESSAGE_REQUEST) => request_cost(&CanonicalMessageRequest::from_canonical_bytes(message)?),
        Some(TYPE_MESSAGE_BUNDLE) => {
            let bundle = CanonicalMessageBundle::from_canonical_bytes(message)?;
            bundle.requests.iter().flatten().try_fold(0u64, |total, r| add(total, request_cost(r)?))
        }
        _ => Ok(0),
    }
}

/// Everything needed to admit a paid consumer message.
pub struct PaymentContext<'a> {
    pub state: Option<&'a HypergraphState>,
    pub clock: Option<&'a dyn quil_types::store::ClockStore>,
    /// Newest global frame whose root a claim may cite, `None` when the venue
    /// has no finalized global anchor.
    pub global_bound: Option<u64>,
    pub frame_number: u64,
    /// Per-unit price of this message (`pricing::fee_multiplier_for_cost`).
    pub multiplier: &'a BigInt,
    /// The shard executing the message; a claim runs only on the shard that
    /// holds its consumption marker.
    pub shard: quil_types::execution::ShardPath,
}

/// A consumed settlement claim: the amount paid to the executing shard's
/// provers and the record's public payment, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedClaim {
    pub settlement: u128,
    pub payment_address: [u8; 32],
    pub payment: u128,
}

/// Enforce payment for a consumer message addressed to `address` and stage its
/// consumption marker. Returns the consumed claim, or `None` when the message
/// grows no state at a nonzero price and carries no claim. Must run before the
/// message's own writes, in the same changeset.
pub fn admit_paid_message(payment: &PaymentContext<'_>, address: &[u8], message: &[u8]) -> Result<Option<AdmittedClaim>> {
    use crate::message_envelope::{TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};
    let bundle = match message.get(..4).map(|p| u32::from_be_bytes(p.try_into().unwrap())) {
        Some(TYPE_MESSAGE_BUNDLE) => CanonicalMessageBundle::from_canonical_bytes(message)?,
        Some(TYPE_MESSAGE_REQUEST) => CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::from_canonical_bytes(message)?)],
            timestamp: 0,
        },
        _ => return Ok(None),
    };
    admit_bundle(payment, address, &bundle, 0)
}

/// Whether a bundle opens with a settlement claim.
pub fn has_claim(bundle: &CanonicalMessageBundle) -> bool {
    bundle.requests.first().and_then(|r| r.as_ref()).is_some_and(|r| r.inner_type_prefix == TYPE_SETTLEMENT_CLAIM)
}

/// [`admit_paid_message`] over a decoded bundle, with `extra_cost` bytes of
/// state growth priced by the caller (token operations of the bundle).
pub fn admit_bundle(
    payment: &PaymentContext<'_>,
    address: &[u8],
    bundle: &CanonicalMessageBundle,
    extra_cost: u64,
) -> Result<Option<AdmittedClaim>> {
    let claim_at: Vec<usize> = bundle.requests.iter().enumerate()
        .filter(|(_, r)| r.as_ref().is_some_and(|r| r.inner_type_prefix == TYPE_SETTLEMENT_CLAIM))
        .map(|(i, _)| i)
        .collect();
    if claim_at.iter().any(|&i| i != 0) {
        return Err(invalid("a claim must be the bundle's first and only claim"));
    }
    let cost = bundle.requests.iter().flatten().try_fold(extra_cost, |total, r| {
        total.checked_add(request_cost(r)?).ok_or_else(|| invalid("cost overflow"))
    })?;
    if payment.multiplier.sign() == num_bigint::Sign::Minus {
        return Err(invalid("negative fee multiplier"));
    }
    let required = payment.multiplier * BigInt::from(cost);
    let Some(claim_request) = claim_at.first().and_then(|_| bundle.requests[0].as_ref()) else {
        if required.sign() == num_bigint::Sign::NoSign {
            return Ok(None);
        }
        return Err(invalid("state-growing bundle requires a settlement claim"));
    };

    let claim = SettlementClaim::decode(&claim_request.inner_bytes)?;
    if address.len() < 32 || claim.application[..] != address[..32] {
        return Err(invalid("claim destination is not the bundle's application"));
    }
    // A record funds one bundle only if every bundle citing it meets the same
    // consumption marker. The marker is one data address of the application,
    // and the shards of an application partition its addresses, so exactly one
    // shard holds it: that shard alone may admit the claim. Deterministic (a
    // function of the frame's filter and the claim), so every replica of any
    // other shard skips the bundle identically instead of failing the frame.
    let marker = consumption_marker(&claim.application, &claim.receipt)?;
    if !payment.shard.covers(&marker) {
        return Err(invalid(
            "the settlement's consumption marker belongs to another shard of this application",
        ));
    }
    claim.check_binding(&bundle_context(bundle)?)?;
    if BigInt::from(claim.settlement) < required {
        return Err(invalid("settlement below the bundle's dynamic cost"));
    }
    // A record funds exactly one bundle, which is true only if consuming it is
    // recorded. Admitting a claim with nowhere to write the marker would let
    // the same record fund every bundle that cites it, so it is refused
    // outright rather than silently admitted unconsumed.
    let state = payment.state.ok_or_else(|| {
        QuilError::ExecutionUnavailable("settlement claim requires application state to record consumption".into())
    })?;

    let bound = payment.global_bound.ok_or_else(|| {
        QuilError::ExecutionUnavailable("settlement claim requires a finalized global anchor".into())
    })?;
    let clock = payment.clock.ok_or_else(|| {
        QuilError::ExecutionUnavailable("settlement claim requires the global clock store".into())
    })?;
    let root = super::mint_authorization::clock_reward_root(clock, claim.cited_global_frame, bound)?;
    if root != claim.global_root {
        return Err(invalid("global root mismatch"));
    }
    settlement_record::verify_membership(&claim.network, &claim.entry()?, &root, &claim.forest_proof)?;

    let disc = vertex_adds_discriminator()?;
    if state.get(&claim.application, &marker, &disc)?.is_some_and(|blob| !blob.is_empty()) {
        return Err(invalid("settlement already consumed"));
    }
    state.set(&claim.application, &marker, &disc, payment.frame_number, marker_record()?)?;
    Ok(Some(AdmittedClaim { settlement: claim.settlement, payment_address: claim.payment_address, payment: claim.payment }))
}

/// The settlement amount a successfully executed message consumed (its
/// claim's amount), credited to the executing shard's provers.
pub fn message_settlement_amount(message: &[u8]) -> u128 {
    use crate::message_envelope::{TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST};
    let of = |r: &CanonicalMessageRequest| {
        (r.inner_type_prefix == TYPE_SETTLEMENT_CLAIM)
            .then(|| SettlementClaim::decode(&r.inner_bytes).map(|c| c.settlement).unwrap_or(0))
            .unwrap_or(0)
    };
    match message.get(..4).map(|p| u32::from_be_bytes(p.try_into().unwrap())) {
        Some(TYPE_MESSAGE_REQUEST) => CanonicalMessageRequest::from_canonical_bytes(message).map(|r| of(&r)).unwrap_or(0),
        Some(TYPE_MESSAGE_BUNDLE) => CanonicalMessageBundle::from_canonical_bytes(message)
            .map(|b| b.requests.iter().flatten().map(of).fold(0u128, u128::saturating_add))
            .unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> SettlementClaim {
        SettlementClaim {
            network: [1; 32], application: [2; 32], cited_global_frame: 77, global_root: [3; 32],
            receipt: [4; 32], settlement: 9_000, context: [5; 32], payment_address: [0; 32], payment: 0,
            claimant_key_type: 0, claimant_public_key: Vec::new(), claimant_signature: Vec::new(),
            forest_proof: vec![6; 40],
        }
    }

    #[test]
    fn claim_codec_is_exact_and_rejects_bad_destinations() {
        let c = claim();
        let bytes = c.encode().unwrap();
        assert_eq!(SettlementClaim::decode(&bytes).unwrap(), c);
        assert!(SettlementClaim::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(SettlementClaim::decode(&longer).is_err());
        let mut version = bytes.clone();
        version[11] ^= 1;
        assert!(SettlementClaim::decode(&version).is_err());
        for destination in [crate::domains::QUIL_TOKEN, crate::domains::GLOBAL] {
            let bad = SettlementClaim { application: destination, ..claim() }.encode().unwrap();
            assert!(SettlementClaim::decode(&bad).is_err());
        }
        assert!(SettlementClaim { settlement: 0, ..claim() }.encode().is_err());
        assert_eq!(c.entry().unwrap().destination, c.application);
    }

    /// Claimants are application authority keys: post-quantum only.
    fn claimant_signer() -> (quil_crypto::FalconSigner, u32, Vec<u8>) {
        use quil_types::crypto::Signer;
        let signer = quil_crypto::FalconSigner::generate();
        let key = signer.public_key().to_vec();
        (signer, quil_types::crypto::KeyType::Falcon512 as u32, key)
    }

    /// A pre-funded claim: the record names a claimant, and the claim carries
    /// that key with a signature over the bundle it funds.
    fn prefunded(context: &[u8; 32]) -> SettlementClaim {
        use quil_types::crypto::Signer;
        let base = claim();
        let (signer, key_type, public_key) = claimant_signer();
        let signature = signer.sign_with_domain(
            &claimant_message(&base.network, &base.application, &base.receipt, context),
            &parameter_context(&base.network, &base.application),
        ).unwrap();
        SettlementClaim { context: [0; 32], claimant_key_type: key_type, claimant_public_key: public_key,
            claimant_signature: signature, ..base }
    }

    #[test]
    fn a_prefunded_claim_binds_the_bundle_its_claimant_signed_and_no_other() {
        let context = [0x77; 32];
        let c = prefunded(&context);
        assert!(c.is_prefunded());
        let bytes = c.encode().unwrap();
        assert_eq!(SettlementClaim::decode(&bytes).unwrap(), c);
        // The record it asserts carries the claimant's address, not a context.
        let entry = c.entry().unwrap();
        assert_eq!(entry.context, [0; 32]);
        assert_eq!(entry.claimant,
            settlement_record::claimant_address(c.claimant_key_type, &c.claimant_public_key).unwrap());
        c.check_binding(&context).unwrap();
        // Another bundle, another settlement, another destination, another key
        // or a tampered signature: none are authorized.
        assert!(c.check_binding(&[0x78; 32]).is_err());
        assert!(SettlementClaim { receipt: [0x40; 32], ..c.clone() }.check_binding(&context).is_err());
        assert!(SettlementClaim { application: [0x41; 32], ..c.clone() }.check_binding(&context).is_err());
        assert!(SettlementClaim { network: [0x42; 32], ..c.clone() }.check_binding(&context).is_err());
        let (_, key_type, other_key) = claimant_signer();
        assert!(SettlementClaim { claimant_key_type: key_type, claimant_public_key: other_key, ..c.clone() }
            .check_binding(&context).is_err());
        let mut tampered = c.claimant_signature.clone();
        tampered[0] ^= 1;
        assert!(SettlementClaim { claimant_signature: tampered, ..c.clone() }.check_binding(&context).is_err());
        // Both bindings, or neither, never decode.
        for bad in [
            SettlementClaim { context, ..c.clone() },
            SettlementClaim { claimant_signature: Vec::new(), ..c.clone() },
            SettlementClaim { context: [0; 32], claimant_public_key: Vec::new(), claimant_signature: Vec::new(),
                claimant_key_type: 0, ..c.clone() },
            // A context-bound claim carrying a claimant's leftovers.
            SettlementClaim { claimant_signature: vec![1; 666], ..claim() },
            SettlementClaim { claimant_key_type: 8, ..claim() },
        ] {
            assert!(SettlementClaim::decode(&bad.encode().unwrap()).is_err());
        }
        // A classical claimant is refused as a key type, never verified.
        let classical = SettlementClaim { claimant_key_type: quil_types::crypto::KeyType::Ed448 as u32, ..c.clone() };
        let error = classical.check_binding(&context).unwrap_err();
        assert!(error.to_string().contains("claimant did not authorize"), "{error}");
        // A context-bound claim carries no claimant and is checked by equality.
        let bound = claim();
        assert!(!bound.is_prefunded());
        assert_eq!(bound.entry().unwrap().claimant, [0; 32]);
        bound.check_binding(&bound.context).unwrap();
        assert!(bound.check_binding(&context).is_err());
    }

    /// A token deploy writes its configuration, and the wallet that pays for
    /// the bundle must charge for exactly what the engine will require. Both
    /// read `request_cost`, so a deploy is never priced at zero (which
    /// underpaid every paid token deploy and had them silently rejected).
    #[test]
    fn a_token_deploy_is_priced_by_its_configuration() {
        let config = vec![7u8; 2_048];
        let deploy = crate::token_intrinsic::TokenDeploy { config: config.clone(), rdf_schema: Vec::new() }
            .to_canonical_bytes().unwrap();
        let request = CanonicalMessageRequest::wrap(deploy).unwrap();
        assert_eq!(request.inner_type_prefix, crate::token_intrinsic::TYPE_TOKEN_DEPLOY);
        assert_eq!(request_cost(&request).unwrap(), config.len() as u64);
        let update = crate::token_intrinsic::TokenUpdate { config: config.clone(), ..Default::default() }
            .to_canonical_bytes().unwrap();
        let update = CanonicalMessageRequest::wrap(update).unwrap();
        assert_eq!(request_cost(&update).unwrap(), config.len() as u64);
        // The whole bundle's charge is the marker plus the configuration.
        let bundle = CanonicalMessageBundle { requests: vec![None, Some(request)], timestamp: 1 };
        let cost = bundle.requests.iter().flatten()
            .try_fold(marker_record().unwrap().len() as u64, |t, r| request_cost(r).map(|c| t + c)).unwrap();
        assert_eq!(cost, marker_record().unwrap().len() as u64 + config.len() as u64);
    }

    #[test]
    fn markers_are_recognizable_and_addressed_per_destination() {
        let marker = marker_record().unwrap();
        assert!(is_consumption_marker(&marker));
        assert!(!is_consumption_marker(&[]));
        let chunk_tree = crate::hypergraph_intrinsic::encrypted_to_vertex_tree(&[vec![7u8; 64]]).unwrap();
        assert!(!is_consumption_marker(&crate::prover_registry::vertex_tree_to_blob(&chunk_tree)));
        assert_ne!(consumption_marker(&[1; 32], &[2; 32]).unwrap(), consumption_marker(&[3; 32], &[2; 32]).unwrap());
    }

    fn request(tp: u32, len: usize) -> Option<CanonicalMessageRequest> {
        let mut inner = tp.to_be_bytes().to_vec();
        inner.resize(len, 0xAB);
        Some(CanonicalMessageRequest { inner_type_prefix: tp, inner_bytes: inner })
    }

    #[test]
    fn unpaid_state_growth_is_rejected_and_free_messages_pass() {
        let compute = crate::compute_intrinsic::config::TYPE_COMPUTE_DEPLOY;
        let bundle = CanonicalMessageBundle { requests: vec![request(compute, 100)], timestamp: 1 };
        let bytes = bundle.to_canonical_bytes().unwrap();
        assert_eq!(message_cost(&bytes).unwrap(), 100);
        let payment = |multiplier: &BigInt| -> Result<Option<AdmittedClaim>> {
            admit_paid_message(&PaymentContext {
                state: None, clock: None, global_bound: Some(10), frame_number: 11, multiplier,
                shard: quil_types::execution::ShardPath::WHOLE,
            }, &[2; 32], &bytes)
        };
        assert!(payment(&BigInt::from(1)).is_err());
        assert_eq!(payment(&BigInt::from(0)).unwrap(), None);

        // A claim anywhere but first is refused before any verification.
        let mut late = bundle.clone();
        late.requests.push(Some(CanonicalMessageRequest { inner_type_prefix: TYPE_SETTLEMENT_CLAIM, inner_bytes: claim().encode().unwrap() }));
        let late = late.to_canonical_bytes().unwrap();
        let error = admit_paid_message(&PaymentContext {
            state: None, clock: None, global_bound: Some(10), frame_number: 11, multiplier: &BigInt::from(0),
            shard: quil_types::execution::ShardPath::WHOLE,
        }, &[2; 32], &late).unwrap_err();
        assert!(error.to_string().contains("first"));
    }

    #[test]
    fn claim_must_bind_destination_context_and_amount_before_proof_work() {
        let compute = crate::compute_intrinsic::config::TYPE_COMPUTE_DEPLOY;
        let rest = CanonicalMessageBundle { requests: vec![None, request(compute, 100)], timestamp: 5 };
        let context = bundle_context(&rest).unwrap();
        let build = |c: SettlementClaim| {
            let mut bundle = rest.clone();
            bundle.requests[0] = Some(CanonicalMessageRequest { inner_type_prefix: TYPE_SETTLEMENT_CLAIM, inner_bytes: c.encode().unwrap() });
            bundle.to_canonical_bytes().unwrap()
        };
        let marker_cost = marker_record().unwrap().len() as u128;
        let admit = |bytes: &[u8], address: &[u8]| admit_paid_message(&PaymentContext {
            state: None, clock: None, global_bound: Some(10), frame_number: 11, multiplier: &BigInt::from(2),
            shard: quil_types::execution::ShardPath::WHOLE,
        }, address, bytes);
        let exact = 2 * (100 + marker_cost);
        // Wrong destination, wrong context, underpaid: deterministic rejections.
        assert!(admit(&build(SettlementClaim { context, settlement: exact, ..claim() }), &[9; 32]).unwrap_err().to_string().contains("destination"));
        assert!(admit(&build(SettlementClaim { settlement: exact, ..claim() }), &[2; 32]).unwrap_err().to_string().contains("context"));
        assert!(admit(&build(SettlementClaim { context, settlement: exact - 1, ..claim() }), &[2; 32]).unwrap_err().to_string().contains("below"));
        // A well-bound claim then needs somewhere to record consumption. A
        // record funds ONE bundle, so a claim admitted where no marker can be
        // written would fund every bundle citing it: that is refused, not
        // quietly allowed through.
        let error = admit(&build(SettlementClaim { context, settlement: exact, ..claim() }), &[2; 32]).unwrap_err();
        assert!(error.is_execution_unavailable());
        assert!(error.to_string().contains("record consumption"), "{error}");
        // The consumed amount is readable from the executed message.
        assert_eq!(message_settlement_amount(&build(SettlementClaim { context, settlement: exact, ..claim() })), exact);
        // The shards of an application partition its addresses, so exactly one
        // of them holds this claim's consumption marker. That shard admits the
        // claim (and then fails the same way the whole application does here,
        // for want of state); its sibling refuses deterministically.
        let good = build(SettlementClaim { context, settlement: exact, ..claim() });
        let marker = consumption_marker(&claim().application, &claim().receipt).unwrap();
        let owner = marker[0] & 0x80 != 0;
        let on = |bit: bool| admit_paid_message(&PaymentContext {
            state: None, clock: None, global_bound: Some(10), frame_number: 11, multiplier: &BigInt::from(2),
            shard: quil_types::execution::ShardPath::from_bits(&[bit]),
        }, &[2; 32], &good).unwrap_err();
        let error = on(!owner);
        assert!(matches!(error, QuilError::InvalidArgument(_)), "{error}");
        assert!(error.to_string().contains("another shard"), "{error}");
        let error = on(owner);
        assert!(error.is_execution_unavailable() && error.to_string().contains("record consumption"), "{error}");
        // A shard whose filter could not be decoded owns nothing.
        let error = admit_paid_message(&PaymentContext {
            state: None, clock: None, global_bound: Some(10), frame_number: 11, multiplier: &BigInt::from(2),
            shard: quil_types::execution::ShardPath::UNKNOWN,
        }, &[2; 32], &good).unwrap_err();
        assert!(error.to_string().contains("another shard"), "{error}");
    }
}
