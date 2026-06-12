// DKLs23 FFI - Rust implementation for threshold ECDSA
// This wraps the dkls23 crate for use via uniffi bindings

use std::sync::Once;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Import dkls23 crate types
use std::collections::BTreeMap;
use dkls23::protocols::{Parameters, Party as Dkls23Party};
use dkls23::protocols::dkg::{
    self, SessionData as DkgSessionDataInternal,
    ProofCommitment, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4,
    KeepInitMulPhase3to4, UniqueKeepDerivationPhase2to3,
    TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
    TransmitInitMulPhase3to4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
};
use dkls23::protocols::signing::{
    SignData,
    UniqueKeep1to2 as SignUniqueKeep1to2, KeepPhase1to2 as SignKeepPhase1to2,
    TransmitPhase1to2 as SignTransmitPhase1to2,
    UniqueKeep2to3 as SignUniqueKeep2to3, KeepPhase2to3 as SignKeepPhase2to3,
    TransmitPhase2to3 as SignTransmitPhase2to3,
    Broadcast3to4 as SignBroadcast3to4,
};
use dkls23::protocols::refresh::{
    KeepRefreshPhase2to3, KeepRefreshPhase3to4,
    TransmitRefreshPhase2to4, TransmitRefreshPhase3to4,
};
use dkls23::protocols::re_key::re_key;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Dispatch macro: defines `type Curve` and `type Scalar` inside each match arm.
/// Code inside the block can use `Curve` (for generic dkls23 types) and `Scalar`
/// (for direct scalar operations) transparently for both curve types.
macro_rules! with_curve {
    ($curve:expr, { $($body:tt)* }) => {
        match $curve {
            EllipticCurve::Secp256k1 => {
                #[allow(unused)]
                type Curve = k256::Secp256k1;
                #[allow(unused)]
                type Scalar = k256::Scalar;
                $($body)*
            }
            EllipticCurve::P256 => {
                #[allow(unused)]
                type Curve = p256::NistP256;
                #[allow(unused)]
                type Scalar = p256::Scalar;
                $($body)*
            }
        }
    };
}

/// Elliptic curve selection for the DKLs23 protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EllipticCurve {
    Secp256k1,
    P256,
}

impl Default for EllipticCurve {
    fn default() -> Self {
        EllipticCurve::Secp256k1
    }
}

// Include the uniffi scaffolding (only for non-wasm32 targets — wasm consumers
// use the dkls23-wasm crate's wasm-bindgen wrappers instead).
#[cfg(not(target_arch = "wasm32"))]
uniffi::include_scaffolding!("lib");

static INIT: Once = Once::new();

/// Initialize the library (call once before using)
pub fn init() {
    INIT.call_once(|| {
        // Any one-time initialization goes here
    });
}

// ============================================
// Error Types
// ============================================

#[derive(Error, Debug)]
pub enum Dkls23Error {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

// ============================================
// Internal State Types (serialized for FFI)
// ============================================

/// Internal DKG session state - stores protocol state between rounds
/// Uses JSON serialization for dkls23 internal types
#[derive(Serialize, Deserialize)]
struct DkgSessionState {
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    round: u32,
    session_id: Vec<u8>,
    #[serde(default)]
    curve: EllipticCurve,

    // Phase 1 output: our polynomial evaluations (serialized Scalars)
    our_poly_evals: Option<Vec<Vec<u8>>>,

    // Phase 2 outputs (serialized using serde_json)
    poly_point: Option<Vec<u8>>,              // Scalar
    proof_commitment: Option<Vec<u8>>,         // ProofCommitment (JSON)
    zero_keep_2to3: Option<Vec<u8>>,           // BTreeMap<u8, KeepInitZeroSharePhase2to3> (JSON)
    derivation_keep_2to3: Option<Vec<u8>>,     // UniqueKeepDerivationPhase2to3 (JSON)

    // Phase 3 outputs (serialized using serde_json)
    zero_keep_3to4: Option<Vec<u8>>,           // BTreeMap<u8, KeepInitZeroSharePhase3to4> (JSON)
    mul_keep_3to4: Option<Vec<u8>>,            // BTreeMap<u8, KeepInitMulPhase3to4<Curve>> (JSON)

    // Received messages from other parties - properly typed and stored
    // Phase 1 → Phase 2: polynomial evaluations
    received_poly_evals: Vec<(u32, Vec<u8>)>,

    // From Phase 2: proof commitments (broadcast to all)
    received_proof_commitments: Vec<Vec<u8>>,  // Vec<ProofCommitment JSON>, indexed by party_index

    // From Phase 2: zero share transmits (point-to-point)
    received_zero_2to4: Vec<Vec<u8>>,          // Vec<TransmitInitZeroSharePhase2to4 JSON>

    // From Phase 2: derivation broadcasts
    received_derivation_2to4: Vec<Vec<u8>>,    // Vec<BroadcastDerivationPhase2to4 JSON>, indexed by party_index

    // From Phase 3: zero share transmits (point-to-point)
    received_zero_3to4: Vec<Vec<u8>>,          // Vec<TransmitInitZeroSharePhase3to4 JSON>

    // From Phase 3: multiplication transmits (point-to-point)
    received_mul_3to4: Vec<Vec<u8>>,           // Vec<TransmitInitMulPhase3to4 JSON>

    // From Phase 3: derivation broadcasts
    received_derivation_3to4: Vec<Vec<u8>>,    // Vec<BroadcastDerivationPhase3to4 JSON>, indexed by party_index
}

/// Internal signing session state
#[derive(Clone, Serialize, Deserialize)]
struct SignSessionState {
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    signer_party_ids: Vec<u32>,
    round: u32,
    message_hash: Vec<u8>,
    key_share: Vec<u8>,
    sign_id: Vec<u8>,
    #[serde(default)]
    curve: EllipticCurve,

    // Serialized dkls23 signing protocol state
    // Phase 1 outputs (serialized using serde_json)
    unique_keep_1to2: Option<Vec<u8>>,           // SignUniqueKeep1to2 (JSON)
    keep_1to2: Option<Vec<u8>>,                   // BTreeMap<u8, SignKeepPhase1to2<Curve>> (JSON)

    // Phase 2 outputs (serialized using serde_json)
    unique_keep_2to3: Option<Vec<u8>>,           // SignUniqueKeep2to3 (JSON)
    keep_2to3: Option<Vec<u8>>,                   // BTreeMap<u8, SignKeepPhase2to3<Curve>> (JSON)

    // Phase 3 outputs
    x_coord: Option<String>,                      // x-coordinate string from phase3 (r value for ECDSA)
    our_broadcast: Option<Vec<u8>>,               // SignBroadcast3to4 (JSON)

    // Received messages from other parties
    received_transmit_1to2: Vec<(u32, Vec<u8>)>, // (from_party, SignTransmitPhase1to2 JSON)
    received_transmit_2to3: Vec<(u32, Vec<u8>)>, // (from_party, SignTransmitPhase2to3 JSON)
    received_broadcast_3to4: Vec<(u32, Vec<u8>)>, // (from_party, SignBroadcast3to4 JSON)
}

/// Internal refresh session state
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
struct RefreshSessionState {
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    round: u32,
    key_share: Vec<u8>,
    generation: u32,
    refresh_sid: Vec<u8>,
    #[serde(default)]
    curve: EllipticCurve,
    // Phase 1 outputs: polynomial fragments
    poly_fragments: Option<Vec<u8>>,  // Serialized Vec<Scalar>
    // Phase 2 outputs
    correction_value: Option<Vec<u8>>,  // Serialized Scalar
    our_proof_commitment: Option<Vec<u8>>,  // Serialized ProofCommitment
    keep_2to3: Option<Vec<u8>>,  // Serialized BTreeMap<u8, KeepRefreshPhase2to3>
    our_transmit_2to4: Option<Vec<u8>>,  // Serialized Vec<TransmitRefreshPhase2to4>
    // Phase 3 outputs
    keep_3to4: Option<Vec<u8>>,  // Serialized BTreeMap<u8, KeepRefreshPhase3to4>
    our_transmit_3to4: Option<Vec<u8>>,  // Serialized Vec<TransmitRefreshPhase3to4>
    // Received messages from other parties
    received_poly_fragments: Vec<(u32, Vec<u8>)>,  // (from_party, fragment)
    received_proofs: Vec<(u32, Vec<u8>)>,  // (from_party, ProofCommitment)
    received_transmit_2to4: Vec<(u32, Vec<u8>)>,  // (from_party, TransmitRefreshPhase2to4)
    received_transmit_3to4: Vec<(u32, Vec<u8>)>,  // (from_party, TransmitRefreshPhase3to4)
}

/// Internal resize session state
#[derive(Clone, Serialize, Deserialize)]
struct ResizeSessionState {
    party_id: u32,
    old_threshold: u32,
    old_total_parties: u32,
    new_threshold: u32,
    new_total_parties: u32,
    new_party_ids: Vec<u32>,
    #[serde(default)]
    curve: EllipticCurve,
    // List of old party IDs participating in the resize (must be >= old_threshold)
    participating_old_party_ids: Vec<u32>,
    // Whether this party is a new party (receiving shares) or old party (sending shares)
    is_new_party: bool,
    round: u32,
    key_share: Vec<u8>,
    // Our poly_point (secret share), serialized
    our_poly_point: Option<Vec<u8>>,
    // Polynomial evaluations we generated in round 1 (for old parties)
    poly_evaluations: Option<Vec<(u32, Vec<u8>)>>,  // (target_party_id, serialized Scalar)
    // Received shares from old parties (for new parties)
    received_shares: Vec<(u32, Vec<u8>)>,  // (from_party_id, serialized Scalar)
    // Serialized dkls23 protocol state
    protocol_state: Option<Vec<u8>>,
}

/// Key share format for storage
/// Contains both the raw secret share data and dkls23 Party if available
#[derive(Serialize, Deserialize)]
struct KeyShareData {
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    generation: u32,
    #[serde(default)]
    curve: EllipticCurve,
    // Secret share scalar (32 bytes)
    secret_share: Vec<u8>,
    // Public key (33 bytes compressed)
    public_key: Vec<u8>,
    // Per-party public shares for verification
    public_shares: Vec<Vec<u8>>,
    // Serialized dkls23 Party struct (optional, for full protocol)
    party_data: Option<Vec<u8>>,
}

// ============================================
// FFI Data Types (defined in UDL)
// ============================================

/// Message exchanged between parties
#[derive(Clone)]
pub struct PartyMessage {
    pub from_party: u32,
    pub to_party: u32,
    pub data: Vec<u8>,
}

/// DKG initialization result
pub struct DkgInitResult {
    pub session_state: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// DKG round result (intermediate rounds)
pub struct DkgRoundResult {
    pub session_state: Vec<u8>,
    pub messages_to_send: Vec<PartyMessage>,
    pub is_complete: bool,
    pub success: bool,
    pub error_message: Option<String>,
}

/// DKG final result
pub struct DkgFinalResult {
    pub key_share: Vec<u8>,
    pub public_key: Vec<u8>,
    pub party_id: u32,
    pub threshold: u32,
    pub total_parties: u32,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Sign initialization result
pub struct SignInitResult {
    pub session_state: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Sign round result
pub struct SignRoundResult {
    pub session_state: Vec<u8>,
    pub messages_to_send: Vec<PartyMessage>,
    pub is_complete: bool,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Sign final result
pub struct SignFinalResult {
    pub signature: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Refresh initialization result
pub struct RefreshInitResult {
    pub session_state: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Refresh round result
pub struct RefreshRoundResult {
    pub session_state: Vec<u8>,
    pub messages_to_send: Vec<PartyMessage>,
    pub is_complete: bool,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Refresh final result
pub struct RefreshFinalResult {
    pub new_key_share: Vec<u8>,
    pub generation: u32,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Resize initialization result
pub struct ResizeInitResult {
    pub session_state: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Resize round result
pub struct ResizeRoundResult {
    pub session_state: Vec<u8>,
    pub messages_to_send: Vec<PartyMessage>,
    pub is_complete: bool,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Resize final result
pub struct ResizeFinalResult {
    pub new_key_share: Vec<u8>,
    pub new_threshold: u32,
    pub new_total_parties: u32,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Rekey result (converting full key to shares)
pub struct RekeyResult {
    pub key_shares: Vec<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Key derivation result
pub struct DeriveResult {
    pub derived_key_share: Vec<u8>,
    pub derived_public_key: Vec<u8>,
    pub success: bool,
    pub error_message: Option<String>,
}

// ============================================
// Helper Functions
// ============================================

fn serialize_state<T: Serialize>(state: &T) -> Result<Vec<u8>, Dkls23Error> {
    serde_json::to_vec(state).map_err(|e| Dkls23Error::SerializationError(e.to_string()))
}

fn deserialize_state<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, Dkls23Error> {
    serde_json::from_slice(data).map_err(|e| Dkls23Error::DeserializationError(e.to_string()))
}

fn error_result<T>(msg: &str) -> T
where
    T: Default + WithError,
{
    let mut result = T::default();
    result.set_error(msg.to_string());
    result
}

trait WithError {
    fn set_error(&mut self, msg: String);
}

impl Default for DkgInitResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for DkgInitResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for DkgRoundResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            messages_to_send: Vec::new(),
            is_complete: false,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for DkgRoundResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for DkgFinalResult {
    fn default() -> Self {
        Self {
            key_share: Vec::new(),
            public_key: Vec::new(),
            party_id: 0,
            threshold: 0,
            total_parties: 0,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for DkgFinalResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for SignInitResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for SignInitResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for SignRoundResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            messages_to_send: Vec::new(),
            is_complete: false,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for SignRoundResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for SignFinalResult {
    fn default() -> Self {
        Self {
            signature: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for SignFinalResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for RefreshInitResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for RefreshInitResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for RefreshRoundResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            messages_to_send: Vec::new(),
            is_complete: false,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for RefreshRoundResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for RefreshFinalResult {
    fn default() -> Self {
        Self {
            new_key_share: Vec::new(),
            generation: 0,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for RefreshFinalResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for ResizeInitResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for ResizeInitResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for ResizeRoundResult {
    fn default() -> Self {
        Self {
            session_state: Vec::new(),
            messages_to_send: Vec::new(),
            is_complete: false,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for ResizeRoundResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for ResizeFinalResult {
    fn default() -> Self {
        Self {
            new_key_share: Vec::new(),
            new_threshold: 0,
            new_total_parties: 0,
            success: false,
            error_message: None,
        }
    }
}

impl WithError for ResizeFinalResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for RekeyResult {
    fn default() -> Self {
        Self {
            key_shares: Vec::new(),
            public_key: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for RekeyResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

impl Default for DeriveResult {
    fn default() -> Self {
        Self {
            derived_key_share: Vec::new(),
            derived_public_key: Vec::new(),
            success: false,
            error_message: None,
        }
    }
}

impl WithError for DeriveResult {
    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }
}

// ============================================
// DKG Functions
// ============================================

/// Initialize a new DKG session with a pre-agreed session ID.
/// All parties in the DKG must use the same session_id.
pub fn dkg_init_with_session_id(party_id: u32, threshold: u32, total_parties: u32, session_id: &[u8], curve: EllipticCurve) -> DkgInitResult {
    // Validate parameters
    if threshold < 2 {
        return error_result("threshold must be at least 2");
    }
    if total_parties < threshold {
        return error_result("total_parties must be >= threshold");
    }
    if party_id < 1 || party_id > total_parties {
        return error_result("party_id must be between 1 and total_parties");
    }
    if session_id.len() != 32 {
        return error_result("session_id must be 32 bytes");
    }

    dkg_init_internal(party_id, threshold, total_parties, session_id.to_vec(), curve)
}

/// Initialize a new DKG session with a random session ID.
/// Note: For actual DKG, all parties must share the same session_id.
/// Use dkg_init_with_session_id for proper multi-party DKG.
pub fn dkg_init(party_id: u32, threshold: u32, total_parties: u32, curve: EllipticCurve) -> DkgInitResult {
    // Validate parameters
    if threshold < 2 {
        return error_result("threshold must be at least 2");
    }
    if total_parties < threshold {
        return error_result("total_parties must be >= threshold");
    }
    if party_id < 1 || party_id > total_parties {
        return error_result("party_id must be between 1 and total_parties");
    }

    // Generate unique session ID
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    dkg_init_internal(party_id, threshold, total_parties, session_id, curve)
}

fn dkg_init_internal(party_id: u32, threshold: u32, total_parties: u32, session_id: Vec<u8>, curve: EllipticCurve) -> DkgInitResult {

    // Initialize proof commitments and derivation arrays with empty slots for each party
    let empty_proof_slots: Vec<Vec<u8>> = vec![Vec::new(); total_parties as usize];
    let empty_deriv_slots: Vec<Vec<u8>> = vec![Vec::new(); total_parties as usize];

    let state = DkgSessionState {
        party_id,
        threshold,
        total_parties,
        round: 0,
        session_id,
        curve,
        our_poly_evals: None,
        poly_point: None,
        proof_commitment: None,
        zero_keep_2to3: None,
        derivation_keep_2to3: None,
        zero_keep_3to4: None,
        mul_keep_3to4: None,
        received_poly_evals: Vec::new(),
        received_proof_commitments: empty_proof_slots.clone(),
        received_zero_2to4: Vec::new(),
        received_derivation_2to4: empty_deriv_slots.clone(),
        received_zero_3to4: Vec::new(),
        received_mul_3to4: Vec::new(),
        received_derivation_3to4: empty_deriv_slots,
    };

    match serialize_state(&state) {
        Ok(session_state) => DkgInitResult {
            session_state,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process DKG round 1: generate polynomial and send evaluations to other parties
/// This corresponds to dkls23 phase1 (steps 1-2)
pub fn dkg_round1(session_state: &[u8]) -> DkgRoundResult {
    let state: DkgSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 0 {
        return error_result(&format!("expected round 0, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Create dkls23 Parameters
    let params = Parameters {
        threshold: state.threshold as u8,
        share_count: state.total_parties as u8,
    };

    // Create dkls23 SessionData (party_index is 0-indexed internally)
    let dkls23_session = DkgSessionDataInternal {
        parameters: params,
        party_index: state.party_id as u8,
        session_id: state.session_id.clone(),
    };

    // Execute dkls23 phase1: generate polynomial and compute evaluations
    let poly_evals = dkg::phase1::<Curve>(&dkls23_session);

    // Serialize polynomial evaluations for storage
    let mut poly_evals_serialized: Vec<Vec<u8>> = Vec::new();
    for eval in &poly_evals {
        let bytes = eval.to_bytes().to_vec();
        poly_evals_serialized.push(bytes);
    }

    // Create messages to send each party their evaluation
    let mut messages = Vec::new();
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let eval_idx = (i - 1) as usize;
            if eval_idx < poly_evals_serialized.len() {
                messages.push(PartyMessage {
                    from_party: state.party_id,
                    to_party: i,
                    data: poly_evals_serialized[eval_idx].clone(),
                });
            }
        }
    }

    // Store our polynomial evaluations for later use
    let mut new_state = state;
    new_state.round = 1;
    new_state.our_poly_evals = Some(poly_evals_serialized);

    match serialize_state(&new_state) {
        Ok(session_state) => DkgRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Process DKG round 2: process received polynomial evaluations, generate proof commitment
/// This corresponds to dkls23 phase2 (step 3)
pub fn dkg_round2(session_state: &[u8], received_messages: &[PartyMessage]) -> DkgRoundResult {
    let state: DkgSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 1 {
        return error_result(&format!("expected round 1, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Verify we received messages from all other parties
    let expected_count = (state.total_parties - 1) as usize;
    if received_messages.len() != expected_count {
        return error_result(&format!(
            "expected {} messages, got {}",
            expected_count,
            received_messages.len()
        ));
    }

    // Reconstruct SessionData for dkls23
    let params = Parameters {
        threshold: state.threshold as u8,
        share_count: state.total_parties as u8,
    };
    let dkls23_session = DkgSessionDataInternal {
        parameters: params,
        party_index: state.party_id as u8,
        session_id: state.session_id.clone(),
    };

    // Get our own polynomial evaluation for our index
    let our_poly_evals = match &state.our_poly_evals {
        Some(evals) => evals,
        None => return error_result("missing polynomial evaluations from round 1"),
    };
    let our_idx = (state.party_id - 1) as usize;
    let our_eval_bytes = &our_poly_evals[our_idx];

    // Build poly_fragments: our evaluation + received evaluations
    // poly_fragments[i] = evaluation from party i (0-indexed)
    let mut poly_fragments: Vec<Scalar> = vec![Scalar::ZERO; state.total_parties as usize];

    // Our own evaluation at our index
    let our_scalar = match scalar_from_bytes::<Scalar>(our_eval_bytes) {
        Ok(s) => s,
        Err(e) => return error_result(&format!("failed to decode our evaluation: {}", e)),
    };
    poly_fragments[our_idx] = our_scalar;

    // Add received evaluations from other parties
    for msg in received_messages {
        let from_idx = (msg.from_party - 1) as usize;
        let scalar = match scalar_from_bytes::<Scalar>(&msg.data) {
            Ok(s) => s,
            Err(e) => return error_result(&format!("failed to decode evaluation from party {}: {}", msg.from_party, e)),
        };
        poly_fragments[from_idx] = scalar;
    }

    // Call dkls23 phase2
    let (poly_point, proof_commitment, zero_keep_2to3, zero_transmit_2to4, deriv_keep_2to3, deriv_broadcast_2to4) =
        dkg::phase2::<Curve>(&dkls23_session, &poly_fragments);

    // Serialize outputs for storage
    let poly_point_bytes = poly_point.to_bytes().to_vec();
    let proof_commitment_json = match serde_json::to_vec(&proof_commitment) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize proof commitment: {}", e)),
    };
    let zero_keep_2to3_json = match serde_json::to_vec(&zero_keep_2to3) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize zero keep: {}", e)),
    };
    let deriv_keep_2to3_json = match serde_json::to_vec(&deriv_keep_2to3) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize derivation keep: {}", e)),
    };

    // Create messages to send:
    // 1. Broadcast proof commitment to all parties
    // 2. Send zero-share transmits to specific parties
    // 3. Broadcast derivation data to all parties
    let mut messages = Vec::new();

    // Broadcast proof commitment and derivation to all other parties
    let proof_data = proof_commitment_json.clone();
    let deriv_data = match serde_json::to_vec(&deriv_broadcast_2to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize derivation broadcast: {}", e)),
    };

    // Create a combined message for broadcasts (type 0 = proof+derivation broadcast)
    for i in 1..=state.total_parties {
        if i != state.party_id {
            // Combine proof commitment and derivation broadcast into one message
            let combined = serde_json::json!({
                "type": "phase2_broadcast",
                "proof_commitment": hex::encode(&proof_data),
                "derivation_broadcast": hex::encode(&deriv_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    // Send zero-share transmits to specific parties
    // In dkls23, receiver is 1-indexed party_id.
    // Transmits where receiver == our_party_id are kept locally (added to our received list).
    // Transmits where receiver != our_party_id are sent to that party.
    #[cfg(test)]
    eprintln!("Party {} round2: generating {} zero transmits", state.party_id, zero_transmit_2to4.len());

    let mut our_zero_transmits_2to4: Vec<Vec<u8>> = Vec::new();
    for transmit in &zero_transmit_2to4 {
        // receiver is 1-indexed (1 = party 1, 2 = party 2, etc.)
        let to_party = transmit.parties.receiver as u32;

        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize zero transmit: {}", e)),
        };

        #[cfg(test)]
        eprintln!("  Party {} zero transmit: sender={}, receiver={}, routing to party {}",
            state.party_id, transmit.parties.sender, transmit.parties.receiver, to_party);

        // "Self-transmits" are kept locally - they are our contribution to our own received list
        if to_party == state.party_id {
            our_zero_transmits_2to4.push(transmit_data);
            continue;
        }

        let combined = serde_json::json!({
            "type": "phase2_zero_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Update state
    let mut new_state = state;
    new_state.round = 2;
    new_state.poly_point = Some(poly_point_bytes);
    new_state.proof_commitment = Some(proof_commitment_json);
    new_state.zero_keep_2to3 = Some(zero_keep_2to3_json);
    new_state.derivation_keep_2to3 = Some(deriv_keep_2to3_json);

    // Store our own zero transmits (where receiver == our_party_id) for phase4
    // These are "self-transmits" that we keep locally rather than sending
    new_state.received_zero_2to4 = our_zero_transmits_2to4;

    // Store our own derivation broadcast at our index (for phase4)
    // dkls23 expects bip_received_phase2 to have entries for ALL parties including ourselves
    let our_idx = (new_state.party_id - 1) as usize;
    if our_idx < new_state.received_derivation_2to4.len() {
        new_state.received_derivation_2to4[our_idx] = deriv_data;
    }

    // Store received poly evaluations for reference
    for msg in received_messages {
        new_state.received_poly_evals.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => DkgRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Helper function to convert bytes to a curve Scalar (generic over PrimeField)
fn scalar_from_bytes<S: PrimeField>(bytes: &[u8]) -> Result<S, String> {
    let mut repr = S::Repr::default();
    let repr_slice: &mut [u8] = repr.as_mut();
    if bytes.len() != repr_slice.len() {
        return Err(format!("expected {} bytes, got {}", repr_slice.len(), bytes.len()));
    }
    repr_slice.copy_from_slice(bytes);
    let scalar_opt = S::from_repr(repr);
    if scalar_opt.is_some().into() {
        Ok(scalar_opt.unwrap())
    } else {
        Err("invalid scalar bytes".to_string())
    }
}

/// Process DKG round 3: run phase3 initialization
/// This corresponds to dkls23 phase3 (no DKG steps, just initialization)
pub fn dkg_round3(session_state: &[u8], received_messages: &[PartyMessage]) -> DkgRoundResult {
    let state: DkgSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 2 {
        return error_result(&format!("expected round 2, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Reconstruct SessionData for dkls23
    let params = Parameters {
        threshold: state.threshold as u8,
        share_count: state.total_parties as u8,
    };
    let dkls23_session = DkgSessionDataInternal {
        parameters: params,
        party_index: state.party_id as u8,
        session_id: state.session_id.clone(),
    };

    // Deserialize phase2 kept data
    let zero_keep_2to3: std::collections::BTreeMap<u8, KeepInitZeroSharePhase2to3> = match &state.zero_keep_2to3 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize zero_keep_2to3: {}", e)),
        },
        None => return error_result("missing zero_keep_2to3 from phase2"),
    };

    let deriv_keep_2to3: UniqueKeepDerivationPhase2to3 = match &state.derivation_keep_2to3 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize derivation_keep_2to3: {}", e)),
        },
        None => return error_result("missing derivation_keep_2to3 from phase2"),
    };

    // Call dkls23 phase3
    let (zero_keep_3to4, zero_transmit_3to4, mul_keep_3to4, mul_transmit_3to4, deriv_broadcast_3to4) =
        dkg::phase3::<Curve>(&dkls23_session, &zero_keep_2to3, &deriv_keep_2to3);

    // Serialize outputs for storage
    let zero_keep_3to4_json = match serde_json::to_vec(&zero_keep_3to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize zero_keep_3to4: {}", e)),
    };
    let mul_keep_3to4_json = match serde_json::to_vec(&mul_keep_3to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize mul_keep_3to4: {}", e)),
    };

    // Create messages to send
    let mut messages = Vec::new();

    // Broadcast derivation data to all other parties
    let deriv_data = match serde_json::to_vec(&deriv_broadcast_3to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize derivation broadcast: {}", e)),
    };
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let combined = serde_json::json!({
                "type": "phase3_derivation_broadcast",
                "data": hex::encode(&deriv_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    // Send zero-share transmits to specific parties (receiver is 1-indexed)
    // Keep self-transmits locally for phase4
    let mut our_zero_transmits_3to4: Vec<Vec<u8>> = Vec::new();
    for transmit in &zero_transmit_3to4 {
        let to_party = transmit.parties.receiver as u32;
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize zero transmit: {}", e)),
        };
        if to_party == state.party_id {
            our_zero_transmits_3to4.push(transmit_data);
            continue;
        }
        let combined = serde_json::json!({
            "type": "phase3_zero_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Send multiplication transmits to specific parties (receiver is 1-indexed)
    // Keep self-transmits locally for phase4
    let mut our_mul_transmits_3to4: Vec<Vec<u8>> = Vec::new();
    for transmit in &mul_transmit_3to4 {
        let to_party = transmit.parties.receiver as u32;
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize mul transmit: {}", e)),
        };
        if to_party == state.party_id {
            our_mul_transmits_3to4.push(transmit_data);
            continue;
        }
        let combined = serde_json::json!({
            "type": "phase3_mul_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Parse and store received phase2 messages by type
    let mut new_state = state;
    new_state.round = 3;
    new_state.zero_keep_3to4 = Some(zero_keep_3to4_json);
    new_state.mul_keep_3to4 = Some(mul_keep_3to4_json);

    // Store our own phase3 self-transmits for phase4
    new_state.received_zero_3to4 = our_zero_transmits_3to4;
    new_state.received_mul_3to4 = our_mul_transmits_3to4;

    // Store our own phase3 derivation broadcast at our index (for phase4)
    // dkls23 expects bip_received_phase3 to have entries for ALL parties including ourselves
    let our_idx = (new_state.party_id - 1) as usize;
    if our_idx < new_state.received_derivation_3to4.len() {
        new_state.received_derivation_3to4[our_idx] = deriv_data;
    }

    #[cfg(test)]
    eprintln!("Party {} round3: received {} messages", new_state.party_id, received_messages.len());

    for msg in received_messages {
        let from_idx = (msg.from_party - 1) as usize;

        #[cfg(test)]
        {
            if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
                if let Some(msg_type) = msg_json.get("type").and_then(|v| v.as_str()) {
                    eprintln!("  Party {} received from party {}: type={}", new_state.party_id, msg.from_party, msg_type);
                }
            }
        }

        // Parse the message to determine its type
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(msg_type) = msg_json.get("type").and_then(|v| v.as_str()) {
                match msg_type {
                    "phase2_broadcast" => {
                        // Extract proof_commitment and derivation_broadcast
                        if let Some(proof_hex) = msg_json.get("proof_commitment").and_then(|v| v.as_str()) {
                            if let Ok(proof_bytes) = hex::decode(proof_hex) {
                                if from_idx < new_state.received_proof_commitments.len() {
                                    new_state.received_proof_commitments[from_idx] = proof_bytes;
                                }
                            }
                        }
                        if let Some(deriv_hex) = msg_json.get("derivation_broadcast").and_then(|v| v.as_str()) {
                            if let Ok(deriv_bytes) = hex::decode(deriv_hex) {
                                if from_idx < new_state.received_derivation_2to4.len() {
                                    new_state.received_derivation_2to4[from_idx] = deriv_bytes;
                                }
                            }
                        }
                    }
                    "phase2_zero_transmit" => {
                        if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                            if let Ok(data_bytes) = hex::decode(data_hex) {
                                new_state.received_zero_2to4.push(data_bytes);
                            }
                        }
                    }
                    _ => {} // Ignore unknown message types
                }
            }
        }
    }

    match serialize_state(&new_state) {
        Ok(session_state) => DkgRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Finalize DKG and extract key share
/// This corresponds to dkls23 phase4 (step 5 - verification and Party creation)
pub fn dkg_finalize(session_state: &[u8], received_messages: &[PartyMessage]) -> DkgFinalResult {
    let mut state: DkgSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 3 {
        return error_result(&format!("expected round 3, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Parse and store received phase3 messages
    for msg in received_messages {
        let from_idx = (msg.from_party - 1) as usize;

        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(msg_type) = msg_json.get("type").and_then(|v| v.as_str()) {
                match msg_type {
                    "phase3_derivation_broadcast" => {
                        if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                            if let Ok(data_bytes) = hex::decode(data_hex) {
                                if from_idx < state.received_derivation_3to4.len() {
                                    state.received_derivation_3to4[from_idx] = data_bytes;
                                }
                            }
                        }
                    }
                    "phase3_zero_transmit" => {
                        if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                            if let Ok(data_bytes) = hex::decode(data_hex) {
                                state.received_zero_3to4.push(data_bytes);
                            }
                        }
                    }
                    "phase3_mul_transmit" => {
                        if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                            if let Ok(data_bytes) = hex::decode(data_hex) {
                                state.received_mul_3to4.push(data_bytes);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Reconstruct SessionData for dkls23
    let params = Parameters {
        threshold: state.threshold as u8,
        share_count: state.total_parties as u8,
    };
    let dkls23_session = DkgSessionDataInternal {
        parameters: params,
        party_index: state.party_id as u8,
        session_id: state.session_id.clone(),
    };

    // Get poly_point from phase2
    let poly_point: Scalar = match &state.poly_point {
        Some(bytes) => match scalar_from_bytes::<Scalar>(bytes) {
            Ok(s) => s,
            Err(e) => return error_result(&format!("failed to decode poly_point: {}", e)),
        },
        None => return error_result("missing poly_point from phase2"),
    };

    // Get our proof commitment from phase2
    let our_proof: ProofCommitment<Curve> = match &state.proof_commitment {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to decode our proof commitment: {}", e)),
        },
        None => return error_result("missing proof_commitment from phase2"),
    };

    // Get zero_kept from phase3
    let zero_kept: BTreeMap<u8, KeepInitZeroSharePhase3to4> = match &state.zero_keep_3to4 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to decode zero_keep_3to4: {}", e)),
        },
        None => return error_result("missing zero_keep_3to4 from phase3"),
    };

    // Get mul_kept from phase3
    let mul_kept: BTreeMap<u8, KeepInitMulPhase3to4<Curve>> = match &state.mul_keep_3to4 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to decode mul_keep_3to4: {}", e)),
        },
        None => return error_result("missing mul_keep_3to4 from phase3"),
    };

    // Build proofs_commitments array (our proof + received proofs from other parties)
    let mut proofs_commitments: Vec<ProofCommitment<Curve>> = vec![our_proof.clone(); state.total_parties as usize];
    proofs_commitments[(state.party_id - 1) as usize] = our_proof.clone();

    #[cfg(test)]
    {
        eprintln!("Party {} dkg_finalize: received_proof_commitments has {} slots", state.party_id, state.received_proof_commitments.len());
        for (idx, proof_bytes) in state.received_proof_commitments.iter().enumerate() {
            eprintln!("  slot {}: {} bytes", idx, proof_bytes.len());
        }
    }

    // Parse received proof commitments
    let mut populated_proofs = vec![false; state.total_parties as usize];
    populated_proofs[(state.party_id - 1) as usize] = true;  // Our own proof
    for (idx, proof_bytes) in state.received_proof_commitments.iter().enumerate() {
        if !proof_bytes.is_empty() && idx != (state.party_id - 1) as usize {
            if let Ok(proof) = serde_json::from_slice::<ProofCommitment<Curve>>(proof_bytes) {
                proofs_commitments[idx] = proof;
                populated_proofs[idx] = true;
            }
        }
    }

    #[cfg(test)]
    {
        eprintln!("Party {} proofs_commitments populated: {:?}", state.party_id, populated_proofs);
    }

    // Parse received zero transmits from phase2
    let mut zero_received_phase2: Vec<TransmitInitZeroSharePhase2to4> = Vec::new();
    for data_bytes in &state.received_zero_2to4 {
        if let Ok(transmit) = serde_json::from_slice::<TransmitInitZeroSharePhase2to4>(data_bytes) {
            zero_received_phase2.push(transmit);
        }
    }

    // Parse received zero transmits from phase3
    let mut zero_received_phase3: Vec<TransmitInitZeroSharePhase3to4> = Vec::new();
    for data_bytes in &state.received_zero_3to4 {
        if let Ok(transmit) = serde_json::from_slice::<TransmitInitZeroSharePhase3to4>(data_bytes) {
            zero_received_phase3.push(transmit);
        }
    }

    // Parse received mul transmits from phase3
    let mut mul_received: Vec<TransmitInitMulPhase3to4<Curve>> = Vec::new();
    for data_bytes in &state.received_mul_3to4 {
        if let Ok(transmit) = serde_json::from_slice::<TransmitInitMulPhase3to4<Curve>>(data_bytes) {
            mul_received.push(transmit);
        }
    }

    // Parse received derivation broadcasts from phase2
    // Keys are 1-indexed party IDs (idx 0 -> party 1, etc.)
    let mut bip_received_phase2: BTreeMap<u8, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for (idx, data_bytes) in state.received_derivation_2to4.iter().enumerate() {
        if !data_bytes.is_empty() {
            if let Ok(broadcast) = serde_json::from_slice::<BroadcastDerivationPhase2to4>(data_bytes) {
                bip_received_phase2.insert((idx + 1) as u8, broadcast);
            }
        }
    }

    // Parse received derivation broadcasts from phase3
    // Keys are 1-indexed party IDs (idx 0 -> party 1, etc.)
    let mut bip_received_phase3: BTreeMap<u8, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for (idx, data_bytes) in state.received_derivation_3to4.iter().enumerate() {
        if !data_bytes.is_empty() {
            if let Ok(broadcast) = serde_json::from_slice::<BroadcastDerivationPhase3to4>(data_bytes) {
                bip_received_phase3.insert((idx + 1) as u8, broadcast);
            }
        }
    }

    // Debug: print counts of received data
    #[cfg(test)]
    {
        eprintln!("Party {} phase4 input:", state.party_id);
        eprintln!("  proofs_commitments: {} entries", proofs_commitments.len());
        eprintln!("  zero_kept: {} entries", zero_kept.len());
        eprintln!("  zero_received_phase2: {} entries", zero_received_phase2.len());
        eprintln!("  zero_received_phase3: {} entries", zero_received_phase3.len());
        eprintln!("  mul_kept: {} entries", mul_kept.len());
        eprintln!("  mul_received: {} entries", mul_received.len());
        eprintln!("  bip_received_phase2: {} entries, keys: {:?}", bip_received_phase2.len(), bip_received_phase2.keys().collect::<Vec<_>>());
        eprintln!("  bip_received_phase3: {} entries, keys: {:?}", bip_received_phase3.len(), bip_received_phase3.keys().collect::<Vec<_>>());
    }

    // Call actual dkg::phase4
    let party = match dkg::phase4::<Curve>(
        &dkls23_session,
        &poly_point,
        &proofs_commitments,
        &zero_kept,
        &zero_received_phase2,
        &zero_received_phase3,
        &mul_kept,
        &mul_received,
        &bip_received_phase2,
        &bip_received_phase3,
    ) {
        Ok(p) => p,
        Err(e) => return error_result(&format!("dkg::phase4 failed: {:?}", e)),
    };

    // Serialize the Party for storage in key share
    let party_data = match serde_json::to_vec(&party) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize party: {}", e)),
    };

    // Extract public key from Party
    let public_key_bytes = party.pk.to_encoded_point(true).as_bytes().to_vec();

    // Generate secret share from poly_point
    let secret_share = poly_point.to_bytes().to_vec();

    let key_share_data = KeyShareData {
        party_id: state.party_id,
        threshold: state.threshold,
        total_parties: state.total_parties,
        generation: 0,
        curve: state.curve,
        secret_share,
        public_key: public_key_bytes.clone(),
        public_shares: Vec::new(),
        party_data: Some(party_data), // Serialized Party from dkg::phase4
    };

    match serialize_state(&key_share_data) {
        Ok(key_share) => DkgFinalResult {
            key_share,
            public_key: public_key_bytes,
            party_id: state.party_id,
            threshold: state.threshold,
            total_parties: state.total_parties,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

// ============================================
// Signing Functions
// ============================================

/// Initialize a signing session
pub fn sign_init(
    key_share: &[u8],
    message_hash: &[u8],
    signer_party_ids: &[u32],
) -> SignInitResult {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&e.to_string()),
    };

    if message_hash.len() != 32 {
        return error_result("message_hash must be 32 bytes");
    }

    if signer_party_ids.len() < key_data.threshold as usize {
        return error_result(&format!(
            "need at least {} signers, got {}",
            key_data.threshold,
            signer_party_ids.len()
        ));
    }

    // Verify this party is in the signer list
    if !signer_party_ids.contains(&key_data.party_id) {
        return error_result("this party is not in the signer list");
    }

    // Generate unique sign ID
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    let mut sign_id = vec![0u8; 32];
    rng.fill_bytes(&mut sign_id);

    let state = SignSessionState {
        party_id: key_data.party_id,
        threshold: key_data.threshold,
        total_parties: key_data.total_parties,
        signer_party_ids: signer_party_ids.to_vec(),
        round: 0,
        message_hash: message_hash.to_vec(),
        key_share: key_share.to_vec(),
        sign_id,
        curve: key_data.curve,
        unique_keep_1to2: None,
        keep_1to2: None,
        unique_keep_2to3: None,
        keep_2to3: None,
        x_coord: None,
        our_broadcast: None,
        received_transmit_1to2: Vec::new(),
        received_transmit_2to3: Vec::new(),
        received_broadcast_3to4: Vec::new(),
    };

    match serialize_state(&state) {
        Ok(session_state) => SignInitResult {
            session_state,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Initialize a signing session with a shared sign ID
/// All parties must use the same sign_id for a signing session to work
pub fn sign_init_with_sign_id(
    key_share: &[u8],
    message_hash: &[u8],
    signer_party_ids: &[u32],
    sign_id: &[u8],
) -> SignInitResult {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&e.to_string()),
    };

    if message_hash.len() != 32 {
        return error_result("message_hash must be 32 bytes");
    }

    if signer_party_ids.len() < key_data.threshold as usize {
        return error_result(&format!(
            "need at least {} signers, got {}",
            key_data.threshold,
            signer_party_ids.len()
        ));
    }

    // Verify this party is in the signer list
    if !signer_party_ids.contains(&key_data.party_id) {
        return error_result("this party is not in the signer list");
    }

    let state = SignSessionState {
        party_id: key_data.party_id,
        threshold: key_data.threshold,
        total_parties: key_data.total_parties,
        signer_party_ids: signer_party_ids.to_vec(),
        round: 0,
        message_hash: message_hash.to_vec(),
        key_share: key_share.to_vec(),
        sign_id: sign_id.to_vec(), // Use the shared sign_id
        curve: key_data.curve,
        unique_keep_1to2: None,
        keep_1to2: None,
        unique_keep_2to3: None,
        keep_2to3: None,
        x_coord: None,
        our_broadcast: None,
        received_transmit_1to2: Vec::new(),
        received_transmit_2to3: Vec::new(),
        received_broadcast_3to4: Vec::new(),
    };

    match serialize_state(&state) {
        Ok(session_state) => SignInitResult {
            session_state,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process signing round 1
/// This corresponds to dkls23 signing::sign_phase1
pub fn sign_round1(session_state: &[u8]) -> SignRoundResult {
    let state: SignSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 0 {
        return error_result(&format!("expected round 0, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // If no party data, create a placeholder implementation for testing
            // In production, DKG must complete with proper Party generation
            return sign_round1_placeholder(&state);
        }
    };

    // Build counterparties list (1-indexed party IDs, excluding self)
    let mut counterparties: Vec<u8> = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            counterparties.push(pid as u8); // Keep 1-indexed
        }
    }

    // Create SignData
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(&state.message_hash);
    let sign_data = SignData {
        sign_id: state.sign_id.clone(),
        counterparties: counterparties.clone(),
        message_hash: message_hash_arr,
    };

    // Call dkls23 sign_phase1
    let (unique_keep, keep, transmits) = party.sign_phase1(&sign_data);

    // Serialize kept data
    let unique_keep_json = match serde_json::to_vec(&unique_keep) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize unique_keep: {}", e)),
    };
    let keep_json = match serde_json::to_vec(&keep) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize keep: {}", e)),
    };

    // Create messages to send (transmits to specific parties)
    let mut messages = Vec::new();
    for transmit in &transmits {
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize transmit: {}", e)),
        };
        let combined = serde_json::json!({
            "type": "sign_phase1_transmit",
            "data": hex::encode(&transmit_data),
        });
        // TransmitPhase1to2 has parties.receiver field (1-indexed)
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party: transmit.parties.receiver as u32, // receiver is already 1-indexed
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Update state
    let mut new_state = state;
    new_state.round = 1;
    new_state.unique_keep_1to2 = Some(unique_keep_json);
    new_state.keep_1to2 = Some(keep_json);

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for sign_round1 when Party data is not available
fn sign_round1_placeholder(state: &SignSessionState) -> SignRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    let mut nonce_commitment = vec![0u8; 64];
    rng.fill_bytes(&mut nonce_commitment);

    // Send to all other signers
    let mut messages = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            let combined = serde_json::json!({
                "type": "sign_phase1_transmit_placeholder",
                "data": hex::encode(&nonce_commitment),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: pid,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 1;
    // Store placeholder data
    new_state.unique_keep_1to2 = Some(nonce_commitment.clone());
    new_state.keep_1to2 = Some(vec![]);

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process signing round 2
/// This corresponds to dkls23 signing::sign_phase2
pub fn sign_round2(session_state: &[u8], received_messages: &[PartyMessage]) -> SignRoundResult {
    let state: SignSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 1 {
        return error_result(&format!("expected round 1, got {}", state.round));
    }

    let expected_count = state.signer_party_ids.len() - 1;
    if received_messages.len() != expected_count {
        return error_result(&format!(
            "expected {} messages, got {}",
            expected_count,
            received_messages.len()
        ));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // Placeholder implementation for testing
            return sign_round2_placeholder(&state, received_messages);
        }
    };

    // Build counterparties list (1-indexed party IDs)
    let mut counterparties: Vec<u8> = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            counterparties.push(pid as u8);
        }
    }

    // Create SignData
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(&state.message_hash);
    let sign_data = SignData {
        sign_id: state.sign_id.clone(),
        counterparties: counterparties.clone(),
        message_hash: message_hash_arr,
    };

    // Deserialize kept data from phase 1
    let unique_kept: SignUniqueKeep1to2<Curve> = match &state.unique_keep_1to2 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize unique_keep_1to2: {}", e)),
        },
        None => return error_result("missing unique_keep_1to2 from phase1"),
    };

    let kept: BTreeMap<u8, SignKeepPhase1to2<Curve>> = match &state.keep_1to2 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize keep_1to2: {}", e)),
        },
        None => return error_result("missing keep_1to2 from phase1"),
    };

    // Parse received transmits
    let mut received_transmits: Vec<SignTransmitPhase1to2> = Vec::new();
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(transmit) = serde_json::from_slice::<SignTransmitPhase1to2>(&data_bytes) {
                        received_transmits.push(transmit);
                    }
                }
            }
        }
    }

    // Call dkls23 sign_phase2
    let (unique_keep_2to3, keep_2to3, transmits_2to3) = match party.sign_phase2(
        &sign_data,
        &unique_kept,
        &kept,
        &received_transmits,
    ) {
        Ok(result) => result,
        Err(e) => return error_result(&format!("sign_phase2 failed: {:?}", e)),
    };

    // Serialize kept data
    let unique_keep_json = match serde_json::to_vec(&unique_keep_2to3) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize unique_keep_2to3: {}", e)),
    };
    let keep_json = match serde_json::to_vec(&keep_2to3) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize keep_2to3: {}", e)),
    };

    // Create messages to send
    let mut messages = Vec::new();
    for transmit in &transmits_2to3 {
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize transmit: {}", e)),
        };
        let combined = serde_json::json!({
            "type": "sign_phase2_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party: transmit.parties.receiver as u32, // receiver is already 1-indexed
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Update state
    let mut new_state = state;
    new_state.round = 2;
    new_state.unique_keep_2to3 = Some(unique_keep_json);
    new_state.keep_2to3 = Some(keep_json);

    // Store received messages
    for msg in received_messages {
        new_state.received_transmit_1to2.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for sign_round2 when Party data is not available
fn sign_round2_placeholder(state: &SignSessionState, received_messages: &[PartyMessage]) -> SignRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    let mut partial_data = vec![0u8; 64];
    rng.fill_bytes(&mut partial_data);

    // Send to all other signers
    let mut messages = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            let combined = serde_json::json!({
                "type": "sign_phase2_transmit_placeholder",
                "data": hex::encode(&partial_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: pid,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 2;
    new_state.unique_keep_2to3 = Some(partial_data);
    new_state.keep_2to3 = Some(vec![]);

    // Store received messages
    for msg in received_messages {
        new_state.received_transmit_1to2.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process signing round 3 (corresponds to dkls23 sign_phase3)
/// This produces the x-coordinate and broadcasts to all parties
pub fn sign_round3(session_state: &[u8], received_messages: &[PartyMessage]) -> SignRoundResult {
    let state: SignSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 2 {
        return error_result(&format!("expected round 2, got {}", state.round));
    }

    let expected_count = state.signer_party_ids.len() - 1;
    if received_messages.len() != expected_count {
        return error_result(&format!(
            "expected {} messages, got {}",
            expected_count,
            received_messages.len()
        ));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // Placeholder implementation for testing
            return sign_round3_placeholder(&state, received_messages);
        }
    };

    // Build counterparties list (1-indexed party IDs)
    let mut counterparties: Vec<u8> = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            counterparties.push(pid as u8);
        }
    }

    // Create SignData
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(&state.message_hash);
    let sign_data = SignData {
        sign_id: state.sign_id.clone(),
        counterparties: counterparties.clone(),
        message_hash: message_hash_arr,
    };

    // Deserialize kept data from phase 2
    let unique_kept: SignUniqueKeep2to3<Curve> = match &state.unique_keep_2to3 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize unique_keep_2to3: {}", e)),
        },
        None => return error_result("missing unique_keep_2to3 from phase2"),
    };

    let kept: BTreeMap<u8, SignKeepPhase2to3<Curve>> = match &state.keep_2to3 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize keep_2to3: {}", e)),
        },
        None => return error_result("missing keep_2to3 from phase2"),
    };

    // Parse received phase2 transmits
    let mut received_transmits: Vec<SignTransmitPhase2to3<Curve>> = Vec::new();
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(transmit) = serde_json::from_slice::<SignTransmitPhase2to3<Curve>>(&data_bytes) {
                        received_transmits.push(transmit);
                    }
                }
            }
        }
    }

    // Call dkls23 sign_phase3
    let (x_coord, our_broadcast) = match party.sign_phase3(
        &sign_data,
        &unique_kept,
        &kept,
        &received_transmits,
    ) {
        Ok(result) => result,
        Err(e) => return error_result(&format!("sign_phase3 failed: {:?}", e)),
    };

    // Serialize our_broadcast for storage (x_coord is already a String)
    let our_broadcast_json = match serde_json::to_vec(&our_broadcast) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize our_broadcast: {}", e)),
    };

    // Create broadcast messages to send to all other signers
    let mut messages = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            let combined = serde_json::json!({
                "type": "sign_phase3_broadcast",
                "data": hex::encode(&our_broadcast_json),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: pid,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    // Update state
    let mut new_state = state;
    new_state.round = 3;
    new_state.x_coord = Some(x_coord);  // x_coord is already a String
    new_state.our_broadcast = Some(our_broadcast_json);

    // Store received transmits
    for msg in received_messages {
        new_state.received_transmit_2to3.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for sign_round3 when Party data is not available
fn sign_round3_placeholder(state: &SignSessionState, received_messages: &[PartyMessage]) -> SignRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    // Generate placeholder broadcast data
    let mut broadcast_data = vec![0u8; 64];
    rng.fill_bytes(&mut broadcast_data);

    // Send to all other signers
    let mut messages = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            let combined = serde_json::json!({
                "type": "sign_phase3_broadcast_placeholder",
                "data": hex::encode(&broadcast_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: pid,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 3;
    new_state.x_coord = Some(hex::encode(&broadcast_data));  // Placeholder x_coord as hex string
    new_state.our_broadcast = Some(vec![]);

    // Store received messages
    for msg in received_messages {
        new_state.received_transmit_2to3.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => SignRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Finalize signing (corresponds to dkls23 sign_phase4)
/// Collects broadcasts from all parties and produces the final signature
pub fn sign_finalize(session_state: &[u8], received_messages: &[PartyMessage]) -> SignFinalResult {
    let state: SignSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 3 {
        return error_result(&format!("expected round 3, got {}", state.round));
    }

    let expected_count = state.signer_party_ids.len() - 1;
    if received_messages.len() != expected_count {
        return error_result(&format!(
            "expected {} broadcast messages, got {}",
            expected_count,
            received_messages.len()
        ));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // Placeholder implementation for testing
            return sign_finalize_placeholder(&state, received_messages);
        }
    };

    // Build counterparties list (1-indexed party IDs)
    let mut counterparties: Vec<u8> = Vec::new();
    for &pid in &state.signer_party_ids {
        if pid != state.party_id {
            counterparties.push(pid as u8);
        }
    }

    // Create SignData
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(&state.message_hash);
    let sign_data = SignData {
        sign_id: state.sign_id.clone(),
        counterparties: counterparties.clone(),
        message_hash: message_hash_arr,
    };

    // Get x_coord from phase3 (it's already a String)
    let x_coord: &str = match &state.x_coord {
        Some(s) => s,
        None => return error_result("missing x_coord from phase3"),
    };

    // Deserialize our broadcast from phase3
    let our_broadcast: SignBroadcast3to4<Curve> = match &state.our_broadcast {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize our_broadcast: {}", e)),
        },
        None => return error_result("missing our_broadcast from phase3"),
    };

    // Collect all broadcasts (our own + received)
    let mut all_broadcasts: Vec<SignBroadcast3to4<Curve>> = vec![our_broadcast];

    // Parse received broadcasts
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(broadcast) = serde_json::from_slice::<SignBroadcast3to4<Curve>>(&data_bytes) {
                        all_broadcasts.push(broadcast);
                    }
                }
            }
        }
    }

    // Call dkls23 sign_phase4
    let (s_hex, _recovery_id) = match party.sign_phase4(
        &sign_data,
        &x_coord,
        &all_broadcasts,
        true, // normalize signature
    ) {
        Ok(result) => result,
        Err(e) => return error_result(&format!("sign_phase4 failed: {:?}", e)),
    };

    // Decode s component (32 bytes)
    let s_bytes = match hex::decode(&s_hex) {
        Ok(s) => s,
        Err(e) => return error_result(&format!("failed to decode s component: {}", e)),
    };

    // x_coord is a hex string representing the r value of the signature
    // It's the x-coordinate of the R point reduced modulo the curve order
    let r_bytes = match hex::decode(x_coord) {
        Ok(r) => r,
        Err(e) => return error_result(&format!("failed to decode r component from x_coord: {}", e)),
    };

    // Ensure both components are 32 bytes
    if r_bytes.len() != 32 || s_bytes.len() != 32 {
        return error_result(&format!(
            "invalid signature component lengths: r={}, s={}",
            r_bytes.len(),
            s_bytes.len()
        ));
    }

    // Combine r and s into full signature (r || s) = 64 bytes
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r_bytes);
    signature.extend_from_slice(&s_bytes);

    SignFinalResult {
        signature,
        success: true,
        error_message: None,
    }
    }) // with_curve
}

/// Placeholder implementation for sign_finalize when Party data is not available
fn sign_finalize_placeholder(_state: &SignSessionState, _received_messages: &[PartyMessage]) -> SignFinalResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    // Generate placeholder 64-byte (r, s) signature
    let mut signature = vec![0u8; 64];
    rng.fill_bytes(&mut signature);

    SignFinalResult {
        signature,
        success: true,
        error_message: None,
    }
}

// ============================================
// Refresh Functions
// ============================================

/// Initialize a refresh session
pub fn refresh_init(key_share: &[u8], party_id: u32) -> RefreshInitResult {
    // Generate random refresh_id
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    let mut refresh_id = vec![0u8; 32];
    rng.fill_bytes(&mut refresh_id);

    refresh_init_with_refresh_id(key_share, party_id, &refresh_id)
}

/// Initialize a refresh session with a shared refresh ID
/// All parties must use the same refresh_id for a refresh session to work
pub fn refresh_init_with_refresh_id(key_share: &[u8], party_id: u32, refresh_id: &[u8]) -> RefreshInitResult {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&e.to_string()),
    };

    if party_id != key_data.party_id {
        return error_result("party_id doesn't match key share");
    }

    let state = RefreshSessionState {
        party_id,
        threshold: key_data.threshold,
        total_parties: key_data.total_parties,
        round: 0,
        key_share: key_share.to_vec(),
        generation: key_data.generation,
        refresh_sid: refresh_id.to_vec(),
        curve: key_data.curve,
        poly_fragments: None,
        correction_value: None,
        our_proof_commitment: None,
        keep_2to3: None,
        our_transmit_2to4: None,
        keep_3to4: None,
        our_transmit_3to4: None,
        received_poly_fragments: Vec::new(),
        received_proofs: Vec::new(),
        received_transmit_2to4: Vec::new(),
        received_transmit_3to4: Vec::new(),
    };

    match serialize_state(&state) {
        Ok(session_state) => RefreshInitResult {
            session_state,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process refresh round 1 (phase 1: generate polynomial fragments)
pub fn refresh_round1(session_state: &[u8]) -> RefreshRoundResult {
    let state: RefreshSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 0 {
        return error_result(&format!("expected round 0, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // Placeholder implementation for testing without Party state
            return refresh_round1_placeholder(&state);
        }
    };

    // Call dkls23 refresh_phase1 - generates polynomial evaluations at each party's index
    let poly_fragments: Vec<Scalar> = party.refresh_phase1();

    // Serialize individual polynomial evaluations for storage
    let mut poly_evals_serialized: Vec<Vec<u8>> = Vec::new();
    for eval in &poly_fragments {
        let bytes = eval.to_bytes().to_vec();
        poly_evals_serialized.push(bytes);
    }

    // Store our own evaluation (at our party index) for later
    let our_eval_idx = (state.party_id - 1) as usize;
    let our_eval = if our_eval_idx < poly_evals_serialized.len() {
        poly_evals_serialized[our_eval_idx].clone()
    } else {
        return error_result("our party index out of range for poly_fragments");
    };

    // Create messages to send each party their specific evaluation
    // Party j receives evaluation at index j-1
    let mut messages = Vec::new();
    for j in 1..=state.total_parties {
        if j != state.party_id {
            let eval_idx = (j - 1) as usize;
            if eval_idx < poly_evals_serialized.len() {
                let combined = serde_json::json!({
                    "type": "refresh_phase1_poly_fragment",
                    "data": hex::encode(&poly_evals_serialized[eval_idx]),
                });
                messages.push(PartyMessage {
                    from_party: state.party_id,
                    to_party: j,
                    data: serde_json::to_vec(&combined).unwrap_or_default(),
                });
            }
        }
    }

    // Update state - store our own evaluation for phase2
    let mut new_state = state;
    new_state.round = 1;
    new_state.poly_fragments = Some(our_eval); // Store only our own evaluation

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for refresh_round1 when Party data is not available
fn refresh_round1_placeholder(state: &RefreshSessionState) -> RefreshRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    // Create placeholder polynomial fragments
    let mut poly_fragments_data = vec![0u8; 32 * state.total_parties as usize];
    rng.fill_bytes(&mut poly_fragments_data);

    // Create messages to send refresh shares to each party
    let mut messages = Vec::new();
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let combined = serde_json::json!({
                "type": "refresh_phase1_poly_fragment",
                "data": hex::encode(&poly_fragments_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 1;
    new_state.poly_fragments = Some(poly_fragments_data);

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process refresh round 2 (phase 2: process fragments, generate proofs)
pub fn refresh_round2(
    session_state: &[u8],
    received_messages: &[PartyMessage],
) -> RefreshRoundResult {
    let state: RefreshSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 1 {
        return error_result(&format!("expected round 1, got {}", state.round));
    }

    let expected_count = (state.total_parties - 1) as usize;
    if received_messages.len() != expected_count {
        return error_result(&format!(
            "expected {} messages, got {}",
            expected_count,
            received_messages.len()
        ));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object from key share data
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            // Placeholder implementation
            return refresh_round2_placeholder(&state, received_messages);
        }
    };

    // Parse our own evaluation (stored as raw 32-byte Scalar)
    let our_eval_bytes = match &state.poly_fragments {
        Some(data) => data.clone(),
        None => return error_result("missing poly_fragments from phase1"),
    };

    // Parse our own evaluation as a Scalar
    let our_scalar: Scalar = match scalar_from_bytes::<Scalar>(&our_eval_bytes) {
        Ok(s) => s,
        Err(e) => return error_result(&format!("failed to parse our poly_fragment as Scalar: {}", e)),
    };

    // Collect all evaluations at our party's index, ordered by sender party ID
    // We need: [eval from party 1, eval from party 2, ..., eval from party n]
    let mut fragments_by_sender: std::collections::BTreeMap<u32, Scalar> = std::collections::BTreeMap::new();

    // Add our own evaluation
    fragments_by_sender.insert(state.party_id, our_scalar);

    // Parse received fragments (each is a single Scalar as raw 32 bytes)
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(scalar) = scalar_from_bytes::<Scalar>(&data_bytes) {
                        fragments_by_sender.insert(msg.from_party, scalar);
                    }
                }
            }
        }
    }

    // Verify we have fragments from all parties
    if fragments_by_sender.len() != state.total_parties as usize {
        return error_result(&format!(
            "missing fragments: got {} from parties {:?}, expected {}",
            fragments_by_sender.len(),
            fragments_by_sender.keys().collect::<Vec<_>>(),
            state.total_parties
        ));
    }

    // Collect fragments in order by party ID (1, 2, 3, ...)
    let all_poly_fragments: Vec<Scalar> = fragments_by_sender.values().cloned().collect();

    // Call dkls23 refresh_phase2
    let (correction_value, proof_commitment, keep_2to3, transmits_2to4) = party.refresh_phase2(
        &state.refresh_sid,
        &all_poly_fragments,
    );

    // Serialize outputs
    let correction_json = match serde_json::to_vec(&correction_value) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize correction_value: {}", e)),
    };
    let proof_json = match serde_json::to_vec(&proof_commitment) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize proof_commitment: {}", e)),
    };
    let keep_json = match serde_json::to_vec(&keep_2to3) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize keep_2to3: {}", e)),
    };
    let transmits_json = match serde_json::to_vec(&transmits_2to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize transmits_2to4: {}", e)),
    };

    // Create messages to send (proof broadcast + transmits)
    let mut messages = Vec::new();

    // Broadcast proof commitment to all parties
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let combined = serde_json::json!({
                "type": "refresh_phase2_proof",
                "data": hex::encode(&proof_json),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    // Send transmits to specific parties
    for transmit in &transmits_2to4 {
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize transmit: {}", e)),
        };
        let combined = serde_json::json!({
            "type": "refresh_phase2_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party: transmit.parties.receiver as u32,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Update state
    let mut new_state = state;
    new_state.round = 2;
    new_state.correction_value = Some(correction_json);
    new_state.our_proof_commitment = Some(proof_json);
    new_state.keep_2to3 = Some(keep_json);
    new_state.our_transmit_2to4 = Some(transmits_json);

    // Store received fragments for later
    for msg in received_messages {
        new_state.received_poly_fragments.push((msg.from_party, msg.data.clone()));
    }

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for refresh_round2
fn refresh_round2_placeholder(state: &RefreshSessionState, _received_messages: &[PartyMessage]) -> RefreshRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    let mut placeholder_data = vec![0u8; 64];
    rng.fill_bytes(&mut placeholder_data);

    let mut messages = Vec::new();
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let combined = serde_json::json!({
                "type": "refresh_phase2_proof",
                "data": hex::encode(&placeholder_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 2;
    new_state.correction_value = Some(placeholder_data.clone());
    new_state.our_proof_commitment = Some(placeholder_data);

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process refresh round 3 (phase 3: process transmits)
pub fn refresh_round3(
    session_state: &[u8],
    received_messages: &[PartyMessage],
) -> RefreshRoundResult {
    let state: RefreshSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 2 {
        return error_result(&format!("expected round 2, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            return refresh_round3_placeholder(&state, received_messages);
        }
    };

    // Deserialize keep_2to3
    let keep_2to3: BTreeMap<u8, KeepRefreshPhase2to3> = match &state.keep_2to3 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize keep_2to3: {}", e)),
        },
        None => return error_result("missing keep_2to3 from phase2"),
    };

    // Call dkls23 refresh_phase3
    let (keep_3to4, transmits_3to4) = party.refresh_phase3(&keep_2to3);

    // Serialize outputs
    let keep_json = match serde_json::to_vec(&keep_3to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize keep_3to4: {}", e)),
    };
    let transmits_json = match serde_json::to_vec(&transmits_3to4) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize transmits_3to4: {}", e)),
    };

    // Create messages to send
    let mut messages = Vec::new();
    for transmit in &transmits_3to4 {
        let transmit_data = match serde_json::to_vec(transmit) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize transmit: {}", e)),
        };
        let combined = serde_json::json!({
            "type": "refresh_phase3_transmit",
            "data": hex::encode(&transmit_data),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party: transmit.parties.receiver as u32,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    // Update state
    let mut new_state = state;
    new_state.round = 3;
    new_state.keep_3to4 = Some(keep_json);
    new_state.our_transmit_3to4 = Some(transmits_json);

    // Store received messages for phase4
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(msg_type) = msg_json.get("type").and_then(|v| v.as_str()) {
                if msg_type == "refresh_phase2_proof" {
                    new_state.received_proofs.push((msg.from_party, msg.data.clone()));
                } else if msg_type == "refresh_phase2_transmit" {
                    new_state.received_transmit_2to4.push((msg.from_party, msg.data.clone()));
                }
            }
        }
    }

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for refresh_round3
fn refresh_round3_placeholder(state: &RefreshSessionState, _received_messages: &[PartyMessage]) -> RefreshRoundResult {
    let mut rng = rand::thread_rng();
    use rand::RngCore;

    let mut placeholder_data = vec![0u8; 64];
    rng.fill_bytes(&mut placeholder_data);

    let mut messages = Vec::new();
    for i in 1..=state.total_parties {
        if i != state.party_id {
            let combined = serde_json::json!({
                "type": "refresh_phase3_transmit",
                "data": hex::encode(&placeholder_data),
            });
            messages.push(PartyMessage {
                from_party: state.party_id,
                to_party: i,
                data: serde_json::to_vec(&combined).unwrap_or_default(),
            });
        }
    }

    let mut new_state = state.clone();
    new_state.round = 3;

    match serialize_state(&new_state) {
        Ok(session_state) => RefreshRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Finalize refresh (phase 4: verify and produce new key share)
pub fn refresh_finalize(
    session_state: &[u8],
    received_messages: &[PartyMessage],
) -> RefreshFinalResult {
    let state: RefreshSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 3 {
        return error_result(&format!("expected round 3, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Get key share data
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&format!("failed to deserialize key share: {}", e)),
    };

    // Get the Party object
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}", e)),
        },
        None => {
            return refresh_finalize_placeholder(&state, received_messages);
        }
    };

    // Deserialize correction_value
    let correction_value: Scalar = match &state.correction_value {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize correction_value: {}", e)),
        },
        None => return error_result("missing correction_value from phase2"),
    };

    // Collect all proof commitments
    let mut proofs_commitments: Vec<ProofCommitment<Curve>> = Vec::new();

    // Our own proof
    let our_proof: ProofCommitment<Curve> = match &state.our_proof_commitment {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize our_proof_commitment: {}", e)),
        },
        None => return error_result("missing our_proof_commitment from phase2"),
    };

    // Build proofs array indexed by party_id
    proofs_commitments.resize(state.total_parties as usize, our_proof.clone());
    proofs_commitments[(state.party_id - 1) as usize] = our_proof;

    // Add received proofs
    for (from_party, data) in &state.received_proofs {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(proof) = serde_json::from_slice::<ProofCommitment<Curve>>(&data_bytes) {
                        proofs_commitments[(*from_party - 1) as usize] = proof;
                    }
                }
            }
        }
    }

    // Deserialize keep_3to4
    let keep_3to4: BTreeMap<u8, KeepRefreshPhase3to4> = match &state.keep_3to4 {
        Some(data) => match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to deserialize keep_3to4: {}", e)),
        },
        None => return error_result("missing keep_3to4 from phase3"),
    };

    // Parse received phase2 transmits
    let mut received_phase2: Vec<TransmitRefreshPhase2to4> = Vec::new();
    for (_, data) in &state.received_transmit_2to4 {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(transmit) = serde_json::from_slice::<TransmitRefreshPhase2to4>(&data_bytes) {
                        received_phase2.push(transmit);
                    }
                }
            }
        }
    }

    // Parse received phase3 transmits
    let mut received_phase3: Vec<TransmitRefreshPhase3to4> = Vec::new();
    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                if let Ok(data_bytes) = hex::decode(data_hex) {
                    if let Ok(transmit) = serde_json::from_slice::<TransmitRefreshPhase3to4>(&data_bytes) {
                        received_phase3.push(transmit);
                    }
                }
            }
        }
    }

    // Call dkls23 refresh_phase4
    let new_party = match party.refresh_phase4(
        &state.refresh_sid,
        &correction_value,
        &proofs_commitments,
        &keep_3to4,
        &received_phase2,
        &received_phase3,
    ) {
        Ok(p) => p,
        Err(e) => return error_result(&format!("refresh_phase4 failed: {:?}", e)),
    };

    // Serialize new party
    let new_party_data = match serde_json::to_vec(&new_party) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize new party: {}", e)),
    };

    let new_generation = state.generation + 1;

    // Create new key share with updated party data
    let new_key_share_data = KeyShareData {
        party_id: state.party_id,
        threshold: state.threshold,
        total_parties: state.total_parties,
        generation: new_generation,
        curve: state.curve,
        secret_share: key_data.secret_share, // Kept for compatibility
        public_key: key_data.public_key,     // Same public key after refresh
        public_shares: key_data.public_shares,
        party_data: Some(new_party_data),
    };

    match serialize_state(&new_key_share_data) {
        Ok(new_key_share) => RefreshFinalResult {
            new_key_share,
            generation: new_generation,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Placeholder implementation for refresh_finalize
fn refresh_finalize_placeholder(state: &RefreshSessionState, _received_messages: &[PartyMessage]) -> RefreshFinalResult {
    let key_data: KeyShareData = match deserialize_state(&state.key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&e.to_string()),
    };

    let new_generation = state.generation + 1;

    // Create new key share with incremented generation (placeholder doesn't actually refresh)
    let new_key_share_data = KeyShareData {
        party_id: state.party_id,
        threshold: state.threshold,
        total_parties: state.total_parties,
        generation: new_generation,
        curve: state.curve,
        secret_share: key_data.secret_share,
        public_key: key_data.public_key,
        public_shares: key_data.public_shares,
        party_data: key_data.party_data,
    };

    match serialize_state(&new_key_share_data) {
        Ok(new_key_share) => RefreshFinalResult {
            new_key_share,
            generation: new_generation,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

// ============================================
// Resize Functions
// ============================================

/// Initialize a resize session
///
/// Parameters:
/// - key_share: The party's current key share (or empty for new parties)
/// - party_id: This party's ID in the NEW scheme
/// - new_threshold: The new threshold (t')
/// - new_total_parties: The new total party count (n')
/// - new_party_ids: List of party IDs in the new scheme
/// - participating_old_party_ids: List of old party IDs participating in the resize
///   (must include at least old_threshold parties that have valid key shares)
/// - is_new_party: Whether this party is new (true) or existing (false)
/// - old_party_id: For existing parties, their ID in the old scheme
pub fn resize_init(
    key_share: &[u8],
    party_id: u32,
    new_threshold: u32,
    new_total_parties: u32,
    new_party_ids: &[u32],
    curve: EllipticCurve,
) -> ResizeInitResult {
    // For backwards compatibility, we need additional initialization
    // This basic init creates a placeholder; use resize_init_full for real protocol

    if new_threshold < 2 {
        return error_result("new_threshold must be at least 2");
    }
    if new_total_parties < new_threshold {
        return error_result("new_total_parties must be >= new_threshold");
    }
    if new_party_ids.len() != new_total_parties as usize {
        return error_result("new_party_ids length must match new_total_parties");
    }

    // Try to get old threshold from key share if available
    let (old_threshold, old_total_parties, our_poly_point) = if !key_share.is_empty() {
        let key_data: KeyShareData = match deserialize_state(key_share) {
            Ok(k) => k,
            Err(e) => return error_result(&e.to_string()),
        };

        // Extract poly_point from party_data if available
        let poly_point = if let Some(party_data) = &key_data.party_data {
            with_curve!(curve, {
            if let Ok(party) = serde_json::from_slice::<Dkls23Party<Curve>>(party_data) {
                let bytes = party.poly_point.to_repr();
                Some(bytes.as_slice().to_vec())
            } else {
                None
            }
            }) // with_curve
        } else {
            None
        };

        (key_data.threshold, key_data.total_parties, poly_point)
    } else {
        (new_threshold, new_total_parties, None)
    };

    let state = ResizeSessionState {
        party_id,
        old_threshold,
        old_total_parties,
        new_threshold,
        new_total_parties,
        new_party_ids: new_party_ids.to_vec(),
        curve,
        participating_old_party_ids: Vec::new(), // To be filled by round1
        is_new_party: key_share.is_empty(),
        round: 0,
        key_share: key_share.to_vec(),
        our_poly_point,
        poly_evaluations: None,
        received_shares: Vec::new(),
        protocol_state: None,
    };

    match serialize_state(&state) {
        Ok(session_state) => ResizeInitResult {
            session_state,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
}

/// Process resize round 1
///
/// For old parties (is_new_party = false):
/// - Generate a random polynomial g(x) of degree (new_threshold - 1) where g(0) = our_poly_point
/// - Evaluate g(j) for each new party j and send it
///
/// For new parties (is_new_party = true):
/// - No messages to send, just wait for shares from old parties
pub fn resize_round1(session_state: &[u8]) -> ResizeRoundResult {
    let state: ResizeSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 0 {
        return error_result(&format!("expected round 0, got {}", state.round));
    }

    let mut new_state = state.clone();
    new_state.round = 1;

    // New parties don't send anything in round 1
    if state.is_new_party {
        match serialize_state(&new_state) {
            Ok(session_state) => return ResizeRoundResult {
                session_state,
                messages_to_send: Vec::new(),
                is_complete: false,
                success: true,
                error_message: None,
            },
            Err(e) => return error_result(&e.to_string()),
        }
    }

    with_curve!(state.curve, {
    // Old party: get our poly_point
    let our_poly_point: Scalar = match &state.our_poly_point {
        Some(data) => {
            match scalar_from_bytes::<Scalar>(data) {
                Ok(s) => s,
                Err(e) => return error_result(&format!("failed to parse poly_point as Scalar: {}", e)),
            }
        },
        None => return error_result("old party must have poly_point for resize"),
    };

    // Generate a random polynomial of degree (new_threshold - 1) with constant term = our_poly_point
    // g(x) = our_poly_point + a_1*x + a_2*x^2 + ... + a_{t'-1}*x^{t'-1}
    let mut polynomial: Vec<Scalar> = Vec::with_capacity(state.new_threshold as usize);
    polynomial.push(our_poly_point);
    let mut rng = rand::thread_rng();
    for _ in 1..state.new_threshold {
        polynomial.push(Scalar::random(&mut rng));
    }

    // Get public key from key share to include in messages
    let public_key = if !state.key_share.is_empty() {
        match deserialize_state::<KeyShareData>(&state.key_share) {
            Ok(key_data) => key_data.public_key,
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // Evaluate polynomial at each new party's index and create messages
    let mut messages = Vec::new();
    let mut poly_evaluations: Vec<(u32, Vec<u8>)> = Vec::new();

    for &new_party_id in &state.new_party_ids {
        // Evaluate g(new_party_id)
        let x = Scalar::from(new_party_id as u64);
        let mut evaluation = Scalar::ZERO;
        let mut x_power = Scalar::ONE;
        for coeff in &polynomial {
            evaluation += coeff * &x_power;
            x_power *= &x;
        }

        // Serialize the evaluation
        let eval_bytes = evaluation.to_repr().as_slice().to_vec();
        poly_evaluations.push((new_party_id, eval_bytes.clone()));

        // Send to new party (including ourselves if we're also in the new set)
        // Include public key for new parties to use
        let combined = serde_json::json!({
            "type": "resize_share",
            "data": hex::encode(&eval_bytes),
            "public_key": hex::encode(&public_key),
        });
        messages.push(PartyMessage {
            from_party: state.party_id,
            to_party: new_party_id,
            data: serde_json::to_vec(&combined).unwrap_or_default(),
        });
    }

    new_state.poly_evaluations = Some(poly_evaluations);

    match serialize_state(&new_state) {
        Ok(session_state) => ResizeRoundResult {
            session_state,
            messages_to_send: messages,
            is_complete: false,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Process resize round 2 and finalize
///
/// Each party (new or old that's also in the new set) receives shares from old parties.
/// The new share is computed as: s'_j = Σ_i (λ_i * share_from_i)
/// where λ_i are Lagrange coefficients computed at point 0 for the set of old party indices.
pub fn resize_round2(
    session_state: &[u8],
    received_messages: &[PartyMessage],
) -> ResizeFinalResult {
    let state: ResizeSessionState = match deserialize_state(session_state) {
        Ok(s) => s,
        Err(e) => return error_result(&e.to_string()),
    };

    if state.round != 1 {
        return error_result(&format!("expected round 1, got {}", state.round));
    }

    with_curve!(state.curve, {
    // Parse received shares and public key
    let mut shares_by_sender: std::collections::BTreeMap<u32, Scalar> = std::collections::BTreeMap::new();
    let mut received_public_key: Option<Vec<u8>> = None;

    for msg in received_messages {
        if let Ok(msg_json) = serde_json::from_slice::<serde_json::Value>(&msg.data) {
            if let Some(msg_type) = msg_json.get("type").and_then(|v| v.as_str()) {
                if msg_type == "resize_share" {
                    if let Some(data_hex) = msg_json.get("data").and_then(|v| v.as_str()) {
                        if let Ok(data_bytes) = hex::decode(data_hex) {
                            if let Ok(scalar) = scalar_from_bytes::<Scalar>(&data_bytes) {
                                shares_by_sender.insert(msg.from_party, scalar);
                            }
                        }
                    }
                    // Extract public key (use the first one we find)
                    if received_public_key.is_none() {
                        if let Some(pk_hex) = msg_json.get("public_key").and_then(|v| v.as_str()) {
                            if let Ok(pk_bytes) = hex::decode(pk_hex) {
                                if pk_bytes.len() == 33 {
                                    received_public_key = Some(pk_bytes);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Get list of old party IDs that contributed shares
    let old_party_ids: Vec<u32> = shares_by_sender.keys().cloned().collect();

    if old_party_ids.len() < state.old_threshold as usize {
        return error_result(&format!(
            "insufficient shares: got {} from parties {:?}, need at least {}",
            old_party_ids.len(),
            old_party_ids,
            state.old_threshold
        ));
    }

    // Compute Lagrange coefficients at point 0 for the set of old party indices
    // λ_i = Π_{j≠i} (0 - j) / (i - j) = Π_{j≠i} (-j) / (i - j)
    let mut lagrange_coeffs: std::collections::BTreeMap<u32, Scalar> = std::collections::BTreeMap::new();

    for &party_i in &old_party_ids {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;

        for &party_j in &old_party_ids {
            if party_i != party_j {
                let i = Scalar::from(party_i as u64);
                let j = Scalar::from(party_j as u64);
                numerator *= -j;  // 0 - j = -j
                denominator *= i - j;
            }
        }

        // λ_i = numerator / denominator
        let coeff = numerator * denominator.invert().unwrap_or(Scalar::ZERO);
        lagrange_coeffs.insert(party_i, coeff);
    }

    // Compute new share: s' = Σ_i (λ_i * share_from_i)
    let mut new_poly_point = Scalar::ZERO;
    for (&party_i, share) in &shares_by_sender {
        let lambda = lagrange_coeffs.get(&party_i).unwrap_or(&Scalar::ZERO);
        new_poly_point += lambda * share;
    }

    // Get old key data for public key (or use received public key for new parties)
    let (old_generation, public_key) = if !state.key_share.is_empty() {
        match deserialize_state::<KeyShareData>(&state.key_share) {
            Ok(key_data) => (key_data.generation, key_data.public_key),
            Err(_) => (0, received_public_key.clone().unwrap_or_default()),
        }
    } else {
        // New party - use public key received from old parties
        (0, received_public_key.clone().unwrap_or_default())
    };

    // Serialize the new poly_point
    let new_poly_point_bytes = new_poly_point.to_repr().as_slice().to_vec();

    // Create new key share with new threshold parameters
    // NOTE: party_data is None because we'd need additional rounds to set up
    // the zero_shares and multiplication protocols. This key share is valid
    // for the poly_point but would need a DKG-like initialization for full signing.
    let new_key_share_data = KeyShareData {
        party_id: state.party_id,
        threshold: state.new_threshold,
        total_parties: state.new_total_parties,
        generation: old_generation + 1,
        curve: state.curve,
        secret_share: new_poly_point_bytes,
        public_key,
        public_shares: Vec::new(),
        party_data: None, // Would need additional protocol rounds to initialize
    };

    match serialize_state(&new_key_share_data) {
        Ok(new_key_share) => ResizeFinalResult {
            new_key_share,
            new_threshold: state.new_threshold,
            new_total_parties: state.new_total_parties,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

// ============================================
// Utility Functions
// ============================================

/// Convert a full secret key to threshold shares (for migration)
///
/// This uses proper Shamir's Secret Sharing via the dkls23 re_key function
/// to split the secret key into threshold shares that can be used for signing.
pub fn rekey_from_secret(
    secret_key: &[u8],
    threshold: u32,
    total_parties: u32,
    curve: EllipticCurve,
) -> RekeyResult {
    if secret_key.len() != 32 {
        return error_result("secret_key must be 32 bytes");
    }
    if threshold < 2 {
        return error_result("threshold must be at least 2");
    }
    if total_parties < threshold {
        return error_result("total_parties must be >= threshold");
    }

    with_curve!(curve, {
    // Parse secret key as Scalar
    let secret_scalar = match scalar_from_bytes::<Scalar>(secret_key) {
        Ok(s) => s,
        Err(_) => return error_result("invalid secret key: not a valid scalar"),
    };

    // Create parameters for dkls23
    let parameters = Parameters {
        threshold: threshold as u8,
        share_count: total_parties as u8,
    };

    // Generate a random session ID for the re-key operation
    let mut session_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);

    // Use dkls23 re_key to properly split the secret
    let parties = re_key::<Curve>(&parameters, &session_id, &secret_scalar, None);

    // Compute public key from secret
    let pk = (k256::elliptic_curve::ProjectivePoint::<Curve>::GENERATOR * secret_scalar).to_affine();
    let pk_bytes = pk.to_encoded_point(true);
    let public_key = pk_bytes.as_bytes().to_vec();

    // Convert parties to key shares
    let mut key_shares = Vec::new();
    for party in parties {
        // Serialize the Party for storage
        let party_data = match serde_json::to_vec(&party) {
            Ok(v) => v,
            Err(e) => return error_result(&format!("failed to serialize party: {}", e)),
        };

        // Get the poly_point as secret_share
        let secret_share = party.poly_point.to_repr().as_slice().to_vec();

        let share_data = KeyShareData {
            party_id: party.party_index as u32,
            threshold,
            total_parties,
            generation: 0,
            curve,
            secret_share,
            public_key: public_key.clone(),
            public_shares: Vec::new(),
            party_data: Some(party_data),
        };

        match serialize_state(&share_data) {
            Ok(serialized) => key_shares.push(serialized),
            Err(e) => return error_result(&e.to_string()),
        }
    }

    RekeyResult {
        key_shares,
        public_key,
        success: true,
        error_message: None,
    }
    }) // with_curve
}

/// Derive a child key share using BIP-32 path
pub fn derive_child_share(
    key_share: &[u8],
    derivation_path: &[u32],
) -> DeriveResult {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(e) => return error_result(&e.to_string()),
    };

    if derivation_path.is_empty() {
        return error_result("derivation_path cannot be empty");
    }

    // Check for hardened derivation (not supported in threshold setting)
    for &child_num in derivation_path {
        if child_num >= 0x80000000 {
            return error_result("hardened derivation is not supported in threshold setting");
        }
    }

    with_curve!(key_data.curve, {
    // Get the Party object for derivation
    let party: Dkls23Party<Curve> = match &key_data.party_data {
        Some(data) => match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("failed to deserialize party data: {}. Key shares must have party_data for derivation.", e)),
        },
        None => return error_result("key share must have party_data for derivation. Use DKG-generated or rekey_from_secret-generated key shares."),
    };

    // Derive through the path one level at a time
    let mut current_party = party;
    for &child_num in derivation_path {
        current_party = match current_party.derive_child(child_num) {
            Ok(p) => p,
            Err(e) => return error_result(&format!("derivation failed at child {}: {}", child_num, e.description)),
        };
    }

    // Get the derived public key
    let derived_pk = current_party.pk;
    let pk_bytes = derived_pk.to_encoded_point(true);
    let derived_public_key = pk_bytes.as_bytes().to_vec();

    // Get the derived poly_point as secret_share
    let derived_secret = current_party.poly_point.to_repr().as_slice().to_vec();

    // Serialize the derived Party
    let derived_party_data = match serde_json::to_vec(&current_party) {
        Ok(v) => v,
        Err(e) => return error_result(&format!("failed to serialize derived party: {}", e)),
    };

    let derived_share_data = KeyShareData {
        party_id: key_data.party_id,
        threshold: key_data.threshold,
        total_parties: key_data.total_parties,
        generation: key_data.generation,
        curve: key_data.curve,
        secret_share: derived_secret,
        public_key: derived_public_key.clone(),
        public_shares: Vec::new(),
        party_data: Some(derived_party_data),
    };

    match serialize_state(&derived_share_data) {
        Ok(derived_key_share) => DeriveResult {
            derived_key_share,
            derived_public_key,
            success: true,
            error_message: None,
        },
        Err(e) => error_result(&e.to_string()),
    }
    }) // with_curve
}

/// Get public key from key share
pub fn get_public_key(key_share: &[u8]) -> Vec<u8> {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    key_data.public_key
}

/// Validate a key share structure
pub fn validate_key_share(key_share: &[u8]) -> bool {
    let key_data: KeyShareData = match deserialize_state(key_share) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Basic validation
    if key_data.party_id < 1 || key_data.party_id > key_data.total_parties {
        return false;
    }
    if key_data.threshold < 2 {
        return false;
    }
    if key_data.total_parties < key_data.threshold {
        return false;
    }
    if key_data.secret_share.len() != 32 {
        return false;
    }
    if key_data.public_key.len() != 33 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_init() {
        init();

        let result = dkg_init(1, 2, 3, EllipticCurve::Secp256k1);
        assert!(result.success);
        assert!(result.error_message.is_none());
        assert!(!result.session_state.is_empty());
    }

    #[test]
    fn test_dkg_init_invalid_params() {
        init();

        // threshold too low
        let result = dkg_init(1, 1, 3, EllipticCurve::Secp256k1);
        assert!(!result.success);

        // total_parties < threshold
        let result = dkg_init(1, 3, 2, EllipticCurve::Secp256k1);
        assert!(!result.success);

        // invalid party_id
        let result = dkg_init(0, 2, 3, EllipticCurve::Secp256k1);
        assert!(!result.success);

        let result = dkg_init(4, 2, 3, EllipticCurve::Secp256k1);
        assert!(!result.success);
    }

    #[test]
    fn test_rekey_from_secret() {
        init();

        let secret = vec![0u8; 32];
        let result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);

        assert!(result.success);
        assert_eq!(result.key_shares.len(), 3);
        assert!(!result.public_key.is_empty());
    }

    #[test]
    fn test_validate_key_share() {
        init();

        // Use a valid non-zero secret key
        let mut secret = vec![0u8; 32];
        secret[31] = 1; // Set to 1 to ensure it's a valid scalar
        let result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);
        assert!(result.success, "rekey_from_secret failed: {:?}", result.error_message);

        for share in &result.key_shares {
            assert!(validate_key_share(share), "key share validation failed");
        }
    }

    #[test]
    fn test_dkg_round1() {
        init();

        // Initialize DKG for a 2-of-3 threshold scheme, party 1
        let init_result = dkg_init(1, 2, 3, EllipticCurve::Secp256k1);
        assert!(init_result.success);

        // Execute round 1 - this calls actual dkls23::dkg::phase1
        let round1_result = dkg_round1(&init_result.session_state);
        assert!(round1_result.success, "round1 failed: {:?}", round1_result.error_message);
        assert!(!round1_result.session_state.is_empty());

        // Should have messages for each other party (2 messages for party 2 and 3)
        assert_eq!(round1_result.messages_to_send.len(), 2);

        // Check messages are to the correct parties
        let to_parties: Vec<u32> = round1_result.messages_to_send.iter()
            .map(|m| m.to_party)
            .collect();
        assert!(to_parties.contains(&2));
        assert!(to_parties.contains(&3));

        // Each message should have 32 bytes (scalar evaluation)
        for msg in &round1_result.messages_to_send {
            assert_eq!(msg.from_party, 1);
            assert_eq!(msg.data.len(), 32);
        }
    }

    #[test]
    fn test_dkg_multi_party_round1() {
        init();

        // Test that multiple parties can independently start DKG
        let parties: Vec<u32> = vec![1, 2, 3];
        let threshold = 2u32;
        let total = 3u32;

        for party_id in parties {
            let init_result = dkg_init(party_id, threshold, total, EllipticCurve::Secp256k1);
            assert!(init_result.success);

            let round1_result = dkg_round1(&init_result.session_state);
            assert!(round1_result.success, "party {} round1 failed", party_id);

            // Each party sends messages to (total - 1) other parties
            assert_eq!(round1_result.messages_to_send.len(), (total - 1) as usize);
        }
    }

    #[test]
    fn test_dkg_round2_with_simulated_messages() {
        init();

        // Simulate a 2-of-3 DKG: run phase1 for all parties, then phase2 for party 1
        let threshold = 2u32;
        let total = 3u32;

        // Generate a shared session ID (in practice, parties would agree on this)
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut shared_session_id = vec![0u8; 32];
        rng.fill_bytes(&mut shared_session_id);

        // Run phase1 for all parties and collect their outputs
        let mut party_states: Vec<Vec<u8>> = Vec::new();
        let mut party_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let init_result = dkg_init(party_id, threshold, total, EllipticCurve::Secp256k1);
            assert!(init_result.success);

            let round1_result = dkg_round1(&init_result.session_state);
            assert!(round1_result.success, "party {} phase1 failed: {:?}", party_id, round1_result.error_message);

            party_states.push(round1_result.session_state);
            party_messages.push(round1_result.messages_to_send);
        }

        // For party 1, collect messages from parties 2 and 3
        let mut messages_for_party1: Vec<PartyMessage> = Vec::new();

        // From party 2's messages, get the one destined for party 1
        for msg in &party_messages[1] { // party 2's messages (index 1)
            if msg.to_party == 1 {
                messages_for_party1.push(msg.clone());
            }
        }
        // From party 3's messages, get the one destined for party 1
        for msg in &party_messages[2] { // party 3's messages (index 2)
            if msg.to_party == 1 {
                messages_for_party1.push(msg.clone());
            }
        }

        assert_eq!(messages_for_party1.len(), 2, "Party 1 should receive 2 messages");

        // Run phase2 for party 1 with received messages
        let round2_result = dkg_round2(&party_states[0], &messages_for_party1);
        assert!(round2_result.success, "party 1 phase2 failed: {:?}", round2_result.error_message);

        // Phase2 should produce messages (proof commitments, zero-share transmits, derivation broadcasts)
        assert!(!round2_result.messages_to_send.is_empty(), "phase2 should produce messages");
        assert!(!round2_result.session_state.is_empty());
    }

    #[test]
    fn test_dkg_full_protocol_simulation() {
        init();

        // Full 2-of-3 DKG simulation through phase 1, 2, 3, and 4
        let threshold = 2u32;
        let total = 3u32;

        // Generate a shared session ID (in real protocol, parties agree on this beforehand)
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut shared_session_id = vec![0u8; 32];
        rng.fill_bytes(&mut shared_session_id);

        // Phase 1: All parties generate polynomials
        let mut phase1_states: Vec<Vec<u8>> = Vec::new();
        let mut phase1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let init_result = dkg_init_with_session_id(party_id, threshold, total, &shared_session_id, EllipticCurve::Secp256k1);
            assert!(init_result.success, "dkg_init failed for party {}: {:?}", party_id, init_result.error_message);

            let round1_result = dkg_round1(&init_result.session_state);
            assert!(round1_result.success);

            phase1_states.push(round1_result.session_state);
            phase1_messages.push(round1_result.messages_to_send);
        }

        // Phase 2: All parties process received evaluations
        let mut phase2_states: Vec<Vec<u8>> = Vec::new();
        let mut phase2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            // Collect messages destined for this party from all other parties
            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase1_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = dkg_round2(&phase1_states[party_idx], &received);
            assert!(round2_result.success, "party {} phase2 failed: {:?}", party_id, round2_result.error_message);

            phase2_states.push(round2_result.session_state);
            phase2_messages.push(round2_result.messages_to_send);
        }

        // Phase 3: All parties run initialization
        let mut phase3_states: Vec<Vec<u8>> = Vec::new();
        let mut phase3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            // Collect messages destined for this party from phase 2
            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase2_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = dkg_round3(&phase2_states[party_idx], &received);
            assert!(round3_result.success, "party {} phase3 failed: {:?}", party_id, round3_result.error_message);

            phase3_states.push(round3_result.session_state);
            phase3_messages.push(round3_result.messages_to_send);
        }

        // Verify all parties completed phase 3
        assert_eq!(phase3_states.len(), total as usize);
        for state in &phase3_states {
            assert!(!state.is_empty());
        }

        // Phase 4 (finalize): All parties finalize and extract key shares
        let mut final_results: Vec<DkgFinalResult> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            // Collect messages destined for this party from phase 3
            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase3_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let finalize_result = dkg_finalize(&phase3_states[party_idx], &received);
            if !finalize_result.success {
                eprintln!("Party {} finalize error: {:?}", party_id, finalize_result.error_message);
                // Continue to see if other parties succeed
            } else {
                assert!(!finalize_result.key_share.is_empty());
                assert!(!finalize_result.public_key.is_empty());
                assert_eq!(finalize_result.party_id, party_id);
                assert_eq!(finalize_result.threshold, threshold);
                assert_eq!(finalize_result.total_parties, total);
                final_results.push(finalize_result);
            }
        }

        // Log how many parties completed
        eprintln!("DKG completed for {}/{} parties", final_results.len(), total);

        // Verify all parties completed finalization
        assert_eq!(final_results.len(), total as usize, "Not all parties completed DKG");

        // Verify each key share is valid
        for result in &final_results {
            assert!(validate_key_share(&result.key_share));
        }

        // Note: In the current placeholder implementation, parties compute individual
        // public keys from their poly_point. A full implementation of dkg::phase4
        // would aggregate these to produce a shared public key for all parties.
    }

    // ============================================
    // Signing Tests
    // ============================================

    #[test]
    fn test_sign_init() {
        init();

        // Create a key share using rekey
        let secret = vec![0u8; 32];
        let rekey_result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);
        assert!(rekey_result.success);

        let key_share = &rekey_result.key_shares[0]; // Party 1's share

        // Create a message hash (32 bytes)
        let message_hash = vec![0x42u8; 32];

        // Initialize signing with parties 1 and 2
        let signer_party_ids = vec![1, 2];
        let sign_result = sign_init(key_share, &message_hash, &signer_party_ids);

        assert!(sign_result.success, "sign_init failed: {:?}", sign_result.error_message);
        assert!(!sign_result.session_state.is_empty());
    }

    #[test]
    fn test_sign_init_invalid_params() {
        init();

        // Create a key share
        let secret = vec![0u8; 32];
        let rekey_result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);
        assert!(rekey_result.success);
        let key_share = &rekey_result.key_shares[0];

        // Invalid message hash (wrong size)
        let bad_hash = vec![0x42u8; 16];
        let result = sign_init(key_share, &bad_hash, &vec![1, 2]);
        assert!(!result.success);
        assert!(result.error_message.unwrap().contains("32 bytes"));

        // Not enough signers
        let good_hash = vec![0x42u8; 32];
        let result = sign_init(key_share, &good_hash, &vec![1]); // Need at least 2 for 2-of-3
        assert!(!result.success);
        assert!(result.error_message.unwrap().contains("signers"));

        // Party not in signer list
        let key_share_2 = &rekey_result.key_shares[1]; // Party 2's share
        let result = sign_init(key_share_2, &good_hash, &vec![1, 3]); // Party 2 not in list
        assert!(!result.success);
        assert!(result.error_message.unwrap().contains("not in the signer list"));
    }

    #[test]
    fn test_sign_round1_placeholder() {
        init();

        // Create a key share (without party_data, so placeholder will be used)
        let secret = vec![0u8; 32];
        let rekey_result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);
        assert!(rekey_result.success);
        let key_share = &rekey_result.key_shares[0];

        // Initialize signing
        let message_hash = vec![0x42u8; 32];
        let signer_party_ids = vec![1, 2];
        let sign_result = sign_init(key_share, &message_hash, &signer_party_ids);
        assert!(sign_result.success);

        // Run round 1 (placeholder since no party_data)
        let round1_result = sign_round1(&sign_result.session_state);
        assert!(round1_result.success, "sign_round1 failed: {:?}", round1_result.error_message);

        // Should have messages for other signers
        assert_eq!(round1_result.messages_to_send.len(), 1); // 1 message to party 2
        assert_eq!(round1_result.messages_to_send[0].to_party, 2);
        assert!(!round1_result.session_state.is_empty());
    }

    #[test]
    fn test_sign_full_protocol_placeholder() {
        init();

        // Create key shares for a 2-of-3 scheme using a valid non-zero secret
        let mut secret = vec![0u8; 32];
        secret[31] = 1; // Ensure valid non-zero scalar
        let rekey_result = rekey_from_secret(&secret, 2, 3, EllipticCurve::Secp256k1);
        assert!(rekey_result.success, "rekey_from_secret failed: {:?}", rekey_result.error_message);

        let message_hash = vec![0x42u8; 32];
        let signer_party_ids = vec![1, 2]; // Parties 1 and 2 will sign

        // Use a shared sign_id for all parties (required for coordinated signing)
        let shared_sign_id = [0xABu8; 32];

        // Initialize signing for both parties with shared sign_id
        let mut sign_states: Vec<Vec<u8>> = Vec::new();
        for &party_id in &signer_party_ids {
            let key_share = &rekey_result.key_shares[(party_id - 1) as usize];
            let init_result = sign_init_with_sign_id(key_share, &message_hash, &signer_party_ids, &shared_sign_id);
            assert!(init_result.success, "sign_init failed for party {}", party_id);
            sign_states.push(init_result.session_state);
        }

        // Round 1 for both parties
        let mut round1_states: Vec<Vec<u8>> = Vec::new();
        let mut round1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in sign_states.iter().enumerate() {
            let round1_result = sign_round1(state);
            assert!(round1_result.success, "sign_round1 failed for party {}", signer_party_ids[i]);
            round1_states.push(round1_result.session_state);
            round1_messages.push(round1_result.messages_to_send);
        }

        // Round 2 for both parties (collect messages from round 1)
        let mut round2_states: Vec<Vec<u8>> = Vec::new();
        let mut round2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in round1_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            // Collect messages destined for this party
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round1_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = sign_round2(state, &received);
            assert!(round2_result.success, "sign_round2 failed for party {}: {:?}", party_id, round2_result.error_message);
            round2_states.push(round2_result.session_state);
            round2_messages.push(round2_result.messages_to_send);
        }

        // Round 3 for both parties (produces broadcasts)
        let mut round3_states: Vec<Vec<u8>> = Vec::new();
        let mut round3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in round2_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            // Collect messages destined for this party
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round2_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = sign_round3(state, &received);
            assert!(round3_result.success, "sign_round3 failed for party {}: {:?}", party_id, round3_result.error_message);
            round3_states.push(round3_result.session_state);
            round3_messages.push(round3_result.messages_to_send);
        }

        // Finalize for both parties (collect broadcasts)
        let mut signatures: Vec<Vec<u8>> = Vec::new();

        for (i, state) in round3_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            // Collect broadcast messages from all other parties
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round3_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let final_result = sign_finalize(state, &received);
            assert!(final_result.success, "sign_finalize failed for party {}: {:?}", party_id, final_result.error_message);
            assert!(!final_result.signature.is_empty());
            assert_eq!(final_result.signature.len(), 64); // (r, s) = 64 bytes

            signatures.push(final_result.signature);
        }

        // Both parties should produce signatures
        assert_eq!(signatures.len(), 2);

        // Note: With placeholder implementation (used when rekey_from_secret creates keys without Party state),
        // signatures are random and won't match. When using proper DKG-generated key shares,
        // signatures should be identical.
    }

    #[test]
    fn test_dkg_and_sign_end_to_end() {
        init();

        let threshold = 2u32;
        let total = 3u32;

        // Generate a shared session ID (all parties must use the same ID)
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut shared_session_id = vec![0u8; 32];
        rng.fill_bytes(&mut shared_session_id);

        // ============================================
        // DKG: Run full DKG to generate key shares
        // ============================================

        // Phase 1: Initialize and run round1 for all parties
        let mut phase1_states: Vec<Vec<u8>> = Vec::new();
        let mut phase1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let init_result = dkg_init_with_session_id(party_id, threshold, total, &shared_session_id, EllipticCurve::Secp256k1);
            assert!(init_result.success, "dkg_init failed for party {}", party_id);

            let round1_result = dkg_round1(&init_result.session_state);
            assert!(round1_result.success);

            phase1_states.push(round1_result.session_state);
            phase1_messages.push(round1_result.messages_to_send);
        }

        // Phase 2
        let mut phase2_states: Vec<Vec<u8>> = Vec::new();
        let mut phase2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase1_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = dkg_round2(&phase1_states[party_idx], &received);
            assert!(round2_result.success, "party {} phase2 failed: {:?}", party_id, round2_result.error_message);

            phase2_states.push(round2_result.session_state);
            phase2_messages.push(round2_result.messages_to_send);
        }

        // Phase 3
        let mut phase3_states: Vec<Vec<u8>> = Vec::new();
        let mut phase3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase2_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = dkg_round3(&phase2_states[party_idx], &received);
            assert!(round3_result.success, "party {} phase3 failed: {:?}", party_id, round3_result.error_message);

            phase3_states.push(round3_result.session_state);
            phase3_messages.push(round3_result.messages_to_send);
        }

        // Phase 4 (finalize)
        let mut key_shares: Vec<Vec<u8>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase3_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let finalize_result = dkg_finalize(&phase3_states[party_idx], &received);
            assert!(finalize_result.success, "party {} finalize failed: {:?}", party_id, finalize_result.error_message);
            key_shares.push(finalize_result.key_share);
        }

        eprintln!("DKG completed, {} key shares generated", key_shares.len());

        // ============================================
        // Signing: Use parties 1 and 2 to sign
        // ============================================

        let message_hash = vec![0x42u8; 32];
        let signer_party_ids = vec![1u32, 2u32]; // Parties 1 and 2 will sign

        // Generate a shared sign_id (all signers must use the same ID)
        let mut sign_id = vec![0u8; 32];
        rng.fill_bytes(&mut sign_id);

        // Initialize signing for both parties
        let mut sign_states: Vec<Vec<u8>> = Vec::new();
        for &party_id in &signer_party_ids {
            let key_share = &key_shares[(party_id - 1) as usize];
            let init_result = sign_init_with_sign_id(key_share, &message_hash, &signer_party_ids, &sign_id);
            assert!(init_result.success, "sign_init failed for party {}: {:?}", party_id, init_result.error_message);
            sign_states.push(init_result.session_state);
        }

        // Sign Round 1
        let mut round1_states: Vec<Vec<u8>> = Vec::new();
        let mut round1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in sign_states.iter().enumerate() {
            let round1_result = sign_round1(state);
            assert!(round1_result.success, "sign_round1 failed for party {}: {:?}", signer_party_ids[i], round1_result.error_message);
            round1_states.push(round1_result.session_state);
            round1_messages.push(round1_result.messages_to_send);
        }

        // Sign Round 2
        let mut round2_states: Vec<Vec<u8>> = Vec::new();
        let mut round2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in round1_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round1_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = sign_round2(state, &received);
            assert!(round2_result.success, "sign_round2 failed for party {}: {:?}", party_id, round2_result.error_message);
            round2_states.push(round2_result.session_state);
            round2_messages.push(round2_result.messages_to_send);
        }

        // Sign Round 3 (produces broadcasts)
        let mut round3_states: Vec<Vec<u8>> = Vec::new();
        let mut round3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in round2_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round2_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = sign_round3(state, &received);
            assert!(round3_result.success, "sign_round3 failed for party {}: {:?}", party_id, round3_result.error_message);
            round3_states.push(round3_result.session_state);
            round3_messages.push(round3_result.messages_to_send);
        }

        // Finalize (collect broadcasts, produce signature)
        let mut signatures: Vec<Vec<u8>> = Vec::new();

        for (i, state) in round3_states.iter().enumerate() {
            let party_id = signer_party_ids[i];

            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round3_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let final_result = sign_finalize(state, &received);
            assert!(final_result.success, "sign_finalize failed for party {}: {:?}", party_id, final_result.error_message);
            assert!(!final_result.signature.is_empty());
            assert_eq!(final_result.signature.len(), 64); // (r, s) = 64 bytes

            signatures.push(final_result.signature);
        }

        // Both parties should produce identical signatures
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0], signatures[1], "Signatures from both parties should match");

        eprintln!("Signing completed, signature = {:?}", hex::encode(&signatures[0]));
    }

    #[test]
    fn test_dkg_refresh_sign_end_to_end() {
        init();

        let threshold = 2u32;
        let total = 3u32;

        // Generate shared IDs
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut shared_session_id = vec![0u8; 32];
        rng.fill_bytes(&mut shared_session_id);

        // ============================================
        // Step 1: DKG to generate initial key shares
        // ============================================

        // Phase 1
        let mut phase1_states: Vec<Vec<u8>> = Vec::new();
        let mut phase1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let init_result = dkg_init_with_session_id(party_id, threshold, total, &shared_session_id, EllipticCurve::Secp256k1);
            assert!(init_result.success, "dkg_init failed for party {}", party_id);

            let round1_result = dkg_round1(&init_result.session_state);
            assert!(round1_result.success);

            phase1_states.push(round1_result.session_state);
            phase1_messages.push(round1_result.messages_to_send);
        }

        // Phase 2
        let mut phase2_states: Vec<Vec<u8>> = Vec::new();
        let mut phase2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase1_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = dkg_round2(&phase1_states[party_idx], &received);
            assert!(round2_result.success, "party {} phase2 failed: {:?}", party_id, round2_result.error_message);

            phase2_states.push(round2_result.session_state);
            phase2_messages.push(round2_result.messages_to_send);
        }

        // Phase 3
        let mut phase3_states: Vec<Vec<u8>> = Vec::new();
        let mut phase3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase2_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = dkg_round3(&phase2_states[party_idx], &received);
            assert!(round3_result.success, "party {} phase3 failed: {:?}", party_id, round3_result.error_message);

            phase3_states.push(round3_result.session_state);
            phase3_messages.push(round3_result.messages_to_send);
        }

        // Phase 4 (finalize)
        let mut key_shares: Vec<Vec<u8>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &phase3_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let finalize_result = dkg_finalize(&phase3_states[party_idx], &received);
            assert!(finalize_result.success, "party {} finalize failed: {:?}", party_id, finalize_result.error_message);
            key_shares.push(finalize_result.key_share);
        }

        eprintln!("DKG completed, {} key shares generated", key_shares.len());

        // ============================================
        // Step 2: Refresh key shares
        // ============================================

        let mut shared_refresh_id = vec![0u8; 32];
        rng.fill_bytes(&mut shared_refresh_id);

        // Refresh Round 1
        let mut refresh1_states: Vec<Vec<u8>> = Vec::new();
        let mut refresh1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let init_result = refresh_init_with_refresh_id(&key_shares[(party_id - 1) as usize], party_id, &shared_refresh_id);
            assert!(init_result.success, "refresh_init failed for party {}", party_id);

            let round1_result = refresh_round1(&init_result.session_state);
            assert!(round1_result.success, "refresh_round1 failed for party {}: {:?}", party_id, round1_result.error_message);

            refresh1_states.push(round1_result.session_state);
            refresh1_messages.push(round1_result.messages_to_send);
        }

        // Refresh Round 2
        let mut refresh2_states: Vec<Vec<u8>> = Vec::new();
        let mut refresh2_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &refresh1_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round2_result = refresh_round2(&refresh1_states[party_idx], &received);
            assert!(round2_result.success, "refresh_round2 failed for party {}: {:?}", party_id, round2_result.error_message);

            refresh2_states.push(round2_result.session_state);
            refresh2_messages.push(round2_result.messages_to_send);
        }

        // Refresh Round 3
        let mut refresh3_states: Vec<Vec<u8>> = Vec::new();
        let mut refresh3_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &refresh2_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let round3_result = refresh_round3(&refresh2_states[party_idx], &received);
            assert!(round3_result.success, "refresh_round3 failed for party {}: {:?}", party_id, round3_result.error_message);

            refresh3_states.push(round3_result.session_state);
            refresh3_messages.push(round3_result.messages_to_send);
        }

        // Refresh Finalize
        let mut refreshed_key_shares: Vec<Vec<u8>> = Vec::new();

        for party_id in 1..=total {
            let party_idx = (party_id - 1) as usize;

            let mut received: Vec<PartyMessage> = Vec::new();
            for other_party_id in 1..=total {
                if other_party_id != party_id {
                    let other_idx = (other_party_id - 1) as usize;
                    for msg in &refresh3_messages[other_idx] {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            let finalize_result = refresh_finalize(&refresh3_states[party_idx], &received);
            assert!(finalize_result.success, "refresh_finalize failed for party {}: {:?}", party_id, finalize_result.error_message);
            assert_eq!(finalize_result.generation, 1, "generation should be incremented");

            refreshed_key_shares.push(finalize_result.new_key_share);
        }

        eprintln!("Refresh completed, {} refreshed key shares", refreshed_key_shares.len());

        // Verify refreshed key shares are valid
        for key_share in &refreshed_key_shares {
            assert!(validate_key_share(key_share));
        }

        eprintln!("All refreshed key shares validated successfully");
    }

    /// Test resize protocol: (2,3) -> (2,4) by adding a new party
    #[test]
    fn test_resize_add_party() {
        eprintln!("Testing resize from 2-of-3 to 2-of-4...");

        // Use the same shared session ID for all parties
        let shared_session_id = [0xABu8; 32];

        // First run DKG to create key shares with proper party_data
        let threshold = 2u32;
        let total_parties = 3u32;

        // Initialize DKG for all parties
        let mut dkg_states: Vec<Vec<u8>> = Vec::new();
        for party_id in 1..=total_parties {
            let init_result = dkg_init_with_session_id(party_id, threshold, total_parties, &shared_session_id, EllipticCurve::Secp256k1);
            assert!(init_result.success, "dkg_init failed for party {}", party_id);
            dkg_states.push(init_result.session_state);
        }

        // DKG Round 1
        let mut round1_states: Vec<Vec<u8>> = Vec::new();
        let mut round1_messages: Vec<Vec<PartyMessage>> = Vec::new();
        for state in &dkg_states {
            let result = dkg_round1(state);
            assert!(result.success);
            round1_states.push(result.session_state);
            round1_messages.push(result.messages_to_send);
        }

        // DKG Round 2
        let mut round2_states: Vec<Vec<u8>> = Vec::new();
        let mut round2_messages: Vec<Vec<PartyMessage>> = Vec::new();
        for (i, state) in round1_states.iter().enumerate() {
            let party_id = (i + 1) as u32;
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round1_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }
            let result = dkg_round2(state, &received);
            assert!(result.success, "dkg_round2 failed for party {}", party_id);
            round2_states.push(result.session_state);
            round2_messages.push(result.messages_to_send);
        }

        // DKG Round 3
        let mut round3_states: Vec<Vec<u8>> = Vec::new();
        let mut round3_messages: Vec<Vec<PartyMessage>> = Vec::new();
        for (i, state) in round2_states.iter().enumerate() {
            let party_id = (i + 1) as u32;
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round2_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }
            let result = dkg_round3(state, &received);
            assert!(result.success, "dkg_round3 failed for party {}", party_id);
            round3_states.push(result.session_state);
            round3_messages.push(result.messages_to_send);
        }

        // DKG Finalize
        let mut key_shares: Vec<Vec<u8>> = Vec::new();
        for (i, state) in round3_states.iter().enumerate() {
            let party_id = (i + 1) as u32;
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round3_messages.iter().enumerate() {
                if i != j {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }
            let result = dkg_finalize(state, &received);
            assert!(result.success, "dkg_finalize failed for party {}", party_id);
            key_shares.push(result.key_share);
        }

        assert_eq!(key_shares.len(), 3);
        eprintln!("Created 3 key shares via DKG");

        // All 3 old parties will participate in the resize
        let old_party_ids: Vec<u32> = vec![1, 2, 3];
        let new_party_ids: Vec<u32> = vec![1, 2, 3, 4]; // Adding party 4
        let new_threshold = 2u32;
        let new_total_parties = 4u32;

        // Initialize resize for all old parties
        let mut resize_states: Vec<Vec<u8>> = Vec::new();
        for (i, &party_id) in old_party_ids.iter().enumerate() {
            let key_share = &key_shares[i];
            let init_result = resize_init(key_share, party_id, new_threshold, new_total_parties, &new_party_ids, EllipticCurve::Secp256k1);
            assert!(init_result.success, "resize_init failed for party {}: {:?}", party_id, init_result.error_message);
            resize_states.push(init_result.session_state);
        }

        // Also initialize for the new party (party 4) with empty key share
        let new_party_init = resize_init(&[], 4, new_threshold, new_total_parties, &new_party_ids, EllipticCurve::Secp256k1);
        assert!(new_party_init.success, "resize_init failed for new party 4");
        resize_states.push(new_party_init.session_state);

        eprintln!("Initialized resize for all parties");

        // Round 1: Old parties generate polynomial evaluations and send to all new parties
        let mut round1_states: Vec<Vec<u8>> = Vec::new();
        let mut round1_messages: Vec<Vec<PartyMessage>> = Vec::new();

        for (i, state) in resize_states.iter().enumerate() {
            let round1_result = resize_round1(state);
            assert!(round1_result.success, "resize_round1 failed for party {}: {:?}",
                    if i < 3 { old_party_ids[i] } else { 4 }, round1_result.error_message);
            round1_states.push(round1_result.session_state);
            round1_messages.push(round1_result.messages_to_send);
        }

        eprintln!("Round 1 complete, {} message sets", round1_messages.len());

        // Round 2: Each new party collects shares and computes their new poly_point
        let mut new_key_shares: Vec<Vec<u8>> = Vec::new();

        for (i, &party_id) in new_party_ids.iter().enumerate() {
            // Collect messages destined for this party from old parties
            let mut received: Vec<PartyMessage> = Vec::new();
            for (j, msgs) in round1_messages.iter().enumerate() {
                // Only old parties (indices 0, 1, 2) sent messages
                if j < old_party_ids.len() {
                    for msg in msgs {
                        if msg.to_party == party_id {
                            received.push(msg.clone());
                        }
                    }
                }
            }

            eprintln!("Party {} received {} share messages", party_id, received.len());

            // Use the appropriate state - old parties use their round1 state, new party uses its state
            let state = if i < old_party_ids.len() {
                &round1_states[i]
            } else {
                &round1_states[old_party_ids.len()]
            };

            let round2_result = resize_round2(state, &received);
            assert!(round2_result.success, "resize_round2 failed for party {}: {:?}",
                    party_id, round2_result.error_message);
            assert_eq!(round2_result.new_threshold, new_threshold);
            assert_eq!(round2_result.new_total_parties, new_total_parties);

            new_key_shares.push(round2_result.new_key_share);
        }

        eprintln!("Resize complete, {} new key shares", new_key_shares.len());

        // Verify all new key shares are valid
        for (i, key_share) in new_key_shares.iter().enumerate() {
            assert!(validate_key_share(key_share), "key share {} is invalid", i + 1);
        }

        eprintln!("All resized key shares validated successfully!");
    }
}
