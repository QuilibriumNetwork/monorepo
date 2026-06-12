//! wasm-bindgen wrappers for dkls23_ffi (threshold ECDSA via DKLs23).
//!
//! Mirrors the existing -wasm crate convention from `bls48581-wasm` /
//! `channel-wasm`: every function takes JSON-string input (with hex-encoded
//! byte fields where applicable) and returns a JSON-string result. All errors
//! are returned in-band as `{"error": "..."}` JSON strings — no panics across
//! the FFI boundary.
//!
//! The wrapped functions live in `crates/dkls23_ffi/src/lib.rs` and are the
//! same plain-Rust functions that the Go bindings call into via uniffi. Here
//! we expose them through wasm-bindgen so the JavaScript sidecar in
//! `qkms-sdk` can drive DKG, signing, refresh, and resize protocols entirely
//! in the browser or in Node.js.

use dkls23_ffi::{
    self as ffi,
    EllipticCurve, PartyMessage,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// JSON-friendly mirror types
// ---------------------------------------------------------------------------
//
// The result types in `dkls23_ffi` are plain `pub struct`s but do not derive
// Serialize/Deserialize. We define mirror types here with hex-encoded byte
// fields so the produced JSON is small and easy to consume from TypeScript.

#[derive(Serialize, Deserialize)]
struct PartyMessageJson {
    from_party: u32,
    to_party: u32,
    /// hex-encoded
    data: String,
}

impl From<&PartyMessage> for PartyMessageJson {
    fn from(m: &PartyMessage) -> Self {
        Self {
            from_party: m.from_party,
            to_party: m.to_party,
            data: hex::encode(&m.data),
        }
    }
}

impl TryFrom<PartyMessageJson> for PartyMessage {
    type Error = String;
    fn try_from(j: PartyMessageJson) -> Result<Self, String> {
        Ok(PartyMessage {
            from_party: j.from_party,
            to_party: j.to_party,
            data: hex::decode(&j.data).map_err(|e| format!("invalid party message hex: {}", e))?,
        })
    }
}

#[derive(Serialize)]
struct DkgInitResultJson {
    /// hex-encoded
    session_state: String,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct DkgRoundResultJson {
    session_state: String,
    messages_to_send: Vec<PartyMessageJson>,
    is_complete: bool,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct DkgFinalResultJson {
    key_share: String,
    public_key: String,
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct SignInitResultJson {
    session_state: String,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct SignRoundResultJson {
    session_state: String,
    messages_to_send: Vec<PartyMessageJson>,
    is_complete: bool,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct SignFinalResultJson {
    /// hex-encoded
    signature: String,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct RefreshInitResultJson {
    session_state: String,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct RefreshRoundResultJson {
    session_state: String,
    messages_to_send: Vec<PartyMessageJson>,
    is_complete: bool,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct RefreshFinalResultJson {
    new_key_share: String,
    generation: u32,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct ResizeInitResultJson {
    session_state: String,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct ResizeFinalResultJson {
    new_key_share: String,
    new_threshold: u32,
    new_total_parties: u32,
    success: bool,
    error_message: Option<String>,
}

#[derive(Serialize)]
struct GetPublicKeyResultJson {
    public_key: String,
}

#[derive(Serialize)]
struct ValidateKeyShareResultJson {
    valid: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn err(message: impl Into<String>) -> String {
    serde_json::json!({ "error": message.into() }).to_string()
}

fn parse_curve(s: &str) -> Result<EllipticCurve, String> {
    match s {
        "Secp256k1" | "secp256k1" => Ok(EllipticCurve::Secp256k1),
        "P256" | "p256" => Ok(EllipticCurve::P256),
        other => Err(format!("unknown curve: {}", other)),
    }
}

fn parse_messages(messages_json: &str) -> Result<Vec<PartyMessage>, String> {
    let parsed: Vec<PartyMessageJson> = serde_json::from_str(messages_json)
        .map_err(|e| format!("invalid messages JSON: {}", e))?;
    parsed.into_iter().map(PartyMessage::try_from).collect()
}

fn parse_session(state_hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(state_hex).map_err(|e| format!("invalid session_state hex: {}", e))
}

fn party_messages_to_json(msgs: &[PartyMessage]) -> Vec<PartyMessageJson> {
    msgs.iter().map(PartyMessageJson::from).collect()
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn js_dkls23_init() {
    ffi::init();
}

// ---------------------------------------------------------------------------
// Distributed Key Generation
// ---------------------------------------------------------------------------

/// Initialize a DKG session with a shared session id (hex-encoded). All
/// participating parties must call this with the same session_id.
#[wasm_bindgen]
pub fn js_dkls23_dkg_init(
    party_id: u32,
    threshold: u32,
    total_parties: u32,
    session_id_hex: &str,
    curve: &str,
) -> String {
    let curve = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let session_id = match hex::decode(session_id_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid session_id hex: {}", e)),
    };

    let result = ffi::dkg_init_with_session_id(
        party_id,
        threshold,
        total_parties,
        &session_id,
        curve,
    );

    serde_json::to_string(&DkgInitResultJson {
        session_state: hex::encode(&result.session_state),
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize dkg_init result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_dkg_round1(session_state_hex: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let result = ffi::dkg_round1(&state);
    serde_json::to_string(&DkgRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize dkg_round1 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_dkg_round2(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::dkg_round2(&state, &messages);
    serde_json::to_string(&DkgRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize dkg_round2 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_dkg_round3(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::dkg_round3(&state, &messages);
    serde_json::to_string(&DkgRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize dkg_round3 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_dkg_finalize(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::dkg_finalize(&state, &messages);
    serde_json::to_string(&DkgFinalResultJson {
        key_share: hex::encode(&result.key_share),
        public_key: hex::encode(&result.public_key),
        party_id: result.party_id,
        threshold: result.threshold,
        total_parties: result.total_parties,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize dkg_finalize result: {}", e)))
}

// ---------------------------------------------------------------------------
// Threshold Signing
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn js_dkls23_sign_init(
    key_share_hex: &str,
    message_hash_hex: &str,
    signer_party_ids_json: &str,
    sign_id_hex: &str,
) -> String {
    let key_share = match hex::decode(key_share_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid key_share hex: {}", e)),
    };
    let message_hash = match hex::decode(message_hash_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid message_hash hex: {}", e)),
    };
    let signer_party_ids: Vec<u32> = match serde_json::from_str(signer_party_ids_json) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid signer_party_ids JSON: {}", e)),
    };
    let sign_id = match hex::decode(sign_id_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid sign_id hex: {}", e)),
    };

    let result =
        ffi::sign_init_with_sign_id(&key_share, &message_hash, &signer_party_ids, &sign_id);
    serde_json::to_string(&SignInitResultJson {
        session_state: hex::encode(&result.session_state),
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize sign_init result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_sign_round1(session_state_hex: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let result = ffi::sign_round1(&state);
    serde_json::to_string(&SignRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize sign_round1 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_sign_round2(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::sign_round2(&state, &messages);
    serde_json::to_string(&SignRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize sign_round2 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_sign_round3(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::sign_round3(&state, &messages);
    serde_json::to_string(&SignRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize sign_round3 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_sign_finalize(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::sign_finalize(&state, &messages);
    serde_json::to_string(&SignFinalResultJson {
        signature: hex::encode(&result.signature),
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize sign_finalize result: {}", e)))
}

// ---------------------------------------------------------------------------
// Refresh (same threshold, new shares)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn js_dkls23_refresh_init(key_share_hex: &str, party_id: u32, refresh_id_hex: &str) -> String {
    let key_share = match hex::decode(key_share_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid key_share hex: {}", e)),
    };
    let refresh_id = match hex::decode(refresh_id_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid refresh_id hex: {}", e)),
    };
    let result = ffi::refresh_init_with_refresh_id(&key_share, party_id, &refresh_id);
    serde_json::to_string(&RefreshInitResultJson {
        session_state: hex::encode(&result.session_state),
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize refresh_init result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_refresh_round1(session_state_hex: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let result = ffi::refresh_round1(&state);
    serde_json::to_string(&RefreshRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize refresh_round1 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_refresh_round2(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::refresh_round2(&state, &messages);
    serde_json::to_string(&RefreshRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize refresh_round2 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_refresh_round3(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::refresh_round3(&state, &messages);
    serde_json::to_string(&RefreshRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize refresh_round3 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_refresh_finalize(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::refresh_finalize(&state, &messages);
    serde_json::to_string(&RefreshFinalResultJson {
        new_key_share: hex::encode(&result.new_key_share),
        generation: result.generation,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize refresh_finalize result: {}", e)))
}

// ---------------------------------------------------------------------------
// Resize (change threshold or party count)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn js_dkls23_resize_init(
    key_share_hex: &str,
    party_id: u32,
    new_threshold: u32,
    new_total_parties: u32,
    new_party_ids_json: &str,
    curve: &str,
) -> String {
    let key_share = match hex::decode(key_share_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid key_share hex: {}", e)),
    };
    let new_party_ids: Vec<u32> = match serde_json::from_str(new_party_ids_json) {
        Ok(v) => v,
        Err(e) => return err(format!("invalid new_party_ids JSON: {}", e)),
    };
    let curve = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let result = ffi::resize_init(
        &key_share,
        party_id,
        new_threshold,
        new_total_parties,
        &new_party_ids,
        curve,
    );
    serde_json::to_string(&ResizeInitResultJson {
        session_state: hex::encode(&result.session_state),
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize resize_init result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_resize_round1(session_state_hex: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let result = ffi::resize_round1(&state);
    serde_json::to_string(&DkgRoundResultJson {
        session_state: hex::encode(&result.session_state),
        messages_to_send: party_messages_to_json(&result.messages_to_send),
        is_complete: result.is_complete,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize resize_round1 result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_resize_round2(session_state_hex: &str, messages_json: &str) -> String {
    let state = match parse_session(session_state_hex) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let messages = match parse_messages(messages_json) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let result = ffi::resize_round2(&state, &messages);
    serde_json::to_string(&ResizeFinalResultJson {
        new_key_share: hex::encode(&result.new_key_share),
        new_threshold: result.new_threshold,
        new_total_parties: result.new_total_parties,
        success: result.success,
        error_message: result.error_message,
    })
    .unwrap_or_else(|e| err(format!("serialize resize_round2 result: {}", e)))
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn js_dkls23_get_public_key(key_share_hex: &str) -> String {
    let key_share = match hex::decode(key_share_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid key_share hex: {}", e)),
    };
    let pk = ffi::get_public_key(&key_share);
    serde_json::to_string(&GetPublicKeyResultJson {
        public_key: hex::encode(&pk),
    })
    .unwrap_or_else(|e| err(format!("serialize get_public_key result: {}", e)))
}

#[wasm_bindgen]
pub fn js_dkls23_validate_key_share(key_share_hex: &str) -> String {
    let key_share = match hex::decode(key_share_hex) {
        Ok(b) => b,
        Err(e) => return err(format!("invalid key_share hex: {}", e)),
    };
    serde_json::to_string(&ValidateKeyShareResultJson {
        valid: ffi::validate_key_share(&key_share),
    })
    .unwrap_or_else(|e| err(format!("serialize validate_key_share result: {}", e)))
}
