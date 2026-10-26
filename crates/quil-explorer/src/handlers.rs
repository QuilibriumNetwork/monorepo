//! Request handlers for the explorer REST API. Each mirrors the
//! corresponding Go `node/explorer` handler with a byte-compatible JSON
//! contract. Two response shapes are used: protobuf-JSON (protojson, no
//! trailing newline) for frames/certified/keys, and Go-`encoding/json`
//! style (snake_case structs, trailing `\n`) for everything else.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::Response,
};
use base64::Engine as _;
use num_bigint::{BigInt, Sign};
use parking_lot::Mutex;
use serde::Serialize;

use quil_execution::prover_registry::{
    allocation_fresh_at, inactivity_start, limit_evictions_to_shard_floor, shard_progressing,
    EvictionCandidate,
};
use quil_types::consensus::{EffectiveStatus, ProverAllocationInfo, ProverInfo, ProverStatus};
use quil_types::error::QuilError;
use quil_types::protojson;

use crate::production;
use crate::ExplorerState;

const CACHE_LONG: &str = "public, max-age=31536000, immutable";
const CACHE_180: &str = "public, max-age=180";
const CACHE_60: &str = "public, max-age=60";
const PROVER_CACHE_TTL: Duration = Duration::from_secs(180);
/// Bodies the response cache holds at most. Its keys come from request
/// paths and queries, so it is bounded: once full of live entries, further
/// bodies are served uncached until entries expire.
pub(crate) const CACHE_MAX_ENTRIES: usize = 1024;
/// How long a client is asked to wait while a full token scan runs.
const TOKEN_SCAN_RETRY_SECS: u64 = 5;
/// Longest a prover snapshot serves requests at its frame (one GLOBAL
/// frame is about 9 s).
const PROVER_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(10);
/// Longest an eviction assessment serves requests, whatever frame it was
/// made at. The indexer makes one at each new head, a tick
/// (`production::TICK`) after it arrives, and at least every
/// `PROVER_SNAPSHOT_MAX_AGE`; an older one means the indexer has not made
/// one yet or runs a long tick, and a request makes one.
const EVICTION_SERVE_MAX_AGE: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn build_response(
    status: StatusCode,
    body: impl Into<axum::body::Body>,
    cache: Option<&str>,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");
    if let Some(c) = cache {
        builder = builder.header("Cache-Control", c);
    }
    builder.body(body.into()).unwrap()
}

/// JSON body in Go `encoding/json` style: serialized value + trailing `\n`.
fn json_value<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    buf.push(b'\n');
    buf
}

fn json_ok<T: Serialize>(value: &T, cache: Option<&str>) -> Response {
    build_response(StatusCode::OK, json_value(value), cache)
}

/// protojson body (no trailing newline), matching Go's `respondProto`.
fn protojson_ok(full_name: &str, msg: &impl prost::Message, cache: Option<&str>) -> Response {
    match protojson::to_protojson(full_name, msg) {
        Ok(bytes) => build_response(StatusCode::OK, bytes, cache),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    let mut map = BTreeMap::new();
    map.insert("error", message);
    build_response(status, json_value(&map), None)
}

/// 503 with `Retry-After`, for work the explorer limits instead of queueing.
pub(crate) fn busy(message: &str, retry_after_secs: u64) -> Response {
    let mut resp = error(StatusCode::SERVICE_UNAVAILABLE, message);
    resp.headers_mut().insert("Retry-After", HeaderValue::from(retry_after_secs));
    resp
}

fn token_scan_busy() -> Response {
    busy("a full token scan is already running; retry shortly", TOKEN_SCAN_RETRY_SECS)
}

fn method_not_allowed() -> Response {
    error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// Mirror of Go's `writeStoreError`: NotFound -> 404 "not found", else 500.
fn store_error(e: &QuilError) -> Response {
    match e {
        QuilError::NotFound(_) => error(StatusCode::NOT_FOUND, "not found"),
        other => error(StatusCode::INTERNAL_SERVER_ERROR, &other.to_string()),
    }
}

/// Parse a 64-byte hex identifier, matching Go's `parseHexID`.
fn parse_hex_id(input: &str) -> Result<[u8; 64], &'static str> {
    let bytes = hex::decode(input).map_err(|_| "invalid hex identifier")?;
    if bytes.len() != 64 {
        return Err("identifier must be 64 bytes");
    }
    let mut id = [0u8; 64];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn is_get(method: &Method) -> bool {
    method == Method::GET
}

// ---------------------------------------------------------------------------
// /frames/{n|latest}, /certified/{rank|latest}
// ---------------------------------------------------------------------------

pub async fn handle_frames(
    method: Method,
    State(state): State<ExplorerState>,
    Path(id): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let (frame, cacheable) = if id == "latest" {
        (state.clock_store.get_latest_global_clock_frame(), false)
    } else {
        match id.parse::<u64>() {
            Ok(n) => (state.clock_store.get_global_clock_frame(n), true),
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid frame number"),
        }
    };
    let frame = match frame {
        Ok(f) => f,
        Err(e) => return store_error(&e),
    };
    let fnum = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
    let outcomes = state
        .clock_store
        .get_global_clock_frame_outcomes(fnum)
        .unwrap_or_default();
    // Don't cache a frame immutably until its outcomes exist (materialization
    // runs a beat after finalization); an empty-request frame needs none.
    let cacheable = cacheable && (frame.requests.is_empty() || !outcomes.is_empty());
    match frame_body(&frame, &outcomes) {
        Ok(body) => build_response(
            StatusCode::OK,
            body,
            if cacheable { Some(CACHE_LONG) } else { None },
        ),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// The `/frames` body: the frame's protojson plus `requestOutcomes`, each
/// bundle's MATERIALIZATION outcome, so the UI can show whether each request
/// actually applied (a frame carries every structurally-valid bundle, but
/// some are rejected/failed at materialize). `requestOutcomes[i]` aligns to
/// `requests[i]`. Built as one JSON value, whose objects sort their keys as
/// the body always has, instead of writing the protojson, parsing it back
/// and writing it again.
fn frame_body(
    frame: &quil_types::proto::global::GlobalFrame,
    outcomes: &[quil_types::store::RequestOutcome],
) -> Result<Vec<u8>, QuilError> {
    let mut body = protojson::to_protojson_value(protojson::GLOBAL_FRAME, frame)?;
    if let Some(object) = body.as_object_mut() {
        let outcomes = outcomes
            .iter()
            .map(|o| serde_json::json!({ "status": o.status.name(), "error": o.error }))
            .collect();
        object.insert("requestOutcomes".to_string(), serde_json::Value::Array(outcomes));
    }
    serde_json::to_vec(&body).map_err(|e| QuilError::Serialization(e.to_string()))
}

pub async fn handle_certified(
    method: Method,
    State(state): State<ExplorerState>,
    Path(id): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let proposal = if id == "latest" {
        state.clock_store.get_latest_certified_global_state()
    } else {
        match id.parse::<u64>() {
            Ok(rank) => state.clock_store.get_certified_global_state(rank),
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid rank"),
        }
    };
    match proposal {
        Ok(p) => protojson_ok(protojson::GLOBAL_PROPOSAL, &p, None),
        Err(e) => store_error(&e),
    }
}

// ---------------------------------------------------------------------------
// /messages
// ---------------------------------------------------------------------------

/// A `/messages` body younger than this is served again although messages
/// arrived since (bounded staleness: under steady gossip every request
/// would otherwise re-serialize megabytes of payloads).
const MESSAGES_CACHE_MAX_AGE: Duration = Duration::from_secs(1);

/// Append `bytes` as lowercase hex.
fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)]);
        out.push(DIGITS[usize::from(b & 0xf)]);
    }
}

/// The `/messages` JSON, written straight into one buffer: an array of
/// objects with hex fields, then a newline (as `json_value` would produce).
fn render_messages(records: &[crate::RecentMessage]) -> axum::body::Bytes {
    let size: usize = records
        .iter()
        .map(|r| {
            2 * (r.from.len() + r.bitmask.len() + r.seqno.len() + r.signature.len() + r.key.len() + r.data.len())
                + 140
        })
        .sum();
    let mut out = Vec::with_capacity(size + 3);
    out.push(b'[');
    for (i, r) in records.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"timestamp\":\"");
        out.extend_from_slice(r.timestamp().as_bytes());
        for (name, value) in [
            ("from", &r.from),
            ("bitmask", &r.bitmask),
            ("seqno", &r.seqno),
            ("signature", &r.signature),
            ("key", &r.key),
            ("data", &r.data),
        ] {
            out.extend_from_slice(b"\",\"");
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"\":\"");
            push_hex(&mut out, value);
        }
        out.extend_from_slice(b"\"}");
    }
    out.extend_from_slice(b"]\n");
    out.into()
}

/// The `/messages` body for `limit` at `now`, reusing the ring's cached one.
fn messages_body(ring: &crate::RecentMessageRing, limit: usize, now: Instant) -> axum::body::Bytes {
    ring.cached_body(limit, now, MESSAGES_CACHE_MAX_AGE, render_messages)
}

pub async fn handle_messages(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let mut limit = 50usize;
    if let Some(s) = params.get("limit") {
        if let Ok(parsed) = s.parse::<i64>() {
            if parsed > 0 {
                limit = parsed as usize;
            }
        }
    }
    build_response(StatusCode::OK, messages_body(&state.messages, limit, Instant::now()), None)
}

// ---------------------------------------------------------------------------
// /peers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PeerCapabilityJson {
    protocol_identifier: u32,
    additional_metadata: String,
}

#[derive(Serialize)]
struct PeerReachabilityJson {
    filter: String,
    pubsub_multiaddrs: Option<Vec<String>>,
    stream_multiaddrs: Option<Vec<String>>,
}

#[derive(Serialize)]
struct PeerInfoJson {
    peer_id: String,
    version: String,
    patch_number: String,
    cores: u32,
    last_seen: i64,
    last_received_frame: u64,
    last_global_head_frame: u64,
    /// `2.1.0.25.92`, or `2.1.0.25` from a peer that advertises no subpatch.
    /// `version` stays the raw version bytes for shape compatibility.
    release: String,
    subpatch: Option<u32>,
    build_fingerprint: Option<String>,
    capabilities: Option<Vec<PeerCapabilityJson>>,
    reachability: Option<Vec<PeerReachabilityJson>>,
}

/// The fields `/peers` reports of a peer, copied out of the node's shared
/// peer-info map: its read lock is held for the copies, not for the
/// encoding (base58, base64, hex) and serialization of every peer.
fn peer_fields(info: &quil_p2p::CanonicalPeerInfo) -> quil_p2p::CanonicalPeerInfo {
    quil_p2p::CanonicalPeerInfo {
        peer_id: info.peer_id.clone(),
        reachability: info.reachability.clone(),
        timestamp: info.timestamp,
        version: info.version.clone(),
        patch_number: info.patch_number.clone(),
        capabilities: info.capabilities.clone(),
        // Not reported.
        public_key: Vec::new(),
        signature: Vec::new(),
        last_received_frame: info.last_received_frame,
        last_global_head_frame: info.last_global_head_frame,
    }
}

fn peer_json(info: &quil_p2p::CanonicalPeerInfo) -> PeerInfoJson {
    let std = base64::engine::general_purpose::STANDARD;
    let capabilities = if info.capabilities.is_empty() {
        None
    } else {
        Some(
            info.capabilities
                .iter()
                .map(|c| PeerCapabilityJson {
                    protocol_identifier: c.protocol_identifier,
                    additional_metadata: std.encode(&c.additional_metadata),
                })
                .collect(),
        )
    };
    let reachability = if info.reachability.is_empty() {
        None
    } else {
        Some(
            info.reachability
                .iter()
                .map(|reach| PeerReachabilityJson {
                    filter: hex::encode(&reach.filter),
                    pubsub_multiaddrs: if reach.pubsub_multiaddrs.is_empty() {
                        None
                    } else {
                        Some(reach.pubsub_multiaddrs.clone())
                    },
                    stream_multiaddrs: if reach.stream_multiaddrs.is_empty() {
                        None
                    } else {
                        Some(reach.stream_multiaddrs.clone())
                    },
                })
                .collect(),
        )
    };
    PeerInfoJson {
        peer_id: bs58::encode(&info.peer_id).into_string(),
        version: String::from_utf8_lossy(&info.version).into_owned(),
        patch_number: hex::encode(&info.patch_number),
        // The Rust `CanonicalPeerInfo` carries no core count; the
        // Go explorer reported a `cores` field, so emit 0 for
        // shape compatibility.
        cores: 0,
        last_seen: info.timestamp,
        last_received_frame: info.last_received_frame,
        last_global_head_frame: info.last_global_head_frame,
        release: info.release(),
        subpatch: info.release_subpatch(),
        build_fingerprint: info.build_fingerprint().map(hex::encode),
        capabilities,
        reachability,
    }
}

pub async fn handle_peers(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let peers: Vec<quil_p2p::CanonicalPeerInfo> =
        state.peer_info_cache.read().values().map(peer_fields).collect();
    let mut response: Vec<PeerInfoJson> = peers.iter().map(peer_json).collect();
    // Sort by last_seen desc, tie-break peer_id asc (Go's slices.SortFunc).
    response.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    json_ok(&response, Some(CACHE_60))
}

// ---------------------------------------------------------------------------
// /peers/releases
// ---------------------------------------------------------------------------

/// A peer counts in the release census while its PeerInfo is at most this old:
/// mainnet peers republish theirs every 30 minutes.
const RELEASE_CENSUS_MAX_AGE_MS: i64 = 2 * 30 * 60 * 1000;
/// A peer is behind GLOBAL when the head it reported trails ours by more than
/// this: a republish interval is ~150 frames at ~12 s per frame.
const RELEASE_CENSUS_BEHIND_FRAMES: u64 = 360;

#[derive(Serialize)]
struct BuildCountJson {
    build_fingerprint: Option<String>,
    peers: usize,
}

#[derive(Serialize)]
struct ReleaseGroupJson {
    /// `2.1.0.25.92`; `2.1.0.25` groups every peer older than the subpatch
    /// capability; empty for malformed version fields.
    release: String,
    subpatch: Option<u32>,
    peers: usize,
    archives: usize,
    /// Peers whose reported GLOBAL head trails `global_head` by more than
    /// `behind_frames`.
    behind_global: usize,
    /// Lowest and highest GLOBAL head the group reported (0 when none did).
    global_head_min: u64,
    global_head_max: u64,
    builds: Vec<BuildCountJson>,
}

#[derive(Serialize)]
struct PeerReleasesJson {
    /// This node's GLOBAL frame, the reference for `behind_global`.
    global_head: u64,
    behind_frames: u64,
    /// Peers whose PeerInfo is recent enough to count, and those left out.
    peers: usize,
    stale_peers: usize,
    /// Most peers first.
    releases: Vec<ReleaseGroupJson>,
}

/// Which release the peers that published PeerInfo recently run, how many of
/// each are archives or behind GLOBAL, and by which builds.
fn peer_releases<'a>(
    infos: impl IntoIterator<Item = &'a quil_p2p::CanonicalPeerInfo>,
    now_ms: i64,
    global_head: u64,
) -> PeerReleasesJson {
    let mut groups: BTreeMap<String, (ReleaseGroupJson, BTreeMap<Option<String>, usize>)> = BTreeMap::new();
    let (mut peers, mut stale_peers) = (0, 0);
    for info in infos {
        if now_ms.saturating_sub(info.timestamp) > RELEASE_CENSUS_MAX_AGE_MS {
            stale_peers += 1;
            continue;
        }
        peers += 1;
        let release = info.release();
        let (group, builds) = groups.entry(release.clone()).or_insert_with(|| (ReleaseGroupJson {
            release,
            subpatch: info.release_subpatch(),
            peers: 0,
            archives: 0,
            behind_global: 0,
            global_head_min: 0,
            global_head_max: 0,
            builds: Vec::new(),
        }, BTreeMap::new()));
        group.peers += 1;
        group.archives += usize::from(info.is_archive());
        let head = info.last_global_head_frame;
        if head > 0 {
            group.global_head_min = if group.global_head_min == 0 { head } else { group.global_head_min.min(head) };
            group.global_head_max = group.global_head_max.max(head);
            group.behind_global += usize::from(head.saturating_add(RELEASE_CENSUS_BEHIND_FRAMES) < global_head);
        }
        *builds.entry(info.build_fingerprint().map(hex::encode)).or_default() += 1;
    }
    let mut releases: Vec<ReleaseGroupJson> = groups
        .into_values()
        .map(|(mut group, builds)| {
            group.builds = builds.into_iter().map(|(build_fingerprint, peers)| BuildCountJson { build_fingerprint, peers }).collect();
            group.builds.sort_by(|a, b| b.peers.cmp(&a.peers).then_with(|| a.build_fingerprint.cmp(&b.build_fingerprint)));
            group
        })
        .collect();
    releases.sort_by(|a, b| b.peers.cmp(&a.peers).then_with(|| b.release.cmp(&a.release)));
    PeerReleasesJson { global_head, behind_frames: RELEASE_CENSUS_BEHIND_FRAMES, peers, stale_peers, releases }
}

pub async fn handle_peer_releases(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let global_head = state.current_frame.load(Ordering::Relaxed);
    let response = {
        let map = state.peer_info_cache.read();
        peer_releases(map.values(), now_ms, global_head)
    };
    json_ok(&response, Some(CACHE_60))
}

// ---------------------------------------------------------------------------
// /provers, /provers/shards, /provers/shards/{filter}
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
struct RestProverAllocation {
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    confirmation_filter: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    rejection_filter: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    join_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    leave_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pause_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    resume_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    kick_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    join_confirm_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    join_reject_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    leave_confirm_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    leave_reject_frame_number: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    last_active_frame_number: u64,
}

#[derive(Serialize, Clone)]
struct RestProverInfo {
    address: String,
    public_key: String,
    status: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    kick_frame_number: u64,
    available_storage: u64,
    seniority: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    delegate_address: String,
    allocations: Vec<RestProverAllocation>,
}

#[derive(Serialize, Clone)]
struct RestProverShardSummary {
    filter: String,
    counts: BTreeMap<String, i64>,
    size_bytes: String,
    active_workers: i64,
    data_shards: u64,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn prover_status_to_string(status: ProverStatus) -> String {
    match status {
        ProverStatus::Unknown => "unknown",
        ProverStatus::Joining => "joining",
        ProverStatus::Active => "active",
        ProverStatus::Paused => "paused",
        ProverStatus::Leaving => "leaving",
        ProverStatus::Rejected => "rejected",
        ProverStatus::Kicked => "kicked",
        ProverStatus::Historic => "historic",
    }
    .to_string()
}

fn encode_hex_or_empty(input: &[u8]) -> String {
    if input.is_empty() {
        String::new()
    } else {
        hex::encode(input)
    }
}

/// Convert a `ProverInfo`. `filter == None` includes all allocations;
/// otherwise only allocations whose confirmation/rejection filter matches.
fn convert_prover_info(info: &ProverInfo, filter: Option<&[u8]>) -> RestProverInfo {
    let include_all = filter.is_none();
    let allocations: Vec<RestProverAllocation> = info
        .allocations
        .iter()
        .filter(|alloc| {
            include_all
                || filter
                    .map(|f| alloc.confirmation_filter == f || alloc.rejection_filter == f)
                    .unwrap_or(true)
        })
        .map(convert_allocation)
        .collect();
    RestProverInfo {
        address: hex::encode(&info.address),
        public_key: hex::encode(&info.public_key),
        status: prover_status_to_string(info.status),
        kick_frame_number: info.kick_frame_number,
        available_storage: info.available_storage,
        seniority: info.seniority,
        delegate_address: encode_hex_or_empty(&info.delegate_address),
        allocations,
    }
}

fn convert_allocation(alloc: &ProverAllocationInfo) -> RestProverAllocation {
    RestProverAllocation {
        status: prover_status_to_string(alloc.status),
        confirmation_filter: encode_hex_or_empty(&alloc.confirmation_filter),
        rejection_filter: encode_hex_or_empty(&alloc.rejection_filter),
        join_frame_number: alloc.join_frame_number,
        leave_frame_number: alloc.leave_frame_number,
        pause_frame_number: alloc.pause_frame_number,
        resume_frame_number: alloc.resume_frame_number,
        kick_frame_number: alloc.kick_frame_number,
        join_confirm_frame_number: alloc.join_confirm_frame_number,
        join_reject_frame_number: alloc.join_reject_frame_number,
        leave_confirm_frame_number: alloc.leave_confirm_frame_number,
        leave_reject_frame_number: alloc.leave_reject_frame_number,
        last_active_frame_number: alloc.last_active_frame_number,
    }
}

/// Result of parsing the `status` query param (Go `parseProverStatusParam`).
enum StatusParam {
    Known(ProverStatus),
    /// A valid numeric status with no known variant (7..=255): no prover
    /// can hold it, so the registry result is empty.
    NumericEmpty,
}

fn parse_prover_status(input: &str) -> Option<StatusParam> {
    let lower = input.to_lowercase();
    let known = match lower.as_str() {
        "unknown" => Some(ProverStatus::Unknown),
        "joining" => Some(ProverStatus::Joining),
        "active" => Some(ProverStatus::Active),
        "paused" => Some(ProverStatus::Paused),
        "leaving" => Some(ProverStatus::Leaving),
        "rejected" => Some(ProverStatus::Rejected),
        "kicked" => Some(ProverStatus::Kicked),
        _ => None,
    };
    if let Some(s) = known {
        return Some(StatusParam::Known(s));
    }
    match lower.parse::<u8>() {
        Ok(0) => Some(StatusParam::Known(ProverStatus::Unknown)),
        Ok(1) => Some(StatusParam::Known(ProverStatus::Joining)),
        Ok(2) => Some(StatusParam::Known(ProverStatus::Active)),
        Ok(3) => Some(StatusParam::Known(ProverStatus::Paused)),
        Ok(4) => Some(StatusParam::Known(ProverStatus::Leaving)),
        Ok(5) => Some(StatusParam::Known(ProverStatus::Rejected)),
        Ok(6) => Some(StatusParam::Known(ProverStatus::Kicked)),
        Ok(_) => Some(StatusParam::NumericEmpty),
        Err(_) => None,
    }
}

fn cache_get(state: &ExplorerState, key: &str) -> Option<Vec<u8>> {
    let cache = state.cache.read();
    cache.get(key).and_then(|(expiry, body)| {
        if *expiry > Instant::now() {
            Some(body.clone())
        } else {
            None
        }
    })
}

fn cache_put(state: &ExplorerState, key: String, body: Vec<u8>) {
    cache_insert(&mut state.cache.write(), Instant::now(), key, body);
}

/// Insert `body` under `key`, first dropping expired entries: `cache_get`
/// only skips them, so every distinct key (each `/provers` filter and
/// status combination, each shard detail) would otherwise keep its body
/// for the node's lifetime. A new key finding [`CACHE_MAX_ENTRIES`] live
/// entries is not cached.
fn cache_insert(
    cache: &mut HashMap<String, (Instant, Vec<u8>)>,
    now: Instant,
    key: String,
    body: Vec<u8>,
) {
    cache.retain(|_, (expiry, _)| *expiry > now);
    if cache.len() >= CACHE_MAX_ENTRIES && !cache.contains_key(&key) {
        return;
    }
    cache.insert(key, (now + PROVER_CACHE_TTL, body));
}

pub async fn handle_provers(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let address_hex = params.get("address").map(|s| s.trim()).unwrap_or("");
    let filter_hex = params.get("filter").map(|s| s.trim()).unwrap_or("");
    let status_param = params.get("status").map(|s| s.trim()).unwrap_or("");

    let mut cache_key = String::new();
    let infos: Vec<ProverInfo> = if !address_hex.is_empty() {
        let address = match hex::decode(address_hex) {
            Ok(a) => a,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid address"),
        };
        match state.prover_registry.get_prover_info(&address) {
            Ok(Some(info)) => vec![info],
            _ => return error(StatusCode::NOT_FOUND, "prover not found"),
        }
    } else {
        let filter: Vec<u8> = if filter_hex.is_empty() {
            Vec::new()
        } else {
            match hex::decode(filter_hex) {
                Ok(f) => f,
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid filter"),
            }
        };
        cache_key = format!(
            "provers|filter:{}|status:{}",
            filter_hex.to_lowercase(),
            status_param.to_lowercase()
        );
        if let Some(body) = cache_get(&state, &cache_key) {
            return build_response(StatusCode::OK, body, Some(CACHE_180));
        }
        let result = if !status_param.is_empty() {
            match parse_prover_status(status_param) {
                Some(StatusParam::Known(status)) => {
                    state.prover_registry.get_provers_by_status(&filter, status)
                }
                Some(StatusParam::NumericEmpty) => Ok(Vec::new()),
                None => return error(StatusCode::BAD_REQUEST, "invalid status"),
            }
        } else {
            state.prover_registry.get_provers(&filter)
        };
        match result {
            Ok(infos) => infos,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    };

    let response: Vec<RestProverInfo> =
        infos.iter().map(|i| convert_prover_info(i, None)).collect();
    let body = json_value(&response);
    if !cache_key.is_empty() {
        cache_put(&state, cache_key, body.clone());
    }
    build_response(StatusCode::OK, body, Some(CACHE_180))
}

pub async fn handle_prover_shards(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let cache_key = "shard-summary";
    if let Some(body) = cache_get(&state, cache_key) {
        return build_response(StatusCode::OK, body, Some(CACHE_180));
    }

    let frame_number = state.current_frame.load(Ordering::Relaxed);
    let summaries = match state.prover_registry.get_prover_shard_summaries(frame_number) {
        Ok(s) => s,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let shard_sizes = compute_shard_sizes(&state);

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut response: Vec<RestProverShardSummary> = Vec::new();
    for summary in &summaries {
        let filter_hex = hex::encode(&summary.filter);
        // Drop stale, off-grid filters: obsolete ancestor-depth prefixes left in
        // the prover registry after the grid split deeper (e.g. a depth-5 parent
        // whose data now lives in its depth-7 children). Their filter matches no
        // current grid shard, so they carry no data and no reward basis — surfacing
        // them as "provers, size 0" is misleading. A filter that maps to a live
        // shard is kept, INCLUDING an empty spine shard (present in the grid with
        // size "0"). Criterion: present in the current-grid `shard_sizes` map.
        let (size_bytes, data_shards) = match shard_sizes.get(&filter_hex) {
            Some((size, ds)) => (size.to_string(), *ds),
            None => continue,
        };
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for (status, count) in &summary.status_counts {
            counts.insert(prover_status_to_string(*status), *count as i64);
        }
        seen.insert(filter_hex.clone());
        let active_workers = counts.get("active").copied().unwrap_or(0)
            + counts.get("joining").copied().unwrap_or(0);
        response.push(RestProverShardSummary {
            filter: filter_hex,
            counts,
            size_bytes,
            active_workers,
            data_shards,
        });
    }

    // Shards with data but no provers assigned.
    for (filter_hex, (size, ds)) in &shard_sizes {
        if seen.contains(filter_hex) || size.sign() == Sign::NoSign {
            continue;
        }
        response.push(RestProverShardSummary {
            filter: filter_hex.clone(),
            counts: BTreeMap::new(),
            size_bytes: size.to_string(),
            active_workers: 0,
            data_shards: *ds,
        });
    }

    response.sort_by(|a, b| a.filter.cmp(&b.filter));

    let body = json_value(&response);
    cache_put(&state, cache_key.to_string(), body.clone());
    build_response(StatusCode::OK, body, Some(CACHE_180))
}

/// Build the filter-hex -> (size, data_shards) map the way Go's
/// `fetchShardSizes` does, but in-process: enumerate the shards store and
/// resolve each shard's `(size, data_shards)` via the same provider the
/// gRPC `GetAppShards` uses. The filter key is `L2 (last 32 bytes of the
/// shard key) ++ each prefix element as a byte`. Rows under GLOBAL's address
/// are left out: they are no app shards (see `production::is_app_shard`).
fn compute_shard_sizes(state: &ExplorerState) -> HashMap<String, (BigInt, u64)> {
    let mut result = HashMap::new();
    let shards = match state.shards_store.range_app_shards() {
        Ok(s) => s,
        Err(_) => return result,
    };
    for shard in shards {
        if shard.shard_key.len() < 32 {
            continue;
        }
        let l2 = &shard.shard_key[shard.shard_key.len() - 32..];
        if !production::is_app_shard(l2) {
            continue;
        }
        let (size_be, data_shards) = match &state.app_shards_provider {
            Some(p) => match p(&shard.shard_key, &shard.prefix) {
                Some((sz, ds, _)) => (sz, ds),
                None => (Vec::new(), 0),
            },
            None => (shard.size.clone(), shard.data_shards),
        };
        let filter = quil_forest::shard_prefix_to_filter(l2, &shard.prefix);
        let size = BigInt::from_bytes_be(Sign::Plus, &size_be);
        result.insert(hex::encode(&filter), (size, data_shards));
    }
    result
}

pub async fn handle_prover_shard_detail(
    method: Method,
    State(state): State<ExplorerState>,
    Path(filter_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let filter_hex = filter_hex.trim_end_matches('/');
    if filter_hex.is_empty() {
        return error(StatusCode::BAD_REQUEST, "filter required");
    }
    let filter = match hex::decode(filter_hex) {
        Ok(f) => f,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid filter"),
    };
    let cache_key = format!("shard-detail|{}", filter_hex.to_lowercase());
    if let Some(body) = cache_get(&state, &cache_key) {
        return build_response(StatusCode::OK, body, Some(CACHE_180));
    }
    let infos = match state.prover_registry.get_provers(&filter) {
        Ok(i) => i,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if infos.is_empty() {
        return error(StatusCode::NOT_FOUND, "no provers for filter");
    }
    let response: Vec<RestProverInfo> = infos
        .iter()
        .map(|i| convert_prover_info(i, Some(&filter)))
        .collect();
    let body = json_value(&response);
    cache_put(&state, cache_key, body.clone());
    build_response(StatusCode::OK, body, Some(CACHE_180))
}

// ---------------------------------------------------------------------------
// /hypergraph/vertex/{id}, /hypergraph/hyperedge/{id}
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AtomJson {
    id: String,
    app_address: String,
    data_address: String,
    serialized: String,
    size: String,
}

pub async fn handle_vertex(
    method: Method,
    State(state): State<ExplorerState>,
    Path(id_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let id = match parse_hex_id(&id_hex) {
        Ok(id) => id,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let location = quil_hypergraph::Location::from_id(&id);
    let value = match state.crdt.get_vertex_data(&location) {
        Some(v) => v,
        None => return error(StatusCode::NOT_FOUND, "vertex not found"),
    };
    // Forest-era: `get_vertex_data` returns the vertex's serialized data blob
    // (a Go-serialized tree), and its on-chain size is that blob's BYTE LENGTH —
    // exactly what `vertex_leaf_value` commits (`commitment ‖ blob.len()`). The
    // old trailing-32-bytes reading assumed the pre-forest Go `vertex.ToBytes()`
    // layout (`0x00||app||data||commitment||size`), which is NOT what is stored
    // now, so it reported a garbage size derived from the tree's tail bytes.
    let size = BigInt::from(value.len() as u64);
    let std = base64::engine::general_purpose::STANDARD;
    let response = AtomJson {
        id: hex::encode(id),
        app_address: hex::encode(&id[..32]),
        data_address: hex::encode(&id[32..]),
        serialized: std.encode(&value),
        size: size.to_string(),
    };
    json_ok(&response, None)
}

pub async fn handle_hyperedge(
    method: Method,
    State(state): State<ExplorerState>,
    Path(id_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let id = match parse_hex_id(&id_hex) {
        Ok(id) => id,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let location = quil_hypergraph::Location::from_id(&id);
    let value = match state.crdt.get_hyperedge_data(&location) {
        Some(v) => v,
        None => return error(StatusCode::NOT_FOUND, "hyperedge not found"),
    };
    // Go `hyperedge.GetSize()` == the extrinsic tree's leaf count, which is
    // the number of extrinsic atom ids.
    let size = extrinsic_count(&value);
    let std = base64::engine::general_purpose::STANDARD;
    let response = AtomJson {
        id: hex::encode(id),
        app_address: hex::encode(&id[..32]),
        data_address: hex::encode(&id[32..]),
        serialized: std.encode(&value),
        size: size.to_string(),
    };
    json_ok(&response, None)
}

/// The extrinsic atom ids (64-byte leaf keys) of a hyperedge's serialized
/// tree, as `get_hyperedge_extrinsic_ids` lists them, counted in the blob
/// already read: no second read of the hyperedge and no copies of its
/// leaves. 0 for an unreadable tree.
fn extrinsic_count(blob: &[u8]) -> usize {
    let Ok(Some(root)) = quil_tries::deserialize_go_tree(blob) else {
        return 0;
    };
    let mut leaves = Vec::new();
    root.collect_leaves(&mut leaves);
    leaves.iter().filter(|leaf| leaf.key.len() == 64).count()
}

// ---------------------------------------------------------------------------
// /keys/identity/{addr}, /keys/prover/{addr}
// ---------------------------------------------------------------------------

pub async fn handle_key_identity(
    method: Method,
    State(state): State<ExplorerState>,
    Path(addr_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let addr_hex = addr_hex.trim_end_matches('/');
    if addr_hex.is_empty() {
        return error(StatusCode::BAD_REQUEST, "identity address required");
    }
    let address = match hex::decode(addr_hex) {
        Ok(a) => a,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid identity address"),
    };
    match state.key_store.get_key_registry(&address) {
        Ok(reg) => protojson_ok(protojson::KEY_REGISTRY, &reg, None),
        Err(e) => store_error(&e),
    }
}

pub async fn handle_key_prover(
    method: Method,
    State(state): State<ExplorerState>,
    Path(addr_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let addr_hex = addr_hex.trim_end_matches('/');
    if addr_hex.is_empty() {
        return error(StatusCode::BAD_REQUEST, "prover address required");
    }
    let address = match hex::decode(addr_hex) {
        Ok(a) => a,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid prover address"),
    };
    match state.key_store.get_key_registry_by_prover(&address) {
        Ok(reg) => protojson_ok(protojson::KEY_REGISTRY, &reg, None),
        Err(e) => store_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Net-new endpoints (no Go counterpart): seniority + eviction risk + stats.
// ---------------------------------------------------------------------------

/// Collect every prover known to the registry, deduplicated by address:
/// the global committee plus every shard filter from the shard summaries,
/// in one registry call that clones each prover once. Asking per filter
/// cloned a prover once per shard it holds, each clone carrying its key
/// and all its allocations.
///
/// Requests within one frame and `PROVER_SNAPSHOT_MAX_AGE` share one
/// snapshot, so one build serves every dashboard request in that window
/// (each refresh asks for eviction risk, seniority, kicked provers and
/// stats). The age bound refreshes the snapshot when the frame stands
/// still. At most one snapshot is held: a newer one replaces it. Returns
/// the frame the snapshot was built at; `None` while no build has
/// succeeded (unknown, never an empty registry).
fn all_provers(state: &ExplorerState, frame: u64) -> Option<(u64, Arc<Vec<ProverInfo>>)> {
    snapshot_for(&state.provers_snapshot, frame, Instant::now(), || {
        let summaries = state.prover_registry.get_prover_shard_summaries(frame).ok()?;
        let mut filters: Vec<Vec<u8>> = vec![Vec::new()];
        filters.extend(summaries.into_iter().map(|s| s.filter));
        state.prover_registry.get_provers_on_filters(&filters).ok()
    })
}

/// The slot's value when it was built at `frame` less than
/// `PROVER_SNAPSHOT_MAX_AGE` before `now`; otherwise `build`'s value, which
/// replaces it. The lock is held while building, so concurrent requests
/// needing a new snapshot build one copy, not several. A failed build
/// (`None`) is not kept: the previous snapshot, if any, serves on with its
/// frame and the next request builds again; with none, `None`.
fn snapshot_for<T>(
    slot: &Mutex<Option<(u64, Instant, Arc<T>)>>,
    frame: u64,
    now: Instant,
    build: impl FnOnce() -> Option<T>,
) -> Option<(u64, Arc<T>)> {
    let mut slot = slot.lock();
    if let Some((built_frame, built_at, value)) = &*slot {
        if *built_frame == frame
            && now.saturating_duration_since(*built_at) < PROVER_SNAPSHOT_MAX_AGE
        {
            return Some((frame, Arc::clone(value)));
        }
    }
    let Some(value) = build() else {
        return slot.as_ref().map(|(built_frame, _, v)| (*built_frame, Arc::clone(v)));
    };
    let value = Arc::new(value);
    *slot = Some((frame, now, Arc::clone(&value)));
    Some((frame, value))
}

/// The answer of an endpoint that needs the prover snapshot before its
/// first successful build.
fn provers_unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "prover registry not read yet")
}

/// Per-allocation inactivity assessment, mirroring
/// `find_eviction_candidates`. Returns `None` for allocations that are not
/// accruing eviction risk (non-active, global/empty-filter, fully-halted
/// shard, or not yet measurably inactive).
struct Assessment {
    halt_duration: u64,
    total_inactive: u64,
    effective_inactive: u64,
}

fn assess_allocation(
    alloc: &ProverAllocationInfo,
    frame: u64,
    halts: &HashMap<Vec<u8>, u64>,
    active_by_filter: &HashMap<Vec<u8>, u64>,
) -> Option<Assessment> {
    // Frame-aware: mirror `find_eviction_candidates` (raw `alloc.status` wrongly
    // flags epoch-EXPIRED allocations, which the committee/shard summaries
    // already exclude via `live_allocation_status`).
    if alloc.effective_status(frame) != EffectiveStatus::Active
        || alloc.confirmation_filter.is_empty()
    {
        return None;
    }
    // Under-provisioned / coverage-halt exemption: mirror
    // `find_eviction_candidates` — a shard below the consensus quorum can't
    // produce frames, so its provers can't submit proofs and are NOT evicted;
    // surfacing them as "at risk" is the "up for eviction but no active shards"
    // contradiction. Derived from the same active census the evictor uses.
    let shard_active = active_by_filter
        .get(&alloc.confirmation_filter)
        .copied()
        .unwrap_or(0);
    if shard_active < quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS {
        return None;
    }
    let halt_duration = halts.get(&alloc.confirmation_filter).copied().unwrap_or(0);
    if halt_duration == u64::MAX {
        return None; // shard fully halted — exempt this tick
    }
    // Inactivity does not start accruing until the network is live for
    // eviction, nor before the allocation's activation — the evictor's own
    // `inactivity_start`, so nobody is surfaced for downtime predating either.
    let start = inactivity_start(alloc);
    if alloc.last_active_frame_number == 0 || frame <= start {
        return None;
    }
    let total_inactive = frame - start;
    let effective_inactive = if halt_duration == 0 {
        total_inactive
    } else if halt_duration < total_inactive {
        total_inactive - halt_duration
    } else {
        0
    };
    Some(Assessment {
        halt_duration,
        total_inactive,
        effective_inactive,
    })
}

/// Per-shard census of effectively-active allocations at `frame`, keyed by
/// confirmation filter. Mirrors the census `find_eviction_candidates` builds
/// so the explorer's eviction views apply the SAME under-provisioned /
/// coverage-halt exemption as the consensus evictor (a shard below
/// `MIN_SHARD_CONSENSUS_PROVERS` can't run consensus → its provers are exempt).
fn active_allocations_by_filter(provers: &[ProverInfo], frame: u64) -> HashMap<Vec<u8>, u64> {
    let mut m: HashMap<Vec<u8>, u64> = HashMap::new();
    for p in provers {
        for alloc in &p.allocations {
            if alloc.confirmation_filter.is_empty() {
                continue;
            }
            if alloc.effective_status(frame) == EffectiveStatus::Active {
                *m.entry(alloc.confirmation_filter.clone()).or_insert(0) += 1;
            }
        }
    }
    m
}

/// Of the census allocations, those the evictor's stall census counts as
/// fresh (`allocation_fresh_at`, with the shard's halt credit), keyed by
/// confirmation filter: the fresh count its stall exemption
/// (`shard_progressing`) uses. `signed_frame_activation` is
/// `SIGNED_FRAME_ACTIVATION_FRAME` outside tests.
fn fresh_allocations_by_filter(
    provers: &[ProverInfo],
    frame: u64,
    halts: &HashMap<Vec<u8>, u64>,
    threshold: u64,
    signed_frame_activation: u64,
) -> HashMap<Vec<u8>, u64> {
    let mut m: HashMap<Vec<u8>, u64> = HashMap::new();
    for p in provers {
        for alloc in &p.allocations {
            if alloc.confirmation_filter.is_empty()
                || alloc.effective_status(frame) != EffectiveStatus::Active
            {
                continue;
            }
            let halt = halts.get(&alloc.confirmation_filter).copied().unwrap_or(0);
            if allocation_fresh_at(alloc, frame, halt, threshold, signed_frame_activation) {
                *m.entry(alloc.confirmation_filter.clone()).or_insert(0) += 1;
            }
        }
    }
    m
}

fn current_halts(state: &ExplorerState, frame: u64) -> HashMap<Vec<u8>, u64> {
    let mut halts = state
        .halt_durations_provider
        .as_ref()
        .map(|p| p(frame))
        .unwrap_or_default();

    // Size-aware correction (mirrors the materializer's eviction gate):
    // the coverage monitor stamps `u64::MAX` on every shard with
    // `active_count <= halt_threshold` regardless of data size, so empty
    // (no-data) under-subscribed shards look "halted" and wrongly exempt
    // their provers from eviction risk. Drop the full-halt mark for shards
    // with zero committed data so this endpoint reflects real eviction
    // behavior. Filter = L2(32) ++ prefix-byte (strip L1(3) from shard_key).
    if let Ok(shards) = state.shards_store.range_app_shards() {
        let mut has_data: HashMap<Vec<u8>, bool> = HashMap::new();
        for s in shards {
            let l2_start = if s.shard_key.len() >= 3 { 3 } else { 0 };
            let filter = quil_forest::shard_prefix_to_filter(&s.shard_key[l2_start..], &s.prefix);
            if filter.is_empty() {
                continue;
            }
            has_data.insert(filter, s.size.iter().any(|&b| b != 0));
        }
        if !has_data.is_empty() {
            halts.retain(|filter, dur| {
                if *dur != u64::MAX {
                    return true;
                }
                // Keep full-halt only for shards we know hold data.
                has_data.get(filter).copied().unwrap_or(false)
            });
        }
    }
    halts
}

/// One allocation's eviction runway. The prover's public key is left out:
/// the response carries one entry per allocation, and
/// `/provers?address=<hex>` serves the key.
#[derive(Serialize)]
struct EvictionRiskEntry {
    address: String,
    seniority: u64,
    filter: String,
    last_active_frame_number: u64,
    current_frame: u64,
    shard_halt_duration: u64,
    frames_inactive: u64,
    effective_inactive: u64,
    eviction_threshold: u64,
    frames_until_eviction: u64,
    risk_ratio: f64,
    eviction_pending: bool,
    /// At least two thirds of the shard's active allocations are within the
    /// threshold; a stalled shard's allocations are never pending.
    shard_progressing: bool,
}

/// Which eviction-risk entries a request asks for: those at least
/// `min_ratio` at risk, one prover's (`address`), one shard's (`filter`),
/// at most `limit` of them. The hex values are lowercase, as the entries
/// carry them.
struct EvictionRiskSelection {
    min_ratio: f64,
    address: Option<String>,
    filter: Option<String>,
    limit: Option<usize>,
}

/// The entries `selection` asks for, in their order (most at risk first),
/// and their count before `limit`. Applied after `eviction_pending` is set
/// over every allocation, so the selection never changes which
/// allocations are pending.
fn select_eviction_risk<'a>(
    entries: &'a [EvictionRiskEntry],
    selection: &EvictionRiskSelection,
) -> (Vec<&'a EvictionRiskEntry>, usize) {
    let mut selected: Vec<&EvictionRiskEntry> = entries
        .iter()
        // Only a ratio below `min_ratio` is left out: a NaN `min_ratio`
        // keeps every entry.
        .filter(|e| e.risk_ratio.partial_cmp(&selection.min_ratio) != Some(std::cmp::Ordering::Less))
        .filter(|e| selection.address.as_deref().is_none_or(|a| e.address == a))
        .filter(|e| selection.filter.as_deref().is_none_or(|f| e.filter == f))
        .collect();
    let total = selected.len();
    if let Some(n) = selection.limit {
        selected.truncate(n);
    }
    (selected, total)
}

/// `/provers/eviction-risk`: one entry per active allocation accruing
/// inactivity, most at risk first. Optional query parameters: `min_ratio`
/// (least `risk_ratio`), `address` (one prover's hex address), `filter`
/// (one shard's hex confirmation filter) and `limit` (the most at risk
/// entries). `eviction_pending` is computed over every allocation,
/// whatever the selection. The `X-Total-Count` header carries the number
/// of entries selected before `limit`. Serves the latest [`Eviction`]
/// assessment, whose frame the entries' `current_frame` names.
pub async fn handle_eviction_risk(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    // Optional hex parameter, normalized to the entries' lowercase hex.
    let hex_param = |name: &str| -> Result<Option<String>, ()> {
        match params.get(name).map(|s| s.trim()).filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(h) => hex::decode(h).map(|b| Some(hex::encode(b))).map_err(|_| ()),
        }
    };
    let Ok(address) = hex_param("address") else {
        return error(StatusCode::BAD_REQUEST, "invalid address");
    };
    let Ok(filter) = hex_param("filter") else {
        return error(StatusCode::BAD_REQUEST, "invalid filter");
    };
    let selection = EvictionRiskSelection {
        min_ratio: params
            .get("min_ratio")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0),
        address,
        filter,
        limit: params.get("limit").and_then(|s| s.parse().ok()),
    };

    let frame = state.current_frame.load(Ordering::Relaxed);
    let eviction = served_eviction(&state, frame, Instant::now());
    if eviction.provers_as_of_frame.is_none() {
        return provers_unavailable();
    }
    let (selected, total) = select_eviction_risk(&eviction.entries, &selection);
    let mut response = json_ok(&selected, None);
    response
        .headers_mut()
        .insert("X-Total-Count", HeaderValue::from(total));
    response
}

/// Every active allocation's eviction runway at one frame, with the
/// prover counts of `/stats`: what `/stats` and `/provers/eviction-risk`
/// serve. The production indexer makes one at each new head (see
/// [`eviction_at`]), so a request selects and serializes instead of
/// scanning the shards store for halts and assessing every allocation.
pub(crate) struct Eviction {
    /// The frame assessed: the head when it was made.
    pub(crate) frame: u64,
    built_at: Instant,
    /// The frame of the prover snapshot assessed; `None` while the registry
    /// has not been read, the counts then being placeholders.
    provers_as_of_frame: Option<u64>,
    total_provers: u64,
    by_status: BTreeMap<String, i64>,
    total_seniority: u64,
    /// Provers with an allocation past the threshold, and past half of it.
    eviction_pending: u64,
    at_risk: u64,
    /// Shards in a full coverage halt.
    halted: BTreeSet<Vec<u8>>,
    /// One entry per active allocation accruing inactivity, most at risk
    /// first, `eviction_pending` set over all of them.
    entries: Vec<EvictionRiskEntry>,
}

/// Assess every allocation of `provers` (a snapshot with the frame it was
/// read at; `None` before the registry was read) at `frame`, with the
/// coverage halts `halts`, as the evictor would.
fn assess_eviction(
    frame: u64,
    built_at: Instant,
    provers: Option<(u64, &[ProverInfo])>,
    halts: &HashMap<Vec<u8>, u64>,
) -> Eviction {
    let threshold = crate::EVICTION_THRESHOLD_FRAMES;
    let provers_as_of_frame = provers.map(|(built, _)| built);
    let provers: &[ProverInfo] = match provers {
        Some((_, provers)) => provers,
        None => &[],
    };
    let active_by_filter = active_allocations_by_filter(provers, frame);
    let fresh_by_filter = fresh_allocations_by_filter(
        provers,
        frame,
        halts,
        threshold,
        quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
    );
    let progressing = |filter: &[u8]| {
        shard_progressing(
            active_by_filter.get(filter).copied().unwrap_or(0),
            fresh_by_filter.get(filter).copied().unwrap_or(0),
        )
    };

    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    let mut total_seniority: u64 = 0;
    let mut eviction_pending: u64 = 0;
    let mut at_risk: u64 = 0;
    let mut entries: Vec<EvictionRiskEntry> = Vec::new();
    // Every allocation past the threshold on a progressing shard, before the
    // shard floor, so `eviction_pending` matches the evictor's selection.
    let mut stale: Vec<EvictionCandidate> = Vec::new();
    for prover in provers {
        *by_status
            .entry(prover_status_to_string(prover.status))
            .or_insert(0) += 1;
        total_seniority = total_seniority.saturating_add(prover.seniority);
        if prover.status != ProverStatus::Active {
            continue;
        }
        let mut worst = 0u64;
        for alloc in &prover.allocations {
            let Some(a) = assess_allocation(alloc, frame, halts, &active_by_filter) else {
                continue;
            };
            worst = worst.max(a.effective_inactive);
            let on_progressing_shard = progressing(&alloc.confirmation_filter);
            if a.effective_inactive > threshold && on_progressing_shard {
                stale.push(EvictionCandidate {
                    prover_address: prover.address.clone(),
                    confirmation_filter: alloc.confirmation_filter.clone(),
                    vertex_address: alloc.vertex_address.clone(),
                    effective_inactive: a.effective_inactive,
                });
            }
            entries.push(EvictionRiskEntry {
                address: hex::encode(&prover.address),
                seniority: prover.seniority,
                filter: hex::encode(&alloc.confirmation_filter),
                last_active_frame_number: alloc.last_active_frame_number,
                current_frame: frame,
                shard_halt_duration: a.halt_duration,
                frames_inactive: a.total_inactive,
                effective_inactive: a.effective_inactive,
                eviction_threshold: threshold,
                frames_until_eviction: threshold.saturating_sub(a.effective_inactive),
                risk_ratio: a.effective_inactive as f64 / threshold as f64,
                // Set below: past the threshold on a progressing shard AND
                // within the shard floor.
                eviction_pending: false,
                shard_progressing: on_progressing_shard,
            });
        }
        if worst > threshold {
            eviction_pending += 1;
        }
        if worst > threshold / 2 {
            at_risk += 1;
        }
    }
    // The evictor keeps every shard at MIN_SHARD_CONSENSUS_PROVERS active
    // allocations, so only the most inactive stale allocations of a shard
    // are pending; the rest stay at risk.
    let pending: std::collections::HashSet<(String, String)> =
        limit_evictions_to_shard_floor(stale, &active_by_filter)
            .into_iter()
            .map(|c| (hex::encode(&c.prover_address), hex::encode(&c.confirmation_filter)))
            .collect();
    for entry in &mut entries {
        entry.eviction_pending = pending.contains(&(entry.address.clone(), entry.filter.clone()));
    }
    // Most-at-risk first: least runway, then highest inactivity.
    entries.sort_by(|a, b| {
        a.frames_until_eviction
            .cmp(&b.frames_until_eviction)
            .then_with(|| b.effective_inactive.cmp(&a.effective_inactive))
    });
    Eviction {
        frame,
        built_at,
        provers_as_of_frame,
        total_provers: provers.len() as u64,
        by_status,
        total_seniority,
        eviction_pending,
        at_risk,
        halted: halts
            .iter()
            .filter(|(_, halt)| **halt == u64::MAX)
            .map(|(filter, _)| filter.clone())
            .collect(),
        entries,
    }
}

/// The eviction assessment at `frame`: the latest one when it was made at
/// `frame` less than `PROVER_SNAPSHOT_MAX_AGE` before `now`, else a new one,
/// which replaces it. One is made at a time: a caller needing one while
/// another is made waits for it rather than making a second. Blocking:
/// halts (a shards-store scan) and the prover snapshot.
pub(crate) fn eviction_at(state: &ExplorerState, frame: u64, now: Instant) -> Arc<Eviction> {
    let current = || {
        state.eviction.read().clone().filter(|e| {
            e.frame == frame && now.saturating_duration_since(e.built_at) < PROVER_SNAPSHOT_MAX_AGE
        })
    };
    if let Some(eviction) = current() {
        return eviction;
    }
    let _making = state.eviction_making.lock();
    if let Some(eviction) = current() {
        return eviction;
    }
    let halts = current_halts(state, frame);
    let provers = all_provers(state, frame);
    let eviction = Arc::new(assess_eviction(
        frame,
        now,
        provers.as_ref().map(|(built, provers)| (*built, provers.as_slice())),
        &halts,
    ));
    *state.eviction.write() = Some(Arc::clone(&eviction));
    eviction
}

/// The eviction assessment a request serves: the latest one when made less
/// than [`EVICTION_SERVE_MAX_AGE`] before `now` (the indexer's, normally a
/// tick behind the head at most), else one made now at `frame` (see
/// [`eviction_at`]).
fn served_eviction(state: &ExplorerState, frame: u64, now: Instant) -> Arc<Eviction> {
    let latest = state.eviction.read().clone();
    match latest {
        Some(eviction)
            if now.saturating_duration_since(eviction.built_at) < EVICTION_SERVE_MAX_AGE =>
        {
            eviction
        }
        _ => eviction_at(state, frame, now),
    }
}

/// One prover's seniority rank. The prover's public key is left out:
/// `/provers?address=<hex>` serves it.
#[derive(Serialize)]
struct SeniorityEntry {
    rank: u64,
    address: String,
    seniority: u64,
    status: String,
    active_shards: u64,
}

pub async fn handle_seniority(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let limit: Option<usize> = params.get("limit").and_then(|s| s.parse().ok());

    let frame = state.current_frame.load(Ordering::Relaxed);
    let Some((_, snapshot)) = all_provers(&state, frame) else {
        return provers_unavailable();
    };
    let mut provers: Vec<&ProverInfo> = snapshot.iter().collect();
    // Seniority descending; ties broken by address ascending for stability.
    provers.sort_by(|a, b| b.seniority.cmp(&a.seniority).then_with(|| a.address.cmp(&b.address)));
    let mut entries: Vec<SeniorityEntry> = provers
        .iter()
        .enumerate()
        .map(|(i, p)| SeniorityEntry {
            rank: (i as u64) + 1,
            address: hex::encode(&p.address),
            seniority: p.seniority,
            status: prover_status_to_string(p.status),
            active_shards: p
                .allocations
                .iter()
                .filter(|a| a.status == ProverStatus::Active && !a.confirmation_filter.is_empty())
                .count() as u64,
        })
        .collect();
    if let Some(n) = limit {
        entries.truncate(n);
    }
    json_ok(&entries, None)
}

#[derive(Serialize)]
struct KickedEntry {
    address: String,
    public_key: String,
    status: String,
    kick_frame_number: u64,
    seniority: u64,
}

pub async fn handle_kicked(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let frame = state.current_frame.load(Ordering::Relaxed);
    let Some((_, provers)) = all_provers(&state, frame) else {
        return provers_unavailable();
    };
    let mut entries: Vec<KickedEntry> = provers
        .iter()
        .filter(|p| p.status == ProverStatus::Kicked)
        .map(|p| KickedEntry {
            address: hex::encode(&p.address),
            public_key: hex::encode(&p.public_key),
            status: prover_status_to_string(p.status),
            kick_frame_number: p.kick_frame_number,
            seniority: p.seniority,
        })
        .collect();
    // Most-recently kicked first.
    entries.sort_by(|a, b| b.kick_frame_number.cmp(&a.kick_frame_number));
    json_ok(&entries, None)
}

#[derive(Serialize)]
struct StatsResponse {
    /// The frame the counts below were assessed at (see [`Eviction`]): the
    /// head, or an earlier one until the indexer assesses a new head,
    /// normally within a tick and at most `EVICTION_SERVE_MAX_AGE` later.
    current_frame: u64,
    eviction_threshold: u64,
    total_provers: u64,
    by_status: BTreeMap<String, i64>,
    total_seniority: u64,
    /// Provers with at least one allocation already past the threshold (the
    /// evictor would kick them on its next archive tick).
    eviction_pending: u64,
    /// Provers with at least one allocation past half the threshold.
    at_risk: u64,
    /// Shards currently in a full coverage halt (eviction-exempt).
    halted_shards: u64,
    /// The `/shards/production` summary of the indexer's latest snapshot;
    /// appended last, so the keys above keep their order. `null` until the
    /// first snapshot.
    app_shards: Option<production::AppShardsStats>,
    /// The `/shards/production/history` rows held; appended after
    /// `app_shards`.
    app_shard_history: production::history::HistoryStats,
    /// The frame the prover snapshot behind `total_provers`, `by_status`,
    /// `total_seniority`, `eviction_pending` and `at_risk` was read at;
    /// `null` while the registry has not been read, the counts then being
    /// placeholders. Appended last.
    provers_as_of_frame: Option<u64>,
    /// The prover snapshot is older than `current_frame` (a failed rebuild)
    /// or missing.
    provers_stale: bool,
}

pub async fn handle_stats(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let frame = state.current_frame.load(Ordering::Relaxed);
    let eviction = served_eviction(&state, frame, Instant::now());
    let app_shards = state.production_snapshot.read().as_ref().map(|s| s.report.stats());
    let app_shard_history = state.production_history.read().stats();

    let response = StatsResponse {
        current_frame: eviction.frame,
        eviction_threshold: crate::EVICTION_THRESHOLD_FRAMES,
        total_provers: eviction.total_provers,
        by_status: eviction.by_status.clone(),
        total_seniority: eviction.total_seniority,
        eviction_pending: eviction.eviction_pending,
        at_risk: eviction.at_risk,
        halted_shards: eviction.halted.len() as u64,
        app_shards,
        app_shard_history,
        provers_as_of_frame: eviction.provers_as_of_frame,
        provers_stale: eviction.provers_as_of_frame != Some(eviction.frame),
    };
    json_ok(&response, None)
}

// ---------------------------------------------------------------------------
// /shards/production
// ---------------------------------------------------------------------------

/// Each shard's head session and GLOBAL's executed tip of it, from one
/// committed GLOBAL snapshot (as `committed_global_app_heads` reads them).
fn committed_heads(
    state: &ExplorerState,
    filters: &BTreeSet<Vec<u8>>,
) -> HashMap<Vec<u8>, production::Committed> {
    use quil_execution::global_intrinsic::handoff::{self, CommittedView};
    let Ok(view) = CommittedView::capture(&state.crdt) else {
        return HashMap::new();
    };
    filters
        .iter()
        .filter_map(|filter| {
            let session = handoff::head(&view, filter).ok()??;
            let tip = handoff::session_tip(&view, &session.id().ok()?).ok()?;
            let committed = production::Committed {
                app_head: tip.map_or(session.base_frame, |tip| tip.frame),
                generation: session.generation,
                members: session.members.len() as u64,
            };
            Some((filter.clone(), committed))
        })
        .collect()
}

/// How often an unavailable live set, or one whose re-read failed, is read
/// again.
const GRID_RETRY: Duration = Duration::from_secs(30);

/// The live set and the grid, read again once [`PROVER_CACHE_TTL`] old (as
/// `/provers/shards` caches its shard sizes), and every [`GRID_RETRY`]
/// while unavailable or while a re-read fails. A failed re-read keeps the
/// last grid read with a live set, flagged stale.
#[derive(Default)]
pub(crate) struct ShardSets {
    /// The last read attempt.
    refreshed: Option<Instant>,
    grid: production::GridView,
    /// When `grid` was read.
    read_at: Option<Instant>,
    /// Why the last re-read failed while an older `grid` serves.
    failed: Option<&'static str>,
}

impl ShardSets {
    /// Read the grid with `read` when due at `now`.
    pub(crate) fn refresh(&mut self, now: Instant, read: impl FnOnce() -> production::GridView) {
        let every = if self.grid.unavailable.is_some() || self.failed.is_some() { GRID_RETRY } else { PROVER_CACHE_TTL };
        if self.refreshed.is_some_and(|at| now.saturating_duration_since(at) < every) {
            return;
        }
        self.refreshed = Some(now);
        let grid = read();
        match grid.unavailable {
            Some(reason) if self.read_at.is_some() && self.grid.unavailable.is_none() => self.failed = Some(reason),
            _ => {
                self.grid = grid;
                self.read_at = Some(now);
                self.failed = None;
            }
        }
    }

    /// Why the serving grid is older than the last read attempt, and its
    /// age at `now`.
    pub(crate) fn kept(&self, now: Instant) -> Option<(&'static str, Duration)> {
        Some((self.failed?, now.saturating_duration_since(self.read_at?)))
    }

    #[cfg(test)]
    pub(crate) fn grid_view(&self) -> &production::GridView {
        &self.grid
    }
}

/// The live set and the grid as the registry and the grid source read now.
fn read_grid(state: &ExplorerState, head: u64) -> production::GridView {
    let Ok(summaries) = state.prover_registry.get_prover_shard_summaries(head) else {
        let source = if state.archive_grid.is_some() {
            production::GridSource::ArchiveCache
        } else {
            production::GridSource::LocalStore
        };
        return production::GridView { source, unavailable: Some(production::NO_REGISTRY), ..Default::default() };
    };
    let registry: Vec<Vec<u8>> = summaries.into_iter().map(|s| s.filter).collect();
    match &state.archive_grid {
        Some(cache) => production::grid_from_cache(&registry, cache()),
        None => production::grid_from_store(
            &registry,
            &compute_shard_sizes(state),
            &state.shards_store.range_app_shards().unwrap_or_default(),
        ),
    }
}

/// The node's stored GLOBAL head and its header timestamp: the received
/// head's header when stored (a header read), else the latest stored frame.
fn stored_head(state: &ExplorerState, head: u64) -> Option<(u64, i64)> {
    if let Ok(header) = state.clock_store.get_global_clock_frame_header(head) {
        return Some((header.frame_number, header.timestamp));
    }
    let header = state.clock_store.get_latest_global_clock_frame().ok()?.header?;
    Some((header.frame_number, header.timestamp))
}

/// Build the production report for `view`: the indexer task's work, never a
/// request's. Blocking: registry, shards-store and committed-state reads.
pub(crate) fn build_production_report(
    state: &ExplorerState,
    head: u64,
    view: &production::IndexView,
    sets: &mut ShardSets,
) -> (production::ProductionReport, production::BuildTimings) {
    let started = Instant::now();
    let mut stage = Instant::now();
    let mut lap = || std::mem::replace(&mut stage, Instant::now()).elapsed();
    let now = Instant::now();
    sets.refresh(now, || read_grid(state, head));
    let kept = sets.kept(now);
    let shard_sets = lap();
    let active = all_provers(state, head).map(|(frame, provers)| (frame, active_allocations_by_filter(&provers, head)));
    let census = lap();
    // Halts from the eviction assessment at this head, made here unless one
    // was: one shards-store scan per head serves the report, `/stats` and
    // `/provers/eviction-risk`.
    let eviction = eviction_at(state, head, Instant::now());
    let halts = lap();
    let committed = committed_heads(state, &sets.grid.live);
    let committed_time = lap();
    let mut report = production::assemble(
        view,
        &production::Inputs {
            head_frame: head,
            grid: &sets.grid,
            active: active.as_ref().map(|(frame, active)| (*frame, active)),
            halted: &eviction.halted,
            committed: &committed,
            quil: quil_str,
        },
    );
    if let Some((reason, age)) = kept {
        report.add_stale_reason(format!(
            "the live shard set cannot be re-read ({reason}): serving the one read {}s ago",
            age.as_secs()
        ));
    }
    let stored = stored_head(state, head);
    report.window.stored_head_frame = stored.map(|(frame, _)| frame);
    report.window.stored_head_timestamp_ms = stored.map(|(_, timestamp)| timestamp);
    report.window.built_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let assemble = lap();
    let timings = production::BuildTimings {
        shard_sets,
        census,
        halts,
        committed: committed_time,
        assemble,
        total: started.elapsed(),
        grid_source: sets.grid.source,
        grid_unavailable: sets.grid.unavailable,
        grid_kept: kept.map(|(reason, _)| reason),
    };
    (report, timings)
}

/// `/shards/production`: per live shard (the `/provers/shards` set), whether
/// GLOBAL applied its app frames over the last `WINDOW_FRAMES` GLOBAL
/// frames, with the network summary. Optional `class` (`no_data`,
/// `producing`, `below_quorum`, `staffed_not_producing`) and `filter` (hex)
/// select shards; the summary covers every live shard. Fees only, no
/// rewards. Serves the indexer's latest snapshot; 503 until its first.
pub async fn handle_shard_production(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let (class, filter) = match production::parse_selection(&params) {
        Ok(selection) => selection,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let Some(snapshot) = state.production_snapshot.read().clone() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "production index not built yet");
    };
    if class.is_none() && filter.is_none() {
        return build_response(StatusCode::OK, snapshot.body.clone(), Some(production::CACHE_CONTROL));
    }
    json_ok(
        &snapshot.report.response(class, filter.as_deref()),
        Some(production::CACHE_CONTROL),
    )
}

/// `/shards/production/history`: a row every `ROW_FRAMES` GLOBAL frames,
/// ascending, each the `/shards/production` window at its frame plus what
/// GLOBAL applied in its own frames. Optional `from_frame` and `to_frame`
/// (inclusive) select at most one week of rows, the last week by default;
/// `bucket=epoch` rolls the selected rows (all held by default) up per
/// epoch. Rows carry the live-set census only when recorded live.
pub async fn handle_shard_production_history(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let query = match production::history::parse_query(&params) {
        Ok(query) => query,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let body = {
        let rows = state.production_history.read();
        match rows.response(&query) {
            Ok(response) => json_value(&response),
            Err(message) => return error(StatusCode::BAD_REQUEST, message),
        }
    };
    build_response(StatusCode::OK, body, Some(production::history::CACHE_CONTROL))
}

// ---------------------------------------------------------------------------
// /token/supply, /token/coin/{address}, /token/coins/{owner}
//
// Token state is the hypergraph CRDT: coins are "vertex/adds" vertices under
// the QUIL_TOKEN domain, keyed `domain(32) ‖ content_address(32)`. Only
// TRANSPARENT coins expose a readable owner + plaintext amount; lattice RingCT
// and decaf `coin:Coin` coins hide the amount (commitment/encrypted) and carry
// no linkable owner — those are reported as value-hidden. There is no live
// supply counter and no owner→coins index, so supply's audited figure is the
// migration receipt and owner listing is a full single-shard scan.
// ---------------------------------------------------------------------------

fn parse_hex_32(input: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex::decode(input).map_err(|_| "invalid hex address")?;
    if bytes.len() != 32 {
        return Err("address must be 32 bytes");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(a)
}

/// Exact sub-units → QUIL decimal string. `QUIL_TOKEN_UNITS = 8e9 = 2^12·5^9`,
/// so the expansion terminates in ≤12 places: value·10^12/8e9 = value·125.
pub(crate) fn quil_str(sub: u128) -> String {
    let scaled = sub.saturating_mul(125); // sub × 10^12 / 8e9
    let whole = scaled / 1_000_000_000_000u128;
    let frac = scaled % 1_000_000_000_000u128;
    let mut s = format!("{whole}.{frac:012}");
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Big-endian bytes → u128, saturating if the value exceeds 128 bits (reward
/// balances are stored as 32-byte BE `FillBytes`; realistic values fit u128).
fn be_bytes_to_u128(bytes: &[u8]) -> u128 {
    let start = bytes.len().saturating_sub(16);
    if bytes[..start].iter().any(|&b| b != 0) {
        return u128::MAX;
    }
    let mut v = 0u128;
    for &b in &bytes[start..] {
        v = (v << 8) | b as u128;
    }
    v
}

/// The reserved (non-coin) vertex addresses under the token domain.
fn is_reserved_token_addr(addr: &[u8]) -> bool {
    use quil_execution::token_intrinsic::legacy_migration::MIGRATION_RECEIPT_ADDRESS;
    use quil_execution::token_intrinsic::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS as ACC_ROOT_ADDRESS;
    addr == MIGRATION_RECEIPT_ADDRESS.as_slice()
        || addr == ACC_ROOT_ADDRESS.as_slice()
        || addr == [0xFFu8; 32].as_slice() // token metadata/config vertex
}

#[derive(Serialize)]
struct CoinJson {
    address: String,
    /// "transparent" | "private" | "unknown"
    kind: &'static str,
    value_hidden: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_subunits: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_quil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
}

/// Decode a coin vertex blob at `address` (32-byte content address) into a
/// `CoinJson`. `None` if the blob isn't a decodable coin tree.
fn decode_coin(domain: &[u8], address: &[u8; 32], blob: &[u8]) -> Option<CoinJson> {
    let root = quil_tries::deserialize_go_tree(blob).ok().flatten();
    let tree = quil_tries::VectorCommitmentTree { root };
    let ty = tree.get(&[0xFFu8; 32])?; // every coin carries a type leaf
    let transparent = quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(domain).ok()?;
    let private = quil_execution::token_intrinsic::materialize::coin_type_hash(domain).ok()?;
    let addr_hex = hex::encode(address);
    if ty == transparent.as_slice() {
        let owner = tree.get(&[0x00]).map(hex::encode);
        let (amount_subunits, amount_quil) = match tree.get(&[1u8 << 2]) {
            Some(a) => {
                let mut b = [0u8; 16];
                let n = a.len().min(16);
                b[..n].copy_from_slice(&a[..n]);
                let v = u128::from_le_bytes(b);
                (Some(v.to_string()), Some(quil_str(v)))
            }
            None => (None, None),
        };
        let origin = tree.get(&[2u8 << 2]).map(hex::encode);
        Some(CoinJson {
            address: addr_hex,
            kind: "transparent",
            value_hidden: false,
            owner,
            amount_subunits,
            amount_quil,
            origin,
            commitment: None,
        })
    } else if ty == private.as_slice() {
        // Lattice RingCT and decaf coins share the `coin:Coin` type hash; both
        // hide the amount and carry no linkable owner. Surface the value
        // commitment for reference (lattice cv at [2<<2], decaf Commitment at
        // [1<<2]) — best-effort, whichever is present.
        let commitment = tree
            .get(&[2u8 << 2])
            .or_else(|| tree.get(&[1u8 << 2]))
            .map(hex::encode);
        Some(CoinJson {
            address: addr_hex,
            kind: "private",
            value_hidden: true,
            owner: None,
            amount_subunits: None,
            amount_quil: None,
            origin: None,
            commitment,
        })
    } else {
        Some(CoinJson {
            address: addr_hex,
            kind: "unknown",
            value_hidden: true,
            owner: None,
            amount_subunits: None,
            amount_quil: None,
            origin: None,
            commitment: None,
        })
    }
}

#[derive(Serialize)]
struct SupplyResponse {
    units_per_quil: u64,
    /// Audited migration baseline (the transparent set at migration time).
    #[serde(skip_serializing_if = "Option::is_none")]
    migration_baseline: Option<SupplyBaseline>,
    /// Present only when `?scan=1`: a live sum over the PUBLIC supply — the
    /// transparent coin set plus the earned/mined reward balances.
    #[serde(skip_serializing_if = "Option::is_none")]
    live_public: Option<SupplyLive>,
    note: &'static str,
}

#[derive(Serialize)]
struct SupplyBaseline {
    coins: u64,
    total_subunits: String,
    total_quil: String,
}

#[derive(Serialize)]
struct SupplyLive {
    transparent_coins: u64,
    transparent_subunits: String,
    /// Earned/mined QUIL held in per-prover `reward:ProverReward` balances
    /// (public plaintext, under the GLOBAL intrinsic domain).
    reward_provers: u64,
    reward_subunits: String,
    /// transparent coins + reward balances — the full PUBLIC supply. Only
    /// shielded (lattice) coins are value-hidden and excluded.
    total_public_subunits: String,
    total_public_quil: String,
    value_hidden_coins: u64,
    scanned: usize,
}

pub async fn handle_token_supply(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let domain = quil_execution::domains::QUIL_TOKEN;
    let units = quil_execution::token_intrinsic::constants::QUIL_TOKEN_UNITS;

    // The `?scan=1` path is O(all coins) — serve a cached result (short TTL) so
    // the full scan runs at most once per window, not per request.
    let want_scan = params
        .get("scan")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if want_scan {
        if let Some(body) = cache_get(&state, "token_supply_scan") {
            return build_response(StatusCode::OK, body, Some(CACHE_60));
        }
    }
    let _scanning = if want_scan {
        let Ok(permit) = state.token_scan.try_acquire() else {
            return token_scan_busy();
        };
        // A scan that ended while this request waited for the cache read.
        if let Some(body) = cache_get(&state, "token_supply_scan") {
            return build_response(StatusCode::OK, body, Some(CACHE_60));
        }
        Some(permit)
    } else {
        None
    };

    // Audited baseline: the migration receipt (count, Σ). Read via the canonical
    // reader so it matches how the intrinsic wrote it.
    let hstate = quil_execution::hypergraph_state::HypergraphState::new(state.crdt.clone());
    let migration_baseline =
        quil_execution::token_intrinsic::legacy_migration::read_migration_receipt(&hstate, &domain)
            .ok()
            .flatten()
            .map(|(coins, total)| SupplyBaseline {
                coins,
                total_subunits: total.to_string(),
                total_quil: quil_str(total),
            });

    // Optional (expensive) live PUBLIC-supply scan: transparent coins (QUIL_TOKEN
    // domain) + earned reward balances (GLOBAL intrinsic domain). Only shielded
    // (lattice) coins are value-hidden and left uncounted.
    let live_public = if want_scan {
        let transparent =
            quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(&domain).ok();
        let private =
            quil_execution::token_intrinsic::materialize::coin_type_hash(&domain).ok();
        // 1. Transparent coins + value-hidden coin count (QUIL_TOKEN domain).
        let (mut tcoins, mut tsum, mut hidden) = (0u64, 0u128, 0u64);
        let mut coin_cb = |vk: Vec<u8>, blob: Vec<u8>| {
            if vk.len() < 64 || is_reserved_token_addr(&vk[32..64]) {
                return;
            }
            let root = quil_tries::deserialize_go_tree(&blob).ok().flatten();
            let tree = quil_tries::VectorCommitmentTree { root };
            let ty = match tree.get(&[0xFFu8; 32]) {
                Some(t) => t.to_vec(),
                None => return,
            };
            if Some(ty.as_slice()) == transparent.as_ref().map(|h| h.as_slice()) {
                if let Some(a) = tree.get(&[1u8 << 2]) {
                    let mut b = [0u8; 16];
                    let n = a.len().min(16);
                    b[..n].copy_from_slice(&a[..n]);
                    tsum = tsum.saturating_add(u128::from_le_bytes(b));
                    tcoins += 1;
                }
            } else if Some(ty.as_slice()) == private.as_ref().map(|h| h.as_slice()) {
                hidden += 1;
            }
        };
        let mut scanned = state.crdt.for_each_vertex_adds_blob(&domain, &mut coin_cb).unwrap_or(0);
        // 2. Earned/mined reward balances (GLOBAL intrinsic domain, plaintext).
        let (mut rprovers, mut rsum) = (0u64, 0u128);
        let mut reward_cb = |_vk: Vec<u8>, blob: Vec<u8>| {
            let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            if quil_execution::global_schema::read_type(&tree) != Some("reward:ProverReward") {
                return;
            }
            let bal = quil_execution::global_intrinsic::materialize::read_reward_balance(&tree);
            if bal.is_empty() {
                return;
            }
            let v = be_bytes_to_u128(&bal);
            if v > 0 {
                rsum = rsum.saturating_add(v);
                rprovers += 1;
            }
        };
        scanned += state
            .crdt
            .for_each_vertex_adds_blob(&quil_execution::domains::GLOBAL, &mut reward_cb)
            .unwrap_or(0);
        let total_public = tsum.saturating_add(rsum);
        Some(SupplyLive {
            transparent_coins: tcoins,
            transparent_subunits: tsum.to_string(),
            reward_provers: rprovers,
            reward_subunits: rsum.to_string(),
            total_public_subunits: total_public.to_string(),
            total_public_quil: quil_str(total_public),
            value_hidden_coins: hidden,
            scanned,
        })
    } else {
        None
    };

    let response = SupplyResponse {
        units_per_quil: units,
        migration_baseline,
        live_public,
        note: "migration_baseline is the audited transparent total at migration. ?scan=1 sums \
               the full PUBLIC supply: transparent coins (QUIL_TOKEN) + earned/mined \
               reward balances (public plaintext, GLOBAL intrinsic domain). Only SHIELDED \
               lattice coins are value-hidden and excluded — everything else is derivable. \
               (?scan=1 is a full scan; result cached ~60s.)",
    };
    let body = json_value(&response);
    if want_scan {
        cache_put(&state, "token_supply_scan".to_string(), body.clone());
        return build_response(StatusCode::OK, body, Some(CACHE_60));
    }
    build_response(StatusCode::OK, body, None)
}

pub async fn handle_token_coin(
    method: Method,
    State(state): State<ExplorerState>,
    Path(addr_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let addr = match parse_hex_32(addr_hex.trim()) {
        Ok(a) => a,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let domain = quil_execution::domains::QUIL_TOKEN;
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(&domain);
    id[32..].copy_from_slice(&addr);
    let location = quil_hypergraph::Location::from_id(&id);
    let blob = match state.crdt.get_vertex_data(&location) {
        Some(b) => b,
        None => return error(StatusCode::NOT_FOUND, "coin not found"),
    };
    match decode_coin(&domain, &addr, &blob) {
        Some(coin) => json_ok(&coin, None),
        None => error(StatusCode::UNPROCESSABLE_ENTITY, "vertex is not a decodable coin"),
    }
}

#[derive(Serialize)]
struct OwnerCoinsResponse {
    owner: String,
    units_per_quil: u64,
    count: u64,
    total_subunits: String,
    total_quil: String,
    coins: Vec<CoinJson>,
    scanned: usize,
    truncated: bool,
    note: &'static str,
}

pub async fn handle_token_coins(
    method: Method,
    State(state): State<ExplorerState>,
    Path(owner_hex): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let owner = match parse_hex_32(owner_hex.trim()) {
        Ok(a) => a,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let cache_key = format!("token_coins:{}", hex::encode(owner));
    if let Some(body) = cache_get(&state, &cache_key) {
        return build_response(StatusCode::OK, body, Some(CACHE_60));
    }
    let Ok(_scanning) = state.token_scan.try_acquire() else {
        return token_scan_busy();
    };
    if let Some(body) = cache_get(&state, &cache_key) {
        return build_response(StatusCode::OK, body, Some(CACHE_60));
    }
    // Cap the number of returned coins to bound the response; the SUM is over
    // all matches (not just the returned page).
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .min(10_000);

    let domain = quil_execution::domains::QUIL_TOKEN;
    let transparent =
        quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(&domain).ok();
    let (mut count, mut total, mut truncated) = (0u64, 0u128, false);
    let mut coins: Vec<CoinJson> = Vec::new();
    let mut cb = |vk: Vec<u8>, blob: Vec<u8>| {
        if vk.len() < 64 || is_reserved_token_addr(&vk[32..64]) {
            return;
        }
        let root = quil_tries::deserialize_go_tree(&blob).ok().flatten();
        let tree = quil_tries::VectorCommitmentTree { root };
        let ty = match tree.get(&[0xFFu8; 32]) {
            Some(t) => t,
            None => return,
        };
        if Some(ty) != transparent.as_ref().map(|h| h.as_slice()) {
            return; // private coins have no readable owner — not enumerable here
        }
        if tree.get(&[0x00]) != Some(owner.as_slice()) {
            return;
        }
        let amount = tree
            .get(&[1u8 << 2])
            .map(|a| {
                let mut b = [0u8; 16];
                let n = a.len().min(16);
                b[..n].copy_from_slice(&a[..n]);
                u128::from_le_bytes(b)
            })
            .unwrap_or(0);
        total = total.saturating_add(amount);
        count += 1;
        if coins.len() < limit {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&vk[32..64]);
            coins.push(CoinJson {
                address: hex::encode(addr),
                kind: "transparent",
                value_hidden: false,
                owner: Some(hex::encode(owner)),
                amount_subunits: Some(amount.to_string()),
                amount_quil: Some(quil_str(amount)),
                origin: tree.get(&[2u8 << 2]).map(hex::encode),
                commitment: None,
            });
        } else {
            truncated = true;
        }
    };
    let scanned = state.crdt.for_each_vertex_adds_blob(&domain, &mut cb).unwrap_or(0);

    let response = OwnerCoinsResponse {
        owner: hex::encode(owner),
        units_per_quil: quil_execution::token_intrinsic::constants::QUIL_TOKEN_UNITS,
        count,
        total_subunits: total.to_string(),
        total_quil: quil_str(total),
        coins,
        scanned,
        truncated,
        note: "TRANSPARENT coins only — lattice/decaf private coins have no linkable owner. \
               `total_*` covers all matches; `coins` is capped by ?limit (default 1000). This \
               is a full single-shard scan (no owner index); cached 60s.",
    };
    let body = json_value(&response);
    cache_put(&state, cache_key, body.clone());
    build_response(StatusCode::OK, body, Some(CACHE_60))
}

#[derive(Serialize)]
struct RewardResponse {
    prover: String,
    reward_address: String,
    units_per_quil: u64,
    balance_subunits: String,
    balance_quil: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate_address: Option<String>,
}

/// A prover's earned/mined QUIL — the public `reward:ProverReward` balance,
/// looked up directly by its deterministic address (no scan).
pub async fn handle_token_reward(
    method: Method,
    State(state): State<ExplorerState>,
    Path(prover_hex): Path<String>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let prover = match parse_hex_32(prover_hex.trim()) {
        Ok(a) => a,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    let reward_addr =
        match quil_execution::global_intrinsic::materialize::reward_address(&prover) {
            Ok(a) => a,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "reward address"),
        };
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(&quil_execution::domains::GLOBAL);
    id[32..].copy_from_slice(&reward_addr);
    let location = quil_hypergraph::Location::from_id(&id);

    let (balance, delegate) = match state.crdt.get_vertex_data(&location) {
        Some(blob) => {
            let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            if quil_execution::global_schema::read_type(&tree) == Some("reward:ProverReward") {
                let bal = quil_execution::global_intrinsic::materialize::read_reward_balance(&tree);
                let deleg = quil_execution::global_schema::read_field(
                    &tree,
                    "reward:ProverReward",
                    "DelegateAddress",
                )
                .map(hex::encode);
                (be_bytes_to_u128(&bal), deleg)
            } else {
                (0u128, None)
            }
        }
        None => (0u128, None), // no reward vertex yet ⇒ zero earned
    };

    let response = RewardResponse {
        prover: hex::encode(prover),
        reward_address: hex::encode(reward_addr),
        units_per_quil: quil_execution::token_intrinsic::constants::QUIL_TOKEN_UNITS,
        balance_subunits: balance.to_string(),
        balance_quil: quil_str(balance),
        delegate_address: delegate,
    };
    json_ok(&response, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_str<T: Serialize>(v: &T) -> String {
        String::from_utf8(serde_json::to_vec(v).unwrap()).unwrap()
    }

    fn peer(subpatch: Option<u32>, fingerprint: u8, archive: bool, head: u64, timestamp: i64) -> quil_p2p::CanonicalPeerInfo {
        let mut capabilities = vec![quil_p2p::CanonicalCapability {
            protocol_identifier: quil_p2p::BUILD_FINGERPRINT_CAPABILITY_ID,
            additional_metadata: vec![fingerprint; 32],
        }];
        capabilities.extend(subpatch.map(|subpatch| quil_p2p::CanonicalCapability {
            protocol_identifier: quil_p2p::RELEASE_SUBPATCH_CAPABILITY_ID,
            additional_metadata: subpatch.to_be_bytes().to_vec(),
        }));
        if archive {
            capabilities.push(quil_p2p::CanonicalCapability {
                protocol_identifier: quil_p2p::ARCHIVE_SERVICE_CAPABILITY_ID,
                additional_metadata: Vec::new(),
            });
        }
        quil_p2p::CanonicalPeerInfo {
            version: vec![2, 1, 0],
            patch_number: vec![25],
            capabilities,
            timestamp,
            last_global_head_frame: head,
            ..Default::default()
        }
    }

    #[test]
    fn peer_releases_group_recent_peers_by_release_and_count_those_behind_global() {
        let now = 10_000_000;
        let peers = [
            peer(Some(93), 1, false, 9_990, now - 1_000),
            peer(Some(93), 1, true, 10_000, now - 1_000),
            peer(Some(93), 2, false, 0, now - 1_000),
            peer(None, 3, false, 9_000, now - 1_000),
            peer(None, 4, false, 9_700, now - 1_000),
            peer(Some(92), 5, false, 9_000, now - RELEASE_CENSUS_MAX_AGE_MS - 1),
        ];
        let census = peer_releases(&peers, now, 10_000);
        assert_eq!((census.global_head, census.peers, census.stale_peers), (10_000, 5, 1));
        let summary: Vec<_> = census.releases.iter()
            .map(|g| (g.release.as_str(), g.subpatch, g.peers, g.archives, g.behind_global, g.global_head_min, g.global_head_max))
            .collect();
        assert_eq!(summary, [
            ("2.1.0.25.93", Some(93), 3, 1, 0, 9_990, 10_000),
            ("2.1.0.25", None, 2, 0, 1, 9_000, 9_700),
        ]);
        let builds: Vec<_> = census.releases[0].builds.iter().map(|b| (b.build_fingerprint.clone(), b.peers)).collect();
        assert_eq!(builds, [(Some(hex::encode([1u8; 32])), 2), (Some(hex::encode([2u8; 32])), 1)]);
        assert!(to_str(&census).contains("\"release\":\"2.1.0.25.93\""));
    }

    #[test]
    fn quil_str_is_exact() {
        assert_eq!(quil_str(8_000_000_000), "1");
        assert_eq!(quil_str(4_000_000_000), "0.5");
        assert_eq!(quil_str(12_000_000_000), "1.5");
        assert_eq!(quil_str(1), "0.000000000125"); // 1/8e9 exactly
        assert_eq!(quil_str(0), "0");
    }

    #[test]
    fn decode_transparent_coin_reads_owner_and_amount() {
        use quil_execution::token_intrinsic::legacy_migration::{
            create_transparent_coin_tree, transparent_type_hash, TransparentCoin,
        };
        let domain = quil_execution::domains::QUIL_TOKEN;
        let th = transparent_type_hash(&domain).unwrap();
        let coin = TransparentCoin { owner_address: [0x7Au8; 32], amount: 16_000_000_000 }; // 2 QUIL
        let tree = create_transparent_coin_tree(&coin, &th, &[0x33u8; 32]).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

        let c = decode_coin(&domain, &[0xABu8; 32], &blob).unwrap();
        assert_eq!(c.kind, "transparent");
        assert!(!c.value_hidden);
        assert_eq!(c.owner.as_deref(), Some(hex::encode([0x7Au8; 32]).as_str()));
        assert_eq!(c.amount_subunits.as_deref(), Some("16000000000"));
        assert_eq!(c.amount_quil.as_deref(), Some("2"));
        assert_eq!(c.origin.as_deref(), Some(hex::encode([0x33u8; 32]).as_str()));
        assert_eq!(c.commitment, None);
    }

    #[test]
    fn be_bytes_to_u128_reads_fillbytes_and_guards_overflow() {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&1000u64.to_be_bytes()); // 32-byte BE FillBytes(1000)
        assert_eq!(be_bytes_to_u128(&b), 1000);
        let mut big = [0u8; 32];
        big[0] = 1; // > 2^128
        assert_eq!(be_bytes_to_u128(&big), u128::MAX);
    }

    #[test]
    fn reward_balance_decodes_as_public_quil() {
        use quil_execution::global_intrinsic::materialize::{read_reward_balance, set_reward_balance};
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let mut bal = [0u8; 32];
        bal[24..].copy_from_slice(&(2u64 * 8_000_000_000).to_be_bytes()); // 2 QUIL
        set_reward_balance(&mut tree, &bal).unwrap();
        assert_eq!(quil_execution::global_schema::read_type(&tree), Some("reward:ProverReward"));
        let raw = read_reward_balance(&tree);
        assert_eq!(be_bytes_to_u128(&raw), 16_000_000_000);
        assert_eq!(quil_str(be_bytes_to_u128(&raw)), "2");
    }

    #[test]
    fn decode_private_coin_hides_amount() {
        // A `coin:Coin`-typed vertex (lattice/decaf) must decode as value-hidden
        // with no owner. Build a minimal tree with just the private type leaf.
        let domain = quil_execution::domains::QUIL_TOKEN;
        let private = quil_execution::token_intrinsic::materialize::coin_type_hash(&domain).unwrap();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[2u8 << 2], &[0xCDu8; 40], &[], &num_bigint::BigInt::from(40)).unwrap();
        tree.insert(&[0xFFu8; 32], &private, &[], &num_bigint::BigInt::from(32)).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

        let c = decode_coin(&domain, &[0x01u8; 32], &blob).unwrap();
        assert_eq!(c.kind, "private");
        assert!(c.value_hidden);
        assert_eq!(c.owner, None);
        assert_eq!(c.amount_subunits, None);
        assert_eq!(c.commitment.as_deref(), Some(hex::encode([0xCDu8; 40]).as_str()));
    }

    #[test]
    fn allocation_omits_zero_frames_and_empty_filters() {
        // active status, everything else zero/empty -> only "status".
        let alloc = RestProverAllocation {
            status: "active".into(),
            confirmation_filter: String::new(),
            rejection_filter: String::new(),
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
        };
        assert_eq!(to_str(&alloc), r#"{"status":"active"}"#);
    }

    #[test]
    fn allocation_includes_set_fields_in_order() {
        let alloc = RestProverAllocation {
            status: "joining".into(),
            confirmation_filter: "ab".into(),
            rejection_filter: String::new(),
            join_frame_number: 5,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 9,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
        };
        // Declaration order preserved; rejection_filter + zero frames omitted.
        assert_eq!(
            to_str(&alloc),
            r#"{"status":"joining","confirmation_filter":"ab","join_frame_number":5,"join_confirm_frame_number":9}"#
        );
    }

    #[test]
    fn prover_info_minimal_shape() {
        let info = ProverInfo {
            public_key: vec![0xAA],
            address: vec![0xBB],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };
        let rest = convert_prover_info(&info, None);
        // kick_frame_number (0) and delegate_address (empty) omitted;
        // allocations present as []; field order matches the Go struct.
        assert_eq!(
            to_str(&rest),
            r#"{"address":"bb","public_key":"aa","status":"active","available_storage":0,"seniority":0,"allocations":[]}"#
        );
    }

    #[test]
    fn prover_info_with_delegate_and_kick() {
        let info = ProverInfo {
            public_key: vec![0x01],
            address: vec![0x02],
            status: ProverStatus::Kicked,
            kick_frame_number: 7,
            allocations: vec![],
            available_storage: 100,
            seniority: 3,
            delegate_address: vec![0xDE],
        };
        let rest = convert_prover_info(&info, None);
        assert_eq!(
            to_str(&rest),
            r#"{"address":"02","public_key":"01","status":"kicked","kick_frame_number":7,"available_storage":100,"seniority":3,"delegate_address":"de","allocations":[]}"#
        );
    }

    #[test]
    fn prover_allocation_filter_inclusion() {
        let filter = vec![0xCA, 0xFE];
        let info = ProverInfo {
            public_key: vec![],
            address: vec![],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![
                ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: filter.clone(),
                    rejection_filter: vec![],
                    join_frame_number: 0,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    last_signed_frame_number: 0,
                    epoch: 0,
                    ring: 0,
                    vertex_address: vec![],
                },
                ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: vec![0x11, 0x22],
                    rejection_filter: vec![],
                    join_frame_number: 0,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    last_signed_frame_number: 0,
                    epoch: 0,
                    ring: 0,
                    vertex_address: vec![],
                },
            ],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };
        // filter=None -> all allocations.
        assert_eq!(convert_prover_info(&info, None).allocations.len(), 2);
        // filter=Some(cafe) -> only the matching allocation.
        let filtered = convert_prover_info(&info, Some(&filter));
        assert_eq!(filtered.allocations.len(), 1);
        assert_eq!(filtered.allocations[0].confirmation_filter, "cafe");
    }

    #[test]
    fn seniority_entry_omits_public_key() {
        let entry = SeniorityEntry {
            rank: 1,
            address: "ab".into(),
            seniority: 5,
            status: "active".into(),
            active_shards: 3,
        };
        let s = to_str(&entry);
        assert!(s.contains(r#""active_shards":3"#), "{s}");
        assert!(!s.contains("public_key"), "{s}");
    }

    #[test]
    fn peer_capabilities_null_when_empty_array_when_present() {
        let empty = PeerInfoJson {
            peer_id: "p".into(),
            version: "v".into(),
            patch_number: "01".into(),
            cores: 0,
            last_seen: 5,
            last_received_frame: 0,
            last_global_head_frame: 0,
            release: "2.1.0.25".into(),
            subpatch: None,
            build_fingerprint: None,
            capabilities: None,
            reachability: None,
        };
        let s = to_str(&empty);
        // No omitempty -> keys present; empty -> null (matches Go nil slice).
        assert!(s.contains(r#""capabilities":null"#), "{s}");
        assert!(s.contains(r#""reachability":null"#), "{s}");
        assert!(s.contains(r#""cores":0"#));
        // 64-bit frame fields emitted as NUMBERS (custom-JSON path).
        assert!(s.contains(r#""last_received_frame":0"#));
        assert!(s.contains(r#""release":"2.1.0.25","subpatch":null,"build_fingerprint":null"#), "{s}");

        let with_cap = PeerInfoJson {
            capabilities: Some(vec![PeerCapabilityJson {
                protocol_identifier: 7,
                additional_metadata: "AQID".into(),
            }]),
            ..empty
        };
        let s = to_str(&with_cap);
        assert!(s.contains(r#""capabilities":[{"protocol_identifier":7,"additional_metadata":"AQID"}]"#), "{s}");
    }

    #[test]
    fn shard_summary_shape() {
        let mut counts = BTreeMap::new();
        counts.insert("active".to_string(), 2i64);
        counts.insert("joining".to_string(), 1i64);
        let summary = RestProverShardSummary {
            filter: "ab".into(),
            counts,
            size_bytes: "1024".into(),
            active_workers: 3,
            data_shards: 224,
        };
        // counts keys sorted (BTreeMap == Go's encoding/json map-key sort);
        // size_bytes is a string; data_shards/active_workers are numbers.
        assert_eq!(
            to_str(&summary),
            r#"{"filter":"ab","counts":{"active":2,"joining":1},"size_bytes":"1024","active_workers":3,"data_shards":224}"#
        );
    }

    #[test]
    fn stats_keeps_its_keys_and_appends_app_shards() {
        let stats = |app_shards: Option<production::AppShardsStats>| StatsResponse {
            current_frame: 7,
            eviction_threshold: 360,
            total_provers: 2,
            by_status: BTreeMap::from([("active".to_string(), 2i64)]),
            total_seniority: 5,
            eviction_pending: 1,
            at_risk: 1,
            halted_shards: 0,
            app_shards,
            app_shard_history: production::history::Rows::default().stats(),
            provers_as_of_frame: Some(7),
            provers_stale: false,
        };
        let old = r#"{"current_frame":7,"eviction_threshold":360,"total_provers":2,"by_status":{"active":2},"total_seniority":5,"eviction_pending":1,"at_risk":1,"halted_shards":0"#;
        let history = r#""app_shard_history":{"rows":0,"first_row_frame":null,"last_row_frame":null,"backfill_complete":false}"#;
        let provers = r#""provers_as_of_frame":7,"provers_stale":false"#;
        assert_eq!(to_str(&stats(None)), format!(r#"{old},"app_shards":null,{history},{provers}}}"#));

        let (none, empty) = (HashMap::new(), BTreeSet::new());
        let grid = production::GridView { grid: Some(BTreeSet::new()), ..Default::default() };
        let report = production::assemble(
            &production::IndexView::default(),
            &production::Inputs {
                head_frame: 9,
                grid: &grid,
                active: Some((9, &none)),
                halted: &empty,
                committed: &HashMap::new(),
                quil: quil_str,
            },
        );
        let s = to_str(&stats(Some(report.stats())));
        assert!(
            s.starts_with(&format!(
                r#"{old},"app_shards":{{"head_frame":9,"indexed_through":null,"window_frames":240,"window_complete":false,"index_waiting_frame":null,"median_frame_interval_ms":null,"stored_head_frame":null,"stored_head_timestamp_ms":null,"as_of_frame":null,"as_of_timestamp_ms":null,"lag_frames":null,"stale":true,"stale_reason":"values unknown: no live shard: no registry filter is on the grid and no grid shard holds data","values_known":false,"built_at_ms":0,"live_shards":0,"#
            )),
            "{s}"
        );
        assert!(
            s.ends_with(&format!(r#""grid_source":"local_store","grid_shards":0,"grid_digest":"e3b0c442","grid_unavailable":null}},{history},{provers}}}"#)),
            "{s}"
        );
    }

    #[test]
    fn json_value_has_trailing_newline_error_has_shape() {
        let body = json_value(&vec![1, 2, 3]);
        assert_eq!(body, b"[1,2,3]\n");
        let resp = error(StatusCode::BAD_REQUEST, "bad thing");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cache_insert_drops_expired_entries() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        cache_insert(&mut cache, t0, "old".into(), vec![1]);
        cache_insert(&mut cache, t0 + PROVER_CACHE_TTL / 2, "live".into(), vec![2]);
        // Past the first entry's expiry, before the second's.
        let now = t0 + PROVER_CACHE_TTL + Duration::from_secs(1);
        cache_insert(&mut cache, now, "new".into(), vec![3]);
        assert!(!cache.contains_key("old"));
        assert_eq!(cache.get("live").map(|(_, body)| body.clone()), Some(vec![2]));
        assert!(cache.contains_key("new"));
    }

    #[test]
    fn cache_holds_at_most_its_bound_of_live_entries() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        for n in 0..CACHE_MAX_ENTRIES + 10 {
            cache_insert(&mut cache, t0, format!("k{n}"), vec![1]);
        }
        assert_eq!(cache.len(), CACHE_MAX_ENTRIES);
        assert!(!cache.contains_key(&format!("k{}", CACHE_MAX_ENTRIES)), "a new key past the bound is not cached");
        cache_insert(&mut cache, t0, "k0".into(), vec![2]);
        assert_eq!(cache.get("k0").map(|(_, body)| body.clone()), Some(vec![2]), "a held key is refreshed");
        let later = t0 + PROVER_CACHE_TTL + Duration::from_secs(1);
        cache_insert(&mut cache, later, "fresh".into(), vec![3]);
        assert_eq!(cache.len(), 1, "expired entries make room");
    }

    #[tokio::test]
    async fn token_scans_run_one_at_a_time() {
        let state = empty_state();
        let held = state.token_scan.clone().try_acquire_owned().unwrap();
        let owner = "11".repeat(32);
        let coins = || handle_token_coins(Method::GET, State(state.clone()), Path(owner.clone()), Query(HashMap::new()));
        let busy = coins().await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers()["Retry-After"], TOKEN_SCAN_RETRY_SECS.to_string().as_str());
        let scan = HashMap::from([("scan".to_string(), "1".to_string())]);
        let supply = handle_token_supply(Method::GET, State(state.clone()), Query(scan.clone())).await;
        assert_eq!(supply.status(), StatusCode::SERVICE_UNAVAILABLE);
        let plain = handle_token_supply(Method::GET, State(state.clone()), Query(HashMap::new())).await;
        assert_eq!(plain.status(), StatusCode::OK, "the supply without a scan is not held back");
        drop(held);
        assert_eq!(coins().await.status(), StatusCode::OK);
        assert_eq!(handle_token_supply(Method::GET, State(state.clone()), Query(scan)).await.status(), StatusCode::OK);
        assert_eq!(state.token_scan.available_permits(), 1, "a finished scan returns its permit");
    }

    /// An explorer over an empty in-memory store.
    fn empty_state() -> ExplorerState {
        state_with_shards(&[], None)
    }

    /// An explorer over an in-memory store holding only the shard rows
    /// `rows`, sized by `sizes` (an archive's provider).
    fn state_with_shards(rows: &[quil_types::store::ShardInfo], sizes: Option<crate::AppShardsProvider>) -> ExplorerState {
        use quil_types::store::{KvDb as _, ShardsStore as _};
        let db = quil_store::RocksDb::open_in_memory().expect("an in-memory store");
        let raw = db.inner();
        let txn = db.new_batch(false).unwrap();
        for row in rows {
            quil_store::RocksShardsStore::new(raw.clone()).put_app_shard(txn.as_ref(), row).unwrap();
        }
        txn.commit().unwrap();
        let hg = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        ExplorerState::new(
            Arc::new(quil_store::RocksClockStore::new(raw.clone())),
            crdt,
            Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
            Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
            Arc::new(quil_store::RocksShardsStore::new(raw)),
            sizes,
            None,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(crate::RecentMessageRing::new(16)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    fn recent(time: std::time::SystemTime, from: &[u8], data: &[u8]) -> crate::RecentMessage {
        crate::RecentMessage {
            time,
            from: from.to_vec().into(),
            bitmask: vec![0xBB].into(),
            seqno: Default::default(),
            signature: vec![0x51, 0x47].into(),
            key: Default::default(),
            data: data.to_vec().into(),
        }
    }

    #[test]
    fn messages_json_keeps_its_shape() {
        let at = std::time::UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        let ring = crate::RecentMessageRing::new(4);
        ring.record(recent(at, &[0x01, 0xAB], &[0x00, 0xFF]));
        ring.record(recent(at, &[0x02], &[]));
        let body = messages_body(&ring, 50, Instant::now());
        // Newest first; hex lowercase; every field present; trailing newline.
        let expected = concat!(
            r#"[{"timestamp":"2023-11-14T22:13:20.000000005Z","from":"02","bitmask":"bb","seqno":"","signature":"5147","key":"","data":""},"#,
            r#"{"timestamp":"2023-11-14T22:13:20.000000005Z","from":"01ab","bitmask":"bb","seqno":"","signature":"5147","key":"","data":"00ff"}]"#,
            "\n"
        );
        assert_eq!(std::str::from_utf8(&body).unwrap(), expected);
        // The same bytes serde would produce for the old shape.
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value[1]["data"], "00ff");
        // Empty ring: an empty array, as before.
        let empty = crate::RecentMessageRing::new(4);
        assert_eq!(&messages_body(&empty, 50, Instant::now())[..], b"[]\n");
    }

    #[test]
    fn messages_body_is_cached_per_version_and_limit() {
        let ring = crate::RecentMessageRing::new(8);
        ring.push_received(&[1], &[2], &[3]);
        let t0 = Instant::now();
        let first = messages_body(&ring, 50, t0);
        assert_eq!(first.as_ptr(), messages_body(&ring, 50, t0 + Duration::from_secs(30)).as_ptr());
        // A push within the window is not shown yet; beyond it, it is.
        ring.push_received(&[4], &[2], &[3]);
        let soon = messages_body(&ring, 50, t0 + MESSAGES_CACHE_MAX_AGE / 2);
        assert_eq!(first.as_ptr(), soon.as_ptr());
        let later = messages_body(&ring, 50, t0 + MESSAGES_CACHE_MAX_AGE * 2);
        assert_ne!(first, later);
        assert_eq!(later.iter().filter(|b| **b == b'{').count(), 2);
        // Another limit is not served the cached body.
        let one = messages_body(&ring, 1, t0 + MESSAGES_CACHE_MAX_AGE * 2);
        assert_eq!(one.iter().filter(|b| **b == b'{').count(), 1);
    }

    #[test]
    fn parse_hex_id_validation() {
        assert!(parse_hex_id("zz").is_err()); // not hex
        assert_eq!(parse_hex_id(&"ab".repeat(10)).unwrap_err(), "identifier must be 64 bytes");
        assert!(parse_hex_id(&"ab".repeat(64)).is_ok()); // 64 bytes
    }

    fn active_alloc(filter: Vec<u8>, last_active: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter,
            rejection_filter: vec![],
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: last_active,
            last_signed_frame_number: 0,
            // Current-epoch so `effective_status` reads Active (not
            // ExpiredEpoch) at the ~EVICTION_INACTIVITY_START_FRAME test frames;
            // epoch is well above any frame these tests use.
            epoch: quil_types::consensus::epoch_for_frame(
                quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 100_000,
            ),
            ring: 0,
            vertex_address: vec![],
        }
    }

    #[test]
    fn assess_allocation_matches_evictor_rule() {
        // Frame past the inactivity start; last_active predates it, so
        // inactivity is measured from EVICTION_INACTIVITY_START_FRAME.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 290;
        let mut halts = HashMap::new();
        // Census that puts every shard used here AT quorum, so the
        // under-provisioned exemption never fires and each `None` below is for
        // its intended reason (halt / inactivity / status).
        let quorum = quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS;
        let census: HashMap<Vec<u8>, u64> = [
            (vec![0xAAu8], quorum),
            (vec![0xBBu8], quorum),
            (vec![0xCCu8], quorum),
        ]
        .into_iter()
        .collect();

        // Active non-global alloc, no halt: effective = inactivity since
        // the start frame (NOT since last_active, which predates it).
        let a = active_alloc(vec![0xAA], 81_000);
        let r = assess_allocation(&a, frame, &halts, &census).unwrap();
        assert_eq!(r.total_inactive, 290);
        assert_eq!(r.effective_inactive, 290);

        // Before the inactivity start, nobody accrues inactivity → None,
        // even if they've been inactive "forever" by last_active.
        assert!(assess_allocation(&a, start, &HashMap::new(), &census).is_none());
        assert!(assess_allocation(&a, start - 1, &HashMap::new(), &census).is_none());

        // Partial halt is subtracted.
        halts.insert(vec![0xAA], 100u64);
        let r = assess_allocation(&a, frame, &halts, &census).unwrap();
        assert_eq!(r.effective_inactive, 190);

        // Full halt (u64::MAX) -> exempt -> None.
        halts.insert(vec![0xAA], u64::MAX);
        assert!(assess_allocation(&a, frame, &halts, &census).is_none());

        // Under-provisioned shard (below consensus quorum) -> exempt, mirroring
        // the evictor: no halt entry and long inactive, yet not at risk.
        let under: HashMap<Vec<u8>, u64> =
            [(vec![0xAAu8], quorum - 1)].into_iter().collect();
        assert!(assess_allocation(&a, frame, &HashMap::new(), &under).is_none());

        // Global allocation (empty filter) -> never at risk.
        assert!(assess_allocation(&active_alloc(vec![], 81_000), frame, &HashMap::new(), &census).is_none());

        // last_active 0 or not-yet-inactive -> None.
        assert!(assess_allocation(&active_alloc(vec![0xBB], 0), frame, &HashMap::new(), &census).is_none());
        assert!(
            assess_allocation(&active_alloc(vec![0xBB], frame + 5), frame, &HashMap::new(), &census)
                .is_none()
        );

        // Non-active allocation -> None.
        let mut paused = active_alloc(vec![0xCC], 81_000);
        paused.status = ProverStatus::Paused;
        assert!(assess_allocation(&paused, frame, &HashMap::new(), &census).is_none());
    }

    #[test]
    fn fresh_census_feeds_the_evictor_stall_rule() {
        // Shard 0xAA: four members at exactly the threshold and two stale →
        // progressing. Shard 0xBB: three fresh, three stale → stalled. Shard
        // 0xCC: a never-credited member (last active 0) is active, not fresh.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let frame = start + 5000;
        let threshold = crate::EVICTION_THRESHOLD_FRAMES;
        let member = |filter: u8, last_active: u64| ProverInfo {
            public_key: vec![],
            address: vec![],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![active_alloc(vec![filter], last_active)],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        };
        let mut provers = Vec::new();
        for (filter, last_active, count) in [
            (0xAAu8, frame - threshold, 4),
            (0xAA, start + 100, 2),
            (0xBB, frame, 3),
            (0xBB, start + 100, 3),
            (0xCC, frame, 2),
            (0xCC, 0, 1),
        ] {
            for _ in 0..count {
                provers.push(member(filter, last_active));
            }
        }
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let active = active_allocations_by_filter(&provers, frame);
        let fresh = fresh_allocations_by_filter(
            &provers,
            frame,
            &halts,
            threshold,
            quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
        );
        let census = |filter: u8| {
            let get = |m: &HashMap<Vec<u8>, u64>| m.get(&vec![filter]).copied().unwrap_or(0);
            (get(&active), get(&fresh))
        };
        assert_eq!(census(0xAA), (6, 4));
        assert_eq!(census(0xBB), (6, 3));
        assert_eq!(census(0xCC), (3, 2));
        assert!(shard_progressing(6, 4));
        assert!(!shard_progressing(6, 3));
    }

    #[test]
    fn fresh_census_reads_signed_frames_once_they_govern() {
        // Shard 0xDD stalled with recent re-confirms: four members confirmed
        // within the threshold but recorded no signed frame, two are stale.
        // Shard 0xEE produces: four signed within the threshold, two are
        // stale. Read by last active both are progressing; once signed frames
        // govern, only 0xEE is, as the evictor's census reads them.
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let threshold = crate::EVICTION_THRESHOLD_FRAMES;
        let activation = start + 2000;
        let frame = activation + threshold + 100;
        let member = |filter: u8, last_active: u64, last_signed: u64| {
            let mut alloc = active_alloc(vec![filter], last_active);
            alloc.last_signed_frame_number = last_signed;
            ProverInfo {
                public_key: vec![],
                address: vec![],
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: vec![alloc],
                available_storage: 0,
                seniority: 0,
                delegate_address: vec![],
            }
        };
        let mut provers = Vec::new();
        for (filter, last_active, last_signed, count) in [
            (0xDDu8, frame - 10, 0, 4),
            (0xDD, start + 100, 0, 2),
            (0xEE, frame - 10, frame - 100, 4),
            (0xEE, start + 100, 0, 2),
        ] {
            for _ in 0..count {
                provers.push(member(filter, last_active, last_signed));
            }
        }
        let halts: HashMap<Vec<u8>, u64> = HashMap::new();
        let active = active_allocations_by_filter(&provers, frame);
        let census = |signed_frame_activation: u64, filter: u8| {
            let fresh = fresh_allocations_by_filter(
                &provers,
                frame,
                &halts,
                threshold,
                signed_frame_activation,
            );
            let get = |m: &HashMap<Vec<u8>, u64>| m.get(&vec![filter]).copied().unwrap_or(0);
            (get(&active), get(&fresh))
        };
        let default = quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME;
        assert_eq!(census(default, 0xDD), (6, 4));
        assert_eq!(census(default, 0xEE), (6, 4));
        assert_eq!(census(activation, 0xDD), (6, 0));
        assert_eq!(census(activation, 0xEE), (6, 4));
        // Each count is the evictor's own predicate over the same allocations.
        for p in &provers {
            let alloc = &p.allocations[0];
            let fresh = |a| allocation_fresh_at(alloc, frame, 0, threshold, a);
            assert_eq!(fresh(activation), alloc.last_signed_frame_number == frame - 100);
            assert_eq!(fresh(default), alloc.last_active_frame_number == frame - 10);
        }
    }

    #[test]
    fn eviction_risk_entry_runway_and_flag() {
        // 350 frames inactive, threshold 360 -> 10 frames runway, not yet evictable.
        let threshold = crate::EVICTION_THRESHOLD_FRAMES;
        let effective = 350u64;
        let entry = EvictionRiskEntry {
            address: "ab".into(),
            seniority: 5,
            filter: "ef".into(),
            last_active_frame_number: 100,
            current_frame: 450,
            shard_halt_duration: 0,
            frames_inactive: 350,
            effective_inactive: effective,
            eviction_threshold: threshold,
            frames_until_eviction: threshold.saturating_sub(effective),
            risk_ratio: effective as f64 / threshold as f64,
            eviction_pending: effective > threshold,
            shard_progressing: true,
        };
        assert_eq!(entry.frames_until_eviction, 10);
        assert!(!entry.eviction_pending);
        let s = to_str(&entry);
        assert!(s.contains(r#""frames_until_eviction":10"#), "{s}");
        assert!(s.contains(r#""eviction_threshold":360"#), "{s}");
        assert!(!s.contains("public_key"), "{s}");
    }

    #[test]
    fn eviction_risk_selection_keeps_order_and_pending() {
        let threshold = crate::EVICTION_THRESHOLD_FRAMES;
        let entry = |address: &str, filter: &str, runway: u64, pending: bool| {
            let effective = threshold - runway;
            EvictionRiskEntry {
                address: address.into(),
                seniority: 0,
                filter: filter.into(),
                last_active_frame_number: 1,
                current_frame: 1000,
                shard_halt_duration: 0,
                frames_inactive: effective,
                effective_inactive: effective,
                eviction_threshold: threshold,
                frames_until_eviction: runway,
                risk_ratio: effective as f64 / threshold as f64,
                eviction_pending: pending,
                shard_progressing: true,
            }
        };
        // As the handler emits them: most at risk first, and the shard
        // floor leaves "bb" on shard 01 stale but not pending.
        let entries = || {
            vec![
                entry("aa", "01", 0, true),
                entry("bb", "01", 0, false),
                entry("aa", "02", 50, false),
                entry("cc", "02", 200, false),
            ]
        };
        let pick_at = |min_ratio: f64, address: Option<&str>, filter: Option<&str>, limit: Option<usize>| {
            let selection = EvictionRiskSelection {
                min_ratio,
                address: address.map(String::from),
                filter: filter.map(String::from),
                limit,
            };
            let entries = entries();
            let (selected, total) = select_eviction_risk(&entries, &selection);
            let selected = selected
                .into_iter()
                .map(|e| (e.address.clone(), e.filter.clone(), e.eviction_pending))
                .collect::<Vec<_>>();
            (selected, total)
        };
        let pick = |address: Option<&str>, filter: Option<&str>, limit: Option<usize>| pick_at(0.0, address, filter, limit);
        let rows = |r: &[(&str, &str, bool)]| {
            r.iter()
                .map(|&(a, f, p)| (a.to_string(), f.to_string(), p))
                .collect::<Vec<_>>()
        };
        let (all, total) = pick(None, None, None);
        assert_eq!((all.len(), total), (4, 4));
        assert_eq!(
            pick(Some("aa"), None, None),
            (rows(&[("aa", "01", true), ("aa", "02", false)]), 2)
        );
        assert_eq!(pick(Some("bb"), None, None), (rows(&[("bb", "01", false)]), 1));
        assert_eq!(
            pick(None, Some("02"), None),
            (rows(&[("aa", "02", false), ("cc", "02", false)]), 2)
        );
        // The limit keeps the most at risk; the total counts all selected.
        assert_eq!(
            pick(None, None, Some(2)),
            (rows(&[("aa", "01", true), ("bb", "01", false)]), 4)
        );
        assert_eq!(pick(Some("aa"), Some("02"), Some(1)), (rows(&[("aa", "02", false)]), 1));
        let (none, total) = pick(None, Some("01"), Some(0));
        assert!(none.is_empty());
        assert_eq!(total, 2);
        // `min_ratio` leaves out lower ratios before the count; NaN none.
        assert_eq!(
            pick_at(0.5, None, None, Some(1)),
            (rows(&[("aa", "01", true)]), 3)
        );
        assert_eq!(pick_at(f64::NAN, None, None, None).1, 4);
    }

    /// An active prover at `address` with one allocation on `filter`.
    fn prover_on(address: u8, filter: u8, last_active: u64) -> ProverInfo {
        ProverInfo {
            public_key: vec![],
            address: vec![address],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![active_alloc(vec![filter], last_active)],
            available_storage: 0,
            seniority: 1,
            delegate_address: vec![],
        }
    }

    /// Shard 0xaa at `frame`: four members active 10 frames ago (a0..a3),
    /// one past half the threshold (a4), one past it (a5); and a kicked
    /// prover (b0).
    fn assessed_provers(frame: u64) -> Vec<ProverInfo> {
        let start = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME;
        let mut provers: Vec<ProverInfo> = (0..4).map(|i| prover_on(0xA0 + i, 0xAA, frame - 10)).collect();
        provers.push(prover_on(0xA4, 0xAA, frame - 200));
        provers.push(prover_on(0xA5, 0xAA, start + 100));
        let mut kicked = prover_on(0xB0, 0xAA, 0);
        kicked.status = ProverStatus::Kicked;
        kicked.allocations.clear();
        provers.push(kicked);
        provers
    }

    #[test]
    fn eviction_assessment_counts_provers_and_orders_entries() {
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 5000;
        let provers = assessed_provers(frame);
        let halts = HashMap::from([(vec![0xBB], u64::MAX), (vec![0xCC], 50)]);
        let e = assess_eviction(frame, Instant::now(), Some((frame - 1, provers.as_slice())), &halts);
        assert_eq!((e.frame, e.provers_as_of_frame, e.total_provers, e.total_seniority), (frame, Some(frame - 1), 7, 7));
        assert_eq!(e.by_status, BTreeMap::from([("active".to_string(), 6), ("kicked".to_string(), 1)]));
        // Provers past the threshold, and past half of it.
        assert_eq!((e.eviction_pending, e.at_risk), (1, 2));
        assert_eq!(e.halted, BTreeSet::from([vec![0xBB]]));
        // Most at risk first, ties in registry order; only a5 is pending:
        // the shard keeps its floor after evicting it.
        let order: Vec<(&str, u64, bool)> = e
            .entries
            .iter()
            .map(|x| (x.address.as_str(), x.frames_until_eviction, x.eviction_pending))
            .collect();
        assert_eq!(
            order,
            [("a5", 0, true), ("a4", 160, false), ("a0", 350, false), ("a1", 350, false), ("a2", 350, false), ("a3", 350, false)]
        );
        assert!(e.entries.iter().all(|x| x.current_frame == frame && x.shard_progressing));
        // Before the registry is read: placeholders, halts still counted.
        let unread = assess_eviction(frame, Instant::now(), None, &halts);
        assert_eq!((unread.provers_as_of_frame, unread.total_provers, unread.entries.len(), unread.halted.len()), (None, 0, 0, 1));
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn stats_and_eviction_risk_serve_the_latest_assessment() {
        let state = empty_state();
        let frame = quil_types::consensus::EVICTION_INACTIVITY_START_FRAME + 5000;
        // The head moved on and the registry is empty: a request assessing
        // for itself would read frame + 1 and no prover.
        state.current_frame.store(frame + 1, Ordering::Relaxed);
        let provers = assessed_provers(frame);
        let halts = HashMap::from([(vec![0xBB], u64::MAX)]);
        *state.eviction.write() = Some(Arc::new(assess_eviction(frame, Instant::now(), Some((frame, provers.as_slice())), &halts)));

        let stats = body_json(handle_stats(Method::GET, State(state.clone())).await).await;
        let count = |key: &str| stats[key].as_u64();
        assert_eq!(
            (count("current_frame"), count("total_provers"), count("eviction_pending"), count("at_risk"), count("halted_shards")),
            (Some(frame), Some(7), Some(1), Some(2), Some(1))
        );
        assert_eq!((count("provers_as_of_frame"), stats["provers_stale"].as_bool()), (Some(frame), Some(false)));

        let query = HashMap::from([("min_ratio".to_string(), "0.5".to_string()), ("limit".to_string(), "1".to_string())]);
        let risk = handle_eviction_risk(Method::GET, State(state.clone()), Query(query)).await;
        assert_eq!(risk.status(), StatusCode::OK);
        assert_eq!(risk.headers()["X-Total-Count"], "2");
        let risk = body_json(risk).await;
        assert_eq!(risk.as_array().map(Vec::len), Some(1));
        assert_eq!(
            (risk[0]["address"].as_str(), risk[0]["eviction_pending"].as_bool(), risk[0]["current_frame"].as_u64()),
            (Some("a5"), Some(true), Some(frame))
        );

        // An assessment made before the registry was read: 503, as before.
        *state.eviction.write() = Some(Arc::new(assess_eviction(frame, Instant::now(), None, &halts)));
        let unread = handle_eviction_risk(Method::GET, State(state.clone()), Query(HashMap::new())).await;
        assert_eq!(unread.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A root row under GLOBAL's address, as an archive's shards store holds
    /// one, is no app shard: `/provers/shards` leaves it out, sized or not.
    #[tokio::test]
    async fn provers_shards_leave_out_a_global_row() {
        let row = |l2: [u8; 32], prefix: Vec<u32>| {
            let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(&l2, 256, 3).to_vec();
            shard_key.extend_from_slice(&l2);
            quil_types::store::ShardInfo { shard_key, prefix, size: vec![], data_shards: 0, commitment: vec![] }
        };
        let quil = quil_execution::domains::QUIL_TOKEN;
        let (global, other) = (quil_execution::domains::GLOBAL, [0xaa; 32]);
        let rows = [row(quil, vec![0]), row(global, vec![]), row(other, vec![])];
        let sized: crate::AppShardsProvider = Arc::new(|_: &[u8], _: &[u32]| Some((vec![1], 1, Default::default())));
        let state = state_with_shards(&rows, Some(sized));
        let sizes = compute_shard_sizes(&state);
        let app = |l2: [u8; 32], prefix: &[u32]| hex::encode(quil_forest::shard_prefix_to_filter(&l2, prefix));
        let mut keys: Vec<&String> = sizes.keys().collect();
        keys.sort();
        let mut expected = vec![app(quil, &[0]), app(other, &[])];
        expected.sort();
        assert_eq!(keys, expected.iter().collect::<Vec<_>>(), "QUIL and another app; GLOBAL out");
        let listed = body_json(handle_prover_shards(Method::GET, State(state)).await).await;
        let filters: Vec<&str> = listed.as_array().unwrap().iter().filter_map(|s| s["filter"].as_str()).collect();
        assert_eq!(filters, expected.iter().map(String::as_str).collect::<Vec<_>>(), "every sized app shard, not GLOBAL");
    }

    #[test]
    fn an_assessment_serves_until_its_age_bound_then_is_made_at_the_head() {
        let state = empty_state();
        let t0 = Instant::now();
        let latest = Arc::new(assess_eviction(10, t0, None, &HashMap::new()));
        *state.eviction.write() = Some(Arc::clone(&latest));
        // Within the bound the latest serves, whatever the head.
        assert!(Arc::ptr_eq(&served_eviction(&state, 12, t0 + EVICTION_SERVE_MAX_AGE / 2), &latest));
        // Past it, one is made at the head, kept and shared at that head.
        let later = t0 + EVICTION_SERVE_MAX_AGE;
        let made = served_eviction(&state, 12, later);
        assert_eq!(made.frame, 12);
        assert!(Arc::ptr_eq(&made, &eviction_at(&state, 12, later + PROVER_SNAPSHOT_MAX_AGE / 2)));
        assert!(Arc::ptr_eq(&made, state.eviction.read().as_ref().unwrap()));
        // A new head is assessed anew.
        assert_eq!(eviction_at(&state, 13, later).frame, 13);
    }

    #[test]
    fn frame_body_is_the_round_trip_body() {
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader, MessageBundle};
        use quil_types::store::{RequestOutcome, RequestStatus};
        let frame = GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: 42,
                timestamp: 651_000,
                output: vec![1, 2, 3],
                ..Default::default()
            }),
            requests: vec![MessageBundle::default(), MessageBundle::default()],
        };
        let outcomes = [
            RequestOutcome { status: RequestStatus::Succeeded, error: String::new() },
            RequestOutcome { status: RequestStatus::Failed, error: "no".into() },
        ];
        // The body as the handler built it before: protojson, parsed into a
        // value, `requestOutcomes` added, written again.
        let bytes = protojson::to_protojson(protojson::GLOBAL_FRAME, &frame).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v.as_object_mut().unwrap().insert(
            "requestOutcomes".into(),
            serde_json::json!([
                { "status": RequestStatus::Succeeded.name(), "error": "" },
                { "status": RequestStatus::Failed.name(), "error": "no" },
            ]),
        );
        assert_eq!(frame_body(&frame, &outcomes).unwrap(), serde_json::to_vec(&v).unwrap());
        let without = frame_body(&frame, &[]).unwrap();
        assert!(without.windows(20).any(|w| w == b"\"requestOutcomes\":[]"));
    }

    #[test]
    fn hyperedge_size_counts_extrinsic_ids_in_the_blob_read() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        for key in [vec![1u8; 64], vec![2; 64], vec![3; 64], vec![4; 32]] {
            tree.insert(&key, &[9], &[], &BigInt::from(1)).unwrap();
        }
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        // As `get_hyperedge_extrinsic_ids` lists them: the 64-byte keys.
        let listed = tree.leaves().into_iter().filter(|(key, _)| key.len() == 64).count();
        assert_eq!((extrinsic_count(&blob), listed), (3, 3));
        let empty = quil_tries::serialize_go_tree(None).unwrap();
        assert_eq!(extrinsic_count(&empty), 0);
    }

    #[test]
    fn peer_fields_keep_what_peers_reports() {
        let mut info = peer(Some(92), 7, true, 500, 1234);
        info.peer_id = vec![0, 1, 2, 3];
        info.last_received_frame = 499;
        info.public_key = vec![5; 57];
        info.signature = vec![6; 114];
        info.reachability = vec![quil_p2p::CanonicalReachability {
            filter: vec![0xAB],
            pubsub_multiaddrs: vec!["/ip4/192.0.2.1/tcp/1".into()],
            stream_multiaddrs: Vec::new(),
        }];
        let copied = peer_fields(&info);
        assert!(copied.public_key.is_empty() && copied.signature.is_empty());
        assert_eq!(to_str(&peer_json(&copied)), to_str(&peer_json(&info)));
    }

    #[test]
    fn status_param_parsing() {
        assert!(matches!(parse_prover_status("active"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("ACTIVE"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("2"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("200"), Some(StatusParam::NumericEmpty)));
        assert!(parse_prover_status("nonsense").is_none());
    }

    #[test]
    fn snapshot_for_builds_once_per_frame() {
        let slot = Mutex::new(None);
        let builds = std::cell::Cell::new(0u32);
        let build = |value: u32| {
            builds.set(builds.get() + 1);
            Some(value)
        };
        let half = PROVER_SNAPSHOT_MAX_AGE / 2;
        let t0 = Instant::now();
        let first = snapshot_for(&slot, 10, t0, || build(1)).unwrap();
        let again = snapshot_for(&slot, 10, t0 + half, || build(2)).unwrap();
        assert_eq!(builds.get(), 1);
        assert!(Arc::ptr_eq(&first.1, &again.1));
        // A new frame rebuilds.
        let t1 = t0 + half;
        let next = snapshot_for(&slot, 11, t1, || build(3)).unwrap();
        assert_eq!((builds.get(), next.0, *next.1), (2, 11, 3));
        // The same frame shares within the max age and rebuilds past it.
        assert_eq!(*snapshot_for(&slot, 11, t1 + half, || build(4)).unwrap().1, 3);
        assert_eq!(builds.get(), 2);
        assert_eq!(*snapshot_for(&slot, 11, t1 + PROVER_SNAPSHOT_MAX_AGE, || build(5)).unwrap().1, 5);
        assert_eq!(builds.get(), 3);
    }

    #[test]
    fn shard_sets_back_off_and_keep_the_last_good_grid() {
        let good = |tag: u8| production::GridView {
            live: BTreeSet::from([vec![tag]]),
            grid: Some(BTreeSet::from([vec![tag]])),
            ..Default::default()
        };
        let failed = || production::GridView { unavailable: Some(production::NO_REGISTRY), ..Default::default() };
        let reads = std::cell::Cell::new(0u32);
        let read = |grid: production::GridView| {
            reads.set(reads.get() + 1);
            grid
        };
        let t0 = Instant::now();
        let mut sets = ShardSets::default();
        // A failed first read leaves the grid unavailable (values unknown),
        // read again every GRID_RETRY, not on every build.
        sets.refresh(t0, || read(failed()));
        assert_eq!((sets.grid.unavailable, sets.kept(t0), reads.get()), (Some(production::NO_REGISTRY), None, 1));
        sets.refresh(t0 + GRID_RETRY / 2, || read(good(1)));
        assert_eq!(reads.get(), 1);
        let t1 = t0 + GRID_RETRY;
        sets.refresh(t1, || read(good(1)));
        assert_eq!((sets.grid.live.len(), sets.grid.unavailable, reads.get()), (1, None, 2));
        // A good grid is read again once PROVER_CACHE_TTL old; a failed
        // re-read keeps it, flagged with its age, and retries sooner.
        sets.refresh(t1 + PROVER_CACHE_TTL / 2, || read(failed()));
        assert_eq!(reads.get(), 2);
        let t2 = t1 + PROVER_CACHE_TTL;
        sets.refresh(t2, || read(failed()));
        assert_eq!((sets.grid.live.clone(), sets.grid.unavailable, reads.get()), (BTreeSet::from([vec![1]]), None, 3));
        assert_eq!(sets.kept(t2), Some((production::NO_REGISTRY, PROVER_CACHE_TTL)));
        sets.refresh(t2 + GRID_RETRY, || read(good(2)));
        assert_eq!((sets.grid.live.clone(), sets.kept(t2 + GRID_RETRY), reads.get()), (BTreeSet::from([vec![2]]), None, 4));
    }

    #[test]
    fn snapshot_for_keeps_the_last_snapshot_when_a_build_fails() {
        let slot = Mutex::new(None);
        let t0 = Instant::now();
        let read = |frame, value: Option<u32>| snapshot_for(&slot, frame, t0, || value).map(|(f, v)| (f, *v));
        // Nothing built yet: unknown (never an empty answer), nothing kept.
        assert_eq!(read(10, None), None);
        assert!(slot.lock().is_none());
        assert_eq!(read(10, Some(7)), Some((10, 7)));
        // A failed build at a new frame serves the previous snapshot with
        // its frame and leaves it in place, so the next request builds again.
        assert_eq!(read(11, None), Some((10, 7)));
        assert_eq!(read(11, Some(8)), Some((11, 8)));
    }
}
