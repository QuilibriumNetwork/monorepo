//! Request handlers for the explorer REST API. Each mirrors the
//! corresponding Go `node/explorer` handler with a byte-compatible JSON
//! contract. Two response shapes are used: protobuf-JSON (protojson, no
//! trailing newline) for frames/certified/keys, and Go-`encoding/json`
//! style (snake_case structs, trailing `\n`) for everything else.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    response::Response,
};
use base64::Engine as _;
use num_bigint::{BigInt, Sign};
use serde::Serialize;

use quil_types::consensus::{ProverAllocationInfo, ProverInfo, ProverStatus};
use quil_types::error::QuilError;
use quil_types::protojson;

use crate::ExplorerState;

const CACHE_LONG: &str = "public, max-age=31536000, immutable";
const CACHE_180: &str = "public, max-age=180";
const CACHE_60: &str = "public, max-age=60";
const PROVER_CACHE_TTL: Duration = Duration::from_secs(180);

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn build_response(status: StatusCode, body: Vec<u8>, cache: Option<&str>) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");
    if let Some(c) = cache {
        builder = builder.header("Cache-Control", c);
    }
    builder.body(axum::body::Body::from(body)).unwrap()
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
    match frame {
        Ok(frame) => protojson_ok(
            protojson::GLOBAL_FRAME,
            &frame,
            if cacheable { Some(CACHE_LONG) } else { None },
        ),
        Err(e) => store_error(&e),
    }
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

#[derive(Serialize)]
struct MessageJson {
    timestamp: String,
    from: String,
    bitmask: String,
    seqno: String,
    signature: String,
    key: String,
    data: String,
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
    let records = state.messages.snapshot(limit);
    let response: Vec<MessageJson> = records
        .into_iter()
        .map(|r| MessageJson {
            timestamp: r.timestamp,
            from: hex::encode(&r.from),
            bitmask: hex::encode(&r.bitmask),
            seqno: hex::encode(&r.seqno),
            signature: hex::encode(&r.signature),
            key: hex::encode(&r.key),
            data: hex::encode(&r.data),
        })
        .collect();
    json_ok(&response, None)
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
    capabilities: Option<Vec<PeerCapabilityJson>>,
    reachability: Option<Vec<PeerReachabilityJson>>,
}

pub async fn handle_peers(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let std = base64::engine::general_purpose::STANDARD;
    let mut response: Vec<PeerInfoJson> = {
        let map = state.peer_info_cache.read();
        map.values()
            .map(|info| {
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
                    capabilities,
                    reachability,
                }
            })
            .collect()
    };
    // Sort by last_seen desc, tie-break peer_id asc (Go's slices.SortFunc).
    response.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
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
    let mut cache = state.cache.write();
    cache.insert(key, (Instant::now() + PROVER_CACHE_TTL, body));
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
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for (status, count) in &summary.status_counts {
            counts.insert(prover_status_to_string(*status), *count as i64);
        }
        let filter_hex = hex::encode(&summary.filter);
        seen.insert(filter_hex.clone());
        let active_workers = counts.get("active").copied().unwrap_or(0)
            + counts.get("joining").copied().unwrap_or(0);
        let (size_bytes, data_shards) = match shard_sizes.get(&filter_hex) {
            Some((size, ds)) => (size.to_string(), *ds),
            None => (String::new(), 0),
        };
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
/// shard key) ++ each prefix element as a byte`.
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
        let (size_be, data_shards) = match &state.app_shards_provider {
            Some(p) => match p(&shard.shard_key, &shard.prefix) {
                Some((sz, ds, _)) => (sz, ds),
                None => (Vec::new(), 0),
            },
            None => (shard.size.clone(), shard.data_shards),
        };
        let l2 = &shard.shard_key[shard.shard_key.len() - 32..];
        let mut filter = l2.to_vec();
        for p in &shard.prefix {
            filter.push(*p as u8);
        }
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
    // Go `vertex.ToBytes()` == the stored value (0x00||app||data||commitment
    // ||size.FillBytes(32)); GetSize() is the trailing 32 bytes as a
    // big-endian integer.
    let size = if value.len() >= 32 {
        BigInt::from_bytes_be(Sign::Plus, &value[value.len() - 32..])
    } else {
        BigInt::from(0)
    };
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
    let size = state.crdt.get_hyperedge_extrinsic_ids(&location).len();
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

/// Collect every prover known to the registry, deduplicated by address.
/// `get_provers(&[])` only returns the global committee, so we also fan out
/// over each shard filter from the shard summaries and merge.
fn all_provers(state: &ExplorerState, frame: u64) -> Vec<ProverInfo> {
    let mut by_addr: HashMap<Vec<u8>, ProverInfo> = HashMap::new();
    if let Ok(globals) = state.prover_registry.get_provers(&[]) {
        for p in globals {
            by_addr.insert(p.address.clone(), p);
        }
    }
    if let Ok(summaries) = state.prover_registry.get_prover_shard_summaries(frame) {
        for s in summaries {
            if let Ok(list) = state.prover_registry.get_provers(&s.filter) {
                for p in list {
                    by_addr.entry(p.address.clone()).or_insert(p);
                }
            }
        }
    }
    by_addr.into_values().collect()
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
) -> Option<Assessment> {
    if alloc.status != ProverStatus::Active || alloc.confirmation_filter.is_empty() {
        return None;
    }
    let halt_duration = halts.get(&alloc.confirmation_filter).copied().unwrap_or(0);
    if halt_duration == u64::MAX {
        return None; // shard fully halted — exempt this tick
    }
    // Inactivity does not start accruing until the network is live for
    // eviction — count from max(last_active, EVICTION_INACTIVITY_START_FRAME)
    // so nobody is surfaced for downtime predating that frame. Mirrors the
    // consensus path's `find_eviction_candidates`.
    let inactivity_start = alloc
        .last_active_frame_number
        .max(quil_types::consensus::EVICTION_INACTIVITY_START_FRAME);
    if alloc.last_active_frame_number == 0 || frame <= inactivity_start {
        return None;
    }
    let total_inactive = frame - inactivity_start;
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
            let mut filter = s.shard_key[l2_start..].to_vec();
            for p in &s.prefix {
                filter.push(*p as u8);
            }
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

#[derive(Serialize)]
struct EvictionRiskEntry {
    address: String,
    public_key: String,
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
}

pub async fn handle_eviction_risk(
    method: Method,
    State(state): State<ExplorerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let min_ratio: f64 = params
        .get("min_ratio")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    let frame = state.current_frame.load(Ordering::Relaxed);
    let halts = current_halts(&state, frame);
    let threshold = crate::EVICTION_THRESHOLD_FRAMES;

    let mut entries: Vec<EvictionRiskEntry> = Vec::new();
    for prover in all_provers(&state, frame) {
        if prover.status != ProverStatus::Active {
            continue;
        }
        for alloc in &prover.allocations {
            let Some(a) = assess_allocation(alloc, frame, &halts) else {
                continue;
            };
            let risk_ratio = a.effective_inactive as f64 / threshold as f64;
            if risk_ratio < min_ratio {
                continue;
            }
            entries.push(EvictionRiskEntry {
                address: hex::encode(&prover.address),
                public_key: hex::encode(&prover.public_key),
                seniority: prover.seniority,
                filter: hex::encode(&alloc.confirmation_filter),
                last_active_frame_number: alloc.last_active_frame_number,
                current_frame: frame,
                shard_halt_duration: a.halt_duration,
                frames_inactive: a.total_inactive,
                effective_inactive: a.effective_inactive,
                eviction_threshold: threshold,
                frames_until_eviction: threshold.saturating_sub(a.effective_inactive),
                risk_ratio,
                eviction_pending: a.effective_inactive > threshold,
            });
        }
    }
    // Most-at-risk first: least runway, then highest inactivity.
    entries.sort_by(|a, b| {
        a.frames_until_eviction
            .cmp(&b.frames_until_eviction)
            .then_with(|| b.effective_inactive.cmp(&a.effective_inactive))
    });
    json_ok(&entries, None)
}

#[derive(Serialize)]
struct SeniorityEntry {
    rank: u64,
    address: String,
    public_key: String,
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
    let mut provers = all_provers(&state, frame);
    // Seniority descending; ties broken by address ascending for stability.
    provers.sort_by(|a, b| b.seniority.cmp(&a.seniority).then_with(|| a.address.cmp(&b.address)));
    let mut entries: Vec<SeniorityEntry> = provers
        .iter()
        .enumerate()
        .map(|(i, p)| SeniorityEntry {
            rank: (i as u64) + 1,
            address: hex::encode(&p.address),
            public_key: hex::encode(&p.public_key),
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
    let mut entries: Vec<KickedEntry> = all_provers(&state, frame)
        .into_iter()
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
}

pub async fn handle_stats(method: Method, State(state): State<ExplorerState>) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let frame = state.current_frame.load(Ordering::Relaxed);
    let halts = current_halts(&state, frame);
    let threshold = crate::EVICTION_THRESHOLD_FRAMES;

    let provers = all_provers(&state, frame);
    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    let mut total_seniority: u64 = 0;
    let mut eviction_pending: u64 = 0;
    let mut at_risk: u64 = 0;
    for prover in &provers {
        *by_status
            .entry(prover_status_to_string(prover.status))
            .or_insert(0) += 1;
        total_seniority = total_seniority.saturating_add(prover.seniority);
        if prover.status == ProverStatus::Active {
            let mut worst = 0u64;
            for alloc in &prover.allocations {
                if let Some(a) = assess_allocation(alloc, frame, &halts) {
                    worst = worst.max(a.effective_inactive);
                }
            }
            if worst > threshold {
                eviction_pending += 1;
            }
            if worst > threshold / 2 {
                at_risk += 1;
            }
        }
    }
    let halted_shards = halts.values().filter(|&&v| v == u64::MAX).count() as u64;

    let response = StatsResponse {
        current_frame: frame,
        eviction_threshold: threshold,
        total_provers: provers.len() as u64,
        by_status,
        total_seniority,
        eviction_pending,
        at_risk,
        halted_shards,
    };
    json_ok(&response, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_str<T: Serialize>(v: &T) -> String {
        String::from_utf8(serde_json::to_vec(v).unwrap()).unwrap()
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
                    epoch: 0,
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
                    epoch: 0,
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
    fn peer_capabilities_null_when_empty_array_when_present() {
        let empty = PeerInfoJson {
            peer_id: "p".into(),
            version: "v".into(),
            patch_number: "01".into(),
            cores: 0,
            last_seen: 5,
            last_received_frame: 0,
            last_global_head_frame: 0,
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
    fn json_value_has_trailing_newline_error_has_shape() {
        let body = json_value(&vec![1, 2, 3]);
        assert_eq!(body, b"[1,2,3]\n");
        let resp = error(StatusCode::BAD_REQUEST, "bad thing");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
            epoch: 0,
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

        // Active non-global alloc, no halt: effective = inactivity since
        // the start frame (NOT since last_active, which predates it).
        let a = active_alloc(vec![0xAA], 81_000);
        let r = assess_allocation(&a, frame, &halts).unwrap();
        assert_eq!(r.total_inactive, 290);
        assert_eq!(r.effective_inactive, 290);

        // Before the inactivity start, nobody accrues inactivity → None,
        // even if they've been inactive "forever" by last_active.
        assert!(assess_allocation(&a, start, &HashMap::new()).is_none());
        assert!(assess_allocation(&a, start - 1, &HashMap::new()).is_none());

        // Partial halt is subtracted.
        halts.insert(vec![0xAA], 100u64);
        let r = assess_allocation(&a, frame, &halts).unwrap();
        assert_eq!(r.effective_inactive, 190);

        // Full halt (u64::MAX) -> exempt -> None.
        halts.insert(vec![0xAA], u64::MAX);
        assert!(assess_allocation(&a, frame, &halts).is_none());

        // Global allocation (empty filter) -> never at risk.
        assert!(assess_allocation(&active_alloc(vec![], 81_000), frame, &HashMap::new()).is_none());

        // last_active 0 or not-yet-inactive -> None.
        assert!(assess_allocation(&active_alloc(vec![0xBB], 0), frame, &HashMap::new()).is_none());
        assert!(
            assess_allocation(&active_alloc(vec![0xBB], frame + 5), frame, &HashMap::new())
                .is_none()
        );

        // Non-active allocation -> None.
        let mut paused = active_alloc(vec![0xCC], 81_000);
        paused.status = ProverStatus::Paused;
        assert!(assess_allocation(&paused, frame, &HashMap::new()).is_none());
    }

    #[test]
    fn eviction_risk_entry_runway_and_flag() {
        // 350 frames inactive, threshold 360 -> 10 frames runway, not yet evictable.
        let threshold = crate::EVICTION_THRESHOLD_FRAMES;
        let effective = 350u64;
        let entry = EvictionRiskEntry {
            address: "ab".into(),
            public_key: "cd".into(),
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
        };
        assert_eq!(entry.frames_until_eviction, 10);
        assert!(!entry.eviction_pending);
        let s = to_str(&entry);
        assert!(s.contains(r#""frames_until_eviction":10"#), "{s}");
        assert!(s.contains(r#""eviction_threshold":360"#), "{s}");
    }

    #[test]
    fn status_param_parsing() {
        assert!(matches!(parse_prover_status("active"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("ACTIVE"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("2"), Some(StatusParam::Known(ProverStatus::Active))));
        assert!(matches!(parse_prover_status("200"), Some(StatusParam::NumericEmpty)));
        assert!(parse_prover_status("nonsense").is_none());
    }
}
