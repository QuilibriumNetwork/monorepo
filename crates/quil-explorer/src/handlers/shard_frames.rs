//! `/shards/{filter}/frames` and `/shards/{filter}/frames/{number}`: the
//! application-shard frames this explorer's node stores, so that a request
//! routed to a shard can be found without the shard's own node.
//!
//! The frames come from the node's clock store, where a node keeps the
//! shards it serves and an archive keeps every shard it has ingested. A
//! shard or frame the store does not hold is reported as such (see
//! [`COVERAGE`]); it is not an empty frame. Only public fields are shown:
//! the VDF output, storage attestation, settlements, accumulator and spend
//! records, and every request payload appear as byte counts or as a request
//! kind and encoded size.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    response::Response,
};
use prost::Message as _;
use serde::Serialize;

use quil_types::error::QuilError;
use quil_types::proto::global::{message_request::Request, AppShardFrame, MessageRequest};

use super::{
    build_response, busy, error, is_get, json_value, method_not_allowed, store_error, CACHE_60,
};
use crate::ExplorerState;

/// Frames a listing returns at most.
pub(crate) const MAX_LIST_FRAMES: usize = 25;
/// Frames a listing returns when `limit` is absent.
pub(crate) const DEFAULT_LIST_FRAMES: usize = 10;
/// Frame numbers a listing looks up at most, held or not, so a shard whose
/// older frames are missing costs a bounded number of lookups.
pub(crate) const MAX_LIST_PROBES: u64 = 200;
/// Requests a frame view lists at most.
pub(crate) const MAX_VIEW_REQUESTS: usize = 500;
/// Requests a frame view lists when `limit` is absent.
pub(crate) const DEFAULT_VIEW_REQUESTS: usize = 200;
/// Shard-frame reads running at once; a frame can be megabytes, and the
/// handlers read the store on the explorer's two worker threads.
pub(crate) const MAX_CONCURRENT_READS: usize = 2;
/// Shortest public filter of an application shard (its L2 address).
const MIN_FILTER_BYTES: usize = 32;
/// Longest public filter accepted.
const MAX_FILTER_BYTES: usize = 128;

/// What the responses say about which frames they can show.
pub(crate) const COVERAGE: &str = "frames this explorer's node has stored: \
an archive holds the shards it has ingested, a regular node only the \
shards it serves; frames it does not hold are skipped, not empty";

#[derive(Serialize)]
struct FrameSummary {
    frame_number: u64,
    rank: u64,
    timestamp: i64,
    prover: String,
    /// Encoded size of the whole frame.
    size_bytes: usize,
    bundles: usize,
    requests: usize,
}

#[derive(Serialize)]
struct ListResponse {
    filter: String,
    /// Highest frame number the store holds for the shard.
    latest_frame: u64,
    coverage: &'static str,
    frames: Vec<FrameSummary>,
    /// Frame numbers looked up that the store does not hold.
    not_held: usize,
    /// Pass as `before` for the next page; absent when the walk reached
    /// frame 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_before: Option<u64>,
}

#[derive(Serialize)]
struct RequestView {
    bundle: usize,
    index: usize,
    /// Request kind (`unknown` for an empty request).
    kind: &'static str,
    /// Encoded size of the request; its payload is not shown.
    size_bytes: usize,
}

#[derive(Serialize)]
struct HeaderView {
    address: String,
    frame_number: u64,
    rank: u64,
    timestamp: i64,
    difficulty: u32,
    prover: String,
    parent_selector: String,
    requests_root: String,
    state_roots: Vec<String>,
    fee_multiplier_vote: u64,
    global_frame_number: u64,
    /// Signers of the frame's certificate, as a bitmask.
    signer_bitmask: String,
    storage_attestation_root: String,
    /// Byte counts of fields shown only by size.
    output_bytes: usize,
    storage_attestation_bytes: usize,
    fee_total_bytes: usize,
    settlements_bytes: usize,
    accumulator_bytes: usize,
    spends_bytes: usize,
}

#[derive(Serialize)]
struct FrameResponse {
    filter: String,
    latest_frame: u64,
    coverage: &'static str,
    header: HeaderView,
    size_bytes: usize,
    bundles: usize,
    /// All requests in the frame; `requests` lists a window of them.
    request_count: usize,
    requests: Vec<RequestView>,
    /// Pass as `offset` for the next window; absent at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

/// The kind of a request, by its protobuf variant.
fn request_kind(request: &MessageRequest) -> &'static str {
    match request.request.as_ref() {
        None => "unknown",
        Some(Request::Join(_)) => "join",
        Some(Request::Leave(_)) => "leave",
        Some(Request::Pause(_)) => "pause",
        Some(Request::Resume(_)) => "resume",
        Some(Request::Confirm(_)) => "confirm",
        Some(Request::Reject(_)) => "reject",
        Some(Request::Kick(_)) => "kick",
        Some(Request::Update(_)) => "update",
        Some(Request::TokenDeploy(_)) => "token_deploy",
        Some(Request::TokenUpdate(_)) => "token_update",
        Some(Request::HypergraphDeploy(_)) => "hypergraph_deploy",
        Some(Request::HypergraphUpdate(_)) => "hypergraph_update",
        Some(Request::VertexAdd(_)) => "vertex_add",
        Some(Request::VertexRemove(_)) => "vertex_remove",
        Some(Request::HyperedgeAdd(_)) => "hyperedge_add",
        Some(Request::HyperedgeRemove(_)) => "hyperedge_remove",
        Some(Request::ComputeDeploy(_)) => "compute_deploy",
        Some(Request::ComputeUpdate(_)) => "compute_update",
        Some(Request::CodeDeploy(_)) => "code_deploy",
        Some(Request::CodeExecute(_)) => "code_execute",
        Some(Request::CodeFinalize(_)) => "code_finalize",
        Some(Request::Shard(_)) => "shard",
        Some(Request::AltShardUpdate(_)) => "alt_shard_update",
        Some(Request::SeniorityMerge(_)) => "seniority_merge",
        Some(Request::ShardSplit(_)) => "shard_split",
        Some(Request::ShardMerge(_)) => "shard_merge",
        Some(Request::TokenOperation(_)) => "token_operation",
        Some(Request::CommitteeHandoff(_)) => "committee_handoff",
        Some(Request::PresenceReport(_)) => "presence_report",
        Some(Request::StorageEpochProof(_)) => "storage_epoch_proof",
    }
}

fn parse_filter(filter_hex: &str) -> Result<Vec<u8>, Response> {
    let filter = hex::decode(filter_hex.trim_end_matches('/'))
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid filter"))?;
    if !(MIN_FILTER_BYTES..=MAX_FILTER_BYTES).contains(&filter.len()) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "filter must be an application shard's public filter, 32 to 128 bytes",
        ));
    }
    Ok(filter)
}

/// A bounded positive integer query parameter: absent gives `default`, a
/// value above `max` is lowered to it, zero or a non-number is a 400.
fn bounded_param(
    params: &HashMap<String, String>,
    name: &str,
    default: usize,
    max: usize,
) -> Result<usize, Response> {
    match params.get(name).map(|v| v.trim()) {
        None | Some("") => Ok(default),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => Ok(n.min(max)),
            _ => Err(error(
                StatusCode::BAD_REQUEST,
                &format!("{name} must be a positive number"),
            )),
        },
    }
}

/// An optional non-negative integer query parameter.
fn number_param<T: std::str::FromStr>(
    params: &HashMap<String, String>,
    name: &str,
) -> Result<Option<T>, Response> {
    match params.get(name).map(|v| v.trim()) {
        None | Some("") => Ok(None),
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|_| error(StatusCode::BAD_REQUEST, &format!("{name} must be a number"))),
    }
}

fn not_held(filter_hex: &str, what: &str) -> Response {
    #[derive(Serialize)]
    struct NotHeld<'a> {
        error: String,
        filter: &'a str,
        coverage: &'static str,
    }
    build_response(
        StatusCode::NOT_FOUND,
        json_value(&NotHeld {
            error: format!("{what} not held by this explorer"),
            filter: filter_hex,
            coverage: COVERAGE,
        }),
        None,
    )
}

fn request_count(frame: &AppShardFrame) -> usize {
    frame.requests.iter().map(|b| b.requests.len()).sum()
}

/// `GET /shards/{filter}/frames?limit=&before=`: the newest frames of a
/// shard below `before` (default: past the latest), newest first.
pub async fn handle_shard_frames(
    method: Method,
    State(state): State<ExplorerState>,
    Path(filter_hex): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let filter = match parse_filter(&filter_hex) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let filter_hex = hex::encode(&filter);
    let limit = match bounded_param(&params, "limit", DEFAULT_LIST_FRAMES, MAX_LIST_FRAMES) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let before = match number_param::<u64>(&params, "before") {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(_reading) = state.shard_frame_reads.try_acquire() else {
        return busy("shard frames are being read; retry shortly", 1);
    };
    let latest = match state
        .clock_store
        .get_latest_shard_clock_frame_number(&filter)
    {
        Ok(Some(n)) => n,
        Ok(None) => return not_held(&filter_hex, "shard"),
        Err(e) => return store_error(&e),
    };
    // The walk starts at the highest frame below `before`, within the latest.
    let mut cursor = match before {
        None => Some(latest),
        Some(b) => b.checked_sub(1).map(|n| n.min(latest)),
    };
    let mut probes = 0u64;
    let mut missing = 0usize;
    let mut frames = Vec::new();
    while let Some(number) = cursor {
        if frames.len() >= limit || probes >= MAX_LIST_PROBES {
            break;
        }
        probes += 1;
        match state
            .clock_store
            .get_shard_clock_frame(&filter, number, false)
        {
            Ok(frame) => {
                let header = frame.header.clone().unwrap_or_default();
                frames.push(FrameSummary {
                    frame_number: number,
                    rank: header.rank,
                    timestamp: header.timestamp,
                    prover: hex::encode(&header.prover),
                    size_bytes: frame.encoded_len(),
                    bundles: frame.requests.len(),
                    requests: request_count(&frame),
                });
            }
            Err(QuilError::NotFound(_)) => missing += 1,
            Err(e) => return store_error(&e),
        }
        cursor = number.checked_sub(1);
    }
    build_response(
        StatusCode::OK,
        json_value(&ListResponse {
            filter: filter_hex,
            latest_frame: latest,
            coverage: COVERAGE,
            frames,
            not_held: missing,
            next_before: cursor.map(|n| n + 1),
        }),
        Some(CACHE_60),
    )
}

/// `GET /shards/{filter}/frames/{number}?offset=&limit=`: one frame's
/// header and a window of its requests (kind and size each).
pub async fn handle_shard_frame(
    method: Method,
    State(state): State<ExplorerState>,
    Path((filter_hex, number)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !is_get(&method) {
        return method_not_allowed();
    }
    let filter = match parse_filter(&filter_hex) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let filter_hex = hex::encode(&filter);
    let Ok(number) = number.parse::<u64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid frame number");
    };
    let limit = match bounded_param(&params, "limit", DEFAULT_VIEW_REQUESTS, MAX_VIEW_REQUESTS) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let offset = match number_param::<usize>(&params, "offset") {
        Ok(o) => o.unwrap_or(0),
        Err(r) => return r,
    };
    let Ok(_reading) = state.shard_frame_reads.try_acquire() else {
        return busy("shard frames are being read; retry shortly", 1);
    };
    let latest = match state
        .clock_store
        .get_latest_shard_clock_frame_number(&filter)
    {
        Ok(Some(n)) => n,
        Ok(None) => return not_held(&filter_hex, "shard"),
        Err(e) => return store_error(&e),
    };
    let frame = match state
        .clock_store
        .get_shard_clock_frame(&filter, number, false)
    {
        Ok(f) => f,
        Err(QuilError::NotFound(_)) => return not_held(&filter_hex, "frame"),
        Err(e) => return store_error(&e),
    };
    let header = frame.header.clone().unwrap_or_default();
    let total = request_count(&frame);
    let requests: Vec<RequestView> = frame
        .requests
        .iter()
        .enumerate()
        .flat_map(|(bundle, b)| {
            b.requests
                .iter()
                .enumerate()
                .map(move |(index, r)| RequestView {
                    bundle,
                    index,
                    kind: request_kind(r),
                    size_bytes: r.encoded_len(),
                })
        })
        .skip(offset)
        .take(limit)
        .collect();
    let end = offset.saturating_add(requests.len());
    build_response(
        StatusCode::OK,
        json_value(&FrameResponse {
            filter: filter_hex,
            latest_frame: latest,
            coverage: COVERAGE,
            header: HeaderView {
                address: hex::encode(&header.address),
                frame_number: header.frame_number,
                rank: header.rank,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                prover: hex::encode(&header.prover),
                parent_selector: hex::encode(&header.parent_selector),
                requests_root: hex::encode(&header.requests_root),
                state_roots: header.state_roots.iter().map(hex::encode).collect(),
                fee_multiplier_vote: header.fee_multiplier_vote,
                global_frame_number: header.global_frame_number,
                signer_bitmask: header
                    .public_key_signature_bls48581
                    .as_ref()
                    .map(|s| hex::encode(&s.bitmask))
                    .unwrap_or_default(),
                storage_attestation_root: hex::encode(&header.storage_attestation_root),
                output_bytes: header.output.len(),
                storage_attestation_bytes: header.storage_attestation.len(),
                fee_total_bytes: header.fee_total.len(),
                settlements_bytes: header.settlements.len(),
                accumulator_bytes: header.accumulator.len(),
                spends_bytes: header.spends.len(),
            },
            size_bytes: frame.encoded_len(),
            bundles: frame.requests.len(),
            request_count: total,
            requests,
            next_offset: (end < total).then_some(end),
        }),
        Some(CACHE_60),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::{FrameHeader, MessageBundle};
    use quil_types::store::ClockStore as _;
    use std::sync::Arc;

    /// Marker bytes inside a request payload: the responses must never
    /// show them, in hex or in any other form.
    const SECRET: u8 = 0xC7;

    fn filter(fill: u8) -> Vec<u8> {
        vec![fill; 32]
    }

    /// An explorer over an in-memory store, and a writer into the same store.
    fn state() -> (ExplorerState, quil_store::RocksClockStore) {
        let db = quil_store::RocksDb::open_in_memory().expect("an in-memory store");
        let raw = db.inner();
        let hg = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let state = ExplorerState::new(
            Arc::new(quil_store::RocksClockStore::new(raw.clone())),
            crdt,
            Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
            Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
            Arc::new(quil_store::RocksShardsStore::new(raw.clone())),
            None,
            None,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(crate::RecentMessageRing::new(16)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        (state, quil_store::RocksClockStore::new(raw))
    }

    fn request(request: Request) -> MessageRequest {
        MessageRequest {
            request: Some(request),
            timestamp: 0,
        }
    }

    /// A frame of `address` numbered `number` with `bundles` bundles, each
    /// of the given requests.
    fn frame(address: &[u8], number: u64, bundles: Vec<Vec<MessageRequest>>) -> AppShardFrame {
        AppShardFrame {
            header: Some(FrameHeader {
                address: address.to_vec(),
                frame_number: number,
                rank: number + 1000,
                timestamp: 1_700_000_000_000 + number as i64,
                difficulty: 7,
                output: vec![1; 516],
                prover: vec![0xAA; 32],
                parent_selector: vec![0xBB; 32],
                requests_root: vec![0xCC; 32],
                state_roots: vec![vec![0xDD; 4], vec![0xEE; 4]],
                global_frame_number: 99,
                settlements: vec![SECRET; 10],
                ..Default::default()
            }),
            requests: bundles
                .into_iter()
                .map(|requests| MessageBundle {
                    requests,
                    timestamp: 0,
                })
                .collect(),
            storage_attestation: None,
        }
    }

    fn store(clock: &quil_store::RocksClockStore, frame: &AppShardFrame) {
        let number = frame.header.as_ref().unwrap().frame_number;
        let mut selector = [0u8; 32];
        selector[..8].copy_from_slice(&number.to_be_bytes());
        clock
            .store_shard_clock_frame_for_serving(&selector, frame)
            .unwrap();
    }

    async fn body(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn list(state: &ExplorerState, filter: &[u8], query: &[(&str, &str)]) -> Response {
        handle_shard_frames(
            Method::GET,
            State(state.clone()),
            Path(hex::encode(filter)),
            Query(
                query
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        )
        .await
    }

    async fn view(
        state: &ExplorerState,
        filter: &[u8],
        number: &str,
        query: &[(&str, &str)],
    ) -> Response {
        handle_shard_frame(
            Method::GET,
            State(state.clone()),
            Path((hex::encode(filter), number.to_string())),
            Query(
                query
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        )
        .await
    }

    fn numbers(listing: &serde_json::Value) -> Vec<u64> {
        listing["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["frame_number"].as_u64().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn a_listing_pages_newest_first_without_gaps_or_overlap() {
        let (state, clock) = state();
        let f = filter(1);
        for n in 1..=12 {
            store(&clock, &frame(&f, n, vec![]));
        }
        let (status, first) = body(list(&state, &f, &[("limit", "5")]).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(numbers(&first), vec![12, 11, 10, 9, 8]);
        assert_eq!(first["latest_frame"], 12);
        assert_eq!(first["next_before"], 8);
        assert!(first["coverage"]
            .as_str()
            .unwrap()
            .contains("does not hold"));
        let (_, second) = body(list(&state, &f, &[("limit", "5"), ("before", "8")]).await).await;
        assert_eq!(numbers(&second), vec![7, 6, 5, 4, 3]);
        assert_eq!(second["next_before"], 3);
        let (_, last) = body(list(&state, &f, &[("limit", "5"), ("before", "3")]).await).await;
        assert_eq!(numbers(&last), vec![2, 1]);
        // The walk ended at frame 0, which no shard has: no further page.
        assert!(last.get("next_before").is_none(), "{last}");
        assert_eq!(last["not_held"], 1);
    }

    #[tokio::test]
    async fn a_listing_summarizes_each_frame() {
        let (state, clock) = state();
        let f = filter(2);
        let join = request(Request::CommitteeHandoff(vec![SECRET; 40]));
        let proof = request(Request::StorageEpochProof(vec![SECRET; 300]));
        store(
            &clock,
            &frame(&f, 1, vec![vec![join.clone(), proof], vec![join]]),
        );
        let (_, listing) = body(list(&state, &f, &[]).await).await;
        let only = &listing["frames"][0];
        assert_eq!(only["frame_number"], 1);
        assert_eq!(only["rank"], 1001);
        assert_eq!(only["bundles"], 2);
        assert_eq!(only["requests"], 3);
        assert_eq!(only["prover"], hex::encode([0xAA; 32]));
        assert_eq!(only["timestamp"], 1_700_000_000_001i64);
        assert!(only["size_bytes"].as_u64().unwrap() > 900);
    }

    #[tokio::test]
    async fn a_listing_is_capped_in_frames() {
        let (state, clock) = state();
        let f = filter(3);
        for n in 1..=(MAX_LIST_FRAMES as u64 + 5) {
            store(&clock, &frame(&f, n, vec![]));
        }
        let (_, capped) = body(list(&state, &f, &[("limit", "1000")]).await).await;
        assert_eq!(numbers(&capped).len(), MAX_LIST_FRAMES);
        let (_, default) = body(list(&state, &f, &[]).await).await;
        assert_eq!(numbers(&default).len(), DEFAULT_LIST_FRAMES);
    }

    #[tokio::test]
    async fn a_listing_over_missing_frames_stops_at_its_lookup_bound() {
        let (state, clock) = state();
        let f = filter(4);
        // Frames 1 and 500 are held; 2..=499 are not.
        store(&clock, &frame(&f, 1, vec![]));
        store(&clock, &frame(&f, 500, vec![]));
        let (status, listing) = body(list(&state, &f, &[]).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(numbers(&listing), vec![500]);
        assert_eq!(
            listing["not_held"].as_u64().unwrap(),
            MAX_LIST_PROBES - 1,
            "every lookup beyond the held frame is counted"
        );
        // The page says where to continue.
        let next = listing["next_before"].as_u64().unwrap();
        assert_eq!(next, 500 - (MAX_LIST_PROBES - 1));
        // Following the pages reaches frame 1, each within the bound.
        let (mut before, mut found) = (next, vec![]);
        for _ in 0..3 {
            let (_, page) = body(list(&state, &f, &[("before", &before.to_string())]).await).await;
            assert!(page["not_held"].as_u64().unwrap() <= MAX_LIST_PROBES);
            found.extend(numbers(&page));
            match page["next_before"].as_u64() {
                Some(n) => before = n,
                None => break,
            }
        }
        assert_eq!(found, vec![1]);
    }

    #[tokio::test]
    async fn a_shard_the_store_does_not_hold_is_reported_not_empty() {
        let (state, clock) = state();
        store(&clock, &frame(&filter(5), 1, vec![]));
        let other = filter(6);
        let (status, listing) = body(list(&state, &other, &[]).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(listing["error"], "shard not held by this explorer");
        assert!(listing["coverage"].as_str().unwrap().contains("archive"));
        let (status, frame) = body(view(&state, &other, "1", &[]).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(frame["error"], "shard not held by this explorer");
        // A held shard missing one frame says so about the frame.
        let (status, frame) = body(view(&state, &filter(5), "7", &[]).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(frame["error"], "frame not held by this explorer");
    }

    #[tokio::test]
    async fn bad_filters_numbers_and_methods_are_refused() {
        let (state, _clock) = state();
        for bad in ["zz", "", "00", "00".repeat(129).as_str()] {
            let resp = handle_shard_frames(
                Method::GET,
                State(state.clone()),
                Path(bad.to_string()),
                Query(HashMap::new()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "filter {bad:?}");
        }
        let f = filter(7);
        assert_eq!(
            view(&state, &f, "latest", &[]).await.status(),
            StatusCode::BAD_REQUEST
        );
        for (name, value) in [("limit", "0"), ("limit", "x"), ("before", "-1")] {
            assert_eq!(
                list(&state, &f, &[(name, value)]).await.status(),
                StatusCode::BAD_REQUEST,
                "{name}={value}"
            );
        }
        let post = handle_shard_frames(
            Method::POST,
            State(state.clone()),
            Path(hex::encode(&f)),
            Query(HashMap::new()),
        )
        .await;
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn a_frame_view_shows_header_and_each_request_kind_and_size_only() {
        let (state, clock) = state();
        let f = filter(8);
        let handoff = request(Request::CommitteeHandoff(vec![SECRET; 40]));
        let proof = request(Request::StorageEpochProof(vec![SECRET; 300]));
        let empty = MessageRequest::default();
        store(
            &clock,
            &frame(
                &f,
                3,
                vec![vec![handoff.clone(), proof], vec![empty, handoff]],
            ),
        );
        let resp = view(&state, &f, "3", &[]).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("c7c7"), "a payload is shown: {text}");
        let shown: serde_json::Value = serde_json::from_str(&text).unwrap();
        let header = &shown["header"];
        assert_eq!(header["frame_number"], 3);
        assert_eq!(header["rank"], 1003);
        assert_eq!(header["difficulty"], 7);
        assert_eq!(header["global_frame_number"], 99);
        assert_eq!(header["address"], hex::encode(&f));
        assert_eq!(header["prover"], hex::encode([0xAA; 32]));
        assert_eq!(header["parent_selector"], hex::encode([0xBB; 32]));
        assert_eq!(header["requests_root"], hex::encode([0xCC; 32]));
        assert_eq!(
            header["state_roots"],
            serde_json::json!([hex::encode([0xDD; 4]), hex::encode([0xEE; 4])])
        );
        assert_eq!(header["output_bytes"], 516);
        assert_eq!(header["settlements_bytes"], 10);
        assert_eq!(shown["latest_frame"], 3);
        assert_eq!(shown["bundles"], 2);
        assert_eq!(shown["request_count"], 4);
        // Field 31 and 33 are two-byte keys: key + length + payload.
        let views: Vec<(u64, u64, &str, u64)> = shown["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["bundle"].as_u64().unwrap(),
                    r["index"].as_u64().unwrap(),
                    r["kind"].as_str().unwrap(),
                    r["size_bytes"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            views,
            vec![
                (0, 0, "committee_handoff", 43),
                (0, 1, "storage_epoch_proof", 304),
                (1, 0, "unknown", 0),
                (1, 1, "committee_handoff", 43),
            ]
        );
        assert!(shown.get("next_offset").is_none());
    }

    #[tokio::test]
    async fn a_frame_view_windows_its_requests_within_a_cap() {
        let (state, clock) = state();
        let f = filter(9);
        let many: Vec<MessageRequest> = (0..MAX_VIEW_REQUESTS + 20)
            .map(|_| request(Request::CommitteeHandoff(vec![SECRET; 4])))
            .collect();
        store(&clock, &frame(&f, 1, vec![many]));
        let (_, capped) = body(view(&state, &f, "1", &[("limit", "100000")]).await).await;
        assert_eq!(capped["request_count"], MAX_VIEW_REQUESTS + 20);
        assert_eq!(
            capped["requests"].as_array().unwrap().len(),
            MAX_VIEW_REQUESTS
        );
        assert_eq!(capped["next_offset"], MAX_VIEW_REQUESTS);
        let (_, tail) = body(
            view(
                &state,
                &f,
                "1",
                &[("offset", &MAX_VIEW_REQUESTS.to_string())],
            )
            .await,
        )
        .await;
        let rest = tail["requests"].as_array().unwrap();
        assert_eq!(rest.len(), 20);
        assert_eq!(rest[0]["index"], MAX_VIEW_REQUESTS);
        assert!(tail.get("next_offset").is_none());
        let (_, default) = body(view(&state, &f, "1", &[]).await).await;
        assert_eq!(
            default["requests"].as_array().unwrap().len(),
            DEFAULT_VIEW_REQUESTS
        );
    }

    #[tokio::test]
    async fn reads_beyond_the_permits_are_answered_busy_and_recover() {
        let (state, clock) = state();
        let f = filter(10);
        store(&clock, &frame(&f, 1, vec![]));
        let held: Vec<_> = (0..MAX_CONCURRENT_READS)
            .map(|_| state.shard_frame_reads.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(
            list(&state, &f, &[]).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            view(&state, &f, "1", &[]).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(held);
        assert_eq!(list(&state, &f, &[]).await.status(), StatusCode::OK);
        assert_eq!(view(&state, &f, "1", &[]).await.status(), StatusCode::OK);
        assert_eq!(
            state.shard_frame_reads.available_permits(),
            MAX_CONCURRENT_READS,
            "finished reads return their permits"
        );
    }

    #[tokio::test]
    async fn the_routes_are_served_beside_the_production_routes() {
        use tower::ServiceExt as _;
        let (state, clock) = state();
        let f = filter(11);
        store(&clock, &frame(&f, 4, vec![]));
        let app = crate::router(state);
        let get = |path: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let listed = get(format!("/shards/{}/frames?limit=1", hex::encode(&f))).await;
        let (status, listed) = body(listed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(numbers(&listed), vec![4]);
        let one = get(format!("/shards/{}/frames/4", hex::encode(&f))).await;
        assert_eq!(body(one).await.0, StatusCode::OK);
        // The static routes keep answering: not the filter route's 400.
        let production = get("/shards/production".to_string()).await;
        assert_ne!(production.status(), StatusCode::BAD_REQUEST);
        assert_ne!(production.status(), StatusCode::NOT_FOUND);
    }
    /// Cost of the handlers over frames of the size an application shard
    /// can carry: `QUIL_SHARD_FRAMES_MB` (default 1) per frame, 30 frames,
    /// in an in-memory store (no disk reads: a floor, not a node's cost).
    /// A debug build overstates the costs.
    #[tokio::test]
    #[ignore = "measurement"]
    async fn measure_shard_frame_handlers() {
        let mb: usize = std::env::var("QUIL_SHARD_FRAMES_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let (state, clock) = state();
        let f = filter(12);
        let per_frame = mb * 1024 * 1024 / 300;
        for n in 1..=30 {
            let requests = (0..per_frame)
                .map(|_| request(Request::CommitteeHandoff(vec![SECRET; 256])))
                .collect();
            store(&clock, &frame(&f, n, vec![requests]));
        }
        let t = std::time::Instant::now();
        let resp = list(&state, &f, &[("limit", "25")]).await;
        let (_, listing) = body(resp).await;
        eprintln!(
            "list 25 frames of ~{mb} MB: {:?} ({} frames)",
            t.elapsed(),
            numbers(&listing).len()
        );
        let t = std::time::Instant::now();
        let resp = view(&state, &f, "30", &[("limit", "500")]).await;
        let (_, shown) = body(resp).await;
        eprintln!(
            "view 1 frame of ~{mb} MB, 500 of {} requests: {:?}",
            shown["request_count"],
            t.elapsed()
        );
    }
}
