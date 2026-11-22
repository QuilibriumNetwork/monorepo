//! Application discovery and pending shard changes on archive nodes.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ExplorerState;
use quil_types::store::{PendingShardChange, ShardChangeKind, ShardInfo};

type ApiError = (StatusCode, Json<ErrorBody>);

#[derive(Serialize)]
pub(crate) struct ErrorBody {
    error: String,
}

fn error(code: StatusCode, message: impl Into<String>) -> ApiError {
    (
        code,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

#[derive(Serialize)]
pub(crate) struct PendingResponse {
    current_frame: u64,
    changes: Vec<PendingChange>,
}

#[derive(Serialize)]
struct PendingChange {
    kind: &'static str,
    parent: String,
    children: Vec<String>,
    proposed_frame: u64,
    effective_epoch: u64,
    effective_frame: u64,
    frames_remaining: u64,
    reward_impact: RewardImpact,
}

#[derive(Serialize)]
struct RewardImpact {
    shard_slots_before: usize,
    shard_slots_after: usize,
    estimated_delta_subunits_per_frame: Option<String>,
    reason: &'static str,
}

impl PendingChange {
    fn from_stored(change: PendingShardChange, current_frame: u64) -> Self {
        let (kind, before, after, reason) = match change.kind {
            ShardChangeKind::Split => (
                "split",
                1,
                change.children.len(),
                "The parent shard will be replaced by its children. Future prover allocations, reward rings and shard sizes are not known yet, so a payout delta cannot be calculated.",
            ),
            ShardChangeKind::Merge => (
                "merge",
                change.children.len(),
                1,
                "The child shards will be replaced by their parent. Future prover allocations, reward rings and shard sizes are not known yet, so a payout delta cannot be calculated.",
            ),
        };
        let effective_frame = change
            .effective_epoch
            .saturating_mul(quil_types::consensus::epoch_length_frames());
        Self {
            kind,
            parent: hex::encode(change.parent),
            children: change.children.into_iter().map(hex::encode).collect(),
            proposed_frame: change.proposed_frame,
            effective_epoch: change.effective_epoch,
            effective_frame,
            frames_remaining: effective_frame.saturating_sub(current_frame),
            reward_impact: RewardImpact {
                shard_slots_before: before,
                shard_slots_after: after,
                estimated_delta_subunits_per_frame: None,
                reason,
            },
        }
    }
}

/// The materializer already records these changes until they take effect.
pub(crate) async fn pending_shards(
    State(state): State<ExplorerState>,
) -> Result<Json<PendingResponse>, ApiError> {
    let current_frame = state.current_frame.load(Ordering::Acquire);
    let mut changes = state
        .shards_store
        .all_pending_shard_changes()
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    changes.sort_by(|a, b| (a.effective_epoch, &a.parent).cmp(&(b.effective_epoch, &b.parent)));
    Ok(Json(PendingResponse {
        current_frame,
        changes: changes
            .into_iter()
            .map(|change| PendingChange::from_stored(change, current_frame))
            .collect(),
    }))
}

fn app_address(shard: &ShardInfo) -> Option<[u8; 32]> {
    shard.shard_key.get(3..35)?.try_into().ok()
}

fn grouped_apps(state: &ExplorerState) -> Result<BTreeMap<[u8; 32], Vec<ShardInfo>>, ApiError> {
    let shards = state
        .shards_store
        .range_app_shards()
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let mut apps = BTreeMap::<[u8; 32], Vec<ShardInfo>>::new();
    for shard in shards {
        if let Some(address) = app_address(&shard) {
            apps.entry(address).or_default().push(shard);
        }
    }
    Ok(apps)
}

fn parse_address(value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| error(StatusCode::BAD_REQUEST, "address must be 32-byte hex"))?;
    bytes
        .try_into()
        .map_err(|_| error(StatusCode::BAD_REQUEST, "address must be 32-byte hex"))
}

#[derive(Deserialize)]
pub(crate) struct AppsQuery {
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AppSummary {
    address: String,
    shard_count: usize,
}

#[derive(Serialize)]
pub(crate) struct AppsResponse {
    /// Applications with a metadata vertex or current shard rows.
    scope: &'static str,
    total: usize,
    apps: Vec<AppSummary>,
    next_cursor: Option<String>,
}

/// Page over deployed applications and registered shard owners. Only tree-root
/// keys are enumerated; vertex data is read once per candidate domain. The
/// page limit bounds the response, while this discovery pass still visits all
/// candidate domains to report an exact total.
pub(crate) async fn apps(
    State(state): State<ExplorerState>,
    Query(query): Query<AppsQuery>,
) -> Result<Json<AppsResponse>, ApiError> {
    tokio::task::spawn_blocking(move || apps_committed(state, query))
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?
}

fn committed_app_blob(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    address: &[u8; 32],
) -> Result<Option<Vec<u8>>, ApiError> {
    let mut id = [0xff; 64];
    id[..32].copy_from_slice(address);
    let shard = quil_hypergraph::shard_key_for_location(&quil_hypergraph::Location::from_id(&id));
    let read_error =
        |e: quil_types::error::QuilError| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
    if snapshot
        .load_vertex_underlying_raw("vertex", "removes", &shard, &id)
        .map_err(read_error)?
        .is_some()
    {
        return Ok(None);
    }
    Ok(snapshot
        .load_vertex_underlying_raw("vertex", "adds", &shard, &id)
        .map_err(read_error)?
        .filter(|blob| !blob.is_empty()))
}

fn apps_committed(state: ExplorerState, query: AppsQuery) -> Result<Json<AppsResponse>, ApiError> {
    let after = query.after.as_deref().map(parse_address).transpose()?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let snapshot = state
        .crdt
        .capture_fresh_committed_snapshot()
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let mut grouped = grouped_apps(&state)?;
    for address in state
        .crdt
        .vertex_adds_domains()
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?
    {
        if address == quil_execution::domains::GLOBAL || grouped.contains_key(&address) {
            continue;
        }
        if committed_app_blob(snapshot.as_ref(), &address)?.is_some() {
            grouped.insert(address, Vec::new());
        }
    }
    let total = grouped.len();
    let mut rows = grouped
        .into_iter()
        .filter(|(address, _)| after.is_none_or(|after| *address > after))
        .map(|(address, shards)| AppSummary {
            address: hex::encode(address),
            shard_count: shards.len(),
        })
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = has_more.then(|| rows.last().unwrap().address.clone());
    Ok(Json(AppsResponse {
        scope: "deployed_and_registered_apps",
        total,
        apps: rows,
        next_cursor,
    }))
}

#[derive(Serialize)]
struct TokenMetadata {
    name: Option<String>,
    symbol: Option<String>,
    units: Option<String>,
    supply: Option<String>,
    behavior: u32,
}

#[derive(Serialize)]
struct AccessMetadata {
    read_public_key: Option<String>,
    write_public_key: Option<String>,
}

#[derive(Serialize)]
struct AppMetadata {
    kind: &'static str,
    type_domain: Option<String>,
    rdf_schema_bytes: Option<usize>,
    rdf_schema_sha256: Option<String>,
    token: Option<TokenMetadata>,
    access: Option<AccessMetadata>,
}

fn public_text(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|text| !text.is_empty() && !text.chars().any(|c| c.is_control()))
        .map(str::to_owned)
}

fn public_number(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| BigUint::from_bytes_be(bytes).to_string())
}

fn metadata(blob: &[u8]) -> Option<AppMetadata> {
    let root = quil_tries::deserialize_go_tree(blob).ok()?;
    let tree = quil_tries::VectorCommitmentTree { root };
    let route: Option<[u8; 32]> = tree
        .get(&[0xff; 32])
        .and_then(|value| value.get(..32))
        .and_then(|value| value.try_into().ok());
    let kind = match route {
        Some(route) if route == quil_execution::token_intrinsic::constants::token_base_domain() => {
            "token"
        }
        Some(route) if route == quil_execution::hypergraph_intrinsic::hypergraph_base_domain() => {
            "hypergraph"
        }
        Some(route) if route == quil_execution::domains::COMPUTE => "compute",
        _ => "unknown",
    };
    let rdf = tree.get(&[2u8 << 2]);
    let token = if kind == "token" {
        tree.get(&quil_execution::token_intrinsic::materialize::TOKEN_CONFIG_OUTER_KEY)
            .and_then(|config| quil_tries::deserialize_go_tree(config).ok())
            .and_then(|root| {
                quil_execution::token_intrinsic::metadata_schema::decode_token_config_from_tree(
                    &quil_tries::VectorCommitmentTree { root },
                )
                .ok()
            })
            .map(|config| TokenMetadata {
                name: public_text(&config.name),
                symbol: public_text(&config.symbol),
                units: public_number(&config.units),
                supply: public_number(&config.supply),
                behavior: config.behavior,
            })
    } else {
        None
    };
    let access = if kind == "hypergraph" || kind == "compute" {
        tree.get(&[16u8 << 2])
            .and_then(|config| quil_tries::deserialize_go_tree(config).ok())
            .map(|root| {
                let config = quil_tries::VectorCommitmentTree { root };
                AccessMetadata {
                    read_public_key: config.get(&[0]).map(hex::encode),
                    write_public_key: config.get(&[4]).map(hex::encode),
                }
            })
    } else {
        None
    };
    Some(AppMetadata {
        kind,
        type_domain: route.map(hex::encode),
        rdf_schema_bytes: rdf.map(|bytes| bytes.len()),
        rdf_schema_sha256: rdf.map(|bytes| hex::encode(Sha256::digest(bytes))),
        token,
        access,
    })
}

#[derive(Serialize)]
struct AppShard {
    filter: String,
    prefix: Vec<u32>,
    size_bytes: Option<String>,
    data_shards: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct AppDetail {
    address: String,
    scope: &'static str,
    metadata: Option<AppMetadata>,
    shards: Vec<AppShard>,
}

/// One application's chain metadata and current shard rows, if any.
pub(crate) async fn app(
    State(state): State<ExplorerState>,
    Path(address_hex): Path<String>,
) -> Result<Json<AppDetail>, ApiError> {
    tokio::task::spawn_blocking(move || app_committed(state, address_hex))
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?
}

fn app_committed(state: ExplorerState, address_hex: String) -> Result<Json<AppDetail>, ApiError> {
    let address = parse_address(&address_hex)?;
    let mut shards = grouped_apps(&state)?.remove(&address).unwrap_or_default();
    shards.sort_by(|a, b| a.prefix.cmp(&b.prefix));
    let snapshot = state
        .crdt
        .capture_fresh_committed_snapshot()
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let blob = committed_app_blob(snapshot.as_ref(), &address)?;
    if shards.is_empty() && blob.is_none() {
        return Err(error(StatusCode::NOT_FOUND, "application not found"));
    }
    let chain_metadata = blob.as_deref().and_then(metadata);
    let scope = if shards.is_empty() {
        "deployed_app"
    } else {
        "registered_shard_app"
    };
    let rows = shards
        .into_iter()
        .map(|shard| {
            let dimensions = state
                .app_shards_provider
                .as_ref()
                .and_then(|provider| provider(&shard.shard_key, &shard.prefix));
            let (size_bytes, data_shards) = match dimensions {
                Some((size, count, _)) => {
                    (Some(BigUint::from_bytes_be(&size).to_string()), Some(count))
                }
                None if !shard.size.is_empty() => (
                    Some(BigUint::from_bytes_be(&shard.size).to_string()),
                    Some(shard.data_shards),
                ),
                None => (None, None),
            };
            AppShard {
                filter: hex::encode(quil_forest::shard_prefix_to_filter(&address, &shard.prefix)),
                prefix: shard.prefix,
                size_bytes,
                data_shards,
            }
        })
        .collect();
    Ok(Json(AppDetail {
        address: hex::encode(address),
        scope,
        metadata: chain_metadata,
        shards: rows,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deployed_app_metadata_excludes_uncommitted_changes() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let raw = db.inner();
        let crdt = std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_store::RocksHypergraphStore::new(raw.clone())),
            std::sync::Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        let address = [9; 32];
        let mut id = [0xff; 64];
        id[..32].copy_from_slice(&address);
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let token = quil_execution::token_intrinsic::constants::token_base_domain();
        tree.insert(&[0xff; 32], &token, &[], &num_bigint::BigInt::from(32))
            .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        crdt.add_vertex(&quil_hypergraph::Location::from_id(&id), &blob)
            .unwrap();
        let state = crate::ExplorerState::new(
            std::sync::Arc::new(quil_store::RocksClockStore::new(raw.clone())),
            crdt.clone(),
            std::sync::Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
            std::sync::Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
            std::sync::Arc::new(quil_store::RocksShardsStore::new(raw)),
            None,
            None,
            std::sync::Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            std::sync::Arc::new(crate::RecentMessageRing::new(16)),
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        );
        assert!(
            matches!(
                app(State(state.clone()), Path(hex::encode(address))).await,
                Err((StatusCode::NOT_FOUND, _))
            ),
            "pending deployment was reported as a deployed application"
        );
        crdt.commit(1).unwrap();
        assert_eq!(crdt.vertex_adds_domains().unwrap(), vec![address]);
        let Json(detail) = match app(State(state.clone()), Path(hex::encode(address))).await {
            Ok(detail) => detail,
            Err((status, _)) => panic!("unexpected status {status}"),
        };
        assert_eq!(detail.scope, "deployed_app");
        assert!(detail.shards.is_empty());
        assert_eq!(detail.metadata.unwrap().kind, "token");

        let Json(list) = apps(
            State(state.clone()),
            Query(AppsQuery {
                after: None,
                limit: None,
            }),
        )
        .await
        .unwrap_or_else(|(status, _)| panic!("unexpected status {status}"));
        assert_eq!(list.total, 1);
        assert_eq!(list.apps[0].address, hex::encode(address));
        assert_eq!(list.apps[0].shard_count, 0);

        let mut draft = quil_tries::VectorCommitmentTree::new();
        draft
            .insert(
                &[0xff; 32],
                &quil_execution::domains::COMPUTE,
                &[],
                &num_bigint::BigInt::from(32),
            )
            .unwrap();
        let draft = quil_tries::serialize_go_tree(draft.root.as_ref()).unwrap();
        crdt.add_vertex(&quil_hypergraph::Location::from_id(&id), &draft)
            .unwrap();
        let Json(detail) = app(State(state.clone()), Path(hex::encode(address)))
            .await
            .unwrap_or_else(|(status, _)| panic!("unexpected status {status}"));
        assert_eq!(
            detail.metadata.unwrap().kind,
            "token",
            "pending metadata escaped before durable publication"
        );
        crdt.discard_staged_mutations().unwrap();
        crdt.remove_vertex(&quil_hypergraph::Location::from_id(&id))
            .unwrap();
        let Json(detail) = app(State(state.clone()), Path(hex::encode(address)))
            .await
            .unwrap_or_else(|(status, _)| panic!("unexpected status {status}"));
        assert_eq!(
            detail.metadata.unwrap().kind,
            "token",
            "pending removal hid a committed app"
        );
        crdt.commit(2).unwrap();
        assert!(matches!(
            app(State(state), Path(hex::encode(address))).await,
            Err((StatusCode::NOT_FOUND, _))
        ));
    }

    #[test]
    fn pending_change_reports_only_determinable_impact() {
        let change = PendingChange::from_stored(
            PendingShardChange {
                kind: ShardChangeKind::Split,
                parent: vec![1],
                children: vec![vec![2], vec![3]],
                effective_epoch: 5,
                proposed_frame: 2_100,
            },
            3_000,
        );
        assert_eq!(change.effective_frame, 3_600);
        assert_eq!(change.frames_remaining, 600);
        assert_eq!(change.reward_impact.shard_slots_before, 1);
        assert_eq!(change.reward_impact.shard_slots_after, 2);
        assert!(change
            .reward_impact
            .estimated_delta_subunits_per_frame
            .is_none());
    }

    #[test]
    fn application_metadata_reports_only_committed_fields() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(
            &[0xff; 32],
            &quil_execution::domains::COMPUTE,
            &[],
            &num_bigint::BigInt::from(32),
        )
        .unwrap();
        tree.insert(&[2u8 << 2], b"schema", &[], &num_bigint::BigInt::from(6))
            .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        let decoded = metadata(&blob).unwrap();
        assert_eq!(decoded.kind, "compute");
        assert_eq!(decoded.type_domain, Some(hex::encode([0xcc; 32])));
        assert_eq!(decoded.rdf_schema_bytes, Some(6));
        assert!(decoded.token.is_none());
    }
}
