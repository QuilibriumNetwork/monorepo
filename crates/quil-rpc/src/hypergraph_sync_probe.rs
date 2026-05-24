//! Diagnostic probe for `HypergraphComparisonService.PerformSync` —
//! pulls the global prover tree's `VertexAdds` root and pages leaves.

use std::sync::Arc;
use std::time::{Duration, Instant};

use num_bigint::BigInt;
use thiserror::Error;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::{debug, info, warn};

use quil_crypto::KzgInclusionProver;
use quil_store::RocksHypergraphStore;
use quil_tries::{
    deserialize_go_tree, deserialize_tree, serialize_tree, VectorCommitmentNode,
    VectorCommitmentTree,
};
use quil_types::proto::application::hypergraph_comparison_service_client::HypergraphComparisonServiceClient;
use quil_types::proto::application::{
    hypergraph_sync_query, hypergraph_sync_response, HypergraphPhaseSet,
    HypergraphSyncGetBranchRequest, HypergraphSyncGetLeavesRequest, HypergraphSyncQuery,
};
use quil_types::store::ShardKey;

use crate::archive_client::{build_quil_client_config, QuilTlsConnector};

#[derive(Debug, Error)]
pub enum HyperSyncProbeError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("tls init error: {0}")]
    TlsInit(String),
    #[error("server stream ended without a response")]
    EmptyResponse,
}

/// Wire encoding of `tries.ShardKey{L1, L2}` as a flat 35-byte slice.
pub fn encode_shard_key(l1: &[u8; 3], l2: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(35);
    out.extend_from_slice(l1);
    out.extend_from_slice(l2);
    out
}

/// Global prover tree shard key: `L1 = [0;3], L2 = [0xff;32]`.
pub fn global_prover_shard_key() -> Vec<u8> {
    encode_shard_key(&[0u8; 3], &[0xffu8; 32])
}

/// Stats from a single `pull_root_leaves` call against an archive.
#[derive(Debug, Default)]
pub struct ProberStats {
    pub root_commitment: Vec<u8>,
    pub root_full_path_len: usize,
    pub root_child_count: usize,
    pub root_leaf_count: u64,
    pub leaves_pulled: u64,
    pub leaves_value_bytes: u64,
    pub leaves_underlying_bytes: u64,
    pub leaves_pages: u32,
    pub stopped_early: bool,
}

/// Send one `PerformSync` `GetBranch` for the global prover tree's
/// `VertexAdds` root over the archive's mTLS channel and log the response.
pub async fn probe_perform_sync(
    addr: &str,
    ed448_seed: &[u8; 57],
    expected_root: &[u8],
) -> Result<(), HyperSyncProbeError> {
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;

    // Build the channel by hand using the same connector the archive client
    // uses for GlobalService — that path is already verified end-to-end.
    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);

    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;
    info!(%addr, "hypersync probe connected");

    // Bump message size from the 4 MiB default — HyperSync responses can
    // exceed 48 MiB when hyperedge leaves carry large underlying_data.
    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(4);
    let req_stream = ReceiverStream::new(rx);

    let shard_key = global_prover_shard_key();
    let req = HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key,
                phase_set: HypergraphPhaseSet::VertexAdds as i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    };
    tx.send(req).await.map_err(|_| {
        HyperSyncProbeError::Rpc(tonic::Status::cancelled("request stream closed"))
    })?;

    debug!(%addr, "calling PerformSync");
    let response = client
        .perform_sync(Request::new(req_stream))
        .await?
        .into_inner();
    let mut response = response;

    let first = response.next().await;
    let Some(first) = first else {
        return Err(HyperSyncProbeError::EmptyResponse);
    };
    let resp = first?;
    match resp.response {
        Some(hypergraph_sync_response::Response::Branch(branch)) => {
            info!(
                %addr,
                full_path = ?branch.full_path,
                commitment = hex::encode(&branch.commitment),
                child_count = branch.children.len(),
                is_leaf = branch.is_leaf,
                leaf_count = branch.leaf_count,
                "PerformSync root branch received"
            );
            for (i, c) in branch.children.iter().enumerate().take(8) {
                info!(
                    %addr,
                    child_index = c.index,
                    commitment = hex::encode(&c.commitment),
                    "child {} of root", i
                );
            }
        }
        Some(hypergraph_sync_response::Response::Leaves(leaves)) => {
            info!(
                %addr,
                path = ?leaves.path,
                leaf_count = leaves.leaves.len(),
                "PerformSync leaves received"
            );
        }
        Some(hypergraph_sync_response::Response::Error(err)) => {
            warn!(
                %addr,
                code = err.code,
                message = %err.message,
                path = ?err.path,
                "PerformSync server error"
            );
        }
        None => {
            warn!(%addr, "PerformSync response had empty oneof");
        }
    }

    drop(tx);

    Ok(())
}

/// Page `GetLeaves` against the global prover tree root until exhausted
/// or `max_pages` reached. Returns counts; stores nothing.
pub async fn probe_pull_root_leaves(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    max_pages: u32,
    expected_root: &[u8],
) -> Result<ProberStats, HyperSyncProbeError> {
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;

    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);
    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;
    info!(%addr, ?phase, "leaf puller connected");

    // Bump from the 4 MiB default — HyperSync responses can exceed 48 MiB.
    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    // The first message must be queued BEFORE `perform_sync`, or the
    // bidi stream setup blocks.
    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(8);
    let req_stream = ReceiverStream::new(rx);

    let shard_key = global_prover_shard_key();
    let phase_i32 = phase as i32;

    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send root branch")))?;

    let response = client
        .perform_sync(Request::new(req_stream))
        .await?
        .into_inner();
    let mut response = response;

    let first = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
    let first = first?;
    let mut stats = ProberStats::default();
    let root_branch = match first.response {
        Some(hypergraph_sync_response::Response::Branch(b)) => b,
        Some(hypergraph_sync_response::Response::Error(e)) => {
            warn!(%addr, code = e.code, msg = %e.message, "GetBranch root error");
            return Ok(stats);
        }
        other => {
            warn!(%addr, ?other, "unexpected first response");
            return Ok(stats);
        }
    };

    stats.root_commitment = root_branch.commitment.clone();
    stats.root_full_path_len = root_branch.full_path.len();
    stats.root_child_count = root_branch.children.len();
    stats.root_leaf_count = root_branch.leaf_count;
    info!(
        %addr,
        ?phase,
        commitment = hex::encode(&stats.root_commitment),
        children = stats.root_child_count,
        leaves = stats.root_leaf_count,
        "root branch ready, paginating leaves"
    );

    // Page GetLeaves against the server-returned canonical root path —
    // an empty path would re-walk the whole compressed prefix.
    let mut continuation: Vec<u8> = Vec::new();
    let leaves_path = root_branch.full_path.clone();
    for page in 0..max_pages {
        tx.send(HypergraphSyncQuery {
            request: Some(hypergraph_sync_query::Request::GetLeaves(
                HypergraphSyncGetLeavesRequest {
                    shard_key: shard_key.clone(),
                    phase_set: phase_i32,
                    path: leaves_path.clone(),
                    max_leaves: 1000,
                    continuation_token: continuation.clone(),
                    expected_root: expected_root.to_vec(),
                },
            )),
        })
        .await
        .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send getleaves")))?;

        let resp = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
        let resp = resp?;
        let leaves_resp = match resp.response {
            Some(hypergraph_sync_response::Response::Leaves(l)) => l,
            Some(hypergraph_sync_response::Response::Error(e)) => {
                warn!(%addr, code = e.code, msg = %e.message, "GetLeaves error");
                stats.stopped_early = true;
                break;
            }
            other => {
                warn!(%addr, ?other, "unexpected leaves response");
                stats.stopped_early = true;
                break;
            }
        };

        let batch_count = leaves_resp.leaves.len();
        stats.leaves_pages += 1;
        for leaf in &leaves_resp.leaves {
            stats.leaves_pulled += 1;
            stats.leaves_value_bytes += leaf.value.len() as u64;
            stats.leaves_underlying_bytes += leaf.underlying_data.len() as u64;
        }
        info!(
            %addr,
            page,
            batch = batch_count,
            total_pulled = stats.leaves_pulled,
            total_available = leaves_resp.total_leaves,
            "leaves page received"
        );
        if leaves_resp.continuation_token.is_empty() {
            break;
        }
        continuation = leaves_resp.continuation_token;
    }

    if stats.leaves_pages == max_pages && !continuation.is_empty() {
        stats.stopped_early = true;
    }

    drop(tx);
    info!(
        %addr,
        ?phase,
        leaves_pulled = stats.leaves_pulled,
        leaves_pages = stats.leaves_pages,
        value_bytes = stats.leaves_value_bytes,
        underlying_bytes = stats.leaves_underlying_bytes,
        stopped_early = stats.stopped_early,
        "pull_root_leaves done"
    );
    Ok(stats)
}

/// Stats from `probe_build_local_tree`.
#[derive(Debug, Default)]
pub struct BuildTreeStats {
    pub server_root_commitment: Vec<u8>,
    pub server_leaf_count: u64,
    pub leaves_pulled: u64,
    pub leaves_pages: u32,
    pub local_root_commitment: Vec<u8>,
    pub local_commit_duration: Duration,
    pub commitments_match: bool,
}

/// Pull all leaves under `phase`, rebuild the tree locally, and compare
/// the recomputed root to the server's. `max_pages == 0` means
/// "until exhausted". The `commitments_match` flag gates byte-identical
/// port correctness.
pub async fn probe_build_local_tree(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    max_pages: u32,
    expected_root: &[u8],
) -> Result<BuildTreeStats, HyperSyncProbeError> {
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;

    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        // The full pull can take ~10 minutes; budget generously.
        .timeout(Duration::from_secs(20 * 60))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);
    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;
    info!(%addr, ?phase, max_pages, "tree builder connected");

    // Bump from the 4 MiB default — HyperSync responses can exceed 48 MiB.
    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(8);
    let req_stream = ReceiverStream::new(rx);

    let shard_key = global_prover_shard_key();
    let phase_i32 = phase as i32;

    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send root branch")))?;

    let mut response = client
        .perform_sync(Request::new(req_stream))
        .await?
        .into_inner();

    let mut stats = BuildTreeStats::default();

    let first = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
    let first = first?;
    let root_branch = match first.response {
        Some(hypergraph_sync_response::Response::Branch(b)) => b,
        Some(hypergraph_sync_response::Response::Error(e)) => {
            warn!(%addr, code = e.code, msg = %e.message, "GetBranch root error");
            return Ok(stats);
        }
        other => {
            warn!(%addr, ?other, "unexpected first response");
            return Ok(stats);
        }
    };
    stats.server_root_commitment = root_branch.commitment.clone();
    stats.server_leaf_count = root_branch.leaf_count;
    info!(
        %addr,
        ?phase,
        commitment = hex::encode(&stats.server_root_commitment),
        leaf_count = stats.server_leaf_count,
        "server root branch acquired, pulling leaves"
    );

    // Build a fresh local tree and feed it leaves as they arrive.
    let mut tree = VectorCommitmentTree::new();
    let mut continuation: Vec<u8> = Vec::new();
    let leaves_path = root_branch.full_path.clone();

    let pull_start = Instant::now();
    let mut pages = 0u32;
    loop {
        if max_pages > 0 && pages >= max_pages {
            break;
        }
        tx.send(HypergraphSyncQuery {
            request: Some(hypergraph_sync_query::Request::GetLeaves(
                HypergraphSyncGetLeavesRequest {
                    shard_key: shard_key.clone(),
                    phase_set: phase_i32,
                    path: leaves_path.clone(),
                    max_leaves: 1000,
                    continuation_token: continuation.clone(),
                    expected_root: expected_root.to_vec(),
                },
            )),
        })
        .await
        .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send getleaves")))?;

        let resp = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
        let resp = resp?;
        let leaves_resp = match resp.response {
            Some(hypergraph_sync_response::Response::Leaves(l)) => l,
            Some(hypergraph_sync_response::Response::Error(e)) => {
                warn!(%addr, code = e.code, msg = %e.message, "GetLeaves error");
                break;
            }
            other => {
                warn!(%addr, ?other, "unexpected leaves response");
                break;
            }
        };

        let batch = leaves_resp.leaves.len();
        pages += 1;
        stats.leaves_pages = pages;
        for leaf in &leaves_resp.leaves {
            let size = if leaf.size.is_empty() {
                BigInt::from(0)
            } else {
                BigInt::from_signed_bytes_be(&leaf.size)
            };
            if let Err(e) = tree.insert(&leaf.key, &leaf.value, &leaf.hash_target, &size) {
                warn!(error = %e, "tree insert failed");
            }
            stats.leaves_pulled += 1;
        }
        if pages == 1 || pages % 10 == 0 {
            info!(
                %addr,
                page = pages,
                batch,
                total_pulled = stats.leaves_pulled,
                elapsed_secs = pull_start.elapsed().as_secs(),
                "build_tree progress"
            );
        }
        if leaves_resp.continuation_token.is_empty() {
            break;
        }
        continuation = leaves_resp.continuation_token;
    }
    drop(tx);
    let pull_elapsed = pull_start.elapsed();
    info!(
        %addr,
        leaves_pulled = stats.leaves_pulled,
        pages = stats.leaves_pages,
        pull_secs = pull_elapsed.as_secs(),
        "all requested leaves pulled, computing local root commitment"
    );

    let prover = KzgInclusionProver;
    let commit_start = Instant::now();
    let local_root = tree.commit(&prover);
    stats.local_commit_duration = commit_start.elapsed();
    stats.local_root_commitment = local_root.clone();
    stats.commitments_match = local_root == stats.server_root_commitment;

    // If the caller pinned an expected_root from a verified frame's
    // `prover_tree_commitment`, the locally-reconstructed root MUST
    // match it. The server-claim match (above) only confirms internal
    // consistency of what the peer sent; without this gate a
    // malicious peer can serve a self-consistent fake snapshot at any
    // root.
    if !expected_root.is_empty() && local_root != expected_root {
        warn!(
            %addr,
            local = hex::encode(&local_root),
            expected = hex::encode(expected_root),
            "synced tree root does NOT match caller-supplied expected_root \
             (frame's prover_tree_commitment) — rejecting"
        );
        stats.commitments_match = false;
        return Err(HyperSyncProbeError::Rpc(tonic::Status::data_loss(format!(
            "HyperSync: synced root {} does not match expected {}",
            hex::encode(&local_root),
            hex::encode(expected_root),
        ))));
    }

    if stats.commitments_match {
        info!(
            %addr,
            commitment = hex::encode(&local_root),
            commit_secs = stats.local_commit_duration.as_secs(),
            leaves = stats.leaves_pulled,
            "local tree commitment MATCHES server root"
        );
    } else {
        warn!(
            %addr,
            local = hex::encode(&local_root),
            server = hex::encode(&stats.server_root_commitment),
            commit_secs = stats.local_commit_duration.as_secs(),
            leaves_pulled = stats.leaves_pulled,
            server_leaves = stats.server_leaf_count,
            "local tree commitment DIVERGES from server root"
        );
    }
    Ok(stats)
}

/// A leaf's key and serialized vertex sub-tree
/// (Go `SerializeNonLazyTree` format; parse with `deserialize_go_tree`).
/// Leaves with no per-vertex data are skipped.
pub struct VertexDataEntry {
    pub key: Vec<u8>,
    pub underlying_data: Vec<u8>,
}

/// Like `probe_build_local_tree` but also returns the committed tree
/// and per-leaf `underlying_data` blobs.
pub async fn build_local_tree_with_handle(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    max_pages: u32,
    expected_root: &[u8],
) -> Result<
    (BuildTreeStats, VectorCommitmentTree, Vec<VertexDataEntry>),
    HyperSyncProbeError,
> {
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;

    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20 * 60))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);
    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;
    info!(%addr, ?phase, max_pages, "tree builder connected (with-handle)");

    // Bump from the 4 MiB default — HyperSync responses can exceed 48 MiB.
    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(8);
    let req_stream = ReceiverStream::new(rx);

    let shard_key = global_prover_shard_key();
    let phase_i32 = phase as i32;

    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send root branch")))?;

    let mut response = client
        .perform_sync(Request::new(req_stream))
        .await?
        .into_inner();

    let mut stats = BuildTreeStats::default();
    let first = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
    let first = first?;
    let root_branch = match first.response {
        Some(hypergraph_sync_response::Response::Branch(b)) => b,
        Some(hypergraph_sync_response::Response::Error(e)) => {
            warn!(%addr, code = e.code, msg = %e.message, "GetBranch root error");
            return Ok((stats, VectorCommitmentTree::new(), Vec::new()));
        }
        other => {
            warn!(%addr, ?other, "unexpected first response");
            return Ok((stats, VectorCommitmentTree::new(), Vec::new()));
        }
    };
    stats.server_root_commitment = root_branch.commitment.clone();
    stats.server_leaf_count = root_branch.leaf_count;
    info!(
        %addr,
        ?phase,
        commitment = hex::encode(&stats.server_root_commitment),
        leaf_count = stats.server_leaf_count,
        "server root branch acquired (with-handle)"
    );

    if stats.server_root_commitment.is_empty() && stats.server_leaf_count == 0 {
        stats.commitments_match = true;
        stats.local_root_commitment.clear();
        info!(%addr, ?phase, "empty phase — nothing to sync");
        drop(tx);
        return Ok((stats, VectorCommitmentTree::new(), Vec::new()));
    }

    let mut tree = VectorCommitmentTree::new();
    let mut vertex_data: Vec<VertexDataEntry> = Vec::new();
    let mut continuation: Vec<u8> = Vec::new();
    let leaves_path = root_branch.full_path.clone();

    let pull_start = Instant::now();
    let mut pages = 0u32;
    loop {
        if max_pages > 0 && pages >= max_pages {
            break;
        }
        tx.send(HypergraphSyncQuery {
            request: Some(hypergraph_sync_query::Request::GetLeaves(
                HypergraphSyncGetLeavesRequest {
                    shard_key: shard_key.clone(),
                    phase_set: phase_i32,
                    path: leaves_path.clone(),
                    max_leaves: 1000,
                    continuation_token: continuation.clone(),
                    expected_root: expected_root.to_vec(),
                },
            )),
        })
        .await
        .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send getleaves")))?;
        let resp = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
        let resp = resp?;
        let leaves_resp = match resp.response {
            Some(hypergraph_sync_response::Response::Leaves(l)) => l,
            Some(hypergraph_sync_response::Response::Error(e)) => {
                warn!(%addr, code = e.code, msg = %e.message, "GetLeaves error");
                break;
            }
            other => {
                warn!(%addr, ?other, "unexpected leaves response");
                break;
            }
        };
        let batch = leaves_resp.leaves.len();
        pages += 1;
        stats.leaves_pages = pages;
        for leaf in leaves_resp.leaves.into_iter() {
            let size = if leaf.size.is_empty() {
                BigInt::from(0)
            } else {
                BigInt::from_signed_bytes_be(&leaf.size)
            };
            if let Err(e) = tree.insert(&leaf.key, &leaf.value, &leaf.hash_target, &size) {
                warn!(error = %e, "tree insert failed");
            }
            stats.leaves_pulled += 1;
            if !leaf.underlying_data.is_empty() {
                vertex_data.push(VertexDataEntry {
                    key: leaf.key,
                    underlying_data: leaf.underlying_data,
                });
            }
        }
        if pages == 1 || pages % 10 == 0 {
            info!(
                %addr,
                page = pages,
                batch,
                total_pulled = stats.leaves_pulled,
                elapsed_secs = pull_start.elapsed().as_secs(),
                "build_tree progress (with-handle)"
            );
        }
        if leaves_resp.continuation_token.is_empty() {
            break;
        }
        continuation = leaves_resp.continuation_token;
    }
    drop(tx);
    info!(
        %addr,
        leaves_pulled = stats.leaves_pulled,
        vertex_data_entries = vertex_data.len(),
        pages = stats.leaves_pages,
        pull_secs = pull_start.elapsed().as_secs(),
        "all leaves pulled, computing local root commitment (with-handle)"
    );

    let prover = KzgInclusionProver;
    let commit_start = Instant::now();
    let local_root = tree.commit(&prover);
    stats.local_commit_duration = commit_start.elapsed();
    stats.local_root_commitment = local_root.clone();
    stats.commitments_match = local_root == stats.server_root_commitment;

    // See probe_build_local_tree for rationale. The expected_root pin
    // must match the locally-reconstructed root or the sync result is
    // rejected.
    if !expected_root.is_empty() && local_root != expected_root {
        warn!(
            %addr,
            local = hex::encode(&local_root),
            expected = hex::encode(expected_root),
            "synced tree root does NOT match expected_root — rejecting"
        );
        stats.commitments_match = false;
        return Err(HyperSyncProbeError::Rpc(tonic::Status::data_loss(format!(
            "HyperSync: synced root {} does not match expected {}",
            hex::encode(&local_root),
            hex::encode(expected_root),
        ))));
    }

    Ok((stats, tree, vertex_data))
}

/// Pull and log a handful of leaves' `underlying_data` sub-trees.
/// Diagnostic only — persists nothing.
pub async fn probe_inspect_vertex_data(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    leaves_to_inspect: usize,
    expected_root: &[u8],
) -> Result<(), HyperSyncProbeError> {
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;

    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);
    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;
    info!(%addr, ?phase, leaves_to_inspect, "vertex data inspector connected");

    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(8);
    let req_stream = ReceiverStream::new(rx);
    let shard_key = global_prover_shard_key();
    let phase_i32 = phase as i32;

    // Get the root branch to learn the canonical path.
    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send branch")))?;

    let mut response = client
        .perform_sync(Request::new(req_stream))
        .await?
        .into_inner();
    let first = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)?;
    let first = first?;
    let root_branch = match first.response {
        Some(hypergraph_sync_response::Response::Branch(b)) => b,
        _ => return Err(HyperSyncProbeError::EmptyResponse),
    };

    // Pull one page of leaves.
    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetLeaves(
            HypergraphSyncGetLeavesRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: root_branch.full_path.clone(),
                max_leaves: leaves_to_inspect as u32,
                continuation_token: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send getleaves")))?;

    let leaves_resp = match response.next().await {
        Some(Ok(r)) => match r.response {
            Some(hypergraph_sync_response::Response::Leaves(l)) => l,
            _ => return Err(HyperSyncProbeError::EmptyResponse),
        },
        _ => return Err(HyperSyncProbeError::EmptyResponse),
    };
    drop(tx);

    info!(
        %addr,
        received = leaves_resp.leaves.len(),
        "inspecting leaves"
    );
    for (i, leaf) in leaves_resp.leaves.iter().enumerate().take(leaves_to_inspect) {
        inspect_leaf(i, leaf);
    }
    Ok(())
}

fn inspect_leaf(index: usize, leaf: &quil_types::proto::application::LeafData) {
    let key_hex = hex::encode(&leaf.key);
    let value_hex = hex::encode(&leaf.value);
    let hash_target_hex = hex::encode(&leaf.hash_target);
    info!(
        index,
        key_len = leaf.key.len(),
        value_len = leaf.value.len(),
        hash_target_len = leaf.hash_target.len(),
        size_bytes = leaf.size.len(),
        underlying_len = leaf.underlying_data.len(),
        key = %key_hex,
        value = %value_hex,
        hash_target = %hash_target_hex,
        "leaf"
    );

    if leaf.underlying_data.is_empty() {
        info!(index, "  no underlying_data");
        return;
    }

    match deserialize_go_tree(&leaf.underlying_data) {
        Ok(Some(root)) => {
            walk_subtree(index, &root, 0);
        }
        Ok(None) => {
            info!(index, "  underlying tree is empty (nil root)");
        }
        Err(e) => {
            warn!(index, error = %e, "  deserialize_go_tree FAILED");
        }
    }
}

fn walk_subtree(index: usize, node: &VectorCommitmentNode, depth: usize) {
    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            info!(
                index,
                depth,
                key = %hex::encode(&leaf.key),
                value_len = leaf.value.len(),
                value_hex = %hex::encode(&leaf.value),
                "  inner leaf"
            );
        }
        VectorCommitmentNode::Branch(branch) => {
            let non_nil_children: Vec<usize> = branch
                .children
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.as_ref().map(|_| i))
                .collect();
            info!(
                index,
                depth,
                prefix = ?branch.prefix,
                leaf_count = branch.leaf_count,
                children = ?non_nil_children,
                "  inner branch"
            );
            for child in branch.children.iter().flatten() {
                walk_subtree(index, child, depth + 1);
            }
        }
    }
}

/// High-level helper: ensure the local hypergraph store holds the
/// server's current prover tree for `phase`. Always performs at least
/// one server commitment comparison — a cached local blob is only
/// trusted when its commitment matches the server's. Pulls a diff (or
/// a full fresh copy) into the store otherwise. The shard key is the
/// global prover shard `{L1=[0;3], L2=[0xff;32]}`.
///
/// Delegates to [`ensure_prover_tree_incremental`] so the startup and
/// archive-discovery paths use the same compare-then-fetch flow as the
/// periodic refresher. The earlier behavior — returning
/// `commitments_match: true` purely on the existence of a deserializable
/// cached blob — produced a bug where the genesis bootstrap path wrote
/// 7 prover leaves into the tree blob, the next call to this function
/// short-circuited on that blob, and the lifecycle gate flipped open
/// against a 7-leaf view of the world. The proposer then treated every
/// real shard as halt-risk (loop-2 phantom descriptors with
/// `total_active_joining = 0`) and piled every worker onto whichever
/// shard reward-greedy picked first.
pub async fn ensure_prover_tree(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    hg_store: Arc<RocksHypergraphStore>,
    expected_root: &[u8],
) -> Result<BuildTreeStats, HyperSyncProbeError> {
    ensure_prover_tree_incremental(addr, ed448_seed, phase, hg_store, expected_root).await
}

/// Like [`ensure_prover_tree`] but always does a network sync, ignoring any
/// cached blob. Used when checking for newly-materialized prover data that
/// wouldn't be in the cache yet.
pub async fn ensure_prover_tree_fresh(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    hg_store: Arc<RocksHypergraphStore>,
    expected_root: &[u8],
) -> Result<BuildTreeStats, HyperSyncProbeError> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let phase_str = match phase {
        HypergraphPhaseSet::VertexAdds => "adds",
        HypergraphPhaseSet::VertexRemoves => "removes",
        HypergraphPhaseSet::HyperedgeAdds => "adds",
        HypergraphPhaseSet::HyperedgeRemoves => "removes",
    };
    let set_str = match phase {
        HypergraphPhaseSet::VertexAdds | HypergraphPhaseSet::VertexRemoves => "vertex",
        HypergraphPhaseSet::HyperedgeAdds | HypergraphPhaseSet::HyperedgeRemoves => "hyperedge",
    };

    info!(?phase, "fresh sync from archive (bypassing cache)");
    let (stats, tree, vertex_data) =
        build_local_tree_with_handle(addr, ed448_seed, phase, 0, expected_root).await?;

    if !stats.commitments_match {
        warn!(?phase, "fresh sync commitment mismatch, NOT persisting");
        return Ok(stats);
    }

    let serialized = match serialize_tree(tree.root.as_ref()) {
        Ok(b) => b,
        Err(e) => {
            warn!(?phase, error = %e, "serialize_tree failed");
            return Ok(stats);
        }
    };
    let blob_size = serialized.len();
    match hg_store.save_tree_blob(set_str, phase_str, &shard, &serialized) {
        Ok(()) => info!(?phase, blob_size, "prover tree refreshed"),
        Err(e) => warn!(?phase, error = %e, "save_tree_blob failed"),
    }

    let mut persisted_vertices = 0usize;
    for entry in &vertex_data {
        if hg_store
            .save_vertex_underlying(set_str, phase_str, &shard, &entry.key, &entry.underlying_data)
            .is_ok()
        {
            persisted_vertices += 1;
        }
    }
    info!(?phase, persisted_vertices, "per-vertex data refreshed");
    Ok(stats)
}

/// Incremental prover tree sync. Loads the cached tree, compares its root
/// commitment against the server, and only fetches leaves from branches that
/// differ. Falls back to a full sync if no cache exists.
pub async fn ensure_prover_tree_incremental(
    addr: &str,
    ed448_seed: &[u8; 57],
    phase: HypergraphPhaseSet,
    hg_store: Arc<RocksHypergraphStore>,
    expected_root: &[u8],
) -> Result<BuildTreeStats, HyperSyncProbeError> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let phase_str = match phase {
        HypergraphPhaseSet::VertexAdds => "adds",
        HypergraphPhaseSet::VertexRemoves => "removes",
        HypergraphPhaseSet::HyperedgeAdds => "adds",
        HypergraphPhaseSet::HyperedgeRemoves => "removes",
    };
    let set_str = match phase {
        HypergraphPhaseSet::VertexAdds | HypergraphPhaseSet::VertexRemoves => "vertex",
        HypergraphPhaseSet::HyperedgeAdds | HypergraphPhaseSet::HyperedgeRemoves => "hyperedge",
    };

    // Step 1: Load existing cached tree. If no cache, fall back to full sync.
    let cached_blob = hg_store.load_tree_blob(set_str, phase_str, &shard);
    let mut local_tree = match cached_blob {
        Ok(Some(bytes)) if !bytes.is_empty() => {
            match deserialize_tree(&bytes) {
                Ok(Some(_root)) => {
                    // Deserialize again but return the full tree this time
                    let mut tree = VectorCommitmentTree::new();
                    tree.root = deserialize_tree(&bytes).ok().flatten();
                    tree
                }
                _ => {
                    info!(?phase, "cached tree invalid, falling back to full sync");
                    return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
                }
            }
        }
        _ => {
            info!(?phase, "no cached tree, falling back to full sync");
            return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
        }
    };

    // Compute local root commitment from the cached tree
    let prover = KzgInclusionProver;
    let local_commitment = local_tree.commit(&prover);

    // Step 2: Connect and get server root branch
    let client_config = build_quil_client_config(ed448_seed)
        .map_err(|e| HyperSyncProbeError::TlsInit(format!("{}", e)))?;
    let url = format!("http://{}", addr);
    let endpoint = Endpoint::from_shared(url)
        .map_err(|e| HyperSyncProbeError::InvalidEndpoint(e.to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(5 * 60))
        .tcp_nodelay(true)
        .keep_alive_while_idle(true);
    let connector = QuilTlsConnector::new(client_config);
    let channel: Channel = endpoint.connect_with_connector(connector).await?;

    let mut client = HypergraphComparisonServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = tokio::sync::mpsc::channel::<HypergraphSyncQuery>(32);
    let req_stream = ReceiverStream::new(rx);
    let shard_key = global_prover_shard_key();
    let phase_i32 = phase as i32;

    // Get root branch
    tx.send(HypergraphSyncQuery {
        request: Some(hypergraph_sync_query::Request::GetBranch(
            HypergraphSyncGetBranchRequest {
                shard_key: shard_key.clone(),
                phase_set: phase_i32,
                path: Vec::new(),
                expected_root: expected_root.to_vec(),
            },
        )),
    })
    .await
    .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send root branch")))?;

    let mut response = client.perform_sync(Request::new(req_stream)).await?.into_inner();
    let first = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)??;
    let root_branch = match first.response {
        Some(hypergraph_sync_response::Response::Branch(b)) => b,
        _ => {
            warn!(%addr, "unexpected root response in incremental sync");
            return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
        }
    };

    let mut stats = BuildTreeStats::default();
    stats.server_root_commitment = root_branch.commitment.clone();
    stats.server_leaf_count = root_branch.leaf_count;

    // When expected_root is pinned, the server's offered root must
    // match it. Reject early — no point pulling leaves against a
    // snapshot we already know diverges from the verified frame's
    // prover_tree_commitment.
    if !expected_root.is_empty() && root_branch.commitment != expected_root {
        warn!(
            %addr,
            server_root = hex::encode(&root_branch.commitment),
            expected = hex::encode(expected_root),
            "incremental sync: server root does NOT match expected_root — rejecting"
        );
        return Err(HyperSyncProbeError::Rpc(tonic::Status::data_loss(format!(
            "HyperSync incremental: server root {} does not match expected {}",
            hex::encode(&root_branch.commitment),
            hex::encode(expected_root),
        ))));
    }

    // Step 3: Compare root commitments — if equal, tree is up to date
    if local_commitment == root_branch.commitment {
        info!(
            ?phase,
            leaf_count = root_branch.leaf_count,
            "incremental sync: commitments match, tree up to date"
        );
        stats.commitments_match = true;
        stats.local_root_commitment = local_commitment;
        drop(tx);
        return Ok(stats);
    }

    info!(
        ?phase,
        server_children = root_branch.children.len(),
        server_leaves = root_branch.leaf_count,
        local = hex::encode(&local_commitment[..local_commitment.len().min(16)]),
        server = hex::encode(&root_branch.commitment[..root_branch.commitment.len().min(16)]),
        "incremental sync: root commitment differs, comparing children"
    );

    // Step 4: Compare children commitments. For each differing child,
    // fetch its leaves and insert into our tree.
    let local_child_commitments: Vec<(i32, Vec<u8>)> = match &local_tree.root {
        Some(VectorCommitmentNode::Branch(branch)) => {
            branch.children.iter().enumerate().filter_map(|(i, c)| {
                c.as_ref().map(|node| {
                    let commit = match node.as_ref() {
                        VectorCommitmentNode::Branch(b) => b.commitment.clone(),
                        VectorCommitmentNode::Leaf(l) => l.commitment.clone(),
                    };
                    (i as i32, commit)
                })
            }).collect()
        }
        _ => Vec::new(),
    };
    let local_map: std::collections::HashMap<i32, Vec<u8>> =
        local_child_commitments.into_iter().collect();

    let mut changed_children = Vec::new();
    for server_child in &root_branch.children {
        let local_commit = local_map.get(&server_child.index);
        let matches = local_commit.map_or(false, |lc| *lc == server_child.commitment);
        if !matches {
            changed_children.push(server_child.index);
        }
    }

    // If the local tree has children at indices the server doesn't, the
    // incremental flow cannot reconcile — the stale subtrees would still
    // contribute to the recomputed root. Trigger a full sync.
    let server_indices: std::collections::HashSet<i32> =
        root_branch.children.iter().map(|c| c.index).collect();
    let has_local_only_children = local_map
        .keys()
        .any(|idx| !server_indices.contains(idx));
    if has_local_only_children {
        info!(
            ?phase,
            local_children = local_map.len(),
            server_children = server_indices.len(),
            "local tree has children server lacks, falling back to full sync"
        );
        drop(tx);
        return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
    }

    if changed_children.is_empty() {
        // All children match but root commitment differs — structural issue.
        // Fall back to full sync for safety.
        info!(?phase, "all children match but root differs, falling back to full sync");
        drop(tx);
        return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
    }

    info!(
        ?phase,
        changed = changed_children.len(),
        total_children = root_branch.children.len(),
        "fetching leaves from changed branches"
    );

    // Step 5: For each changed child, fetch its leaves
    let mut vertex_data: Vec<VertexDataEntry> = Vec::new();
    let pull_start = Instant::now();
    for &child_idx in &changed_children {
        let child_path = {
            let mut p = root_branch.full_path.clone();
            p.push(child_idx);
            p
        };
        let mut continuation: Vec<u8> = Vec::new();
        loop {
            tx.send(HypergraphSyncQuery {
                request: Some(hypergraph_sync_query::Request::GetLeaves(
                    HypergraphSyncGetLeavesRequest {
                        shard_key: shard_key.clone(),
                        phase_set: phase_i32,
                        path: child_path.clone(),
                        max_leaves: 1000,
                        continuation_token: continuation.clone(),
                        expected_root: expected_root.to_vec(),
                    },
                )),
            })
            .await
            .map_err(|_| HyperSyncProbeError::Rpc(tonic::Status::cancelled("send getleaves")))?;

            let resp = response.next().await.ok_or(HyperSyncProbeError::EmptyResponse)??;
            let leaves_resp = match resp.response {
                Some(hypergraph_sync_response::Response::Leaves(l)) => l,
                Some(hypergraph_sync_response::Response::Error(e)) => {
                    warn!(%addr, child_idx, code = e.code, msg = %e.message, "GetLeaves error for child");
                    break;
                }
                _ => break,
            };

            for leaf in leaves_resp.leaves.into_iter() {
                let size = if leaf.size.is_empty() {
                    BigInt::from(0)
                } else {
                    BigInt::from_signed_bytes_be(&leaf.size)
                };
                if let Err(e) = local_tree.insert(&leaf.key, &leaf.value, &leaf.hash_target, &size) {
                    warn!(error = %e, "tree insert failed during incremental sync");
                }
                stats.leaves_pulled += 1;
                if !leaf.underlying_data.is_empty() {
                    vertex_data.push(VertexDataEntry {
                        key: leaf.key,
                        underlying_data: leaf.underlying_data,
                    });
                }
            }

            if leaves_resp.continuation_token.is_empty() {
                break;
            }
            continuation = leaves_resp.continuation_token;
        }
    }
    drop(tx);

    info!(
        ?phase,
        changed_branches = changed_children.len(),
        leaves_pulled = stats.leaves_pulled,
        vertex_data = vertex_data.len(),
        pull_secs = pull_start.elapsed().as_secs(),
        "incremental leaf fetch complete"
    );

    // Step 6: Recompute root commitment
    let commit_start = Instant::now();
    let new_root = local_tree.commit(&prover);
    stats.local_commit_duration = commit_start.elapsed();
    stats.local_root_commitment = new_root.clone();
    stats.commitments_match = new_root == stats.server_root_commitment;

    if !stats.commitments_match {
        warn!(
            ?phase,
            local = hex::encode(&new_root[..new_root.len().min(16)]),
            server = hex::encode(
                &stats.server_root_commitment[..stats.server_root_commitment.len().min(16)]
            ),
            "incremental sync commitment still doesn't match after leaf update, falling back to full sync"
        );
        return ensure_prover_tree_fresh(addr, ed448_seed, phase, hg_store, expected_root).await;
    }

    // Final guard against caller's pinned expected_root. The earlier
    // early-reject covered the server's claimed root; this catches
    // any divergence introduced during the leaf pull.
    if !expected_root.is_empty() && new_root != expected_root {
        warn!(
            ?phase,
            local = hex::encode(&new_root[..new_root.len().min(16)]),
            expected = hex::encode(&expected_root[..expected_root.len().min(16)]),
            "incremental sync: post-leaf-pull root does NOT match expected_root — rejecting"
        );
        return Err(HyperSyncProbeError::Rpc(tonic::Status::data_loss(format!(
            "HyperSync incremental: post-pull root {} does not match expected {}",
            hex::encode(&new_root),
            hex::encode(expected_root),
        ))));
    }

    // Step 7: Persist updated tree
    let serialized = match serialize_tree(local_tree.root.as_ref()) {
        Ok(b) => b,
        Err(e) => {
            warn!(?phase, error = %e, "serialize_tree failed after incremental sync");
            return Ok(stats);
        }
    };
    let blob_size = serialized.len();
    match hg_store.save_tree_blob(set_str, phase_str, &shard, &serialized) {
        Ok(()) => info!(?phase, blob_size, "prover tree updated incrementally"),
        Err(e) => warn!(?phase, error = %e, "save_tree_blob failed"),
    }

    let mut persisted_vertices = 0usize;
    for entry in &vertex_data {
        if hg_store
            .save_vertex_underlying(set_str, phase_str, &shard, &entry.key, &entry.underlying_data)
            .is_ok()
        {
            persisted_vertices += 1;
        }
    }
    info!(?phase, persisted_vertices, "per-vertex data updated incrementally");
    Ok(stats)
}
