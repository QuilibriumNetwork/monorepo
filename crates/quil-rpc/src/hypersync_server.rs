//! HyperSync gRPC server — serves tree branch commitments and leaves
//! to other nodes for synchronization.
//!
//! Implements the `HypergraphComparisonService` gRPC trait.
//! Mirrors Go's server-side sync at `hypergraph/sync_client_driven.go`.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

use quil_store::RocksHypergraphStore;
use quil_tries::{deserialize_tree, BranchNode, VectorCommitmentNode, VectorCommitmentTree};
use quil_types::proto::application::{
    hypergraph_comparison_service_server::HypergraphComparisonService,
    hypergraph_sync_query, hypergraph_sync_response,
    GetChildrenForPathRequest, GetChildrenForPathResponse,
    HypergraphComparison, HypergraphPhaseSet,
    HypergraphSyncBranchResponse, HypergraphSyncChildInfo,
    HypergraphSyncError, HypergraphSyncLeavesResponse, HypergraphSyncQuery,
    HypergraphSyncResponse, LeafData,
};
use quil_types::store::{ShardKey, SnapshotReadable};

const DEFAULT_LEAF_PAGE_SIZE: usize = 1000;

/// HyperSync server implementation.
pub struct HyperSyncServer {
    hg_store: Arc<RocksHypergraphStore>,
    /// When set, sync requests with a non-empty `expected_root` are
    /// validated against the snapshot generation registry.
    crdt: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
}

impl HyperSyncServer {
    pub fn new(hg_store: Arc<RocksHypergraphStore>) -> Self {
        Self { hg_store, crdt: None }
    }

    pub fn with_crdt(mut self, crdt: Arc<quil_hypergraph::HypergraphCrdt>) -> Self {
        self.crdt = Some(crdt);
        self
    }
}

fn phase_strings(phase: HypergraphPhaseSet) -> (&'static str, &'static str) {
    match phase {
        HypergraphPhaseSet::VertexAdds => ("vertex", "adds"),
        HypergraphPhaseSet::VertexRemoves => ("vertex", "removes"),
        HypergraphPhaseSet::HyperedgeAdds => ("hyperedge", "adds"),
        HypergraphPhaseSet::HyperedgeRemoves => ("hyperedge", "removes"),
    }
}

/// Deserialize the captured-at-snapshot-time tree blob, if present.
/// `Ok(Some)` = served from the snapshot (point-in-time consistent);
/// `Ok(None)` = no blob in snapshot (caller may try the live store).
fn load_tree_from_snapshot(
    snap: &std::sync::Arc<dyn quil_types::store::SnapshotReadable>,
    phase: HypergraphPhaseSet,
    shard: &ShardKey,
) -> Result<Option<VectorCommitmentTree>, quil_types::error::QuilError> {
    let (set_str, phase_str) = phase_strings(phase);
    let blob = match snap.load_tree_blob(set_str, phase_str, shard)? {
        Some(b) if !b.is_empty() => b,
        _ => return Ok(None),
    };
    let root = quil_tries::deserialize_tree(&blob)?;
    let mut t = VectorCommitmentTree::new();
    t.root = root;
    Ok(Some(t))
}

/// Bounded-eager load of a phase tree's top two levels (~1 + 64 +
/// 64×64 reads). Returns `None` if no root is stored.
fn load_tree_for_phase(
    hg_store: &std::sync::Arc<quil_store::RocksHypergraphStore>,
    phase: HypergraphPhaseSet,
    shard: ShardKey,
) -> Option<VectorCommitmentTree> {
    let (set_str, phase_str) = phase_strings(phase);
    let lazy = quil_tries::LazyVectorCommitmentTree::new(
        std::sync::Arc::clone(hg_store)
            as std::sync::Arc<dyn quil_types::store::HypergraphStore>,
        set_str.to_string(),
        phase_str.to_string(),
        shard.clone(),
        Vec::new(),
    );
    let root_result = lazy.load_root_and_two_levels();
    let root = match root_result {
        Ok(Some(node)) => node,
        Ok(None) => {
            tracing::info!(
                set = %set_str, phase = %phase_str,
                "sync server: load_tree_for_phase returned None (no root in store)",
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                set = %set_str, phase = %phase_str, error = %e,
                "sync server: load_tree_for_phase errored",
            );
            return None;
        }
    };
    let (root_commit_hex, child_count_loaded, leaf_count_loaded) = match &root {
        quil_tries::VectorCommitmentNode::Branch(b) => (
            hex::encode(&b.commitment),
            b.children.iter().filter(|c| c.is_some()).count(),
            b.leaf_count as u64,
        ),
        quil_tries::VectorCommitmentNode::Leaf(l) => (
            hex::encode(&l.commitment),
            0usize,
            1u64,
        ),
    };
    let mut t = VectorCommitmentTree::new();
    t.root = Some(root);

    // Diagnostic: detect lazy-load truncation or stale-cache divergence
    // by comparing loaded-leaf count + recomputed commit to stored values.
    let collected = if let Some(root_ref) = t.root.as_ref() {
        collect_leaves(root_ref).len() as u64
    } else { 0 };
    let leaves_match = collected == leaf_count_loaded;

    let mut t_for_recompute = VectorCommitmentTree::new();
    t_for_recompute.root = t.root.clone();
    // Solo leaf encoding strips `value` to avoid double-storing the vertex
    // blob — hydrate from the per-vertex keyspace so recompute sees the
    // same input that `tree.commit` originally saw.
    if let Some(root) = t_for_recompute.root.as_mut() {
        hydrate_leaf_values(root, hg_store.as_ref(), set_str, phase_str, &shard);
    }
    let prover = quil_crypto::KzgInclusionProver;
    let recomputed = t_for_recompute.commit(&prover);
    let recomputed_hex = hex::encode(&recomputed);
    let stored_commit = if let Some(quil_tries::VectorCommitmentNode::Branch(b)) = t.root.as_ref() {
        b.commitment.clone()
    } else { Vec::new() };
    let commits_match = recomputed == stored_commit;

    tracing::info!(
        set = %set_str, phase = %phase_str,
        root_commit = %root_commit_hex,
        recomputed_commit = %recomputed_hex,
        commits_match,
        children_loaded = child_count_loaded,
        leaf_count_meta = leaf_count_loaded,
        leaves_collected = collected,
        leaves_match,
        "sync server: load_tree_for_phase loaded root (diagnostic)",
    );
    if !commits_match || !leaves_match {
        tracing::warn!(
            set = %set_str, phase = %phase_str,
            commits_match,
            leaves_match,
            stored_commit_prefix = %hex::encode(&stored_commit[..stored_commit.len().min(16)]),
            recomputed_prefix = %hex::encode(&recomputed[..recomputed.len().min(16)]),
            "sync server: tree state divergence — clients will see commitment mismatch",
        );
    }
    Some(t)
}

/// Pagination continuation token — ASCII hex of a 4-byte big-endian
/// int32. Empty token means "start from 0".
fn parse_continuation_token(token: &[u8]) -> Option<usize> {
    if token.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(token).ok()?;
    if s.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 4];
    for i in 0..4 {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        buf[i] = (hi << 4) | lo;
    }
    Some(u32::from_be_bytes(buf) as usize)
}

fn make_continuation_token(idx: usize) -> Vec<u8> {
    let be = (idx as u32).to_be_bytes();
    let mut out = Vec::with_capacity(8);
    for b in be {
        out.push(hex_char(b >> 4));
        out.push(hex_char(b & 0x0f));
    }
    out
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_char(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'?',
    }
}

/// Canonical global-prover shard key. Fallback when a request omits one.
fn global_prover_shard() -> ShardKey {
    ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    }
}

/// Decode the wire shard key (Go's `slices.Concat(L1[:], L2[:])`):
/// - empty → global prover shard
/// - 35 bytes → canonical `L1=bytes[0..3], L2=bytes[3..35]`
/// - other → take up to 32 bytes as L2 and derive L1 from the address
fn shard_key_from_bytes(shard_bytes: &[u8]) -> ShardKey {
    if shard_bytes.is_empty() {
        return global_prover_shard();
    }
    if shard_bytes.len() == 35 {
        let mut l1 = [0u8; 3];
        l1.copy_from_slice(&shard_bytes[..3]);
        let mut l2 = [0u8; 32];
        l2.copy_from_slice(&shard_bytes[3..35]);
        return ShardKey { l1, l2 };
    }
    let mut l2 = [0u8; 32];
    let n = shard_bytes.len().min(32);
    l2[..n].copy_from_slice(&shard_bytes[..n]);
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&l2, 256, 3);
    ShardKey { l1, l2 }
}

/// Navigation outcome when walking from the root along a 6-bit path.
enum NavResult<'a> {
    Found(&'a VectorCommitmentNode),
    PrefixMatch {
        node: &'a VectorCommitmentNode,
        full_path: Vec<i32>,
    },
    Missing,
}

fn navigate<'a>(
    node: &'a VectorCommitmentNode,
    remaining: &[i32],
    full_path: Vec<i32>,
) -> NavResult<'a> {
    if remaining.is_empty() {
        return NavResult::Found(node);
    }
    match node {
        VectorCommitmentNode::Leaf(_) => NavResult::Missing,
        VectorCommitmentNode::Branch(branch) => {
            let prefix = &branch.prefix;
            let shared = prefix.len().min(remaining.len());
            if remaining.len() < prefix.len() {
                if &prefix[..remaining.len()] == remaining {
                    let mut fp = full_path;
                    fp.extend_from_slice(prefix);
                    return NavResult::PrefixMatch {
                        node,
                        full_path: fp,
                    };
                }
                return NavResult::Missing;
            }
            // remaining.len() >= prefix.len(); they must match for the
            // path to pass through this branch.
            if &remaining[..shared] != prefix.as_slice() {
                return NavResult::Missing;
            }
            let rest = &remaining[prefix.len()..];
            if rest.is_empty() {
                // Path terminates exactly at this branch.
                let mut fp = full_path;
                fp.extend_from_slice(prefix);
                return NavResult::Found(node);
            }
            let next_idx = rest[0];
            if !(0..64).contains(&next_idx) {
                return NavResult::Missing;
            }
            let child = match &branch.children[next_idx as usize] {
                Some(c) => c.as_ref(),
                None => return NavResult::Missing,
            };
            let mut fp = full_path;
            fp.extend_from_slice(prefix);
            fp.push(next_idx);
            navigate(child, &rest[1..], fp)
        }
    }
}

fn branch_to_response(
    node: &VectorCommitmentNode,
    full_path: Vec<i32>,
) -> HypergraphSyncBranchResponse {
    match node {
        VectorCommitmentNode::Leaf(leaf) => HypergraphSyncBranchResponse {
            full_path,
            commitment: leaf.commitment.clone(),
            children: Vec::new(),
            is_leaf: true,
            leaf_count: 1,
        },
        VectorCommitmentNode::Branch(branch) => {
            let children: Vec<HypergraphSyncChildInfo> = branch
                .children
                .iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    c.as_ref().map(|node| {
                        let commit = match node.as_ref() {
                            VectorCommitmentNode::Branch(b) => b.commitment.clone(),
                            VectorCommitmentNode::Leaf(l) => l.commitment.clone(),
                        };
                        HypergraphSyncChildInfo {
                            index: i as i32,
                            commitment: commit,
                        }
                    })
                })
                .collect();
            HypergraphSyncBranchResponse {
                full_path,
                commitment: branch.commitment.clone(),
                children,
                is_leaf: false,
                leaf_count: branch.leaf_count as u64,
            }
        }
    }
}

fn root_response(tree: &VectorCommitmentTree) -> HypergraphSyncBranchResponse {
    match &tree.root {
        None => HypergraphSyncBranchResponse {
            full_path: Vec::new(),
            commitment: Vec::new(),
            children: Vec::new(),
            is_leaf: false,
            leaf_count: 0,
        },
        Some(node) => {
            let full_path = match node {
                VectorCommitmentNode::Branch(b) => b.prefix.clone(),
                VectorCommitmentNode::Leaf(_) => Vec::new(),
            };
            branch_to_response(node, full_path)
        }
    }
}

/// Rehydrate each leaf's `value` from the per-vertex keyspace; solo
/// encoding strips it to avoid double-storing the vertex blob.
fn hydrate_leaf_values(
    node: &mut VectorCommitmentNode,
    hg_store: &quil_store::RocksHypergraphStore,
    set_str: &str,
    phase_str: &str,
    shard: &ShardKey,
) {
    match node {
        VectorCommitmentNode::Leaf(leaf) => {
            if !leaf.value.is_empty() {
                return;
            }
            if let Ok(Some(v)) =
                hg_store.load_vertex_underlying(set_str, phase_str, shard, &leaf.key)
            {
                leaf.value = v;
            }
        }
        VectorCommitmentNode::Branch(branch) => {
            for child in branch.children.iter_mut() {
                if let Some(c) = child.as_mut() {
                    hydrate_leaf_values(c, hg_store, set_str, phase_str, shard);
                }
            }
        }
    }
}

fn collect_leaves(node: &VectorCommitmentNode) -> Vec<LeafData> {
    match node {
        VectorCommitmentNode::Leaf(leaf) => vec![LeafData {
            key: leaf.key.clone(),
            value: leaf.value.clone(),
            hash_target: leaf.hash_target.clone(),
            size: leaf.size.to_signed_bytes_be(),
            underlying_data: Vec::new(),
        }],
        VectorCommitmentNode::Branch(branch) => {
            let mut leaves = Vec::new();
            for child in &branch.children {
                if let Some(c) = child {
                    leaves.extend(collect_leaves(c));
                }
            }
            leaves
        }
    }
}

fn err_response(msg: impl Into<String>, path: Vec<i32>) -> HypergraphSyncResponse {
    HypergraphSyncResponse {
        response: Some(hypergraph_sync_response::Response::Error(
            HypergraphSyncError {
                code: 1,
                message: msg.into(),
                path,
            },
        )),
    }
}

type PerformSyncStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<HypergraphSyncResponse, Status>> + Send>>;
type HyperStreamStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<HypergraphComparison, Status>> + Send>>;

#[tonic::async_trait]
impl HypergraphComparisonService for HyperSyncServer {
    type PerformSyncStream = PerformSyncStream;
    type HyperStreamStream = HyperStreamStream;

    async fn perform_sync(
        &self,
        request: Request<Streaming<HypergraphSyncQuery>>,
    ) -> Result<Response<Self::PerformSyncStream>, Status> {
        let hg_store = self.hg_store.clone();
        let crdt = self.crdt.clone();
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<HypergraphSyncResponse, Status>>(16);

        // TODO https://github.com/QuilibriumNetwork/monorepo/issues/559
        tokio::spawn(async move {
            // Cache tree per (phase, shard, snapshot_root) so multi-phase
            // streams don't reload, shards never cross-serve, and a
            // pinned `expected_root` gets a distinct tree from the
            // live-store fallback.
            let mut trees: HashMap<(i32, ShardKey, Vec<u8>), VectorCommitmentTree> = HashMap::new();

            // When the client pinned `expected_root`, require a matching
            // snapshot generation. The returned handle's `db_snapshot`
            // gives point-in-time reads under concurrent writes; without
            // a CRDT bound we can't validate, so accept (legacy).
            let acquire_snapshot_for = |expected_root: &[u8]|
                -> Result<Option<quil_hypergraph::GenerationHandle>, HypergraphSyncResponse>
            {
                if expected_root.is_empty() {
                    return Ok(None);
                }
                if let Some(c) = crdt.as_ref() {
                    match c.acquire_snapshot(expected_root) {
                        Some(handle) => Ok(Some(handle)),
                        None => Err(err_response(
                            format!(
                                "expected_root {} not in snapshot registry",
                                hex::encode(expected_root),
                            ),
                            Vec::new(),
                        )),
                    }
                } else {
                    Ok(None)
                }
            };

            // Load the tree for this request, preferring the
            // generation-bound snapshot when one is available so reads
            // are point-in-time consistent under concurrent writes.
            // Falls back to the live store on snapshot miss or decode
            // failure.
            let load_tree_for_request = |
                handle: &Option<quil_hypergraph::GenerationHandle>,
                phase: HypergraphPhaseSet,
                shard: &ShardKey,
            | -> Option<VectorCommitmentTree> {
                if let Some(h) = handle {
                    if let Some(snap) = h.db_snapshot.as_ref() {
                        match load_tree_from_snapshot(snap, phase, shard) {
                            Ok(Some(t)) => return Some(t),
                            Ok(None) => {}
                            Err(e) => warn!(
                                error = %e,
                                "snapshot tree decode failed, falling back to live store",
                            ),
                        }
                    }
                }
                load_tree_for_phase(&hg_store, phase, shard.clone())
            };

            while let Some(query) = inbound.next().await {
                let query = match query {
                    Ok(q) => q,
                    Err(e) => {
                        warn!(error = %e, "perform_sync: inbound error");
                        break;
                    }
                };

                let response = match query.request {
                    Some(hypergraph_sync_query::Request::GetBranch(req)) => {
                        let handle = match acquire_snapshot_for(&req.expected_root) {
                            Ok(h) => h,
                            Err(err) => {
                                if tx.send(Ok(err)).await.is_err() { break; }
                                continue;
                            }
                        };
                        let phase = HypergraphPhaseSet::try_from(req.phase_set)
                            .unwrap_or(HypergraphPhaseSet::VertexAdds);
                        let shard = shard_key_from_bytes(&req.shard_key);
                        let snapshot_id = handle
                            .as_ref()
                            .map(|h| h.root.clone())
                            .unwrap_or_default();
                        let cache_key: (i32, ShardKey, Vec<u8>) =
                            (req.phase_set, shard.clone(), snapshot_id);
                        if !trees.contains_key(&cache_key) {
                            if let Some(t) = load_tree_for_request(&handle, phase, &shard) {
                                trees.insert(cache_key.clone(), t);
                            }
                        }
                        match trees.get(&cache_key) {
                            Some(tree) => {
                                if req.path.is_empty() {
                                    HypergraphSyncResponse {
                                        response: Some(
                                            hypergraph_sync_response::Response::Branch(
                                                root_response(tree),
                                            ),
                                        ),
                                    }
                                } else if let Some(root) = tree.root.as_ref() {
                                    match navigate(root, &req.path, Vec::new()) {
                                        NavResult::Found(node) => {
                                            HypergraphSyncResponse {
                                                response: Some(
                                                    hypergraph_sync_response::Response::Branch(
                                                        branch_to_response(node, req.path),
                                                    ),
                                                ),
                                            }
                                        }
                                        NavResult::PrefixMatch { node, full_path } => {
                                            HypergraphSyncResponse {
                                                response: Some(
                                                    hypergraph_sync_response::Response::Branch(
                                                        branch_to_response(node, full_path),
                                                    ),
                                                ),
                                            }
                                        }
                                        NavResult::Missing => {
                                            err_response("path not found", req.path)
                                        }
                                    }
                                } else {
                                    err_response("tree is empty", req.path)
                                }
                            }
                            None => err_response("no tree data available", req.path),
                        }
                    }
                    Some(hypergraph_sync_query::Request::GetLeaves(req)) => {
                        let handle = match acquire_snapshot_for(&req.expected_root) {
                            Ok(h) => h,
                            Err(err) => {
                                if tx.send(Ok(err)).await.is_err() { break; }
                                continue;
                            }
                        };
                        let phase = HypergraphPhaseSet::try_from(req.phase_set)
                            .unwrap_or(HypergraphPhaseSet::VertexAdds);
                        let shard = shard_key_from_bytes(&req.shard_key);
                        let snapshot_id = handle
                            .as_ref()
                            .map(|h| h.root.clone())
                            .unwrap_or_default();
                        let cache_key: (i32, ShardKey, Vec<u8>) =
                            (req.phase_set, shard.clone(), snapshot_id);
                        if !trees.contains_key(&cache_key) {
                            if let Some(t) = load_tree_for_request(&handle, phase, &shard) {
                                trees.insert(cache_key.clone(), t);
                            }
                        }
                        match trees.get(&cache_key) {
                            Some(tree) => match tree.root.as_ref() {
                                Some(root) => {
                                    let subtree_node = if req.path.is_empty() {
                                        Some(root as &VectorCommitmentNode)
                                    } else {
                                        match navigate(root, &req.path, Vec::new()) {
                                            NavResult::Found(n) => Some(n),
                                            NavResult::PrefixMatch { node, .. } => Some(node),
                                            NavResult::Missing => None,
                                        }
                                    };
                                    match subtree_node {
                                        Some(node) => {
                                            let leaves = collect_leaves(node);

                                            let start = parse_continuation_token(
                                                &req.continuation_token,
                                            )
                                            .unwrap_or(0);
                                            let max = if req.max_leaves == 0 {
                                                DEFAULT_LEAF_PAGE_SIZE
                                            } else {
                                                req.max_leaves as usize
                                            };
                                            let end = (start + max).min(leaves.len());
                                            let mut page = leaves[start..end].to_vec();
                                            // Hydrate stripped values from per-vertex keyspace
                                            // so the client can recompute leaf commitments.
                                            let (set_str, phase_str) = match phase {
                                                HypergraphPhaseSet::VertexAdds => ("vertex", "adds"),
                                                HypergraphPhaseSet::VertexRemoves => ("vertex", "removes"),
                                                HypergraphPhaseSet::HyperedgeAdds => ("hyperedge", "adds"),
                                                HypergraphPhaseSet::HyperedgeRemoves => ("hyperedge", "removes"),
                                            };
                                            for leaf in page.iter_mut() {
                                                if !leaf.value.is_empty() {
                                                    continue;
                                                }
                                                if let Ok(Some(v)) = hg_store
                                                    .load_vertex_underlying(
                                                        set_str,
                                                        phase_str,
                                                        &shard,
                                                        &leaf.key,
                                                    )
                                                {
                                                    leaf.value = v;
                                                }
                                            }
                                            let cont = if end < leaves.len() {
                                                make_continuation_token(end)
                                            } else {
                                                Vec::new()
                                            };

                                            HypergraphSyncResponse {
                                                response: Some(
                                                    hypergraph_sync_response::Response::Leaves(
                                                        HypergraphSyncLeavesResponse {
                                                            path: req.path,
                                                            leaves: page,
                                                            continuation_token: cont,
                                                            total_leaves: leaves.len() as u64,
                                                        },
                                                    ),
                                                ),
                                            }
                                        }
                                        None => err_response("path not found", req.path),
                                    }
                                }
                                None => err_response("tree is empty", req.path),
                            },
                            None => err_response("no tree data available", req.path),
                        }
                    }
                    None => continue,
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }

            debug!("perform_sync stream closed");
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::PerformSyncStream))
    }

    async fn hyper_stream(
        &self,
        _request: Request<Streaming<HypergraphComparison>>,
    ) -> Result<Response<Self::HyperStreamStream>, Status> {
        // Legacy sync protocol — not used by current clients
        Err(Status::unimplemented("hyper_stream not supported"))
    }

    async fn get_children_for_path(
        &self,
        _request: Request<GetChildrenForPathRequest>,
    ) -> Result<Response<GetChildrenForPathResponse>, Status> {
        Ok(Response::new(GetChildrenForPathResponse {
            path_segments: Vec::new(),
        }))
    }
}

// Keep the unused import out of warnings when BranchNode isn't referenced.
#[allow(dead_code)]
fn _silence_unused(_: BranchNode) {}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_tries::LeafNode;

    fn make_leaf(key: &[u8]) -> VectorCommitmentNode {
        VectorCommitmentNode::Leaf(LeafNode {
            key: key.to_vec(),
            value: vec![0x11],
            hash_target: vec![0x22; 32],
            size: num_bigint::BigInt::from(1u32),
            commitment: vec![0xAA; 32],
        })
    }

    fn make_branch(prefix: Vec<i32>, children: Vec<(usize, VectorCommitmentNode)>) -> VectorCommitmentNode {
        let mut arr: [Option<Box<VectorCommitmentNode>>; 64] =
            std::array::from_fn(|_| None);
        let mut leaf_count: usize = 0;
        for (idx, child) in children {
            leaf_count += match &child {
                VectorCommitmentNode::Leaf(_) => 1,
                VectorCommitmentNode::Branch(b) => b.leaf_count,
            };
            arr[idx] = Some(Box::new(child));
        }
        VectorCommitmentNode::Branch(BranchNode {
            prefix,
            commitment: vec![0xBB; 32],
            children: arr,
            leaf_count,
            size: num_bigint::BigInt::from(leaf_count as u64),
            longest_branch: 1,
            full_prefix: Vec::new(),
            fully_loaded: true,
        })
    }

    #[test]
    fn navigate_empty_path_returns_root() {
        let root = make_leaf(b"x");
        match navigate(&root, &[], Vec::new()) {
            NavResult::Found(_) => {}
            _ => panic!("expected Found for empty path"),
        }
    }

    #[test]
    fn navigate_leaf_with_nonempty_path_is_missing() {
        let root = make_leaf(b"x");
        match navigate(&root, &[5], Vec::new()) {
            NavResult::Missing => {}
            _ => panic!("expected Missing — leaf can't have children"),
        }
    }

    #[test]
    fn navigate_through_prefix_descends_into_child() {
        // Branch at prefix [] with one child at index 3, which is a
        // branch at prefix [7] with leaf child at index 5.
        let deep = make_branch(vec![7], vec![(5, make_leaf(b"deep"))]);
        let root = make_branch(vec![], vec![(3, deep)]);
        match navigate(&root, &[3, 7, 5], Vec::new()) {
            NavResult::Found(VectorCommitmentNode::Leaf(_)) => {}
            _ => panic!("expected Found leaf at [3,7,5]"),
        }
    }

    #[test]
    fn navigate_returns_prefix_match_when_path_lands_in_compressed_edge() {
        // Branch at prefix [] with child at idx 3 pointing to a branch
        // whose prefix is [7,7,7] (compressed). Querying [3,7] should
        // return the [3,7,7,7] branch with its full_path.
        let deep = make_branch(vec![7, 7, 7], vec![(0, make_leaf(b"x"))]);
        let root = make_branch(vec![], vec![(3, deep)]);
        match navigate(&root, &[3, 7], Vec::new()) {
            NavResult::PrefixMatch { full_path, .. } => {
                assert_eq!(full_path, vec![3, 7, 7, 7]);
            }
            _ => panic!("expected PrefixMatch"),
        }
    }

    #[test]
    fn collect_leaves_walks_subtree() {
        let root = make_branch(
            vec![],
            vec![(0, make_leaf(b"a")), (1, make_leaf(b"b")), (2, make_leaf(b"c"))],
        );
        let leaves = collect_leaves(&root);
        assert_eq!(leaves.len(), 3);
    }

    #[test]
    fn branch_to_response_reports_children() {
        let node = make_branch(
            vec![1, 2],
            vec![(5, make_leaf(b"a")), (7, make_leaf(b"b"))],
        );
        let resp = branch_to_response(&node, vec![1, 2]);
        assert!(!resp.is_leaf);
        assert_eq!(resp.children.len(), 2);
        assert_eq!(resp.leaf_count, 2);
        assert_eq!(resp.full_path, vec![1, 2]);
    }
}
