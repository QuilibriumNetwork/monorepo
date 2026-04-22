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
use quil_types::store::ShardKey;

const DEFAULT_LEAF_PAGE_SIZE: usize = 1000;

/// HyperSync server implementation.
pub struct HyperSyncServer {
    hg_store: Arc<RocksHypergraphStore>,
}

impl HyperSyncServer {
    pub fn new(hg_store: Arc<RocksHypergraphStore>) -> Self {
        Self { hg_store }
    }
}

/// Load the tree for the given phase from the hypergraph store and
/// commit it to compute fresh commitments. Returns `None` if the
/// tree doesn't exist (empty node).
fn load_tree_for_phase(
    hg_store: &RocksHypergraphStore,
    phase: HypergraphPhaseSet,
) -> Option<VectorCommitmentTree> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let (set_str, phase_str) = match phase {
        HypergraphPhaseSet::VertexAdds => ("vertex", "adds"),
        HypergraphPhaseSet::VertexRemoves => ("vertex", "removes"),
        HypergraphPhaseSet::HyperedgeAdds => ("hyperedge", "adds"),
        HypergraphPhaseSet::HyperedgeRemoves => ("hyperedge", "removes"),
    };
    let blob = hg_store.load_tree_blob(set_str, phase_str, &shard).ok().flatten()?;
    let root = deserialize_tree(&blob).ok().flatten()?;
    let mut t = VectorCommitmentTree::new();
    t.root = Some(root);
    let prover = quil_crypto::KzgInclusionProver;
    t.commit(&prover);
    Some(t)
}

/// Navigate from the tree root to the node at `path` (sequence of
/// 0-63 child indices). Returns:
/// - `NavResult::Found(node)`: an exact match — `path` terminates at `node`.
/// - `NavResult::PrefixMatch(node)`: a branch whose `full_path` extends
///   the requested path (the common ancestor). Caller returns this
///   branch with its compressed prefix, matching Go's behavior at
///   `hypergraph/sync_client_driven.go:getBranch`.
/// - `NavResult::Missing`: no node covers `path`.
enum NavResult<'a> {
    Found(&'a VectorCommitmentNode),
    PrefixMatch {
        node: &'a VectorCommitmentNode,
        full_path: Vec<i32>,
    },
    Missing,
}

/// Walk from `node` along `remaining`, accumulating the traversed
/// path segment in `full_path`.
fn navigate<'a>(
    node: &'a VectorCommitmentNode,
    remaining: &[i32],
    full_path: Vec<i32>,
) -> NavResult<'a> {
    if remaining.is_empty() {
        return NavResult::Found(node);
    }
    match node {
        // A leaf reached before consuming the full path — the requested
        // path doesn't exist in this tree.
        VectorCommitmentNode::Leaf(_) => NavResult::Missing,
        VectorCommitmentNode::Branch(branch) => {
            // Consume as many of `remaining` as match this branch's
            // compressed prefix.
            let prefix = &branch.prefix;
            let shared = prefix.len().min(remaining.len());
            // The branch's prefix is the edge from the parent — but
            // in our store the prefix contains the nibbles *below*
            // the parent. Two cases:
            //   1. remaining starts with prefix → descend via the
            //      next nibble after prefix.
            //   2. prefix extends beyond remaining → the requested
            //      path lands inside this branch's compressed edge;
            //      we return the branch itself with its full_path
            //      so the client learns where it is.
            if remaining.len() < prefix.len() {
                // Check that remaining is a proper prefix of the branch's prefix.
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

/// Build the wire `HypergraphSyncBranchResponse` for a branch node
/// located at `full_path`.
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

/// Build a "root" response for a tree whose root matches an empty path.
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

/// Flatten all leaves under `node` into a list. Order is a stable
/// depth-first walk — child index low → high.
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
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<HypergraphSyncResponse, Status>>(16);

        tokio::spawn(async move {
            // Cache one tree per phase so the client can stream
            // multi-phase queries on the same RPC without reloading.
            let mut trees: HashMap<i32, VectorCommitmentTree> = HashMap::new();

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
                        let phase = HypergraphPhaseSet::try_from(req.phase_set)
                            .unwrap_or(HypergraphPhaseSet::VertexAdds);
                        if !trees.contains_key(&req.phase_set) {
                            if let Some(t) = load_tree_for_phase(&hg_store, phase) {
                                trees.insert(req.phase_set, t);
                            }
                        }
                        match trees.get(&req.phase_set) {
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
                        let phase = HypergraphPhaseSet::try_from(req.phase_set)
                            .unwrap_or(HypergraphPhaseSet::VertexAdds);
                        if !trees.contains_key(&req.phase_set) {
                            if let Some(t) = load_tree_for_phase(&hg_store, phase) {
                                trees.insert(req.phase_set, t);
                            }
                        }
                        match trees.get(&req.phase_set) {
                            Some(tree) => match tree.root.as_ref() {
                                Some(root) => {
                                    // Navigate to the requested subtree root.
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

                                            let start = if req.continuation_token.is_empty() {
                                                0usize
                                            } else {
                                                String::from_utf8_lossy(&req.continuation_token)
                                                    .trim()
                                                    .parse::<usize>()
                                                    .unwrap_or(0)
                                            };
                                            let max = if req.max_leaves == 0 {
                                                DEFAULT_LEAF_PAGE_SIZE
                                            } else {
                                                req.max_leaves as usize
                                            };
                                            let end = (start + max).min(leaves.len());
                                            let page = leaves[start..end].to_vec();
                                            let cont = if end < leaves.len() {
                                                end.to_string().into_bytes()
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
