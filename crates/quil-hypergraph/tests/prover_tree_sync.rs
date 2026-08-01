//! CRDT-level prover-tree sync round-trip: a stale/empty "follower" CRDT syncs
//! the global prover shard from a "leader" CRDT and its prover root converges to
//! the leader's. This is the invariant behind the archive "prover root MISMATCH"
//! reports — a follower that syncs correctly MUST reach the source root — and it
//! had no end-to-end coverage (only the forest primitive `diff_leaves` was
//! tested, not `sync_shard_phase_from` + `compute_shard_root` together).
//!
//! The sync runs fully in-process: an [`InProcTreeReader`] calls the source
//! CRDT's `serve_forest_node` / `serve_forest_value` (the same server methods
//! the gRPC `RemoteTreeReader` wraps), so no network is involved.

use std::sync::Arc;

use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{KeyHash, OwnedValue, Version};

use quil_hypergraph::testing::{MemStore, StubProver};
use quil_hypergraph::{HypergraphCrdt, Location};

/// The global intrinsic (prover) shard. `compute_shard_root` uses only `l2`;
/// the forest tree-id / sync `shard_id` for this single-shard app is `l2`.
const GLOBAL_APP: [u8; 32] = [0xffu8; 32];

fn global_prover_shard() -> quil_types::store::ShardKey {
    quil_types::store::ShardKey { l1: [0u8; 3], l2: GLOBAL_APP }
}

fn fresh_crdt() -> Arc<HypergraphCrdt> {
    Arc::new(HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(StubProver)))
}

/// A [`TreeReader`] over a source CRDT's forest, calling its `serve_forest_*`
/// methods directly (no gRPC). Mirrors `quil_rpc::RemoteTreeReader`.
struct InProcTreeReader {
    source: Arc<HypergraphCrdt>,
    shard_id: Vec<u8>,
    phase: usize,
}

impl TreeReader for InProcTreeReader {
    fn get_node_option(&self, node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
        let key_bytes = borsh::to_vec(node_key)?;
        match self.source.serve_forest_node(&self.shard_id, self.phase, &key_bytes) {
            Some(b) => Ok(Some(borsh::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> anyhow::Result<Option<OwnedValue>> {
        Ok(self
            .source
            .serve_forest_value(&self.shard_id, self.phase, max_version, key_hash.0))
    }

    fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
        // Merkle-diff sync never calls this (it addresses nodes explicitly).
        Ok(None)
    }
}

/// Seed `n` distinct prover-like vertices under the global app into `crdt` and
/// commit at `frame`.
fn seed_and_commit(crdt: &HypergraphCrdt, n: u8, frame: u64) {
    for i in 0..n {
        let mut data = [0u8; 32];
        data[0] = i;
        data[31] = i.wrapping_mul(11);
        crdt.add_vertex(
            &Location { app_address: GLOBAL_APP, data_address: data },
            &vec![i; 48 + i as usize],
        )
        .unwrap();
    }
    crdt.commit(frame).unwrap();
}

/// Sync phase 0 (vertex-adds) of the global shard from `source` into `target`
/// and return the target's new prover root. Mirrors `forest_sync::sync_one_phase`
/// minus the blob fetch (roots are what the mismatch check compares).
fn sync_prover_phase0(target: &HypergraphCrdt, source: Arc<HypergraphCrdt>) -> Vec<u8> {
    let shard_id = GLOBAL_APP.to_vec();
    let (source_version, _root) = source
        .serve_forest_head(&shard_id, 0)
        .expect("source has a committed vertex-adds head for the prover shard");
    let reader = InProcTreeReader { source, shard_id: shard_id.clone(), phase: 0 };
    let (root, _ver, _changed) = target
        .sync_shard_phase_from(&reader, source_version, &shard_id, 0)
        .expect("sync_shard_phase_from");
    let _ = root;
    target.compute_shard_root("vertex", "adds", &global_prover_shard())
}

/// A follower that starts EMPTY converges to the leader's prover root.
#[test]
fn empty_follower_converges_to_leader_prover_root() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 10, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_eq!(leader_root.len(), 32);
    assert!(leader_root.iter().any(|&b| b != 0));

    let follower = fresh_crdt();
    // Sanity: the follower's prover root differs before sync.
    let before = follower.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_ne!(before, leader_root, "empty follower must differ pre-sync");

    let after = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(
        after, leader_root,
        "after syncing the prover shard the follower root must equal the leader's"
    );
}

/// A follower that is STALE (holds an older subset) converges after sync — the
/// Merkle diff carries only the missing/changed leaves and reaches the leader root.
#[test]
fn stale_follower_converges_to_leader_prover_root() {
    // Follower first: 4 vertices committed.
    let follower = fresh_crdt();
    seed_and_commit(&follower, 4, 1);
    let stale_root = follower.compute_shard_root("vertex", "adds", &global_prover_shard());

    // Leader: the same 4 PLUS 6 more (superset), committed.
    let leader = fresh_crdt();
    seed_and_commit(&leader, 10, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());
    assert_ne!(stale_root, leader_root, "stale subset must differ from the leader");

    let after = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(after, leader_root, "stale follower converges to the leader prover root");
}

/// Re-syncing an already-converged follower is a no-op: the root is unchanged
/// (the diff is empty). Guards against a re-sync perturbing an in-sync node —
/// which would manifest as a node that oscillates in/out of "mismatch".
#[test]
fn resync_when_already_converged_is_stable() {
    let leader = fresh_crdt();
    seed_and_commit(&leader, 8, 1);
    let leader_root = leader.compute_shard_root("vertex", "adds", &global_prover_shard());

    let follower = fresh_crdt();
    let first = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(first, leader_root, "first sync converges");

    let second = sync_prover_phase0(&follower, leader.clone());
    assert_eq!(second, leader_root, "re-sync of a converged follower leaves the root unchanged");
}
