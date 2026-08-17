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

/// Phase-2 unified: a follower syncs a SPLIT app committed in UNIFIED mode as
/// ONE tree (shard_id = app `l2`, not 64 sub-shard trees) and converges to the
/// leader's app-phase root — the single-tree sync path the dispatch now routes
/// unified apps to (`prover_tree_syncer_prod::sync_shard_tree`).
#[test]
fn unified_split_app_follower_converges_via_single_tree_sync() {
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = quil_types::store::ShardKey { l1: [0u8; 3], l2: app };

    // Seed a 64-way split app in UNIFIED mode: all vertices land in ONE tree
    // keyed by the app address, spread (by top-6-bits) across logical sub-shards.
    let seed = |crdt: &HypergraphCrdt, n: u8| {
        crdt.set_shard_partition(app, 1); // 64-way
        crdt.set_unified_tree(true);
        for i in 0..n {
            let mut data = [0u8; 32];
            data[0] = i.wrapping_mul(4); // top-6-bits vary → different logical shards
            data[31] = i;
            crdt.add_vertex(
                &Location { app_address: app, data_address: data },
                &vec![i; 40 + i as usize],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
    };

    let leader = fresh_crdt();
    seed(&leader, 12);
    let leader_root = leader.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(leader_root.len(), 32);
    assert!(leader_root.iter().any(|&b| b != 0));

    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let before = follower.compute_shard_root("vertex", "adds", &sk);
    assert_ne!(before, leader_root, "empty unified follower differs pre-sync");

    // Sync the ONE app tree (shard_id = app l2), phase 0 — no per-sub-shard heads.
    let shard_id = app.to_vec();
    let (v_s, _r) = leader
        .serve_forest_head(&shard_id, 0)
        .expect("leader has a committed app-tree head");
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_phase_from(&reader, v_s, &shard_id, 0)
        .expect("sync_shard_phase_from");
    let after = follower.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(
        after, leader_root,
        "unified split-app follower converges to the leader app root via single-tree sync"
    );
}

/// Phase-2 shard-prover SUBTREE-RANGE sync: a follower covering ONLY shard X
/// pulls just X's subtree from the leader's app tree — NOT shards Y or the far
/// shard — authenticated against the leader's app root, and its local shard
/// commitment matches the leader's. This is what lets a shard prover store only
/// its shard yet stay consensus-consistent.
#[test]
fn shard_prover_pulls_only_its_subtree() {
    use quil_types::store::ShardKey;

    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    // Vertices in shard X (prefix [0], top-6-bits 0), shard Y (prefix [1]), + far.
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };
    let vfar = Location { app_address: app, data_address: [0x80u8; 32] };

    // LEADER: full unified app tree.
    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1);
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.add_vertex(&vfar, b"far-data").unwrap();
    leader.commit(1).unwrap();
    let leader_app_root = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(leader_app_root.len(), 32);
    let pinned = <[u8; 32]>::try_from(leader_app_root.as_slice()).unwrap();

    // FOLLOWER covering shard X only: EMPTY unified app tree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);

    // Sync ONLY shard X's subtree (phase 0), pinned to the leader's app root.
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).expect("leader app-tree head");
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    let (subtree_root, _ver, changed) = follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .expect("subtree sync");

    // Subtree-scoping: ONLY shard X's leaves transferred (byte0 in 0x00..0x03) —
    // no shard Y (0x04..) and no far shard (0x80). (Blobs are fetched separately
    // via `fetch_changed_blobs` in the wired path; here we assert on the forest.)
    assert!(!changed.is_empty(), "shard X leaves transferred");
    for (k, _) in &changed {
        assert!(k[0] < 0x04, "only shard X leaves transfer, got byte0 {:#x}", k[0]);
    }

    // The follower's local shard-X commitment equals the leader's (composes to
    // the app root) and equals the authenticated subtree root returned by sync.
    let follower_x_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(follower_x_commit, leader_x_commit, "shard X commitment matches leader");
    assert_eq!(follower_x_commit.as_slice(), subtree_root.as_slice(), "== authenticated subtree root");

    // Shard Y was NOT pulled → the follower's Y subtree is still empty, while the
    // leader's is populated. Concretely proves the sync did not fetch the whole app.
    let follower_y_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[1u32]);
    let leader_y_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[1u32]);
    assert_eq!(follower_y_commit, vec![0u8; 32], "follower shard Y stays empty (not pulled)");
    assert_ne!(leader_y_commit, vec![0u8; 32], "leader shard Y is populated");
}

/// SPIKE (unified-cutover worker design): a worker holding ONLY its covered
/// subtree reproduces the correct SUBTREE commitment, but NOT the whole-app
/// AGGREGATE root — the un-held sibling subtrees read as empty. Crux finding:
/// `app_engine` publishes the per-shard `state_root` as `compute_shard_root(app)`
/// (the whole-app aggregate over ALL sub-shards), which a subtree-only worker
/// canNOT reproduce. So the sharded unified design requires the per-shard
/// `state_root` to become the SUBTREE root (`sub_shard_commitment` /
/// `app_subtree_root(bit_path)`), bound to the app root via the co-path — not
/// the aggregate. Wiring the unified flip into workers is necessary but NOT
/// sufficient without this state_root semantic change.
#[test]
fn partial_worker_reproduces_subtree_root_but_not_app_aggregate() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };

    // Leader: full unified app tree, data in shard X ([0]) and Y ([1]).
    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1);
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.commit(1).unwrap();
    let leader_app_root = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x_commit = leader.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    let pinned = <[u8; 32]>::try_from(leader_app_root.as_slice()).unwrap();

    // Follower covers shard X only; sync ONLY X's subtree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).unwrap();
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .unwrap();

    // (1) The SUBTREE commitment reproduces exactly on partial storage.
    let follower_x_commit = follower.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    assert_eq!(
        follower_x_commit, leader_x_commit,
        "subtree root reproduces on partial storage"
    );

    // (2) The WHOLE-APP AGGREGATE does NOT — shard Y is un-held (empty) here.
    let follower_app_root = follower.compute_shard_root("vertex", "adds", &sk);
    assert_ne!(
        follower_app_root, leader_app_root,
        "partial worker CANNOT reproduce compute_shard_root(app) — the per-shard \
         state_root must be the SUBTREE root, not the whole-app aggregate"
    );
}

/// (A) producer/verifier symmetry: a subtree-only worker reproduces the exact
/// per-shard `state_root` (`sub_shard_commitment_for_filter`) that a full-holder
/// leader commits — from PARTIAL storage — and it differs from the whole-app
/// aggregate. This is what makes the sharded `state_root` (A) sound.
#[test]
fn sub_shard_commitment_for_filter_matches_leader_from_partial_storage() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let vx = Location { app_address: app, data_address: [0x00u8; 32] };
    let vy = Location { app_address: app, data_address: [0x04u8; 32] };

    let leader = fresh_crdt();
    leader.set_shard_partition(app, 1); // 64-way; shard X = prefix [0]
    leader.set_unified_tree(true);
    leader.add_vertex(&vx, b"x-data").unwrap();
    leader.add_vertex(&vy, b"y-data").unwrap();
    leader.commit(1).unwrap();

    // Wire filter for shard X (prefix [0]) = app ‖ 0x00 (byte-suffix encoding).
    let filter_x = {
        let mut f = app.to_vec();
        f.push(0x00);
        f
    };
    let leader_app = leader.compute_shard_root("vertex", "adds", &sk);
    let leader_x = leader.sub_shard_commitment_for_filter("vertex", "adds", &filter_x);
    assert_eq!(leader_x.len(), 32);
    assert_ne!(
        leader_x, leader_app,
        "per-shard state_root (subtree) differs from the whole-app aggregate on a split app"
    );

    // Follower covers X only; sync just X's subtree.
    let follower = fresh_crdt();
    follower.set_shard_partition(app, 1);
    follower.set_unified_tree(true);
    let bits_x = follower.canonical_bits_for_prefix(&app, &[0u32]);
    let shard_id = app.to_vec();
    let (v_s, _r) = leader.serve_forest_head(&shard_id, 0).unwrap();
    let pinned = <[u8; 32]>::try_from(leader_app.as_slice()).unwrap();
    let reader = InProcTreeReader { source: leader.clone(), shard_id: shard_id.clone(), phase: 0 };
    follower
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(pinned))
        .unwrap();

    // The subtree-only follower computes the SAME per-shard state_root.
    let follower_x = follower.sub_shard_commitment_for_filter("vertex", "adds", &filter_x);
    assert_eq!(
        follower_x, leader_x,
        "subtree-only worker reproduces the leader's per-shard state_root from partial storage"
    );
}

/// (A) unsplit app is a no-op: the bare-app filter's subtree root IS the app
/// root, so switching producer/verifier to `sub_shard_commitment_for_filter`
/// changes nothing for an unsplit app (or any app before its first split).
#[test]
fn sub_shard_commitment_for_filter_unsplit_app_is_app_root() {
    use quil_types::store::ShardKey;
    let app = *b"quil-app-address-0123456789abcd!";
    let sk = ShardKey { l1: [0u8; 3], l2: app };
    let crdt = fresh_crdt();
    crdt.set_unified_tree(true); // single-shard (no partition) → empty prefix
    let v = Location { app_address: app, data_address: [0x11u8; 32] };
    crdt.add_vertex(&v, b"data").unwrap();
    crdt.commit(1).unwrap();

    let filter_bare = app.to_vec(); // unsplit: bare 32-byte app filter
    let sub = crdt.sub_shard_commitment_for_filter("vertex", "adds", &filter_bare);
    let agg = crdt.compute_shard_root("vertex", "adds", &sk);
    assert_eq!(sub, agg, "unsplit app: subtree root == whole-app aggregate (no-op)");
    assert_eq!(sub.len(), 32);
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
