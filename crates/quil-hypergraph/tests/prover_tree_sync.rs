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

#[test]
fn atomic_subtree_chunks_preserve_siblings_and_install_readable_data() {
    use quil_forest::{bit_path_to_prefix, shard_prefix_to_filter, SubtreeSyncAnchor};
    let app = [0x71; 32];
    let bits = [false, false, true];
    let filter = shard_prefix_to_filter(&app, &bit_path_to_prefix(&bits));
    let location = |byte| Location { app_address: app, data_address: [byte; 32] };
    let source = fresh_crdt();
    source.set_unified_tree(true);
    for byte in [0x20, 0x30, 0x60] { source.add_vertex(&location(byte), &[byte; 48]).unwrap(); }
    source.commit(1).unwrap();
    let (version, _) = source.serve_forest_head(&app, 0).unwrap();
    let root = source.sub_shard_commitment_for_filter("vertex", "adds", &filter).try_into().unwrap();
    let reader = InProcTreeReader { source, shard_id: app.to_vec(), phase: 0 };
    let target = fresh_crdt();
    target.set_unified_tree(true);
    target.add_vertex(&location(0xe0), b"local sibling").unwrap();
    target.commit(1).unwrap();
    let mut plan = target.prepare_phase_sync(&reader, version, &app, 0, &bits, Some(SubtreeSyncAnchor::SubtreeRoot(root))).unwrap();
    assert_eq!(plan.remaining().len(), 2);
    while let Some((key, _)) = plan.remaining().first() {
        let byte = key[0];
        target.apply_sync_chunk(&mut plan, &[vec![byte; 48]]).unwrap();
        assert_eq!(target.get_vertex_data_checked(&location(byte)).unwrap(), Some(vec![byte; 48]));
    }
    assert_eq!(target.finish_phase_sync(&plan).unwrap(), root);
    assert_eq!(target.get_vertex_data_checked(&location(0xe0)).unwrap(), Some(b"local sibling".to_vec()));
    assert!(target.get_vertex_data_checked(&location(0x60)).unwrap().is_none());
}

/// A failed local GLOBAL replay can create records that never existed at the
/// authenticated source. Repair must remove them, including when JMT leaves
/// collapse to a different branch shape, and retain source values at common keys.
#[test]
fn anchored_global_sync_reconciles_local_only_records() {
    use quil_forest::SubtreeSyncAnchor;
    for phase in [0, 2] {
        let add = if phase == 0 { HypergraphCrdt::add_vertex } else { HypergraphCrdt::add_hyperedge };
        let read = if phase == 0 { HypergraphCrdt::get_vertex_data_checked } else { HypergraphCrdt::get_hyperedge_data_checked };
        for (canonical, local) in [
            (vec![0x10], vec![0x10, 0x11, 0xe0]),
            (vec![0x10, 0x11, 0x12, 0xf0], vec![0x10, 0x80]),
            (vec![0x10, 0x11, 0x12, 0xf0], vec![0x10, 0x11, 0x12, 0x80]),
            (vec![0x10], vec![0x80]),
        ] {
            for audited in [false, true] {
                let location = |key| Location { app_address: GLOBAL_APP, data_address: [key; 32] };
                let source = fresh_crdt();
                for &key in &canonical { add(&source, &location(key), &[key; 48]).unwrap(); }
                source.commit(1).unwrap();
                let (version, root) = source.serve_forest_head(&GLOBAL_APP, phase).unwrap();
                let reader = InProcTreeReader { source, shard_id: GLOBAL_APP.to_vec(), phase };
                let target = fresh_crdt();
                for &key in &local {
                    let value = if key != 0x10 && canonical.contains(&key) { vec![key; 48] }
                        else { b"stale local record".to_vec() };
                    add(&target, &location(key), &value).unwrap();
                }
                target.commit(1).unwrap();
                if audited {
                    // The reverse diff must also work once the one-time data audit
                    // is complete and the forward diff prunes equal branches.
                    let self_reader = InProcTreeReader { source: target.clone(), shard_id: GLOBAL_APP.to_vec(), phase };
                    let (v, r) = target.serve_forest_head(&GLOBAL_APP, phase).unwrap();
                    let mut audit = target.prepare_phase_sync(&self_reader, v, &GLOBAL_APP, phase, &[], Some(SubtreeSyncAnchor::AppRoot(r))).unwrap();
                    let blobs: Vec<_> = audit.remaining().iter().map(|(key, _)|
                        read(&target, &location(key[0])).unwrap().unwrap()).collect();
                    target.apply_sync_chunk(&mut audit, &blobs).unwrap();
                    target.finish_phase_sync(&audit).unwrap();
                }
                let mut plan = target.prepare_phase_sync(&reader, version, &GLOBAL_APP, phase, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap();
                assert!(plan.remaining().iter().any(|(_, value)| value.is_none()));
                while let Some((key, value)) = plan.remaining().first() {
                    let blob = if value.is_some() { vec![key[0]; 48] } else { Vec::new() };
                    target.apply_sync_chunk(&mut plan, &[blob]).unwrap();
                }
                assert_eq!(target.finish_phase_sync(&plan).unwrap(), root);
                for &key in &canonical {
                    assert_eq!(read(&target, &location(key)).unwrap(), Some(vec![key; 48]));
                }
                for &key in local.iter().filter(|key| !canonical.contains(key)) {
                    assert!(read(&target, &location(key)).unwrap().is_none());
                }
                assert!(target.prepare_phase_sync(&reader, version, &GLOBAL_APP, phase, &[], Some(SubtreeSyncAnchor::AppRoot(root))).unwrap().remaining().is_empty());
            }
        }
    }
}

#[test]
fn global_reconciliation_requires_a_valid_anchor_and_never_prunes_application_data() {
    use quil_forest::SubtreeSyncAnchor;
    for phase in [0, 2] {
        let add = if phase == 0 { HypergraphCrdt::add_vertex } else { HypergraphCrdt::add_hyperedge };
        let read = if phase == 0 { HypergraphCrdt::get_vertex_data_checked } else { HypergraphCrdt::get_hyperedge_data_checked };
        for app in [GLOBAL_APP, [0x71; 32]] {
            let location = |key| Location { app_address: app, data_address: [key; 32] };
            let source = fresh_crdt();
            add(&source, &location(1), b"canonical").unwrap();
            source.commit(1).unwrap();
            let (version, root) = source.serve_forest_head(&app, phase).unwrap();
            let reader = InProcTreeReader { source, shard_id: app.to_vec(), phase };
            let target = fresh_crdt();
            add(&target, &location(2), b"local only").unwrap();
            target.commit(1).unwrap();
            let before = target.serve_forest_head(&app, phase);
            let mut wrong = root;
            wrong[0] ^= 1;
            assert!(target.prepare_phase_sync(&reader, version, &app, phase, &[], Some(SubtreeSyncAnchor::AppRoot(wrong))).is_err());
            assert!(target.prepare_phase_sync(&reader, version, &app, phase, &[], None).is_err());
            if app != GLOBAL_APP {
                assert!(target.prepare_phase_sync(&reader, version, &app, phase, &[], Some(SubtreeSyncAnchor::AppRoot(root))).is_err());
            }
            assert_eq!(target.serve_forest_head(&app, phase), before);
            assert_eq!(read(&target, &location(2)).unwrap(), Some(b"local only".to_vec()));
            assert!(read(&target, &location(1)).unwrap().is_none());
        }
    }
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

/// Unified: a follower syncs a SPLIT app committed in UNIFIED mode as
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

/// Shard-prover SUBTREE-RANGE sync: a follower covering ONLY shard X
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
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(quil_forest::SubtreeSyncAnchor::AppRoot(pinned)))
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

/// SPIKE: a worker holding ONLY its covered
/// subtree reproduces the correct SUBTREE commitment, but NOT the whole-app
/// AGGREGATE root — the un-held sibling subtrees read as empty.
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
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(quil_forest::SubtreeSyncAnchor::AppRoot(pinned)))
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
        .sync_shard_subtree_phase_from(&reader, v_s, &app, 0, &bits_x, Some(quil_forest::SubtreeSyncAnchor::AppRoot(pinned)))
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

/// Resolve the actual shard-header commitment after the archive advances this
/// shard and its sibling, then recover only the shard at the cited version.
#[test]
fn unified_shard_sync_uses_the_header_subtree_at_its_retained_version() {
    use quil_forest::{bit_path_to_prefix, shard_prefix_to_filter, SubtreeSyncAnchor};
    for depth in [1, 4, 5, 6, 9] {
        let app = [0x51; 32];
        let bits = vec![false; depth];
        let filter = shard_prefix_to_filter(&app, &bit_path_to_prefix(&bits));
        let archive = fresh_crdt();
        archive.set_unified_tree(true);
        // The encoded path is meaningful even before grid metadata arrives.
        for (first, tag) in [(0u8, 1u8), (0, 2), (0x80, 3)] {
            let mut address = [0; 32];
            address[0] = first;
            address[31] = tag;
            archive.add_vertex(&Location { app_address: app, data_address: address }, &[tag; 32]).unwrap();
        }
        archive.commit(1).unwrap();
        let header_root: [u8; 32] = archive
            .sub_shard_commitment_for_filter("vertex", "adds", &filter)
            .try_into().unwrap();
        let (version, app_root) = archive.serve_forest_head(&app, 0).unwrap();
        assert_ne!(header_root, app_root, "a shard header does not carry the app root");
        let mut newer = [0; 32];
        newer[31] = 4;
        archive.add_vertex(&Location { app_address: app, data_address: newer }, b"newer shard state").unwrap();
        archive.add_vertex(&Location { app_address: app, data_address: [0x80; 32] }, b"newer sibling").unwrap();
        archive.commit(2).unwrap();
        let (resolved, _) = archive.resolve_root(&filter, 0, header_root).expect("retained shard root");
        assert_eq!(resolved, version);

        let worker = fresh_crdt();
        worker.set_unified_tree(true);
        assert_eq!(worker.canonical_bits_for_filter(&filter), Some(bits.clone()));
        let reader = InProcTreeReader { source: archive.clone(), shard_id: app.to_vec(), phase: 0 };
        assert!(worker.sync_shard_subtree_phase_from(
            &reader, resolved, &app, 0, &bits, Some(SubtreeSyncAnchor::AppRoot(header_root)),
        ).is_err(), "the former app-root interpretation must fail on this fixture");
        let (got, _, changed) = worker.sync_shard_subtree_phase_from(
            &reader, resolved, &app, 0, &bits, Some(SubtreeSyncAnchor::SubtreeRoot(header_root)),
        ).unwrap();
        assert_eq!(got, header_root);
        assert_eq!(changed.len(), 2, "only this shard at the cited version transfers");
        assert_eq!(worker.sub_shard_commitment_for_filter("vertex", "adds", &filter), header_root);
        let before = worker.serve_forest_head(&app, 0);
        let mut wrong = header_root;
        wrong[0] ^= 1;
        assert!(worker.sync_shard_subtree_phase_from(
            &reader, resolved, &app, 0, &bits, Some(SubtreeSyncAnchor::SubtreeRoot(wrong)),
        ).is_err());
        assert_eq!(worker.serve_forest_head(&app, 0), before, "bad anchor must not write state");
        assert!(archive.resolve_root(&filter, 0, wrong).is_none());

        let ahead = fresh_crdt();
        ahead.set_unified_tree(true);
        let mut extra = [0; 32];
        extra[31] = 99;
        ahead.add_vertex(&Location { app_address: app, data_address: extra }, b"extra local leaf").unwrap();
        ahead.commit(1).unwrap();
        let before = ahead.serve_forest_head(&app, 0);
        assert!(ahead.sync_shard_subtree_phase_from(
            &reader, resolved, &app, 0, &bits, Some(SubtreeSyncAnchor::SubtreeRoot(header_root)),
        ).is_err(), "an incompatible local tree must not be merged and published");
        assert_eq!(ahead.serve_forest_head(&app, 0), before, "failed reconstruction leaves the prior tree intact");
    }
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
