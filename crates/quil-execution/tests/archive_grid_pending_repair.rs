//! The pending-change repair: an archive whose local store lost the pending
//! record of a committee-governed split restores it from the committed
//! handoff request, and flips in step with an archive that kept it. On a
//! healthy store the repair writes nothing.
//!
//! Each test drives two stores through the same frames and compares their
//! shard grids, pending changes and committed roots after every frame. The
//! repair scans at the first frame a process executes, after a trigger
//! (`request_pending_repair`, called after a prover-shard reconcile or state
//! jump), and at the first frame of each epoch.
//!
//! The trigger and the settled verdicts are process-wide: these tests rely on
//! nextest running each test in its own process.

use std::collections::HashMap;
use std::sync::Arc;

use quil_execution::global_intrinsic::{
    handoff, intrinsic, intrinsic::GlobalIntrinsic, materialize,
};
use quil_execution::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use quil_execution::hypergraph_state::{
    hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState,
};
use quil_execution::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};
use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
use quil_types::error::Result;
use quil_types::store::{
    ClockStore, KvDb as _, PendingShardChange, ShardChangeKind, ShardInfo, ShardKey, ShardsStore,
};

struct AcceptAll;
impl quil_types::crypto::KeyManager for AcceptAll {
    fn validate_signature(
        &self,
        _: quil_types::crypto::KeyType,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<bool> {
        Ok(true)
    }
}

const EPOCH: u64 = 720;
/// Past the unified cutover and every grid reset, as on mainnet.
const ACTIVATION: u64 = 2000 * EPOCH;
const APP: [u8; 32] = [0x31; 32];

fn install_policy() {
    quil_types::consensus::set_epoch_length_frames(EPOCH);
    quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
        activation_frame: ACTIVATION,
        chain_id: [0x51; 32],
        legacy_history: LegacyHistory::Discard,
        membership_boundary_frame: ACTIVATION,
        first_session_boundary_frame: u64::MAX,
    }));
}

fn shard(bits: &[bool]) -> Vec<u8> {
    quil_forest::encode_shard_bit_path(&APP, bits)
}

/// The split parent: the application's shard 1, beside the empty shard 0.
const P: &[bool] = &[true];
/// Its children 1‖1‖0 and 1‖1‖1; the deep split also registers the spine 1‖0.
const C0: &[bool] = &[true, true, false];
const C1: &[bool] = &[true, true, true];
const SPINE: &[bool] = &[true, false];
/// The children's branch, which a merge re-creates.
const BRANCH: &[bool] = &[true, true];

fn grid_key() -> Vec<u8> {
    let mut key = quil_hypergraph::addressing::get_bloom_filter_indices(&APP, 256, 3).to_vec();
    key.extend_from_slice(&APP);
    key
}

fn row(bits: &[bool]) -> ShardInfo {
    ShardInfo {
        shard_key: grid_key(),
        prefix: quil_forest::bit_path_to_prefix(bits),
        size: vec![],
        data_shards: 0,
        commitment: vec![],
    }
}

struct Prover {
    key: Vec<u8>,
}

/// One archive's store.
struct World {
    db: Arc<quil_store::RocksDb>,
    shards: Arc<dyn ShardsStore>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    clock: Arc<quil_store::RocksClockStore>,
    intrinsic: GlobalIntrinsic,
    /// Run with the repair off (on this thread).
    repair_off: bool,
}

/// What the two stores must agree on after a frame.
#[derive(Debug, PartialEq)]
struct Observed {
    rows: Vec<(Vec<u8>, Vec<u32>)>,
    pending: Vec<PendingShardChange>,
    roots: HashMap<ShardKey, Vec<Vec<u8>>>,
    commitments: Vec<Vec<u8>>,
}

impl World {
    fn new(provers: u8) -> (Self, Vec<Prover>) {
        Self::new_on(provers, &[&[false], P], P)
    }

    /// A store whose grid holds `rows`, with `provers` on `on`.
    fn new_on(provers: u8, rows: &[&[bool]], on: &[bool]) -> (Self, Vec<Prover>) {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let intrinsic = GlobalIntrinsic::new(Arc::new(AcceptAll))
            .with_shards_store(shards.clone())
            .with_shards_db(db.clone())
            .with_hypergraph(crdt.clone())
            .with_clock_store(clock.clone());
        let world = Self {
            db,
            shards,
            crdt,
            clock,
            intrinsic,
            repair_off: false,
        };
        world.edit_grid(&rows.iter().map(|bits| row(bits)).collect::<Vec<_>>(), &[]);
        let state = HypergraphState::new(world.crdt.clone());
        let seeded = (0..provers)
            .map(|i| seed(&state, 0x10 + i, 10 + u64::from(i) * 7, &shard(on)))
            .collect();
        state.commit().unwrap();
        state.abort();
        world.crdt.commit(1).unwrap();
        (world, seeded)
    }

    /// Write grid rows and remove others outside execution, as a store
    /// rewrite would.
    fn edit_grid(&self, put: &[ShardInfo], delete: &[ShardInfo]) {
        let txn = self.db.new_batch(false).unwrap();
        for shard in delete {
            self.shards
                .delete_app_shard(txn.as_ref(), &shard.shard_key, &shard.prefix)
                .unwrap();
        }
        for shard in put {
            self.shards.put_app_shard(txn.as_ref(), shard).unwrap();
        }
        txn.commit().unwrap();
    }

    /// A proposal's pending record, staged as its frame would.
    fn propose(&self, change: &PendingShardChange) {
        let txn = self.db.new_batch(false).unwrap();
        self.shards
            .put_pending_shard_change(txn.as_ref(), change)
            .unwrap();
        txn.commit().unwrap();
    }

    /// The GLOBAL frame record of a frame that executed `merge`.
    fn record_merge_frame(&self, merge: &PendingShardChange) {
        use quil_types::proto::global::{
            message_request::Request, GlobalFrame, GlobalFrameHeader, MessageBundle, MessageRequest,
        };
        let frame = GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: merge.proposed_frame,
                ..Default::default()
            }),
            requests: vec![MessageBundle {
                requests: vec![MessageRequest {
                    request: Some(Request::ShardMerge(quil_types::proto::global::ShardMerge {
                        shard_addresses: merge.children.clone(),
                        parent_address: merge.parent.clone(),
                        frame_number: merge.proposed_frame,
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let txn = self.clock.new_transaction(false).unwrap();
        self.clock
            .put_global_clock_frame(&frame, txn.as_ref())
            .unwrap();
        txn.commit().unwrap();
    }

    /// Lose every pending record, as a store rewrite would.
    fn lose_pending(&self) {
        let txn = self.db.new_batch(false).unwrap();
        for change in self.shards.all_pending_shard_changes().unwrap() {
            self.shards
                .delete_pending_shard_change(txn.as_ref(), &change.parent, change.effective_epoch)
                .unwrap();
        }
        txn.commit().unwrap();
    }

    /// Execute `frame`'s maintenance pass and commit it.
    fn step(&self, frame: u64) -> Observed {
        self.step_with(frame, |_| {})
    }

    /// [`Self::step`], after `messages` wrote to the frame's state.
    fn step_with(&self, frame: u64, messages: impl FnOnce(&HypergraphState)) -> Observed {
        intrinsic::set_pending_repair_off_for_thread(self.repair_off);
        let state = HypergraphState::new(self.crdt.clone());
        messages(&state);
        self.intrinsic
            .apply_due_shard_changes(frame, &state)
            .unwrap();
        state.commit().unwrap();
        state.abort();
        let roots = self.crdt.commit(frame).unwrap();
        intrinsic::set_pending_repair_off_for_thread(false);
        Observed {
            roots,
            ..self.observe()
        }
    }

    fn observe(&self) -> Observed {
        let mut rows: Vec<_> = self
            .shards
            .range_app_shards()
            .unwrap()
            .into_iter()
            .map(|r| (r.shard_key, r.prefix))
            .collect();
        rows.sort();
        let mut pending = self.shards.all_pending_shard_changes().unwrap();
        pending.sort_by(|a, b| (a.effective_epoch, &a.parent).cmp(&(b.effective_epoch, &b.parent)));
        Observed {
            rows,
            pending,
            roots: HashMap::new(),
            commitments: self.prover_root(),
        }
    }

    /// The four phase roots of GLOBAL's prover shard, as committed.
    fn prover_root(&self) -> Vec<Vec<u8>> {
        let key = ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(
                &GLOBAL_INTRINSIC_ADDRESS,
                256,
                3,
            ),
            l2: GLOBAL_INTRINSIC_ADDRESS,
        };
        [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ]
        .into_iter()
        .map(|(set, phase)| self.crdt.compute_shard_root(set, phase, &key))
        .collect()
    }

    fn in_grid(&self, bits: &[bool]) -> bool {
        self.observe()
            .rows
            .contains(&(grid_key(), quil_forest::bit_path_to_prefix(bits)))
    }

    fn state(&self) -> HypergraphState {
        HypergraphState::new(self.crdt.clone())
    }
}

/// A prover with an Active allocation on `filter`, eligible for many epochs.
fn seed(state: &HypergraphState, n: u8, seniority: u64, filter: &[u8]) -> Prover {
    let va = vertex_adds_discriminator().unwrap();
    let key = vec![n; 897];
    let address = materialize::prover_address_from_pubkey(&key).unwrap();
    let mut prover = materialize::create_prover_vertex_tree(&key, seniority).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[1]).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &va,
            1,
            vertex_tree_to_blob(&prover),
        )
        .unwrap();
    let allocation_address = materialize::allocation_address(&key, filter).unwrap();
    let mut allocation = materialize::create_allocation_vertex_tree(&address, filter, 1).unwrap();
    let class = "allocation:ProverAllocation";
    write_field(&mut allocation, class, "Status", &[1]).unwrap();
    write_field(
        &mut allocation,
        class,
        "JoinConfirmFrameNumber",
        &0u64.to_be_bytes(),
    )
    .unwrap();
    write_field(
        &mut allocation,
        class,
        "Epoch",
        &(ACTIVATION / EPOCH + 1000).to_be_bytes(),
    )
    .unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &allocation_address,
            &va,
            1,
            vertex_tree_to_blob(&allocation),
        )
        .unwrap();
    let blob = materialize::build_prover_allocation_hyperedge_blob(
        &address,
        &[(allocation_address, &allocation)],
    )
    .unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &hyperedge_adds_discriminator().unwrap(),
            1,
            blob,
        )
        .unwrap();
    Prover { key }
}

/// A prover with a Joining allocation on each of `filters`, joined at
/// different frames: a merge of those shards writes one parent slot from them,
/// and the last child the merge moves wins.
fn seed_on_each(state: &HypergraphState, n: u8, filters: &[Vec<u8>]) -> Prover {
    let va = vertex_adds_discriminator().unwrap();
    let key = vec![n; 897];
    let address = materialize::prover_address_from_pubkey(&key).unwrap();
    let mut prover = materialize::create_prover_vertex_tree(&key, 1).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[1]).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &va,
            1,
            vertex_tree_to_blob(&prover),
        )
        .unwrap();
    let mut atoms = Vec::new();
    for (i, filter) in filters.iter().enumerate() {
        let allocation_address = materialize::allocation_address(&key, filter).unwrap();
        let mut allocation =
            materialize::create_allocation_vertex_tree(&address, filter, 1).unwrap();
        let class = "allocation:ProverAllocation";
        write_field(&mut allocation, class, "Status", &[0]).unwrap();
        write_field(
            &mut allocation,
            class,
            "JoinFrameNumber",
            &(ACTIVATION + 11 + i as u64).to_be_bytes(),
        )
        .unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &allocation_address,
                &va,
                1,
                vertex_tree_to_blob(&allocation),
            )
            .unwrap();
        atoms.push((allocation_address, allocation));
    }
    let refs: Vec<_> = atoms.iter().map(|(a, t)| (*a, t)).collect();
    let blob = materialize::build_prover_allocation_hyperedge_blob(&address, &refs).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &hyperedge_adds_discriminator().unwrap(),
            1,
            blob,
        )
        .unwrap();
    Prover { key }
}

fn allocation_field(
    state: &HypergraphState,
    prover: &Prover,
    filter: &[u8],
    field: &str,
) -> Option<Vec<u8>> {
    let address = materialize::allocation_address(&prover.key, filter).unwrap();
    state
        .get(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &vertex_adds_discriminator().unwrap(),
        )
        .unwrap()
        .filter(|blob| !blob.is_empty())
        .map(|blob| rebuild_vertex_tree_from_blob(&blob))
        .and_then(|tree| read_field(&tree, "allocation:ProverAllocation", field))
}

fn allocation_status(state: &HypergraphState, prover: &Prover, filter: &[u8]) -> Option<u8> {
    let address = materialize::allocation_address(&prover.key, filter).unwrap();
    state
        .get(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &vertex_adds_discriminator().unwrap(),
        )
        .unwrap()
        .filter(|blob| !blob.is_empty())
        .map(|blob| rebuild_vertex_tree_from_blob(&blob))
        .and_then(|tree| read_field(&tree, "allocation:ProverAllocation", "Status"))
        .and_then(|bytes| bytes.first().copied())
}

/// Pause `prover`'s allocation on `filter`: it stops being committee-eligible.
fn pause(state: &HypergraphState, prover: &Prover, filter: &[u8]) {
    let va = vertex_adds_discriminator().unwrap();
    let address = materialize::allocation_address(&prover.key, filter).unwrap();
    let blob = state
        .get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va)
        .unwrap()
        .unwrap();
    let mut tree = rebuild_vertex_tree_from_blob(&blob);
    write_field(&mut tree, "allocation:ProverAllocation", "Status", &[2]).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS[..],
            &address,
            &va,
            1,
            vertex_tree_to_blob(&tree),
        )
        .unwrap();
}

/// The frames both stores execute in `epoch`: its first two (the epoch's
/// session pass and the gate after it) and the next pass with the frame after.
fn frames(epoch: u64) -> [u64; 4] {
    let base = epoch * EPOCH;
    [base, base + 1, base + 8, base + 9]
}

/// The deep split of P, proposed early in the activation epoch.
fn p_split() -> PendingShardChange {
    let proposed = ACTIVATION + 100;
    PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: shard(P),
        children: vec![shard(C0), shard(C1)],
        effective_epoch: proposed / EPOCH + 2,
        proposed_frame: proposed,
    }
}

/// Two stores through the root split; `lose` runs on the second after each
/// frame and may rewrite its store. Returns both, after the epoch the split
/// flipped in plus one more.
fn split_lifecycle(
    lose: impl Fn(&World, u64),
    second_repair_off: bool,
) -> (World, World, Vec<(u64, Observed, Observed)>) {
    install_policy();
    let (a, _) = World::new(5);
    let (mut b, _) = World::new(5);
    b.repair_off = second_repair_off;
    let mut trace = Vec::new();
    let mut flipped_epoch = None;
    for epoch in ACTIVATION / EPOCH..ACTIVATION / EPOCH + 12 {
        for frame in frames(epoch) {
            if frame == ACTIVATION + 1 {
                a.propose(&p_split());
                b.propose(&p_split());
            }
            let observed_a = a.step(frame);
            let observed_b = b.step(frame);
            lose(&b, frame);
            // As left for the next frame.
            trace.push((
                frame,
                observed_a,
                Observed {
                    roots: observed_b.roots,
                    ..b.observe()
                },
            ));
        }
        if flipped_epoch.is_none() && !a.in_grid(P) {
            flipped_epoch = Some(epoch);
        }
        if flipped_epoch.is_some_and(|flipped| epoch > flipped) {
            break;
        }
    }
    assert!(
        flipped_epoch.is_some(),
        "the healthy store applies the split"
    );
    (a, b, trace)
}

/// The split's request, once scheduled in `world`.
fn p_request(world: &World) -> Option<[u8; 32]> {
    handoff::schedule::topology_request(&world.state(), &p_split()).unwrap()
}

#[test]
fn a_record_lost_mid_epoch_is_restored_at_the_next_epoch_and_flips_in_step() {
    // The second store loses the pending record right after the split is
    // scheduled (mid-epoch, with no restart or reconcile): its committed state
    // still holds the request.
    let lose = |world: &World, frame: u64| {
        if frame == p_split().effective_epoch * EPOCH {
            assert!(
                p_request(world).is_some(),
                "scheduled at the first due frame"
            );
            world.lose_pending();
        }
    };
    let (_a, b, trace) = split_lifecycle(lose, false);
    let lost_at = trace
        .iter()
        .position(|(_, a, b)| a.pending != b.pending)
        .expect("the second store lost the record");
    let next_epoch = (trace[lost_at].0 / EPOCH + 1) * EPOCH;
    for (frame, observed_a, observed_b) in &trace[lost_at..] {
        if *frame < next_epoch {
            assert_ne!(
                observed_a.pending, observed_b.pending,
                "no trigger until the next epoch (frame {frame})"
            );
        } else {
            assert_eq!(
                observed_a, observed_b,
                "both stores agree after frame {frame}"
            );
        }
    }
    assert!(!b.in_grid(P) && b.in_grid(SPINE) && b.in_grid(C0) && b.in_grid(C1));
    let flip = trace
        .iter()
        .position(|(_, a, _)| {
            !a.rows
                .contains(&(grid_key(), quil_forest::bit_path_to_prefix(P)))
        })
        .unwrap();
    assert!(
        trace[flip].0 > next_epoch,
        "the record was back before the flip"
    );
    assert!(
        trace[flip]
            .1
            .commitments
            .iter()
            .any(|root| !root.is_empty()),
        "the prover shard has a root"
    );
    assert_ne!(
        trace[flip - 1].1.commitments,
        trace[flip].1.commitments,
        "the flip moves allocations: roots change"
    );
    let parent = handoff::head(&b.state(), &shard(P)).unwrap().unwrap();
    assert!(
        handoff::is_fenced(&b.state(), &parent.id().unwrap()).unwrap(),
        "the parent was fenced, as on mainnet"
    );
}

/// The frame the healthy store flips at: the fence authorizes the successors
/// in the session pass of the epoch four after scheduling, and the gate
/// applies the change on the next frame.
fn fence_frame() -> u64 {
    (p_split().effective_epoch + handoff::schedule::FENCE_AFTER_EPOCHS) * EPOCH
}

/// Lose the record in the fenced frame, after this epoch's scan: the healthy
/// store flips on the very next frame.
fn lose_at_the_fence(world: &World, frame: u64, trigger: bool) {
    if frame == fence_frame() {
        let request = p_request(world).unwrap();
        assert!(
            handoff::schedule::activated(&world.state(), &request).unwrap(),
            "authorized by the fence"
        );
        world.lose_pending();
        if trigger {
            // A restart with this store, or a reconcile, before the next frame.
            intrinsic::request_pending_repair();
        }
    }
}

#[test]
fn a_trigger_restores_a_lost_record_on_the_next_frame_and_flips_with_the_network() {
    let (_a, b, trace) =
        split_lifecycle(|world, frame| lose_at_the_fence(world, frame, true), false);
    let fence = trace
        .iter()
        .position(|(frame, _, _)| *frame == fence_frame())
        .unwrap();
    assert_ne!(
        trace[fence].1.pending, trace[fence].2.pending,
        "lost after the fence"
    );
    let (frame, observed_a, observed_b) = &trace[fence + 1];
    assert!(
        !observed_a
            .rows
            .contains(&(grid_key(), quil_forest::bit_path_to_prefix(P))),
        "the healthy store flips at {frame}"
    );
    for (frame, observed_a, observed_b) in &trace[fence + 1..] {
        assert_eq!(
            observed_a, observed_b,
            "both stores agree after frame {frame}"
        );
    }
    assert_eq!(observed_a, observed_b);
    assert!(!b.in_grid(P) && b.in_grid(C0) && b.in_grid(C1));
}

#[test]
fn without_a_trigger_a_record_lost_before_its_flip_is_restored_late() {
    let (_a, _b, trace) =
        split_lifecycle(|world, frame| lose_at_the_fence(world, frame, false), false);
    let fence = trace
        .iter()
        .position(|(frame, _, _)| *frame == fence_frame())
        .unwrap();
    let parent = (grid_key(), quil_forest::bit_path_to_prefix(P));
    for (frame, observed_a, observed_b) in &trace[fence + 1..] {
        if *frame < fence_frame() + EPOCH {
            assert!(
                !observed_a.rows.contains(&parent) && observed_b.rows.contains(&parent),
                "the second store keeps the parent until the next epoch (frame {frame})"
            );
        } else {
            assert_eq!(
                observed_a.rows, observed_b.rows,
                "restored and flipped at the next epoch (frame {frame})"
            );
            assert_eq!(observed_a.pending, observed_b.pending);
        }
    }
    assert!(trace.last().unwrap().0 >= fence_frame() + EPOCH);
}

#[test]
fn without_the_repair_a_store_that_lost_a_scheduled_split_keeps_the_parent_and_diverges() {
    let lose = |world: &World, _frame: u64| {
        if p_request(world).is_some() {
            world.lose_pending();
            intrinsic::request_pending_repair();
        }
    };
    let (a, b, trace) = split_lifecycle(lose, true);
    assert!(b.in_grid(P), "the parent stays in the grid");
    assert!(b.observe().pending.is_empty());
    let (_, last_a, last_b) = trace.last().unwrap();
    assert_ne!(last_a.rows, last_b.rows);
    assert_ne!(
        last_a.commitments, last_b.commitments,
        "the allocations did not move: roots diverge"
    );
    drop(a);
}

#[test]
fn a_store_whose_grid_was_rewound_after_the_flip_reapplies_it_and_matches() {
    // Both stores flip; then the second's shard keyspace is rewound to the
    // parent with no pending record, while its committed state is the
    // network's (a reconcile skip or store rewrite).
    let (a, b, _) = split_lifecycle(|_, _| {}, false);
    assert_eq!(a.observe(), b.observe());
    b.edit_grid(&[row(P)], &[row(SPINE), row(C0), row(C1)]);
    assert!(b.in_grid(P) && !b.in_grid(C0));
    let next = (ACTIVATION / EPOCH + 40) * EPOCH;
    let observed_a = a.step(next);
    let observed_b = b.step(next);
    assert_eq!(
        observed_a.rows, observed_b.rows,
        "the rewound grid flips again"
    );
    assert_eq!(observed_a.pending, observed_b.pending);
    assert_eq!(
        observed_a.commitments, observed_b.commitments,
        "a late flip moves nothing more"
    );
    for frame in frames(ACTIVATION / EPOCH + 41) {
        assert_eq!(a.step(frame), b.step(frame));
    }
}

#[test]
fn the_repair_leaves_a_rewound_grid_alone_when_off() {
    let (a, mut b, _) = split_lifecycle(|_, _| {}, false);
    b.edit_grid(&[row(P)], &[row(SPINE), row(C0), row(C1)]);
    b.repair_off = true;
    let next = (ACTIVATION / EPOCH + 40) * EPOCH;
    let observed_a = a.step(next);
    let observed_b = b.step(next);
    assert_ne!(
        observed_a.rows, observed_b.rows,
        "without the repair the rewound grid stays"
    );
}

#[test]
fn the_repair_writes_nothing_through_a_full_lifecycle() {
    install_policy();
    let (on, provers) = World::new(5);
    let (mut off, _) = World::new(5);
    off.repair_off = true;
    let worlds = [&on, &off];
    let one = shard(BRANCH);
    let mut merge_proposed = false;
    let mut joined = false;
    let mut drop_proposed = false;
    let late = Prover {
        key: vec![0x40; 897],
    };
    let mut steps = 0;
    for epoch in ACTIVATION / EPOCH..ACTIVATION / EPOCH + 40 {
        for frame in frames(epoch) {
            if frame == ACTIVATION + 1 {
                worlds.iter().for_each(|w| w.propose(&p_split()));
            }
            // The same split proposed again an epoch later (an E+3
            // duplicate): it waits on the parent's closing session, and once
            // the first flips it is consumed as stale.
            if frame == ACTIVATION + EPOCH + 1 {
                let duplicate = PendingShardChange {
                    effective_epoch: p_split().effective_epoch + 1,
                    proposed_frame: frame,
                    ..p_split()
                };
                worlds.iter().for_each(|w| w.propose(&duplicate));
            }
            // After the split: merge its children back into 1.
            if !merge_proposed && !on.in_grid(P) {
                merge_proposed = true;
                let merge = PendingShardChange {
                    kind: ShardChangeKind::Merge,
                    parent: one.clone(),
                    children: vec![shard(C0), shard(C1)],
                    effective_epoch: frame / EPOCH + 2,
                    proposed_frame: frame,
                };
                worlds.iter().for_each(|w| w.propose(&merge));
            }
            // After the merge: a prover joins the merged shard, so its
            // committee is replaced at the next epoch boundary.
            let join =
                merge_proposed && !joined && on.in_grid(BRANCH) && on.observe().pending.is_empty();
            joined |= join;
            // While that membership successor closes: every prover on the
            // merged shard pauses and a split of it is proposed, which the gate
            // drops once the successor is live.
            let pause_all = joined
                && !join
                && !drop_proposed
                && handoff::schedule::retiring_request(&on.state(), &one)
                    .unwrap()
                    .is_some();
            if pause_all {
                drop_proposed = true;
                let split = PendingShardChange {
                    kind: ShardChangeKind::Split,
                    parent: one.clone(),
                    children: vec![shard(C0), shard(C1)],
                    effective_epoch: frame / EPOCH + 2,
                    proposed_frame: frame,
                };
                worlds.iter().for_each(|w| w.propose(&split));
            }
            let messages = |state: &HypergraphState| {
                if join {
                    seed(state, 0x40, 1, &one);
                }
                if pause_all {
                    for prover in provers.iter().chain(std::iter::once(&late)) {
                        if allocation_status(state, prover, &one) == Some(1) {
                            pause(state, prover, &one);
                        }
                    }
                }
            };
            // Scan at every frame, not only at the triggers.
            intrinsic::request_pending_repair();
            let observed_on = on.step_with(frame, messages);
            let observed_off = off.step_with(frame, messages);
            assert_eq!(
                observed_on, observed_off,
                "the repair changes nothing at frame {frame}"
            );
            steps += 1;
        }
    }
    let state = on.state();
    assert!(steps > 100);
    assert!(
        !on.in_grid(P) && on.in_grid(SPINE) && on.in_grid(BRANCH),
        "split, then merged"
    );
    assert!(
        !on.in_grid(C0) && !on.in_grid(C1),
        "the split of the merged shard was dropped"
    );
    assert!(drop_proposed && on.observe().pending.is_empty());
    let head = handoff::head(&state, &one).unwrap().unwrap();
    assert!(
        head.generation >= 2,
        "1's committee was replaced by a membership successor"
    );
    let root = handoff::head(&state, &shard(P)).unwrap().unwrap();
    assert!(handoff::is_fenced(&state, &root.id().unwrap()).unwrap());
}

#[test]
fn a_shard_without_a_session_and_a_shard_with_an_active_one_are_left_alone() {
    install_policy();
    // P has provers and gets a session; shard 0 gets none. No shard of the
    // second store has provers.
    let (world, _) = World::new(3);
    let (bare, _) = World::new(0);
    for epoch in ACTIVATION / EPOCH..ACTIVATION / EPOCH + 3 {
        for frame in frames(epoch) {
            for w in [&world, &bare] {
                let before = w.observe().rows;
                intrinsic::request_pending_repair();
                let observed = w.step(frame);
                assert!(
                    observed.pending.is_empty(),
                    "nothing is restored at frame {frame}"
                );
                assert_eq!(observed.rows, before);
            }
        }
    }
    assert!(handoff::head(&world.state(), &shard(&[false]))
        .unwrap()
        .is_none());
    assert!(
        handoff::head(&world.state(), &shard(P)).unwrap().is_some(),
        "P runs an active session"
    );
    assert!(handoff::head(&bare.state(), &shard(P)).unwrap().is_none());
}

#[test]
fn a_trigger_survives_an_execution_below_the_highest_frame() {
    // Lost mid-epoch, then a trigger (a reconcile); before the next frame a
    // fork executes an earlier frame of the same epoch and discards it.
    let lost = p_split().effective_epoch * EPOCH + 8;
    let lose = |world: &World, frame: u64| {
        if frame == lost {
            world.lose_pending();
            intrinsic::request_pending_repair();
            let state = world.state();
            world
                .intrinsic
                .apply_due_shard_changes(frame - 5, &state)
                .unwrap();
            state.abort();
        }
    };
    let (_a, _b, trace) = split_lifecycle(lose, false);
    let at = trace
        .iter()
        .position(|(frame, _, _)| *frame == lost)
        .unwrap();
    assert_ne!(trace[at].1.pending, trace[at].2.pending, "lost");
    for (frame, observed_a, observed_b) in &trace[at + 1..] {
        assert_eq!(
            observed_a, observed_b,
            "restored at the next frame; both stores agree after frame {frame}"
        );
    }
}

#[test]
fn a_merge_that_re_registers_a_split_parent_does_not_split_it_again() {
    // Both stores split P; the second then runs without the repair, as the
    // reference.
    let (a, mut b, _) = split_lifecycle(|_, _| {}, false);
    b.repair_off = true;
    // The spine and the unregistered range beside it merge back into P.
    // Neither has a committee, so the merge needs no request and applies at
    // once: P is back in the grid beside the split's children, its head still
    // closed for the split.
    let start = (ACTIVATION / EPOCH + 20) * EPOCH;
    let merge = PendingShardChange {
        kind: ShardChangeKind::Merge,
        parent: shard(P),
        children: vec![shard(SPINE), shard(BRANCH)],
        effective_epoch: start / EPOCH + 2,
        proposed_frame: start,
    };
    a.propose(&merge);
    b.propose(&merge);
    let mut reentered = false;
    for epoch in start / EPOCH..start / EPOCH + 4 {
        for frame in frames(epoch) {
            intrinsic::request_pending_repair();
            let observed_a = a.step(frame);
            let observed_b = b.step(frame);
            assert_eq!(
                observed_a, observed_b,
                "the repair leaves the re-registered parent alone at frame {frame}"
            );
            reentered |= a.in_grid(P);
        }
    }
    assert!(
        reentered && a.in_grid(P) && a.in_grid(C0) && a.in_grid(C1),
        "P is back beside the split's children"
    );
    let head = handoff::head(&a.state(), &shard(P)).unwrap().unwrap();
    assert!(matches!(
        handoff::status(&a.state(), &head.id().unwrap()).unwrap(),
        handoff::Status::Closed(_)
    ));
}

/// Both stores split P; then the children merge back into 1‖1, proposed in
/// unsorted order, optionally with a prover joining both children
/// (`shared`) and optionally with the proposing frame's record (`record`).
/// The second store loses the merge's record once it is scheduled, and is
/// asked to scan at the next frame (a trigger).
fn merge_run(record: bool, shared: bool) -> (World, World, Vec<(u64, Observed, Observed)>, usize) {
    let (a, b, _) = split_lifecycle(|_, _| {}, false);
    let start = (ACTIVATION / EPOCH + 20) * EPOCH;
    let merge = merge_of_children(start + 1);
    let both = vec![shard(C0), shard(C1)];
    let mut lost_at = None;
    let mut trace = Vec::new();
    'run: for epoch in start / EPOCH..start / EPOCH + 30 {
        for frame in frames(epoch) {
            if frame == start + 1 {
                for w in [&a, &b] {
                    w.propose(&merge);
                    if record {
                        w.record_merge_frame(&merge);
                    }
                }
            }
            let messages = |state: &HypergraphState| {
                if shared && frame == start {
                    seed_on_each(state, 0x50, &both);
                }
            };
            let observed_a = a.step_with(frame, messages);
            let observed_b = b.step_with(frame, messages);
            if lost_at.is_none()
                && handoff::schedule::topology_request(&b.state(), &merge)
                    .unwrap()
                    .is_some()
            {
                lost_at = Some(frame);
                b.lose_pending();
                intrinsic::request_pending_repair();
            }
            trace.push((
                frame,
                observed_a,
                Observed {
                    roots: observed_b.roots,
                    ..b.observe()
                },
            ));
            if a.in_grid(BRANCH) && frame % EPOCH == 9 {
                break 'run;
            }
        }
    }
    let lost_at = lost_at.expect("the merge was scheduled");
    let at = trace
        .iter()
        .position(|(frame, _, _)| *frame == lost_at)
        .unwrap();
    assert_ne!(trace[at].1.pending, trace[at].2.pending, "lost");
    assert!(
        a.in_grid(BRANCH) && !a.in_grid(C0) && !a.in_grid(C1),
        "merged"
    );
    (a, b, trace, at)
}

/// The merge of P's split children back into 1‖1, children unsorted.
fn merge_of_children(proposed: u64) -> PendingShardChange {
    let children = vec![shard(C1), shard(C0)];
    assert!(children[0] > children[1]);
    PendingShardChange {
        kind: ShardChangeKind::Merge,
        parent: shard(BRANCH),
        children,
        effective_epoch: proposed / EPOCH + 2,
        proposed_frame: proposed,
    }
}

#[test]
fn a_restored_merge_moves_allocations_in_the_proposal_order() {
    // The proposal's order comes from the frame record.
    let (a, b, trace, at) = merge_run(true, true);
    for (frame, observed_a, observed_b) in &trace[at + 1..] {
        assert_eq!(
            observed_a, observed_b,
            "both stores agree after frame {frame}"
        );
    }
    // The prover's parent slot came from the last child moved: C0, the
    // proposal's second.
    let joined = Prover {
        key: vec![0x50; 897],
    };
    let from_c0 = (ACTIVATION + 11).to_be_bytes().to_vec();
    assert_eq!(
        allocation_field(&a.state(), &joined, &shard(BRANCH), "JoinFrameNumber"),
        Some(from_c0.clone())
    );
    assert_eq!(
        allocation_field(&b.state(), &joined, &shard(BRANCH), "JoinFrameNumber"),
        Some(from_c0)
    );
}

#[test]
fn a_lost_merge_without_its_frame_record_is_not_restored() {
    // Without the proposing frame's record the children's order is unknown,
    // and telling whether a prover holds two of them would take a scan of
    // every committed prover: the merge is reported, not restored, with or
    // without such a prover.
    for shared in [false, true] {
        let (_a, b, trace, at) = merge_run(false, shared);
        for (frame, observed_a, observed_b) in &trace[at + 1..] {
            assert!(
                observed_b.pending.is_empty(),
                "not restored (frame {frame}, shared {shared})"
            );
            assert!(
                observed_a.rows != observed_b.rows || observed_a.pending != observed_b.pending,
                "the second store stays diverged (frame {frame}, shared {shared})"
            );
        }
        assert!(b.in_grid(C0) && b.in_grid(C1) && !b.in_grid(BRANCH));
    }
}

/// The address and blob of a handoff record (`kind`, `key`) holding `value`,
/// as the handoff module writes them.
fn handoff_record(kind: &[u8], key: &[u8], value: &[u8]) -> ([u8; 32], Vec<u8>) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"quil/global/app-handoff/v1/");
    h.update((kind.len() as u32).to_be_bytes());
    h.update(kind);
    h.update((key.len() as u32).to_be_bytes());
    h.update(key);
    let address: [u8; 32] = h.finalize().into();
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0], value, &[], &num_bigint::BigInt::from(value.len()))
        .unwrap();
    (
        address,
        quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
    )
}

#[test]
fn a_lasting_store_error_neither_repeats_the_examination_nor_the_warning() {
    // One prover splits P, so a child gets no member and the lost split is
    // unresolved. Then shard 0's head record is corrupt: every scan fails on
    // it and asks for the next frame's scan. The unresolved verdict stays
    // settled: it is examined (and warned about) once.
    install_policy();
    let (world, _) = World::new(1);
    for epoch in ACTIVATION / EPOCH..p_split().effective_epoch + 1 {
        for frame in frames(epoch) {
            if frame == ACTIVATION + 1 {
                world.propose(&p_split());
            }
            world.step(frame);
        }
    }
    assert!(p_request(&world).is_some(), "scheduled");
    world.lose_pending();
    intrinsic::request_pending_repair();
    let base = (p_split().effective_epoch + 1) * EPOCH;
    let (address, blob) = handoff_record(b"head", &shard(&[false]), &[0xAB; 5]);
    let before = handoff::schedule::recovery_examinations();
    let failures = intrinsic::pending_repair_failures();
    // Frames off the eight-frame session pass, which would read the corrupt
    // head too and fail the frame.
    world.step_with(base + 1, |state| {
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &address,
                &vertex_adds_discriminator().unwrap(),
                base + 1,
                blob.clone(),
            )
            .unwrap();
    });
    let first = handoff::schedule::recovery_examinations();
    assert_eq!(first, before + 1, "the lost split is examined once");
    for frame in base + 2..base + 8 {
        world.step(frame);
    }
    assert_eq!(
        handoff::schedule::recovery_examinations(),
        first,
        "no repeated examination (key search, warning) while the error lasts"
    );
    assert_eq!(
        intrinsic::pending_repair_failures(),
        failures + 7,
        "every one of the seven scans hit the corrupt head"
    );
    assert!(world.observe().pending.is_empty(), "not restored");
}

#[test]
fn a_split_parent_brought_back_through_an_ancestor_is_not_split_again() {
    // F = 1‖1 splits (R1); its children merge with the rest of the
    // application into the root (R2, governed); the root splits with 1 as an
    // unmanned spine (R3); then an ungoverned split of 1 registers F again.
    // F's head is still closed for R1, with no later reservation, and none of
    // R1's targets nor anything overlapping F is in the grid. Only R1's
    // children's heads, closed for R2, show that R1 applied.
    install_policy();
    let f: &[bool] = &[true, true];
    let rows: &[&[bool]] = &[&[false], &[true, false], f];
    let (on, _) = World::new_on(5, rows, f);
    let (mut off, _) = World::new_on(5, rows, f);
    off.repair_off = true;
    let split = |parent: &[bool], children: &[&[bool]], frame: u64| PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: shard(parent),
        children: children.iter().map(|bits| shard(bits)).collect(),
        effective_epoch: frame / EPOCH + 2,
        proposed_frame: frame,
    };
    let f0: &[bool] = &[true, true, false];
    let f1: &[bool] = &[true, true, true];
    let mut step = 0;
    let mut reentered = None;
    for epoch in ACTIVATION / EPOCH..ACTIVATION / EPOCH + 40 {
        for frame in frames(epoch) {
            let proposal = match step {
                0 if frame == ACTIVATION + 1 => Some(split(f, &[f0, f1], frame)),
                1 if on.in_grid(f0) && !on.in_grid(f) => Some(PendingShardChange {
                    kind: ShardChangeKind::Merge,
                    parent: shard(&[]),
                    children: [&[false][..], &[true, false], f0, f1]
                        .iter()
                        .map(|bits| shard(bits))
                        .collect(),
                    effective_epoch: frame / EPOCH + 2,
                    proposed_frame: frame,
                }),
                2 if on.in_grid(&[]) => Some(split(&[], &[&[false, false], &[false, true]], frame)),
                3 if on.in_grid(&[true]) => Some(split(&[true], &[&[true, false], f], frame)),
                _ => None,
            };
            if let Some(change) = proposal {
                step += 1;
                on.propose(&change);
                off.propose(&change);
            }
            intrinsic::request_pending_repair();
            let observed_on = on.step(frame);
            let observed_off = off.step(frame);
            assert_eq!(
                observed_on, observed_off,
                "the repair leaves F alone at frame {frame}"
            );
            if step == 4 && reentered.is_none() && on.in_grid(f) {
                reentered = Some(epoch);
            }
        }
        if reentered.is_some_and(|at| epoch > at + 1) {
            break;
        }
    }
    assert!(reentered.is_some(), "F is back in the grid (step {step})");
    let state = on.state();
    let head = handoff::head(&state, &shard(f)).unwrap().unwrap();
    assert!(matches!(
        handoff::status(&state, &head.id().unwrap()).unwrap(),
        handoff::Status::Closed(_)
    ));
    assert!(on.in_grid(f) && !on.in_grid(f0) && !on.in_grid(f1));
}

#[test]
fn a_record_lost_while_a_split_parent_splits_again_is_restored() {
    // P splits into its halves (R1), they merge back (M0), and P splits into
    // the same halves again (R2). Until R2 activates, its targets' heads are
    // R1's sessions, closed for M0: no sign that R2 applied. The second store
    // loses R2's record right after it is scheduled.
    install_policy();
    let (a, _) = World::new(5);
    let (b, _) = World::new(5);
    let halves: [&[bool]; 2] = [&[true, false], &[true, true]];
    let change = |kind, frame: u64| PendingShardChange {
        kind,
        parent: shard(P),
        children: halves.iter().map(|bits| shard(bits)).collect(),
        effective_epoch: frame / EPOCH + 2,
        proposed_frame: frame,
    };
    let mut step = 0;
    let mut lost_at = None;
    let mut trace = Vec::new();
    'run: for epoch in ACTIVATION / EPOCH..ACTIVATION / EPOCH + 40 {
        for frame in frames(epoch) {
            let proposal = match step {
                0 if frame == ACTIVATION + 1 => Some(change(ShardChangeKind::Split, frame)),
                1 if a.in_grid(halves[0]) && !a.in_grid(P) => {
                    Some(change(ShardChangeKind::Merge, frame))
                }
                2 if a.in_grid(P) && a.observe().pending.is_empty() => {
                    Some(change(ShardChangeKind::Split, frame))
                }
                _ => None,
            };
            if let Some(proposed) = proposal {
                step += 1;
                a.propose(&proposed);
                b.propose(&proposed);
            }
            let observed_a = a.step(frame);
            let observed_b = b.step(frame);
            if step == 3 && lost_at.is_none() {
                let scheduled = b.observe().pending.iter().any(|pending| {
                    handoff::schedule::topology_request(&b.state(), pending)
                        .unwrap()
                        .is_some()
                });
                if scheduled {
                    lost_at = Some(frame);
                    b.lose_pending();
                    intrinsic::request_pending_repair();
                }
            }
            trace.push((
                frame,
                observed_a,
                Observed {
                    roots: observed_b.roots,
                    ..b.observe()
                },
            ));
            if lost_at.is_some() && !a.in_grid(P) && frame % EPOCH == 9 {
                break 'run;
            }
        }
    }
    let lost_at = lost_at.expect("R2 was scheduled");
    let at = trace
        .iter()
        .position(|(frame, _, _)| *frame == lost_at)
        .unwrap();
    assert_ne!(trace[at].1.pending, trace[at].2.pending, "lost");
    for (frame, observed_a, observed_b) in &trace[at + 1..] {
        assert_eq!(
            observed_a, observed_b,
            "restored at the next frame; both stores agree after frame {frame}"
        );
    }
    assert!(
        !b.in_grid(P) && b.in_grid(halves[0]) && b.in_grid(halves[1]),
        "R2 flipped in both"
    );
}

#[test]
fn a_stale_split_whose_children_changed_committees_is_restored() {
    // #814's shape: both stores split P; afterwards C0's committee is
    // replaced by a membership successor and C1's is still closing for one.
    // Then the second store's grid is rewound to P. A head closing for a
    // request that names the child itself is no sign the child was split or
    // merged away: the split is restored and flips again.
    let (a, b, _) = split_lifecycle(|_, _| {}, false);
    let start = (ACTIVATION / EPOCH + 8) * EPOCH;
    let mut done = None;
    for epoch in start / EPOCH..start / EPOCH + 12 {
        for frame in frames(epoch) {
            let messages = |state: &HypergraphState| {
                if frame == start + 1 {
                    seed(state, 0x60, 1, &shard(C0));
                }
                if frame == start + 4 * EPOCH + 1 {
                    seed(state, 0x61, 1, &shard(C1));
                }
            };
            a.step_with(frame, messages);
            b.step_with(frame, messages);
        }
        let state = a.state();
        let replaced = handoff::head(&state, &shard(C0))
            .unwrap()
            .unwrap()
            .generation
            >= 2;
        let closing = handoff::schedule::retiring_request(&state, &shard(C1)).unwrap();
        if replaced && closing.is_some() {
            done = Some((epoch, closing.unwrap()));
            break;
        }
    }
    let (epoch, closing) = done.expect("C0's successor is live and C1's is closing");
    let request = handoff::request(&a.state(), &closing).unwrap().unwrap();
    assert!(
        request
            .targets
            .iter()
            .any(|target| target.committee.filter == shard(C1)),
        "C1 closes for its own successor"
    );
    b.edit_grid(&[row(P)], &[row(SPINE), row(C0), row(C1)]);
    intrinsic::request_pending_repair();
    let next = epoch * EPOCH + 10;
    let observed_a = a.step(next);
    let observed_b = b.step(next);
    assert_eq!(
        observed_a.rows, observed_b.rows,
        "restored and flipped again"
    );
    assert_eq!(observed_a.pending, observed_b.pending);
    assert!(!b.in_grid(P) && b.in_grid(C0) && b.in_grid(C1));
}
