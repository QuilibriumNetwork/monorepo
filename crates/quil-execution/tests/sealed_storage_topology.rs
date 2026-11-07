//! Sealed storage across a split or merge, from the sealed storage epoch
//! (`MAINNET_SEALED_STORAGE_EPOCH`, 1467).
//!
//! A storage seat is per member and shard. A split or merge moves the
//! members' allocations onto the shards it creates; no GLOBAL path moves a
//! seat. From the sealed storage epoch a member counts on a shard only with a
//! seat sealed there for the epoch: header admission
//! (`storage_seat::require_sealed_participant`) and committee scheduling
//! (`CommittedProverScan::active_on_filter`). A healthy network needs a shard
//! a split or merge creates to produce with its moved members from the epoch
//! it is created in.
//!
//! Each test runs GLOBAL's shard-change pass (`apply_due_shard_changes`) over
//! one store from epoch 2000, with members that follow the GLOBAL rules they
//! meet:
//! - In each epoch a member confirms, for the next epoch, each shard it holds
//!   an active allocation on and the shards a change applying then creates
//!   from it (`pre_registration_targets`, which GLOBAL's confirm honours).
//! - A shard's header executes when one of its members passes the
//!   sealed-participant gate, and records the shard's snapshot for the next
//!   epoch from the snapshot frame (`storage_snapshot::record`), as
//!   `invoke_frame_header` does after verifying.
//! - A registration seals once GLOBAL can find its data
//!   (`storage_snapshot::sources`, which `storage_epoch_proof::check_seat`
//!   requires before the STARK), for the shards the member's engines seal:
//!   with [`Seal::Engine`] as `AppEngine` does, its own shard's and those
//!   its shard's data was read for (`storage_snapshot::seals_pre_registered`),
//!   or with [`Seal::PreRegistered`] every shard it pre-registered.
//!
//! The global settings are process-wide: these tests rely on nextest running
//! each test in its own process.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use quil_execution::global_intrinsic::frame_header::FrameHeader;
use quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets;
use quil_execution::global_intrinsic::storage_seat::{self, Seat};
use quil_execution::global_intrinsic::{intrinsic::GlobalIntrinsic, materialize, storage_snapshot};
use quil_execution::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use quil_execution::hypergraph_state::{
    hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState,
};
use quil_execution::prover_registry::{
    rebuild_vertex_tree_from_blob, vertex_tree_to_blob, CommittedProverScan,
};
use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
use quil_types::error::Result;
use quil_types::store::{KvDb as _, PendingShardChange, ShardChangeKind, ShardInfo, ShardsStore};

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
/// Past the sealed storage epoch (1467), the unified cutover and every grid
/// reset, as on mainnet.
const START: u64 = 2000 * EPOCH;
const APP: [u8; 32] = [0x31; 32];
/// Epochs after the change applies through which its new shards must produce.
const HORIZON: u64 = 4;
const ALLOCATION: &str = "allocation:ProverAllocation";

/// The split parent, beside the empty shard 0.
const P: &[bool] = &[true];
/// Its children 1‖1‖0 and 1‖1‖1; the deep split also registers the spine 1‖0.
const C0: &[bool] = &[true, true, false];
const C1: &[bool] = &[true, true, true];
const SPINE: &[bool] = &[true, false];
/// The children's branch, which their merge creates.
const BRANCH: &[bool] = &[true, true];

fn shard(bits: &[bool]) -> Vec<u8> {
    quil_forest::encode_shard_bit_path(&APP, bits)
}

fn name(filter: &[u8]) -> &'static str {
    [
        (P, "1"),
        (C0, "1‖1‖0"),
        (C1, "1‖1‖1"),
        (SPINE, "1‖0"),
        (BRANCH, "1‖1"),
    ]
    .into_iter()
    .find(|(bits, _)| shard(bits) == filter)
    .map_or("?", |(_, name)| name)
}

fn row(bits: &[bool]) -> ShardInfo {
    let mut shard_key =
        quil_hypergraph::addressing::get_bloom_filter_indices(&APP, 256, 3).to_vec();
    shard_key.extend_from_slice(&APP);
    ShardInfo {
        shard_key,
        prefix: quil_forest::bit_path_to_prefix(bits),
        size: vec![],
        data_shards: 0,
        commitment: vec![],
    }
}

/// Which of a member's registrations its engines seal.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Seal {
    /// As `AppEngine` does: those of the shards it holds an active allocation
    /// on, and those of the shards it pre-registered whose data is its
    /// shard's (`storage_snapshot::seals_pre_registered`).
    Engine,
    /// Those of the shards it holds an active allocation on and of every
    /// shard it pre-registered for a change.
    PreRegistered,
}

/// What a new shard did in one epoch.
#[derive(Debug, Clone, PartialEq)]
struct EpochRow {
    epoch: u64,
    /// Members holding an active allocation on it at the epoch's end.
    members: usize,
    /// Of them, those passing the sealed-participant gate at its end.
    sealed: usize,
    /// `active_on_filter` at its end, from committed state.
    committee: usize,
    /// Whether GLOBAL executed any header of it in the epoch.
    produced: bool,
    /// Whether its snapshot for the next epoch is recorded at its end.
    next_snapshot: bool,
}

struct World {
    db: Arc<quil_store::RocksDb>,
    shards: Arc<dyn ShardsStore>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    intrinsic: GlobalIntrinsic,
    members: Vec<[u8; 32]>,
    seal: Seal,
    produced: RefCell<BTreeSet<(Vec<u8>, u64)>>,
    app_frame: RefCell<u64>,
}

impl World {
    /// A store whose grid holds `rows`, with a member on each `(n, shard)`
    /// sealed there for the first epoch.
    fn new(rows: &[&[bool]], seeds: &[(u8, &[bool])], seal: Seal) -> Self {
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
            .with_clock_store(clock);
        let txn = db.new_batch(false).unwrap();
        for bits in rows {
            shards.put_app_shard(txn.as_ref(), &row(bits)).unwrap();
        }
        txn.commit().unwrap();
        let state = HypergraphState::new(crdt.clone());
        let first = START / EPOCH;
        let members = seeds
            .iter()
            .map(|(n, bits)| {
                let member = seed(&state, *n, 10 + u64::from(*n) * 7, &shard(bits));
                let mut seat = Seat::new(member, shard(bits));
                seat.register(first, &[vec![0]], START - 10);
                assert!(seat.seal(first, START - 5));
                storage_seat::write(&state, 1, &seat).unwrap();
                member
            })
            .collect();
        state.commit().unwrap();
        state.abort();
        crdt.commit(1).unwrap();
        Self {
            db,
            shards,
            crdt,
            intrinsic,
            members,
            seal,
            produced: RefCell::new(BTreeSet::new()),
            app_frame: RefCell::new(0),
        }
    }

    fn propose(&self, change: &PendingShardChange) {
        let txn = self.db.new_batch(false).unwrap();
        self.shards
            .put_pending_shard_change(txn.as_ref(), change)
            .unwrap();
        txn.commit().unwrap();
    }

    /// The shards each member holds an active allocation on, in `state`.
    fn holdings(&self, state: &HypergraphState) -> BTreeMap<Vec<u8>, Vec<[u8; 32]>> {
        let va = vertex_adds_discriminator().unwrap();
        let ha = hyperedge_adds_discriminator().unwrap();
        let mut on: BTreeMap<Vec<u8>, Vec<[u8; 32]>> = BTreeMap::new();
        for member in &self.members {
            let hyperedge = state
                .get(&GLOBAL_INTRINSIC_ADDRESS[..], member, &ha)
                .unwrap()
                .unwrap_or_default();
            for allocation in materialize::hyperedge_allocation_addresses(&hyperedge).unwrap() {
                let Some(blob) = state
                    .get(&GLOBAL_INTRINSIC_ADDRESS[..], &allocation, &va)
                    .unwrap()
                    .filter(|blob| !blob.is_empty())
                else {
                    continue;
                };
                let tree = rebuild_vertex_tree_from_blob(&blob);
                let active = read_field(&tree, ALLOCATION, "Status")
                    .is_some_and(|status| status.first() == Some(&materialize::STATUS_ACTIVE));
                if let (true, Some(filter)) =
                    (active, read_field(&tree, ALLOCATION, "ConfirmationFilter"))
                {
                    on.entry(filter).or_default().push(*member);
                }
            }
        }
        on
    }

    /// What the members do in GLOBAL frame `frame`, before GLOBAL's pass.
    fn act(&self, state: &HypergraphState, frame: u64) {
        let epoch = frame / EPOCH;
        let next = epoch + 1;
        let pending = self.shards.all_pending_shard_changes().unwrap();
        let on = self.holdings(state);
        // Headers: one per shard with a member GLOBAL admits.
        for (filter, members) in &on {
            let admitted = members.iter().any(|member| {
                storage_seat::require_sealed_participant(state, member, filter, frame, epoch)
                    .is_ok()
            });
            if !admitted {
                continue;
            }
            self.produced.borrow_mut().insert((filter.clone(), epoch));
            let mut app_frame = self.app_frame.borrow_mut();
            *app_frame += 1;
            let header = FrameHeader {
                address: filter.clone(),
                frame_number: *app_frame,
                global_frame_number: frame,
                state_roots: vec![vec![(frame % 251) as u8; 32]; 4],
                ..Default::default()
            };
            storage_snapshot::record(state, frame, &header).unwrap();
        }
        let lookup = |filter: &[u8]| storage_snapshot::read(state, next, filter).ok().flatten();
        for (filter, members) in &on {
            let targets = pre_registration_targets(&pending, std::slice::from_ref(filter), next);
            for member in members {
                // Confirms: the held shard and the shards it pre-registers.
                for shard in std::iter::once(filter).chain(&targets) {
                    let mut seat = storage_seat::read(state, member, shard)
                        .unwrap()
                        .unwrap_or_else(|| Seat::new(*member, shard.clone()));
                    if seat.slot(next).is_none() {
                        seat.register(next, &[vec![0]], frame);
                        storage_seat::write(state, frame, &seat).unwrap();
                    }
                }
                // Seals, late in the epoch, once GLOBAL can read the data.
                if frame % EPOCH < 300 {
                    continue;
                }
                let sealing: Vec<Vec<u8>> = match self.seal {
                    Seal::Engine => std::iter::once(filter.clone())
                        .chain(
                            targets
                                .iter()
                                .filter(|shard| {
                                    storage_snapshot::sources(shard, next, &pending, lookup)
                                        .is_some_and(|sources| {
                                            storage_snapshot::seals_pre_registered(
                                                filter, shard, &sources, next,
                                            )
                                        })
                                })
                                .cloned(),
                        )
                        .collect(),
                    Seal::PreRegistered => {
                        std::iter::once(filter).chain(&targets).cloned().collect()
                    }
                };
                for shard in &sealing {
                    let Some(mut seat) = storage_seat::read(state, member, shard).unwrap() else {
                        continue;
                    };
                    let registered = seat.slot(next).map(|slot| slot.registered_at);
                    if registered.is_some_and(|at| at + 1 < frame)
                        && storage_snapshot::sources(shard, next, &pending, lookup).is_some()
                        && seat.seal(next, frame)
                    {
                        storage_seat::write(state, frame, &seat).unwrap();
                    }
                }
            }
        }
    }

    fn step(&self, frame: u64) {
        let state = HypergraphState::new(self.crdt.clone());
        self.act(&state, frame);
        self.intrinsic
            .apply_due_shard_changes(frame, &state)
            .unwrap();
        state.commit().unwrap();
        state.abort();
        self.crdt.commit(frame).unwrap();
    }

    /// `filter`'s row for the epoch of `frame`, its last stepped frame.
    fn row(&self, filter: &[u8], frame: u64) -> EpochRow {
        let epoch = frame / EPOCH;
        let state = HypergraphState::new(self.crdt.clone());
        let members = self.holdings(&state).remove(filter).unwrap_or_default();
        let sealed = members
            .iter()
            .filter(|member| {
                storage_seat::require_sealed_participant(&state, *member, filter, frame, epoch)
                    .is_ok()
            })
            .count();
        let committee = CommittedProverScan::try_scan(&self.crdt)
            .unwrap()
            .active_on_filter(filter, frame)
            .len();
        EpochRow {
            epoch,
            members: members.len(),
            sealed,
            committee,
            produced: self.produced.borrow().contains(&(filter.to_vec(), epoch)),
            next_snapshot: storage_snapshot::read(&state, epoch + 1, filter)
                .unwrap()
                .is_some(),
        }
    }
}

/// A prover with an Active allocation on `filter`, eligible for many epochs.
fn seed(state: &HypergraphState, n: u8, seniority: u64, filter: &[u8]) -> [u8; 32] {
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
    write_field(&mut allocation, ALLOCATION, "Status", &[1]).unwrap();
    write_field(
        &mut allocation,
        ALLOCATION,
        "JoinConfirmFrameNumber",
        &0u64.to_be_bytes(),
    )
    .unwrap();
    write_field(
        &mut allocation,
        ALLOCATION,
        "Epoch",
        &(START / EPOCH + 1000).to_be_bytes(),
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
    address
}

fn install(handoff: bool) {
    quil_types::consensus::set_epoch_length_frames(EPOCH);
    quil_types::consensus::set_committee_handoff_policy(handoff.then_some(
        CommitteeHandoffPolicy {
            activation_frame: START,
            chain_id: [0x51; 32],
            legacy_history: LegacyHistory::Discard,
            membership_boundary_frame: START,
            first_session_boundary_frame: u64::MAX,
        },
    ));
    assert!(
        quil_types::consensus::sealed_storage_required(START / EPOCH),
        "the run is past the sealed storage epoch"
    );
}

/// The frames stepped in `epoch`: its session pass and the gate after it,
/// the next pass, the snapshot frame and the one after, and a late frame the
/// seals land in.
fn frames(epoch: u64) -> [u64; 7] {
    let base = epoch * EPOCH;
    [
        base,
        base + 1,
        base + 8,
        base + 9,
        base + 16,
        base + 17,
        base + 300,
    ]
}

type Trace = BTreeMap<Vec<u8>, Vec<EpochRow>>;

/// Run `change` from `START + 1` and return the epoch it applied in and, for
/// each shard it creates, its rows from then through [`HORIZON`] epochs after.
fn run(
    rows: &[&[bool]],
    seeds: &[(u8, &[bool])],
    change: PendingShardChange,
    handoff: bool,
    seal: Seal,
) -> (Option<u64>, Trace) {
    install(handoff);
    let world = World::new(rows, seeds, seal);
    let created: Vec<Vec<u8>> = match change.kind {
        ShardChangeKind::Split => change.children.clone(),
        ShardChangeKind::Merge => vec![change.parent.clone()],
    };
    let mut applied = None;
    let mut trace = Trace::new();
    for epoch in START / EPOCH..START / EPOCH + 16 {
        for frame in frames(epoch) {
            if frame == START + 1 {
                world.propose(&change);
            }
            world.step(frame);
        }
        let last = frames(epoch)[6];
        if applied.is_none() {
            let held = world.holdings(&HypergraphState::new(world.crdt.clone()));
            if created.iter().any(|filter| held.contains_key(filter)) {
                applied = Some(epoch);
            }
        }
        if let Some(applied) = applied {
            for filter in &created {
                trace
                    .entry(filter.clone())
                    .or_default()
                    .push(world.row(filter, last));
            }
            if epoch >= applied + HORIZON {
                break;
            }
        }
    }
    (applied, trace)
}

/// Fail unless every shard the change created produced with a committee in
/// every traced epoch, naming what each epoch saw.
fn assert_produces(what: &str, applied: Option<u64>, trace: &Trace) {
    let applied = applied.unwrap_or_else(|| panic!("{what}: the change never applied"));
    let mut failures = Vec::new();
    for (filter, rows) in trace {
        let dead: Vec<u64> = rows
            .iter()
            .filter(|row| !row.produced || row.committee == 0)
            .map(|row| row.epoch)
            .collect();
        if dead.is_empty() {
            continue;
        }
        let first = rows.iter().find(|row| row.produced && row.committee > 0);
        let detail: Vec<String> = rows
            .iter()
            .map(|row| {
                format!(
                    "epoch {}: {} members, {} sealed, committee {}, {}, next snapshot {}",
                    row.epoch,
                    row.members,
                    row.sealed,
                    row.committee,
                    if row.produced {
                        "produced"
                    } else {
                        "no header admitted"
                    },
                    if row.next_snapshot {
                        "recorded"
                    } else {
                        "none"
                    }
                )
            })
            .collect();
        failures.push(format!(
            "shard {} produced nothing in epochs {:?} ({}); {}",
            name(filter),
            dead,
            match first {
                Some(row) => format!("first produced in epoch {}", row.epoch),
                None => format!("never within {HORIZON} epochs of the change"),
            },
            detail.join("; ")
        ));
    }
    assert!(
        failures.is_empty(),
        "{what} applied in epoch {applied} (sealed storage from epoch 1467): {}",
        failures.join(" | ")
    );
}

/// The deep split of P, proposed early in the first epoch.
fn p_split() -> PendingShardChange {
    PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: shard(P),
        children: vec![shard(C0), shard(C1)],
        effective_epoch: (START + 1) / EPOCH + 2,
        proposed_frame: START + 1,
    }
}

/// The merge of 1‖1‖0 and 1‖1‖1 into 1‖1, children unsorted.
fn branch_merge() -> PendingShardChange {
    PendingShardChange {
        kind: ShardChangeKind::Merge,
        parent: shard(BRANCH),
        children: vec![shard(C1), shard(C0)],
        effective_epoch: (START + 1) / EPOCH + 2,
        proposed_frame: START + 1,
    }
}

const SPLIT_ROWS: &[&[bool]] = &[&[false], P];
const SPLIT_SEEDS: &[(u8, &[bool])] = &[(0x10, P), (0x11, P), (0x12, P), (0x13, P)];
const MERGE_ROWS: &[&[bool]] = &[&[false], SPINE, C0, C1];
const MERGE_SEEDS: &[(u8, &[bool])] = &[(0x10, C0), (0x11, C0), (0x12, C1), (0x13, C1)];

/// (a) A split at its effective epoch (no committee handoff: the change
/// applies at the epoch's first frame, as when the parent seals at once).
/// Members confirm and seal as their engines do.
#[test]
fn a_split_child_produces_with_its_moved_members_past_the_sealed_storage_epoch() {
    let (applied, trace) = run(SPLIT_ROWS, SPLIT_SEEDS, p_split(), false, Seal::Engine);
    assert_produces("the split of 1", applied, &trace);
}

/// (b) The same for a merge.
#[test]
fn a_merged_shard_produces_with_its_moved_members_past_the_sealed_storage_epoch() {
    let (applied, trace) = run(MERGE_ROWS, MERGE_SEEDS, branch_merge(), false, Seal::Engine);
    assert_produces("the merge into 1‖1", applied, &trace);
}

/// (a) through committee handoff, the mainnet path: the change applies once
/// its sources seal or are fenced, which can be after its effective epoch.
/// Members seal even their pre-registered shards, the most GLOBAL admits.
#[test]
fn a_split_through_committee_handoff_keeps_its_children_producing() {
    let (applied, trace) = run(
        SPLIT_ROWS,
        SPLIT_SEEDS,
        p_split(),
        true,
        Seal::PreRegistered,
    );
    assert_produces("the split of 1 through handoff", applied, &trace);
}

/// (b) through committee handoff.
#[test]
fn a_merge_through_committee_handoff_keeps_the_merged_shard_producing() {
    let (applied, trace) = run(
        MERGE_ROWS,
        MERGE_SEEDS,
        branch_merge(),
        true,
        Seal::PreRegistered,
    );
    assert_produces("the merge into 1‖1 through handoff", applied, &trace);
}

/// Control for (a): when members seal every child seat they
/// pre-registered, which GLOBAL admits from the parent's snapshot, the
/// children produce from the split's epoch on. (a) differs from it only in
/// sealing by the engines' rule, so it fails when that rule leaves a seat
/// the children need unsealed.
#[test]
fn sealing_pre_registered_seats_keeps_a_split_child_producing() {
    let (applied, trace) = run(
        SPLIT_ROWS,
        SPLIT_SEEDS,
        p_split(),
        false,
        Seal::PreRegistered,
    );
    assert_eq!(applied, Some(p_split().effective_epoch));
    assert_produces(
        "the split of 1, pre-registered seats sealed",
        applied,
        &trace,
    );
}

/// Control for (b).
#[test]
fn sealing_pre_registered_seats_keeps_a_merged_shard_producing() {
    let (applied, trace) = run(
        MERGE_ROWS,
        MERGE_SEEDS,
        branch_merge(),
        false,
        Seal::PreRegistered,
    );
    assert_eq!(applied, Some(branch_merge().effective_epoch));
    assert_produces(
        "the merge into 1‖1, pre-registered seats sealed",
        applied,
        &trace,
    );
}
