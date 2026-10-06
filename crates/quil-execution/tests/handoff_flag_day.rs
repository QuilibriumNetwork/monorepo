//! The committee-handoff flag day (`LegacyHistory::Discard`, mainnet's
//! policy): the first session pass from activation records a ring key on every
//! allocation, gives an application without grid shards its root shard, moves
//! off-grid allocations onto the grid, and authorizes first sessions whose
//! rings rank earlier cohorts first, then the most senior.
//!
//! One test per binary: the committee-handoff policy is process-global.

use std::sync::Arc;

use quil_execution::global_intrinsic::{handoff, intrinsic::GlobalIntrinsic, materialize, prover_rings};
use quil_execution::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use quil_execution::hypergraph_state::{hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState};
use quil_execution::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};
use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
use quil_types::error::Result;
use quil_types::store::{KvDb as _, ShardInfo, ShardsStore};

struct AcceptAll;
impl quil_types::crypto::KeyManager for AcceptAll {
    fn validate_signature(&self, _: quil_types::crypto::KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
        Ok(true)
    }
}

const EPOCH: u64 = 720;
const ACTIVATION: u64 = 10 * EPOCH;

struct Prover {
    key: Vec<u8>,
    address: [u8; 32],
}

/// A prover with `seniority` and an Active allocation on each of `filters`,
/// confirmed at `confirmed` (0: a genesis allocation) and current through the
/// activation epoch.
fn seed(state: &HypergraphState, n: u8, seniority: u64, filters: &[(&[u8], u64)]) -> Prover {
    let va = vertex_adds_discriminator().unwrap();
    let key = vec![n; 897];
    let address = materialize::prover_address_from_pubkey(&key).unwrap();
    let mut prover = materialize::create_prover_vertex_tree(&key, seniority).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[1]).unwrap();
    state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va, 1, vertex_tree_to_blob(&prover)).unwrap();
    let mut atoms = Vec::new();
    for (filter, confirmed) in filters {
        let allocation_address = materialize::allocation_address(&key, filter).unwrap();
        let mut allocation = materialize::create_allocation_vertex_tree(&address, filter, 1).unwrap();
        let class = "allocation:ProverAllocation";
        write_field(&mut allocation, class, "Status", &[1]).unwrap();
        write_field(&mut allocation, class, "JoinConfirmFrameNumber", &confirmed.to_be_bytes()).unwrap();
        write_field(&mut allocation, class, "Epoch", &(ACTIVATION / EPOCH).to_be_bytes()).unwrap();
        state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &allocation_address, &va, 1, vertex_tree_to_blob(&allocation)).unwrap();
        atoms.push((allocation_address, allocation));
    }
    let refs: Vec<_> = atoms.iter().map(|(a, t)| (*a, t)).collect();
    let blob = materialize::build_prover_allocation_hyperedge_blob(&address, &refs).unwrap();
    state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &hyperedge_adds_discriminator().unwrap(), 1, blob).unwrap();
    Prover { key, address }
}

fn allocation(state: &HypergraphState, prover: &Prover, filter: &[u8]) -> Option<quil_tries::VectorCommitmentTree> {
    let address = materialize::allocation_address(&prover.key, filter).unwrap();
    state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &vertex_adds_discriminator().unwrap()).unwrap()
        .filter(|blob| !blob.is_empty())
        .map(|blob| rebuild_vertex_tree_from_blob(&blob))
}

fn status(state: &HypergraphState, prover: &Prover, filter: &[u8]) -> Option<u8> {
    allocation(state, prover, filter)
        .and_then(|tree| read_field(&tree, "allocation:ProverAllocation", "Status"))
        .and_then(|bytes| bytes.first().copied())
}

fn key(state: &HypergraphState, prover: &Prover, filter: &[u8]) -> Option<prover_rings::RingKey> {
    allocation(state, prover, filter).and_then(|tree| prover_rings::read_key(&tree))
}

fn grid_key(app: &[u8; 32]) -> Vec<u8> {
    let mut key = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3).to_vec();
    key.extend_from_slice(app);
    key
}

/// Every test in this binary installs the same policy.
fn install_policy() {
    quil_types::consensus::set_epoch_length_frames(EPOCH);
    quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
        activation_frame: ACTIVATION,
        chain_id: [0x51; 32],
        legacy_history: LegacyHistory::Discard, membership_boundary_frame: u64::MAX
    }));
}

#[test]
fn the_flag_day_keys_allocations_moves_off_grid_ones_and_seats_seniority_rings() {
    install_policy();

    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    let state = HypergraphState::new(crdt.clone());
    let intrinsic = GlobalIntrinsic::new(Arc::new(AcceptAll))
        .with_shards_store(shards.clone())
        .with_shards_db(db.clone())
        .with_hypergraph(crdt.clone());

    // The grid: application A split once. Application G has no grid shard.
    let app = [0x31u8; 32];
    let gridless = [0x41u8; 32];
    let left = quil_forest::encode_shard_bit_path(&app, &[false]);
    let right = quil_forest::encode_shard_bit_path(&app, &[true]);
    let below_left = quil_forest::encode_shard_bit_path(&app, &[false, true]);
    let gridless_child = quil_forest::encode_shard_bit_path(&gridless, &[true]);
    {
        let txn = db.new_batch(false).unwrap();
        for bits in [[false], [true]] {
            shards.put_app_shard(txn.as_ref(), &ShardInfo {
                shard_key: grid_key(&app),
                prefix: quil_forest::bit_path_to_prefix(&bits),
                size: vec![],
                data_shards: 0,
                commitment: vec![],
            }).unwrap();
        }
        txn.commit().unwrap();
    }

    // Cohorts on the left shard: a genesis allocation, then two joined in
    // epoch 3 (activated in 4) of different seniority.
    let genesis = seed(&state, 1, 5, &[(&left, 0)]);
    let junior = seed(&state, 2, 10, &[(&left, 3 * EPOCH + 1)]);
    let senior = seed(&state, 3, 900, &[(&left, 3 * EPOCH + 2)]);
    // Off the grid: under the left shard, the whole application (covering
    // both shards), and a gridless application's child.
    let under = seed(&state, 4, 50, &[(&below_left, 0)]);
    let covering = seed(&state, 5, 60, &[(&app[..], 0)]);
    let stranded = seed(&state, 6, 70, &[(&gridless_child, 0)]);
    // Already on the left shard, and also off the grid under it.
    let twice = seed(&state, 7, 80, &[(&left, 0), (&below_left, 0)]);
    state.commit().unwrap();
    state.abort();
    crdt.commit(1).unwrap();
    let state = HypergraphState::new(crdt.clone());

    assert!(handoff::frames::refuse_legacy_after_flag_day(ACTIVATION - 1).is_ok());
    assert!(handoff::frames::refuse_legacy_after_flag_day(ACTIVATION).is_err(),
        "no legacy certificate is accepted from activation");
    assert!(!handoff::legacy::records_tips(&quil_types::consensus::committee_handoff_policy().unwrap(), ACTIVATION));

    intrinsic.apply_due_shard_changes(ACTIVATION, &state).unwrap();
    assert!(handoff::flag_day_applied(&state).unwrap());

    // 1. Every live allocation records a key: its join-confirm cohort and
    // its prover's seniority.
    assert_eq!(key(&state, &genesis, &left), Some(prover_rings::RingKey { cohort: 0, seniority: 5 }));
    assert_eq!(key(&state, &junior, &left), Some(prover_rings::RingKey { cohort: 4, seniority: 10 }));
    assert_eq!(key(&state, &senior, &left), Some(prover_rings::RingKey { cohort: 4, seniority: 900 }));

    // 3. Off-grid allocations moved onto the shard covering them, as a new
    // cohort; the old slots are retired; a prover already on the destination
    // keeps that allocation.
    let historic = Some(6);
    assert_eq!(status(&state, &under, &below_left), historic);
    assert_eq!(key(&state, &under, &left), Some(prover_rings::RingKey { cohort: 10, seniority: 50 }));
    assert_eq!(status(&state, &stranded, &gridless_child), historic);
    assert_eq!(key(&state, &stranded, &gridless[..]).map(|k| k.cohort), Some(10));
    assert_eq!(status(&state, &covering, &app[..]), historic);
    // Equal (empty) sizes: the first child in filter order takes the group.
    let first = std::cmp::min(left.clone(), right.clone());
    assert_eq!(key(&state, &covering, &first).map(|k| k.seniority), Some(60));
    assert_eq!(status(&state, &twice, &below_left), historic);
    assert_eq!(status(&state, &twice, &left), Some(1));

    // First sessions: the left shard's members, with rings fixed at creation:
    // the genesis cohort, then epoch 4's by seniority, then the moved ones.
    let session = handoff::head(&state, &left).unwrap().expect("first session on the left shard");
    assert_eq!((session.generation, session.base_frame), (1, 0));
    let mut expected = vec![genesis.key.clone(), junior.key.clone(), senior.key.clone(), under.key.clone(), twice.key.clone()];
    if first == left {
        expected.push(covering.key.clone());
    }
    expected.sort();
    assert_eq!(session.members, expected);
    let rings = handoff::session_rings(&state, &session.id().unwrap()).unwrap().expect("rings fixed at creation");
    let ranked: Vec<(Vec<u8>, prover_rings::RingKey)> = session.members.iter().map(|member| {
        let prover = [&genesis, &junior, &senior, &under, &twice, &covering]
            .into_iter().find(|p| &p.key == member).unwrap();
        (prover.address.to_vec(), key(&state, prover, &left).unwrap())
    }).collect();
    let borrowed: Vec<(&[u8], prover_rings::RingKey)> = ranked.iter().map(|(a, k)| (a.as_slice(), *k)).collect();
    assert_eq!(rings, prover_rings::assign(&borrowed, false));
    assert!(rings.iter().all(|ring| *ring == 0), "one ring of eight holds them all");
    assert!(handoff::head(&state, &gridless[..]).unwrap().is_some(), "the gridless application's root runs a session");

    // The flag day runs once.
    state.commit().unwrap();
    state.abort();
    crdt.commit(ACTIVATION).unwrap();
    // 2. The gridless application has its root shard, committed with the frame.
    assert!(shards.range_app_shards().unwrap().iter()
        .any(|row| row.shard_key == grid_key(&gridless) && row.prefix.is_empty()));
    let state = HypergraphState::new(crdt.clone());
    intrinsic.apply_due_shard_changes(ACTIVATION + 8, &state).unwrap();
    assert_eq!(status(&state, &twice, &left), Some(1));
}

fn put_split(shards: &Arc<dyn ShardsStore>, db: &quil_store::RocksDb, parent: &[u8], children: Vec<Vec<u8>>, epoch: u64) {
    let txn = db.new_batch(false).unwrap();
    shards.put_pending_shard_change(txn.as_ref(), &quil_types::store::PendingShardChange {
        kind: quil_types::store::ShardChangeKind::Split,
        parent: parent.to_vec(),
        children,
        effective_epoch: epoch,
        proposed_frame: u64::MAX / 2,
    }).unwrap();
    txn.commit().unwrap();
}

#[test]
fn a_split_moves_its_most_senior_provers_together_onto_its_most_valuable_child() {
    install_policy();
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    crdt.set_unified_tree(true);
    let intrinsic = GlobalIntrinsic::new(Arc::new(AcceptAll))
        .with_shards_store(shards.clone())
        .with_shards_db(db.clone())
        .with_hypergraph(crdt.clone());

    // Application state only under bit 1, deeper only under 1‖1.
    let app = [0x31u8; 32];
    for d in [0xC0u8, 0xD0, 0xE0] {
        crdt.add_vertex(&quil_hypergraph::Location { app_address: app, data_address: [d; 32] }, &[d; 256]).unwrap();
    }
    crdt.commit(0).unwrap();
    {
        let txn = db.new_batch(false).unwrap();
        shards.put_app_shard(txn.as_ref(), &ShardInfo {
            shard_key: grid_key(&app), prefix: quil_forest::bit_path_to_prefix(&[]),
            size: vec![], data_shards: 0, commitment: vec![],
        }).unwrap();
        txn.commit().unwrap();
    }
    let state = HypergraphState::new(crdt.clone());
    let seniority = [10u64, 70, 30, 60, 20];
    let provers: Vec<Prover> = seniority.iter().enumerate()
        .map(|(i, s)| seed(&state, 0x10 + i as u8, *s, &[(&app[..], 0)]))
        .collect();
    state.commit().unwrap();
    state.abort();
    crdt.commit(1).unwrap();

    // The root splits at the flag day itself, before its first session: the
    // flip moves the three most senior (70, 60, 30) onto the child with state.
    let left = quil_forest::encode_shard_bit_path(&app, &[false]);
    let right = quil_forest::encode_shard_bit_path(&app, &[true]);
    put_split(&shards, &db, &app[..], vec![left.clone(), right.clone()], ACTIVATION / EPOCH);
    let state = HypergraphState::new(crdt.clone());
    intrinsic.apply_due_shard_changes(ACTIVATION, &state).unwrap();
    let on = |filter: &[u8]| -> Vec<u64> {
        let mut found: Vec<u64> = provers.iter().zip(seniority)
            .filter(|(p, _)| status(&state, p, filter) == Some(1)).map(|(_, s)| s).collect();
        found.sort();
        found
    };
    assert_eq!(on(&right), vec![30, 60, 70], "the most senior go together to the child holding the state");
    assert_eq!(on(&left), vec![10, 20]);
    for prover in &provers {
        assert_eq!(status(&state, prover, &app[..]), Some(6), "the parent's allocations are retired");
    }
    let moved = provers.iter().find_map(|p| key(&state, p, &right)).unwrap();
    assert_eq!(moved.cohort, ACTIVATION / EPOCH, "a split's provers start one new cohort");
    state.commit().unwrap();
    state.abort();
    crdt.commit(ACTIVATION).unwrap();
    // The children's first sessions follow at the next pass, from the
    // committed allocations.
    let state = HypergraphState::new(crdt.clone());
    intrinsic.apply_due_shard_changes(ACTIVATION + 8, &state).unwrap();
    let first = handoff::head(&state, &right).unwrap().expect("the child's first session");
    assert_eq!(first.members.len(), 3);
    state.commit().unwrap();
    state.abort();
    crdt.commit(ACTIVATION + 8).unwrap();

    // A shard with a session splits through its request: the committees it
    // authorizes put the two most senior together on the grandchild with state.
    let below_left = quil_forest::encode_shard_bit_path(&app, &[true, false]);
    let below_right = quil_forest::encode_shard_bit_path(&app, &[true, true]);
    let next = ACTIVATION / EPOCH + 1;
    put_split(&shards, &db, &right, vec![below_left.clone(), below_right.clone()], next);
    let state = HypergraphState::new(crdt.clone());
    intrinsic.apply_due_shard_changes(next * EPOCH, &state).unwrap();
    let change = shards.all_pending_shard_changes().unwrap().into_iter().find(|c| c.parent == right).unwrap();
    let targets = handoff::schedule::topology_targets(&state, &change).unwrap().expect("the split is scheduled");
    let members = |filter: &[u8]| -> Vec<u64> {
        let committee = targets.iter().find(|t| t.filter == filter).unwrap();
        let mut found: Vec<u64> = provers.iter().zip(seniority)
            .filter(|(p, _)| committee.members.contains(&p.key)).map(|(_, s)| s).collect();
        found.sort();
        found
    };
    assert_eq!(members(&below_right), vec![60, 70]);
    assert_eq!(members(&below_left), vec![30]);
}
