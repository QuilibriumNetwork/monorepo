// Included in prover_registry::tests: the seniority penalty pass (#976) on
// real registry record fixtures.

const PENALTY_EPOCH: u64 = 2_000;
const ALLOC_CLS: &str = "allocation:ProverAllocation";

/// Seed a Leaving allocation of `prover_byte` on `filter`, keyed
/// `make_vertex_key(alloc_byte)`: proposed at `leave_frame`, confirmed at
/// `confirm_frame` (0: unconfirmed), renewed for `epoch`.
#[allow(clippy::too_many_arguments)]
fn seed_leaving(
    store: &RocksHypergraphStore,
    shard: &ShardKey,
    prover_byte: u8,
    alloc_byte: u8,
    filter: &[u8],
    leave_frame: u64,
    confirm_frame: u64,
    epoch: u64,
) {
    let alloc = build_sub_tree(vec![
        type_hash_leaf(ALLOC_CLS),
        field_leaf(ALLOC_CLS, "Prover", vec![prover_byte; 32]),
        field_leaf(ALLOC_CLS, "Status", vec![3u8]),
        field_leaf(ALLOC_CLS, "ConfirmationFilter", filter.to_vec()),
        field_leaf(ALLOC_CLS, "LeaveFrameNumber", leave_frame.to_be_bytes().to_vec()),
        field_leaf(ALLOC_CLS, "LeaveConfirmFrameNumber", confirm_frame.to_be_bytes().to_vec()),
        field_leaf(ALLOC_CLS, "LastActiveFrameNumber", confirm_frame.to_be_bytes().to_vec()),
        field_leaf(ALLOC_CLS, "Epoch", epoch.to_be_bytes().to_vec()),
    ]);
    store
        .save_vertex_underlying("vertex", "adds", shard, &make_vertex_key(alloc_byte), &alloc)
        .unwrap();
}

/// An Active allocation of `prover_byte` on `filter`, current at `frame`,
/// that missed `missed` consecutive frames of its committee.
fn seed_missed(
    store: &RocksHypergraphStore,
    shard: &ShardKey,
    prover_byte: u8,
    alloc_byte: u8,
    filter: &[u8],
    frame: u64,
    missed: u64,
) {
    let alloc = build_sub_tree(vec![
        type_hash_leaf(ALLOC_CLS),
        field_leaf(ALLOC_CLS, "Prover", vec![prover_byte; 32]),
        field_leaf(ALLOC_CLS, "Status", vec![1u8]),
        field_leaf(ALLOC_CLS, "ConfirmationFilter", filter.to_vec()),
        field_leaf(ALLOC_CLS, "LastActiveFrameNumber", frame.to_be_bytes().to_vec()),
        field_leaf(ALLOC_CLS, "Epoch", quil_types::consensus::epoch_for_frame(frame).to_be_bytes().to_vec()),
        field_leaf(ALLOC_CLS, "AbsentFrameCount", missed.to_be_bytes().to_vec()),
    ]);
    store
        .save_vertex_underlying("vertex", "adds", shard, &make_vertex_key(alloc_byte), &alloc)
        .unwrap();
}

fn u64_field(tree: &VectorCommitmentTree, cls: &str, field: &str) -> u64 {
    crate::global_schema::read_field(tree, cls, field)
        .map(|b| u64::from_be_bytes(b[..8].try_into().unwrap()))
        .unwrap_or(0)
}

/// Run the pass at `frame` with penalties from `epoch` on this thread.
fn penalty_pass(
    shared: &SharedProverRegistry,
    state: &crate::hypergraph_state::HypergraphState,
    store: &RocksHypergraphStore,
    frame: u64,
    epoch: Option<u64>,
) -> SeniorityPenaltyPass {
    quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(epoch);
    let pass = shared.apply_seniority_penalties(frame, state, Some(store)).unwrap();
    quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    pass
}

/// A shard with `others` fresh members at the boundary of `PENALTY_EPOCH`,
/// and prover 0x57 (seniority `seniority`) whose confirmed leave departs at
/// that boundary, renewed for its leave's epoch.
fn departure_fixture(others: u64, seniority: u64) -> (tempfile::TempDir, Arc<RocksHypergraphStore>, SharedProverRegistry, u64, u64) {
    departure_fixture_confirmed(others, seniority, true)
}

/// [`departure_fixture`], the leave confirmed or never confirmed (it then
/// expires at the same boundary).
fn departure_fixture_confirmed(
    others: u64,
    seniority: u64,
    confirmed: bool,
) -> (tempfile::TempDir, Arc<RocksHypergraphStore>, SharedProverRegistry, u64, u64) {
    let departure = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH);
    let leave = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH - 2) + 10;
    let confirm = if confirmed { quil_types::consensus::epoch_start_frame(PENALTY_EPOCH - 1) + 5 } else { 0 };
    let filter = vec![0x71u8; 64];
    let (tmp, store) = temp_store();
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    seed_prover(&store, &shard, 0x57, seniority);
    seed_leaving(&store, &shard, 0x57, 0xA7, &filter, leave, confirm, PENALTY_EPOCH - 2);
    for i in 0..others {
        seed_active_filler(&store, &shard, &filter, departure, 0xE0 + i as u8);
    }
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(store.as_ref()).unwrap();
    (tmp, store, shared, departure, leave)
}

#[test]
fn halt_risk_departure_costs_one_epoch_of_seniority_once() {
    let (_tmp, store, shared, departure, leave) = departure_fixture(3, 10_000);
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    let state = empty_state();
    let pass = penalty_pass(&shared, &state, &store, departure, Some(PENALTY_EPOCH));
    assert_eq!(pass.departures.len(), 1);
    assert_eq!(pass.penalties, vec![SeniorityPenalty {
        prover_address: vec![0x57; 32],
        confirmation_filter: vec![0x71; 64],
        amount: 7_200,
        leave_frame: leave,
        remaining: 3,
    }]);
    assert!(pass.evicted.is_empty());
    let prover = read_global_vertex(&state, &store, &shard, 0x57);
    assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), 2_800);
    assert_eq!(u64_field(&prover, "prover:Prover", "SeniorityPenalty"), 7_200);
    let alloc = read_global_vertex(&state, &store, &shard, 0xA7);
    assert_eq!(u64_field(&alloc, ALLOC_CLS, "LeavePenaltyFrameNumber"), leave);
    assert_eq!(shared.get_prover_info(&[0x57u8; 32]).unwrap().unwrap().seniority, 2_800);

    // A later pass in the same epoch (a node restarted mid-epoch)
    // decides nothing again.
    let again = penalty_pass(&shared, &state, &store, departure + 5, Some(PENALTY_EPOCH));
    assert_eq!(again, SeniorityPenaltyPass::default());
    let prover = read_global_vertex(&state, &store, &shard, 0x57);
    assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), 2_800);
}

/// A leave never confirmed expires and departs at the same boundary a
/// confirmed one would: it costs the same, once, and nothing before the
/// penalty epoch.
#[test]
fn an_expired_unconfirmed_leave_costs_like_a_confirmed_one() {
    for (epoch, charged) in [(None, 10_000u64), (Some(PENALTY_EPOCH), 2_800)] {
        let (_tmp, store, shared, departure, leave) = departure_fixture_confirmed(3, 10_000, false);
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let state = empty_state();
        let pass = penalty_pass(&shared, &state, &store, departure, epoch);
        let again = penalty_pass(&shared, &state, &store, departure + 5, epoch);
        assert_eq!(pass.penalties.len(), usize::from(epoch.is_some()), "epoch {epoch:?}");
        assert!(again.is_empty(), "decided once; epoch {epoch:?}");
        let prover = read_global_vertex(&state, &store, &shard, 0x57);
        assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), charged, "epoch {epoch:?}");
        if epoch.is_some() {
            assert_eq!((pass.penalties[0].leave_frame, pass.penalties[0].remaining), (leave, 3));
        }
    }
}

#[test]
fn a_departure_that_keeps_four_provers_is_decided_without_a_charge() {
    let (_tmp, store, shared, departure, leave) = departure_fixture(4, 10_000);
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    let state = empty_state();
    let pass = penalty_pass(&shared, &state, &store, departure, Some(PENALTY_EPOCH));
    assert_eq!(pass.departures.len(), 1);
    assert_eq!(pass.departures[0].remaining, 4);
    assert!(pass.penalties.is_empty());
    let prover = read_global_vertex(&state, &store, &shard, 0x57);
    assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), 10_000);
    let alloc = read_global_vertex(&state, &store, &shard, 0xA7);
    assert_eq!(u64_field(&alloc, ALLOC_CLS, "LeavePenaltyFrameNumber"), leave);
}

#[test]
fn leaving_a_halted_shard_still_costs_and_saturates_at_zero() {
    let (_tmp, store, shared, departure, leave) = departure_fixture(0, 100);
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    let state = empty_state();
    let pass = penalty_pass(&shared, &state, &store, departure, Some(PENALTY_EPOCH));
    assert_eq!(pass.penalties.len(), 1);
    assert_eq!(pass.penalties[0].amount, 100);
    assert_eq!((pass.penalties[0].leave_frame, pass.penalties[0].remaining), (leave, 0));
    let prover = read_global_vertex(&state, &store, &shard, 0x57);
    assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), 0);
    assert_eq!(u64_field(&prover, "prover:Prover", "SeniorityPenalty"), 100, "what it took, not the penalty");
}

/// Only a leave departing at this boundary, of a seat that counted toward
/// its shard, of a prover not kicked, is decided.
#[test]
fn departures_that_took_no_prover_or_are_not_due_are_not_decided() {
    let departure = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH);
    let leave = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH - 2) + 10;
    let confirm = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH - 1) + 5;
    let filter = vec![0x72u8; 64];
    let (_tmp, store) = temp_store();
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    // Lapsed: renewed only up to the epoch before its leave.
    seed_prover(&store, &shard, 0x51, 10_000);
    seed_leaving(&store, &shard, 0x51, 0xA1, &filter, leave, confirm, PENALTY_EPOCH - 3);
    // Unconfirmed, proposed an epoch later: expires at the next boundary.
    seed_prover(&store, &shard, 0x52, 10_000);
    seed_leaving(&store, &shard, 0x52, 0xA2, &filter, departure - 700, 0, PENALTY_EPOCH - 1);
    // Confirmed in this epoch: departs at the next boundary.
    seed_prover(&store, &shard, 0x53, 10_000);
    seed_leaving(&store, &shard, 0x53, 0xA3, &filter, departure - 700, departure + 3, PENALTY_EPOCH);
    // Kicked prover: its seniority is already gone.
    let kicked = build_sub_tree(vec![
        type_hash_leaf("prover:Prover"),
        field_leaf("prover:Prover", "PublicKey", vec![0xCD; 57]),
        field_leaf("prover:Prover", "Status", vec![1u8]),
        field_leaf("prover:Prover", "Seniority", 0u64.to_be_bytes().to_vec()),
        field_leaf("prover:Prover", "KickFrameNumber", 7u64.to_be_bytes().to_vec()),
    ]);
    store.save_vertex_underlying("vertex", "adds", &shard, &make_vertex_key(0x54), &kicked).unwrap();
    seed_leaving(&store, &shard, 0x54, 0xA4, &filter, leave, confirm, PENALTY_EPOCH - 2);
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(store.as_ref()).unwrap();
    let state = empty_state();
    let pass = penalty_pass(&shared, &state, &store, departure, Some(PENALTY_EPOCH));
    assert_eq!(pass, SeniorityPenaltyPass::default());
    assert_eq!(state.changeset_len(), 0);
}

/// Inert before activation: with the epoch unset, or set later than the
/// pass, the pass reads and writes nothing, so committed state is byte for
/// byte what it was without it, though a departure and an allocation past
/// the eviction count are due. With the epoch reached, the same inputs
/// charge and evict (the check can fail).
#[test]
fn penalties_write_nothing_before_their_epoch() {
    for (epoch, writes) in [(None, false), (Some(PENALTY_EPOCH + 1), false), (Some(PENALTY_EPOCH), true)] {
        let (_tmp, store, shared, departure, _) = departure_fixture(3, 10_000);
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let other = vec![0x75u8; 64];
        seed_shard_floor(&store, &shard, &other, departure, 0xD0);
        seed_prover(&store, &shard, 0x58, 10_000);
        seed_missed(&store, &shard, 0x58, 0xA8, &other, departure, 5_000);
        shared.refresh_from_store(store.as_ref()).unwrap();
        let state = empty_state();
        let pass = penalty_pass(&shared, &state, &store, departure, epoch);
        assert_eq!(!pass.is_empty(), writes, "epoch {epoch:?}");
        assert_eq!(pass.evicted.len(), usize::from(writes), "epoch {epoch:?}");
        assert_eq!(state.changeset_len() > 0, writes, "epoch {epoch:?}");
        if !writes {
            assert_eq!(shared.get_prover_info(&[0x57u8; 32]).unwrap().unwrap().seniority, 10_000);
        }
    }
}

/// The pass evicts allocations that missed 2,160 consecutive committee
/// frames, most absent first, keeping each shard's floor, and resets their
/// count; one short of it stays. Absence itself is charged by GLOBAL
/// execution, not here.
#[test]
fn allocations_that_missed_2160_committee_frames_are_evicted_within_the_floor() {
    let frame = quil_types::consensus::epoch_start_frame(PENALTY_EPOCH) + 3;
    let filter = vec![0x76u8; 64];
    let (_tmp, store) = temp_store();
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    seed_active_filler(&store, &shard, &filter, frame, 0xE0);
    seed_active_filler(&store, &shard, &filter, frame, 0xE1);
    // Five active: the floor of four spares one, the most absent.
    for (i, missed) in [(0u8, 2_160u64), (1, 2_159), (2, 3_000)] {
        seed_prover(&store, &shard, 0x40 + i, 10_000);
        seed_missed(&store, &shard, 0x40 + i, 0xC0 + i, &filter, frame, missed);
    }
    let shared = SharedProverRegistry::new();
    shared.refresh_from_store(store.as_ref()).unwrap();
    let state = empty_state();
    let pass = penalty_pass(&shared, &state, &store, frame, Some(PENALTY_EPOCH));
    let evicted: Vec<(Vec<u8>, u64)> =
        pass.evicted.iter().map(|c| (c.prover_address.clone(), c.effective_inactive)).collect();
    assert_eq!(evicted, vec![(vec![0x42u8; 32], 3_000)]);
    let alloc = read_global_vertex(&state, &store, &shard, 0xC2);
    assert_eq!(crate::global_schema::read_field(&alloc, ALLOC_CLS, "Status").unwrap(), vec![4u8]);
    assert_eq!(u64_field(&alloc, ALLOC_CLS, "AbsentFrameCount"), 0);
    // 0x40 reached the count but the floor keeps it; 0x41 is one short.
    for byte in [0xC0u8, 0xC1] {
        let kept = read_global_vertex(&state, &store, &shard, byte);
        assert_eq!(crate::global_schema::read_field(&kept, ALLOC_CLS, "Status").unwrap(), vec![1u8]);
    }
    // With the floor spared, the next pass takes 0x40, not 0x41.
    seed_active_filler(&store, &shard, &filter, frame, 0xE2);
    seed_active_filler(&store, &shard, &filter, frame, 0xE3);
    shared.refresh_from_store(store.as_ref()).unwrap();
    let again = penalty_pass(&shared, &state, &store, frame, Some(PENALTY_EPOCH));
    let evicted: Vec<Vec<u8>> = again.evicted.iter().map(|c| c.prover_address.clone()).collect();
    assert_eq!(evicted, vec![vec![0x40u8; 32]]);
    // Seniority is untouched by the pass: absence was charged frame by frame.
    let prover = read_global_vertex(&state, &store, &shard, 0x40);
    assert_eq!(u64_field(&prover, "prover:Prover", "Seniority"), 10_000);
}
