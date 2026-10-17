// Included into `prover_registry::tests`.

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

fn row_address(n: u64) -> [u8; 32] {
    [n as u8 + 1; 32]
}

/// A row of any kind the registry reads: provers (some retired), allocations
/// owned by provers with and without rows, leaf roots whose keys collide
/// across rows, rewards, rows without a type and rows that do not decode.
fn random_row(rng: &mut Rng) -> Vec<u8> {
    let filters = [vec![0xA1u8; 32], vec![0xA2u8; 32], vec![0xA3u8; 33]];
    let cls = "allocation:ProverAllocation";
    match rng.below(8) {
        0 | 1 => build_sub_tree(vec![
            type_hash_leaf("prover:Prover"),
            field_leaf("prover:Prover", "PublicKey", vec![0xC0 + rng.below(4) as u8; 57 + rng.below(3) as usize]),
            field_leaf("prover:Prover", "Status", vec![rng.below(5) as u8]),
            field_leaf("prover:Prover", "Seniority", rng.below(1000).to_be_bytes().to_vec()),
        ]),
        2 | 3 | 4 => {
            let owner = if rng.below(8) == 0 { vec![9u8; 20] } else { row_address(rng.below(10)).to_vec() };
            build_sub_tree(vec![
                type_hash_leaf(cls),
                field_leaf(cls, "Prover", owner),
                field_leaf(cls, "Status", vec![rng.below(5) as u8]),
                field_leaf(cls, "ConfirmationFilter", filters[rng.below(3) as usize].clone()),
                field_leaf(cls, "LastActiveFrameNumber", rng.below(100).to_be_bytes().to_vec()),
            ])
        }
        5 => {
            let tree = crate::global_intrinsic::materialize::create_leaf_root_vertex_tree(
                &[rng.below(2) as u8 + 1; 32],
                &filters[rng.below(2) as usize],
                &[rng.below(2) as u32],
                rng.below(3),
                &vec![rng.below(250) as u8; 74],
                rng.below(9),
                100,
            )
            .unwrap();
            let mut tree = tree;
            if rng.below(3) == 0 {
                // A second slot for the same epoch: the later slot wins.
                let cls = "leafroot:LeafRootRegistration";
                let epoch = crate::global_schema::read_field(&tree, cls, "Epoch").unwrap();
                crate::global_schema::write_field(&mut tree, cls, "PrevEpoch", &epoch).unwrap();
                crate::global_schema::write_field(&mut tree, cls, "PrevLeafRoot", &[0x5A; 74]).unwrap();
            }
            vertex_tree_to_blob(&tree)
        }
        6 => build_sub_tree(vec![type_hash_leaf("reward:ProverReward")]),
        _ if rng.below(2) == 0 => vec![0xEE; 1 + rng.below(40) as usize],
        _ => build_sub_tree(vec![field_leaf("prover:Prover", "Seniority", vec![1; 8])]),
    }
}

fn put_row(store: &RocksHypergraphStore, phase: &str, address: &[u8; 32], value: Option<&[u8]>) {
    let shard = quil_store::encoding::prover_registry_shard();
    let mut vk = shard.l2.to_vec();
    vk.extend_from_slice(address);
    let key = quil_store::encoding::hypergraph_vertex_data_key("vertex", phase, &shard, &vk);
    let txn = store.new_transaction(false).unwrap();
    match value {
        Some(value) => txn.set(&key, value).unwrap(),
        None => txn.delete(&key).unwrap(),
    }
    txn.commit().unwrap();
}

fn refreshed(store: &RocksHypergraphStore, limits: RegistryLimits) -> InMemoryProverRegistry {
    let mut registry = InMemoryProverRegistry::new();
    registry.refresh_with_limits(store, limits).unwrap();
    registry
}

// Publication updates a branch's registry from the rows its frame wrote
// instead of rescanning them all; one archive spent 3 s per frame on the
// rescan. The update must leave exactly what a rescan leaves.
#[test]
fn row_updates_leave_what_a_full_refresh_leaves() {
    let (_tmp, store) = temp_store();
    let limits = RegistryLimits::UNBOUNDED;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for n in 0..24 {
        put_row(&store, "adds", &row_address(n), Some(&random_row(&mut rng)));
        if rng.below(6) == 0 {
            put_row(&store, "removes", &row_address(n), Some(&[1, 2, 3]));
        }
    }
    let mut updated = refreshed(&store, limits);
    let mut updates = 0;
    for round in 0..300 {
        let mut written: std::collections::BTreeMap<[u8; 32], registry_rows::Written> = Default::default();
        for _ in 0..1 + rng.below(4) {
            let address = row_address(rng.below(26));
            let entry = written.entry(address).or_default();
            match rng.below(10) {
                0..=5 => {
                    put_row(&store, "adds", &address, Some(&random_row(&mut rng)));
                    entry.adds = true;
                }
                6 => {
                    put_row(&store, "adds", &address, None);
                    entry.adds = true;
                }
                7 | 8 => {
                    put_row(&store, "removes", &address, Some(&vec![7; 1 + rng.below(9) as usize]));
                    entry.removes = true;
                }
                _ => {
                    put_row(&store, "removes", &address, None);
                    entry.removes = true;
                }
            }
        }
        let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
        let fresh = refreshed(&store, limits);
        if updated.update_rows(snapshot.as_ref(), &written, limits).unwrap() {
            updates += 1;
            assert_eq!(updated.content(), fresh.content(), "round {round}");
            assert!(updated.scanned.is_none(), "an update is not a database scan");
        } else {
            updated = fresh;
        }
    }
    assert!(updates > 250, "updates applied: {updates}");
}

// An update a refresh would refuse fails the same way and changes nothing.
#[test]
fn a_row_update_past_a_limit_fails_like_a_refresh_and_changes_nothing() {
    let (_tmp, store) = temp_store();
    let mut rng = Rng(7);
    for n in 0..8 {
        put_row(&store, "adds", &row_address(n), Some(&random_row(&mut rng)));
    }
    let limits = RegistryLimits { max_record_bytes: 4096, ..RegistryLimits::UNBOUNDED };
    let mut registry = refreshed(&store, limits);
    let before = registry.content();
    put_row(&store, "adds", &row_address(3), Some(&vec![0xEE; 8192]));
    let written = [(row_address(3), registry_rows::Written { adds: true, removes: false })].into();
    let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
    assert!(registry.update_rows(snapshot.as_ref(), &written, limits).is_err());
    assert!(InMemoryProverRegistry::new().refresh_with_limits(store.as_ref(), limits).is_err());
    assert_eq!(registry.content(), before);
}

// Where a row update could differ from a refresh it declines.
#[test]
fn a_row_update_declines_after_a_direct_edit_or_with_no_rows_left() {
    let (_tmp, store) = temp_store();
    let limits = RegistryLimits::UNBOUNDED;
    let only = row_address(0);
    put_row(&store, "adds", &only, Some(&build_sub_tree(vec![
        type_hash_leaf("allocation:ProverAllocation"),
        field_leaf("allocation:ProverAllocation", "Prover", row_address(0).to_vec()),
        field_leaf("allocation:ProverAllocation", "Status", vec![1]),
        field_leaf("allocation:ProverAllocation", "ConfirmationFilter", vec![0xA1; 32]),
    ])));
    let written = [(only, registry_rows::Written { adds: true, removes: false })].into();

    let mut edited = refreshed(&store, limits);
    assert_eq!(edited.update_prover_activity(&only, &[0xA1; 32], 50), 1);
    let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
    assert!(!edited.update_rows(snapshot.as_ref(), &written, limits).unwrap());

    let mut emptied = refreshed(&store, limits);
    put_row(&store, "adds", &only, None);
    let snapshot = store.capture_tree_snapshot().unwrap().unwrap();
    assert!(!emptied.update_rows(snapshot.as_ref(), &written, limits).unwrap(), "a refresh would read the legacy tree");
}
