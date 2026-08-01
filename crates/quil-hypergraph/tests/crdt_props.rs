//! Property-based tests for HypergraphCrdt merge semantics.
//!
//! The hypergraph uses 2P-set semantics: a vertex is "present" iff
//! it has been added AND not removed. Both `vertex_adds` and
//! `vertex_removes` are monotonic — once an ID enters either set, it
//! stays. This enforces:
//!
//!   * **Commutativity**: the final state depends only on the SET of
//!     operations applied, not their order.
//!   * **Idempotency**: applying the same op twice is the same as
//!     applying it once.
//!   * **Tombstone wins**: any `remove` (whether before or after `add`)
//!     makes the vertex permanently absent.
//!   * **Monotonic growth of adds + removes**: replaying the operation
//!     log against a fresh CRDT yields the same observable state.
//!
//! These properties hold for vertex and hyperedge sets independently.
//! We test the vertex path; hyperedge has identical semantics.

use std::sync::Arc;

use proptest::prelude::*;
use quil_hypergraph::testing::{MemStore, StubProver};
use quil_hypergraph::{HypergraphCrdt, Location};

// ---------------------------------------------------------------------
// Operation alphabet + interpreter
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Add(Location, Vec<u8>),
    Remove(Location),
}

fn fresh_crdt() -> HypergraphCrdt {
    HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(StubProver))
}

fn apply(crdt: &HypergraphCrdt, op: &Op) {
    match op {
        Op::Add(loc, data) => {
            // add_vertex returns Result but the only failure is store
            // backend errors — MemStore is infallible.
            crdt.add_vertex(loc, data).expect("add_vertex");
        }
        Op::Remove(loc) => {
            crdt.remove_vertex(loc).expect("remove_vertex");
        }
    }
}

/// Snapshot the observable state of the CRDT over a known location
/// set. Compares by what `get_vertex_data` would return for each.
fn snapshot(crdt: &HypergraphCrdt, locations: &[Location]) -> Vec<Option<Vec<u8>>> {
    locations
        .iter()
        .map(|loc| crdt.get_vertex_data(loc))
        .collect()
}

/// Project the `(location, last-add-data)` pairs from an op log, so
/// the expected post-state can be computed independently of replay
/// order. If a location appears in any Remove, its data is None
/// regardless of any Add positions (tombstone wins).
fn expected_state(ops: &[Op], locations: &[Location]) -> Vec<Option<Vec<u8>>> {
    locations
        .iter()
        .map(|loc| {
            let mut last_add: Option<Vec<u8>> = None;
            let mut tombstoned = false;
            for op in ops {
                match op {
                    Op::Add(l, d) if l == loc => last_add = Some(d.clone()),
                    Op::Remove(l) if l == loc => tombstoned = true,
                    _ => {}
                }
            }
            if tombstoned {
                None
            } else {
                last_add
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------

/// Generate a Location from a small pool of distinct IDs so operations
/// have a reasonable chance of conflicting (testing commutativity
/// requires the same locations to be touched in different orders).
fn small_location() -> impl Strategy<Value = Location> {
    (0u8..8u8, 0u8..8u8).prop_map(|(app, data)| {
        let mut id = [0u8; 64];
        id[..32].fill(app);
        id[32..].fill(data);
        Location::from_id(&id)
    })
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (small_location(), prop::collection::vec(any::<u8>(), 1..=32))
            .prop_map(|(loc, data)| Op::Add(loc, data)),
        small_location().prop_map(Op::Remove),
    ]
}

fn op_log() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(op_strategy(), 0..=24)
}

fn distinct_locations(ops: &[Op]) -> Vec<Location> {
    let mut seen = Vec::new();
    for op in ops {
        let loc = match op {
            Op::Add(l, _) => l,
            Op::Remove(l) => l,
        };
        if !seen.contains(loc) {
            seen.push(loc.clone());
        }
    }
    seen
}

// ---------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------

proptest! {
    /// Tombstone semantics + last-add-wins (for never-removed
    /// locations): replaying the log against a fresh CRDT matches the
    /// hand-computed expected state. This is the strongest property —
    /// it pins the entire observable surface.
    #[test]
    fn replay_matches_expected_state(ops in op_log()) {
        let crdt = fresh_crdt();
        for op in &ops {
            apply(&crdt, op);
        }
        let locs = distinct_locations(&ops);
        let observed = snapshot(&crdt, &locs);
        let expected = expected_state(&ops, &locs);
        prop_assert_eq!(observed, expected);
    }

    /// Commutativity: shuffling the op log preserves the final state.
    /// 2P-set semantics make remove a permanent tombstone, so the
    /// final state depends only on (which locations were added at
    /// all, which were removed at all, last-add-data per never-removed
    /// location).
    ///
    /// We test by running the same ops in two orders: original and
    /// reversed. Both must yield the same observable snapshot.
    ///
    /// CAVEAT: this property holds only when adds for the same
    /// location use the same data value — different concurrent adds
    /// produce a "last writer wins" race that's order-dependent. The
    /// helper here filters to that case.
    #[test]
    fn commutativity_under_uniform_adds(ops in op_log()) {
        // Normalize: for each (location, add) pair, replace data with
        // a deterministic function of the location so multiple Adds
        // to the same location produce the same data.
        let normalized: Vec<Op> = ops
            .iter()
            .map(|op| match op {
                Op::Add(loc, _) => {
                    let mut canonical_data = Vec::with_capacity(16);
                    canonical_data.extend_from_slice(&loc.to_id()[..16]);
                    Op::Add(loc.clone(), canonical_data)
                }
                Op::Remove(loc) => Op::Remove(loc.clone()),
            })
            .collect();

        let crdt_forward = fresh_crdt();
        for op in &normalized {
            apply(&crdt_forward, op);
        }
        let crdt_reverse = fresh_crdt();
        for op in normalized.iter().rev() {
            apply(&crdt_reverse, op);
        }

        let locs = distinct_locations(&normalized);
        prop_assert_eq!(snapshot(&crdt_forward, &locs), snapshot(&crdt_reverse, &locs));
    }

    /// Idempotency: applying the same operation twice yields the same
    /// state as applying it once. True for both Add(loc, d) and
    /// Remove(loc).
    #[test]
    fn idempotency(ops in op_log()) {
        let crdt_once = fresh_crdt();
        let crdt_twice = fresh_crdt();
        for op in &ops {
            apply(&crdt_once, op);
            apply(&crdt_twice, op);
            apply(&crdt_twice, op); // applied a second time
        }
        let locs = distinct_locations(&ops);
        prop_assert_eq!(snapshot(&crdt_once, &locs), snapshot(&crdt_twice, &locs));
    }

    /// Tombstone permanence: once a Remove for a location is applied,
    /// no subsequent Add can resurrect the vertex.
    #[test]
    fn tombstone_is_permanent(
        loc in small_location(),
        add_data_before in prop::collection::vec(any::<u8>(), 1..=32),
        add_data_after in prop::collection::vec(any::<u8>(), 1..=32),
    ) {
        let crdt = fresh_crdt();
        crdt.add_vertex(&loc, &add_data_before).unwrap();
        crdt.remove_vertex(&loc).unwrap();
        // Any further adds must NOT make the vertex visible again.
        crdt.add_vertex(&loc, &add_data_after).unwrap();
        crdt.add_vertex(&loc, &add_data_before).unwrap();
        prop_assert!(crdt.get_vertex_data(&loc).is_none(),
            "tombstoned vertex must remain absent after re-add");
    }

    /// Remove-before-add: a Remove with no prior Add makes the
    /// vertex permanently absent (the Remove inserts an empty
    /// placeholder into adds + a tombstone into removes).
    #[test]
    fn remove_before_add_is_absent(
        loc in small_location(),
        add_data in prop::collection::vec(any::<u8>(), 1..=32),
    ) {
        let crdt = fresh_crdt();
        crdt.remove_vertex(&loc).unwrap();
        prop_assert!(crdt.get_vertex_data(&loc).is_none());
        crdt.add_vertex(&loc, &add_data).unwrap();
        prop_assert!(crdt.get_vertex_data(&loc).is_none(),
            "add after remove must still observe the tombstone");
    }

    /// Add-only convergence: a CRDT that has only ever seen Adds (no
    /// Removes) observes the LATEST Add value for each location,
    /// regardless of the order Adds for OTHER locations interleave.
    #[test]
    fn add_only_last_write_wins(ops in op_log()) {
        // Filter to Add-only.
        let adds: Vec<Op> = ops.into_iter().filter(|op| matches!(op, Op::Add(..))).collect();
        let crdt = fresh_crdt();
        for op in &adds {
            apply(&crdt, op);
        }
        let locs = distinct_locations(&adds);
        // Expected: for each location, the LAST Add wins.
        let mut expected = Vec::with_capacity(locs.len());
        for loc in &locs {
            let last = adds.iter().rev().find_map(|op| match op {
                Op::Add(l, d) if l == loc => Some(d.clone()),
                _ => None,
            });
            expected.push(last);
        }
        prop_assert_eq!(snapshot(&crdt, &locs), expected);
    }
}

// ---------------------------------------------------------------------
// Forest membership proof: producer (CRDT) → verifier round-trip
// ---------------------------------------------------------------------

/// The producer side (`build_membership_proof`, used by the node's
/// CreateTraversalProof RPC) must yield a proof that the verifier side
/// (`quil_forest::verify_vertex_membership`, used by the token/kick/PoMW
/// engines) accepts against the shard's committed vertex-adds root. This
/// closes the whole forest spend loop that replaced the KZG traversal proof.
#[test]
fn forest_membership_producer_verifier_round_trip() {
    use num_bigint::BigInt;

    let crdt = fresh_crdt();
    let loc = Location { app_address: [0x2a; 32], data_address: [0x07; 32] };

    // A coin-shaped vertex: commitment @ [0x04], type @ [0xFF; 32].
    let commitment = vec![0xAAu8; 56];
    let type_hash = vec![0xBBu8; 32];
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x04u8], &commitment, &[], &BigInt::from(56u64)).unwrap();
    tree.insert(&[0xFFu8; 32], &type_hash, &[], &BigInt::from(32u64)).unwrap();
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

    crdt.add_vertex(&loc, &blob).unwrap();
    let commits = crdt.commit(10).unwrap();

    let shard_key = quil_hypergraph::shard_key_for_location(&loc);
    let roots = commits.get(&shard_key).expect("shard committed");
    let root32: [u8; 32] = roots[0].as_slice().try_into().expect("32-byte vertex-adds root");

    // Producer: build a membership proof for the vertex's two fields.
    let vertex_id = loc.to_id().to_vec();
    let field_keys = vec![vec![0x04u8], vec![0xFFu8; 32]];
    let mp = crdt
        .build_membership_proof("vertex", "adds", &shard_key, &[(vertex_id.clone(), field_keys)])
        .expect("build membership proof");
    assert_eq!(mp.inputs.len(), 1);
    assert_eq!(mp.inputs[0].vertex_address, vertex_id);

    // Wire round-trip, then verify against the committed root.
    let decoded = quil_forest::MembershipProof::from_bytes(&mp.to_bytes()).unwrap();
    let expected = vec![
        (vec![0x04u8], commitment.clone()),
        (vec![0xFFu8; 32], type_hash.clone()),
    ];
    quil_forest::verify_vertex_membership(&root32, &decoded.inputs[0], &expected)
        .expect("produced proof verifies against the committed vertex-adds root");

    // A tampered expected value is rejected.
    let bad = vec![
        (vec![0x04u8], vec![0xCCu8; 56]),
        (vec![0xFFu8; 32], type_hash),
    ];
    assert!(quil_forest::verify_vertex_membership(&root32, &decoded.inputs[0], &bad).is_err());
}

/// The QUIL-split path in `commit_inner`: an app declared with a 64-way
/// partition routes its vertices into sub-shards (by data-address top-6-bits)
/// and aggregates the sub-shard roots into the app root. The result must be
/// deterministic and MUST differ from committing the same vertices as one tree
/// — proving the split actually happened.
#[test]
fn quil_split_commit_is_deterministic_and_differs_from_single_shard() {
    let quil = [0xABu8; 32];
    // data[0]=0x00 → shard 0; 0xFF → shard 63 (top-6-bits differ).
    let mk = |d0: u8| {
        let mut a = [0u8; 32];
        a[0] = d0;
        Location { app_address: quil, data_address: a }
    };
    let (v0, v63) = (mk(0x00), mk(0xFF));

    let build_split = || {
        let c = fresh_crdt();
        c.set_shard_partition(quil, 1);
        c.add_vertex(&v0, b"a").unwrap();
        c.add_vertex(&v63, b"b").unwrap();
        c.commit(1).unwrap()
    };
    let r1 = build_split();
    let r2 = build_split();

    // Both vertices share the app → one ShardKey entry with the four phase roots.
    let split_root = &r1.values().next().unwrap()[0];
    assert_eq!(split_root.len(), 32, "aggregated app root is a 32-byte JMT/Merkle root");
    assert_eq!(split_root, &r2.values().next().unwrap()[0], "split commit is deterministic");

    // Same vertices, no partition → one tree. The root must differ.
    let single = fresh_crdt();
    single.add_vertex(&v0, b"a").unwrap();
    single.add_vertex(&v63, b"b").unwrap();
    let rs = single.commit(1).unwrap();
    assert_ne!(
        split_root,
        &rs.values().next().unwrap()[0],
        "splitting into sub-shards changes the app root vs a single tree"
    );
}

/// The full model-B membership chain for a SPLIT app (QUIL): a vertex lives in
/// a sub-shard, so its field proof is against the sub-shard root and the proof
/// carries a co-path binding that sub-shard root up to the AGGREGATED app phase
/// root the header advertises. The verifier accepts it against the app root and
/// rejects it against any other root (the co-path is load-bearing).
#[test]
fn quil_split_membership_round_trip_binds_subshard_to_app_root() {
    use num_bigint::BigInt;

    let quil = [0xABu8; 32];
    let crdt = fresh_crdt();
    crdt.set_shard_partition(quil, 1);

    // data[0]=0x07 → sub-shard 0x07>>2 = 1.
    let loc = Location { app_address: quil, data_address: [0x07; 32] };
    let commitment = vec![0xAAu8; 56];
    let type_hash = vec![0xBBu8; 32];
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x04u8], &commitment, &[], &BigInt::from(56u64)).unwrap();
    tree.insert(&[0xFFu8; 32], &type_hash, &[], &BigInt::from(32u64)).unwrap();
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

    crdt.add_vertex(&loc, &blob).unwrap();
    let commits = crdt.commit(10).unwrap();

    let shard_key = quil_hypergraph::shard_key_for_location(&loc);
    // The AGGREGATED app vertex-adds root (over all 64 sub-shards).
    let app_root: [u8; 32] = commits.get(&shard_key).unwrap()[0]
        .as_slice()
        .try_into()
        .expect("32-byte aggregated app root");

    let vertex_id = loc.to_id().to_vec();
    let field_keys = vec![vec![0x04u8], vec![0xFFu8; 32]];
    let mp = crdt
        .build_membership_proof("vertex", "adds", &shard_key, &[(vertex_id, field_keys)])
        .expect("build membership proof");
    assert!(
        mp.inputs[0].shard_aggregation.is_some(),
        "a split-app proof must carry the sub-shard aggregation co-path"
    );

    let decoded = quil_forest::MembershipProof::from_bytes(&mp.to_bytes()).unwrap();
    let expected = vec![
        (vec![0x04u8], commitment.clone()),
        (vec![0xFFu8; 32], type_hash.clone()),
    ];
    quil_forest::verify_vertex_membership(&app_root, &decoded.inputs[0], &expected)
        .expect("split-app proof verifies against the aggregated app root");

    // The co-path binding is load-bearing: a different app root is rejected.
    let mut wrong = app_root;
    wrong[0] ^= 0xFF;
    assert!(
        quil_forest::verify_vertex_membership(&wrong, &decoded.inputs[0], &expected).is_err(),
        "proof must not verify against a different app root"
    );
    // A tampered field value is still rejected (the JMT field proof).
    let bad = vec![(vec![0x04u8], vec![0xCCu8; 56]), (vec![0xFFu8; 32], type_hash)];
    assert!(quil_forest::verify_vertex_membership(&app_root, &decoded.inputs[0], &bad).is_err());
}

/// A NON-QUIL binary split (the case the encoding reconciliation fixes): the
/// shard set is the rebalancer's marker-byte prefixes `[0]`/`[128]` (filter
/// suffix `0x00`/`0x80`), NOT QUIL 6-bit indices. Routing sends a leaf by its
/// data-address TOP BIT, canonical bit-paths give "0"/"1", and the commit is
/// deterministic + differs from a single unsplit tree.
#[test]
fn binary_split_marker_prefixes_commit_deterministically() {
    let app = [0xCDu8; 32];
    let mk = |d0: u8| {
        let mut a = [0u8; 32];
        a[0] = d0;
        Location { app_address: app, data_address: a }
    };
    // data[0] top bit 0 → sub-shard [0]; top bit 1 → sub-shard [128].
    let (v_lo, v_hi) = (mk(0x00), mk(0x80));

    let build_split = || {
        let c = fresh_crdt();
        c.set_app_shard_prefixes(app, vec![vec![0], vec![128]]);
        c.add_vertex(&v_lo, b"a").unwrap();
        c.add_vertex(&v_hi, b"b").unwrap();
        c.commit(1).unwrap()
    };
    let r1 = build_split();
    let r2 = build_split();
    let split_root = &r1.values().next().unwrap()[0];
    assert_eq!(split_root.len(), 32, "aggregated binary-split app root is 32 bytes");
    assert_eq!(split_root, &r2.values().next().unwrap()[0], "binary split is deterministic");

    let single = fresh_crdt();
    single.add_vertex(&v_lo, b"a").unwrap();
    single.add_vertex(&v_hi, b"b").unwrap();
    let rs = single.commit(1).unwrap();
    assert_ne!(
        split_root,
        &rs.values().next().unwrap()[0],
        "binary split changes the app root vs a single tree"
    );
}

/// Full membership chain for a binary-split app: a vertex in the `0x80` sub-shard
/// proves against that sub-shard root, and the co-path binds it to the aggregated
/// app root — verifying the marker-byte prefix path end to end.
#[test]
fn binary_split_membership_binds_subshard_to_app_root() {
    use num_bigint::BigInt;

    let app = [0xCDu8; 32];
    let crdt = fresh_crdt();
    crdt.set_app_shard_prefixes(app, vec![vec![0], vec![128]]);

    // data[0]=0x80 → top bit 1 → sub-shard [128].
    let loc = Location { app_address: app, data_address: [0x80; 32] };
    let commitment = vec![0xAAu8; 56];
    let type_hash = vec![0xBBu8; 32];
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x04u8], &commitment, &[], &BigInt::from(56u64)).unwrap();
    tree.insert(&[0xFFu8; 32], &type_hash, &[], &BigInt::from(32u64)).unwrap();
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

    crdt.add_vertex(&loc, &blob).unwrap();
    let commits = crdt.commit(10).unwrap();
    let shard_key = quil_hypergraph::shard_key_for_location(&loc);
    let app_root: [u8; 32] =
        commits.get(&shard_key).unwrap()[0].as_slice().try_into().unwrap();

    let vertex_id = loc.to_id().to_vec();
    let field_keys = vec![vec![0x04u8], vec![0xFFu8; 32]];
    let mp = crdt
        .build_membership_proof("vertex", "adds", &shard_key, &[(vertex_id, field_keys)])
        .expect("build membership proof");
    assert!(
        mp.inputs[0].shard_aggregation.is_some(),
        "binary-split proof carries the sub-shard co-path"
    );
    let decoded = quil_forest::MembershipProof::from_bytes(&mp.to_bytes()).unwrap();
    let expected = vec![(vec![0x04u8], commitment), (vec![0xFFu8; 32], type_hash)];
    quil_forest::verify_vertex_membership(&app_root, &decoded.inputs[0], &expected)
        .expect("binary-split proof verifies against the aggregated app root");
    let mut wrong = app_root;
    wrong[0] ^= 0xFF;
    assert!(
        quil_forest::verify_vertex_membership(&wrong, &decoded.inputs[0], &expected).is_err(),
        "co-path binding is load-bearing"
    );
}

/// Interleaved commits of different apps must NOT corrupt each other's trees.
/// JMT needs contiguous per-tree versions; commit_inner uses a global version
/// counter, so app A committed at frames 1 and 3 (with app B at frame 2 bumping
/// the counter) gets non-contiguous versions. This asserts A keeps BOTH its
/// vertices — i.e. the incremental commit built on A's real prior root, not an
/// empty one.
#[test]
fn interleaved_app_commits_preserve_each_others_state() {
    let crdt = fresh_crdt();
    let a1 = Location { app_address: [0xA1; 32], data_address: [0x01; 32] };
    let a2 = Location { app_address: [0xA1; 32], data_address: [0x02; 32] };
    let b1 = Location { app_address: [0xB2; 32], data_address: [0x01; 32] };

    // Frame 1: app A vertex 1.
    crdt.add_vertex(&a1, b"a1").unwrap();
    crdt.commit(1).unwrap();
    // Frame 2: app B (bumps the global forest version).
    crdt.add_vertex(&b1, b"b1").unwrap();
    crdt.commit(2).unwrap();
    // Frame 3: app A vertex 2 (incremental commit of A's tree, non-contiguous).
    crdt.add_vertex(&a2, b"a2").unwrap();
    crdt.commit(3).unwrap();

    // Both of A's vertices must still be present.
    assert_eq!(crdt.get_vertex_data(&a1).as_deref(), Some(&b"a1"[..]), "A vertex 1 survived");
    assert_eq!(crdt.get_vertex_data(&a2).as_deref(), Some(&b"a2"[..]), "A vertex 2 present");
}

/// The FOREST tree (not just blobs) must survive interleaved commits: app A's
/// frame-1 vertex must still prove against A's committed root after app B's
/// frame-2 commit bumped the global version and A was re-committed at frame 3.
/// This directly exercises whether commit_inner's global version counter builds
/// each incremental commit on the tree's real prior root.
#[test]
fn interleaved_commits_keep_forest_tree_intact() {
    use num_bigint::BigInt;

    let crdt = fresh_crdt();
    let app_a = [0xA1u8; 32];
    let a1 = Location { app_address: app_a, data_address: [0x01; 32] };
    let a2 = Location { app_address: app_a, data_address: [0x02; 32] };
    let b1 = Location { app_address: [0xB2; 32], data_address: [0x01; 32] };

    // A coin-shaped vertex for a1 so we can prove it.
    let commitment = vec![0xAAu8; 56];
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x04u8], &commitment, &[], &BigInt::from(56u64)).unwrap();
    let a1_blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();

    crdt.add_vertex(&a1, &a1_blob).unwrap();
    crdt.commit(1).unwrap(); // frame 1: A
    crdt.add_vertex(&b1, b"b1").unwrap();
    crdt.commit(2).unwrap(); // frame 2: B (bumps global version)
    crdt.add_vertex(&a2, b"a2").unwrap();
    let commits = crdt.commit(3).unwrap(); // frame 3: A incremental

    let sk = quil_hypergraph::shard_key_for_location(&a1);
    let root: [u8; 32] = commits.get(&sk).unwrap()[0].as_slice().try_into().unwrap();

    // Prove a1's commitment field against A's frame-3 root.
    let mp = crdt
        .build_membership_proof("vertex", "adds", &sk, &[(a1.to_id().to_vec(), vec![vec![0x04u8]])])
        .expect("build proof");
    quil_forest::verify_vertex_membership(&root, &mp.inputs[0], &[(vec![0x04u8], commitment)])
        .expect("a1 still proves against the forest root after interleaved commits");
}

/// The O(1) metadata memo (`metadata_cache`) MUST be transparent: repeated
/// reads return the same value, and every mutation (stage) or `commit` is
/// reflected on the very next read — never a stale cached `size`/`leaf_count`.
/// This is consensus-critical: the reward path derives `state_size` /
/// `shard_count` from `sub_shard_metadata_for_filter` (→ this memo), so a stale
/// value would mis-mint and fork. Prior to the memo this path did a full
/// RocksDB-iterator KV scan per call (the archive-OOM leak); the memoized value
/// must equal what that scan produced.
#[test]
fn phase_metadata_memo_is_transparent_and_invalidates() {
    use num_bigint::BigInt;

    let crdt = fresh_crdt();
    let app = [0x11u8; 32];
    let mk = |d0: u8| {
        let mut a = [0u8; 32];
        a[0] = d0;
        Location { app_address: app, data_address: a }
    };

    // Empty shard → no vertex-adds metadata (and a repeat read agrees).
    assert!(crdt.sub_shard_metadata_for_filter(&app).is_none());
    assert!(crdt.sub_shard_metadata_for_filter(&app).is_none());

    // First add → next read reflects it (memo was invalidated by `stage`).
    crdt.add_vertex(&mk(0x01), b"hello").unwrap(); // 5 bytes
    let m1 = crdt.sub_shard_metadata_for_filter(&app).expect("metadata after add");
    assert_eq!(m1.leaf_count, 1);
    assert_eq!(m1.size, BigInt::from(5u64));
    // Repeat read is a memo HIT → identical.
    let m1b = crdt.sub_shard_metadata_for_filter(&app).expect("memo hit");
    assert_eq!((m1b.leaf_count, m1b.size.clone()), (m1.leaf_count, m1.size.clone()));

    // Second add → must UPDATE, not serve the stale memo.
    crdt.add_vertex(&mk(0x02), b"worldwide").unwrap(); // 9 bytes
    let m2 = crdt.sub_shard_metadata_for_filter(&app).expect("metadata after 2nd add");
    assert_eq!(m2.leaf_count, 2);
    assert_eq!(m2.size, BigInt::from(14u64));

    // Commit also invalidates; the committed read matches the pre-commit live value.
    crdt.commit(1).unwrap();
    let m3 = crdt.sub_shard_metadata_for_filter(&app).expect("metadata after commit");
    assert_eq!(m3.leaf_count, 2);
    assert_eq!(m3.size, BigInt::from(14u64));
}

/// The maintained live-size accounting: `state_size` = Σ present vertices'
/// blob size (adds − removes) + Σ present hyperedges' blob size (adds − removes),
/// bucketed by the forest partition; `leaf_count` = RAW vertex-adds count;
/// `total_size()` = Σ per-sub-shard sizes (prover shard 0xff excluded); and the
/// `remove_hyperedge` bug (size never freed) is fixed. All maintained live in
/// the mutation path — no scan — and `warm_sizes` recomputes the same value.
#[test]
fn live_size_all_phases_tombstones_and_world_sum() {
    use num_bigint::BigInt;
    let c = fresh_crdt();
    let app = [0x11u8; 32];
    c.set_shard_partition(app, 1); // 64-way split
    let v = |d0: u8, tag: u8| {
        let mut d = [0u8; 32];
        d[0] = d0; // top 6 bits pick the sub-shard: 0x00 & 0x01 → 0; 0xFF → 63
        d[31] = tag;
        Location { app_address: app, data_address: d }
    };
    let s0 = |c: &HypergraphCrdt| {
        c.sub_shard_metadata_for_filter(&[app.as_slice(), &[0u8]].concat())
            .map(|m| (m.leaf_count, m.size))
    };

    c.add_vertex(&v(0x00, 1), b"aaaa").unwrap(); // 4  → shard 0
    c.add_vertex(&v(0x00, 2), b"bbbbb").unwrap(); // 5 → shard 0
    c.add_vertex(&v(0xFF, 3), b"cccccc").unwrap(); // 6 → shard 63
    assert_eq!(c.total_size(), BigInt::from(15));
    assert_eq!(s0(&c), Some((2, BigInt::from(9))));

    // Remove a present vertex: LIVE size drops, RAW count is unchanged.
    c.remove_vertex(&v(0x00, 1)).unwrap(); // -4
    assert_eq!(c.total_size(), BigInt::from(11));
    assert_eq!(s0(&c), Some((2, BigInt::from(5))));

    // Hyperedge add contributes to size but NOT the vertex count.
    c.add_hyperedge(&v(0x00, 4), b"eeeeeee").unwrap(); // +7
    assert_eq!(s0(&c), Some((2, BigInt::from(12))));
    assert_eq!(c.total_size(), BigInt::from(18));

    // Hyperedge remove frees size — the bug fix (was never subtracted before).
    c.remove_hyperedge(&v(0x00, 4)).unwrap(); // -7
    assert_eq!(s0(&c), Some((2, BigInt::from(5))));
    assert_eq!(c.total_size(), BigInt::from(11));

    // Correct top-6-bit sharding: data 0x01 → shard 0 (the scan's bug misrouted it).
    c.add_vertex(&v(0x01, 5), b"ff").unwrap(); // +2 → shard 0
    assert_eq!(s0(&c), Some((3, BigInt::from(7))));

    // The prover shard (app 0xff) is EXCLUDED from world size.
    let before = c.total_size();
    let pv = {
        let mut d = [0u8; 32];
        d[31] = 9;
        Location { app_address: [0xFFu8; 32], data_address: d }
    };
    c.add_vertex(&pv, b"zzzzzzzz").unwrap();
    assert_eq!(c.total_size(), before, "prover shard excluded from world size");
    assert_eq!(c.total_size(), BigInt::from(13)); // Σ: shard0=7 + shard63=6

    // Warm recomputes the SAME value from committed state (idempotent vs live).
    c.commit(1).unwrap();
    c.warm_sizes(&[app]).unwrap();
    assert_eq!(c.total_size(), BigInt::from(13));
    assert_eq!(s0(&c), Some((3, BigInt::from(7))));
}

/// Level-1 global commitments: each of the 256 buckets is the root of a tree
/// of `AppEntry` leaves for the apps whose FIRST address byte equals the bucket
/// index. `commit_inner` maintains them live; `global_commitments()` retrieves
/// all 256 and touching a bucket updates only that bucket's root.
#[test]
fn global_commitments_maintained_per_bucket() {
    let c = fresh_crdt();
    // Two apps in bucket 0x2a, one in bucket 0x50, none elsewhere.
    let app_a = { let mut a = [0u8; 32]; a[0] = 0x2a; a[31] = 0x01; a };
    let app_b = { let mut a = [0u8; 32]; a[0] = 0x2a; a[31] = 0x02; a };
    let app_c = { let mut a = [0u8; 32]; a[0] = 0x50; a };
    c.add_vertex(&Location { app_address: app_a, data_address: [0x11; 32] }, b"a").unwrap();
    c.add_vertex(&Location { app_address: app_b, data_address: [0x22; 32] }, b"b").unwrap();
    c.add_vertex(&Location { app_address: app_c, data_address: [0x33; 32] }, b"c").unwrap();
    c.commit(1).unwrap();

    let gc = c.global_commitments();
    assert_eq!(gc.len(), 256, "always 256 buckets");
    assert!(!gc[0x2a].is_empty(), "bucket 0x2a has apps → non-empty root");
    assert!(!gc[0x50].is_empty(), "bucket 0x50 has an app → non-empty root");
    assert!(gc[0x00].is_empty(), "bucket 0x00 has no apps → empty");
    assert_eq!(gc[0x2a].len(), 32, "a bucket root is a 32-byte JMT root");
    assert_ne!(gc[0x2a], gc[0x50], "distinct buckets commit distinct app sets");

    // Touching an app in bucket 0x2a changes THAT bucket's root only.
    let before_2a = gc[0x2a].clone();
    let before_50 = gc[0x50].clone();
    c.add_vertex(&Location { app_address: app_a, data_address: [0x44; 32] }, b"more").unwrap();
    c.commit(2).unwrap();
    let gc2 = c.global_commitments();
    assert_ne!(gc2[0x2a], before_2a, "touching bucket 0x2a updates its root");
    assert_eq!(gc2[0x50], before_50, "untouched bucket 0x50 root is unchanged");
}

/// The global prover shard (`0xff..ff`) is excluded from L1 global commitments
/// — its root is carried separately as `prover_tree_commitment`.
#[test]
fn global_prover_shard_excluded_from_l1() {
    let c = fresh_crdt();
    let global = [0xffu8; 32];
    c.add_vertex(&Location { app_address: global, data_address: [0x01; 32] }, b"prover").unwrap();
    c.commit(1).unwrap();
    let gc = c.global_commitments();
    assert!(gc[0xff].is_empty(), "global prover shard must NOT create an L1 bucket leaf");
}

// ---------------------------------------------------------------------
// Prover-root determinism (the archive prover-root-mismatch class)
// ---------------------------------------------------------------------

/// The global intrinsic (prover) shard: `l1=[0;3], l2=[0xff;32]`. Matches
/// `GlobalLeaderProvider::compute_prover_root` and the materializer's
/// prover-root read — `compute_shard_root` uses only `l2`, so `l1` is nominal.
fn global_prover_shard() -> quil_types::store::ShardKey {
    quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] }
}

/// The PROVER ROOT (= `compute_shard_root("vertex","adds", global-shard)`) must
/// be a pure function of the vertex SET, independent of insertion order. Two
/// archives that applied the same prover/allocation vertices in different orders
/// (different frame arrival, sync vs live, HashMap iteration) MUST commit to the
/// same root — the invariant whose violation is the "prover root MISMATCH"
/// field report. This is the core determinism guarantee that had no coverage.
#[test]
fn prover_root_is_insertion_order_independent() {
    let global = [0xffu8; 32];
    // A set of distinct prover-like vertices under the global intrinsic address.
    let vertices: Vec<(Location, Vec<u8>)> = (0u8..12)
        .map(|i| {
            let mut data = [0u8; 32];
            data[0] = i;
            data[31] = i.wrapping_mul(7);
            (
                Location { app_address: global, data_address: data },
                vec![i; 40 + i as usize],
            )
        })
        .collect();

    let commit_in_order = |order: &[usize]| -> Vec<u8> {
        let c = fresh_crdt();
        for &idx in order {
            let (loc, blob) = &vertices[idx];
            c.add_vertex(loc, blob).unwrap();
        }
        c.commit(1).unwrap();
        // Read via the SAME entry point the leader/materializer use.
        c.compute_shard_root("vertex", "adds", &global_prover_shard())
    };

    let forward: Vec<usize> = (0..vertices.len()).collect();
    let reversed: Vec<usize> = (0..vertices.len()).rev().collect();
    // A non-trivial shuffle (deterministic, no rng): odd indices then even.
    let mut interleaved: Vec<usize> = (0..vertices.len()).filter(|i| i % 2 == 1).collect();
    interleaved.extend((0..vertices.len()).filter(|i| i % 2 == 0));

    let r_fwd = commit_in_order(&forward);
    let r_rev = commit_in_order(&reversed);
    let r_int = commit_in_order(&interleaved);

    assert_eq!(r_fwd.len(), 32, "prover root is a 32-byte forest root");
    assert!(r_fwd.iter().any(|&b| b != 0), "prover root must be non-empty");
    assert_eq!(r_fwd, r_rev, "prover root must not depend on insertion order (fwd vs rev)");
    assert_eq!(r_fwd, r_int, "prover root must not depend on insertion order (fwd vs interleaved)");
}

/// `compute_shard_root` (the verify/leader read path) must equal the root
/// `commit` returns for the same shard/phase — the two are used
/// interchangeably (leader binds `compute_shard_root`; the materializer's
/// post-apply path publishes `commit`'s root), so if they ever diverged, a
/// producer and a verifier on the SAME state would disagree → self-inflicted
/// "mismatch". No prior test tied the compare path to a real committed tree.
#[test]
fn compute_shard_root_matches_commit_root_for_prover_shard() {
    let global = [0xffu8; 32];
    let c = fresh_crdt();
    for i in 0u8..6 {
        let mut data = [0u8; 32];
        data[0] = i;
        c.add_vertex(&Location { app_address: global, data_address: data }, &vec![i; 33])
            .unwrap();
    }
    let commits = c.commit(9).unwrap();

    let shard = global_prover_shard();
    // commit() keys by the location-derived shard key (real l1); compute_shard_root
    // ignores l1. Find the committed entry for l2 == global address.
    let commit_root = commits
        .iter()
        .find(|(k, _)| k.l2 == global)
        .map(|(_, roots)| roots[0].clone())
        .expect("global shard committed");
    let read_root = c.compute_shard_root("vertex", "adds", &shard);

    assert_eq!(read_root.len(), 32);
    assert_eq!(
        read_root, commit_root,
        "compute_shard_root (verify/leader read) must equal commit()'s vertex-adds root"
    );
}
