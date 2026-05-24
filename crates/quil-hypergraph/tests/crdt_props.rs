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
