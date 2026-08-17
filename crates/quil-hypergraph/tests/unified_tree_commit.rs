//! Phase-2 unified-app-tree: `commit_inner`'s unified path.
//!
//! A split app in UNIFIED mode commits ALL its vertices into ONE L3 tree per
//! phase keyed by the app address (a shard = the in-place subtree), so its
//! app-phase roots must be IDENTICAL to committing the same vertices as an
//! unsplit single-shard app — and DIFFERENT from the legacy separate-per-shard-
//! tree + `app_root_from_shard_paths` rollup (the §4 commitment fork). All
//! vertices remain retrievable regardless of which sub-shard they route to.

use std::sync::Arc;

use quil_hypergraph::testing::{MemStore, StubProver};
use quil_hypergraph::{HypergraphCrdt, Location};

fn fresh() -> HypergraphCrdt {
    HypergraphCrdt::new(Arc::new(MemStore::new()), Arc::new(StubProver))
}

/// The four app-phase roots for the app's single ShardKey after committing
/// `frame`. (One app ⇒ one entry in the commit result.)
fn phase_roots(crdt: &HypergraphCrdt, frame: u64) -> Vec<Vec<u8>> {
    let result = crdt.commit(frame).expect("commit");
    let mut entries: Vec<_> = result.into_values().collect();
    assert_eq!(entries.len(), 1, "expected exactly one app ShardKey");
    entries.pop().unwrap()
}

/// Deep-bifurcation Phase 3: the split PROPOSAL descends to the real branch on
/// SKEWED data (the `[7,0]` localnet case) instead of cutting at the immediate
/// bit — producing two DATA-BEARING bit-path children, never an empty child.
#[test]
fn propose_split_children_descends_to_the_real_branch() {
    use quil_forest::{bit_path_starts_with, decode_shard_bit_path};

    let app = *b"quil-app-address-0123456789abcd!";
    let c = fresh();
    c.set_unified_tree(true);
    // All data shares the top 3 address bits (byte0 0x00 / 0x10 = 0b000….),
    // diverging only at bit 3 — the immediate split would be one-sided.
    let addr = |b0: u8, tag: u8| {
        let mut a = [0u8; 32];
        a[0] = b0;
        a[31] = tag;
        a
    };
    for (b0, tag) in [(0x00u8, 1u8), (0x00, 2), (0x10, 3), (0x10, 4)] {
        c.add_vertex(&Location { app_address: app, data_address: addr(b0, tag) }, &[0xCC, b0])
            .unwrap();
    }
    c.commit(1).unwrap();

    let children = c
        .propose_split_children("vertex", "adds", &app, &[], 16)
        .expect("skewed app with 4 leaves splits at the real branch");
    assert_eq!(children.len(), 2, "binary bifurcation");

    // Both children are valid bit-path filters extending the parent (the root),
    // and BOTH are data-bearing — the empty-split guard, done as a real cut.
    for cf in &children {
        let (dec_app, bits) = decode_shard_bit_path(cf, 32).expect("decodes");
        assert_eq!(dec_app, app.to_vec());
        assert!(bit_path_starts_with(&bits, &[]), "extends the root");
        assert!(
            c.unified_subtree_leaf_count("vertex", "adds", &app, &bits) >= 1,
            "child is data-bearing: {bits:?}"
        );
    }
    // The branch is at bit 3 (bits 0-2 uniform-false, diverge at bit 3).
    assert_eq!(decode_shard_bit_path(&children[0], 32).unwrap().1, vec![false, false, false, false]);
    assert_eq!(decode_shard_bit_path(&children[1], 32).unwrap().1, vec![false, false, false, true]);

    // A single-leaf app is unsplittable → None (the guard).
    let single = fresh();
    single.set_unified_tree(true);
    single
        .add_vertex(&Location { app_address: app, data_address: addr(0x00, 9) }, &[0xAB])
        .unwrap();
    single.commit(1).unwrap();
    assert!(single.propose_split_children("vertex", "adds", &app, &[], 16).is_none());
}

/// Deep-bifurcation flip: shards persisted as SENTINEL-tagged bit-path prefixes
/// (`bit_path_to_prefix`, riding the existing `ShardInfo.prefix`) route via
/// `shard_bit_paths` to the exact deep bit-paths — a branch impossible in the
/// canonical `Vec<u32>` form. This is the persistence bridge the flip uses.
#[test]
fn sentinel_bit_path_prefixes_route_to_deep_bit_paths() {
    use quil_forest::bit_path_to_prefix;
    let app = *b"quil-app-address-0123456789abcd!";
    let c = fresh();
    // A deep-split app: two shards at [0,0,0,0] and [0,0,0,1] (branch at bit 3).
    c.set_app_shard_prefixes(
        app,
        vec![
            bit_path_to_prefix(&[false, false, false, false]),
            bit_path_to_prefix(&[false, false, false, true]),
        ],
    );
    let subs = c.app_sub_shards(&app);
    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0].1, vec![false, false, false, false], "deep bit-path decoded from sentinel prefix");
    assert_eq!(subs[1].1, vec![false, false, false, true]);
}

/// Deep-bifurcation Phase 2: the shard bit-path SOURCE is swappable. By default
/// it's `canonical_shard_bit_paths(prefixes)`; when directly-stored bit-paths are
/// set they take over — including a bit-path the `Vec<u32>` prefix form could not
/// express (a 7-bit path where 64-way canonical gives 6) — and clearing reverts.
#[test]
fn shard_bit_path_source_swaps_directly_stored_over_canonical() {
    let app = *b"quil-app-address-0123456789abcd!";
    let c = fresh();
    c.set_shard_partition(app, 1); // 64-way → prefixes [0..64], canonical = 6-bit paths

    let canonical = c.app_sub_shards(&app);
    assert_eq!(canonical.len(), 64);
    assert!(canonical.iter().all(|(_, b)| b.len() == 6), "64-way canonical = 6-bit paths");
    let canonical_bits: Vec<Vec<bool>> = canonical.iter().map(|(_, b)| b.clone()).collect();

    // Directly-stored = the SAME bits → identical (routing swap is a no-op).
    c.set_app_shard_bit_paths(app, canonical_bits.clone());
    assert_eq!(c.app_sub_shards(&app), canonical, "directly-stored canonical == canonical");

    // A DEEP 7-bit path for shard 0 — impossible in the Vec<u32> form (64-way
    // canonical is always 6 bits). The source now serves it.
    let mut deep = canonical_bits.clone();
    deep[0] = vec![false; 7];
    c.set_app_shard_bit_paths(app, deep);
    assert_eq!(c.app_sub_shards(&app)[0].1, vec![false; 7], "deep bit-path is served");

    // Clear → back to canonical.
    c.set_app_shard_bit_paths(app, vec![]);
    assert_eq!(c.app_sub_shards(&app), canonical, "cleared → canonical source");
}

#[test]
fn unified_split_app_commits_identically_to_single_shard() {
    let app = *b"quil-app-address-0123456789abcd!"; // 32B
    // Two vertices in DIFFERENT 64-way sub-shards: top-6-bits 0 and 63.
    let v0 = Location { app_address: app, data_address: [0x00u8; 32] };
    let v63 = Location { app_address: app, data_address: [0xFCu8; 32] };
    let d0 = b"vertex-zero".to_vec();
    let d63 = b"vertex-sixty-three".to_vec();

    // (A) split app (64-way) in UNIFIED mode → one tree.
    let a = fresh();
    a.set_shard_partition(app, 1); // depth-1 = 64 shards (6-bit)
    a.set_unified_tree(true);
    a.add_vertex(&v0, &d0).unwrap();
    a.add_vertex(&v63, &d63).unwrap();
    let roots_unified = phase_roots(&a, 1);

    // (B) same vertices as an UNSPLIT single-shard app → also one tree.
    let b = fresh();
    // no set_shard_partition ⇒ default single shard (prefixes = [[]])
    b.add_vertex(&v0, &d0).unwrap();
    b.add_vertex(&v63, &d63).unwrap();
    let roots_single = phase_roots(&b, 1);

    // (C) same vertices, split app, LEGACY (separate per-shard trees +
    //     app_root_from_shard_paths rollup).
    let c = fresh();
    c.set_shard_partition(app, 1);
    // unified_tree stays false
    c.add_vertex(&v0, &d0).unwrap();
    c.add_vertex(&v63, &d63).unwrap();
    let roots_legacy = phase_roots(&c, 1);

    // Unified split-app == single-shard (both = ONE tree over the same leaves).
    assert_eq!(
        roots_unified, roots_single,
        "unified split app must commit identically to a single-shard app"
    );
    // Unified != legacy (the commitment-scheme fork: JMT root vs hash_pair rollup).
    assert_ne!(
        roots_unified, roots_legacy,
        "unified must differ from the legacy separate-tree rollup (the §4 fork)"
    );
    // The VertexAdds phase root is non-empty (data committed).
    assert_eq!(roots_unified[0].len(), 32);
    assert_ne!(roots_unified[0], vec![0u8; 32]);

    // Both sub-shards' data is retrievable from the ONE unified tree.
    assert_eq!(a.get_vertex_data(&v0).as_deref(), Some(d0.as_slice()));
    assert_eq!(a.get_vertex_data(&v63).as_deref(), Some(d63.as_slice()));

    println!(
        "unified split-app roots == single-shard roots, != legacy rollup; \
         both sub-shards retrievable from one tree — Phase-2 commit_inner OK"
    );
}

/// `sub_shard_commitment` reads a SPECIFIC shard's in-place subtree root under
/// unified mode: populated shards are non-empty and distinct, an empty shard is
/// the zero placeholder, and the empty prefix reproduces the app-phase root
/// (`compute_shard_root`) — i.e. the shards compose to the header commitment.
#[test]
fn sub_shard_commitment_reads_in_place_subtrees_under_unified() {
    use quil_types::store::ShardKey;

    let app = *b"quil-app-address-0123456789abcd!";
    let v0 = Location { app_address: app, data_address: [0x00u8; 32] }; // shard [0]
    let v63 = Location { app_address: app, data_address: [0xFCu8; 32] }; // shard [63]

    let c = fresh();
    c.set_shard_partition(app, 1); // 64-way
    c.set_unified_tree(true);
    c.add_vertex(&v0, b"a").unwrap();
    c.add_vertex(&v63, b"b").unwrap();
    let _ = c.commit(1).expect("commit");

    let sk = ShardKey { l1: [0u8; 3], l2: app };

    // Empty prefix == the app-phase root (compute_shard_root) — shards compose.
    let app_root = c.compute_shard_root("vertex", "adds", &sk);
    let empty = c.sub_shard_commitment("vertex", "adds", &sk, &[]);
    assert_eq!(empty, app_root, "empty-prefix commitment == app-phase root");

    // Populated shards [0] and [63]: non-empty and distinct.
    let s0 = c.sub_shard_commitment("vertex", "adds", &sk, &[0u32]);
    let s63 = c.sub_shard_commitment("vertex", "adds", &sk, &[63u32]);
    assert_eq!(s0.len(), 32);
    assert_ne!(s0, vec![0u8; 32]);
    assert_ne!(s0, s63);
    assert_ne!(s63, vec![0u8; 32]);

    // An empty shard [32] (no data routed there) → all-zero placeholder.
    let s32 = c.sub_shard_commitment("vertex", "adds", &sk, &[32u32]);
    assert_eq!(s32, vec![0u8; 32], "empty shard → zero placeholder");

    println!("sub_shard_commitment: [0]/[63] populated+distinct, [32] empty, []==app root — Phase-2 (b) OK");
}

/// Deep-bifurcation: a SENTINEL-prefixed (deep bit-path) shard's per-shard
/// SIZE/COUNT metadata is read CORRECTLY. `build_app_shard_full_prefix` casts the
/// prefix to `i32` (sentinel `0xFFFF_FFFF` → `-1`) and `phase_set_metadata_at_path`
/// casts back (`-1` → `0xFFFF_FFFF`) — a LOSSLESS round-trip — and both
/// `bump_meta` (write) and `sub_meta_for` (read) key the buckets by
/// `addr_path_shard_id(app, sentinel_prefix)` via the sentinel-aware
/// `shard_bit_paths` routing. So a deep shard reports its REAL size/count, not
/// zero — i.e. the merge 16 GiB size-gate and eviction size reads are correct for
/// deep shards. (Confirms the suspected "metadata is sentinel-blind" concern is a
/// NON-issue: the i32 round-trip recovers the sentinel.)
#[test]
fn sentinel_shard_metadata_size_and_count_are_read_correctly() {
    use quil_forest::bit_path_to_prefix;
    use quil_types::store::ShardKey;

    let app = *b"quil-app-address-0123456789abcd!";
    let c = fresh();
    c.set_unified_tree(true);
    // Two deep shards at bit-paths [0,0,0] / [0,0,1] as SENTINEL prefixes.
    c.set_app_shard_prefixes(
        app,
        vec![
            bit_path_to_prefix(&[false, false, false]),
            bit_path_to_prefix(&[false, false, true]),
        ],
    );
    // Route vertices: byte0 top-3 bits 000 (0x00) → [0,0,0]; 001 (0x20) → [0,0,1].
    let mk = |b0: u8, tag: u8| {
        let mut a = [0u8; 32];
        a[0] = b0;
        a[31] = tag;
        a
    };
    c.add_vertex(&Location { app_address: app, data_address: mk(0x00, 1) }, &[0xAB; 10]).unwrap();
    c.add_vertex(&Location { app_address: app, data_address: mk(0x00, 2) }, &[0xAB; 10]).unwrap();
    c.add_vertex(&Location { app_address: app, data_address: mk(0x20, 3) }, &[0xCD; 20]).unwrap();
    c.commit(1).unwrap();

    let sk = ShardKey { l1: [0u8; 3], l2: app };
    // Rebuild the metadata full-path exactly as `build_app_shard_full_prefix`:
    // `get_full_path(app) ‖ (sentinel-prefix elems as i32)`.
    let full_path = |bits: &[bool]| -> Vec<i32> {
        let mut p = quil_tries::get_full_path(&app);
        for v in bit_path_to_prefix(bits) {
            p.push(v as i32);
        }
        p
    };

    let m000 = c
        .phase_set_metadata_at_path(&sk, &full_path(&[false, false, false]))
        .expect("meta [0,0,0]");
    let m001 = c
        .phase_set_metadata_at_path(&sk, &full_path(&[false, false, true]))
        .expect("meta [0,0,1]");

    // Deep shard [0,0,0]: 2 vertices, 20 bytes of live data — NOT zero.
    let a = m000[0].as_ref().expect("deep shard [0,0,0] has metadata (not None)");
    assert_eq!(a.leaf_count, 2, "two vertices routed to [0,0,0]");
    assert_ne!(a.size.to_string(), "0", "deep shard [0,0,0] reports non-zero size");
    // Deep shard [0,0,1]: 1 vertex, 20 bytes.
    let b = m001[0].as_ref().expect("deep shard [0,0,1] has metadata (not None)");
    assert_eq!(b.leaf_count, 1, "one vertex routed to [0,0,1]");
    assert_ne!(b.size.to_string(), "0", "deep shard [0,0,1] reports non-zero size");

    println!("sentinel shard metadata size/count read correctly — item #1 is a NON-issue");
}
