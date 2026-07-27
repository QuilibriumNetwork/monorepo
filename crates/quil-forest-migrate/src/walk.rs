//! The store walk: read the legacy KZG hypergraph DB shard-by-shard,
//! flatten each shard's four phase trees into forest Level-3 leaves, and roll
//! them up into the Level-2 app trees and Level-1 global trees.
//!
//! The forest is written to a **separate** RocksDB from the source
//! hypergraph store: forest node keys are prefixed by tree level
//! (`0x01/0x02/0x03`), which collides with the hypergraph's own node tags
//! (e.g. `HG_VERTEX_ADDS_TREE_NODE = 0x02`). Writing a fresh destination DB
//! matches the existing `--import-db` model and keeps the two key-spaces
//! disjoint.

use std::collections::BTreeMap;

use quil_forest::{
    app_root_from_shard_paths, canonical_shard_bit_paths, global_tree_index, rollup_phase_roots,
    AppEntry, Forest, Phase, ShardRoots, PHASES,
};
use quil_hypergraph::addressing::get_bloom_filter_indices;
use quil_store::RocksHypergraphStore;
use quil_types::store::{HypergraphStore, ShardKey};

// The flatten core lives in the crate root.
use crate::per_vertex_phase_leaves;

/// The `(set_type, phase_type)` string pair the legacy store keys a phase by.
fn phase_strs(p: Phase) -> (&'static str, &'static str) {
    match p {
        Phase::VertexAdds => ("vertex", "adds"),
        Phase::VertexRemoves => ("vertex", "removes"),
        Phase::HyperedgeAdds => ("hyperedge", "adds"),
        Phase::HyperedgeRemoves => ("hyperedge", "removes"),
    }
}

/// One shard's conversion result: the forest [`ShardRoots`] plus the
/// aggregates the app-level [`ShardEntry`] needs. `num_leaves`/`total_size`
/// mirror the legacy `ShardMetadata`, which sourced them from the
/// vertex-adds tree — so we count that phase's flattened leaves.
#[derive(Clone, Debug)]
pub struct ShardConversion {
    pub roots: ShardRoots,
    pub num_leaves: u64,
    pub total_size: u128,
}

/// Read one phase's `(vertex_address, blob)` leaves from the legacy store,
/// with the transitional whole-tree-blob fallback the prover-registry refresh
/// also uses (stores from before the per-vertex-commit invariant keep their
/// leaves in a single tree blob rather than the per-vertex keyspace).
fn read_phase_vertex_blobs(
    hg: &RocksHypergraphStore,
    set: &str,
    phase: &str,
    shard_key: &ShardKey,
) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut blobs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    hg.for_each_vertex_underlying(set, phase, shard_key, |vk, data| blobs.push((vk, data)))
        .map_err(|e| anyhow::anyhow!("for_each_vertex_underlying {set}/{phase}: {e}"))?;
    if blobs.is_empty() {
        if let Some(blob) = hg
            .load_tree_blob(set, phase, shard_key)
            .map_err(|e| anyhow::anyhow!("load_tree_blob {set}/{phase}: {e}"))?
        {
            if let Some(root) = quil_tries::deserialize_tree(&blob)
                .map_err(|e| anyhow::anyhow!("deserialize_tree {set}/{phase}: {e}"))?
            {
                let mut t = quil_tries::VectorCommitmentTree::new();
                t.root = Some(root);
                blobs = t.leaves();
            }
        }
    }
    Ok(blobs)
}

/// Convert one shard: walk its four phase trees, flatten each into Level-3
/// leaves, commit them under the shard's forest trees, and return the rolled
/// commitment + aggregates.
pub fn convert_shard(
    hg: &RocksHypergraphStore,
    forest: &Forest,
    shard_key: &ShardKey,
    version: u64,
) -> anyhow::Result<ShardConversion> {
    let mut phase_leaves: [Vec<(Vec<u8>, Vec<u8>)>; 4] = Default::default();
    let mut num_leaves: u64 = 0;
    let mut total_size: u128 = 0;
    for phase in PHASES {
        let (set, ph) = phase_strs(phase);
        let blobs = read_phase_vertex_blobs(hg, set, ph, shard_key)?;
        let leaves = per_vertex_phase_leaves(blobs)?;
        // Aggregates track the vertex-adds phase, mirroring ShardMetadata.
        if phase == Phase::VertexAdds {
            num_leaves = leaves.len() as u64;
            total_size = leaves.iter().map(|(_, v)| quil_forest::vertex_leaf_size(v)).sum();
        }
        phase_leaves[phase as usize] = leaves;
    }
    let roots = forest
        .commit_shard_raw(&shard_key.l2, version, phase_leaves)
        .map_err(|e| anyhow::anyhow!("commit_shard_raw: {e}"))?;
    Ok(ShardConversion { roots, num_leaves, total_size })
}

/// The default shard partition for an app in the address-path (model B) forest:
/// the QUIL_TOKEN domain is split ONE 64-way level (64 shards, prefixes
/// `[0..64)`); every other app defaults to a SINGLE shard (empty prefix) and
/// splits dynamically via shard-split logic. Mirrors the genesis registry
/// (`genesis.rs` QUIL = 64) and the user's "non-QUIL defaults to 1" model.
pub fn quil_shards_for_app(app_address: &[u8; 32]) -> Vec<Vec<u32>> {
    if app_address == &quil_execution::domains::QUIL_TOKEN {
        (0..64u32).map(|i| vec![i]).collect()
    } else {
        vec![Vec::new()]
    }
}

/// Convert one APP: read its vertices, split them into the app's shards by
/// address (model B), commit each shard as a field-flattened tree keyed
/// `addr_path_shard_id(app, prefix)`, and aggregate the shard commitments into
/// the app root via [`app_root_from_shard_paths`] (positioned by prefix bits).
/// The complete shard set is committed — empty shards get the empty-JMT
/// commitment — so the aggregation is over the full set (sparse ≠ complete),
/// which is what keeps every node's app root identical. `num_leaves`/
/// `total_size` are the app-wide sums (invariant to how the leaves shard).
/// Returns `None` for an app with no state at all.
pub fn convert_app(
    hg: &RocksHypergraphStore,
    forest: &Forest,
    app_shard_key: &ShardKey,
    version: u64,
    prefixes: &[Vec<u32>],
) -> anyhow::Result<Option<(AppEntry, usize)>> {
    // Canonical bit-path per shard (resolves the QUIL-vs-split-marker overload +
    // supports non-uniform splits), in the SAME order as `prefixes`.
    let bit_paths = canonical_shard_bit_paths(prefixes);

    // shard INDEX → the four phases' raw (vertex_key, blob) leaves. Route each
    // vertex to its sub-shard by matching its data address against the canonical
    // bit-paths (mirrors the running node's `commit_inner`); addresses outside the
    // declared set fall back to shard 0 so no state is dropped.
    let mut shard_blobs: Vec<[Vec<(Vec<u8>, Vec<u8>)>; 4]> =
        (0..prefixes.len()).map(|_| Default::default()).collect();
    for phase in PHASES {
        let (set, ph) = phase_strs(phase);
        for (vk, blob) in read_phase_vertex_blobs(hg, set, ph, app_shard_key)? {
            let data: &[u8] = if vk.len() == 64 { &vk[32..] } else { &vk[..] };
            let pi = quil_forest::address_shard_index(data, &bit_paths);
            shard_blobs[pi][phase as usize].push((vk, blob));
        }
    }

    // Commit each shard (field-flattened) and collect, PER PHASE, its
    // (bit-path → phase root). Aggregation is per-phase (then rolled up) to
    // match the running node's `commit_inner` — so a membership proof chains
    // leaf → shard phase root → app phase root. num_leaves/total_size mirror
    // ShardMetadata (the vertex-adds phase), summed across shards.
    let mut phase_shards: [Vec<(Vec<bool>, [u8; 32])>; 4] = Default::default();
    let mut num_leaves: u64 = 0;
    let mut total_size: u128 = 0;
    let mut nonempty = 0usize;
    for (i, prefix) in prefixes.iter().enumerate() {
        let phase_blobs = std::mem::take(&mut shard_blobs[i]);
        let mut phase_leaves: [Vec<(Vec<u8>, Vec<u8>)>; 4] = Default::default();
        let mut shard_has_state = false;
        for (blobs, phase) in phase_blobs.into_iter().zip(PHASES) {
            let leaves = per_vertex_phase_leaves(blobs)?;
            if !leaves.is_empty() {
                shard_has_state = true;
            }
            if phase == Phase::VertexAdds {
                num_leaves += leaves.len() as u64;
                total_size += leaves.iter().map(|(_, v)| quil_forest::vertex_leaf_size(v)).sum::<u128>();
            }
            phase_leaves[phase as usize] = leaves;
        }
        if shard_has_state {
            nonempty += 1;
        }
        let shard_id = Forest::addr_path_shard_id(&app_shard_key.l2, prefix);
        let roots = forest
            .commit_shard_raw(&shard_id, version, phase_leaves)
            .map_err(|e| anyhow::anyhow!("commit_shard_raw: {e}"))?;
        // Mark each phase tree's head version so the running node's version-exact
        // reads (commit_inner / membership / sync) can address the migrated tree
        // after the live forest version advances past `version`.
        for phase in PHASES {
            forest
                .write_head_version(&shard_id, phase, version)
                .map_err(|e| anyhow::anyhow!("write_head_version: {e}"))?;
        }
        for p in 0..4 {
            phase_shards[p].push((bit_paths[i].clone(), roots.phase_roots[p]));
        }
    }

    if num_leaves == 0 && nonempty == 0 {
        return Ok(None);
    }
    // Aggregate the sub-shard roots into an app root PER PHASE, then roll the
    // four app phase roots up into the app commitment.
    let mut app_phase_roots = [[0u8; 32]; 4];
    for p in 0..4 {
        app_phase_roots[p] = app_root_from_shard_paths(&phase_shards[p]);
    }
    let app_root = rollup_phase_roots(&app_phase_roots);
    Ok(Some((
        AppEntry { app_root, num_leaves, total_size, metadata: Vec::new() },
        nonempty,
    )))
}

/// What `convert_db` produced: how many shards/apps were converted and the
/// resulting Level-1 global-tree roots (by tree index).
#[derive(Clone, Debug, Default)]
pub struct ConvertReport {
    pub shards: usize,
    pub apps: usize,
    pub global_roots: BTreeMap<u8, [u8; 32]>,
}

/// Convert the whole legacy hypergraph DB into the forest (model B).
///
/// Each enumerated ShardKey is one app (its vertices are keyed by the app
/// address). `shards_for_app` returns that app's shard partition — the list of
/// `ShardInfo.prefix`es ([`quil_shards_for_app`] is the default: QUIL = 64,
/// every other app = a single shard). [`convert_app`] splits the app's vertices
/// into those shards, commits each as a field-flattened tree, and aggregates
/// the shard commitments into the app root via [`app_root_from_shard_paths`].
///
/// Steps: enumerate every app (`range_alt_shard_addresses` ∪ recent
/// `get_root_commits`), convert each (split → L3 shards → app root), then group
/// the app entries by global index (first address byte) and commit each of the
/// touched L1 global trees.
pub fn convert_db(
    hg: &RocksHypergraphStore,
    forest: &Forest,
    version: u64,
    head_frame: u64,
    shards_for_app: impl Fn(&[u8; 32]) -> Vec<Vec<u32>>,
) -> anyhow::Result<ConvertReport> {
    // Enumerate every shard that carries state. `range_alt_shard_addresses`
    // only indexes SPLIT sub-shards (`set_alt_shard_commit` at
    // frame_materializer.rs:1056) — on its own it MISSES the global prover
    // shard and regular app shards, which register via plain `set_shard_commit`.
    // Mirror `verify_migration`: union the all-time alt-shard index with the
    // shard commits over a lookback window below head. The global prover shard
    // commits every frame, so the window captures it.
    const LOOKBACK: u64 = 128;
    let mut shard_keys: std::collections::HashSet<ShardKey> = std::collections::HashSet::new();
    for addr in HypergraphStore::range_alt_shard_addresses(hg)
        .map_err(|e| anyhow::anyhow!("range_alt_shard_addresses: {e}"))?
    {
        if addr.len() >= 32 {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(&addr[..32]);
            shard_keys.insert(ShardKey { l2, l1: get_bloom_filter_indices(&addr, 256, 3) });
        }
    }
    let lo = head_frame.saturating_sub(LOOKBACK);
    for fno in lo..=head_frame {
        for sk in HypergraphStore::get_root_commits(hg, fno)
            .map_err(|e| anyhow::anyhow!("get_root_commits({fno}): {e}"))?
            .into_keys()
        {
            shard_keys.insert(sk);
        }
    }

    // Each ShardKey is one app: split it into its shards, commit them, and
    // aggregate into the app root. Group the resulting AppEntries by global
    // index (first address byte) for the L1 commit.
    let mut global_apps: BTreeMap<u8, Vec<(Vec<u8>, AppEntry)>> = BTreeMap::new();
    let mut shards_converted = 0usize;
    let mut apps_converted = 0usize;
    for shard_key in &shard_keys {
        let prefixes = shards_for_app(&shard_key.l2);
        // Skip an app with no state at all (e.g. a lookback frame that listed a
        // since-emptied shard) so it doesn't create a spurious L1 leaf.
        let Some((app_entry, nonempty_shards)) =
            convert_app(hg, forest, shard_key, version, &prefixes)?
        else {
            continue;
        };
        shards_converted += nonempty_shards;
        apps_converted += 1;
        let g = global_tree_index(&shard_key.l2);
        global_apps.entry(g).or_default().push((shard_key.l2.to_vec(), app_entry));
    }

    // L1: commit each touched global tree.
    let mut global_roots = BTreeMap::new();
    for (g, apps) in global_apps {
        let root = forest
            .commit_global(g, version, apps)
            .map_err(|e| anyhow::anyhow!("commit_global: {e}"))?;
        global_roots.insert(g, root);
    }

    Ok(ConvertReport { shards: shards_converted, apps: apps_converted, global_roots })
}

/// Install the Phase-3 forest on `crdt` — namespaced into `hg`'s own DB — iff
/// that DB has already been migrated (`has_forest_data()`). Returns whether it
/// was installed. The runtime calls this right after constructing a CRDT so a
/// migrated node commits state to the forest while a non-migrated node keeps
/// the KZG path (the cutover is gated on the migration, per design).
pub fn install_forest_if_migrated(
    crdt: &quil_hypergraph::HypergraphCrdt,
    hg: &RocksHypergraphStore,
) -> bool {
    if hg.has_forest_data() {
        crdt.set_forest(Forest::with_namespace(
            hg.raw_db(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        // Declare the same shard partition the converter used
        // (`quil_shards_for_app`): QUIL splits 64-way (depth 1), every other app
        // is a single shard. MUST match the converter and every node, since it
        // determines the committed state root.
        crdt.set_shard_partition(quil_execution::domains::QUIL_TOKEN, 1);
        true
    } else {
        false
    }
}

/// Boot-time forest install. Installs the persistent (RocksDB) forest when the
/// store is EITHER already migrated (`has_forest_data`) OR brand-new/fresh
/// (`store_is_fresh` — no committed state yet), so a fresh forest-native node
/// builds directly on the persistent forest from genesis (rather than the
/// default ephemeral in-memory one, whose roots are correct but never persisted
/// and which never gets `set_shard_partition`, so a QUIL producer would compute
/// a wrong un-split root). Skips ONLY a store that carries un-migrated legacy
/// state (committed frames but no forest) — that MUST run `--migrate-db` first.
/// Idempotent: no-op if the forest is already persistent.
pub fn install_forest_boot(
    crdt: &quil_hypergraph::HypergraphCrdt,
    hg: &RocksHypergraphStore,
    store_is_fresh: bool,
) -> bool {
    if crdt.forest_is_persistent() {
        return false;
    }
    if hg.has_forest_data() || store_is_fresh {
        crdt.set_forest(Forest::with_namespace(
            hg.raw_db(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        crdt.set_shard_partition(quil_execution::domains::QUIL_TOKEN, 1);
        true
    } else {
        false
    }
}

/// Install the persistent (RocksDB) forest on a node that is ONBOARDING via sync
/// (state-jump / bootstrap), regardless of whether the store already carries
/// forest data. A fresh node boots on the default IN-MEMORY forest (its state
/// commits are correct but ephemeral, and `sync_shard_phase_from` writes into
/// that in-memory forest — never persisted), and it never gets
/// `set_shard_partition`, so a QUIL producer would compute a WRONG (un-split)
/// app root. Calling this BEFORE the sync swaps in the namespaced RocksDB forest
/// (shared with the store's DB) + declares the QUIL partition, so the sync writes
/// to disk and subsequent commits produce network-consistent roots.
///
/// Idempotent: a node whose forest is already persistent (migrated at boot, or a
/// prior sync) is left untouched. Unlike [`install_forest_if_migrated`] this does
/// NOT gate on `has_forest_data()` — a syncing node is pulling authenticated
/// state from peers and will fill the (initially empty) forest itself.
pub fn install_forest_for_sync(
    crdt: &quil_hypergraph::HypergraphCrdt,
    hg: &RocksHypergraphStore,
) -> bool {
    if crdt.forest_is_persistent() {
        return false;
    }
    crdt.set_forest(Forest::with_namespace(
        hg.raw_db(),
        quil_store::FOREST_NAMESPACE.to_vec(),
    ));
    crdt.set_shard_partition(quil_execution::domains::QUIL_TOKEN, 1);
    true
}

/// Open a fresh forest DB at `dest_path` and convert the entire hypergraph
/// store into it with the default [`quil_shards_for_app`] partition. The one-call
/// one-call convenience wrapper — `dest_path` must be a NEW/empty path (the
/// forest key-space collides with the source hypergraph store's, so it never
/// shares that DB). `version` is the forest commit version (0 for a fresh DB).
pub fn run_conversion(
    hg: &RocksHypergraphStore,
    dest_path: &std::path::Path,
    version: u64,
    head_frame: u64,
) -> anyhow::Result<ConvertReport> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    let db = std::sync::Arc::new(
        rocksdb::DB::open(&opts, dest_path)
            .map_err(|e| anyhow::anyhow!("open dest forest db {}: {e}", dest_path.display()))?,
    );
    let forest = Forest::new(db);
    convert_db(hg, &forest, version, head_frame, quil_shards_for_app)
}

/// Convert the hypergraph state into a forest written **in place** into the
/// store's OWN RocksDB, under [`quil_store::FOREST_NAMESPACE`]. This is the
/// migration model the runtime expects: the migrated DB then contains both
/// the legacy data and the forest (disjoint key-spaces), and the node gates
/// the forest commitment path on `RocksHypergraphStore::has_forest_data()`.
/// `version` is the forest commit version (0 for a first migration).
pub fn run_conversion_in_place(
    hg: &RocksHypergraphStore,
    version: u64,
    head_frame: u64,
) -> anyhow::Result<ConvertReport> {
    let forest = Forest::with_namespace(hg.raw_db(), quil_store::FOREST_NAMESPACE.to_vec());
    convert_db(hg, &forest, version, head_frame, quil_shards_for_app)
}

/// Build a `shards_for_app` closure from a shards store: each app's REAL prefix
/// set (grouped from `range_app_shards` by app address = `shard_key[3..35]`),
/// falling back to [`quil_shards_for_app`] for an app with no rows. Use this to
/// migrate state that may have ALREADY dynamically split (non-uniform), where the
/// hardcoded default would mis-shard the vertices.
pub fn shards_for_app_from_store(
    shards_store: &dyn quil_types::store::ShardsStore,
) -> impl Fn(&[u8; 32]) -> Vec<Vec<u32>> {
    let mut by_app: std::collections::HashMap<[u8; 32], Vec<Vec<u32>>> =
        std::collections::HashMap::new();
    if let Ok(rows) = shards_store.range_app_shards() {
        for row in rows {
            if row.shard_key.len() >= 35 {
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&row.shard_key[3..35]);
                by_app.entry(l2).or_default().push(row.prefix);
            }
        }
    }
    move |app: &[u8; 32]| by_app.get(app).cloned().unwrap_or_else(|| quil_shards_for_app(app))
}

/// Like [`run_conversion_in_place`] but sources each app's shard set from the
/// SHARDS STORE (via [`shards_for_app_from_store`]) instead of the uniform
/// default — so a DB whose apps have already split non-uniformly migrates onto
/// the correct (canonical bit-path) sub-shard structure.
pub fn run_conversion_in_place_with_shards(
    hg: &RocksHypergraphStore,
    shards_store: &dyn quil_types::store::ShardsStore,
    version: u64,
    head_frame: u64,
) -> anyhow::Result<ConvertReport> {
    let forest = Forest::with_namespace(hg.raw_db(), quil_store::FOREST_NAMESPACE.to_vec());
    convert_db(hg, &forest, version, head_frame, shards_for_app_from_store(shards_store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use quil_forest::{l3_leaf_key, rollup_phase_roots};
    use quil_tries::{serialize_go_tree, VectorCommitmentTree};
    use std::sync::Arc;

    fn open_db(path: &std::path::Path) -> Arc<rocksdb::DB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        Arc::new(rocksdb::DB::open(&opts, path).unwrap())
    }

    fn vertex_blob(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut t = VectorCommitmentTree::new();
        for (k, v) in fields {
            t.insert(k, v, &[], &BigInt::from(v.len() as u64)).unwrap();
        }
        serialize_go_tree(t.root.as_ref()).unwrap()
    }

    #[test]
    fn convert_shard_commits_one_per_vertex_leaf() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let hg = RocksHypergraphStore::new(open_db(src.path()));
        let forest = Forest::new(open_db(dst.path()));

        let shard_key = ShardKey { l2: [0xAAu8; 32], l1: [0u8; 3] };
        // Two vertices in vertex_adds, each with fields.
        let v1 = vec![0x11u8; 64];
        let v2 = vec![0x22u8; 64];
        let type_key = vec![0xFFu8; 32];
        let blob1 = vertex_blob(&[(&type_key, b"prover:Prover"), (&[0x00u8; 32], &[1u8])]);
        let blob2 = vertex_blob(&[(&type_key, b"reward:ProverReward")]);
        hg.save_vertex_underlying("vertex", "adds", &shard_key, &v1, &blob1).unwrap();
        hg.save_vertex_underlying("vertex", "adds", &shard_key, &v2, &blob2).unwrap();

        let sc = convert_shard(&hg, &forest, &shard_key, 0).unwrap();
        // Per-vertex-subtree model: 2 vertices → 2 leaves (one per vertex, NOT
        // one per flattened field).
        assert_eq!(sc.num_leaves, 2);
        assert_eq!(sc.roots.commitment, rollup_phase_roots(&sc.roots.phase_roots));
        // Empty phases (removes/hyperedges) share the same empty-tree root.
        assert_eq!(sc.roots.phase_roots[1], sc.roots.phase_roots[2]);

        // Each vertex is ONE raw-key leaf: `data_address(32) → vertex_leaf_value`
        // (`commitment(32) ‖ size`). Prove it against the vertex_adds shard root.
        let data_addr = &v1[32..64];
        let expected = quil_tries::vertex_leaf_value(&blob1).unwrap();
        let (val, proof) = forest
            .shard_phase_get_with_proof_raw(&shard_key.l2, Phase::VertexAdds, 0, data_addr)
            .unwrap();
        assert_eq!(val.as_deref(), Some(&expected[..]));
        proof
            .verify_existence(
                jmt::RootHash(sc.roots.phase_roots[0]),
                quil_forest::shard_path_key_hash(data_addr),
                &expected,
            )
            .expect("per-vertex leaf verifies against the vertex_adds root");
    }

    /// Seed one vertex (in vertex_adds) for `shard_addr` and register the
    /// shard in the alt-shard index so `range_alt_shard_addresses` finds it.
    fn seed_shard(hg: &RocksHypergraphStore, db: &Arc<rocksdb::DB>, shard_addr: [u8; 32], tag: u8) {
        // Key with the SAME l1 the converter reconstructs (bloom indices of the
        // address), as production does — else the per-vertex read misses it.
        let sk = ShardKey { l2: shard_addr, l1: get_bloom_filter_indices(&shard_addr, 256, 3) };
        hg.save_vertex_underlying(
            "vertex",
            "adds",
            &sk,
            &vec![tag; 64],
            &vertex_blob(&[(&[0xFFu8; 32], b"prover:Prover")]),
        )
        .unwrap();
        db.put(
            quil_store::encoding::hypergraph_alt_shard_address_index_key(&shard_addr),
            [] as [u8; 0],
        )
        .unwrap();
    }

    #[test]
    fn convert_db_enumerates_and_splits_by_global_index() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let db = open_db(src.path());
        let hg = RocksHypergraphStore::new(db.clone());
        let forest = Forest::new(open_db(dst.path()));

        // Two shards whose addresses select different Level-1 global trees.
        let mut a = [0x2au8; 32];
        a[0] = 0x2a;
        let mut b = [0x40u8; 32];
        b[0] = 0x40;
        seed_shard(&hg, &db, a, 0x11);
        seed_shard(&hg, &db, b, 0x22);

        // Model-B default: each app = a single shard (non-QUIL). Two apps →
        // two global trees.
        let report = convert_db(&hg, &forest, 0, 0, quil_shards_for_app).unwrap();
        assert_eq!(report.shards, 2);
        assert_eq!(report.apps, 2);
        assert_eq!(report.global_roots.len(), 2, "two distinct global trees touched");
        assert!(report.global_roots.contains_key(&0x2a));
        assert!(report.global_roots.contains_key(&0x40));
    }

    #[test]
    fn convert_db_splits_quil_app_into_shards() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let db = open_db(src.path());
        let hg = RocksHypergraphStore::new(db.clone());
        let forest = Forest::new(open_db(dst.path()));

        // The QUIL app is split 64-way. Seed two vertices whose DATA addresses
        // (id[32..]) fall in different top-6-bit shards: 0x00 → shard 0,
        // 0xFF → shard 63. id = [app(32) | data(32)].
        let quil = quil_execution::domains::QUIL_TOKEN;
        let sk = ShardKey { l2: quil, l1: get_bloom_filter_indices(&quil, 256, 3) };
        for data0 in [0x00u8, 0xFFu8] {
            let mut id = [0u8; 64];
            id[..32].copy_from_slice(&quil);
            id[32] = data0;
            hg.save_vertex_underlying(
                "vertex",
                "adds",
                &sk,
                &id[..],
                &vertex_blob(&[(&[0xFFu8; 32], b"prover:Prover")]),
            )
            .unwrap();
        }
        db.put(
            quil_store::encoding::hypergraph_alt_shard_address_index_key(&quil),
            [] as [u8; 0],
        )
        .unwrap();

        let report = convert_db(&hg, &forest, 0, 0, quil_shards_for_app).unwrap();
        assert_eq!(report.apps, 1, "one QUIL app");
        assert_eq!(report.shards, 2, "two of the 64 shards carry state");
        let g = global_tree_index(&quil);
        assert!(report.global_roots.contains_key(&g));

        // Shards 0 and 63 committed non-empty vertex-adds trees; a third
        // (empty) shard did not — the split routed each vertex by its address.
        let empty = forest
            .shard_phase_root(&Forest::addr_path_shard_id(&quil, &[1u32]), Phase::VertexAdds, 0)
            .unwrap();
        for i in [0u32, 63u32] {
            let root = forest
                .shard_phase_root(&Forest::addr_path_shard_id(&quil, &[i]), Phase::VertexAdds, 0)
                .unwrap();
            assert!(root.is_some(), "shard {i} committed");
            assert_ne!(root, empty, "shard {i} is non-empty, unlike shard 1");
        }
    }

    #[test]
    fn convert_shard_uses_whole_tree_blob_fallback() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let db = open_db(src.path());
        let hg = RocksHypergraphStore::new(db.clone());
        let forest = Forest::new(open_db(dst.path()));
        let shard_key = ShardKey { l2: [0xBBu8; 32], l1: [0u8; 3] };

        // Seed a WHOLE-TREE blob (no per-vertex rows): a tree whose leaves are
        // (vertex_address, per_vertex_blob).
        let v1 = vec![0x33u8; 64];
        let inner = vertex_blob(&[(&[0xFFu8; 32], b"prover:Prover")]);
        let mut outer = VectorCommitmentTree::new();
        outer.insert(&v1, &inner, &[], &BigInt::from(inner.len() as u64)).unwrap();
        let tree_blob = quil_tries::serialize_tree(outer.root.as_ref()).unwrap();
        let key = quil_store::encoding::hypergraph_tree_blob_key("vertex", "adds", &shard_key);
        db.put(&key, &tree_blob).unwrap();

        let sc = convert_shard(&hg, &forest, &shard_key, 0).unwrap();
        assert_eq!(sc.num_leaves, 1, "fallback path flattened the one vertex field");
    }
}
