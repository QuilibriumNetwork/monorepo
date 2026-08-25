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

/// Commit one sub-shard's ONE phase from its `(vertex_key, blob)` buffer, write
/// the phase-tree head version, and (for the vertex-adds phase) fold the leaf
/// count + live size into the app aggregates. Returns the phase root. Factored
/// out so the streaming `convert_app` can flush a sub-shard the moment its
/// contiguous run of vertices ends — without ever holding a second sub-shard.
#[allow(clippy::too_many_arguments)]
fn commit_subshard_phase(
    forest: &Forest,
    app_l2: &[u8; 32],
    prefix: &[u32],
    phase: Phase,
    version: u64,
    buffer: Vec<(Vec<u8>, Vec<u8>)>,
    num_leaves: &mut u64,
    total_size: &mut u128,
) -> anyhow::Result<[u8; 32]> {
    let leaves = per_vertex_phase_leaves(buffer)?;
    if phase == Phase::VertexAdds {
        *num_leaves += leaves.len() as u64;
        *total_size += leaves.iter().map(|(_, v)| quil_forest::vertex_leaf_size(v)).sum::<u128>();
    }
    let shard_id = Forest::addr_path_shard_id(app_l2, prefix);
    let root = forest
        .commit_shard_phase_raw(&shard_id, phase, version, leaves)
        .map_err(|e| anyhow::anyhow!("commit_shard_phase_raw: {e}"))?;
    forest
        .write_head_version(&shard_id, phase, version)
        .map_err(|e| anyhow::anyhow!("write_head_version: {e}"))?;
    Ok(root)
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
///
/// STREAMING (bounded memory): the legacy vertices are read one at a time in
/// address order (`for_each_vertex_unversioned_ordered`), and because the
/// address-path keys sort by `domain ‖ address`, a sub-shard's vertices (the top
/// `bpl` address bits) arrive as one contiguous run. We buffer only the CURRENT
/// sub-shard and commit it the instant the run ends — so peak memory is O(one
/// sub-shard), NOT O(app). Roots are byte-identical to the old all-at-once path:
/// `per_vertex_phase_leaves` is per-vertex and the JMT is content-addressed, so
/// the same leaves under the same shard produce the same root regardless of how
/// they were buffered. A 100+ GB QUIL coin set used to be loaded whole (OOM).
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
    let n = prefixes.len();

    // Per phase, per sub-shard: the committed phase root (None until committed).
    let mut phase_roots: [Vec<Option<[u8; 32]>>; 4] = Default::default();
    for p in 0..4 {
        phase_roots[p] = vec![None; n];
    }
    let mut num_leaves: u64 = 0;
    let mut total_size: u128 = 0;
    // Which sub-shards carry any real (non-empty) state, for the "app has state"
    // decision and the returned nonempty count.
    let mut sub_has_state = vec![false; n];

    for phase in PHASES {
        let (set, ph) = phase_strs(phase);

        // (a) v2 pass: bucket the MVCC v2 vertices by sub-shard, and record their
        // keys so the (b) unversioned scan skips any it superseded. Bounded by the
        // v2 count — nil on a fresh Go→rocks DB (v2 is written only by the live
        // Rust commit AFTER migration), small on a re-run.
        let mut v2_bufs: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![Vec::new(); n];
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        hg.for_each_vertex_v2_max_version(set, ph, app_shard_key, |vk, blob| {
            let data: &[u8] = if vk.len() == 64 { &vk[32..] } else { vk };
            let si = quil_forest::address_shard_index(data, &bit_paths);
            v2_bufs[si].push((vk.to_vec(), blob.to_vec()));
            seen.insert(vk.to_vec());
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("v2 scan {set}/{ph}: {e}"))?;
        let had_v2 = !seen.is_empty();

        // (b) unversioned pass: stream in address order, flushing one contiguous
        // sub-shard at a time — combined with that sub-shard's v2 leaves.
        let mut cur_sub: Option<usize> = None;
        let mut buffer: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        let rows = hg.for_each_vertex_unversioned_ordered(
            set,
            ph,
            app_shard_key,
            |vk, blob| {
                if seen.contains(vk) {
                    return Ok(()); // superseded by a v2 rewrite
                }
                let data: &[u8] = if vk.len() == 64 { &vk[32..] } else { vk };
                let si = quil_forest::address_shard_index(data, &bit_paths);
                match cur_sub {
                    Some(c) if c == si => buffer.push((vk.to_vec(), blob.to_vec())),
                    Some(c) => {
                        // Contiguity invariant: address-ordered keys ⇒ sub-shard
                        // index is monotonically non-decreasing. A decrease means
                        // the key layout assumption is wrong — fail LOUDLY rather
                        // than silently produce a divergent root.
                        if si < c {
                            return Err(quil_types::error::QuilError::Store(format!(
                                "forest migration: non-monotonic sub-shard {si} < {c}; \
                                 vertex-key ordering assumption violated for phase {ph}"
                            )));
                        }
                        let mut taken = std::mem::take(&mut buffer);
                        taken.append(&mut v2_bufs[c]);
                        let root = commit_subshard_phase(
                            forest, &app_shard_key.l2, &prefixes[c], phase, version,
                            taken, &mut num_leaves, &mut total_size,
                        )
                        .map_err(|e| quil_types::error::QuilError::Store(e.to_string()))?;
                        phase_roots[phase as usize][c] = Some(root);
                        sub_has_state[c] = true;
                        cur_sub = Some(si);
                        buffer.push((vk.to_vec(), blob.to_vec()));
                    }
                    None => {
                        cur_sub = Some(si);
                        buffer.push((vk.to_vec(), blob.to_vec()));
                    }
                }
                Ok(())
            },
        )
        .map_err(|e| anyhow::anyhow!("stream {set}/{ph}: {e}"))?;

        // Flush the final contiguous run (combined with its v2 leaves).
        if let Some(c) = cur_sub {
            let mut taken = std::mem::take(&mut buffer);
            taken.append(&mut v2_bufs[c]);
            let root = commit_subshard_phase(
                forest, &app_shard_key.l2, &prefixes[c], phase, version,
                taken, &mut num_leaves, &mut total_size,
            )?;
            phase_roots[phase as usize][c] = Some(root);
            sub_has_state[c] = true;
        }

        // Sub-shards touched ONLY by v2 (no unversioned run reached them).
        for si in 0..n {
            if !v2_bufs[si].is_empty() {
                let taken = std::mem::take(&mut v2_bufs[si]);
                let root = commit_subshard_phase(
                    forest, &app_shard_key.l2, &prefixes[si], phase, version,
                    taken, &mut num_leaves, &mut total_size,
                )?;
                phase_roots[phase as usize][si] = Some(root);
                sub_has_state[si] = true;
            }
        }

        // Legacy whole-tree-blob fallback: a pre-per-vertex-commit shard keeps
        // its leaves in a single serialized tree rather than the vertex keyspace,
        // so BOTH keyspace scans find nothing. Load it (bounded — this format
        // predates the large coin sets) and route + commit per sub-shard.
        if rows == 0 && !had_v2 {
            if let Some(blob) = hg
                .load_tree_blob(set, ph, app_shard_key)
                .map_err(|e| anyhow::anyhow!("load_tree_blob {set}/{ph}: {e}"))?
            {
                if let Some(root_node) = quil_tries::deserialize_tree(&blob)
                    .map_err(|e| anyhow::anyhow!("deserialize_tree {set}/{ph}: {e}"))?
                {
                    let mut t = quil_tries::VectorCommitmentTree::new();
                    t.root = Some(root_node);
                    let mut buckets: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![Vec::new(); n];
                    for (vk, b) in t.leaves() {
                        let data: &[u8] = if vk.len() == 64 { &vk[32..] } else { &vk[..] };
                        let si = quil_forest::address_shard_index(data, &bit_paths);
                        buckets[si].push((vk, b));
                    }
                    for (si, buf) in buckets.into_iter().enumerate() {
                        if buf.is_empty() {
                            continue;
                        }
                        let root = commit_subshard_phase(
                            forest, &app_shard_key.l2, &prefixes[si], phase, version,
                            buf, &mut num_leaves, &mut total_size,
                        )?;
                        phase_roots[phase as usize][si] = Some(root);
                        sub_has_state[si] = true;
                    }
                }
            }
        }

        // Commit the empty (never-touched) sub-shards for this phase so the
        // aggregation is over the COMPLETE set (empty shard = empty-JMT root).
        for si in 0..n {
            if phase_roots[phase as usize][si].is_none() {
                let root = commit_subshard_phase(
                    forest, &app_shard_key.l2, &prefixes[si], phase, version,
                    Vec::new(), &mut num_leaves, &mut total_size,
                )?;
                phase_roots[phase as usize][si] = Some(root);
            }
        }
    }

    let nonempty = sub_has_state.iter().filter(|&&b| b).count();
    if num_leaves == 0 && nonempty == 0 {
        return Ok(None);
    }

    // Aggregate the sub-shard roots into an app root PER PHASE, then roll the
    // four app phase roots up into the app commitment.
    let mut app_phase_roots = [[0u8; 32]; 4];
    for p in 0..4 {
        let shards: Vec<(Vec<bool>, [u8; 32])> = (0..n)
            .map(|si| (bit_paths[si].clone(), phase_roots[p][si].unwrap_or([0u8; 32])))
            .collect();
        app_phase_roots[p] = app_root_from_shard_paths(&shards);
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

    // L1: commit each touched global tree. Record each bucket's head version
    // (as the shard-phase trees do) so the LIVE commit path can resolve the
    // next version (`head + 1`) after the forest version advances past the
    // migration version — without it, the first live L1 commit would start at
    // version 0 and JMT would reject the out-of-order write.
    let mut global_roots = BTreeMap::new();
    for (g, apps) in global_apps {
        let root = forest
            .commit_global(g, version, apps)
            .map_err(|e| anyhow::anyhow!("commit_global: {e}"))?;
        forest
            .write_global_head_version(g, version)
            .map_err(|e| anyhow::anyhow!("write_global_head_version: {e}"))?;
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
/// `mainnet_quil_grid`: when true (mainnet, network 0), declare QUIL's fixed
/// 64-way (`depth 1`) uniform split — the legacy topology the pebble→rocksdb
/// migration and the committed mainnet state root depend on. When false
/// (testnet/devnet), QUIL is left at the default single-shard partition and
/// splits dynamically like every other app; declaring a split here would make
/// genesis `commit(0)` aggregate over 64 sub-shards and fork against the
/// single-shard shards-store registry.
pub fn install_forest_boot(
    crdt: &quil_hypergraph::HypergraphCrdt,
    hg: &RocksHypergraphStore,
    store_is_fresh: bool,
    mainnet_quil_grid: bool,
) -> bool {
    if crdt.forest_is_persistent() {
        return false;
    }
    if hg.has_forest_data() || store_is_fresh {
        crdt.set_forest(Forest::with_namespace(
            hg.raw_db(),
            quil_store::FOREST_NAMESPACE.to_vec(),
        ));
        if mainnet_quil_grid {
            crdt.set_shard_partition(quil_execution::domains::QUIL_TOKEN, 1);
        }
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
/// `mainnet_quil_grid`: see [`install_forest_boot`]. Mainnet declares the fixed
/// 64-way QUIL split so a syncing node computes the network-consistent app root;
/// testnet/devnet leaves QUIL single-shard (its network is single-shard, so the
/// default is already correct and a declared split would produce a wrong root).
pub fn install_forest_for_sync(
    crdt: &quil_hypergraph::HypergraphCrdt,
    hg: &RocksHypergraphStore,
    mainnet_quil_grid: bool,
) -> bool {
    if crdt.forest_is_persistent() {
        return false;
    }
    crdt.set_forest(Forest::with_namespace(
        hg.raw_db(),
        quil_store::FOREST_NAMESPACE.to_vec(),
    ));
    if mainnet_quil_grid {
        crdt.set_shard_partition(quil_execution::domains::QUIL_TOKEN, 1);
    }
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

/// UNIFIED-APP-TREE consolidation (the Phase-2 `UNIFIED_APP_TREE_DESIGN.md` §9
/// cutover, run in place). For every SPLIT app — one with a real sub-shard
/// partition, not a single shard — rebuild its ONE app tree
/// (`TreeId::shard_phase(app, phase)`) from the app's vertices via
/// [`convert_app`] with a SINGLE EMPTY prefix: all leaves land in the app tree,
/// raw-key positioned, so a shard becomes the in-place subtree at its prefix.
///
/// The unified app root produced here is byte-identical to what `commit_inner`
/// emits in unified mode (same leaves, content-addressed JMT). Single-shard apps
/// are ALREADY their own app tree (the live path keys them by `app.l2`), so they
/// are SKIPPED — rebuilding would collide with their live version. This does NOT
/// touch L1: `commit_inner` rebuilds each app's L1 leaf with the unified root the
/// first time it commits that app at/after the cutover frame.
///
/// The CALLER guards idempotency (a persisted marker) and the flag-day gate — this
/// routine unconditionally rebuilds the split apps it finds. Returns the count of
/// apps consolidated. `version` should be `0` (the app trees are fresh keyspace;
/// live commits then continue from the written head version).
/// Peak-memory bound for the streaming fold: commit the app tree in chunks of at
/// most this many leaves. Overridable via `QUIL_FOLD_CHUNK_LEAVES` for stores with
/// unusually large per-vertex blobs. Because the final root is history-independent
/// (JMT) and the chunk size affects only the LOCAL head-version number (not the
/// committed root), nodes may safely use different values.
fn fold_chunk_leaves() -> usize {
    std::env::var("QUIL_FOLD_CHUNK_LEAVES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(50_000)
}

/// Bounded-memory unified fold: rebuild an app's ONE tree (`shard_phase(app)`)
/// from its vertices, committing in fixed-size chunks across SUCCESSIVE versions
/// instead of buffering the whole app. `put_value_set` builds each version on the
/// prior (the same delta-per-version pattern the live commit path uses), so the
/// final version holds every leaf and its root is byte-identical to a single
/// all-at-once `convert_app(&[Vec::new()])` — but peak memory is O(chunk).
///
/// This fixes the OOM the single-empty-prefix `convert_app` reintroduces: with one
/// sub-shard, its streaming per-sub-shard flush never triggers, so it buffered
/// QUIL's entire 100+GB coin set before one giant commit. Empty phases are
/// committed empty at version 0 (parity with `convert_app`, so the app-root rollup
/// is over the complete four-phase set). Live commits resume at head+1
/// (`commit_one_shard_phase`), so each phase's head is set to its final chunk
/// version. Idempotent: a re-run after a crashed fold rebuilds the same per-version
/// deltas. Returns whether the app carried any state.
fn fold_app_into_single_tree(
    hg: &RocksHypergraphStore,
    forest: &Forest,
    app_shard_key: &ShardKey,
    chunk: usize,
) -> anyhow::Result<bool> {
    use quil_types::error::QuilError;
    let chunk = chunk.max(1);
    let shard_id = Forest::addr_path_shard_id(&app_shard_key.l2, &[]);
    let app_hex: String =
        app_shard_key.l2.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let mut app_has_state = false;

    for phase in PHASES {
        let (set, ph) = phase_strs(phase);

        // (a) v2 max-version leaves (bounded — nil on a freshly-migrated DB), plus
        //     the key set to skip in the unversioned pass (superseded rewrites).
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut v2_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        hg.for_each_vertex_v2_max_version(set, ph, app_shard_key, |vk, blob| {
            seen.insert(vk.to_vec());
            v2_leaves.push((vk.to_vec(), blob.to_vec()));
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("v2 scan {set}/{ph}: {e}"))?;

        // Running per-phase commit state.
        let mut next_version: u64 = 0;
        let mut last_committed: Option<u64> = None;
        let mut total_leaves: u64 = 0;
        let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        // (b) unversioned ordered pass — the bulk; flush a full chunk inline so
        //     peak memory is O(chunk), never O(app).
        hg.for_each_vertex_unversioned_ordered(set, ph, app_shard_key, |vk, blob| {
            if seen.contains(vk) {
                return Ok(()); // superseded by a v2 rewrite
            }
            batch.push((vk.to_vec(), blob.to_vec()));
            if batch.len() >= chunk {
                let n = batch.len() as u64;
                let leaves = per_vertex_phase_leaves(std::mem::take(&mut batch))
                    .map_err(|e| QuilError::Store(e.to_string()))?;
                forest
                    .commit_shard_phase_raw(&shard_id, phase, next_version, leaves)
                    .map_err(|e| QuilError::Store(e.to_string()))?;
                last_committed = Some(next_version);
                next_version += 1;
                total_leaves += n;
                if next_version % 20 == 0 {
                    tracing::info!(
                        app = %app_hex, phase = ph, chunks = next_version, leaves = total_leaves,
                        "unified fold: progress (streaming chunks)"
                    );
                }
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("stream {set}/{ph}: {e}"))?;

        // Continue chunking through the tail + the v2 rewrites (v2 keys were skipped
        // above, so this is their only writer; a later version wins regardless).
        batch.append(&mut v2_leaves);
        while !batch.is_empty() {
            let take: Vec<(Vec<u8>, Vec<u8>)> =
                batch.drain(..batch.len().min(chunk)).collect();
            let n = take.len() as u64;
            let leaves = per_vertex_phase_leaves(take)?;
            forest.commit_shard_phase_raw(&shard_id, phase, next_version, leaves)?;
            last_committed = Some(next_version);
            next_version += 1;
            total_leaves += n;
        }

        // (c) whole-tree-blob fallback (pre-per-vertex-commit shards) — only if the
        //     keyspace scans found nothing. Chunked the same way.
        if last_committed.is_none() {
            if let Some(blob) = hg
                .load_tree_blob(set, ph, app_shard_key)
                .map_err(|e| anyhow::anyhow!("load_tree_blob {set}/{ph}: {e}"))?
            {
                if let Some(root_node) = quil_tries::deserialize_tree(&blob)
                    .map_err(|e| anyhow::anyhow!("deserialize_tree {set}/{ph}: {e}"))?
                {
                    let mut t = quil_tries::VectorCommitmentTree::new();
                    t.root = Some(root_node);
                    let mut fb: Vec<(Vec<u8>, Vec<u8>)> = t.leaves();
                    while !fb.is_empty() {
                        let take: Vec<(Vec<u8>, Vec<u8>)> =
                            fb.drain(..fb.len().min(chunk)).collect();
                        let leaves = per_vertex_phase_leaves(take)?;
                        forest.commit_shard_phase_raw(&shard_id, phase, next_version, leaves)?;
                        last_committed = Some(next_version);
                        next_version += 1;
                    }
                }
            }
        }

        // Record the head at the phase's final version. An empty phase commits an
        // empty tree at version 0 (parity with convert_app's complete-set rollup).
        let head = match last_committed {
            Some(v) => {
                app_has_state = true;
                v
            }
            None => {
                forest
                    .commit_shard_phase_raw(&shard_id, phase, 0, Vec::new())
                    .map_err(|e| anyhow::anyhow!("commit empty {set}/{ph}: {e}"))?;
                0
            }
        };
        forest
            .write_head_version(&shard_id, phase, head)
            .map_err(|e| anyhow::anyhow!("write_head_version {set}/{ph}: {e}"))?;
        if last_committed.is_some() {
            tracing::info!(
                app = %app_hex, phase = ph, head, leaves = total_leaves,
                "unified fold: phase folded into the app tree"
            );
        }
    }

    Ok(app_has_state)
}

pub fn run_unified_consolidation_in_place(
    hg: &RocksHypergraphStore,
    shards_store: &dyn quil_types::store::ShardsStore,
    version: u64,
    head_frame: u64,
) -> anyhow::Result<usize> {
    let forest = Forest::with_namespace(hg.raw_db(), quil_store::FOREST_NAMESPACE.to_vec());
    let shards_for_app = shards_for_app_from_store(shards_store);

    // Enumerate every app that carries state (the same union `convert_db` uses:
    // the all-time split sub-shard index ∪ a lookback window of shard commits).
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
    // ALSO enumerate every app in the current GRID (`shards_store`). Without this
    // an app whose state is entirely HISTORICAL — no commit within the lookback
    // window and not in the alt-shard index — is MISSED: e.g. QUIL, whose recent
    // writes are prover-only, so it never appeared via the two sources above and
    // its app tree was left EMPTY (splits could never see any data). The grid key
    // is `L1(3) ‖ L2(32)`; the app address is the L2.
    if let Ok(rows) = shards_store.range_app_shards() {
        for s in rows {
            if s.shard_key.len() >= 3 + 32 {
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(&s.shard_key[3..3 + 32]);
                shard_keys.insert(ShardKey {
                    l1: get_bloom_filter_indices(&l2, 256, 3),
                    l2,
                });
            }
        }
    }

    let mut consolidated = 0usize;
    for shard_key in &shard_keys {
        let prefixes = shards_for_app(&shard_key.l2);
        // Split iff there's more than one shard OR a single non-empty prefix.
        // A single empty prefix is an unsplit app → already its own app tree.
        let is_split = prefixes.len() > 1 || prefixes.iter().any(|p| !p.is_empty());
        if !is_split {
            continue;
        }
        // Rebuild the app's ONE tree with the bounded-memory streaming fold (empty
        // prefix ⇒ every vertex routes to the app.l2 tree). Chunked across versions
        // so a 100+GB app never buffers whole — the OOM the empty-prefix
        // `convert_app` hit (its per-sub-shard streaming flush never triggers when
        // there is only one sub-shard). Writes per-phase head versions like convert_app.
        let _ = version; // fold is version-0-based; live commits resume at head+1
        if fold_app_into_single_tree(hg, &forest, shard_key, fold_chunk_leaves())? {
            consolidated += 1;
        }
    }
    Ok(consolidated)
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

    /// Phase-2 §9 consolidation: rebuilding a SPLIT app with a single empty
    /// prefix yields ONE app tree whose root IS the JMT root (native, no
    /// `app_root_from_shard_paths` rollup) — byte-identical to unified
    /// `commit_inner` — differing from the legacy 64-way rollup (the fork), with
    /// every vertex proving directly against the app root (shard = subtree).
    #[test]
    fn unified_consolidation_builds_one_app_tree_matching_the_jmt_root() {
        use quil_execution::domains::QUIL_TOKEN;

        let src = tempfile::tempdir().unwrap();
        let dst_legacy = tempfile::tempdir().unwrap();
        let dst_unified = tempfile::tempdir().unwrap();
        let hg = RocksHypergraphStore::new(open_db(src.path()));
        let app_key = ShardKey { l2: QUIL_TOKEN, l1: [0u8; 3] };
        let type_key = vec![0xFFu8; 32];

        // 3 vertices in QUIL sub-shards 0, 1, 63 (by the top-6 address bits).
        for (b0, tag) in [(0x00u8, 0xA1u8), (0x04, 0xB2), (0xFC, 0xC3)] {
            let mut data_addr = [0u8; 32];
            data_addr[0] = b0;
            data_addr[31] = tag;
            let mut vk = QUIL_TOKEN.to_vec();
            vk.extend_from_slice(&data_addr);
            let blob = vertex_blob(&[(&type_key, b"token:Coin")]);
            hg.save_vertex_underlying("vertex", "adds", &app_key, &vk, &blob).unwrap();
        }

        // Legacy: 64-way split → per-sub-shard trees + hash_pair rollup.
        let forest_legacy = Forest::new(open_db(dst_legacy.path()));
        let (legacy, _) = convert_app(&hg, &forest_legacy, &app_key, 0, &quil_shards_for_app(&QUIL_TOKEN))
            .unwrap()
            .unwrap();

        // Unified consolidation: SINGLE empty prefix → ONE app tree.
        let forest_unified = Forest::new(open_db(dst_unified.path()));
        let (unified, nonempty) =
            convert_app(&hg, &forest_unified, &app_key, 0, &[Vec::new()]).unwrap().unwrap();

        // The unified commitment IS the rollup of the ONE app tree's four native
        // phase JMT roots (no per-sub-shard `app_root_from_shard_paths`).
        let mut phase_roots = [[0u8; 32]; 4];
        for (i, ph) in PHASES.iter().enumerate() {
            phase_roots[i] =
                forest_unified.app_subtree_root(&QUIL_TOKEN, *ph, 0, &[]).unwrap();
        }
        assert_eq!(
            unified.app_root,
            rollup_phase_roots(&phase_roots),
            "unified commitment == rollup of the app tree's phase roots"
        );
        let jmt_root = phase_roots[Phase::VertexAdds as usize]; // for the leaf proof below
        assert_eq!(unified.num_leaves, 3, "all 3 vertices in the one app tree");
        assert_eq!(nonempty, 1, "one non-empty shard = the whole app");
        assert_ne!(unified.app_root, legacy.app_root, "unified != legacy rollup (the fork)");
        assert_eq!(unified.num_leaves, legacy.num_leaves, "same leaves, invariant to sharding");

        // A vertex proves DIRECTLY against the unified app root (shard=subtree).
        let mut probe = [0u8; 32];
        probe[0] = 0xFC;
        probe[31] = 0xC3;
        let expected =
            quil_tries::vertex_leaf_value(&vertex_blob(&[(&type_key, b"token:Coin")])).unwrap();
        let (val, proof) = forest_unified
            .shard_phase_get_with_proof_raw(&QUIL_TOKEN, Phase::VertexAdds, 0, &probe)
            .unwrap();
        assert_eq!(val.as_deref(), Some(&expected[..]));
        proof
            .verify_existence(
                jmt::RootHash(jmt_root),
                quil_forest::shard_path_key_hash(&probe),
                &expected,
            )
            .expect("leaf verifies against the unified app root");
    }

    /// The streaming `convert_app` routes an app's vertices to the right
    /// sub-shard from a SINGLE ordered pass (peak memory = one sub-shard, not the
    /// whole app — the fix for the QUIL coin-set OOM), and each vertex proves
    /// against ITS sub-shard's root. Three vertices in a QUIL-style 64-way split
    /// land in sub-shards 0, 1, and 63 (by the top 6 address bits), arriving in
    /// address order so the per-sub-shard flush stays monotonic.
    #[test]
    fn convert_app_streams_multi_subshard_and_routes_correctly() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let hg = RocksHypergraphStore::new(open_db(src.path()));
        let forest = Forest::new(open_db(dst.path()));

        let app_key = ShardKey { l2: [0xAAu8; 32], l1: [0u8; 3] };
        // QUIL-style 64-way split.
        let prefixes: Vec<Vec<u32>> = (0..64u32).map(|i| vec![i]).collect();

        // vertex_key = domain(32) ‖ address(32); the top 6 address bits pick the
        // sub-shard. 0x00→0, 0x04→1, 0xFC→63.
        let domain = [0x11u8; 32];
        let mk = |first: u8| -> ([u8; 32], Vec<u8>) {
            let mut addr = [0u8; 32];
            addr[0] = first;
            let mut vk = domain.to_vec();
            vk.extend_from_slice(&addr);
            (addr, vk)
        };
        let type_key = vec![0xFFu8; 32];
        let cases: [(u8, usize); 3] = [(0x00, 0), (0x04, 1), (0xFC, 63)];
        for (first, _sub) in cases {
            let (_addr, vk) = mk(first);
            let blob = vertex_blob(&[(&type_key, b"x"), (&[first; 32], &[first])]);
            hg.save_vertex_underlying("vertex", "adds", &app_key, &vk, &blob).unwrap();
        }

        let (entry, nonempty) = convert_app(&hg, &forest, &app_key, 0, &prefixes).unwrap().unwrap();
        assert_eq!(entry.num_leaves, 3, "all three vertices counted");
        assert_eq!(nonempty, 3, "three distinct sub-shards carry state");

        // Each vertex proves against ITS sub-shard's vertex-adds root — i.e. it
        // was routed to the correct sub-shard tree, not sub-shard 0.
        for (first, sub) in cases {
            let (addr, vk) = mk(first);
            let blob = vertex_blob(&[(&type_key, b"x"), (&[first; 32], &[first])]);
            let _ = &vk;
            let shard_id = Forest::addr_path_shard_id(&app_key.l2, &[sub as u32]);
            let expected = quil_tries::vertex_leaf_value(&blob).unwrap();
            let (val, _proof) = forest
                .shard_phase_get_with_proof_raw(&shard_id, Phase::VertexAdds, 0, &addr)
                .unwrap();
            assert_eq!(
                val.as_deref(),
                Some(&expected[..]),
                "vertex 0x{first:02x} present under sub-shard {sub}",
            );
        }

        // Deterministic: a second conversion into a fresh forest yields the same
        // app root.
        let dst2 = tempfile::tempdir().unwrap();
        let forest2 = Forest::new(open_db(dst2.path()));
        let (entry2, _) = convert_app(&hg, &forest2, &app_key, 0, &prefixes).unwrap().unwrap();
        assert_eq!(entry.app_root, entry2.app_root, "app root is deterministic");
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

    /// The mainnet regression the grid-enumeration fix closes: an app whose
    /// state is entirely HISTORICAL — reachable via NEITHER the alt-shard index
    /// NOR any recent shard commit, only via the current grid (`shards_store`) —
    /// must still be folded into its single app tree by the boot consolidation.
    /// This is exactly the condition that left QUIL's unified app tree EMPTY
    /// (its recent writes were prover-only), so splits could never see any data.
    #[test]
    fn consolidation_folds_grid_only_app_that_the_legacy_enumeration_misses() {
        use quil_execution::domains::QUIL_TOKEN;
        use quil_store::{RocksDb, RocksShardsStore};
        use quil_types::store::{KvDb, ShardInfo, ShardsStore};

        let src = tempfile::tempdir().unwrap();
        let src_db = open_db(src.path());
        let hg = RocksHypergraphStore::new(src_db.clone());

        // QUIL carries state ONLY in the hypergraph, keyed under the SAME l1 the
        // consolidation reconstructs (`bloom(l2)`), across three sub-shards.
        let quil = QUIL_TOKEN;
        let app_key = ShardKey { l2: quil, l1: get_bloom_filter_indices(&quil, 256, 3) };
        let type_key = vec![0xFFu8; 32];
        for (b0, tag) in [(0x00u8, 0xA1u8), (0x04, 0xB2), (0xFC, 0xC3)] {
            let mut data_addr = [0u8; 32];
            data_addr[0] = b0;
            data_addr[31] = tag;
            let mut vk = quil.to_vec();
            vk.extend_from_slice(&data_addr);
            let blob = vertex_blob(&[(&type_key, b"token:Coin")]);
            hg.save_vertex_underlying("vertex", "adds", &app_key, &vk, &blob).unwrap();
        }

        // Precondition: BOTH legacy enumeration sources are empty, so the pre-fix
        // consolidation (alt-shard ∪ recent-commits) would never reach QUIL.
        assert!(
            HypergraphStore::range_alt_shard_addresses(&hg).unwrap().is_empty(),
            "QUIL is NOT in the alt-shard index (historical, prover-only recent writes)"
        );
        assert!(
            HypergraphStore::get_root_commits(&hg, 0).unwrap().is_empty(),
            "no recent shard commit lists QUIL"
        );

        // The QUIL grid IS registered in the shards store as a multi-prefix split.
        let shdb = RocksDb::open_in_memory().unwrap();
        let shards_store = RocksShardsStore::new(shdb.inner());
        let mut sk35 = Vec::with_capacity(35);
        sk35.extend_from_slice(&app_key.l1);
        sk35.extend_from_slice(&quil);
        {
            let txn = shdb.new_batch(false).unwrap();
            for p in [0u32, 1, 63] {
                shards_store
                    .put_app_shard(
                        txn.as_ref(),
                        &ShardInfo {
                            shard_key: sk35.clone(),
                            prefix: vec![p],
                            size: Vec::new(),
                            data_shards: 0,
                            commitment: Vec::new(),
                        },
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        // REGRESSION GUARD: with an EMPTY grid, QUIL is enumerated by NONE of the
        // three sources → nothing is consolidated. This is the pre-fix behavior.
        {
            let empty_shdb = RocksDb::open_in_memory().unwrap();
            let empty_store = RocksShardsStore::new(empty_shdb.inner());
            let n = run_unified_consolidation_in_place(&hg, &empty_store, 0, 0).unwrap();
            assert_eq!(n, 0, "without the grid source QUIL is missed — the empty-app-tree bug");
        }

        // THE FIX: the grid source enumerates QUIL and folds it into ONE app tree.
        let n = run_unified_consolidation_in_place(&hg, &shards_store, 0, 0).unwrap();
        assert_eq!(n, 1, "QUIL enumerated via the grid and consolidated");

        // The app tree is now POPULATED (was [0;32] = empty before the fold).
        let forest = Forest::with_namespace(src_db.clone(), quil_store::FOREST_NAMESPACE.to_vec());
        let vadds_root = forest.app_subtree_root(&quil, Phase::VertexAdds, 0, &[]).unwrap();
        assert_ne!(vadds_root, [0u8; 32], "unified app tree is non-empty after the fold");

        // A seeded vertex proves DIRECTLY against the unified app root (shard =
        // subtree at the empty prefix) — the leaf really landed in the app tree.
        let mut probe = [0u8; 32];
        probe[0] = 0xFC;
        probe[31] = 0xC3;
        let expected =
            quil_tries::vertex_leaf_value(&vertex_blob(&[(&type_key, b"token:Coin")])).unwrap();
        let (val, proof) = forest
            .shard_phase_get_with_proof_raw(&quil, Phase::VertexAdds, 0, &probe)
            .unwrap();
        assert_eq!(val.as_deref(), Some(&expected[..]));
        proof
            .verify_existence(
                jmt::RootHash(vadds_root),
                quil_forest::shard_path_key_hash(&probe),
                &expected,
            )
            .expect("folded leaf verifies against the unified app root");
    }

    /// The bounded-memory streaming fold (chunked across successive versions) must
    /// produce a tree byte-identical to a single all-at-once fold, with EVERY leaf
    /// provable against the final-version root — this is the OOM fix's correctness
    /// guarantee (JMT roots are history-independent for the final live set).
    #[test]
    fn streaming_fold_chunks_across_versions_match_single_commit() {
        use quil_execution::domains::QUIL_TOKEN;

        let src = tempfile::tempdir().unwrap();
        let hg = RocksHypergraphStore::new(open_db(src.path()));
        let quil = QUIL_TOKEN;
        let app_key = ShardKey { l2: quil, l1: get_bloom_filter_indices(&quil, 256, 3) };
        let type_key = vec![0xFFu8; 32];

        // Seed 7 distinct QUIL vertices (spanning sub-shards, in address order).
        let addrs: Vec<[u8; 32]> = (0u8..7)
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i * 0x20; // 0x00,0x20,.. spread across the top bits
                a[31] = 0xD0 + i;
                a
            })
            .collect();
        for a in &addrs {
            let mut vk = quil.to_vec();
            vk.extend_from_slice(a);
            hg.save_vertex_underlying(
                "vertex",
                "adds",
                &app_key,
                &vk,
                &vertex_blob(&[(&type_key, b"token:Coin")]),
            )
            .unwrap();
        }

        // Fold A: tiny chunk=2 → forces MULTIPLE versions (4 chunks: 2+2+2+1).
        let dst_chunked = tempfile::tempdir().unwrap();
        let forest_chunked = Forest::new(open_db(dst_chunked.path()));
        assert!(fold_app_into_single_tree(&hg, &forest_chunked, &app_key, 2).unwrap());

        // Fold B: one giant chunk → a single version-0 commit.
        let dst_single = tempfile::tempdir().unwrap();
        let forest_single = Forest::new(open_db(dst_single.path()));
        assert!(fold_app_into_single_tree(&hg, &forest_single, &app_key, 10_000).unwrap());

        // The chunked head is the LAST version (3, for 4 chunks); the single head is 0.
        let head_chunked = forest_chunked.read_head_version(&quil, Phase::VertexAdds).unwrap();
        let head_single = forest_single.read_head_version(&quil, Phase::VertexAdds).unwrap();
        assert_eq!(head_chunked, Some(3), "chunk=2 over 7 leaves ⇒ versions 0..3");
        assert_eq!(head_single, Some(0), "single chunk ⇒ version 0");

        // ROOT PARITY: the chunked tree at its head == the single tree at its head,
        // despite different version numbers (history-independent final set).
        let root_chunked =
            forest_chunked.app_subtree_root(&quil, Phase::VertexAdds, 3, &[]).unwrap();
        let root_single =
            forest_single.app_subtree_root(&quil, Phase::VertexAdds, 0, &[]).unwrap();
        assert_ne!(root_chunked, [0u8; 32], "populated");
        assert_eq!(root_chunked, root_single, "chunked fold root == single-commit root");

        // Every seeded leaf proves against the CHUNKED tree's final-version root —
        // i.e. no leaf was lost across the version chaining.
        let expected =
            quil_tries::vertex_leaf_value(&vertex_blob(&[(&type_key, b"token:Coin")])).unwrap();
        for a in &addrs {
            let (val, proof) = forest_chunked
                .shard_phase_get_with_proof_raw(&quil, Phase::VertexAdds, 3, a)
                .unwrap();
            assert_eq!(val.as_deref(), Some(&expected[..]), "leaf present at final version");
            proof
                .verify_existence(
                    jmt::RootHash(root_chunked),
                    quil_forest::shard_path_key_hash(a),
                    &expected,
                )
                .expect("leaf verifies against the chunked final-version root");
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
