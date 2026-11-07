//! In-place consolidation using a bound forest and captured record view.
use anyhow::{ensure, Result};
use quil_forest::{Forest, Phase, PHASES};
use quil_types::store::{
    HypergraphStore, ShardKey, ShardsStore, SnapshotReadable, VertexPageLimits,
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
#[path = "consolidation_tests.rs"]
mod tests;

fn phase_names(phase: Phase) -> (&'static str, &'static str) {
    match phase {
        Phase::VertexAdds => ("vertex", "adds"),
        Phase::VertexRemoves => ("vertex", "removes"),
        Phase::HyperedgeAdds => ("hyperedge", "adds"),
        Phase::HyperedgeRemoves => ("hyperedge", "removes"),
    }
}

/// Both providers must share the captured database/overlay. The caller holds
/// its whole-frame and CRDT maintenance barriers. A failed tentative operation
/// invalidates the entire branch; this function does not publish or roll back.
/// Overlay read/delta limits also bound cumulative work. The durable caller
/// must supply its own lifetime, I/O and disk policy.
pub fn run_unified_consolidation(
    store: &dyn HypergraphStore,
    forest: &Forest,
    shards: &dyn ShardsStore,
    head_frame: u64,
    chunk: usize,
) -> Result<usize> {
    let identity = store
        .backing_store_identity()
        .ok_or_else(|| anyhow::anyhow!("consolidation requires identifiable storage"))?;
    ensure!(
        forest.backing_store_identity().as_ref() == Some(&identity),
        "consolidation forest/store mismatch"
    );
    ensure!(
        shards.backing_store_identity().as_ref() == Some(&identity),
        "consolidation shard store mismatch"
    );
    let rows = shards.range_app_shards()?;
    let mut grid: BTreeMap<[u8; 32], Vec<Vec<u32>>> = BTreeMap::new();
    for row in rows {
        ensure!(row.shard_key.len() == 35, "invalid consolidation shard key");
        let app = row.shard_key[3..].try_into().unwrap();
        grid.entry(app).or_default().push(row.prefix);
    }
    let mut apps: BTreeSet<[u8; 32]> = grid.keys().copied().collect();
    for address in store.range_alt_shard_addresses()? {
        ensure!(
            address.len() >= 32,
            "invalid consolidation alternate shard address"
        );
        apps.insert(address[..32].try_into().unwrap());
    }
    for number in head_frame.saturating_sub(128)..=head_frame {
        for shard in store.get_root_commits(number)?.into_keys() {
            apps.insert(shard.l2);
        }
    }
    let snapshot = store
        .capture_tree_snapshot()?
        .ok_or_else(|| anyhow::anyhow!("consolidation requires a captured record view"))?;
    let mut count = 0;
    for app in apps {
        let prefixes = grid
            .remove(&app)
            .unwrap_or_else(|| crate::quil_shards_for_app(&app));
        if prefixes.len() <= 1 && prefixes.iter().all(Vec::is_empty) {
            continue;
        }
        let shard = ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
            l2: app,
        };
        if fold_snapshot(snapshot.as_ref(), forest, &shard, chunk)? {
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn fold_snapshot(
    snapshot: &dyn SnapshotReadable,
    forest: &Forest,
    shard: &ShardKey,
    chunk: usize,
) -> Result<bool> {
    // The page byte cap also bounds the accumulated input to a forest commit.
    let page_limit = VertexPageLimits {
        max_entries: chunk.clamp(1, 256),
        max_bytes: 16 << 20,
    };
    let shard_id = Forest::addr_path_shard_id(&shard.l2, &[]);
    let mut any_state = false;
    for phase in PHASES {
        let (set, name) = phase_names(phase);
        let mut version = 0u64;
        let mut after = None;
        let mut wrote = false;
        loop {
            let page = snapshot.page_vertex_underlying_fixed(
                set,
                name,
                shard,
                &shard.l2,
                after.as_ref(),
                page_limit,
            )?;
            ensure!(
                !page.has_more || !page.entries.is_empty(),
                "consolidation page made no progress"
            );
            let mut input = Vec::with_capacity(page.entries.len());
            for (address, blob) in page.entries {
                ensure!(
                    after.as_ref().is_none_or(|last| address > *last),
                    "consolidation page out of order"
                );
                after = Some(address);
                input.push(([shard.l2.as_slice(), address.as_slice()].concat(), blob));
            }
            if !input.is_empty() {
                forest.commit_shard_phase_raw(
                    &shard_id,
                    phase,
                    version,
                    crate::per_vertex_phase_leaves(input)?,
                )?;
                version = version
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("consolidation version overflow"))?;
                wrote = true;
            }
            if !page.has_more {
                break;
            }
        }
        if !wrote {
            if let Some(blob) = snapshot.load_tree_blob(set, name, shard)? {
                if let Some(root) = quil_tries::deserialize_tree(&blob)? {
                    // Visit borrowed leaves instead of cloning the whole tree's
                    // output. The source record itself is bounded by its store.
                    let mut batch = Vec::new();
                    let mut bytes = 0usize;
                    visit_legacy(&root, &mut |key, value| {
                        let size = key
                            .len()
                            .checked_add(value.len())
                            .ok_or_else(|| anyhow::anyhow!("consolidation record overflow"))?;
                        ensure!(
                            size <= page_limit.max_bytes,
                            "consolidation legacy record limit"
                        );
                        if !batch.is_empty()
                            && (batch.len() >= page_limit.max_entries
                                || bytes + size > page_limit.max_bytes)
                        {
                            forest.commit_shard_phase_raw(
                                &shard_id,
                                phase,
                                version,
                                crate::per_vertex_phase_leaves(std::mem::take(&mut batch))?,
                            )?;
                            version = version
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("consolidation version overflow"))?;
                            bytes = 0;
                        }
                        batch.push((key.to_vec(), value.to_vec()));
                        bytes += size;
                        Ok(())
                    })?;
                    if !batch.is_empty() {
                        forest.commit_shard_phase_raw(
                            &shard_id,
                            phase,
                            version,
                            crate::per_vertex_phase_leaves(batch)?,
                        )?;
                        version = version
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("consolidation version overflow"))?;
                    }
                    wrote = version != 0;
                }
            }
        }
        let head = if wrote {
            any_state = true;
            version - 1
        } else {
            forest.commit_shard_phase_raw(&shard_id, phase, 0, Vec::new())?;
            0
        };
        forest.write_head_version(&shard_id, phase, head)?;
    }
    Ok(any_state)
}

fn visit_legacy(
    node: &quil_tries::VectorCommitmentNode,
    visit: &mut impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    match node {
        quil_tries::VectorCommitmentNode::Leaf(leaf) => visit(&leaf.key, &leaf.value),
        quil_tries::VectorCommitmentNode::Branch(branch) => {
            for child in branch.children.iter().flatten() {
                visit_legacy(child, visit)?;
            }
            Ok(())
        }
    }
}
