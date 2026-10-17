//! Which superseded versions a store may drop.
//!
//! Every commit that changes a `(set, phase, shard)` tree writes a new tree
//! version, new versioned vertex blobs and a `root → (version, frame)` index
//! entry; nothing below the newest is needed except to serve historical roots
//! to syncing peers. A tree's retention watermark is the version that was
//! current at its cull frame, `max{version : frame ≤ cull}`: every root
//! committed after the cull stays resolvable and readable.
//!
//! Two properties of real stores make a watermark unsafe, and such trees are
//! left untouched rather than guessed at:
//!
//! * **Version restarts.** A reset or a rebuild restarts a tree's versions
//!   while frames keep rising. JMT node keys are `(version, path)`, so a
//!   rebuild that did not wipe the old tree can reuse a key its old stale
//!   records name, and pruning those records would delete a live node. The
//!   index shows the restart as versions that do not rise with frames.
//! * **Several frame sequences in one tree.** An archive's unified application
//!   tree is committed by GLOBAL frames and by each shard's own frames, whose
//!   numbers are unrelated; the same index shows it the same way.
//!
//! Blob versions are shared by all trees of one application keyspace, so they
//! are pruned only when every such tree has a watermark, and to the least of
//! them. The newest blob of every vertex is always kept.
use std::collections::HashMap;

/// `(set byte, phase byte, shard id)` of one indexed tree.
pub(crate) type TreeKey = (u8, u8, Vec<u8>);
/// One index entry: `(index key, version, frame)`.
pub(crate) type IndexEntry = (Vec<u8>, u64, u64);

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PrunePlan {
    /// Index entries below their tree's watermark.
    pub delete_roots: Vec<Vec<u8>>,
    /// `(shard id, phase index, watermark)` for the matching forest trees.
    pub trees: Vec<(Vec<u8>, usize, u64)>,
    /// `((set byte, phase byte, application), watermark)` for blob keyspaces.
    pub blobs: Vec<((u8, u8, [u8; 32]), u64)>,
    /// Trees skipped because their versions do not rise with their frames.
    pub restarted: usize,
}

/// Whether a tree's index is one history, sorted by version on return.
///
/// Without the tree's head version: versions strictly rise with
/// non-decreasing frames. With it: versions are distinct and none exceeds the
/// head. A reset restarts versions below indexed ones, which then lie above
/// the head until the new history passes them and repeat after; either can
/// let a record name a reused `(version, path)` key. Frames that fall while
/// versions rise cannot: roots a sync indexed under an older pinned frame, or
/// two frame sequences in one tree. One such break at the start of a GLOBAL
/// tree (e.g. versions 0–3 at frames 40, 4, 32, 40) keeps its whole keyspace
/// from ever being pruned.
fn one_history(entries: &mut [IndexEntry], head: Option<u64>) -> bool {
    entries.sort_by_key(|(_, version, frame)| (*version, *frame));
    match head {
        None => entries.windows(2).all(|pair| pair[0].1 < pair[1].1 && pair[0].2 <= pair[1].2),
        Some(head) => entries.windows(2).all(|pair| pair[0].1 < pair[1].1)
            && entries.last().is_none_or(|(_, version, _)| *version <= head),
    }
}

/// `cull` maps a tree's newest indexed frame to its cull frame, or `None` to
/// keep all of it.
pub(crate) fn plan_prune(
    trees: HashMap<TreeKey, Vec<IndexEntry>>,
    cull: impl Fn(u64) -> Option<u64>,
    head: impl Fn(&TreeKey) -> Option<u64>,
) -> PrunePlan {
    let mut plan = PrunePlan::default();
    // Per application keyspace: the least watermark, or None once any of its
    // trees cannot be pruned.
    let mut keyspaces: HashMap<(u8, u8, [u8; 32]), Option<u64>> = HashMap::new();
    for ((set, phase, shard_id), mut entries) in trees {
        let clean = one_history(&mut entries, head(&(set, phase, shard_id.clone())));
        // The version current at the cull frame, but never above a version
        // committed after it: when frames do not rise with versions, every
        // root committed after the cull stays resolvable.
        let watermark = clean
            .then(|| entries.iter().map(|(_, _, frame)| *frame).max())
            .flatten()
            .and_then(&cull)
            .and_then(|cull| {
                let current = entries.iter().filter(|(_, _, frame)| *frame <= cull).map(|(_, v, _)| *v).max()?;
                let later = entries.iter().filter(|(_, _, frame)| *frame > cull).map(|(_, v, _)| *v).min();
                Some(later.map_or(current, |later| current.min(later)))
            })
            .filter(|watermark| *watermark > 0);
        if !clean {
            plan.restarted += 1;
        }
        if let Some(application) = shard_id.get(..32).and_then(|a| <[u8; 32]>::try_from(a).ok()) {
            let slot = keyspaces.entry((set, phase, application)).or_insert(Some(u64::MAX));
            *slot = match (*slot, watermark) {
                (Some(least), Some(watermark)) => Some(least.min(watermark)),
                _ => None,
            };
        }
        let Some(watermark) = watermark else { continue };
        plan.delete_roots.extend(
            entries.iter().filter(|(_, version, _)| *version < watermark).map(|(key, _, _)| key.clone()),
        );
        let phase_idx = usize::from(set) * 2 + usize::from(phase);
        if phase_idx < 4 {
            plan.trees.push((shard_id, phase_idx, watermark));
        }
    }
    plan.blobs = keyspaces
        .into_iter()
        .filter_map(|(keyspace, watermark)| watermark.filter(|w| *w != u64::MAX).map(|w| (keyspace, w)))
        .collect();
    plan.blobs.sort();
    plan.trees.sort();
    plan.delete_roots.sort();
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(entries: &[(u64, u64)]) -> Vec<IndexEntry> {
        entries.iter().map(|(v, f)| (format!("root-{v}-{f}").into_bytes(), *v, *f)).collect()
    }

    fn app(byte: u8, suffix: &[u8]) -> Vec<u8> {
        let mut id = vec![byte; 32];
        id.extend_from_slice(suffix);
        id
    }

    #[test]
    fn a_clean_tree_keeps_everything_committed_after_its_cull_frame() {
        let trees = HashMap::from([((0, 0, app(1, &[])), tree(&[(1, 10), (2, 20), (3, 30), (4, 40)]))]);
        let plan = plan_prune(trees, |newest| newest.checked_sub(15), |_| None);
        // Cull 25: version 2 was current then, so versions 2..4 stay readable.
        assert_eq!(plan.trees, vec![(app(1, &[]), 0, 2)]);
        assert_eq!(plan.delete_roots, vec![b"root-1-10".to_vec()]);
        assert_eq!(plan.blobs, vec![((0, 0, [1; 32]), 2)]);
        assert_eq!(plan.restarted, 0);
    }

    /// The prover tree after a reset, and a worker tree rebuilt at version
    /// zero: versions fall while frames rise. Nothing of either is pruned.
    #[test]
    fn a_tree_whose_versions_restart_is_never_pruned() {
        let trees = HashMap::from([
            ((0, 0, app(2, &[])), tree(&[(5, 10), (6, 11), (7, 12), (1, 40), (2, 41)])),
            ((0, 0, app(3, &[])), tree(&[(3, 5), (3, 60)])),
        ]);
        let plan = plan_prune(trees, |newest| newest.checked_sub(1), |_| None);
        assert_eq!(plan, PrunePlan { restarted: 2, ..Default::default() });
    }

    /// A GLOBAL tree with a break at its start (versions 0–3 at frames
    /// 40, 4, 32, 40) and one history after. With its head known it is pruned,
    /// and the watermark never passes a version committed after the cull.
    #[test]
    fn falling_frames_under_rising_versions_prune_conservatively_with_a_head() {
        let key = (0, 0, app(6, &[]));
        let entries = tree(&[(0, 40), (1, 4), (2, 32), (3, 40), (4, 50), (5, 60), (6, 70)]);
        let strict = plan_prune(HashMap::from([(key.clone(), entries.clone())]), |newest| newest.checked_sub(15), |_| None);
        assert_eq!(strict.restarted, 1, "without its head the tree is left alone");
        let plan = plan_prune(HashMap::from([(key.clone(), entries)]), |newest| newest.checked_sub(15), |_| Some(6));
        // Cull 55: version 4 (frame 50) was current; nothing after the cull is below it.
        assert_eq!(plan.trees, vec![(app(6, &[]), 0, 4)]);
        assert_eq!(plan.blobs, vec![((0, 0, [6; 32]), 4)]);
        assert_eq!(plan.restarted, 0);

        // A version committed after the cull below the current one bounds it.
        let anomaly = tree(&[(1, 10), (2, 60), (3, 20), (4, 70)]);
        let plan = plan_prune(HashMap::from([(key, anomaly)]), |newest| newest.checked_sub(15), |_| Some(4));
        assert_eq!(plan.trees, vec![(app(6, &[]), 0, 2)], "cull 55: version 3 is current, version 2 is later");
    }

    /// A reset restarts versions: before the new history passes the old one,
    /// indexed versions lie above the head; after, they repeat. Either keeps
    /// the tree untouched with its head known.
    #[test]
    fn a_restart_is_still_refused_with_its_head_known() {
        let key = (0, 0, app(7, &[]));
        let before = tree(&[(5, 10), (6, 11), (7, 12), (1, 40), (2, 41)]);
        assert_eq!(plan_prune(HashMap::from([(key.clone(), before)]), |n| n.checked_sub(1), |_| Some(2)).restarted, 1);
        let after = tree(&[(5, 10), (6, 11), (7, 12), (1, 40), (5, 44), (6, 45), (7, 46), (8, 47)]);
        assert_eq!(plan_prune(HashMap::from([(key, after)]), |n| n.checked_sub(1), |_| Some(8)).restarted, 1);
    }

    /// An archive's unified tree carries GLOBAL frames and shard frames.
    #[test]
    fn a_tree_committed_under_two_frame_sequences_is_never_pruned() {
        let trees = HashMap::from([((0, 0, app(4, &[])), tree(&[(1, 500), (2, 250), (3, 501), (4, 251)]))]);
        let plan = plan_prune(trees, |newest| newest.checked_sub(10), |_| None);
        assert_eq!(plan.restarted, 1);
        assert!(plan.trees.is_empty() && plan.blobs.is_empty() && plan.delete_roots.is_empty());
    }

    /// Trees sharing an application's blob keyspace bound it together: a tree
    /// with nothing prunable yet, or one skipped, keeps all blobs.
    #[test]
    fn a_blob_keyspace_is_pruned_only_to_the_least_watermark_of_all_its_trees() {
        let base = |second: Vec<IndexEntry>| {
            HashMap::from([
                ((0, 0, app(5, &[1])), tree(&[(1, 10), (2, 20), (9, 30)])),
                ((0, 0, app(5, &[2])), second),
            ])
        };
        let plan = plan_prune(base(tree(&[(1, 10), (4, 12), (5, 30)])), |newest| newest.checked_sub(10), |_| None);
        assert_eq!(plan.blobs, vec![((0, 0, [5; 32]), 2)]);
        let young = plan_prune(base(tree(&[(1, 29), (2, 30)])), |newest| newest.checked_sub(10), |_| None);
        assert!(young.blobs.is_empty(), "the young tree still reads old blob versions");
        assert_eq!(young.trees, vec![(app(5, &[1]), 0, 2)]);
        let restarted = plan_prune(base(tree(&[(4, 10), (1, 30)])), |newest| newest.checked_sub(10), |_| None);
        assert!(restarted.blobs.is_empty());
    }
}
