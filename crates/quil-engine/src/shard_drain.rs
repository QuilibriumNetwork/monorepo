//! Draining a shard that a recorded split or merge is about to retire.
//!
//! A legacy (no committee-session) split or merge applies at the first GLOBAL
//! frame of its effective epoch. The retiring shard's members keep finalizing
//! until each learns of the flip, and GLOBAL refuses those late frames: their
//! shard is no longer registered and its committee has moved. A late frame
//! that executed coin deliveries or requests leaves the members' state ahead
//! of GLOBAL and the archives, and the coins it delivered become unusable.
//! So a retiring shard finalizes only empty
//! frames from `DRAIN_LEAD_FRAMES` before its flip: whatever GLOBAL refuses
//! carries nothing, and its pending deliveries and requests go to the shards
//! that replace it. A shard the flip has already retired drains everything.

use quil_types::store::{PendingShardChange, ShardChangeKind, ShardsStore};
use std::sync::Arc;

/// How far before its flip a retiring shard stops executing: one more than
/// the lockstep window, the oldest anchor GLOBAL still includes, so any
/// frame anchored before the drain can still be included before the flip.
pub const DRAIN_LEAD_FRAMES: u64 = quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW + 1;

/// The first anchor from which `filter` may finalize only empty frames, or
/// `None` when it does not drain.
///
/// - A recorded split names it as the parent, or a recorded merge as a
///   source: `DRAIN_LEAD_FRAMES` before the flip.
/// - A recorded change creates it (a split child, a merge target): never; a
///   member can start it before the local grid flips.
/// - The grid no longer lists it but lists an overlapping shard of its
///   application: the flip has retired it, from anchor 0.
pub fn drain_from(
    filter: &[u8],
    changes: &[PendingShardChange],
    grid: &[Vec<u8>],
    epoch_length: u64,
) -> Option<u64> {
    let mut arriving = false;
    for change in changes {
        let flip = change.effective_epoch.saturating_mul(epoch_length);
        let retiring = match change.kind {
            ShardChangeKind::Split => change.parent == filter,
            ShardChangeKind::Merge => change.children.iter().any(|child| child == filter),
        };
        if retiring {
            return Some(flip.saturating_sub(DRAIN_LEAD_FRAMES));
        }
        arriving |= match change.kind {
            ShardChangeKind::Split => change.children.iter().any(|child| child == filter),
            ShardChangeKind::Merge => change.parent == filter,
        };
    }
    if arriving || grid.is_empty() || grid.iter().any(|shard| shard == filter) {
        return None;
    }
    let (app, bits) = quil_forest::decode_shard_filter_or_root(filter, 32)?;
    grid.iter()
        .filter_map(|shard| quil_forest::decode_shard_filter_or_root(shard, 32))
        .any(|(shard_app, shard_bits)| {
            shard_app == app
                && (quil_forest::bit_path_starts_with(&shard_bits, &bits)
                    || quil_forest::bit_path_starts_with(&bits, &shard_bits))
        })
        .then_some(0)
}

/// A shard's drain, read from the node's committed topology (the master's
/// shards store: the grid and the recorded pending changes).
pub struct ShardDrain {
    filter: Vec<u8>,
    topology: Arc<dyn ShardsStore>,
}

impl ShardDrain {
    pub fn new(filter: Vec<u8>, topology: Arc<dyn ShardsStore>) -> Self {
        Self { filter, topology }
    }

    /// Whether a frame anchored at `anchor` must be empty. Applies from this
    /// release's activation (the relay activation frame); an unreadable
    /// topology does not drain.
    pub fn drains_at(&self, anchor: u64) -> bool {
        if anchor < quil_execution::token_intrinsic::global_commit::relay_activation_frame() {
            return false;
        }
        let Ok(changes) = self.topology.all_pending_shard_changes() else { return false };
        let Ok(rows) = self.topology.range_app_shards() else { return false };
        let app = &self.filter[..self.filter.len().min(32)];
        let grid: Vec<Vec<u8>> = rows
            .into_iter()
            .filter(|row| row.shard_key.len() == 35 && &row.shard_key[3..35] == app)
            .map(|row| quil_forest::shard_prefix_to_filter(&row.shard_key[3..35], &row.prefix))
            .collect();
        drain_from(&self.filter, &changes, &grid, quil_types::consensus::epoch_length_frames())
            .is_some_and(|from| anchor >= from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(bits: &[bool]) -> Vec<u8> {
        quil_forest::encode_shard_bit_path(&[0x21u8; 32], bits)
    }

    fn change(kind: ShardChangeKind, parent: &[bool], children: &[&[bool]]) -> PendingShardChange {
        PendingShardChange {
            kind,
            parent: filter(parent),
            children: children.iter().map(|bits| filter(bits)).collect(),
            effective_epoch: 6,
            proposed_frame: 140,
        }
    }

    /// The root splits at GLOBAL 180 (epoch 6 of 30 frames); its members
    /// finalize frames anchored at 177 after the flip, one of them delivering
    /// coins GLOBAL then never records.
    #[test]
    fn a_retiring_shard_drains_before_its_flip_and_what_replaces_it_does_not() {
        let root = filter(&[]);
        let (left, right) = (filter(&[false]), filter(&[true]));
        let split = [change(ShardChangeKind::Split, &[], &[&[false], &[true]])];
        let before = [root.clone()];
        assert_eq!(drain_from(&root, &split, &before, 30), Some(180 - DRAIN_LEAD_FRAMES), "the parent drains");
        assert_eq!(drain_from(&left, &split, &before, 30), None, "a child starts before the local grid flips");

        let after = [left.clone(), right.clone()];
        assert_eq!(drain_from(&root, &[], &after, 30), Some(0), "a retired parent drains everything");
        assert_eq!(drain_from(&left, &[], &after, 30), None);

        let merge = [change(ShardChangeKind::Merge, &[], &[&[false], &[true]])];
        assert_eq!(drain_from(&right, &merge, &after, 30), Some(180 - DRAIN_LEAD_FRAMES), "a merge source drains");
        assert_eq!(drain_from(&root, &merge, &after, 30), None, "the merge target does not");
        assert_eq!(drain_from(&right, &[], &[root.clone()], 30), Some(0), "a merged-away source drains everything");

        let other_app = quil_forest::encode_shard_bit_path(&[0x22u8; 32], &[]);
        assert_eq!(drain_from(&other_app, &[], &after, 30), None, "another application is not this grid's");
        assert_eq!(drain_from(&root, &[], &[], 30), None, "an unknown topology does not drain");
    }

    /// The node reads its drain from the master's shards store: the recorded
    /// split before the flip, the flipped grid after it.
    #[test]
    fn the_drain_follows_the_recorded_change_and_the_flipped_grid() {
        use quil_types::store::{KvDb as _, ShardInfo};
        let flip = 6 * quil_types::consensus::epoch_length_frames();
        let app = [0x21u8; 32];
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        shard_key.extend_from_slice(&app);
        let put = |bits: &[bool]| {
            let txn = db.new_batch(false).unwrap();
            store.put_app_shard(txn.as_ref(), &ShardInfo {
                shard_key: shard_key.clone(), prefix: quil_forest::bit_path_to_prefix(bits),
                size: vec![], data_shards: 0, commitment: vec![],
            }).unwrap();
            txn.commit().unwrap();
        };
        put(&[]);
        let split = change(ShardChangeKind::Split, &[], &[&[false], &[true]]);
        let txn = db.new_batch(false).unwrap();
        store.put_pending_shard_change(txn.as_ref(), &split).unwrap();
        txn.commit().unwrap();
        let root = ShardDrain::new(filter(&[]), store.clone());
        let child = ShardDrain::new(filter(&[false]), store.clone());
        assert!(!root.drains_at(flip - DRAIN_LEAD_FRAMES - 1));
        assert!(root.drains_at(flip - DRAIN_LEAD_FRAMES), "anchored inside the drain");
        assert!(root.drains_at(flip - 3), "late frames like the drill's");
        assert!(!child.drains_at(flip - 3));

        // The local flip: the change applies, the grid lists the children.
        let txn = db.new_batch(false).unwrap();
        store.delete_pending_shard_change(txn.as_ref(), &split.parent, split.effective_epoch).unwrap();
        store.delete_app_shard(txn.as_ref(), &shard_key, &quil_forest::bit_path_to_prefix(&[])).unwrap();
        txn.commit().unwrap();
        put(&[false]);
        put(&[true]);
        assert!(root.drains_at(1), "a retired parent drains everything");
        assert!(!child.drains_at(flip + 1));
    }
}
