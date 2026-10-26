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
//!
//! The topology is the node's own, current only while the node executes
//! GLOBAL frames. A regular node executes none once committee sessions govern
//! (archives, which do, run no application workers): its grid stays the one
//! it was seeded with and it records no change, so every shard split from that
//! grid since reads as retired and would drain from anchor 0, permanently.
//! Under sessions a shard retires through its session instead: a closing
//! request makes its members propose empty frames, the seal waits for a run of
//! request-free frames, and GLOBAL flips the grid only after the seal. A voter
//! therefore never refuses a proposal for a drain under sessions, and a leader
//! stops draining from [`session_leader_no_drain_frame`], once enough voters
//! accept its content.

use quil_types::store::{PendingShardChange, ShardChangeKind, ShardsStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// How far before its flip a retiring shard stops executing: one more than
/// the lockstep window, the oldest anchor GLOBAL still includes, so any
/// frame anchored before the drain can still be included before the flip.
pub const DRAIN_LEAD_FRAMES: u64 =
    quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW + 1;

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

/// Who asks whether a shard drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainRole {
    /// A leader building a frame: a draining shard's carries no content.
    Leader,
    /// A member validating a proposal: a draining shard's that carries
    /// content is refused.
    Voter,
}

/// From this GLOBAL frame, under committee sessions, a leader no longer
/// drains a shard its node's frozen grid names retired, and proposes its
/// requests and coin deliveries. A member that still refuses such a proposal
/// does not vote for it, so the frame must follow the upgrade of the voters
/// (see [`DrainRole::Voter`]) by enough members of every committee. Unset on
/// mainnet until that frame is chosen; `QUIL_SESSION_LEADER_NO_DRAIN_FRAME`
/// elsewhere, never by default.
pub const MAINNET_SESSION_LEADER_NO_DRAIN_FRAME: Option<u64> = None;

static SESSION_LEADER_NO_DRAIN_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static SESSION_LEADER_NO_DRAIN_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn session_leader_no_drain_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_SESSION_LEADER_NO_DRAIN_FRAME.unwrap_or(u64::MAX);
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's session leader no-drain frame from its network, and
/// return it. Called at startup before any shard engine runs; the first call
/// decides.
pub fn init_session_leader_no_drain_frame(network: u8) -> u64 {
    *SESSION_LEADER_NO_DRAIN_FRAME.get_or_init(|| {
        session_leader_no_drain_frame_for(
            network,
            std::env::var("QUIL_SESSION_LEADER_NO_DRAIN_FRAME")
                .ok()
                .as_deref(),
        )
    })
}

pub fn session_leader_no_drain_frame() -> u64 {
    if let Some(frame) = SESSION_LEADER_NO_DRAIN_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *SESSION_LEADER_NO_DRAIN_FRAME.get_or_init(|| {
        std::env::var("QUIL_SESSION_LEADER_NO_DRAIN_FRAME")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(u64::MAX)
    })
}

/// Set the session leader no-drain frame for the calling thread only (tests).
pub fn set_session_leader_no_drain_frame_for_thread(frame: Option<u64>) {
    SESSION_LEADER_NO_DRAIN_OVERRIDE.with(|cell| cell.set(frame));
}

/// Whether committee sessions make a drain verdict moot for `role` at
/// `anchor` (see the module documentation): for a voter always, for a
/// leader from [`session_leader_no_drain_frame`].
fn sessions_bypass(role: DrainRole, sessions_govern: bool, anchor: u64) -> bool {
    sessions_govern
        && match role {
            DrainRole::Voter => true,
            DrainRole::Leader => anchor >= session_leader_no_drain_frame(),
        }
}

/// A shard's drain, read from the node's committed topology (the master's
/// shards store: the grid and the recorded pending changes).
pub struct ShardDrain {
    filter: Vec<u8>,
    topology: Arc<dyn ShardsStore>,
    /// Whether committee sessions govern a GLOBAL frame.
    sessions_govern: fn(u64) -> bool,
    /// Per role, whether a bypassed drain was last reported.
    bypassing: [AtomicBool; 2],
}

impl ShardDrain {
    pub fn new(filter: Vec<u8>, topology: Arc<dyn ShardsStore>) -> Self {
        Self {
            filter,
            topology,
            sessions_govern: quil_types::consensus::committee_handoff_active,
            bypassing: [AtomicBool::new(false), AtomicBool::new(false)],
        }
    }

    /// Whether a frame anchored at `anchor` must be empty for `role`.
    /// Applies from this release's activation (the relay activation frame);
    /// an unreadable topology does not drain.
    pub fn drains_at(&self, anchor: u64, role: DrainRole) -> bool {
        if anchor < quil_execution::token_intrinsic::global_commit::relay_activation_frame() {
            return false;
        }
        let Ok(changes) = self.topology.all_pending_shard_changes() else {
            return false;
        };
        let Ok(rows) = self.topology.range_app_shards() else {
            return false;
        };
        let app = &self.filter[..self.filter.len().min(32)];
        let grid: Vec<Vec<u8>> = rows
            .into_iter()
            .filter(|row| row.shard_key.len() == 35 && &row.shard_key[3..35] == app)
            .map(|row| quil_forest::shard_prefix_to_filter(&row.shard_key[3..35], &row.prefix))
            .collect();
        let drains = drain_from(
            &self.filter,
            &changes,
            &grid,
            quil_types::consensus::epoch_length_frames(),
        )
        .is_some_and(|from| anchor >= from);
        let bypassed = drains && sessions_bypass(role, (self.sessions_govern)(anchor), anchor);
        let slot = &self.bypassing[role as usize];
        if slot.swap(bypassed, Ordering::Relaxed) != bypassed && bypassed {
            tracing::info!(
                filter = %hex::encode(&self.filter),
                anchor,
                role = ?role,
                grid_rows = grid.len(),
                "shard drain bypassed: this node's grid is its frozen genesis grid (a regular node \
                 executes no GLOBAL frame under committee sessions), so it names this shard retired; \
                 the shard's session retires it instead, no action needed",
            );
        }
        drains && !bypassed
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
        assert_eq!(
            drain_from(&root, &split, &before, 30),
            Some(180 - DRAIN_LEAD_FRAMES),
            "the parent drains"
        );
        assert_eq!(
            drain_from(&left, &split, &before, 30),
            None,
            "a child starts before the local grid flips"
        );

        let after = [left.clone(), right.clone()];
        assert_eq!(
            drain_from(&root, &[], &after, 30),
            Some(0),
            "a retired parent drains everything"
        );
        assert_eq!(drain_from(&left, &[], &after, 30), None);

        let merge = [change(ShardChangeKind::Merge, &[], &[&[false], &[true]])];
        assert_eq!(
            drain_from(&right, &merge, &after, 30),
            Some(180 - DRAIN_LEAD_FRAMES),
            "a merge source drains"
        );
        assert_eq!(
            drain_from(&root, &merge, &after, 30),
            None,
            "the merge target does not"
        );
        assert_eq!(
            drain_from(&right, &[], &[root.clone()], 30),
            Some(0),
            "a merged-away source drains everything"
        );

        let other_app = quil_forest::encode_shard_bit_path(&[0x22u8; 32], &[]);
        assert_eq!(
            drain_from(&other_app, &[], &after, 30),
            None,
            "another application is not this grid's"
        );
        assert_eq!(
            drain_from(&root, &[], &[], 30),
            None,
            "an unknown topology does not drain"
        );
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
        let mut shard_key =
            quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        shard_key.extend_from_slice(&app);
        let put = |bits: &[bool]| {
            let txn = db.new_batch(false).unwrap();
            store
                .put_app_shard(
                    txn.as_ref(),
                    &ShardInfo {
                        shard_key: shard_key.clone(),
                        prefix: quil_forest::bit_path_to_prefix(bits),
                        size: vec![],
                        data_shards: 0,
                        commitment: vec![],
                    },
                )
                .unwrap();
            txn.commit().unwrap();
        };
        put(&[]);
        let split = change(ShardChangeKind::Split, &[], &[&[false], &[true]]);
        let txn = db.new_batch(false).unwrap();
        store
            .put_pending_shard_change(txn.as_ref(), &split)
            .unwrap();
        txn.commit().unwrap();
        let legacy = |filter| ShardDrain {
            sessions_govern: |_| false,
            ..ShardDrain::new(filter, store.clone())
        };
        let (root, child) = (legacy(filter(&[])), legacy(filter(&[false])));
        assert!(!root.drains_at(flip - DRAIN_LEAD_FRAMES - 1, DrainRole::Leader));
        assert!(
            root.drains_at(flip - DRAIN_LEAD_FRAMES, DrainRole::Leader),
            "anchored inside the drain"
        );
        assert!(
            root.drains_at(flip - 3, DrainRole::Voter),
            "late frames like the drill's"
        );
        assert!(!child.drains_at(flip - 3, DrainRole::Leader));

        // The local flip: the change applies, the grid lists the children.
        let txn = db.new_batch(false).unwrap();
        store
            .delete_pending_shard_change(txn.as_ref(), &split.parent, split.effective_epoch)
            .unwrap();
        store
            .delete_app_shard(
                txn.as_ref(),
                &shard_key,
                &quil_forest::bit_path_to_prefix(&[]),
            )
            .unwrap();
        txn.commit().unwrap();
        put(&[false]);
        put(&[true]);
        assert!(
            root.drains_at(1, DrainRole::Leader),
            "a retired parent drains everything"
        );
        assert!(!child.drains_at(flip + 1, DrainRole::Voter));
    }

    /// A regular node's grid as seeded, holding `[false]` and `[true]`,
    /// after the network split `[false]`. Committee sessions govern from
    /// GLOBAL 1000. Thread-local and injected settings only: no
    /// process-wide policy, so the tests stay safe under `cargo test`.
    fn regular_node_drain(role_frames: &[(DrainRole, u64, bool, &str)]) {
        use quil_types::store::{KvDb as _, ShardInfo};
        quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread(
            Some(0),
        );
        let app = [0x21u8; 32];
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
        let mut shard_key =
            quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        shard_key.extend_from_slice(&app);
        let txn = db.new_batch(false).unwrap();
        for bits in [[false], [true]] {
            store
                .put_app_shard(
                    txn.as_ref(),
                    &ShardInfo {
                        shard_key: shard_key.clone(),
                        prefix: quil_forest::bit_path_to_prefix(&bits),
                        size: vec![],
                        data_shards: 0,
                        commitment: vec![],
                    },
                )
                .unwrap();
        }
        txn.commit().unwrap();
        let drain = ShardDrain {
            sessions_govern: |anchor| anchor >= 1000,
            ..ShardDrain::new(filter(&[false, true]), store)
        };
        for &(role, anchor, drains, why) in role_frames {
            assert_eq!(
                drain.drains_at(anchor, role),
                drains,
                "{role:?} at {anchor}: {why}"
            );
        }
        quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread(None);
    }

    /// The frozen grid names the child retired. Every frame the node's
    /// workers led was empty, and each refused any proposal carrying
    /// requests or deliveries: no member of such a shard executed any.
    #[test]
    fn a_voter_does_not_refuse_content_for_a_frozen_grid_drain() {
        regular_node_drain(&[
            (
                DrainRole::Voter,
                999,
                true,
                "before sessions the node still executes GLOBAL",
            ),
            (
                DrainRole::Voter,
                1000,
                false,
                "sessions retire shards; the frozen grid is moot",
            ),
            (
                DrainRole::Voter,
                50_000,
                false,
                "sessions retire shards; the frozen grid is moot",
            ),
            (
                DrainRole::Leader,
                50_000,
                true,
                "leaders keep draining until voters have upgraded",
            ),
        ]);
    }

    #[test]
    fn sessions_bypass_only_a_voter_s_drain() {
        assert!(sessions_bypass(DrainRole::Voter, true, 5));
        assert!(!sessions_bypass(DrainRole::Voter, false, 5));
        assert!(!sessions_bypass(DrainRole::Leader, true, 5));
    }

    /// From the session leader no-drain frame a leader proposes the shard's
    /// content too; before it, and without sessions, it still drains.
    #[test]
    fn a_leader_stops_draining_for_a_frozen_grid_from_its_activation() {
        set_session_leader_no_drain_frame_for_thread(Some(2000));
        regular_node_drain(&[
            (
                DrainRole::Leader,
                1999,
                true,
                "voters may still refuse content",
            ),
            (
                DrainRole::Leader,
                2000,
                false,
                "voters accept content: lead it",
            ),
            (
                DrainRole::Voter,
                1999,
                false,
                "a voter never refuses under sessions",
            ),
        ]);
        assert!(
            !sessions_bypass(DrainRole::Leader, false, 5000),
            "a legacy leader drains"
        );
        set_session_leader_no_drain_frame_for_thread(None);
    }

    /// Mainnet waits for its frame to be chosen; other networks take theirs
    /// from the environment, and none by default.
    #[test]
    fn the_session_leader_no_drain_frame_is_fixed_on_mainnet_and_configured_elsewhere() {
        assert_eq!(
            session_leader_no_drain_frame_for(0, Some("5")),
            MAINNET_SESSION_LEADER_NO_DRAIN_FRAME.unwrap_or(u64::MAX)
        );
        assert_eq!(
            MAINNET_SESSION_LEADER_NO_DRAIN_FRAME, None,
            "chosen once the voters have upgraded"
        );
        assert_eq!(session_leader_no_drain_frame_for(1, Some("5")), 5);
        assert_eq!(session_leader_no_drain_frame_for(1, None), u64::MAX);
        assert_eq!(session_leader_no_drain_frame_for(99, Some("x")), u64::MAX);
    }
}
