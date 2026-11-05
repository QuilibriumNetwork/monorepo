//! Coordinated activation of persistent label certificates and sector roots.
//! Mainnet deliberately has no activation epoch until the rollout is agreed.
use std::{cell::Cell, sync::OnceLock};

pub const MAINNET_PERSISTENT_STORAGE_EPOCH: Option<u64> = None;
/// Nodes must carry the coordinated epoch before capacity precommits begin.
pub const PERSISTENT_STORAGE_WARMUP_EPOCHS: u64 = 32;
/// The smallest sector GLOBAL certifies: 32 MiB of labels, about two CPU
/// minutes to label. Mainnet leaves already need more, bar empty shards.
pub const MIN_SECTOR_NODES: u64 = 1 << 20;
/// Certified sectors each seat allows: the 64 leaves of a shard at
/// `MERGE_MAX_SIZE_BYTES`, 4x the largest mainnet shard's 16.
pub const SECTORS_PER_SEAT: u64 = 64;
/// Certified sectors a member may hold beyond its seats'. Labelling runs for
/// seats it holds, so this only covers allocations in transition.
pub const SECTOR_MARGIN: u64 = 8;
static EPOCH: OnceLock<u64> = OnceLock::new();
thread_local! {
    static OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
    static MIN_NODES: Cell<Option<u64>> = const { Cell::new(None) };
}

fn configured(network: u8, setting: Option<&str>, hash: u64, stable: u64) -> u64 {
    let from = if network == 0 {
        MAINNET_PERSISTENT_STORAGE_EPOCH
    } else {
        setting.and_then(|s| s.parse().ok())
    };
    from.map_or(u64::MAX, |from| from.max(hash).max(stable))
}

/// Called after the hash-proof and stable-key gates. Environment overrides
/// apply only to non-mainnet networks; setting an env var cannot fork mainnet.
pub fn init_persistent_storage_epoch(network: u8) -> u64 {
    *EPOCH.get_or_init(|| {
        configured(
            network,
            std::env::var("QUIL_PERSISTENT_STORAGE_EPOCH")
                .ok()
                .as_deref(),
            super::hash_storage_proof_epoch(),
            super::stable_replica_key_epoch(),
        )
    })
}

pub fn persistent_storage_epoch() -> u64 {
    OVERRIDE.with(|o| o.get()).unwrap_or_else(|| {
        EPOCH
            .get()
            .copied()
            .unwrap_or(MAINNET_PERSISTENT_STORAGE_EPOCH.unwrap_or(u64::MAX))
    })
}

pub fn persistent_storage_at(epoch: u64) -> bool {
    let from = persistent_storage_epoch();
    from != u64::MAX && epoch >= from
}

/// The most certified sectors a member holding `seats` may have.
pub fn max_certified_sectors(seats: u64) -> u64 {
    seats
        .saturating_mul(SECTORS_PER_SEAT)
        .saturating_add(SECTOR_MARGIN)
}

/// [`MIN_SECTOR_NODES`]. A thread's scoped activation epoch runs the small
/// sectors of tests and the readiness tool, unless it sets its own floor.
pub fn min_sector_nodes() -> u64 {
    MIN_NODES.with(Cell::get).unwrap_or_else(|| {
        if OVERRIDE.with(Cell::get).is_some() {
            2
        } else {
            MIN_SECTOR_NODES
        }
    })
}

/// Thread-scoped tests; `None` restores the rule of [`min_sector_nodes`].
pub fn set_min_sector_nodes_for_thread(nodes: Option<u64>) {
    MIN_NODES.with(|n| n.set(nodes));
}
/// The floor this thread set with [`set_min_sector_nodes_for_thread`].
pub fn min_sector_nodes_thread_override() -> Option<u64> {
    MIN_NODES.with(Cell::get)
}

/// Thread-scoped tests; `None` restores startup configuration, MAX disables.
pub fn set_persistent_storage_epoch_for_thread(epoch: Option<u64>) {
    OVERRIDE.with(|o| o.set(epoch));
}
pub fn persistent_storage_epoch_thread_override() -> Option<u64> {
    OVERRIDE.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mainnet_is_disabled_and_ignores_environment_settings() {
        assert_eq!(MAINNET_PERSISTENT_STORAGE_EPOCH, None);
        for setting in [None, Some("0"), Some("1393"), Some("bad")] {
            assert_eq!(configured(0, setting, 1314, 1393), u64::MAX);
        }
        assert_eq!(configured(1, Some("1400"), 1314, 1393), 1400);
        assert_eq!(configured(1, Some("12"), 1314, 1393), 1393);
        assert_eq!(configured(1, None, 1314, 1393), u64::MAX);
        assert_eq!(configured(1, Some("1400"), 1314, u64::MAX), u64::MAX);
    }
    #[test]
    fn sector_cap_and_floor_are_the_proposed_values() {
        assert_eq!(max_certified_sectors(0), 8);
        assert_eq!(max_certified_sectors(1), 72);
        assert_eq!(max_certified_sectors(109), 6984);
        assert_eq!(max_certified_sectors(u64::MAX), u64::MAX);
        assert_eq!(min_sector_nodes(), 1 << 20);
        set_persistent_storage_epoch_for_thread(Some(1500));
        assert_eq!(min_sector_nodes(), 2, "a scoped epoch runs small sectors");
        set_min_sector_nodes_for_thread(Some(64));
        assert_eq!(min_sector_nodes(), 64);
        set_min_sector_nodes_for_thread(None);
        set_persistent_storage_epoch_for_thread(None);
        assert_eq!(min_sector_nodes(), 1 << 20);
    }
    #[test]
    fn activation_is_exact_and_max_never_activates() {
        set_persistent_storage_epoch_for_thread(Some(1500));
        assert!(!persistent_storage_at(1499));
        assert!(persistent_storage_at(1500));
        super::super::set_sealed_storage_epoch_for_thread(Some(u64::MAX));
        assert!(super::super::sealed_storage_required(1500));
        super::super::set_sealed_storage_epoch_for_thread(None);
        set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        assert!(!persistent_storage_at(u64::MAX));
        set_persistent_storage_epoch_for_thread(None);
    }
}
