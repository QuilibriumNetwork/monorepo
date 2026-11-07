//! Coordinated activation of persistent label certificates and sector roots.
//! Mainnet persistent certificates and three-layer seals activate at epoch 1444.
use std::{cell::Cell, sync::OnceLock};

pub const MAINNET_PERSISTENT_STORAGE_EPOCH: Option<u64> = Some(1444);
/// The faster suite switches with the coordinated persistent-storage activation.
pub const MAINNET_FAST_STORAGE_EPOCH: Option<u64> = MAINNET_PERSISTENT_STORAGE_EPOCH;
pub const MAINNET_FAST_STORAGE_PROFILE: Option<StorageSealProfile> =
    Some(StorageSealProfile::Three);
/// Hard end-to-end startup target; warmup eligibility is a separate rule.
pub const INITIAL_STORAGE_SETUP_BUDGET_SECS: u64 = 2 * 60 * 60;

/// An explicit proof suite. The legacy suite and its serialization stay frozen.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum StorageSealProfile {
    #[default]
    Eleven = 11,
    Three = 3,
    Two = 2,
}
impl StorageSealProfile {
    pub const fn layers(self) -> usize {
        self as usize
    }
    pub const fn tag(self) -> &'static [u8; 4] {
        match self {
            Self::Eleven => b"PS01",
            Self::Three => b"PS03",
            Self::Two => b"PS02",
        }
    }
    pub fn from_tag(tag: &[u8]) -> Option<Self> {
        match tag {
            b"PS01" => Some(Self::Eleven),
            b"PS03" => Some(Self::Three),
            b"PS02" => Some(Self::Two),
            _ => None,
        }
    }
    pub fn from_layers(layers: usize) -> Option<Self> {
        match layers {
            11 => Some(Self::Eleven),
            3 => Some(Self::Three),
            2 => Some(Self::Two),
            _ => None,
        }
    }
}
thread_local! { static PROFILE: Cell<Option<StorageSealProfile>> = const { Cell::new(None) }; }
/// Readiness experiments are scoped to a thread; node environment variables
/// cannot select a fast mainnet suite.
pub fn set_storage_seal_profile_for_thread(profile: Option<StorageSealProfile>) {
    PROFILE.with(|p| p.set(profile));
}
pub fn storage_seal_profile_thread_override() -> Option<StorageSealProfile> {
    PROFILE.with(Cell::get)
}
pub fn storage_seal_profile(epoch: u64) -> StorageSealProfile {
    if let Some(profile) = storage_seal_profile_thread_override() {
        return profile;
    }
    profile_at(
        epoch,
        MAINNET_FAST_STORAGE_EPOCH,
        MAINNET_FAST_STORAGE_PROFILE,
        persistent_storage_at(epoch),
    )
}
fn profile_at(
    epoch: u64,
    activation: Option<u64>,
    selected: Option<StorageSealProfile>,
    persistent: bool,
) -> StorageSealProfile {
    match (activation, selected) {
        (Some(from), Some(profile)) if epoch >= from && persistent => profile,
        _ => StorageSealProfile::Eleven,
    }
}

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
    fn mainnet_activation_is_coordinated_and_ignores_environment_settings() {
        assert_eq!(MAINNET_PERSISTENT_STORAGE_EPOCH, Some(1444));
        for setting in [None, Some("0"), Some("1393"), Some("bad")] {
            assert_eq!(configured(0, setting, 1314, 1429), 1444);
        }
        assert_eq!(configured(1, Some("1400"), 1314, 1393), 1400);
        assert_eq!(configured(1, Some("12"), 1314, 1393), 1393);
        assert_eq!(configured(1, None, 1314, 1393), u64::MAX);
        assert_eq!(configured(1, Some("1400"), 1314, u64::MAX), u64::MAX);
    }
    #[test]
    fn mainnet_switches_to_three_layers_exactly_at_epoch_1444() {
        set_persistent_storage_epoch_for_thread(None);
        set_storage_seal_profile_for_thread(None);
        assert_eq!(persistent_storage_epoch(), 1444);
        assert_eq!(1444 * super::super::EPOCH_LENGTH_FRAMES, 1_039_680);
        assert!(super::super::stable_replica_keys_at(1444));
        for epoch in [1442, 1443] {
            assert!(!persistent_storage_at(epoch));
            assert_eq!(storage_seal_profile(epoch), StorageSealProfile::Eleven);
        }
        for epoch in [1444, 1445] {
            assert!(persistent_storage_at(epoch));
            assert_eq!(storage_seal_profile(epoch), StorageSealProfile::Three);
        }
        set_persistent_storage_epoch_for_thread(Some(u64::MAX));
        assert_eq!(storage_seal_profile(1444), StorageSealProfile::Eleven);
        set_persistent_storage_epoch_for_thread(None);
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

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    fn fast_suites_require_both_coordinated_settings_and_persistent_activation() {
        assert_eq!(MAINNET_FAST_STORAGE_EPOCH, Some(1444));
        assert_eq!(
            MAINNET_FAST_STORAGE_PROFILE,
            Some(StorageSealProfile::Three)
        );
        assert_eq!(storage_seal_profile(1500), StorageSealProfile::Three);
        for suite in [StorageSealProfile::Two, StorageSealProfile::Three] {
            assert_eq!(
                profile_at(1499, Some(1500), Some(suite), true),
                StorageSealProfile::Eleven
            );
            assert_eq!(profile_at(1500, Some(1500), Some(suite), true), suite);
            assert_eq!(
                profile_at(1501, Some(1500), Some(suite), false),
                StorageSealProfile::Eleven
            );
            assert_eq!(
                profile_at(1501, None, Some(suite), true),
                StorageSealProfile::Eleven
            );
            assert_eq!(
                profile_at(1501, Some(1500), None, true),
                StorageSealProfile::Eleven
            );
        }
        assert_eq!(StorageSealProfile::from_layers(1), None);
        assert_eq!(INITIAL_STORAGE_SETUP_BUDGET_SECS, 7200);
    }
}
