//! Coordinated activation of persistent label certificates and sector roots.
//! Mainnet deliberately has no activation epoch until the rollout is agreed.
use std::{cell::Cell, sync::OnceLock};

pub const MAINNET_PERSISTENT_STORAGE_EPOCH: Option<u64> = None;
/// Nodes must carry the coordinated epoch before capacity precommits begin.
pub const PERSISTENT_STORAGE_WARMUP_EPOCHS: u64 = 32;
static EPOCH: OnceLock<u64> = OnceLock::new();
thread_local! { static OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) }; }

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
