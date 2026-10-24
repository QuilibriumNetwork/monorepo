//! The storage watch of this process's stores
//! ([`quil_forest::storage_health`]), with the operator's `db` thresholds.

/// Start this process's storage watch with `db`'s disk usage thresholds,
/// or the defaults when they are not ordered percentages.
pub(crate) fn start(db: &quil_config::DbConfig) {
    let thresholds =
        quil_forest::DiskThresholds::new(db.notice_percentage, db.warn_percentage, db.terminate_percentage)
            .unwrap_or_else(|error| {
                let defaults = quil_forest::DiskThresholds::default();
                tracing::warn!(
                    %error,
                    notice_pct = defaults.notice,
                    warn_pct = defaults.warn,
                    terminate_pct = defaults.terminate,
                    "invalid db disk usage thresholds in the node config; using the defaults"
                );
                defaults
            });
    quil_forest::storage_health::spawn_storage_watch(thresholds);
}
