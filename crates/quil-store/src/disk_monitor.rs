//! Disk usage monitoring. Periodically checks disk space and logs
//! warnings when thresholds are exceeded.
//!
//! Usage:
//! ```ignore
//! let monitor = DiskMonitor::new("/path/to/db", 80.0, 90.0, 95.0);
//! let (handle, err_rx) = monitor.start();
//! // err_rx receives when disk usage exceeds the critical threshold
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default check interval (1 minute).
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Disk usage statistics.
#[derive(Debug, Clone)]
pub struct DiskStats {
    /// Usage percentage (0.0–100.0).
    pub usage_percent: f64,
    /// Total disk capacity in bytes.
    pub total_bytes: u64,
    /// Used bytes.
    pub used_bytes: u64,
    /// Free bytes.
    pub free_bytes: u64,
}

/// Disk usage monitor with three threshold tiers.
pub struct DiskMonitor {
    /// Path to monitor (typically the DB directory).
    path: PathBuf,
    /// Percentage at which to log an info notice.
    notice_threshold: f64,
    /// Percentage at which to log a warning.
    warn_threshold: f64,
    /// Percentage at which to signal a critical error (shutdown).
    critical_threshold: f64,
    /// Check interval.
    check_interval: Duration,
}

impl DiskMonitor {
    /// - `notice_threshold`: Log info when usage exceeds this (e.g. 80.0)
    /// - `warn_threshold`: Log warning (e.g. 90.0)
    /// - `critical_threshold`: Send error to shutdown channel (e.g. 95.0)
    pub fn new(
        path: impl AsRef<Path>,
        notice_threshold: f64,
        warn_threshold: f64,
        critical_threshold: f64,
    ) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            notice_threshold,
            warn_threshold,
            critical_threshold,
            check_interval: DEFAULT_CHECK_INTERVAL,
        }
    }

    /// Set a custom check interval.
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Start the disk monitor. Returns a cancellation token and an
    /// error receiver. The monitor sends an error when disk usage
    /// exceeds the critical threshold.
    pub fn start(self) -> (CancellationToken, mpsc::Receiver<String>) {
        let cancel = CancellationToken::new();
        let (err_tx, err_rx) = mpsc::channel(1);
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.check_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match get_disk_stats(&self.path) {
                            Ok(stats) => {
                                self.check_thresholds(&stats, &err_tx).await;
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to get disk stats");
                            }
                        }
                    }
                    _ = cancel_clone.cancelled() => {
                        info!("disk monitor stopped");
                        break;
                    }
                }
            }
        });

        (cancel, err_rx)
    }

    async fn check_thresholds(&self, stats: &DiskStats, err_tx: &mpsc::Sender<String>) {
        let pct = stats.usage_percent;
        let free_gb = stats.free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        if pct >= self.critical_threshold {
            let msg = format!(
                "CRITICAL: disk usage {:.1}% ({:.1} GB free) exceeds critical threshold {:.0}%",
                pct, free_gb, self.critical_threshold
            );
            tracing::error!("{}", msg);
            let _ = err_tx.send(msg).await;
        } else if pct >= self.warn_threshold {
            warn!(
                usage_percent = format!("{:.1}", pct),
                free_gb = format!("{:.1}", free_gb),
                "disk usage exceeds warning threshold"
            );
        } else if pct >= self.notice_threshold {
            info!(
                usage_percent = format!("{:.1}", pct),
                free_gb = format!("{:.1}", free_gb),
                "disk usage notice"
            );
        } else {
            debug!(
                usage_percent = format!("{:.1}", pct),
                free_gb = format!("{:.1}", free_gb),
                "disk usage OK"
            );
        }
    }
}

/// Get disk usage statistics for the partition containing `path`.
#[cfg(unix)]
fn get_disk_stats(path: &Path) -> std::result::Result<DiskStats, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| format!("invalid path: {}", e))?;

    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        if libc::statfs(c_path.as_ptr(), &mut stat) != 0 {
            return Err(format!(
                "statfs failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let total = stat.f_blocks as u64 * stat.f_bsize as u64;
        let free = stat.f_bavail as u64 * stat.f_bsize as u64;
        let used = total.saturating_sub(free);
        let usage_percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Ok(DiskStats {
            usage_percent,
            total_bytes: total,
            used_bytes: used,
            free_bytes: free,
        })
    }
}

#[cfg(not(unix))]
fn get_disk_stats(_path: &Path) -> std::result::Result<DiskStats, String> {
    // Fallback for non-Unix platforms — report 0% usage
    Ok(DiskStats {
        usage_percent: 0.0,
        total_bytes: 0,
        used_bytes: 0,
        free_bytes: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_disk_stats_works() {
        let stats = get_disk_stats(Path::new("/")).unwrap();
        assert!(stats.total_bytes > 0);
        assert!(stats.usage_percent >= 0.0);
        assert!(stats.usage_percent <= 100.0);
        assert!(stats.free_bytes <= stats.total_bytes);
    }

    #[test]
    fn disk_monitor_construction() {
        let monitor = DiskMonitor::new("/tmp", 80.0, 90.0, 95.0);
        assert_eq!(monitor.notice_threshold, 80.0);
        assert_eq!(monitor.warn_threshold, 90.0);
        assert_eq!(monitor.critical_threshold, 95.0);
    }

    #[test]
    fn disk_monitor_custom_interval() {
        let monitor = DiskMonitor::new("/tmp", 80.0, 90.0, 95.0)
            .with_check_interval(Duration::from_secs(30));
        assert_eq!(monitor.check_interval, Duration::from_secs(30));
    }
}
