use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub max_size: i32,
    #[serde(default)]
    pub max_backups: i32,
    #[serde(default)]
    pub max_age: i32,
    #[serde(default)]
    pub compress: bool,
    #[serde(default)]
    pub log_filters: HashMap<String, String>,
    /// Lowest level also written to stderr (the service journal) while the
    /// node writes log files: `error`, `warn`, `info`, `debug` or `trace`.
    /// Empty means `warn`, so routine lines are not stored twice. Without log
    /// files stderr gets every level.
    #[serde(default)]
    pub stderr_level: String,
}

/// The log directory under the config directory when `path` is empty.
pub const DEFAULT_LOG_DIR: &str = ".log";

/// The `path` that keeps the node logging to stderr only.
pub const NO_LOG_FILES: &str = "none";

/// Rotation of the default log directory: 50 MB files, ten compressed
/// backups, fourteen days.
const DEFAULT_ROTATION: (i32, i32, i32, bool) = (50, 10, 14, true);

impl LogConfig {
    /// The directory the node writes its log files to, or `None` to log to
    /// stderr only. An empty `path` means `<config dir>/.log`; any other
    /// path is used as given, a relative one from the working directory.
    pub fn log_dir(&self, config_dir: &Path) -> Option<PathBuf> {
        match self.path.trim() {
            NO_LOG_FILES => None,
            "" => Some(config_dir.join(DEFAULT_LOG_DIR)),
            path => Some(PathBuf::from(path)),
        }
    }

    /// The lowest level mirrored to stderr while log files are written:
    /// the configured `stderrLevel`, or `warn` when it is empty or unknown.
    pub fn stderr_level(&self) -> &'static str {
        match self.stderr_level.trim().to_ascii_lowercase().as_str() {
            "error" => "error",
            "info" => "info",
            "debug" => "debug",
            "trace" => "trace",
            _ => "warn",
        }
    }

    /// `(max_size MB, max_backups, max_age days, compress)` as configured.
    /// The default directory stays bounded: a setting of 0 there takes the
    /// default rotation's value, and its rotated files are always
    /// compressed, since generated configs carry `compress: false`.
    pub fn rotation(&self) -> (i32, i32, i32, bool) {
        if self.path.trim().is_empty() {
            let (max_size, max_backups, max_age, compress) = DEFAULT_ROTATION;
            let or_default = |configured: i32, default: i32| if configured > 0 { configured } else { default };
            (
                or_default(self.max_size, max_size),
                or_default(self.max_backups, max_backups),
                or_default(self.max_age, max_age),
                compress,
            )
        } else {
            (self.max_size, self.max_backups, self.max_age, self.compress)
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            max_size: 0,
            max_backups: 0,
            max_age: 0,
            compress: false,
            log_filters: HashMap::new(),
            stderr_level: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_path(path: &str) -> LogConfig {
        LogConfig { path: path.to_string(), ..LogConfig::default() }
    }

    /// The default config writes log files to `.log` under the config
    /// directory with bounded rotation; `none` keeps stderr only.
    #[test]
    fn an_empty_log_path_means_the_default_directory() {
        let config_dir = Path::new("/node/.config");
        assert_eq!(with_path("").log_dir(config_dir), Some(config_dir.join(".log")));
        assert_eq!(with_path("").rotation(), (50, 10, 14, true));
        assert_eq!(with_path("none").log_dir(config_dir), None);
        assert_eq!(with_path("/var/node-logs").log_dir(config_dir), Some(PathBuf::from("/var/node-logs")));
        assert_eq!(with_path(".logs").log_dir(config_dir), Some(PathBuf::from(".logs")));
        let custom = LogConfig { max_size: 5, max_backups: 2, ..with_path("logs") };
        assert_eq!(custom.rotation(), (5, 2, 0, false));
    }

    /// Rotation settings apply to the default directory too; unset ones
    /// keep its bounded defaults.
    #[test]
    fn rotation_settings_apply_to_the_default_directory() {
        let configured = LogConfig { max_size: 200, max_backups: 3, max_age: 30, ..with_path("") };
        assert_eq!(configured.rotation(), (200, 3, 30, true));
        let partly = LogConfig { max_backups: 40, ..with_path(" ") };
        assert_eq!(partly.rotation(), (50, 40, 14, true));
        let parsed: LogConfig = serde_yaml::from_str("maxSize: 10\nmaxAge: 2\ncompress: false\n").unwrap();
        assert_eq!(parsed.rotation(), (10, 10, 2, true));
    }

    /// While log files are written, stderr (the journal) keeps warnings and
    /// errors unless configured otherwise.
    #[test]
    fn stderr_mirrors_warnings_by_default() {
        let level = |setting: &str| LogConfig { stderr_level: setting.to_string(), ..LogConfig::default() }.stderr_level();
        assert_eq!(level(""), "warn");
        assert_eq!(level("bogus"), "warn");
        assert_eq!(level("INFO"), "info");
        assert_eq!(level(" error "), "error");
    }
}
