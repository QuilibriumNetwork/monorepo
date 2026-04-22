use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_worker_path_prefix")]
    pub worker_path_prefix: String,
    #[serde(default)]
    pub worker_paths: Vec<String>,
    #[serde(default = "default_notice_pct")]
    pub notice_percentage: i32,
    #[serde(default = "default_warn_pct")]
    pub warn_percentage: i32,
    #[serde(default = "default_terminate_pct")]
    pub terminate_percentage: i32,
}

fn default_worker_path_prefix() -> String { "worker-store/%d".into() }
fn default_notice_pct() -> i32 { 70 }
fn default_warn_pct() -> i32 { 90 }
fn default_terminate_pct() -> i32 { 95 }

impl Default for DbConfig {
    fn default() -> Self {
        serde_yaml::from_str("{}").unwrap()
    }
}

impl DbConfig {
    pub fn apply_defaults(&mut self) {
        if self.worker_path_prefix.is_empty() {
            self.worker_path_prefix = default_worker_path_prefix();
        }
        if self.notice_percentage == 0 {
            self.notice_percentage = default_notice_pct();
        }
        if self.warn_percentage == 0 {
            self.warn_percentage = default_warn_pct();
        }
        if self.terminate_percentage == 0 {
            self.terminate_percentage = default_terminate_pct();
        }
    }
}
