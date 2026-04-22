use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        }
    }
}
