//! Thread-safe registry of active compose project names, used as a safety net
//! to tear down any still-running projects on interrupt.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct ProjectRegistry {
    projects: Arc<Mutex<HashSet<String>>>,
}

impl ProjectRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, project_name: &str) {
        self.projects
            .lock()
            .unwrap()
            .insert(project_name.to_string());
    }

    pub fn unregister(&self, project_name: &str) {
        self.projects.lock().unwrap().remove(project_name);
    }

    pub fn get_all(&self) -> Vec<String> {
        self.projects.lock().unwrap().iter().cloned().collect()
    }
}
