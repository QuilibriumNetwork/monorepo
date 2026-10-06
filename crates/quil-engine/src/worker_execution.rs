//! Local engine observations, with no allocation or reward inference.
use std::sync::{Arc, Mutex};
use quil_types::proto::node::WorkerExecution;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64
}

#[derive(Clone, Debug, Default)]
pub struct SharedWorkerExecution(Arc<Mutex<WorkerExecution>>);

impl SharedWorkerExecution {
    pub fn snapshot(&self) -> WorkerExecution { self.0.lock().unwrap().clone() }

    pub fn state(&self, state: &str, blocker: &str) {
        let mut s = self.0.lock().unwrap();
        s.state = state.into();
        s.blocker = blocker.into();
        s.observed_unix_ms = now_ms();
    }

    pub fn restored(&self, height: u64) {
        let mut s = self.0.lock().unwrap();
        s.materialized_frame = Some(height);
        s.last_advance_unix_ms = 0;
        s.observed_unix_ms = now_ms();
    }

    pub fn materialized(&self, height: u64) {
        let mut s = self.0.lock().unwrap();
        let now = now_ms();
        // Restoring the initial cursor is an observation, not an advance.
        if s.materialized_frame.is_some_and(|old| height > old) {
            s.last_advance_unix_ms = now;
        }
        s.materialized_frame = Some(height);
        s.observed_unix_ms = now;
    }

    pub fn observe(&self) { self.0.lock().unwrap().observed_unix_ms = now_ms(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoration_rewind_and_state_are_independent() {
        let s = SharedWorkerExecution::default();
        assert_eq!(s.snapshot().materialized_frame, None);
        s.restored(42);
        assert_eq!(s.snapshot().last_advance_unix_ms, 0);
        s.state("blocked", "checkpoint mismatch");
        s.materialized(43);
        assert!(s.snapshot().last_advance_unix_ms > 0);
        assert_eq!(s.snapshot().state, "blocked");
        s.materialized(40);
        assert_eq!(s.snapshot().materialized_frame, Some(40));
        s.state("running", "");
        assert!(s.snapshot().blocker.is_empty());
        assert!(s.snapshot().observed_unix_ms > 0);
    }
}
