//! An accepted rejection belongs to one leave request, not to a reward-cache
//! generation. Keep it through the request's decision epoch, including restart.
use std::sync::{Arc, Mutex};

use quil_types::error::{QuilError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Rejection {
    filter: Vec<u8>,
    leave_frame: u64,
    decision_epoch: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    version: u8,
    rejections: Vec<Rejection>,
}

#[derive(Default)]
struct State {
    rejections: Vec<Rejection>,
    store: Option<(Arc<quil_store::RocksDb>, Vec<u8>)>,
}

#[derive(Default)]
pub(crate) struct LeaveDecisions(Mutex<State>);

impl LeaveDecisions {
    pub(crate) fn attach(&self, db: Arc<quil_store::RocksDb>, address: &[u8]) -> Result<()> {
        use quil_types::store::KvDb;
        let mut key = b"local:lifecycle:leave-decisions:v1:".to_vec();
        key.extend_from_slice(address);
        let rejections = match db.get(&key)? {
            None => Vec::new(),
            Some(bytes) => {
                if bytes.len() > 1_048_576 {
                    return Err(QuilError::Store("leave decision journal exceeds size limit".into()));
                }
                let journal: Journal = serde_json::from_slice(&bytes)
                    .map_err(|e| QuilError::Store(format!("invalid leave decision journal: {e}")))?;
                if journal.version != 1 || journal.rejections.len() > 4096
                    || journal.rejections.iter().any(|r| r.filter.is_empty() || r.filter.len() > 256
                        || r.decision_epoch != quil_types::consensus::epoch_for_frame(r.leave_frame) + 1)
                {
                    return Err(QuilError::Store("invalid leave decision journal records".into()));
                }
                journal.rejections
            }
        };
        let mut state = self.0.lock().map_err(|_| QuilError::Internal("leave decision lock poisoned".into()))?;
        state.rejections = rejections;
        state.store = Some((db, key));
        Ok(())
    }

    pub(crate) fn rejected(&self, filter: &[u8], leave_frame: u64, frame: u64) -> Result<bool> {
        let state = self.0.lock().map_err(|_| QuilError::Internal("leave decision lock poisoned".into()))?;
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        Ok(state.rejections.iter().any(|r| r.filter == filter && r.leave_frame == leave_frame
            && r.decision_epoch == epoch))
    }

    /// Persist accepted plan decisions before dispatch. A failed write or WAL
    /// sync returns an error without changing memory or allowing publication.
    pub(crate) fn commit(&self, rejected: &[(Vec<u8>, u64)], frame: u64) -> Result<()> {
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        let mut state = self.0.lock().map_err(|_| QuilError::Internal("leave decision lock poisoned".into()))?;
        let mut next: Vec<Rejection> = state.rejections.iter()
            .filter(|r| r.decision_epoch >= epoch).cloned().collect();
        for (filter, leave_frame) in rejected {
            let record = Rejection { filter: filter.clone(), leave_frame: *leave_frame, decision_epoch: epoch };
            if !next.contains(&record) { next.push(record); }
        }
        if next == state.rejections { return Ok(()); }
        if next.len() > 4096 {
            return Err(QuilError::Store("too many pending leave decisions".into()));
        }
        if let Some((db, key)) = &state.store {
            let bytes = serde_json::to_vec(&Journal { version: 1, rejections: next.clone() })
                .map_err(|e| QuilError::Store(e.to_string()))?;
            let inner = db.inner();
            inner.put(key, bytes).map_err(|e| QuilError::Store(e.to_string()))?;
            inner.flush_wal(true).map_err(|e| QuilError::Store(e.to_string()))?;
        }
        state.rejections = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!("leave-decisions-{}-{}", std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
    }

    #[test]
    fn rejection_survives_reopen_but_not_a_new_request_or_epoch() {
        let path = directory();
        let db = Arc::new(quil_store::RocksDb::open(&path).unwrap());
        let first = LeaveDecisions::default();
        first.attach(db.clone(), &[7; 32]).unwrap();
        first.commit(&[(vec![1], 90)], 800).unwrap();
        drop(first);
        drop(db);
        let db = Arc::new(quil_store::RocksDb::open(&path).unwrap());
        let reopened = LeaveDecisions::default();
        reopened.attach(db.clone(), &[7; 32]).unwrap();
        assert!(reopened.rejected(&[1], 90, 1439).unwrap());
        assert!(!reopened.rejected(&[1], 100, 1439).unwrap());
        assert!(!reopened.rejected(&[1], 90, 1440).unwrap());
        let other = LeaveDecisions::default();
        other.attach(db, &[8; 32]).unwrap();
        assert!(!other.rejected(&[1], 90, 800).unwrap());
        drop(reopened);
        drop(other);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn failed_persistence_does_not_commit_an_in_memory_rejection() {
        let path = directory();
        drop(quil_store::RocksDb::open(&path).unwrap());
        let decisions = LeaveDecisions::default();
        decisions.attach(Arc::new(quil_store::RocksDb::open_for_read_only(&path).unwrap()), &[7; 32]).unwrap();
        assert!(decisions.commit(&[(vec![1], 90)], 800).is_err());
        assert!(!decisions.rejected(&[1], 90, 800).unwrap());
        drop(decisions);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn malformed_journal_is_not_silently_discarded() {
        use quil_types::store::KvDb;
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let mut key = b"local:lifecycle:leave-decisions:v1:".to_vec();
        key.extend_from_slice(&[7; 32]);
        db.set(&key, b"invalid").unwrap();
        assert!(LeaveDecisions::default().attach(db, &[7; 32]).is_err());
    }
}
