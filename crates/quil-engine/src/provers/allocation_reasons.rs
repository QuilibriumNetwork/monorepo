//! Local proposal intent, matched to observed allocation request frames.
//! This is operator history, not consensus state or committee authorization.
use std::sync::{Arc, Mutex};
use quil_types::error::{QuilError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    filter: Vec<u8>,
    joining: bool,
    frame: u64,
    reason: String,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    store: Option<(Arc<quil_store::RocksDb>, Vec<u8>)>,
}

#[derive(Default)]
pub struct AllocationReasons(Mutex<State>);

fn valid_reason(reason: &str) -> bool {
    matches!(reason, "$" | "H" | "S" | "G" | "T" | "E" | "C" | "O" | "M" | "D")
}

impl AllocationReasons {
    pub fn attach(&self, db: Arc<quil_store::RocksDb>, address: &[u8]) -> Result<()> {
        use quil_types::store::KvDb;
        let mut key = b"local:allocation-reasons:v1:".to_vec();
        key.extend_from_slice(address);
        let entries = match db.get(&key)? {
            None => Vec::new(),
            Some(bytes) => {
                if bytes.len() > 1_048_576 { return Err(QuilError::Store("allocation reason history exceeds limit".into())); }
                let entries: Vec<Entry> = serde_json::from_slice(&bytes)
                    .map_err(|e| QuilError::Store(format!("invalid allocation reason history: {e}")))?;
                if entries.len() > 4096 || entries.iter().any(|e| e.filter.is_empty()
                    || e.filter.len() > 256 || e.frame == 0 || !valid_reason(&e.reason)) {
                    return Err(QuilError::Store("invalid allocation reason records".into()));
                }
                entries
            }
        };
        let mut state = self.0.lock().map_err(|_| QuilError::Internal("allocation reason lock poisoned".into()))?;
        state.entries = entries;
        state.store = Some((db, key));
        Ok(())
    }

    /// Save intent before dispatch. Failed persistence does not update memory.
    pub fn record(&self, filters: &[Vec<u8>], joining: bool, frame: u64, reason: &str) -> Result<()> {
        if frame == 0 || !valid_reason(reason) { return Err(QuilError::InvalidArgument("invalid allocation reason".into())); }
        let mut state = self.0.lock().map_err(|_| QuilError::Internal("allocation reason lock poisoned".into()))?;
        let mut next = state.entries.clone();
        for filter in filters.iter().filter(|f| !f.is_empty()) {
            if filter.len() > 256 { return Err(QuilError::InvalidArgument("allocation reason filter exceeds limit".into())); }
            // Retain retry attempts separately: the observed request can predate
            // a later retry. Matching always uses the newest preceding intent.
            let entry = Entry { filter: filter.clone(), joining, frame, reason: reason.into() };
            if !next.contains(&entry) { next.push(entry); }
        }
        if next == state.entries { return Ok(()); }
        // Retain the newest bounded history; absence remains unknown in RPC.
        next.sort_by_key(|e| e.frame);
        if next.len() > 4096 { next.drain(..next.len() - 4096); }
        if let Some((db, key)) = &state.store {
            let bytes = serde_json::to_vec(&next).map_err(|e| QuilError::Store(e.to_string()))?;
            db.inner().put(key, bytes).map_err(|e| QuilError::Store(e.to_string()))?;
            db.inner().flush_wal(true).map_err(|e| QuilError::Store(e.to_string()))?;
        }
        state.entries = next;
        Ok(())
    }

    /// A local intent cannot establish a reason for an older request or for a
    /// future epoch's unrelated request. Exact matches take precedence.
    pub fn reason(&self, filter: &[u8], joining: bool, request_frame: u64) -> Option<String> {
        let state = self.0.lock().ok()?;
        state.entries.iter().filter(|e| e.filter == filter && e.joining == joining
            && e.frame <= request_frame
            && quil_types::consensus::epoch_for_frame(e.frame) == quil_types::consensus::epoch_for_frame(request_frame))
            .max_by_key(|e| e.frame).map(|e| e.reason.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intent_survives_reopen_and_does_not_label_an_older_or_future_request() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let reasons = AllocationReasons::default();
        reasons.attach(db.clone(), &[1;32]).unwrap();
        reasons.record(&[vec![9]], true, 100, "M").unwrap();
        reasons.record(&[vec![9]], false, 200, "$").unwrap();
        reasons.record(&[vec![9]], false, 220, "H").unwrap();
        let reopened = AllocationReasons::default();
        reopened.attach(db, &[1;32]).unwrap();
        assert_eq!(reopened.reason(&[9], true, 101).as_deref(), Some("M"));
        assert_eq!(reopened.reason(&[9], false, 210).as_deref(), Some("$"));
        assert_eq!(reopened.reason(&[9], false, 221).as_deref(), Some("H"));
        assert!(reopened.reason(&[9], true, 99).is_none());
        assert!(reopened.reason(&[9], true, 800).is_none());
        assert!(reopened.reason(&[8], true, 101).is_none());
    }
}
