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
    matches!(reason, "$" | "H" | "S" | "G" | "T" | "E" | "C" | "O" | "M" | "D" | "W")
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

    /// The reason of `allocation`'s pending join or leave at `frame`: the
    /// recorded intent, else, for a leave of a node holding more seats than
    /// `worker_capacity` (its configured worker count), `W`, worker shortage.
    /// `W` is inferred from the current counts when no record exists (after
    /// a store reset, say); it is never recorded.
    pub fn reason_or_inferred(
        &self,
        allocation: &quil_types::consensus::ProverAllocationInfo,
        allocations: &[quil_types::consensus::ProverAllocationInfo],
        frame: u64,
        worker_capacity: usize,
    ) -> Option<String> {
        use quil_types::consensus::EffectiveStatus;
        let joining = match allocation.effective_status(frame) {
            EffectiveStatus::Joining => true,
            EffectiveStatus::Leaving => false,
            _ => return None,
        };
        let request = if joining { allocation.join_frame_number } else { allocation.leave_frame_number };
        self.reason(&allocation.confirmation_filter, joining, request).or_else(|| {
            let held = allocations.iter().filter(|a| super::draining::holds_seat(a, frame, true)).count();
            (!joining && worker_capacity > 0 && held > worker_capacity).then(|| "W".to_string())
        })
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

    /// A leave with no local record reads `W` while the node holds more seats
    /// than its configured worker count, and unknown otherwise; a record
    /// wins, a join is never inferred, and `W` is not recorded.
    #[test]
    fn a_leave_without_a_record_is_a_worker_shortage_while_seats_exceed_workers() {
        use quil_types::consensus::{ProverAllocationInfo, ProverStatus};
        let seat = |filter: u8, status: ProverStatus, frame: u64| ProverAllocationInfo {
            status, confirmation_filter: vec![filter], join_frame_number: if status == ProverStatus::Joining { frame } else { 1 },
            leave_frame_number: if status == ProverStatus::Leaving { frame } else { 0 }, epoch: u64::MAX,
            rejection_filter: vec![], pause_frame_number: 0, resume_frame_number: 0, kick_frame_number: 0,
            join_confirm_frame_number: 0, join_reject_frame_number: 0, leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0, last_active_frame_number: 0, last_signed_frame_number: 0, ring: 0,
            vertex_address: vec![],
        };
        // After a store reset: 6 Active seats and 3 leaves of a 9 -> 6 downscale.
        let mut held: Vec<ProverAllocationInfo> = (1..=6).map(|f| seat(f, ProverStatus::Active, 0)).collect();
        held.extend((7..=9).map(|f| seat(f, ProverStatus::Leaving, 100)));
        held.push(seat(10, ProverStatus::Joining, 100));
        let reasons = AllocationReasons::default();
        assert_eq!(reasons.reason_or_inferred(&held[6], &held, 200, 6).as_deref(), Some("W"));
        assert_eq!(reasons.reason_or_inferred(&held[6], &held, 200, 9), None, "seats within the count");
        assert_eq!(reasons.reason_or_inferred(&held[6], &held, 200, 0), None, "count unknown");
        assert_eq!(reasons.reason_or_inferred(&held[9], &held, 200, 6), None, "a join is not inferred");
        assert_eq!(reasons.reason_or_inferred(&held[0], &held, 200, 6), None, "an Active seat has no reason");
        reasons.record(&[vec![7]], false, 100, "C").unwrap();
        assert_eq!(reasons.reason_or_inferred(&held[6], &held, 200, 6).as_deref(), Some("C"), "the record wins");
        assert_eq!(reasons.reason(&[8], false, 100), None, "W is never recorded");
    }
}
