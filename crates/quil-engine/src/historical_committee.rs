//! Committees of legacy app sessions as they stood when a frame was certified.
//!
//! A legacy (generation-zero, unmanaged) app frame is certified by the
//! committee `get_active_provers(filter, anchor)` that the proposer's registry
//! produced when it proposed. Verification recomputed that set from today's
//! registry, which cannot reproduce it once provers have left, been kicked,
//! rejoined or been reassigned: every archive checkpoint of such a shard was
//! rejected ("app shard frame CW finalization cert verification failed"), and
//! members that had to recover it never could (public issues #664, #672).
//!
//! A [`HistoricalCommitteeSource`] answers with the committees the GLOBAL
//! prover tree gave at frames around the anchor, each read from a tree pinned
//! to a certified GLOBAL header's commitment (the node-side implementation
//! syncs that tree into a scratch store). The validator tries them only after
//! the live registry's committee fails, and only for legacy certificates; the
//! certificate check itself is unchanged.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use quil_types::error::Result;

/// `(filter, anchor GLOBAL frame)` → candidate committees (each a list of
/// committee public keys), every one authenticated by the GLOBAL prover tree
/// at a frame near the anchor.
pub type HistoricalCommitteeSource = Arc<
    dyn Fn(Vec<u8>, u64) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<Vec<u8>>>>> + Send>> + Send + Sync,
>;

/// How long one reconstruction may take: it can sync a historical prover
/// tree from an archive.
pub const HISTORICAL_COMMITTEE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Anchors whose candidates are kept.
const KEPT: usize = 64;

/// Candidates fetched per `(filter, anchor)`, newest kept.
#[derive(Default)]
pub(crate) struct HistoricalCommittees {
    entries: Mutex<VecDeque<((Vec<u8>, u64), Arc<Vec<Vec<Vec<u8>>>>)>>,
}

impl HistoricalCommittees {
    pub(crate) fn get(&self, filter: &[u8], anchor: u64) -> Option<Arc<Vec<Vec<Vec<u8>>>>> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .find(|((f, a), _)| f.as_slice() == filter && *a == anchor)
            .map(|(_, committees)| committees.clone())
    }

    pub(crate) fn put(&self, filter: Vec<u8>, anchor: u64, committees: Vec<Vec<Vec<u8>>>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.retain(|((f, a), _)| !(f == &filter && *a == anchor));
        entries.push_back(((filter, anchor), Arc::new(committees)));
        while entries.len() > KEPT {
            entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_kept_per_filter_and_anchor_and_bounded() {
        let kept = HistoricalCommittees::default();
        assert!(kept.get(b"shard", 5).is_none());
        kept.put(b"shard".to_vec(), 5, vec![vec![vec![1u8; 897]]]);
        kept.put(b"other".to_vec(), 5, vec![]);
        assert_eq!(kept.get(b"shard", 5).unwrap().len(), 1);
        assert!(kept.get(b"shard", 6).is_none());
        kept.put(b"shard".to_vec(), 5, vec![vec![vec![2u8; 897]], vec![vec![3u8; 897]]]);
        assert_eq!(kept.get(b"shard", 5).unwrap().len(), 2, "replaced, not duplicated");
        for anchor in 0..(KEPT as u64 + 10) {
            kept.put(b"many".to_vec(), anchor + 100, vec![]);
        }
        assert!(kept.get(b"shard", 5).is_none(), "oldest dropped past the bound");
        assert!(kept.get(b"many", 100 + KEPT as u64 + 9).is_some());
    }
}
