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
    dyn Fn(Vec<u8>, u64) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<Vec<u8>>>>> + Send>>
        + Send
        + Sync,
>;

/// How long one reconstruction may take: it can sync a historical prover
/// tree from an archive.
pub const HISTORICAL_COMMITTEE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Anchors whose candidates are kept.
const KEPT: usize = 64;

/// How long candidates are kept: a reconstruction may have missed a root
/// that a later one finds.
pub(crate) const KEPT_FOR: std::time::Duration = std::time::Duration::from_secs(3600);

/// How long a failed reconstruction is answered as failed, so callers in
/// an engine's actor (sync anchors, engine start) do not repeat it at once.
pub(crate) const FAILED_KEPT_FOR: std::time::Duration = std::time::Duration::from_secs(600);

/// Reconstructions run at a time, node-wide: each may sync a historical
/// prover tree, and forced ones at chosen anchors must not pile up.
pub(crate) static REBUILDS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(2));

/// Candidates fetched per `(filter, anchor)`, newest kept for [`KEPT_FOR`],
/// the anchors whose reconstruction failed within [`FAILED_KEPT_FOR`], and
/// the anchors being rebuilt.
#[derive(Default)]
pub(crate) struct HistoricalCommittees {
    entries: Mutex<VecDeque<((Vec<u8>, u64), std::time::Instant, Arc<Vec<Vec<Vec<u8>>>>)>>,
    failures: Mutex<VecDeque<((Vec<u8>, u64), std::time::Instant)>>,
    rebuilding: Mutex<std::collections::HashMap<(Vec<u8>, u64), tokio::sync::watch::Receiver<()>>>,
}

/// A reconstruction of one `(filter, anchor)`'s committees under way
/// ([`HistoricalCommittees::begin`]), ended when dropped, which wakes those
/// waiting on it.
pub(crate) struct Rebuilding<'a> {
    committees: &'a HistoricalCommittees,
    key: (Vec<u8>, u64),
    _done: tokio::sync::watch::Sender<()>,
}

impl Drop for Rebuilding<'_> {
    fn drop(&mut self) {
        self.committees
            .rebuilding
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.key);
    }
}

/// Whether a caller rebuilds an anchor's committees or waits on another
/// that does ([`HistoricalCommittees::begin`]).
pub(crate) enum Begun<'a> {
    Rebuild(Rebuilding<'a>),
    /// Ends (with an error, its sender gone) when that reconstruction ends.
    Wait(tokio::sync::watch::Receiver<()>),
}

impl HistoricalCommittees {
    /// Start rebuilding `(filter, anchor)`'s committees, or, while a
    /// reconstruction of them is under way, wait on it: one at a time per
    /// anchor, however many frames or carried copies need it, so copies
    /// planted with a certificate that sends the node to GLOBAL history
    /// start one reconstruction, not one each, and every caller still gets
    /// its result.
    pub(crate) fn begin(&self, filter: &[u8], anchor: u64) -> Begun<'_> {
        let key = (filter.to_vec(), anchor);
        let mut rebuilding = self.rebuilding.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(done) = rebuilding.get(&key) {
            return Begun::Wait(done.clone());
        }
        let (done, waiting) = tokio::sync::watch::channel(());
        rebuilding.insert(key.clone(), waiting);
        Begun::Rebuild(Rebuilding {
            committees: self,
            key,
            _done: done,
        })
    }

    pub(crate) fn get(&self, filter: &[u8], anchor: u64) -> Option<Arc<Vec<Vec<Vec<u8>>>>> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .find(|((f, a), at, _)| {
                f.as_slice() == filter && *a == anchor && at.elapsed() < KEPT_FOR
            })
            .map(|(_, _, committees)| committees.clone())
    }

    pub(crate) fn put(&self, filter: Vec<u8>, anchor: u64, committees: Vec<Vec<Vec<u8>>>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .retain(|((f, a), at, _)| !(f == &filter && *a == anchor) && at.elapsed() < KEPT_FOR);
        entries.push_back((
            (filter, anchor),
            std::time::Instant::now(),
            Arc::new(committees),
        ));
        while entries.len() > KEPT {
            entries.pop_front();
        }
    }

    /// Record that rebuilding `(filter, anchor)`'s committees failed now.
    pub(crate) fn failed(&self, filter: Vec<u8>, anchor: u64) {
        let mut failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        failures.retain(|((f, a), at)| {
            !(f == &filter && *a == anchor) && at.elapsed() < FAILED_KEPT_FOR
        });
        failures.push_back(((filter, anchor), std::time::Instant::now()));
        while failures.len() > KEPT {
            failures.pop_front();
        }
    }

    /// How long ago rebuilding `(filter, anchor)`'s committees failed, within
    /// [`FAILED_KEPT_FOR`].
    pub(crate) fn failed_ago(&self, filter: &[u8], anchor: u64) -> Option<std::time::Duration> {
        let failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        failures
            .iter()
            .find(|((f, a), at)| {
                f.as_slice() == filter && *a == anchor && at.elapsed() < FAILED_KEPT_FOR
            })
            .map(|(_, at)| at.elapsed())
    }

    /// Age every entry and failure past [`KEPT_FOR`] and
    /// [`FAILED_KEPT_FOR`], as time would.
    #[cfg(test)]
    pub(crate) fn expire(&self) {
        let Some(past) = std::time::Instant::now().checked_sub(KEPT_FOR) else {
            return;
        };
        for (_, at, _) in self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter_mut()
        {
            *at = past;
        }
        for (_, at) in self
            .failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter_mut()
        {
            *at = past;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_reconstruction_per_anchor_at_a_time_and_the_others_wait_on_it() {
        let kept = HistoricalCommittees::default();
        let Begun::Rebuild(first) = kept.begin(b"shard", 5) else {
            panic!("nothing under way")
        };
        let Begun::Wait(mut waiting) = kept.begin(b"shard", 5) else {
            panic!("under way")
        };
        assert!(
            matches!(kept.begin(b"shard", 6), Begun::Rebuild(_)),
            "another anchor"
        );
        drop(first);
        assert!(waiting.changed().await.is_err(), "woken when it ends");
        assert!(
            matches!(kept.begin(b"shard", 5), Begun::Rebuild(_)),
            "ended"
        );
    }

    #[test]
    fn a_failure_is_kept_a_while() {
        let kept = HistoricalCommittees::default();
        assert!(kept.failed_ago(b"shard", 5).is_none());
        kept.failed(b"shard".to_vec(), 5);
        assert!(kept.failed_ago(b"shard", 5).is_some());
        assert!(kept.failed_ago(b"shard", 6).is_none());
        kept.expire();
        assert!(
            kept.failed_ago(b"shard", 5).is_none(),
            "tried again after a while"
        );
    }

    #[test]
    fn candidates_expire() {
        let kept = HistoricalCommittees::default();
        kept.put(b"shard".to_vec(), 5, vec![vec![vec![1u8; 897]]]);
        assert!(kept.get(b"shard", 5).is_some());
        kept.expire();
        assert!(
            kept.get(b"shard", 5).is_none(),
            "rebuilt again after a while"
        );
    }

    #[test]
    fn candidates_are_kept_per_filter_and_anchor_and_bounded() {
        let kept = HistoricalCommittees::default();
        assert!(kept.get(b"shard", 5).is_none());
        kept.put(b"shard".to_vec(), 5, vec![vec![vec![1u8; 897]]]);
        kept.put(b"other".to_vec(), 5, vec![]);
        assert_eq!(kept.get(b"shard", 5).unwrap().len(), 1);
        assert!(kept.get(b"shard", 6).is_none());
        kept.put(
            b"shard".to_vec(),
            5,
            vec![vec![vec![2u8; 897]], vec![vec![3u8; 897]]],
        );
        assert_eq!(
            kept.get(b"shard", 5).unwrap().len(),
            2,
            "replaced, not duplicated"
        );
        for anchor in 0..(KEPT as u64 + 10) {
            kept.put(b"many".to_vec(), anchor + 100, vec![]);
        }
        assert!(
            kept.get(b"shard", 5).is_none(),
            "oldest dropped past the bound"
        );
        assert!(kept.get(b"many", 100 + KEPT as u64 + 9).is_some());
    }
}
