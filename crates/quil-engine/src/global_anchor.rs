//! Historical GLOBAL frames from a worker's own, identity-pinned master.
//!
//! This is the same trust boundary as the master's worker stream. An arbitrary
//! archive must never implement this source without independent authentication
//! of the returned frame's place in the canonical GLOBAL chain.

use prost::Message;
use quil_types::{
    error::{QuilError, Result},
    proto::global::GlobalFrame,
    store::ClockStore,
};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub const MAX_GLOBAL_ANCHOR_BYTES: usize = 64 * 1024 * 1024;
pub type GlobalAnchorSource =
    Arc<dyn Fn(u64) -> Pin<Box<dyn Future<Output = Result<GlobalFrame>> + Send>> + Send + Sync>;

/// Backfill one missing historical frame. Never fetch the latest-frame alias,
/// advance the known GLOBAL head, or turn a local read failure into a miss.
pub async fn ensure_global_anchor(
    store: &dyn ClockStore,
    source: &GlobalAnchorSource,
    number: u64,
) -> Result<()> {
    if number == 0 {
        return Ok(());
    }
    match store.get_global_clock_frame(number) {
        Ok(_) => return Ok(()),
        Err(QuilError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    let head = store
        .get_latest_global_clock_frame()?
        .header
        .ok_or_else(|| QuilError::ExecutionUnavailable("worker GLOBAL head lacks header".into()))?;
    if number >= head.frame_number {
        return Err(QuilError::ExecutionUnavailable(
            "historical anchor is not behind the worker GLOBAL head".into(),
        ));
    }
    // The master has a bounded archive fallback; give that hop time.
    let frame = tokio::time::timeout(Duration::from_secs(12), source(number))
        .await
        .map_err(|_| {
            QuilError::ExecutionUnavailable("master GLOBAL anchor fetch timed out".into())
        })??;
    if frame
        .header
        .as_ref()
        .is_none_or(|header| header.frame_number != number)
        || frame.encoded_len() > MAX_GLOBAL_ANCHOR_BYTES
    {
        return Err(QuilError::InvalidArgument(
            "master returned an invalid or oversized GLOBAL anchor".into(),
        ));
    }
    let txn = store.new_transaction(false)?;
    store.put_global_clock_frame(&frame, txn.as_ref())?;
    txn.commit()?;
    tracing::info!(
        frame = number,
        bytes = frame.encoded_len(),
        "recovered historical GLOBAL anchor from own master"
    );
    Ok(())
}

/// What [`fetch_cited_frames`] left: the frames now held (fetched and
/// stored, or held already), and those still missing with the reason.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CitedFetch {
    pub held: Vec<u64>,
    pub missing: Vec<(u64, String)>,
}

impl CitedFetch {
    /// Each of `frames` missing for `reason`: nothing could fetch them.
    pub fn unfetchable(frames: &[u64], reason: &str) -> Self {
        Self {
            held: Vec::new(),
            missing: frames
                .iter()
                .map(|&number| (number, reason.to_string()))
                .collect(),
        }
    }
}

/// Backfill each of `frames` the store lacks, in order, through
/// [`ensure_global_anchor`], all within `budget`: the GLOBAL frames the
/// reward citations of a frame about to execute name. A frame not fetched
/// within the budget is left missing, never refused: the frame then waits
/// for retry with nothing executed, and the frames fetched so far are kept.
pub async fn fetch_cited_frames(
    store: &dyn ClockStore,
    source: &GlobalAnchorSource,
    frames: &[u64],
    budget: Duration,
) -> CitedFetch {
    let deadline = tokio::time::Instant::now() + budget;
    let mut outcome = CitedFetch::default();
    for &number in frames {
        if tokio::time::Instant::now() >= deadline {
            outcome
                .missing
                .push((number, "the fetch budget was spent".into()));
            continue;
        }
        match tokio::time::timeout_at(deadline, ensure_global_anchor(store, source, number)).await {
            Ok(Ok(())) => outcome.held.push(number),
            Ok(Err(error)) => outcome.missing.push((number, error.to_string())),
            Err(_) => outcome
                .missing
                .push((number, "the fetch budget was spent".into())),
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::GlobalFrameHeader;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn frame(number: u64) -> GlobalFrame {
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: number,
                ..Default::default()
            }),
            requests: vec![],
        }
    }
    fn put(store: &dyn ClockStore, frame: &GlobalFrame) {
        let txn = store.new_transaction(false).unwrap();
        store.put_global_clock_frame(frame, txn.as_ref()).unwrap();
        txn.commit().unwrap();
    }

    #[tokio::test]
    async fn historical_backfill_is_persisted_without_moving_head_and_reused_after_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "quil-global-anchor-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let source: GlobalAnchorSource = Arc::new(move |n| {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(frame(n)) })
        });
        {
            let db = quil_store::RocksDb::open(&dir).unwrap();
            let store = quil_store::RocksClockStore::new(db.inner());
            put(&store, &frame(100));
            ensure_global_anchor(&store, &source, 50).await.unwrap();
            assert_eq!(store.get_global_clock_frame(50).unwrap(), frame(50));
            assert_eq!(store.get_latest_global_clock_frame().unwrap(), frame(100));
        }
        let db = quil_store::RocksDb::open(&dir).unwrap();
        let store = quil_store::RocksClockStore::new(db.inner());
        ensure_global_anchor(&store, &source, 50).await.unwrap();
        ensure_global_anchor(&store, &source, 0).await.unwrap();
        assert!(ensure_global_anchor(&store, &source, 101).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.get_latest_global_clock_frame().unwrap(), frame(100));
        drop(store);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_mismatched_and_oversized_anchors_do_not_write() {
        for case in 0..4 {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let store = quil_store::RocksClockStore::new(db.inner());
            put(&store, &frame(100));
            let source: GlobalAnchorSource = Arc::new(move |n| {
                Box::pin(async move {
                    let mut answer = frame(n);
                    match case {
                        0 => return Err(QuilError::ExecutionUnavailable("master offline".into())),
                        1 => answer.header = None,
                        2 => answer.header.as_mut().unwrap().frame_number += 1,
                        _ => {
                            answer.header.as_mut().unwrap().output =
                                vec![0; MAX_GLOBAL_ANCHOR_BYTES]
                        }
                    }
                    Ok(answer)
                })
            });
            assert!(ensure_global_anchor(&store, &source, 50).await.is_err());
            assert!(matches!(
                store.get_global_clock_frame(50),
                Err(QuilError::NotFound(_))
            ));
            assert_eq!(store.get_latest_global_clock_frame().unwrap(), frame(100));
        }
    }

    /// A master that cannot answer costs at most the budget, and the
    /// frames it serves are still fetched; nothing is fetched twice.
    #[tokio::test(start_paused = true)]
    async fn cited_frame_fetches_end_within_their_budget() {
        type Fetch = Pin<Box<dyn Future<Output = Result<GlobalFrame>> + Send>>;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store = quil_store::RocksClockStore::new(db.inner());
        put(&store, &frame(100));
        put(&store, &frame(30));
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let one_hangs: GlobalAnchorSource = Arc::new(move |n: u64| -> Fetch {
            counted.fetch_add(1, Ordering::SeqCst);
            if n == 50 {
                Box::pin(std::future::pending::<Result<GlobalFrame>>())
            } else {
                Box::pin(async move { Ok(frame(n)) })
            }
        });
        let budget = Duration::from_secs(30);
        let started = tokio::time::Instant::now();
        let outcome = fetch_cited_frames(&store, &one_hangs, &[30, 40, 50, 60], budget).await;
        assert_eq!(outcome.held, vec![30, 40, 60]);
        assert_eq!(
            outcome.missing.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![50]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a held frame is not fetched"
        );
        assert_eq!(store.get_global_clock_frame(60).unwrap(), frame(60));
        assert!(started.elapsed() <= budget);

        let all_hang: GlobalAnchorSource =
            Arc::new(|_: u64| -> Fetch { Box::pin(std::future::pending::<Result<GlobalFrame>>()) });
        let frames: Vec<u64> = (1..=10).collect();
        let started = tokio::time::Instant::now();
        let outcome = fetch_cited_frames(&store, &all_hang, &frames, budget).await;
        assert!(outcome.held.is_empty());
        assert_eq!(
            outcome.missing.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            frames
        );
        assert!(
            started.elapsed() <= budget,
            "ten unanswered fetches must end within the budget, took {:?}",
            started.elapsed()
        );
    }
}
