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
    let frame = tokio::time::timeout(Duration::from_secs(10), source(number))
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
}
