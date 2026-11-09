//! Takes each worker's shard consensus messages off the node's inbound queue
//! ahead of the message loop.
//!
//! The loop stores and executes GLOBAL frames on its own task. While one of
//! those waits on a busy disk, the inbound queue fills in seconds and the
//! network task drops what arrives: votes, certificates and the frame bodies
//! of every shard this node serves, though handing them on takes a queue send.
//! A worker missing a body cannot verify on it or anything built on it, until
//! archive replay brings the frame. This lane routes those messages itself and
//! passes the rest on, so only the loop's own work waits for the loop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_p2p::node::ReceivedMessage;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::warn;

/// How often a filling loop queue is reported.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// Messages the lane could not pass to the loop, whose queue was full.
#[derive(Default)]
pub(super) struct LoopQueueDrops(AtomicU64);

impl LoopQueueDrops {
    pub(super) fn total(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Route messages from `inbound` until it or `to_loop` closes: `route` hands
/// a shard consensus message to its engine without waiting and says so; all
/// others go to the loop, dropped and counted when its queue is full.
pub(super) async fn run(
    mut inbound: Receiver<ReceivedMessage>,
    to_loop: Sender<ReceivedMessage>,
    drops: Arc<LoopQueueDrops>,
    mut route: impl FnMut(&mut ReceivedMessage) -> bool,
) {
    let mut reported = Instant::now();
    let mut reported_total = 0;
    while let Some(mut received) = inbound.recv().await {
        if route(&mut received) {
            continue;
        }
        match to_loop.try_send(received) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                drops.0.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Closed(_)) => return,
        }
        let total = drops.total();
        if total > reported_total && reported.elapsed() >= REPORT_EVERY {
            warn!(dropped = total - reported_total, secs = reported.elapsed().as_secs(), total,
                scope = "this node",
                action = "shard consensus messages are not affected; GLOBAL frames dropped here come back from the archive poller; if this repeats, look for 'master task blocked' lines and check this node's disk",
                "the master's message loop is falling behind: messages for it were dropped");
            reported = Instant::now();
            reported_total = total;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn message(bitmask: u8) -> ReceivedMessage {
        ReceivedMessage {
            bitmask: vec![bitmask],
            data: vec![bitmask],
            from: Vec::new(),
            via: Vec::new(),
            direct: false,
        }
    }

    const SHARD: u8 = 1;
    const GLOBAL: u8 = 2;

    /// A loop that takes nothing costs only its own messages: every shard
    /// message still reaches its engine, past far more messages than the
    /// inbound queue holds, and the dropped ones are counted.
    #[tokio::test]
    async fn a_blocked_loop_holds_back_no_shard_message() {
        let (inbound_tx, inbound) = mpsc::channel(4);
        let (to_loop, mut loop_queue) = mpsc::channel(2);
        let drops = Arc::new(LoopQueueDrops::default());
        let (routed_tx, mut routed) = mpsc::unbounded_channel();
        let lane = tokio::spawn(run(inbound, to_loop, drops.clone(), move |received| {
            let shard = received.bitmask == [SHARD];
            if shard {
                routed_tx.send(()).unwrap();
            }
            shard
        }));
        const EACH: usize = 100;
        for _ in 0..EACH {
            for bitmask in [GLOBAL, SHARD] {
                tokio::time::timeout(Duration::from_secs(5), inbound_tx.send(message(bitmask)))
                    .await
                    .expect("the inbound queue waited for the loop")
                    .unwrap();
            }
        }
        for _ in 0..EACH {
            tokio::time::timeout(Duration::from_secs(5), routed.recv())
                .await
                .expect("a shard message waited for the loop")
                .unwrap();
        }
        drop(inbound_tx);
        lane.await.unwrap();
        let mut queued = 0;
        while loop_queue.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, 2, "the loop keeps what its queue holds");
        assert_eq!(drops.total(), EACH as u64 - 2, "and the rest are counted");
    }

    /// A message the lane does not route reaches the loop unchanged, in order.
    #[tokio::test]
    async fn other_messages_reach_the_loop_in_order() {
        let (inbound_tx, inbound) = mpsc::channel(4);
        let (to_loop, mut loop_queue) = mpsc::channel(4);
        let drops = Arc::new(LoopQueueDrops::default());
        let lane = tokio::spawn(run(inbound, to_loop, drops.clone(), |_| false));
        for bitmask in [5, 6, 7] {
            inbound_tx.send(message(bitmask)).await.unwrap();
        }
        for bitmask in [5, 6, 7] {
            let received = loop_queue.recv().await.unwrap();
            assert_eq!(received.bitmask, [bitmask]);
            assert_eq!(received.data, [bitmask]);
        }
        drop(inbound_tx);
        lane.await.unwrap();
        assert_eq!(drops.total(), 0);
    }

    /// The lane ends with the loop, rather than route for a stopped node.
    #[tokio::test]
    async fn the_lane_ends_when_the_loop_has_stopped() {
        let (inbound_tx, inbound) = mpsc::channel(4);
        let (to_loop, loop_queue) = mpsc::channel(4);
        drop(loop_queue);
        let lane = tokio::spawn(run(
            inbound,
            to_loop,
            Arc::new(LoopQueueDrops::default()),
            |_| false,
        ));
        inbound_tx.send(message(GLOBAL)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), lane)
            .await
            .expect("the lane stops")
            .unwrap();
    }
}
