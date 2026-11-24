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

use quil_engine::app_engine::AppEngineMessage;
use quil_engine::remote_worker::RemoteDelivery;
use quil_p2p::direct::{DirectAck, DirectAnswer};
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

/// Hand a shard CW message to the in-process engine `deliver` puts it to,
/// saying whether its queue took it. A direct sender is answered "taken"
/// only then; otherwise "refused", and it sends its topic copy.
pub(super) fn deliver_in_process(
    received: &ReceivedMessage,
    deliver: impl FnOnce(AppEngineMessage) -> bool,
    channel: u64,
    from: Vec<u8>,
    data: Vec<u8>,
) -> bool {
    let taken = deliver(AppEngineMessage::CwIn {
        channel,
        from,
        data,
    });
    received.answer(if taken {
        DirectAnswer::Taken
    } else {
        DirectAnswer::Refused
    });
    taken
}

/// This node's standalone workers, as the lane hands them messages.
#[async_trait::async_trait]
pub(super) trait ShardWorkers: Send + Sync {
    async fn deliver_shard_consensus(
        &self,
        filter: &[u8],
        channel: u64,
        data: Vec<u8>,
        from: Vec<u8>,
    ) -> RemoteDelivery;
}

#[async_trait::async_trait]
impl ShardWorkers for quil_engine::remote_worker::RemoteWorkerManager {
    async fn deliver_shard_consensus(
        &self,
        filter: &[u8],
        channel: u64,
        data: Vec<u8>,
        from: Vec<u8>,
    ) -> RemoteDelivery {
        quil_engine::remote_worker::RemoteWorkerManager::deliver_shard_consensus(
            self, filter, channel, data, from,
        )
        .await
    }
}

/// The answer a direct sender gets for what this node's standalone worker
/// did with its message: "taken" only when the worker says its engine took
/// it; "queued" from an earlier worker, whose acceptance does not say, so
/// the sender still sends its topic copy for votes, certificates and blocks.
pub(super) fn worker_answer(delivery: RemoteDelivery) -> DirectAnswer {
    match delivery {
        RemoteDelivery::Accepted => DirectAnswer::Taken,
        RemoteDelivery::Queued => DirectAnswer::Queued,
        RemoteDelivery::Refused | RemoteDelivery::Unsupported | RemoteDelivery::Failed => {
            DirectAnswer::Refused
        }
    }
}

/// Direct messages being handed to this node's standalone workers at once,
/// each in its own task for up to the worker call's timeout.
pub(super) static WORKER_FORWARDS: quil_engine::spawn_gate::SpawnGate =
    quil_engine::spawn_gate::SpawnGate::new("shard-cw-forward", 256);

/// A place in `places` for handing one direct message to a standalone
/// worker, or, with every place taken, none and its sender answered
/// "refused": the sender then serves its member by the topic, which the
/// worker hears itself.
pub(super) fn forward_place(
    places: &'static quil_engine::spawn_gate::SpawnGate,
    ack: &mut Option<DirectAck>,
) -> Option<tokio::sync::SemaphorePermit<'static>> {
    let place = places.try_enter();
    if place.is_none() {
        if let Some(ack) = ack.take() {
            ack.answer(DirectAnswer::Refused);
        }
    }
    place
}

/// Hand a shard CW message a committee member sent this node directly to
/// the standalone worker running its shard, and answer the sender
/// ([`worker_answer`]).
pub(super) async fn forward_to_worker<W: ShardWorkers + ?Sized>(
    workers: &W,
    filter: &[u8],
    channel: u64,
    data: Vec<u8>,
    from: Vec<u8>,
    ack: Option<DirectAck>,
) -> RemoteDelivery {
    let delivery = workers
        .deliver_shard_consensus(filter, channel, data, from)
        .await;
    if let Some(ack) = ack {
        ack.answer(worker_answer(delivery));
    }
    delivery
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// A direct message, and what its sender is answered.
    fn direct() -> (
        ReceivedMessage,
        tokio::sync::oneshot::Receiver<DirectAnswer>,
    ) {
        let (ack, answered) = DirectAck::new();
        let mut received = message(SHARD);
        received.direct = true;
        received.ack = Some(ack);
        (received, answered)
    }

    /// What a sender is answered: a dropped ack, as the network task reads
    /// it, is "refused".
    async fn answer_of(answered: tokio::sync::oneshot::Receiver<DirectAnswer>) -> DirectAnswer {
        answered.await.unwrap_or(DirectAnswer::Refused)
    }

    /// An in-process engine's sender is told "taken" only when the engine's
    /// queue took the message; a full queue answers "refused", so the
    /// sender sends its topic copy.
    #[tokio::test]
    async fn a_direct_sender_is_told_taken_only_when_the_engine_queue_takes_it() {
        let (engine, mut engine_queue) = mpsc::channel(1);
        let deliver = |message| engine.try_send(message).is_ok();
        for (state, taken, answer) in [
            ("take", true, DirectAnswer::Taken),
            ("full", false, DirectAnswer::Refused),
        ] {
            let (received, answered) = direct();
            assert_eq!(
                deliver_in_process(&received, deliver, 0, vec![5], b"vote".to_vec()),
                taken,
                "{state}"
            );
            assert_eq!(
                answer_of(answered).await,
                answer,
                "{state}: the sender is answered what the engine queue did"
            );
        }
        assert!(matches!(
            engine_queue.recv().await,
            Some(AppEngineMessage::CwIn { channel: 0, .. })
        ));
    }

    struct Answering(RemoteDelivery);

    #[async_trait::async_trait]
    impl ShardWorkers for Answering {
        async fn deliver_shard_consensus(
            &self,
            _: &[u8],
            _: u64,
            _: Vec<u8>,
            _: Vec<u8>,
        ) -> RemoteDelivery {
            self.0
        }
    }

    /// A standalone worker's sender is told "taken" only on the worker's
    /// own "taken"; an earlier worker's acceptance is "queued"; anything
    /// else is "refused".
    #[tokio::test]
    async fn a_direct_sender_is_answered_what_the_standalone_worker_did() {
        for (delivery, answer) in [
            (RemoteDelivery::Accepted, DirectAnswer::Taken),
            (RemoteDelivery::Queued, DirectAnswer::Queued),
            (RemoteDelivery::Refused, DirectAnswer::Refused),
            (RemoteDelivery::Unsupported, DirectAnswer::Refused),
            (RemoteDelivery::Failed, DirectAnswer::Refused),
        ] {
            let (received, answered) = direct();
            let delivered = forward_to_worker(
                &Answering(delivery),
                &[1; 32],
                0,
                b"vote".to_vec(),
                vec![5],
                received.ack,
            )
            .await;
            assert_eq!(delivered, delivery);
            assert_eq!(answer_of(answered).await, answer, "{delivery:?}");
        }
    }

    /// Hand-offs to a standalone worker are bounded: with every place
    /// taken, the next sender is answered "refused" at once and nothing is
    /// handed on; a place freed takes the next.
    #[tokio::test]
    async fn a_hand_off_to_a_worker_with_every_place_taken_is_refused() {
        static PLACES: quil_engine::spawn_gate::SpawnGate =
            quil_engine::spawn_gate::SpawnGate::new("test-shard-cw-forward", 1);
        let (first, mut first_answered) = direct();
        let mut first_ack = first.ack;
        let place = forward_place(&PLACES, &mut first_ack).expect("a free place");
        assert!(
            first_ack.is_some(),
            "the handed-on sender is answered by its worker"
        );
        assert!(first_answered.try_recv().is_err(), "not answered yet");

        let (second, second_answered) = direct();
        let mut second_ack = second.ack;
        assert!(
            forward_place(&PLACES, &mut second_ack).is_none(),
            "a hand-off with every place taken is refused"
        );
        assert!(second_ack.is_none());
        assert_eq!(second_answered.await, Ok(DirectAnswer::Refused));

        drop(place);
        let (third, _answered) = direct();
        let mut third_ack = third.ack;
        assert!(
            forward_place(&PLACES, &mut third_ack).is_some(),
            "a freed place is taken"
        );
    }

    fn message(bitmask: u8) -> ReceivedMessage {
        ReceivedMessage {
            bitmask: vec![bitmask],
            data: vec![bitmask],
            from: Vec::new(),
            via: Vec::new(),
            direct: false,
            ack: None,
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
