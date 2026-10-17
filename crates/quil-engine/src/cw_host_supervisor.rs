//! Keep GLOBAL's transport addresses stable across a failed consensus worker.
//! A replacement may open the journal only after the old host thread joins.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quil_cw_consensus::engine_host::GlobalHostHandle;
use quil_cw_consensus::falcon_base::FalconPublicKey;
use quil_cw_consensus::p2p_bridge::{Message, Outbound};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::Instant;

use crate::cw_global_seams::GlobalConsensusTransport;

type Inbound = Message<FalconPublicKey>;
type Inputs = [UnboundedSender<Inbound>; 3];

struct Policy {
    poll: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
    healthy_after: Duration,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(250),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            healthy_after: Duration::from_secs(60),
        }
    }
}

struct LiveHost {
    inbound: Inputs,
    outbound: mpsc::UnboundedReceiver<Outbound<FalconPublicKey>>,
    outbound_open: bool,
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    started: Instant,
}
impl LiveHost {
    fn spawn(factory: &mut impl FnMut(Arc<AtomicBool>) -> GlobalHostHandle) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let GlobalHostHandle {
            inbound,
            outbound,
            thread,
        } = factory(shutdown.clone());
        Self {
            inbound,
            outbound,
            outbound_open: true,
            thread: Some(thread),
            shutdown,
            started: Instant::now(),
        }
    }

    fn finished(&self) -> bool {
        self.thread.as_ref().unwrap().is_finished()
    }

    fn join(mut self) -> bool {
        // Call only after is_finished: no blocking join on the node runtime.
        self.thread.take().unwrap().join().is_err()
    }
}
impl Drop for LiveHost {
    fn drop(&mut self) {
        // Also stop the host if the supervisor task is aborted or its node
        // runtime is dropped. No replacement is started along this path.
        self.shutdown.store(true, Ordering::Release);
    }
}

async fn next_outbound(host: &mut Option<LiveHost>) -> Option<Outbound<FalconPublicKey>> {
    match host {
        Some(host) if host.outbound_open => host.outbound.recv().await,
        _ => std::future::pending().await,
    }
}

fn route(host: &Option<LiveHost>, open: &mut [bool; 3], channel: usize, message: Option<Inbound>) {
    if let Some(message) = message {
        if let Some(host) = host {
            let _ = host.inbound[channel].send(message);
        }
        // During backoff discard input instead of accumulating another retry
        // queue. Simplex retransmits votes/certificates when peers recover.
    } else {
        open[channel] = false;
    }
}

pub(crate) fn supervise_global_host(
    factory: impl FnMut(Arc<AtomicBool>) -> GlobalHostHandle + Send + 'static,
    transport: Arc<dyn GlobalConsensusTransport>,
) -> Inputs {
    start(factory, transport, Policy::default()).0
}

fn start(
    mut factory: impl FnMut(Arc<AtomicBool>) -> GlobalHostHandle + Send + 'static,
    transport: Arc<dyn GlobalConsensusTransport>,
    policy: Policy,
) -> (Inputs, tokio::task::JoinHandle<()>) {
    let [(tx0, mut rx0), (tx1, mut rx1), (tx2, mut rx2)] =
        std::array::from_fn(|_| mpsc::unbounded_channel());
    // The node may inject its local finalization certificate immediately on
    // activation. Have a host queue ready before exposing the stable routes.
    let initial_host = LiveHost::spawn(&mut factory);
    let task = tokio::spawn(async move {
        let mut host = Some(initial_host);
        let mut open = [true; 3];
        let mut tick = tokio::time::interval(policy.poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut backoff = policy.initial_backoff;
        let mut retry_at = Instant::now();
        let mut starts = 1u64;
        loop {
            tokio::select! {
                message = rx0.recv(), if open[0] => route(&host, &mut open, 0, message),
                message = rx1.recv(), if open[1] => route(&host, &mut open, 1, message),
                message = rx2.recv(), if open[2] => route(&host, &mut open, 2, message),
                outbound = next_outbound(&mut host) => {
                    if let Some(message) = outbound {
                        transport.deliver(message.channel, message.recipients, message.bytes);
                    } else if let Some(host) = host.as_mut() {
                        host.outbound_open = false;
                    }
                }
                _ = tick.tick() => {
                    let stopping = open.iter().all(|open| !open);
                    if stopping {
                        if let Some(host) = &host {
                            host.shutdown.store(true, Ordering::Release);
                        }
                    }
                    if host.as_ref().is_some_and(LiveHost::finished) {
                        let finished = host.take().unwrap();
                        let healthy = finished.started.elapsed() >= policy.healthy_after;
                        let panicked = finished.join();
                        if !stopping {
                            if healthy { backoff = policy.initial_backoff; }
                            tracing::error!(panicked, retry_ms = backoff.as_millis() as u64,
                                "GLOBAL consensus host exited; joined before scheduling recovery");
                            retry_at = Instant::now() + backoff;
                            backoff = backoff.saturating_mul(2).min(policy.max_backoff);
                        }
                    }
                    if stopping && host.is_none() { break; }
                    if !stopping && host.is_none() && Instant::now() >= retry_at {
                        host = Some(LiveHost::spawn(&mut factory));
                        starts += 1;
                        if starts > 1 {
                            tracing::warn!(starts,
                                "restarted GLOBAL consensus host on its retained journal");
                        }
                    }
                }
            }
        }
    });
    ([tx0, tx1, tx2], task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_cw_consensus::adapters::{
        digest_from_identity, BlockStore, Digest, FrameFinalizer, FrameSink, GlobalProposer,
        Recipients,
    };
    use quil_cw_consensus::engine_host::{spawn_global_host, GlobalEngineParams};
    use quil_cw_consensus::p2p_bridge::inbound_message;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    struct Transport(mpsc::UnboundedSender<(u64, Vec<u8>)>);
    impl GlobalConsensusTransport for Transport {
        fn deliver(&self, channel: u64, _: Vec<FalconPublicKey>, bytes: Vec<u8>) {
            let _ = self.0.send((channel, bytes));
        }
    }

    fn policy() -> Policy {
        Policy {
            poll: Duration::from_millis(5),
            initial_backoff: Duration::from_millis(30),
            max_backoff: Duration::from_millis(120),
            healthy_after: Duration::from_secs(10),
        }
    }

    struct Worker {
        active: Arc<AtomicUsize>,
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn factory(
        active: Arc<AtomicUsize>,
        starts: Arc<Mutex<Vec<Instant>>>,
        fail_count: usize,
        flags: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    ) -> impl FnMut(Arc<AtomicBool>) -> GlobalHostHandle + Send {
        move |shutdown| {
            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0, "hosts overlapped");
            let mut times = starts.lock().unwrap();
            times.push(Instant::now());
            let generation = times.len();
            drop(times);
            flags.lock().unwrap().push(shutdown.clone());
            let [(tx0, rx0), (tx1, rx1), (tx2, rx2)] =
                std::array::from_fn(|_| mpsc::unbounded_channel::<Inbound>());
            let (out_tx, out_rx) = mpsc::unbounded_channel();
            let active = active.clone();
            let thread = std::thread::spawn(move || {
                let _worker = Worker { active };
                if generation <= fail_count {
                    drop(out_tx);
                    // Closing outbound does not mean the thread released the
                    // journal. Simulate detached I/O still draining afterward.
                    std::thread::sleep(Duration::from_millis(40));
                    if generation == 1 {
                        panic!("injected host failure");
                    }
                    return;
                }
                let mut inputs = [rx0, rx1, rx2];
                while !shutdown.load(Ordering::Acquire) {
                    for (channel, input) in inputs.iter_mut().enumerate() {
                        while input.try_recv().is_ok() {
                            let _ = out_tx.send(Outbound {
                                channel: channel as u64,
                                recipients: Vec::new(),
                                bytes: vec![generation as u8],
                                priority: false,
                            });
                        }
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            GlobalHostHandle {
                inbound: [tx0, tx1, tx2],
                outbound: out_rx,
                thread,
            }
        }
    }

    async fn until(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn restarts_after_join_with_backoff_and_keeps_all_three_routes() {
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let flags = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut received) = mpsc::unbounded_channel();
        let (inputs, task) = start(
            factory(active.clone(), starts.clone(), 3, flags),
            Arc::new(Transport(tx)),
            policy(),
        );
        until(|| starts.lock().unwrap().len() == 4).await;
        {
            let times = starts.lock().unwrap();
            for (pair, delay) in times.windows(2).zip([30, 60, 120]) {
                assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(40 + delay));
            }
        }
        let peer = FalconPublicKey::from_bytes(&[0; 897]).unwrap();
        for input in &inputs {
            input.send(inbound_message(peer.clone(), vec![1])).unwrap();
        }
        let mut channels = Vec::new();
        for _ in 0..3 {
            let (channel, bytes) = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, vec![4]);
            channels.push(channel);
        }
        channels.sort();
        assert_eq!(channels, vec![0, 1, 2]);
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn aborting_supervisor_stops_its_host_without_replacement() {
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let flags = Arc::new(Mutex::new(Vec::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_inputs, task) = start(
            factory(active.clone(), starts.clone(), 0, flags.clone()),
            Arc::new(Transport(tx)),
            policy(),
        );
        until(|| starts.lock().unwrap().len() == 1).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        until(|| active.load(Ordering::SeqCst) == 0).await;
        assert!(flags.lock().unwrap()[0].load(Ordering::Acquire));
        assert_eq!(starts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn initial_certificate_route_is_ready_before_returning_to_the_node() {
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (inputs, task) = start(
            factory(active, starts.clone(), 0, Arc::new(Mutex::new(Vec::new()))),
            Arc::new(Transport(tx)),
            policy(),
        );
        // No yield: startup must already own the host receiving this one-shot
        // local certificate, before the node's scheduler runs the supervisor.
        assert_eq!(starts.lock().unwrap().len(), 1);
        inputs[1]
            .send(inbound_message(
                FalconPublicKey::from_bytes(&[0; 897]).unwrap(),
                vec![1],
            ))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            (1, vec![1])
        );
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn closing_all_inputs_during_backoff_does_not_restart() {
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut policy = policy();
        policy.initial_backoff = Duration::from_secs(1);
        let (inputs, task) = start(
            factory(
                active.clone(),
                starts.clone(),
                10,
                Arc::new(Mutex::new(Vec::new())),
            ),
            Arc::new(Transport(tx)),
            policy,
        );
        until(|| starts.lock().unwrap().len() == 1 && active.load(Ordering::SeqCst) == 0).await;
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(starts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn real_host_recovers_after_reporter_panics_without_resetting_its_journal() {
        use quil_types::crypto::Signer as _;
        use sha2::{Digest as _, Sha256};

        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = Directory(std::env::temp_dir().join(format!(
            "quil-supervised-host-{}-{suffix}",
            std::process::id()
        )));
        std::fs::create_dir(&directory.0).unwrap();

        struct Proposer;
        impl GlobalProposer for Proposer {
            fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
                let mut hash = Sha256::new();
                hash.update(view.to_be_bytes());
                hash.update(parent.as_ref());
                let digest = digest_from_identity(hash.finalize().into());
                Some((digest, digest.as_ref().to_vec()))
            }
            fn verify(
                &self,
                view: u64,
                parent: Digest,
                digest: Digest,
                bytes: Option<Vec<u8>>,
            ) -> bool {
                let (expected, body) = self.propose(view, parent).unwrap();
                digest == expected && bytes.as_deref() == Some(body.as_slice())
            }
        }
        struct Sink;
        impl FrameSink for Sink {
            fn broadcast(&self, _: Digest, _: Vec<u8>, _: Recipients<FalconPublicKey>) {}
        }
        struct Finalizer {
            failed: AtomicBool,
            reported: mpsc::UnboundedSender<u64>,
        }
        impl FrameFinalizer for Finalizer {
            fn on_notarized(&self, _: u64, _: Digest, _: Option<Vec<u8>>) {}
            fn on_finalized(
                &self,
                view: u64,
                _: Digest,
                _: Option<Vec<u8>>,
                _: Option<Vec<u8>>,
                _: bool,
            ) {
                if !self.failed.swap(true, Ordering::SeqCst) {
                    panic!("injected reporter failure");
                }
                let _ = self.reported.send(view);
            }
        }
        let key = quil_crypto::FalconSigner::generate();
        let committee = quil_cw_consensus::committee::build_global_committee(
            &[key.public_key().to_vec()],
            key.private_key(),
            key.public_key(),
            b"supervised-test",
        )
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let finalizer = Arc::new(Finalizer {
            failed: AtomicBool::new(false),
            reported: tx,
        });
        let starts = Arc::new(AtomicUsize::new(0));
        let (tx, _outbound) = mpsc::unbounded_channel();
        let (inputs, task) = start(
            {
                let starts = starts.clone();
                let path = directory.0.clone();
                let store = BlockStore::new();
                move |shutdown| {
                    if starts.fetch_add(1, Ordering::SeqCst) > 0 {
                        assert!(
                            std::fs::read_dir(path.join("journal"))
                                .unwrap()
                                .next()
                                .is_some(),
                            "replacement must reopen the retained journal"
                        );
                    }
                    spawn_global_host(
                        committee.scheme.clone(),
                        committee.peers.clone(),
                        Arc::new(Proposer),
                        Arc::new(Sink),
                        finalizer.clone(),
                        store.clone(),
                        GlobalEngineParams::new("journal", 17, digest_from_identity([0; 32])),
                        Some(path.clone()),
                        Some(shutdown),
                    )
                }
            },
            Arc::new(Transport(tx)),
            policy(),
        );
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            while rx.recv().await.unwrap() < 5 {}
        })
        .await;
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        result.expect("replacement must continue finalizing after the injected failure");
        assert_eq!(starts.load(Ordering::SeqCst), 2);
    }
}
