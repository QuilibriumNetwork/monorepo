//! Exercise the production host's bounded journal runtime, including joining
//! it before reopening a journal. The shared bodies are a consensus fixture;
//! this does not test crash atomicity of application execution.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::Recipients;
use commonware_utils::ordered::Set;
use quil_cw_consensus::adapters::{BlockStore, FrameFinalizer, FrameSink, GlobalProposer};
use quil_cw_consensus::app_cert::{verify_finalization_details, AppFinalization};
use quil_cw_consensus::engine_host::{spawn_global_host, GlobalEngineParams, GlobalHostHandle};
use quil_cw_consensus::falcon_base::{FalconPrivateKey, FalconPublicKey};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;
use quil_cw_consensus::p2p_bridge::inbound_message;
use tokio::sync::mpsc;

const NAMESPACE: &[u8] = b"bounded-journal-host";

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        // Tests run in parallel and the clock can be coarser than a
        // nanosecond (microseconds on macOS), so two directories created at
        // once got the same name and one test failed creating it.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("quil-host-{}-{suffix}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Proposer;
impl GlobalProposer for Proposer {
    fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
        let mut hash = Sha256::default();
        hash.update(&view.to_be_bytes());
        hash.update(parent.as_ref());
        let digest = hash.finalize();
        Some((digest, digest.as_ref().to_vec()))
    }

    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        let (expected, body) = self.propose(view, parent).unwrap();
        digest == expected && bytes.as_deref() == Some(body.as_slice())
    }
}

struct Sink;
impl FrameSink for Sink {
    fn broadcast(&self, _: Digest, _: Vec<u8>, _: Recipients<FalconPublicKey>) {}
}

struct Finalizer {
    member: usize,
    tx: mpsc::UnboundedSender<(usize, Digest, Vec<u8>)>,
}
impl FrameFinalizer for Finalizer {
    fn on_notarized(&self, _: u64, _: Digest, _: Option<Vec<u8>>) {}
    fn on_finalized(
        &self,
        _: u64,
        digest: Digest,
        _: Option<Vec<u8>>,
        certificate: Option<Vec<u8>>,
        _: bool,
    ) {
        let _ = self.tx.send((self.member, digest, certificate.unwrap()));
    }
}

struct Committee {
    peers: Arc<[FalconPublicKey]>,
    schemes: Vec<SimplexFalconScheme>,
}
impl Committee {
    fn new(n: usize) -> Self {
        let keys: Vec<_> = (0..n)
            .map(|_| FalconPrivateKey::random(commonware_utils::test_rng()))
            .collect();
        let peers: Vec<_> = keys.iter().map(|key| key.public_key()).collect();
        let set: Set<_> = peers.clone().try_into().unwrap();
        let schemes = keys
            .into_iter()
            .map(|key| SimplexFalconScheme::signer(NAMESPACE, set.clone(), key).unwrap())
            .collect();
        Self {
            peers: peers.into(),
            schemes,
        }
    }
}

// A failed lifecycle must fail the test instead of hanging on JoinHandle::join.
async fn join_hosts(threads: Vec<std::thread::JoinHandle<()>>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while threads.iter().any(|thread| !thread.is_finished()) {
        assert!(
            Instant::now() < deadline,
            "consensus host did not release its runtime"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for thread in threads {
        thread
            .join()
            .expect("host must drop its runtime on the owning thread");
    }
}

async fn phase(
    dir: &Directory,
    committee: &Committee,
    store: &BlockStore,
    certificates: &mut BTreeMap<u64, AppFinalization>,
    target: u64,
) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut inbound = HashMap::new();
    let mut outbound = Vec::new();
    let mut threads = Vec::new();
    let floor = certificates.values().next().cloned();
    for (member, peer) in committee.peers.iter().enumerate() {
        let directory = dir.0.join(member.to_string());
        if floor.is_some() {
            assert!(std::fs::read_dir(directory.join("journal"))
                .unwrap()
                .next()
                .is_some());
        }
        // Votes in flight when every member stops are lost, so a reopened
        // committee may have to time out the view it resumes in. At the
        // standard 30 s leader timeout two such views exceed the phase budget;
        // what is tested here is the reopened journal, not that timeout.
        let mut params = GlobalEngineParams::new("journal", 17, Digest([0; 32])).with_leader_timeout_secs(2);
        if let Some(floor) = &floor {
            params = params.with_finalized_floor(floor.clone()).unwrap();
        }
        let GlobalHostHandle {
            inbound: inputs,
            outbound: outputs,
            thread,
        } = spawn_global_host(
            committee.schemes[member].clone(),
            committee.peers.clone(),
            Arc::new(Proposer),
            Arc::new(Sink),
            Arc::new(Finalizer {
                member,
                tx: tx.clone(),
            }),
            store.clone(),
            params,
            Some(directory),
            Some(shutdown.clone()),
        );
        inbound.insert(peer.clone(), inputs);
        outbound.push((peer.clone(), outputs));
        threads.push(thread);
    }
    let inbound = Arc::new(inbound);
    let routers: Vec<_> = outbound
        .into_iter()
        .map(|(sender, mut rx)| {
            let inbound = inbound.clone();
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    for recipient in message.recipients {
                        if recipient != sender {
                            if let Some(inputs) = inbound.get(&recipient) {
                                let _ = inputs[message.channel as usize]
                                    .send(inbound_message(sender.clone(), message.bytes.clone()));
                            }
                        }
                    }
                }
            })
        })
        .collect();
    let keys: Vec<Vec<u8>> = committee
        .peers
        .iter()
        .map(|key| key.as_ref().to_vec())
        .collect();
    let mut tips = vec![0; committee.peers.len()];
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        while tips.iter().any(|tip| *tip < target) {
            let (member, digest, bytes) = rx.recv().await.expect("finalization report");
            let cert = verify_finalization_details(&bytes, &keys, NAMESPACE, digest.0)
                .unwrap()
                .finalization;
            let view = cert.proposal.round.view().get();
            if let Some(previous) = certificates.get(&view) {
                assert_eq!(
                    previous.proposal, cert.proposal,
                    "restart changed finalized history"
                );
            }
            certificates.insert(view, cert);
            tips[member] = tips[member].max(view);
        }
    })
    .await;
    shutdown.store(true, Ordering::Release);
    join_hosts(threads).await;
    for router in routers {
        router.await.unwrap();
    }
    result.expect("all committee members must finalize");
}

#[test]
fn production_hosts_stop_join_and_reopen_the_same_journals() {
    let directory = Directory::new();
    let committee = Committee::new(4);
    let store = BlockStore::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut certificates = BTreeMap::new();
        phase(&directory, &committee, &store, &mut certificates, 5).await;
        let next_target = certificates.keys().next_back().unwrap() + 5;
        phase(
            &directory,
            &committee,
            &store,
            &mut certificates,
            next_target,
        )
        .await;
    });
}

#[test]
fn production_host_joins_after_transport_closes_without_shutdown_flag() {
    let directory = Directory::new();
    let committee = Committee::new(1);
    let (tx, _rx) = mpsc::unbounded_channel();
    let host = spawn_global_host(
        committee.schemes[0].clone(),
        committee.peers,
        Arc::new(Proposer),
        Arc::new(Sink),
        Arc::new(Finalizer { member: 0, tx }),
        BlockStore::new(),
        GlobalEngineParams::new("journal", 17, Digest([0; 32])),
        Some(directory.0.clone()),
        None,
    );
    drop(host.inbound);
    drop(host.outbound);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(join_hosts(vec![host.thread]));
}

#[test]
fn production_host_drains_after_voter_panics_on_corrupt_journal() {
    let directory = Directory::new();
    let partition = directory.0.join("journal");
    std::fs::create_dir(&partition).unwrap();
    let path = partition.join("0000000000000001");
    // Longer than the record-less torn-header case: corruption must remain
    // on disk for diagnosis, and the journal must refuse to vote over it.
    let corrupt = [0u8; 64];
    std::fs::write(&path, corrupt).unwrap();
    let committee = Committee::new(1);
    let (tx, _rx) = mpsc::unbounded_channel();
    let host = spawn_global_host(
        committee.schemes[0].clone(),
        committee.peers,
        Arc::new(Proposer),
        Arc::new(Sink),
        Arc::new(Finalizer { member: 0, tx }),
        BlockStore::new(),
        GlobalEngineParams::new("journal", 17, Digest([0; 32])),
        Some(directory.0.clone()),
        None,
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(join_hosts(vec![host.thread]));
    assert!(host.inbound.iter().all(|sender| sender.is_closed()));
    assert_eq!(std::fs::read(path).unwrap(), corrupt);
}
