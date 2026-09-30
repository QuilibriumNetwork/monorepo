//! Restart the production host/adapters from synced Simplex journals and an
//! older quorum certificate. The deterministic runtime drops unsynced storage
//! at recovery. Application bodies remain in a shared store across the crash;
//! this tests consensus recovery, not application-state crash atomicity.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
use commonware_p2p::Recipients;
use commonware_runtime::{deterministic, Quota, Runner, Storage as _, Supervisor as _};
use commonware_utils::channel::{fallible::FallibleExt as _, mpsc};
use commonware_utils::{ordered::Set, NZUsize};

use quil_cw_consensus::adapters::{BlockStore, FrameFinalizer, FrameSink, GlobalProposer};
use quil_cw_consensus::app_cert::{verify_finalization_details, AppFinalization};
use quil_cw_consensus::engine_host::{build_global_engine, GlobalEngineParams};
use quil_cw_consensus::falcon_base::{FalconPrivateKey, FalconPublicKey};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;

const NAMESPACE: &[u8] = b"appshard/persisted-restart-test";
const EPOCH: u64 = 17;

struct Committee {
    members: Vec<FalconPublicKey>,
    schemes: Vec<SimplexFalconScheme>,
}

impl Committee {
    fn new() -> Self {
        let keys: Vec<_> = (0..4)
            .map(|_| FalconPrivateKey::random(commonware_utils::test_rng()))
            .collect();
        let members: Vec<_> = keys.iter().map(|key| key.public_key()).collect();
        let set: Set<_> = members.clone().try_into().unwrap();
        let schemes = keys
            .into_iter()
            .map(|key| SimplexFalconScheme::signer(NAMESPACE, set.clone(), key).unwrap())
            .collect();
        Self { members, schemes }
    }
}

struct Proposer {
    floor_view: u64,
}

impl GlobalProposer for Proposer {
    fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
        assert!(
            view > self.floor_view,
            "a certified view must never be reproposed"
        );
        let mut hash = Sha256::default();
        hash.update(&view.to_be_bytes());
        hash.update(parent.as_ref());
        let digest = hash.finalize();
        Some((digest, digest.as_ref().to_vec()))
    }

    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        let mut hash = Sha256::default();
        hash.update(&view.to_be_bytes());
        hash.update(parent.as_ref());
        hash.finalize() == digest && bytes.as_deref() == Some(digest.as_ref())
    }
}

struct Sink;
impl FrameSink for Sink {
    fn broadcast(&self, _: Digest, _: Vec<u8>, _: Recipients<FalconPublicKey>) {}
}

struct Finalizer {
    member: usize,
    tx: mpsc::UnboundedSender<(usize, u64, Digest, Vec<u8>)>,
}

impl FrameFinalizer for Finalizer {
    fn on_notarized(&self, _: u64, _: Digest, _: Option<Vec<u8>>) {}

    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        _: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        _: bool,
    ) {
        let _ = self.tx.send_lossy((
            self.member,
            view,
            digest,
            cert.expect("finalization certificate"),
        ));
    }
}

struct Observed {
    tip: u64,
    certificates: BTreeMap<u64, AppFinalization>,
}

async fn run_phase(
    context: deterministic::Context,
    committee: Arc<Committee>,
    store: BlockStore,
    floor: Option<AppFinalization>,
    target: u64,
    mut certificates: BTreeMap<u64, AppFinalization>,
) -> Observed {
    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        NetConfig {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        committee.members.clone(),
    )
    .await;
    network.start();

    let quota = Quota::per_second(std::num::NonZeroU32::MAX);
    let mut registrations = HashMap::new();
    for member in &committee.members {
        let control = oracle.control(member.clone());
        let vote = control.register(0, quota).await.unwrap();
        let cert = control.register(1, quota).await.unwrap();
        let resolver = control.register(2, quota).await.unwrap();
        registrations.insert(member.clone(), (vote, cert, resolver));
    }
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    for from in &committee.members {
        for to in &committee.members {
            if from != to {
                oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    let floor_view = floor
        .as_ref()
        .map(|f| f.proposal.round.view().get())
        .unwrap_or(0);
    let proposer = Arc::new(Proposer { floor_view });
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handlers = Vec::new();
    for (index, member) in committee.members.iter().enumerate() {
        let partition = format!("adapter-restart-{index}");
        if floor.is_some() {
            assert!(
                !context.scan(&partition).await.unwrap().is_empty(),
                "every member must recover its existing journal"
            );
        }
        // Deliberately disagree on the fallback genesis after restart. The
        // shared certificate supplies the authoritative floor at its real view.
        let genesis = Digest([if floor.is_some() { index as u8 + 1 } else { 0 }; 32]);
        let mut params = GlobalEngineParams::new(partition, EPOCH, genesis);
        if let Some(floor) = &floor {
            params = params.with_finalized_floor(floor.clone()).unwrap();
        }
        let engine = build_global_engine(
            context.child("validator").with_attribute("pk", member),
            committee.schemes[index].clone(),
            oracle.control(member.clone()),
            proposer.clone(),
            Arc::new(Sink),
            Arc::new(Finalizer {
                member: index,
                tx: tx.clone(),
            }),
            store.clone(),
            params,
        );
        let (vote, cert, resolver) = registrations.remove(member).unwrap();
        handlers.push(engine.start(vote, cert, resolver));
    }

    let keys: Vec<Vec<u8>> = committee
        .members
        .iter()
        .map(|m| m.as_ref().to_vec())
        .collect();
    let mut tips = vec![0; committee.members.len()];
    while tips.iter().any(|tip| *tip < target) {
        let (member, view, digest, bytes) = rx.recv().await.expect("finalization report");
        let verified = verify_finalization_details(&bytes, &keys, NAMESPACE, digest.0).unwrap();
        let cert = verified.finalization;
        assert_eq!(cert.proposal.round.epoch().get(), EPOCH);
        assert_eq!(cert.proposal.round.view().get(), view);
        if let Some(previous) = certificates.get(&view) {
            assert_eq!(
                cert.proposal, previous.proposal,
                "recovery must not finalize a conflicting proposal at an old view"
            );
        }
        certificates.insert(view, cert);
        tips[member] = tips[member].max(view);
    }
    assert!(oracle.blocked().await.unwrap().is_empty());
    Observed {
        tip: *tips.iter().min().unwrap(),
        certificates,
    }
}

#[test]
fn falcon_host_recovers_existing_journals_above_an_older_certified_floor() {
    let committee = Arc::new(Committee::new());
    let store = BlockStore::new();
    let (initial, checkpoint) = deterministic::Runner::timed(Duration::from_secs(300))
        .start_and_recover({
            let committee = committee.clone();
            let store = store.clone();
            move |context| run_phase(context, committee, store, None, 12, BTreeMap::new())
        });
    let floor = initial
        .certificates
        .values()
        .filter(|cert| cert.proposal.round.view().get() < initial.tip)
        .nth(4)
        .expect("older certified floor")
        .clone();
    assert!(floor.proposal.round.view().get() < initial.tip);
    let target = initial.tip + 10;
    let recovered = deterministic::Runner::from(checkpoint).start(move |context| {
        run_phase(
            context,
            committee,
            store,
            Some(floor),
            target,
            initial.certificates,
        )
    });
    assert!(
        recovered.tip >= target,
        "every validator must finalize beyond the pre-crash tip"
    );
}
