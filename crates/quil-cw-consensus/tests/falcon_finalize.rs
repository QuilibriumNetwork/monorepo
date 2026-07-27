//! End-to-end: a real commonware `simplex::Engine` finalizing on the
//! commonware runtime, driven by our **Falcon** `SimplexFalconScheme` (equal
//! votes). This is the P2a runtime-marriage de-risk: it proves the Engine +
//! Falcon scheme + adapters finalize a chain, using commonware's mock
//! Automaton/Relay/Reporter over the simulated network.
//!
//! Mirrors the commonware `all_online` harness (consensus/simplex/mod.rs) with
//! ed25519 swapped for our Falcon scheme and the participant/network identity
//! set to `FalconPublicKey`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use commonware_consensus::simplex::{
    elector::RoundRobin, mocks, Config, Engine, Floor, ForwardingPolicy,
};
use commonware_consensus::types::{Epoch, View, ViewDelta};
use commonware_consensus::Monitor;
use commonware_cryptography::{Sha256, Signer as _};
use commonware_parallel::Sequential;
use commonware_p2p::simulated::{Config as NetConfig, Link, Network, Oracle, Receiver, Sender};
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{deterministic, Quota, Runner, Spawner as _, Supervisor as _};
use commonware_utils::{ordered::Set, NZUsize, NZU16};

use commonware_math::algebra::Random;
use quil_cw_consensus::falcon_base::{FalconPrivateKey, FalconPublicKey};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;

type Chan = (
    Sender<FalconPublicKey, deterministic::Context>,
    Receiver<FalconPublicKey>,
);

const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

async fn register_one(oracle: &mut Oracle<FalconPublicKey, deterministic::Context>, v: FalconPublicKey) -> (Chan, Chan, Chan) {
    let control = oracle.control(v);
    let vote = control.register(0, TEST_QUOTA).await.unwrap();
    let cert = control.register(1, TEST_QUOTA).await.unwrap();
    let resolver = control.register(2, TEST_QUOTA).await.unwrap();
    (vote, cert, resolver)
}

#[test]
fn falcon_simplex_finalizes() {
    // 4 participants → N3f1 quorum = floor(2*4/3)+1 = 3 (equal votes).
    let n: usize = 4;
    let namespace = b"global".to_vec();

    // Generate Falcon keys up front (keygen uses OS entropy; see falcon_base).
    let sks: Vec<FalconPrivateKey> =
        (0..n).map(|_| FalconPrivateKey::random(commonware_utils::test_rng())).collect();
    let participants: Vec<FalconPublicKey> = sks.iter().map(|s| s.public_key()).collect();
    let part_set: Set<FalconPublicKey> = participants.clone().try_into().unwrap();
    let schemes: Vec<SimplexFalconScheme> = sks
        .into_iter()
        .map(|sk| SimplexFalconScheme::signer(&namespace, part_set.clone(), sk).unwrap())
        .collect();

    // Finalize this many views before declaring success.
    let required = View::new(15);
    let activity_timeout = ViewDelta::new(10);
    let skip_timeout = ViewDelta::new(5);
    let epoch = Epoch::new(333);

    let executor = deterministic::Runner::timed(Duration::from_secs(300));
    executor.start(|context| async move {
        // Simulated network over Falcon identities.
        let (network, mut oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            participants.clone(),
        )
        .await;
        network.start();

        // Register the 3 channels per validator.
        let mut regs: HashMap<FalconPublicKey, (Chan, Chan, Chan)> = HashMap::new();
        for v in participants.iter() {
            regs.insert(v.clone(), register_one(&mut oracle, v.clone()).await);
        }

        // Fully connect.
        let link = Link { latency: Duration::from_millis(10), jitter: Duration::from_millis(1), success_rate: 1.0 };
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v1 != v2 {
                    oracle.add_link(v1.clone(), v2.clone(), link.clone()).await.unwrap();
                }
            }
        }

        let elector = RoundRobin::<Sha256>::default();
        let relay = Arc::new(mocks::relay::Relay::new());

        let mut reporters = Vec::new();
        let mut handlers = Vec::new();
        for (idx, v) in participants.iter().enumerate() {
            let vctx = context.child("validator").with_attribute("pk", v);

            let reporter_cfg = mocks::reporter::Config {
                participants: part_set.clone(),
                scheme: schemes[idx].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(vctx.child("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: v.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) = mocks::application::Application::new(vctx.child("app"), app_cfg);
            actor.start();

            let blocker = oracle.control(v.clone());
            let cfg = Config {
                scheme: schemes[idx].clone(),
                elector: elector.clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                strategy: Sequential,
                partition: format!("falcon-{idx}"),
                mailbox_size: NZUsize!(1024),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&vctx, NZU16!(1024), NZUsize!(10)),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(vctx.child("engine"), cfg);

            let (vote, cert, resolver) = regs.remove(v).expect("registered");
            handlers.push(engine.start(vote, cert, resolver));
        }

        // Wait for every reporter to observe the target view finalize.
        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let (mut latest, mut monitor) = reporter.subscribe().await;
            finalizers.push(context.child("finalizer").spawn(move |_| async move {
                while latest < required {
                    latest = monitor.recv().await.expect("monitor event");
                }
            }));
        }
        futures::future::join_all(finalizers).await;
    });
}
