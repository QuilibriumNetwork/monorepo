//! The vote channel delivers a member's own broadcasts back to it
//! (`build_vote_channel`), and that copy can reach the batcher before the
//! voter's. A real `simplex::Engine` must take its own vote in that order, and
//! count it once.
//!
//! The batcher's unit tests live in `commonware-consensus`, which the workspace
//! excludes, so CI runs only this one. It uses ed25519: an equal echo needs a
//! deterministic signature, and Falcon's is randomized.

use std::sync::Arc;
use std::time::Duration;

use commonware_codec::Encode as _;
use commonware_consensus::simplex::scheme::ed25519;
use commonware_consensus::simplex::types::{Nullify, Vote};
use commonware_consensus::simplex::{
    elector::RoundRobin, mocks, Config, Engine, Floor, ForwardingPolicy,
};
use commonware_consensus::types::{Epoch, Round, View, ViewDelta};
use commonware_cryptography::certificate::mocks::Fixture;
use commonware_cryptography::ed25519::PublicKey;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
use commonware_utils::{ordered::Set, test_rng, NZUsize, NZU16};
use quil_cw_consensus::p2p_bridge::{
    build_channel, build_vote_channel, inbound_message, NoopBlocker, Outbound,
};
use tokio::sync::mpsc;

/// Takes what the engine sent since the last call; returns how many messages
/// were certificates and whether one was exactly `vote`.
fn drain(out: &mut mpsc::UnboundedReceiver<Outbound<PublicKey>>, vote: &[u8]) -> (usize, bool) {
    let (mut certificates, mut seen) = (0, false);
    while let Ok(message) = out.try_recv() {
        certificates += usize::from(message.channel == 1);
        seen |= message.channel == 0 && message.bytes == vote;
    }
    (certificates, seen)
}

#[test]
fn own_nullify_echoed_before_constructed_counts_once() {
    let epoch = Epoch::new(333);
    let executor = deterministic::Runner::timed(Duration::from_secs(120));
    executor.start(|context| async move {
        // Four members: a quorum of three.
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"echoed-own-vote", 4);
        let me = participants[0].clone();
        let peers: Arc<[PublicKey]> =
            Arc::from(participants.iter().skip(1).cloned().collect::<Vec<_>>());
        let members: Set<PublicKey> = participants.clone().try_into().unwrap();

        let (out_tx, mut out) = mpsc::unbounded_channel::<Outbound<PublicKey>>();
        let votes = build_vote_channel(0, peers.clone(), out_tx.clone(), Some(me.clone()));
        let certificates = build_channel(1, peers.clone(), out_tx.clone());
        let resolver = build_channel(2, peers, out_tx);
        let inbound = votes.inbound_tx.clone();

        // The voter times out on this view with no proposal, so it signs a
        // nullify; each member's copy is the same bytes it would broadcast.
        let round = Round::new(epoch, View::new(1));
        let nullify = |i: usize| -> Vec<u8> {
            Vote::<ed25519::Scheme, Sha256Digest>::Nullify(
                Nullify::sign::<Sha256Digest>(&schemes[i], round).unwrap(),
            )
            .encode()
            .to_vec()
        };
        let own = nullify(0);

        // Our vote arrives looped back before the voter has made its copy.
        inbound
            .send(inbound_message(me.clone(), own.clone()))
            .unwrap();

        let elector = RoundRobin::<Sha256>::default();
        let relay = Arc::new(mocks::relay::Relay::new());
        let reporter = mocks::reporter::Reporter::new(
            context.child("reporter"),
            mocks::reporter::Config {
                participants: members,
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            },
        );
        let (actor, application) = mocks::application::Application::new(
            context.child("application"),
            mocks::application::Config {
                hasher: Sha256::default(),
                relay,
                me,
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            },
        );
        actor.start();
        let engine = Engine::new(
            context.child("engine"),
            Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: NoopBlocker::<PublicKey>::default(),
                automaton: application.clone(),
                relay: application,
                reporter,
                strategy: Sequential,
                partition: "echoed-own-vote".to_string(),
                mailbox_size: NZUsize!(1024),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(30),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                forwarding: ForwardingPolicy::Disabled,
            },
        );
        let _engine = engine.start(
            (votes.sender, votes.receiver),
            (certificates.sender, certificates.receiver),
            (resolver.sender, resolver.receiver),
        );

        // The voter broadcasts after handing its copy to the batcher, whose
        // panic on a duplicate would end the run here. The deterministic
        // runner's time limit fails the test if the vote never comes.
        loop {
            context.sleep(Duration::from_millis(100)).await;
            if drain(&mut out, &own).1 {
                break;
            }
        }
        context.sleep(Duration::from_secs(1)).await;

        // One other member's vote makes two distinct votes: no certificate.
        inbound
            .send(inbound_message(participants[1].clone(), nullify(1)))
            .unwrap();
        context.sleep(Duration::from_secs(1)).await;
        assert_eq!(
            drain(&mut out, &own).0,
            0,
            "our nullify counts once toward the quorum"
        );

        // A second other member's vote completes the quorum.
        inbound
            .send(inbound_message(participants[2].clone(), nullify(2)))
            .unwrap();
        loop {
            context.sleep(Duration::from_millis(100)).await;
            if drain(&mut out, &own).0 > 0 {
                break;
            }
        }
    });
}
