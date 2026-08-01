//! Node-side wiring for the commonware-simplex global consensus (P2c),
//! **additive + gated**: it runs only when `config.engine.consensus_committee`
//! is non-empty and does NOT replace the existing quil-consensus path (removing
//! that + this gate is the localnet-validated cutover step). It bridges the
//! simplex engine's channels to the existing `:8340` transport:
//!
//! - outbound: [`Cw8340Transport`] (`GlobalConsensusTransport`) tags each
//! simplex message with its channel and fans it out via the existing
//! `DirectGlobalConsensusPublisher`;
//! - inbound: [`CwInboundRouter`] demuxes a `:8340` message (by its channel
//! bitmask) into the engine's matching inbound channel, resolving the sender
//! to its committee Falcon key.
//!
//! These types compile and are ready to invoke; the two remaining wires — the
//! `start_cw_global_consensus` call at the activation site and a `route(...)`
//! arm in the receive loop — flip the path on and are applied in the
//! localnet-validated cutover (they modify the live receive loop, so they are
//! not enabled here).
#![allow(dead_code)]

use std::sync::Arc;

use quil_cw_consensus::committee::build_global_committee;
use quil_cw_consensus::falcon_base::FalconPublicKey;
use quil_cw_consensus::p2p_bridge::{inbound_message, Message};
use quil_engine::cw_global_seams::{
    activate_global_consensus_cw, GlobalConsensusCwHandle, GlobalConsensusTransport,
};

use crate::direct_global_consensus_publisher::DirectGlobalConsensusPublisher;

/// The consensus domain (namespace) — matches the existing vote domain.
pub const CW_NAMESPACE: &[u8] = b"global";

/// Resolves an inbound message's sender bytes (mTLS peer identity) to its
/// committee Falcon public key, so simplex can attribute the message.
pub type PeerResolver = Arc<dyn Fn(&[u8]) -> Option<FalconPublicKey> + Send + Sync>;

/// `GlobalConsensusTransport` over the existing `:8340` fan-out.
pub struct Cw8340Transport {
    publisher: Arc<DirectGlobalConsensusPublisher>,
}

impl Cw8340Transport {
    pub fn new(publisher: Arc<DirectGlobalConsensusPublisher>) -> Self {
        Self { publisher }
    }
}

impl GlobalConsensusTransport for Cw8340Transport {
    fn deliver(&self, channel: u64, _recipients: Vec<FalconPublicKey>, bytes: Vec<u8>) {
        // The existing publisher fans out to the whole committee; recipients is
        // a subset of that, so a full send is a safe superset.
        self.publisher.submit_cw_channel(channel, bytes);
    }
}

/// Routes demuxed inbound `:8340` messages into the engine's channels.
pub struct CwInboundRouter {
    inbound: [tokio::sync::mpsc::UnboundedSender<Message<FalconPublicKey>>; 3],
    /// Feed a peer-delivered frame's bytes into the engine's `BlockStore`
    /// (channel 3); no sender attribution needed (frames are self-validating).
    ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    resolve_peer: PeerResolver,
    /// Our own committee Falcon key — the attributed sender for locally-injected
    /// certificates (see [`Self::feed_finalization_cert`]).
    inject_from: FalconPublicKey,
}

impl CwInboundRouter {
    /// Feed a FINALIZATION certificate the node already holds (unwrapped from a
    /// committed frame header's `CWCT` field) straight into the engine's
    /// certificate channel, driving RESOLVER-BASED CATCH-UP from LOCAL state.
    ///
    /// The simplex voter only advances a behind node when it *sees a higher-view
    /// certificate* (`resolver.updated(Certificate::Finalization)`); a node that
    /// resumed/reset below the live view receives only current-view VOTES on the
    /// wire and never gets that trigger, so it freezes. But its clock store DOES
    /// hold finalized frames (via the poller) whose headers carry the simplex
    /// finalization cert. Injecting the highest one sets the resolver's fetch
    /// target, so it backfills the gap and rejoins — no coordinated restart.
    ///
    /// Wire format: the certificate channel decodes `Certificate<S,D>` =
    /// `[tag:u8] ++ variant`; a Finalization is tag `2`, and the raw CWCT bytes
    /// are exactly `encode_finalization(f)` = the Finalization body. So we just
    /// prepend the tag and inject as if received from our own committee key (a
    /// finalization is a self-verifying aggregate — sender attribution is moot).
    pub fn feed_finalization_cert(&self, raw_cwct_cert: &[u8]) {
        let mut msg = Vec::with_capacity(1 + raw_cwct_cert.len());
        msg.push(2u8); // Certificate::Finalization discriminant
        msg.extend_from_slice(raw_cwct_cert);
        let _ = self.inbound[1].send(inbound_message(self.inject_from.clone(), msg));
    }

    /// Feed a received `:8340` message (identified by its channel bitmask) into
    /// the engine, if the bitmask is a CW channel. Channels 0/1/2 (vote/cert/
    /// resolver) need the sender's committee key; channel 3 (block) does not.
    pub fn route(&self, bitmask: &[u8], from: &[u8], data: Vec<u8>) -> bool {
        let Some(channel) = quil_engine::bitmasks::global_cw_channel_of(bitmask) else {
            return false;
        };
        if channel == 3 {
            (self.ingest_block)(data);
            return true;
        }
        let Some(from_pk) = (self.resolve_peer)(from) else {
            tracing::debug!("cw inbound: unresolved sender, dropping");
            return true; // it WAS a cw message, just undeliverable
        };
        let _ = self.inbound[channel as usize].send(inbound_message(from_pk, data));
        true
    }
}

/// Dependencies needed to start the simplex-backed global consensus. Mirrors the
/// subset of `ConsensusActivationParams` the simplex path needs.
pub struct CwGlobalDeps {
    pub committee_hex: Vec<String>,
    /// This node's `q-consensus-key` bytes.
    pub my_signing_key: Vec<u8>,
    pub my_public_key: Vec<u8>,
    pub leader_provider: Arc<dyn quil_consensus::leader_provider::LeaderProvider<quil_engine::consensus_types::GlobalState>>,
    pub verifier: Arc<quil_engine::frame_validator::GlobalFrameVerifier>,
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// The node's existing global-materializer channel (`(frame, frame_number)`)
    /// — reused so finalized frames run the same commit/evict/rebalance worker.
    pub mat_job_tx: tokio::sync::mpsc::UnboundedSender<(quil_types::proto::global::GlobalFrame, u64)>,
    /// Bump head atomics / CurrentFrame on finalize.
    pub head_hook: quil_engine::cw_global_seams::HeadHook,
    pub filter: Vec<u8>,
    pub epoch: u64,
    pub genesis_digest: quil_cw_consensus::adapters::Digest,
    pub genesis_frame_number: u64,
    /// simplex leader timeout (seconds); 0 = engine default (30s).
    pub leader_timeout_secs: u64,
    pub transport: Arc<dyn GlobalConsensusTransport>,
    pub resolve_peer: PeerResolver,
    /// Persistent directory for the simplex journal. MUST be stable under the
    /// node's data dir so consensus resumes across restarts (the default is a
    /// random temp dir → every restart replays from the migration head).
    pub storage_directory: std::path::PathBuf,
}

/// Build the committee, start the simplex engine, and return the inbound router.
/// Returns `None` if the committee is empty (simplex disabled) or this node's
/// key is not in the committee / keys are malformed.
///
/// Must be called from within the node's tokio runtime (the activation spawns
/// the outbound drain there).
pub fn start_cw_global_consensus(deps: CwGlobalDeps) -> Option<CwInboundRouter> {
    if deps.committee_hex.is_empty() {
        return None; // simplex cutover not enabled
    }
    let committee_pubkeys: Vec<Vec<u8>> = deps
        .committee_hex
        .iter()
        .map(|h| hex::decode(h).ok())
        .collect::<Option<_>>()?;
    let committee = build_global_committee(
        &committee_pubkeys,
        &deps.my_signing_key,
        &deps.my_public_key,
        CW_NAMESPACE,
    )?;

    let GlobalConsensusCwHandle { inbound, ingest_block } = activate_global_consensus_cw(
        committee.scheme,
        committee.peers,
        deps.leader_provider,
        deps.verifier,
        deps.clock_store,
        deps.mat_job_tx,
        deps.head_hook,
        deps.filter,
        deps.epoch,
        deps.genesis_digest,
        deps.genesis_frame_number,
        deps.leader_timeout_secs,
        deps.transport,
        deps.storage_directory,
    );

    tracing::info!("commonware-simplex global consensus started");
    // Our own committee key — the committee build above already validated
    // `my_public_key`, so this decode succeeds.
    let inject_from = FalconPublicKey::from_bytes(&deps.my_public_key)?;
    Some(CwInboundRouter {
        inbound,
        ingest_block,
        resolve_peer: deps.resolve_peer,
        inject_from,
    })
}
