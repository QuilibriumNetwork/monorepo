//! Node-side wiring for the commonware-simplex global consensus. It runs only
//! when the consensus committee is non-empty, and bridges the simplex engine's
//! channels to the existing `:8340` transport:
//!
//! - outbound: [`Cw8340Transport`] (`GlobalConsensusTransport`) tags each
//! simplex message with its channel and fans it out via the existing
//! `DirectGlobalConsensusPublisher`;
//! - inbound: [`CwInboundRouter`] demuxes a `:8340` message (by its channel
//! bitmask) into the engine's matching inbound channel, resolving the sender
//! to its committee Falcon key.
//!
//! [`start_cw_global_consensus`] is called at the GLOBAL activation site, and
//! the receive loop hands inbound consensus messages to
//! [`CwInboundRouter::route`].
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
    /// Feed a committee member's frame bytes into the engine's `BlockStore`
    /// (channel 3).
    ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    resolve_peer: PeerResolver,
    /// Our own committee Falcon key — the attributed sender for locally-injected
    /// certificates (see [`Self::feed_finalization_cert`]).
    inject_from: FalconPublicKey,
    /// When each member was last heard, for the GLOBAL stall watch.
    contact: Arc<quil_engine::global_stall::GlobalContact>,
    /// Messages dropped because their sender is not a committee member.
    unresolved: std::sync::Mutex<UnresolvedDrops>,
}

/// Minimum interval between two summaries of unresolved-sender drops.
const UNRESOLVED_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Drops of messages from senders outside the committee since the last
/// summary, per channel.
#[derive(Default)]
struct UnresolvedDrops {
    counts: [u64; 4],
    latest_peer: Vec<u8>,
    last_summary: Option<std::time::Instant>,
}

impl UnresolvedDrops {
    /// Count a drop on `channel` from `from`; the summary line to log, at
    /// most one per [`UNRESOLVED_LOG_INTERVAL`].
    fn record(&mut self, channel: u64, from: &[u8], now: std::time::Instant) -> Option<String> {
        if let Some(count) = self.counts.get_mut(channel as usize) {
            *count += 1;
        }
        self.latest_peer = from.to_vec();
        let since_previous = self
            .last_summary
            .map(|last| now.saturating_duration_since(last));
        if since_previous.is_some_and(|elapsed| elapsed < UNRESOLVED_LOG_INTERVAL) {
            return None;
        }
        self.last_summary = Some(now);
        let [vote, certificate, resolver, block] = std::mem::take(&mut self.counts);
        let window = match since_previous {
            Some(elapsed) => format!("the last {}s", elapsed.as_secs()),
            None => "startup".to_string(),
        };
        Some(format!(
            "since {window}: vote={vote} certificate={certificate} resolver={resolver} \
             block={block}, latest peer {}",
            bs58::encode(&self.latest_peer).into_string()
        ))
    }
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

    /// Whether `from` (an inbound mTLS peer identity) is a committee member.
    pub fn is_member(&self, from: &[u8]) -> bool {
        (self.resolve_peer)(from).is_some()
    }

    /// Feed a received `:8340` message (identified by its channel bitmask) into
    /// the engine, if the bitmask is a CW channel. Every channel needs the
    /// sender's committee key: only members send votes, certificates,
    /// resolver messages and blocks, and a block from anyone else would only
    /// take room in the `BlockStore`.
    pub fn route(&self, bitmask: &[u8], from: &[u8], data: Vec<u8>) -> bool {
        let Some(channel) = quil_engine::bitmasks::global_cw_channel_of(bitmask) else {
            return false;
        };
        let Some(from_pk) = (self.resolve_peer)(from) else {
            // It WAS a cw message, just undeliverable.
            let summary = self
                .unresolved
                .lock()
                .ok()
                .and_then(|mut drops| drops.record(channel, from, std::time::Instant::now()));
            if let Some(summary) = summary {
                tracing::info!(
                    "cw inbound: dropped GLOBAL consensus messages from senders outside the \
                     committee {summary}; a committee member whose peer id does not resolve \
                     here cannot vote or deliver blocks to this node; report this line if the \
                     peer is a member"
                );
            }
            return true;
        };
        if channel == 3 {
            (self.ingest_block)(data);
            return true;
        }
        self.contact.heard(&from_pk);
        let _ = self.inbound[channel as usize].send(inbound_message(from_pk, data));
        true
    }
}

/// Dependencies needed to start the simplex-backed global consensus. Mirrors the
/// subset of `ConsensusActivationParams` the simplex path needs.
pub struct CwGlobalDeps {
    pub selected_parent_execution:
        Option<Arc<quil_engine::frame_materializer::GlobalParentExecutor>>,
    /// Atomic finalization shared with the materializer worker. `None` keeps
    /// the legacy order (canonical clock write, then materialization).
    pub finalization_pipeline:
        Option<Arc<quil_engine::global_finalization::GlobalFinalizationPipeline>>,
    pub committee_hex: Vec<String>,
    /// The members' peer IDs, parallel to `committee_hex`; logs name a
    /// member by its tail.
    pub committee_peer_ids: Vec<String>,
    /// This node's `q-consensus-key` bytes.
    pub my_signing_key: Vec<u8>,
    pub my_public_key: Vec<u8>,
    pub leader_provider: Arc<
        dyn quil_consensus::leader_provider::LeaderProvider<
            quil_engine::consensus_types::GlobalState,
        >,
    >,
    pub verifier: Arc<quil_engine::frame_validator::GlobalFrameVerifier>,
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// The node's existing global-materializer channel (`(frame, frame_number)`)
    /// — reused so finalized frames run the same commit/evict/rebalance worker.
    pub mat_job_tx:
        tokio::sync::mpsc::UnboundedSender<(quil_types::proto::global::GlobalFrame, u64)>,
    /// Bump head atomics / CurrentFrame on finalize.
    pub head_hook: quil_engine::cw_global_seams::HeadHook,
    pub filter: Vec<u8>,
    pub epoch: u64,
    pub genesis_digest: quil_cw_consensus::adapters::Digest,
    pub genesis_frame_number: u64,
    /// simplex leader timeout (seconds); 0 = engine default (30s).
    pub leader_timeout_secs: u64,
    pub transport: Arc<dyn GlobalConsensusTransport>,
    /// GOSSIP publisher for finalized global frames (proposer-only) so regular
    /// nodes get frames over gossip instead of RPC-polling. `None` = disabled.
    pub global_frame_publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// This node's 32-byte prover address — the proposer gate for the publisher
    /// (a finalized global frame's `prover` field is the proposer's address).
    pub local_prover_address: Vec<u8>,
    pub resolve_peer: PeerResolver,
    /// Persistent directory for the simplex journal. MUST be stable under the
    /// node's data dir so consensus resumes across restarts (the default is a
    /// random temp dir → every restart replays from the migration head).
    pub storage_directory: std::path::PathBuf,
    /// Wired to the frame materializer's `flag_prover_root_mismatch`; the vote
    /// seam invokes it on a prover-tree FORK so the archive prover-tree reconcile
    /// fires during the resulting halt (nothing materializes then to set the flag
    /// the normal way). `None` on non-archive nodes.
    pub on_prover_fork: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
}

/// Build the committee, start the simplex engine, and return the inbound router.
/// Returns `None` if the committee is empty (simplex disabled) or this node's
/// key is not in the committee / keys are malformed.
///
/// Must be called from within the node's tokio runtime (the activation spawns
/// the outbound drain there).
pub fn start_cw_global_consensus(deps: CwGlobalDeps) -> Option<CwInboundRouter> {
    if deps.committee_hex.is_empty() {
        return None; // simplex not enabled
    }
    let Some(selected_execution) = deps.selected_parent_execution else {
        tracing::error!("GLOBAL consensus requires a selected-parent execution owner");
        return None;
    };
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

    let member_labels = if deps.committee_peer_ids.len() == deps.committee_hex.len() {
        deps.committee_peer_ids
            .iter()
            .map(|id| quil_engine::global_stall::tail(id))
            .collect()
    } else {
        Vec::new()
    };
    let GlobalConsensusCwHandle {
        inbound,
        ingest_block,
        contact,
    } = activate_global_consensus_cw(
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
        deps.global_frame_publisher,
        deps.local_prover_address,
        deps.on_prover_fork,
        selected_execution,
        deps.finalization_pipeline,
        member_labels,
    )
    .inspect_err(|error| tracing::error!(%error, "GLOBAL consensus recovery refused activation"))
    .ok()?;

    tracing::info!("commonware-simplex global consensus started");
    // Our own committee key — the committee build above already validated
    // `my_public_key`, so this decode succeeds.
    let inject_from = FalconPublicKey::from_bytes(&deps.my_public_key)?;
    Some(CwInboundRouter {
        inbound,
        ingest_block,
        resolve_peer: deps.resolve_peer,
        inject_from,
        contact,
        unresolved: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(ingested: Arc<std::sync::Mutex<Vec<Vec<u8>>>>) -> CwInboundRouter {
        let member = FalconPublicKey::from_bytes(&[7u8; 897]).unwrap();
        let resolved = member.clone();
        let inbound = [(); 3].map(|_| tokio::sync::mpsc::unbounded_channel().0);
        CwInboundRouter {
            inbound,
            ingest_block: Arc::new(move |bytes: Vec<u8>| ingested.lock().unwrap().push(bytes)),
            resolve_peer: Arc::new(move |from: &[u8]| {
                (from == b"member").then(|| resolved.clone())
            }),
            inject_from: member.clone(),
            contact: Arc::new(quil_engine::global_stall::GlobalContact::new([member])),
            unresolved: Default::default(),
        }
    }

    /// A block from a peer outside the committee is dropped before it reaches
    /// the block store; a member's block is stored as before.
    #[test]
    fn only_committee_members_deliver_blocks() {
        let ingested = Arc::new(std::sync::Mutex::new(Vec::new()));
        let router = router(ingested.clone());
        let block = quil_engine::bitmasks::GLOBAL_CW_BLOCK;
        assert!(router.route(block, b"stranger", b"junk".to_vec()));
        assert!(ingested.lock().unwrap().is_empty());
        assert!(router.route(block, b"member", b"frame".to_vec()));
        assert_eq!(*ingested.lock().unwrap(), vec![b"frame".to_vec()]);
        assert!(!router.route(&[0x00, 0x00, 0x00], b"member", Vec::new()));
    }

    /// Drops from outside the committee are counted per channel and
    /// summarised at most once a minute.
    #[test]
    fn unresolved_drops_are_summarised() {
        let mut drops = UnresolvedDrops::default();
        let start = std::time::Instant::now();
        let first = drops.record(3, b"stranger", start).unwrap();
        assert!(first.contains("block=1"), "{first}");
        assert_eq!(drops.record(0, b"stranger", start), None);
        assert_eq!(drops.record(3, b"stranger", start), None);
        let next = drops
            .record(1, b"stranger", start + UNRESOLVED_LOG_INTERVAL)
            .unwrap();
        assert!(
            next.contains("vote=1 certificate=1 resolver=0 block=1"),
            "{next}"
        );
    }

    #[test]
    fn members_are_the_resolved_identities() {
        let router = router(Default::default());
        assert!(router.is_member(b"member"));
        assert!(!router.is_member(b"stranger"));
    }
}
