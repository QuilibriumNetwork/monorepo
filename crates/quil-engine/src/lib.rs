pub mod app_engine;
pub mod storage_history;
pub mod global_anchor;
pub mod app_handoff;
mod app_history_recovery;
pub mod app_glue;
pub mod archive_ingest;
pub mod app_shard_cache;
pub mod app_shard_metadata;
pub mod app_types;
pub mod multi_proof_cache;
pub mod committee;
pub mod consensus_metrics;
pub mod consensus_types;
/// Commonware-simplex consensus seams: real-state impls of the
/// quil-cw-consensus GlobalProposer/FrameSink/FrameFinalizer traits.
pub mod cw_app_seams;
pub mod cw_global_seams;
mod cw_host_supervisor;
pub mod consensus_wire;
pub mod coverage;
pub mod current_frame;
pub mod shard_rebalancer;
pub mod difficulty;
pub mod engine_state;
pub mod event_distributor;
pub mod fees;
pub mod fork_choice;
pub mod frame_chain_checker;
pub mod frame_materializer;
pub mod frame_maintenance;
pub mod frame_processor;
pub mod genesis;
pub mod global_finalization;
pub mod frame_replay;
pub mod frame_validator;
pub mod halt_state;
pub mod message_collector;
pub mod message_router;
pub mod leader_provider;
pub mod prover_op_tally;
pub mod historical_committee;
pub mod resolver_traffic;
pub mod metrics;
pub mod remote_worker;
pub mod rewards;
pub mod thread_worker;
pub mod time_reel;
pub mod prover_message_transport;
pub mod prover_pipeline;
pub mod provers;
pub mod shard_info;
pub mod worker_allocator;
pub mod worker_node;
pub mod worker;
pub mod prover_tree_syncer;

/// Test support mocks (TestProverRegistry, TestWorkerManager).
/// Exposed for integration tests in `tests/`; hidden from public
/// docs since these are not part of the production API.
#[doc(hidden)]
pub mod test_support;

pub use app_engine::AppConsensusEngine;
pub use app_shard_cache::AppShardCache;
pub use difficulty::AsertDifficultyAdjuster;
pub use rewards::OptRewardIssuance;
pub use fees::InMemoryDynamicFeeManager;
pub use time_reel::GlobalTimeReel;

/// Consensus bitmask constants matching the Go implementation.
pub mod bitmasks {
    /// Global consensus coordination.
    pub const GLOBAL_CONSENSUS: &[u8] = &[0x00];
    /// Global frame distribution.
    pub const GLOBAL_FRAME: &[u8] = &[0x00, 0x00];
    // Commonware-simplex consensus channels. Distinct bitmasks so
    // the node demuxes an inbound `:8340` message back to the right simplex
    // channel. Only used when the simplex committee is configured.
    /// simplex vote channel (id 0).
    pub const GLOBAL_CW_VOTE: &[u8] = &[0x00, 0x10];
    /// simplex certificate channel (id 1).
    pub const GLOBAL_CW_CERT: &[u8] = &[0x00, 0x11];
    /// simplex resolver channel (id 2).
    pub const GLOBAL_CW_RESOLVER: &[u8] = &[0x00, 0x12];
    /// Out-of-band block (frame-bytes) delivery channel (id 3). Not a simplex
    /// engine channel — the node routes it into the shared `BlockStore`.
    pub const GLOBAL_CW_BLOCK: &[u8] = &[0x00, 0x13];

    /// Map a CW channel id (0/1/2/3) to its `:8340` bitmask.
    pub const fn global_cw_channel_bitmask(channel: u64) -> &'static [u8] {
        match channel {
            0 => GLOBAL_CW_VOTE,
            1 => GLOBAL_CW_CERT,
            2 => GLOBAL_CW_RESOLVER,
            _ => GLOBAL_CW_BLOCK,
        }
    }

    /// Inverse: map a `:8340` bitmask back to a CW channel id, if it is one.
    pub fn global_cw_channel_of(bitmask: &[u8]) -> Option<u64> {
        match bitmask {
            b if b == GLOBAL_CW_VOTE => Some(0),
            b if b == GLOBAL_CW_CERT => Some(1),
            b if b == GLOBAL_CW_RESOLVER => Some(2),
            b if b == GLOBAL_CW_BLOCK => Some(3),
            _ => None,
        }
    }
    /// Prover work delegation.
    pub const GLOBAL_PROVER: &[u8] = &[0x00, 0x00, 0x00];
    /// Peer info exchange.
    pub const GLOBAL_PEER_INFO: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    /// Global alert channel (16 zero bytes).
    pub const GLOBAL_ALERT: &[u8] = &[0u8; 16];

    /// Compute the 32-byte `appFilter` from a shard address. Mirrors
    /// Go's `up2p.GetBloomFilter(address, 256, 3)` — a 256-bit
    /// bitmask with exactly 3 bits set, used as the per-shard
    /// pubsub topic identifier. The shard `address` is typically a
    /// 32-byte poseidon hash; only the first 32 bytes participate
    /// in the SHA3-256 the bloom function consumes.
    pub fn shard_app_filter(address: &[u8]) -> Vec<u8> {
        quil_hypergraph::addressing::get_bloom_filter(address, 256, 3)
    }

    /// Per-shard frame bitmask = the shard's `appFilter` (32 bytes
    /// with 3 bits set).
    pub fn shard_frame_bitmask(address: &[u8]) -> Vec<u8> {
        shard_app_filter(address)
    }

    /// Per-shard consensus bitmask = `0x00 || appFilter`.
    pub fn shard_consensus_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(1 + af.len());
        v.push(0u8);
        v.extend_from_slice(&af);
        v
    }

    /// Per-shard prover bitmask = `0x00 0x00 0x00 || appFilter`.
    pub fn shard_prover_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(3 + af.len());
        v.extend_from_slice(&[0u8, 0u8, 0u8]);
        v.extend_from_slice(&af);
        v
    }

    /// The APPLICATION a shard filter belongs to: its first 32 bytes. A
    /// whole-application shard's filter already IS that address, so this is
    /// the identity before any split.
    pub fn app_address_of(filter: &[u8]) -> &[u8] {
        if filter.len() >= 32 { &filter[..32] } else { filter }
    }

    /// Per-APPLICATION submission topic, on which wallets publish operations.
    ///
    /// A wallet knows the application, not which sub-shard covers its coins, so
    /// every sub-shard of a split application must listen on ONE topic: the
    /// bloom is taken over the 32-byte application address and NEVER over the
    /// shard's longer filter. `get_bloom_filter` hashes every byte it is given,
    /// so keying this topic on a child filter puts the shard on a topic no
    /// wallet can address — submissions then fail with
    /// `NoPeersSubscribedToTopic` the moment an application splits.
    pub fn app_prover_bitmask(filter: &[u8]) -> Vec<u8> {
        shard_prover_bitmask(app_address_of(filter))
    }

    /// Per-shard dispatch bitmask = `0x00 0x00 || appFilter`.
    pub fn shard_dispatch_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(2 + af.len());
        v.extend_from_slice(&[0u8, 0u8]);
        v.extend_from_slice(&af);
        v
    }

    /// Per-shard commonware-simplex bitmask = `0x01 || appFilter`. ONE
    /// gossip topic per shard for all CW consensus traffic; the CW channel id
    /// (0=vote,1=cert,2=resolver,3=block) is carried as the FIRST payload byte
    /// (see `shard_cw_split_payload`). The `0x01` discriminator distinguishes it
    /// from every legacy shard bitmask (which start with `0x00` or are the raw
    /// 32-byte `appFilter`), so it can't collide.
    pub fn shard_cw_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(1 + af.len());
        v.push(0x01u8);
        v.extend_from_slice(&af);
        v
    }

    /// Set in the first payload byte of a transmission that carries a nonce.
    const SHARD_CW_NONCE_FLAG: u8 = 0x80;

    /// First nonce byte of a transmission addressed to one committee member.
    /// Its top bit is never set in a broadcast nonce: ours clear it, and the
    /// time-based nonces of earlier releases (nanoseconds since 1970, XOR the
    /// process id shifted 32 bits) cannot set it before the year 2262.
    const SHARD_CW_ADDRESSED: u8 = 0xAD;

    /// Length of the addressee tag in an addressed transmission's nonce.
    pub const SHARD_CW_ADDRESSEE_LEN: usize = 4;

    /// The tag naming committee member `key` (its raw Falcon public key) as
    /// the one addressee of a transmission.
    pub fn shard_cw_addressee_tag(key: &[u8]) -> [u8; SHARD_CW_ADDRESSEE_LEN] {
        use sha2::Digest as _;
        let digest = sha2::Sha256::new()
            .chain_update(b"quilibrium shard cw addressee")
            .chain_update(key)
            .finalize();
        let mut tag = [0u8; SHARD_CW_ADDRESSEE_LEN];
        tag.copy_from_slice(&digest[..SHARD_CW_ADDRESSEE_LEN]);
        tag
    }

    /// A fresh nonce with its top bit clear (see [`SHARD_CW_ADDRESSED`]).
    fn shard_cw_nonce() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        // Distinct across restarts too: a replayed vote must not collide with
        // the copy its previous process published less than five minutes ago.
        let base = *BASE.get_or_init(|| {
            let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            time ^ (u64::from(std::process::id()) << 32)
        });
        base.wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed)) & !(1u64 << 63)
    }

    fn shard_cw_frame(channel: u64, nonce: [u8; 8], cw_bytes: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + cw_bytes.len());
        v.push(SHARD_CW_NONCE_FLAG | (channel as u8 & !SHARD_CW_NONCE_FLAG));
        v.extend_from_slice(&nonce);
        v.extend_from_slice(cw_bytes);
        v
    }

    /// Frame a CW message for gossip:
    /// `[0x80 | channel] || nonce (8 bytes) || cw_bytes`.
    ///
    /// The nonce makes every TRANSMISSION a distinct gossip message. The gossip
    /// message id is a hash of the content with a five-minute duplicate cache,
    /// and a duplicate publish is reported as success. Consensus rebroadcasts
    /// are byte-identical on purpose (Falcon signatures are randomized, so a
    /// re-sent vote reuses its cached signature, and a restart replays its
    /// journaled votes verbatim). Without the nonce every retry inside five
    /// minutes was dropped before leaving the node, so a member that subscribed
    /// a moment after the first broadcast never received that vote; in a small
    /// committee, where every vote is needed, the view then never certified.
    /// Receivers strip the nonce; the consensus layer sees identical votes and
    /// ignores the repeats.
    pub fn shard_cw_frame_payload(channel: u64, cw_bytes: &[u8]) -> Vec<u8> {
        shard_cw_frame(channel, shard_cw_nonce().to_be_bytes(), cw_bytes)
    }

    /// Frame a CW message for `recipients` (raw committee keys). A message for
    /// exactly one member names it in the nonce:
    /// `0xAD || addressee tag (4 bytes) || counter (3 bytes)`.
    ///
    /// Resolver requests and responses are each meant for one member, but a
    /// transmission the topic carries reaches every member. Commonware answers
    /// any request it receives, so one request drew an answer from every member
    /// holding the certificate, each answer went to every member, and members
    /// could match another member's answer to their own request by its request
    /// id (ids count from zero in every engine). Receivers drop a transmission
    /// that names another member before it reaches consensus. Earlier releases
    /// read the tag as an ordinary nonce and strip it.
    pub fn shard_cw_frame_for(channel: u64, cw_bytes: &[u8], recipients: &[Vec<u8>]) -> Vec<u8> {
        let [recipient] = recipients else {
            return shard_cw_frame_payload(channel, cw_bytes);
        };
        let tag = shard_cw_addressee_tag(recipient);
        let counter = shard_cw_nonce().to_be_bytes();
        let mut nonce = [0u8; 8];
        nonce[0] = SHARD_CW_ADDRESSED;
        nonce[1..5].copy_from_slice(&tag);
        nonce[5..].copy_from_slice(&counter[5..]);
        shard_cw_frame(channel, nonce, cw_bytes)
    }

    /// Inverse of [`shard_cw_frame_payload`]: `(channel, cw_bytes)`, or `None`
    /// if the payload is empty or truncated. The earlier un-nonced framing
    /// (`[channel] || cw_bytes`) is still accepted.
    pub fn shard_cw_split_payload(payload: &[u8]) -> Option<(u64, &[u8])> {
        let (first, rest) = payload.split_first()?;
        if first & SHARD_CW_NONCE_FLAG == 0 {
            return Some((u64::from(*first), rest));
        }
        Some((u64::from(first & !SHARD_CW_NONCE_FLAG), rest.get(8..)?))
    }

    /// The member a transmission is addressed to (see [`shard_cw_frame_for`]),
    /// or `None` for a broadcast, an earlier release's framing, or a payload
    /// too short to carry a nonce.
    pub fn shard_cw_addressee(payload: &[u8]) -> Option<[u8; SHARD_CW_ADDRESSEE_LEN]> {
        let (first, rest) = payload.split_first()?;
        if first & SHARD_CW_NONCE_FLAG == 0 || rest.len() < 8 || rest[0] != SHARD_CW_ADDRESSED {
            return None;
        }
        rest[1..1 + SHARD_CW_ADDRESSEE_LEN].try_into().ok()
    }

    /// Split an inbound CW transmission for the member tagged `local`, or
    /// `None` when it is malformed or addressed to another member (counted).
    /// Resolver traffic that is kept is counted by shard.
    pub fn shard_cw_admit<'a>(
        filter: &[u8],
        payload: &'a [u8],
        local: &[u8; SHARD_CW_ADDRESSEE_LEN],
    ) -> Option<(u64, &'a [u8])> {
        use crate::resolver_traffic::{Addressed, ResolverTraffic};
        let (channel, cw_bytes) = shard_cw_split_payload(payload)?;
        let addressee = shard_cw_addressee(payload);
        let resolver = channel == crate::cw_app_seams::CW_APP_RESOLVER_CHANNEL;
        match addressee {
            Some(tag) if &tag != local => {
                if resolver {
                    ResolverTraffic::process().note_received(filter, cw_bytes, Addressed::Elsewhere);
                }
                None
            }
            addressee => {
                if resolver {
                    let addressed = if addressee.is_some() { Addressed::Here } else { Addressed::Untagged };
                    ResolverTraffic::process().note_received(filter, cw_bytes, addressed);
                }
                Some((channel, cw_bytes))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The framing decoder over arbitrary bytes: `None` or a split, never
        /// a panic, and every framed payload comes back intact.
        #[test]
        fn shard_cw_framing_survives_arbitrary_bytes() {
            let mut x = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = || { x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x.wrapping_mul(0x2545_F491_4F6C_DD1D) };
            for i in 0..20_000u64 {
                let len = (next() % 64) as usize;
                let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if i % 3 == 0 {
                    let channel = next() % 4;
                    let framed = shard_cw_frame_payload(channel, &bytes);
                    assert_eq!(shard_cw_split_payload(&framed), Some((channel, bytes.as_slice())));
                    bytes = framed;
                    if !bytes.is_empty() {
                        let at = (next() as usize) % bytes.len();
                        bytes[at] ^= 1 << (next() % 8);
                    }
                }
                let _ = std::panic::catch_unwind(|| shard_cw_split_payload(&bytes))
                    .unwrap_or_else(|_| panic!("framing panicked on {}", hex::encode(&bytes)));
            }
        }

        /// Byte-identical consensus rebroadcasts must leave the node as
        /// distinct gossip messages, and decode to the same vote.
        #[test]
        fn every_shard_cw_transmission_is_a_distinct_gossip_message() {
            let vote = b"identical signed vote bytes";
            let first = shard_cw_frame_payload(1, vote);
            let second = shard_cw_frame_payload(1, vote);
            assert_ne!(first, second, "a content-hashed message id would drop the retry");
            for payload in [&first, &second] {
                assert_eq!(shard_cw_split_payload(payload), Some((1, vote.as_slice())));
            }
            // The earlier framing still decodes; truncated nonces do not.
            assert_eq!(shard_cw_split_payload(&[3, 9, 9]), Some((3, [9u8, 9].as_slice())));
            assert_eq!(shard_cw_split_payload(&first[..5]), None);
            assert_eq!(shard_cw_split_payload(&[]), None);
        }

        /// A message for one member names it; the member keeps it, the others
        /// drop it, and an earlier release (which only knows the nonce)
        /// still reads the channel and the message.
        #[test]
        fn an_addressed_transmission_reaches_only_its_member() {
            let (alice, bob) = (vec![1u8; 897], vec![2u8; 897]);
            let (alice_tag, bob_tag) = (shard_cw_addressee_tag(&alice), shard_cw_addressee_tag(&bob));
            assert_ne!(alice_tag, bob_tag);
            let filter = [7u8; 32];
            let request = b"resolver request bytes";
            let framed = shard_cw_frame_for(2, request, std::slice::from_ref(&alice));
            assert_eq!(shard_cw_addressee(&framed), Some(alice_tag));
            assert_eq!(shard_cw_split_payload(&framed), Some((2, request.as_slice())));
            assert_eq!(shard_cw_admit(&filter, &framed, &alice_tag), Some((2, request.as_slice())));
            assert_eq!(shard_cw_admit(&filter, &framed, &bob_tag), None);
            assert_ne!(framed, shard_cw_frame_for(2, request, std::slice::from_ref(&alice)), "still distinct per transmission");

            // Broadcasts, several recipients and earlier framings name nobody.
            for framed in [
                shard_cw_frame_payload(2, request),
                shard_cw_frame_for(2, request, &[]),
                shard_cw_frame_for(2, request, &[alice.clone(), bob.clone()]),
            ] {
                assert_eq!(shard_cw_addressee(&framed), None);
                assert_eq!(framed[1] & 0x80, 0, "a broadcast nonce never looks addressed");
                assert_eq!(shard_cw_admit(&filter, &framed, &bob_tag), Some((2, request.as_slice())));
            }
            let mut legacy = vec![0x82u8];
            legacy.extend_from_slice(&(1_780_000_000_000_000_000u64 ^ (4_194_303u64 << 32)).to_be_bytes());
            legacy.extend_from_slice(request);
            assert_eq!(shard_cw_addressee(&legacy), None);
            assert_eq!(shard_cw_admit(&filter, &legacy, &bob_tag), Some((2, request.as_slice())));
            assert_eq!(shard_cw_addressee(&[0x82, 0xAD, 1, 2]), None, "truncated");
        }

        /// A wallet addresses an application, not a shard. Every sub-shard of a
        /// split application must therefore subscribe to the SAME submission
        /// topic the wallet publishes on — the one keyed by the 32-byte app
        /// address. Keying it on the shard's own filter silently strands every
        /// submission the moment the application splits.
        #[test]
        fn every_sub_shard_listens_on_the_application_submission_topic() {
            let app = [0x11u8; 32];
            // `app ‖ bit_len(u16 BE) ‖ packed bits`, as a split child's filter.
            let child = |bits: u16, packed: u8| {
                let mut f = app.to_vec();
                f.extend_from_slice(&bits.to_be_bytes());
                f.push(packed);
                f
            };
            let wallet_publishes_to = app_prover_bitmask(&app);
            for filter in [app.to_vec(), child(1, 0x00), child(1, 0x80), child(3, 0x20)] {
                assert_eq!(
                    app_prover_bitmask(&filter), wallet_publishes_to,
                    "shard {} must share the application's submission topic", hex::encode(&filter),
                );
            }
            // Why the helper exists: the bloom hashes every byte it is given, so
            // keying on the longer child filter lands on a different topic.
            assert_ne!(shard_prover_bitmask(&child(1, 0x00)), wallet_publishes_to);
            // Per-shard traffic stays per-shard.
            assert_ne!(shard_frame_bitmask(&child(1, 0x00)), shard_frame_bitmask(&app));
        }
    }
}
pub(crate) mod submission_attempts;
pub(crate) mod stage_clock;
pub mod shard_drain;
