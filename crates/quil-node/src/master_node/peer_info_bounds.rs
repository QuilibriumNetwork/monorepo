//! Bounds of the in-memory PeerInfo cache (`peer_info_file::PeerInfoCache`).
//!
//! Every node publishes a signed PeerInfo, and a Falcon key costs nothing,
//! so the records of new peer IDs arrive without limit. The cache keeps two
//! tiers. Preferred peers are the ones this node uses: genesis archives and
//! registered provers, whose keys are what committees, shard member
//! endpoints, wallet reads and direct delivery look up. Every other peer
//! shares a smaller quota and cannot evict a preferred one. Within a tier a
//! full quota evicts the record with the oldest signed timestamp, and every
//! record expires [`MAX_AGE_MS`] after its timestamp (peers republish every
//! 30 minutes on mainnet).
//!
//! A mainnet node held about 105 records and its prover registry 204
//! provers (2026-10-26), so the quotas leave a wide margin for honest
//! operation.
use std::collections::{BTreeSet, HashMap, HashSet};

use super::peer_info_file::MAX_AGE_MS;

/// Most records of preferred peers.
pub(super) const MAX_PREFERRED: usize = 16_384;
/// Most memory the records of preferred peers take, by [`footprint`].
pub(super) const MAX_PREFERRED_BYTES: usize = 192 << 20;
/// Most records of other peers: as many as the file restores.
pub(super) const MAX_OTHER: usize = super::peer_info_file::MAX_RECORDS;
/// Most memory the records of other peers take, by [`footprint`].
pub(super) const MAX_OTHER_BYTES: usize = 32 << 20;
/// A record taking more memory than this is not cached. A published one
/// takes under 1 KB per allocated worker.
pub(super) const MAX_RECORD_FOOTPRINT: usize = 4 << 20;

type Cache = HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>;

/// What [`PeerInfoBounds::admit`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// Cached; it is the peer's first record held.
    Inserted,
    /// Cached in place of the peer's older record.
    Replaced,
    /// The cache holds a record of the peer at least as new.
    Superseded,
    /// Larger than [`MAX_RECORD_FOOTPRINT`], or older than every record of
    /// its full tier.
    Refused,
}

impl Admission {
    pub(super) fn admitted(self) -> bool {
        matches!(self, Admission::Inserted | Admission::Replaced)
    }
}

struct Held {
    preferred: bool,
    timestamp: i64,
    footprint: usize,
}

/// The index that bounds a [`Cache`]. Every insertion and removal of the
/// cache goes through it once it has adopted the cache.
#[derive(Default)]
pub(super) struct PeerInfoBounds {
    held: HashMap<Vec<u8>, Held>,
    /// Per tier (`[other, preferred]`): (signed timestamp, peer ID).
    by_age: [BTreeSet<(i64, Vec<u8>)>; 2],
    bytes: [usize; 2],
    /// Records evicted to make room, since start.
    pub(super) evicted: u64,
    /// Records dropped for age, since start.
    pub(super) expired: u64,
    /// Records refused, since start.
    pub(super) refused: u64,
}

/// The memory a cached record takes, approximately: its fields' bytes plus
/// their allocation headers, and the peer ID's copies in the map key and
/// in this index.
pub(super) fn footprint(info: &quil_p2p::CanonicalPeerInfo) -> usize {
    use std::mem::size_of;
    let vec = size_of::<Vec<u8>>();
    let reachability: usize = info
        .reachability
        .iter()
        .map(|reach| {
            size_of::<quil_p2p::CanonicalReachability>()
                + reach.filter.len()
                + reach
                    .pubsub_multiaddrs
                    .iter()
                    .chain(&reach.stream_multiaddrs)
                    .map(|addr| size_of::<String>() + addr.len())
                    .sum::<usize>()
        })
        .sum();
    let capabilities: usize = info
        .capabilities
        .iter()
        .map(|cap| size_of::<quil_p2p::CanonicalCapability>() + cap.additional_metadata.len())
        .sum();
    size_of::<quil_p2p::CanonicalPeerInfo>()
        + 3 * (vec + info.peer_id.len())
        + info.version.len()
        + info.patch_number.len()
        + info.public_key.len()
        + info.signature.len()
        + reachability
        + capabilities
}

/// Whether `public_key` is a registered prover's (any status).
pub(super) fn registered_prover(
    public_key: &[u8],
    registry: &dyn quil_types::consensus::ProverRegistry,
) -> bool {
    quil_crypto::poseidon::hash_bytes_to_32(public_key)
        .ok()
        .and_then(|address| registry.get_prover_info(&address).ok().flatten())
        .is_some()
}

/// Whether this node uses `info`'s peer: a genesis archive or a registered
/// prover.
pub(super) fn preferred(
    info: &quil_p2p::CanonicalPeerInfo,
    genesis_archives: &HashSet<Vec<u8>>,
    registry: &dyn quil_types::consensus::ProverRegistry,
) -> bool {
    genesis_archives.contains(&info.peer_id) || registered_prover(&info.public_key, registry)
}

impl PeerInfoBounds {
    fn caps(preferred: bool) -> (usize, usize) {
        if preferred {
            (MAX_PREFERRED, MAX_PREFERRED_BYTES)
        } else {
            (MAX_OTHER, MAX_OTHER_BYTES)
        }
    }

    /// Index the records `cache` already holds (restored from the last
    /// run), dropping what exceeds the bounds.
    pub(super) fn adopt(
        &mut self,
        cache: &mut Cache,
        preferred: impl Fn(&quil_p2p::CanonicalPeerInfo) -> bool,
    ) {
        let records: Vec<_> = cache.drain().map(|(_, info)| info).collect();
        for info in records {
            let is_preferred = preferred(&info);
            self.admit(cache, info, is_preferred);
        }
    }

    /// Cache `info` unless the cache holds a record of its peer at least as
    /// new, evicting the oldest records of its tier when the tier is full.
    pub(super) fn admit(
        &mut self,
        cache: &mut Cache,
        info: quil_p2p::CanonicalPeerInfo,
        preferred: bool,
    ) -> Admission {
        let size = footprint(&info);
        if size > MAX_RECORD_FOOTPRINT {
            self.refused += 1;
            return Admission::Refused;
        }
        let replacing = match self.held.get(&info.peer_id) {
            Some(held) if held.timestamp >= info.timestamp => return Admission::Superseded,
            Some(_) => true,
            None => false,
        };
        let tier = usize::from(preferred);
        let (max_records, max_bytes) = Self::caps(preferred);
        if !replacing && self.by_age[tier].len() >= max_records {
            // A full tier keeps its newer records.
            if self.by_age[tier]
                .first()
                .is_some_and(|(oldest, _)| *oldest > info.timestamp)
            {
                self.refused += 1;
                return Admission::Refused;
            }
        }
        if replacing {
            self.remove(cache, &info.peer_id);
        }
        while self.by_age[tier].len() >= max_records || self.bytes[tier] + size > max_bytes {
            let Some((_, victim)) = self.by_age[tier].pop_first() else {
                break;
            };
            self.remove(cache, &victim);
            self.evicted += 1;
        }
        self.by_age[tier].insert((info.timestamp, info.peer_id.clone()));
        self.bytes[tier] += size;
        self.held.insert(
            info.peer_id.clone(),
            Held {
                preferred,
                timestamp: info.timestamp,
                footprint: size,
            },
        );
        cache.insert(info.peer_id.clone(), info);
        if replacing {
            Admission::Replaced
        } else {
            Admission::Inserted
        }
    }

    /// Drop the records older than [`MAX_AGE_MS`] at `now_ms`. Returns how
    /// many were dropped.
    pub(super) fn expire(&mut self, cache: &mut Cache, now_ms: i64) -> usize {
        let cutoff = now_ms.saturating_sub(MAX_AGE_MS);
        let mut dropped = 0;
        for tier in 0..2 {
            while let Some((timestamp, peer)) = self.by_age[tier].first().cloned() {
                if timestamp >= cutoff {
                    break;
                }
                self.remove(cache, &peer);
                dropped += 1;
            }
        }
        self.expired += dropped as u64;
        dropped
    }

    fn remove(&mut self, cache: &mut Cache, peer: &[u8]) {
        if let Some(held) = self.held.remove(peer) {
            let tier = usize::from(held.preferred);
            self.by_age[tier].remove(&(held.timestamp, peer.to_vec()));
            self.bytes[tier] -= held.footprint;
        }
        cache.remove(peer);
    }

    /// Memory the cached records take, by [`footprint`].
    pub(super) fn bytes(&self) -> usize {
        self.bytes[0] + self.bytes[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn record(peer: u32, timestamp: i64) -> quil_p2p::CanonicalPeerInfo {
        quil_p2p::CanonicalPeerInfo {
            peer_id: peer.to_be_bytes().to_vec(),
            reachability: vec![quil_p2p::CanonicalReachability {
                filter: vec![7; 32],
                pubsub_multiaddrs: vec!["/ip4/203.0.113.7/udp/8336/quic-v1".into()],
                stream_multiaddrs: vec!["/ip4/203.0.113.7/tcp/8340".into()],
            }],
            timestamp,
            public_key: vec![1; 897],
            signature: vec![2; 666],
            ..Default::default()
        }
    }

    #[test]
    fn other_peers_cannot_evict_preferred_ones() {
        let mut cache = Cache::new();
        let mut bounds = PeerInfoBounds::default();
        assert_eq!(
            bounds.admit(&mut cache, record(0, NOW - 60_000), true),
            Admission::Inserted
        );
        let others = MAX_OTHER as u32 + 10;
        for peer in 1..=others {
            bounds.admit(&mut cache, record(peer, NOW + i64::from(peer)), false);
        }
        assert!(cache.contains_key(&0u32.to_be_bytes().to_vec()));
        assert_eq!(cache.len(), MAX_OTHER + 1);
        assert_eq!(bounds.evicted, 10);
        // The oldest others went first.
        assert!(!cache.contains_key(&1u32.to_be_bytes().to_vec()));
        assert!(cache.contains_key(&others.to_be_bytes().to_vec()));
        // A full tier refuses a record older than all it holds.
        assert_eq!(
            bounds.admit(&mut cache, record(others + 1, NOW - 1), false),
            Admission::Refused
        );
    }

    #[test]
    fn padded_records_are_bounded_by_memory() {
        let mut cache = Cache::new();
        let mut bounds = PeerInfoBounds::default();
        let padded = |peer: u32| {
            let mut info = record(peer, NOW + i64::from(peer));
            // Empty reachability entries: 12 bytes each on the wire.
            info.reachability = vec![Default::default(); 20_000];
            info
        };
        let size = footprint(&padded(0));
        assert!(size > 1 << 20 && size < MAX_RECORD_FOOTPRINT);
        for peer in 0..64 {
            assert!(bounds.admit(&mut cache, padded(peer), false).admitted());
        }
        assert!(bounds.bytes() <= MAX_OTHER_BYTES);
        assert_eq!(cache.len(), MAX_OTHER_BYTES / size);
        let mut huge = padded(99);
        huge.reachability = vec![Default::default(); 100_000];
        assert_eq!(bounds.admit(&mut cache, huge, false), Admission::Refused);
    }

    #[test]
    fn records_expire_and_a_newer_record_replaces_an_older_one() {
        let mut cache = Cache::new();
        let mut bounds = PeerInfoBounds::default();
        bounds.admit(&mut cache, record(1, NOW - MAX_AGE_MS - 1), true);
        bounds.admit(&mut cache, record(2, NOW - 1_000), false);
        assert_eq!(
            bounds.admit(&mut cache, record(2, NOW - 2_000), false),
            Admission::Superseded
        );
        assert_eq!(
            bounds.admit(&mut cache, record(2, NOW), true),
            Admission::Replaced
        );
        assert_eq!(bounds.expire(&mut cache, NOW), 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache[&2u32.to_be_bytes().to_vec()].timestamp, NOW);
        assert_eq!(bounds.bytes(), footprint(&record(2, NOW)));
    }

    #[test]
    fn adopting_restored_records_applies_the_bounds() {
        let mut cache: Cache = (0..MAX_OTHER as u32 + 5)
            .map(|peer| {
                (
                    peer.to_be_bytes().to_vec(),
                    record(peer, NOW + i64::from(peer)),
                )
            })
            .collect();
        let mut bounds = PeerInfoBounds::default();
        bounds.adopt(&mut cache, |info| info.peer_id == 0u32.to_be_bytes());
        assert_eq!(cache.len(), MAX_OTHER + 1);
        assert!(cache.contains_key(&0u32.to_be_bytes().to_vec()));
    }
}
