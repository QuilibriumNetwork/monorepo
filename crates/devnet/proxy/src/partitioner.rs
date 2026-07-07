//! Tracks which peer pairs are partitioned from each other.
//!
//! A single [`NetworkPartitioner`] is shared (via `Arc`) by both the BlossomSub
//! proxy and the gRPC proxy so that one `apply_partition` call affects every
//! transport. Forwarding between two peers is allowed unless their (unordered)
//! pair has been partitioned.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::RwLock;

use quil_p2p::PeerId;

/// Canonical unordered key for a pair of peers.
fn pair_key(a: PeerId, b: PeerId) -> (PeerId, PeerId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Thread-safe set of partitioned peer pairs.
#[derive(Default)]
pub struct NetworkPartitioner {
    partitioned_pairs: RwLock<HashSet<(PeerId, PeerId)>>,
}

impl NetworkPartitioner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when forwarding between `from` and `to` is allowed.
    pub fn forward_filter(&self, from: &PeerId, to: &PeerId) -> bool {
        let blocked = self
            .partitioned_pairs
            .read()
            .unwrap()
            .contains(&pair_key(*from, *to));
        !blocked
    }

    /// Suppresses forwarding between `peer_a` and `peer_b`. Idempotent.
    pub fn partition_peers(&self, peer_a: PeerId, peer_b: PeerId) {
        self.partitioned_pairs
            .write()
            .unwrap()
            .insert(pair_key(peer_a, peer_b));
    }

    /// Removes all active partitions.
    pub fn clear_partitions(&self) {
        self.partitioned_pairs.write().unwrap().clear();
    }

    /// Clears existing partitions and blocks all `group1 × group2` pairs. Each
    /// element is a base58-encoded peer ID string; unparseable entries are
    /// skipped (with a warning), matching the Go proxy's lenient decode.
    pub fn apply_partition(&self, group1: &[String], group2: &[String]) {
        self.clear_partitions();
        for p1 in group1 {
            let Some(pid1) = parse_peer_id(p1) else {
                continue;
            };
            for p2 in group2 {
                let Some(pid2) = parse_peer_id(p2) else {
                    continue;
                };
                self.partition_peers(pid1, pid2);
            }
        }
    }
}

fn parse_peer_id(s: &str) -> Option<PeerId> {
    match PeerId::from_str(s.trim()) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(peer = %s, error = %e, "skipping unparseable peer ID in partition");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::ed448_identity::Ed448Identity;

    fn peer(seed_suffix: u8) -> (PeerId, String) {
        // Deterministic distinct identities for tests.
        let id = Ed448Identity::generate().unwrap();
        let _ = seed_suffix;
        let b58 = id.peer_id_base58();
        (PeerId::from_str(&b58).unwrap(), b58)
    }

    #[test]
    fn forward_allowed_by_default() {
        let (a, _) = peer(1);
        let (b, _) = peer(2);
        let p = NetworkPartitioner::new();
        assert!(p.forward_filter(&a, &b));
        assert!(p.forward_filter(&b, &a));
    }

    #[test]
    fn partition_blocks_both_directions() {
        let (a, _) = peer(1);
        let (b, _) = peer(2);
        let p = NetworkPartitioner::new();
        p.partition_peers(a, b);
        assert!(!p.forward_filter(&a, &b));
        assert!(!p.forward_filter(&b, &a), "partition is symmetric");
    }

    #[test]
    fn apply_partition_blocks_cross_group_only() {
        let (a, a58) = peer(1);
        let (b, b58) = peer(2);
        let (c, c58) = peer(3);
        let p = NetworkPartitioner::new();
        p.apply_partition(&[a58, b58], &[c58]);
        // cross-group blocked
        assert!(!p.forward_filter(&a, &c));
        assert!(!p.forward_filter(&c, &b));
        // same-group allowed
        assert!(p.forward_filter(&a, &b));
    }

    #[test]
    fn apply_partition_clears_previous() {
        let (a, a58) = peer(1);
        let (b, b58) = peer(2);
        let (c, c58) = peer(3);
        let p = NetworkPartitioner::new();
        p.apply_partition(std::slice::from_ref(&a58), &[b58]);
        assert!(!p.forward_filter(&a, &b));
        // a new partition replaces the old one entirely
        p.apply_partition(&[a58], &[c58]);
        assert!(
            p.forward_filter(&a, &b),
            "previous partition should be cleared"
        );
        assert!(!p.forward_filter(&a, &c));
    }

    #[test]
    fn clear_partitions_unblocks() {
        let (a, _) = peer(1);
        let (b, _) = peer(2);
        let p = NetworkPartitioner::new();
        p.partition_peers(a, b);
        p.clear_partitions();
        assert!(p.forward_filter(&a, &b));
    }
}
