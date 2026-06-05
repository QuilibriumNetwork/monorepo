use std::collections::{HashMap, HashSet};
use std::time::Instant;

use libp2p::PeerId;

use crate::bitmask::slice_bitmask;
use crate::params::*;

/// A composite mesh entry for multi-bit bitmask subscriptions.
///
/// Maintains D total peers (not D per slice). Peers are classified as:
/// - "same": subscribed to ALL slices of the composite
/// - "broker": subscribed to some (but not all) slices, bridging traffic
#[derive(Debug, Clone)]
pub struct CompositeMeshEntry {
    /// The full (unspliced) bitmask.
    pub bitmask: Vec<u8>,
    /// Cached result of slice_bitmask(bitmask).
    pub slices: Vec<Vec<u8>>,
    /// Peers subscribed to ALL slices.
    pub same: HashSet<PeerId>,
    /// Peers subscribed to some (but not all) slices.
    pub broker: HashSet<PeerId>,
}

impl CompositeMeshEntry {
    pub fn new(bitmask: Vec<u8>) -> Self {
        let slices = slice_bitmask(&bitmask);
        Self {
            bitmask,
            slices,
            same: HashSet::new(),
            broker: HashSet::new(),
        }
    }

    pub fn total_peers(&self) -> usize {
        self.same.len() + self.broker.len()
    }
}

/// The BlossomSub router state.
///
/// This is the core data structure that manages mesh formation, message
/// routing, and peer scoring. It will be wrapped in a libp2p NetworkBehaviour
/// implementation.
pub struct BlossomSubRouter {
    /// Peer protocol versions.
    pub peers: HashMap<PeerId, String>,
    /// Known peer subscriptions (which bitmasks each peer is subscribed to).
    pub peer_subscriptions: HashMap<PeerId, HashSet<Vec<u8>>>,
    /// Direct (always-connected) peers.
    pub direct: HashSet<PeerId>,
    /// Per-slice bitmask meshes. Key = hex(slice_bitmask).
    pub mesh: HashMap<Vec<u8>, HashSet<PeerId>>,
    /// Fanout for bitmasks we publish to but aren't joined.
    pub fanout: HashMap<Vec<u8>, HashSet<PeerId>>,
    /// Composite meshes for multi-bit bitmasks.
    pub composites: HashMap<Vec<u8>, CompositeMeshEntry>,
    /// Reverse index: slice key -> list of composite bitmask keys.
    pub slice_to_composite: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Last publish time per bitmask (for fanout TTL).
    pub last_pub: HashMap<Vec<u8>, Instant>,
    /// Prune backoff per peer per bitmask.
    pub backoff: HashMap<Vec<u8>, HashMap<PeerId, Instant>>,
    /// Whether each peer is an outbound connection.
    pub outbound: HashMap<PeerId, bool>,
    /// Message cache (recent messages for IHAVE/IWANT gossip).
    pub mcache: MessageCache,
}

impl BlossomSubRouter {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            peer_subscriptions: HashMap::new(),
            direct: HashSet::new(),
            mesh: HashMap::new(),
            fanout: HashMap::new(),
            composites: HashMap::new(),
            slice_to_composite: HashMap::new(),
            last_pub: HashMap::new(),
            backoff: HashMap::new(),
            outbound: HashMap::new(),
            mcache: MessageCache::new(HISTORY_LENGTH, HISTORY_GOSSIP),
        }
    }

    /// Join a bitmask mesh. Selects D peers and sends GRAFT.
    pub fn join(&mut self, bitmask: &[u8]) -> Vec<(PeerId, Vec<u8>)> {
        let slices = slice_bitmask(bitmask);

        if slices.len() <= 1 {
            // Simple (single-slice) join
            self.join_simple(bitmask)
        } else {
            // Composite (multi-bit) join
            self.join_composite(bitmask, slices)
        }
    }

    /// Leave a bitmask mesh. Sends PRUNE to all mesh peers.
    pub fn leave(&mut self, bitmask: &[u8]) -> Vec<(PeerId, Vec<u8>)> {
        let mut prunes = Vec::new();

        if let Some(peers) = self.mesh.remove(bitmask) {
            for peer in peers {
                prunes.push((peer, bitmask.to_vec()));
            }
        }

        // Also clean up composite if exists
        self.composites.remove(bitmask);

        prunes
    }

    fn join_simple(&mut self, bitmask: &[u8]) -> Vec<(PeerId, Vec<u8>)> {
        if self.mesh.contains_key(bitmask) {
            return Vec::new(); // Already joined
        }

        // Select D peers: prefer fanout, then random
        let mut selected = HashSet::new();
        if let Some(fanout_peers) = self.fanout.remove(bitmask) {
            for peer in fanout_peers {
                if selected.len() >= D {
                    break;
                }
                selected.insert(peer);
            }
        }

        // Fill remaining slots from available peers (subscribed, not backed off).
        if selected.len() < D {
            let backoffs = self.backoff.get(bitmask);
            let now = Instant::now();
            for (peer, _subs) in &self.peer_subscriptions {
                if selected.len() >= D {
                    break;
                }
                if selected.contains(peer) {
                    continue;
                }
                if !_subs.contains(bitmask) {
                    continue;
                }
                if let Some(bo) = backoffs {
                    if let Some(expiry) = bo.get(peer) {
                        if *expiry > now {
                            continue;
                        }
                    }
                }
                selected.insert(*peer);
            }
        }

        let grafts: Vec<(PeerId, Vec<u8>)> = selected
            .iter()
            .map(|p| (*p, bitmask.to_vec()))
            .collect();

        self.mesh.insert(bitmask.to_vec(), selected);
        grafts
    }

    fn join_composite(
        &mut self,
        bitmask: &[u8],
        _slices: Vec<Vec<u8>>,
    ) -> Vec<(PeerId, Vec<u8>)> {
        let mut entry = CompositeMeshEntry::new(bitmask.to_vec());

        // Select D "same" peers (subscribed to all slices).
        let backoffs = self.backoff.get(bitmask);
        let now = Instant::now();
        for (peer, subs) in &self.peer_subscriptions {
            if entry.total_peers() >= D {
                break;
            }
            // Skip backed-off peers.
            if let Some(bo) = backoffs {
                if let Some(expiry) = bo.get(peer) {
                    if *expiry > now {
                        continue;
                    }
                }
            }
            // Check if peer is subscribed to ALL slices (= "same" peer).
            let subscribed_all = entry.slices.iter().all(|slice| subs.contains(slice));
            if subscribed_all {
                entry.same.insert(*peer);
            }
        }

        // If fewer than D same peers, add "broker" peers (subscribed to some slices).
        if entry.total_peers() < D {
            for (peer, subs) in &self.peer_subscriptions {
                if entry.total_peers() >= D {
                    break;
                }
                if entry.same.contains(peer) {
                    continue;
                }
                if let Some(bo) = backoffs {
                    if let Some(expiry) = bo.get(peer) {
                        if *expiry > now {
                            continue;
                        }
                    }
                }
                // Broker = subscribed to at least one slice but not all.
                let subscribed_any = entry.slices.iter().any(|slice| subs.contains(slice));
                if subscribed_any {
                    entry.broker.insert(*peer);
                }
            }
        }

        // Register reverse index from each slice to this composite.
        for slice in &entry.slices {
            self.slice_to_composite
                .entry(slice.clone())
                .or_default()
                .push(bitmask.to_vec());
        }

        let grafts: Vec<(PeerId, Vec<u8>)> = entry
            .same
            .iter()
            .chain(entry.broker.iter())
            .map(|p| (*p, bitmask.to_vec()))
            .collect();

        self.composites.insert(bitmask.to_vec(), entry);
        grafts
    }

    /// Run the periodic heartbeat: maintain mesh, gossip, prune.
    pub fn heartbeat(&mut self) -> HeartbeatActions {
        let mut actions = HeartbeatActions::default();
        let now = Instant::now();

        // Collect bitmask keys to avoid borrow conflicts.
        let bitmask_keys: Vec<Vec<u8>> = self.mesh.keys().cloned().collect();

        for bitmask in &bitmask_keys {
            let peers = match self.mesh.get_mut(bitmask) {
                Some(p) => p,
                None => continue,
            };

            // Remove peers no longer tracked (disconnected). This serves as
            // a proxy for negative-score removal — the router has no scorer,
            // so we evict peers that have been removed from self.peers.
            let stale: Vec<PeerId> = peers
                .iter()
                .filter(|p| !self.peers.contains_key(p))
                .copied()
                .collect();
            for peer in stale {
                peers.remove(&peer);
                actions.prunes.push((peer, bitmask.clone()));
            }

            // Enforce D_LO / D_HI bounds
            if peers.len() < D_LO {
                // GRAFT: select from available peers subscribed to this
                // bitmask, not already in mesh, not backed off.
                let needed = D - peers.len();
                let backoffs = self.backoff.get(bitmask);
                let candidates: Vec<PeerId> = self
                    .peer_subscriptions
                    .iter()
                    .filter_map(|(p, subs)| {
                        if peers.contains(p) || !subs.contains(bitmask) {
                            return None;
                        }
                        if let Some(bo) = backoffs {
                            if let Some(expiry) = bo.get(p) {
                                if *expiry > now {
                                    return None;
                                }
                            }
                        }
                        Some(*p)
                    })
                    .take(needed)
                    .collect();
                for peer in candidates {
                    peers.insert(peer);
                    actions.grafts.push((peer, bitmask.clone()));
                }
            } else if peers.len() > D_HI {
                // PRUNE: remove random excess peers to reach D.
                // The router has no scorer; behaviour.rs handles
                // scoring-aware pruning. Here we just trim to D.
                let excess = peers.len() - D;
                let to_prune: Vec<PeerId> = peers.iter().copied().take(excess).collect();
                for peer in to_prune {
                    peers.remove(&peer);
                    actions.prunes.push((peer, bitmask.clone()));
                }
            }
        }

        // Shift message cache window
        self.mcache.shift();

        actions
    }
}

impl Default for BlossomSubRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Actions to take after a heartbeat cycle.
#[derive(Debug, Default)]
pub struct HeartbeatActions {
    pub grafts: Vec<(PeerId, Vec<u8>)>,
    pub prunes: Vec<(PeerId, Vec<u8>)>,
    pub ihaves: Vec<(PeerId, Vec<u8>, Vec<Vec<u8>>)>,
}

/// Message cache for IHAVE/IWANT gossip protocol.
pub struct MessageCache {
    /// Sliding windows of message IDs.
    windows: Vec<Vec<Vec<u8>>>,
    /// Message data by ID.
    messages: HashMap<Vec<u8>, CachedMessage>,
    /// Number of history windows to maintain.
    history_length: usize,
    /// Number of windows to include in gossip.
    history_gossip: usize,
}

#[derive(Clone)]
struct CachedMessage {
    pub bitmask: Vec<u8>,
    pub data: Vec<u8>,
    pub _from: PeerId,
}

impl MessageCache {
    pub fn new(history_length: usize, history_gossip: usize) -> Self {
        Self {
            windows: vec![Vec::new()],
            messages: HashMap::new(),
            history_length,
            history_gossip,
        }
    }

    /// Add a message to the current window.
    pub fn put(&mut self, msg_id: Vec<u8>, bitmask: Vec<u8>, data: Vec<u8>, from: PeerId) {
        self.messages.insert(
            msg_id.clone(),
            CachedMessage {
                bitmask,
                data,
                _from: from,
            },
        );
        if let Some(window) = self.windows.last_mut() {
            window.push(msg_id);
        }
    }

    /// Get a cached message by ID.
    pub fn get(&self, msg_id: &[u8]) -> Option<(&[u8], &[u8])> {
        self.messages
            .get(msg_id)
            .map(|m| (m.bitmask.as_slice(), m.data.as_slice()))
    }

    /// Get message IDs for gossip (last history_gossip windows).
    pub fn get_gossip_ids(&self, bitmask: &[u8]) -> Vec<Vec<u8>> {
        let start = self.windows.len().saturating_sub(self.history_gossip);
        self.windows[start..]
            .iter()
            .flat_map(|w| w.iter())
            .filter(|id| {
                self.messages
                    .get(id.as_slice())
                    .map(|m| m.bitmask == bitmask)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Advance the window (called at end of each heartbeat).
    pub fn shift(&mut self) {
        self.windows.push(Vec::new());
        if self.windows.len() > self.history_length {
            let old = self.windows.remove(0);
            for id in old {
                self.messages.remove(&id);
            }
        }
    }
}

impl std::fmt::Debug for MessageCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageCache")
            .field("windows", &self.windows.len())
            .field("messages", &self.messages.len())
            .finish()
    }
}

#[cfg(test)]
mod mcache_tests {
    //! Observable-contract tests for `MessageCache`. The cache backs
    //! IHAVE/IWANT gossip — a put-then-get cycle must round-trip the
    //! message, gossip queries must be scoped by bitmask and window,
    //! and `shift` must bound memory by evicting entries past the
    //! configured `history_length`.
    use super::*;

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    /// A message put into the cache is retrievable by ID with the
    /// same bitmask + data round-tripped.
    #[test]
    fn put_then_get_round_trips_the_message() {
        let mut mc = MessageCache::new(5, 3);
        let id = b"msg-1".to_vec();
        let bitmask = vec![0xC0];
        let data = b"hello".to_vec();
        mc.put(id.clone(), bitmask.clone(), data.clone(), make_peer());

        let got = mc.get(&id);
        assert!(got.is_some(), "put message must be gettable");
        let (gb, gd) = got.unwrap();
        assert_eq!(gb, bitmask.as_slice());
        assert_eq!(gd, data.as_slice());
    }

    /// `get` of an unknown ID returns None — no false positives.
    #[test]
    fn get_unknown_id_returns_none() {
        let mc = MessageCache::new(5, 3);
        assert!(mc.get(b"never-inserted").is_none());
    }

    /// `get_gossip_ids` returns only IDs whose stored bitmask matches
    /// the query — cross-bitmask leakage would defeat the per-topic
    /// gossip flow.
    #[test]
    fn gossip_ids_filtered_by_bitmask() {
        let mut mc = MessageCache::new(5, 3);
        let bm_a = vec![0xC0];
        let bm_b = vec![0x0C];
        mc.put(b"a1".to_vec(), bm_a.clone(), b"x".to_vec(), make_peer());
        mc.put(b"b1".to_vec(), bm_b.clone(), b"y".to_vec(), make_peer());
        mc.put(b"a2".to_vec(), bm_a.clone(), b"z".to_vec(), make_peer());

        let mut ids_a = mc.get_gossip_ids(&bm_a);
        ids_a.sort();
        let mut ids_b = mc.get_gossip_ids(&bm_b);
        ids_b.sort();
        assert_eq!(ids_a, vec![b"a1".to_vec(), b"a2".to_vec()]);
        assert_eq!(ids_b, vec![b"b1".to_vec()]);
    }

    /// After enough shifts to push the original window past the
    /// `history_length` cap, the messages stored in that window
    /// are evicted from the cache. Construction starts with one
    /// window already present, so the original window survives
    /// `history_length - 1` shifts and is evicted on the
    /// `history_length`th shift (when `windows.len()` exceeds the
    /// cap and `windows[0]` is dropped).
    #[test]
    fn shift_past_history_length_evicts_oldest() {
        let history_length = 3;
        let mut mc = MessageCache::new(history_length, 2);
        let bm = vec![0xC0];

        let id1 = b"id-1".to_vec();
        mc.put(id1.clone(), bm.clone(), b"d".to_vec(), make_peer());
        assert!(mc.get(&id1).is_some());

        // history_length - 1 = 2 shifts: original window still
        // present, no eviction.
        for _ in 0..(history_length - 1) {
            mc.shift();
        }
        assert!(mc.get(&id1).is_some(),
            "id should survive history_length - 1 shifts");

        // One more shift puts windows.len() at history_length + 1 →
        // oldest window evicted.
        mc.shift();
        assert!(mc.get(&id1).is_none(),
            "id should be evicted on the history_length-th shift");
    }

    /// `get_gossip_ids` returns IDs from at most the last
    /// `history_gossip` windows — older entries are filtered out
    /// even if still memory-resident.
    #[test]
    fn gossip_ids_scoped_to_history_gossip_window() {
        let mut mc = MessageCache::new(10, 2);
        let bm = vec![0xC0];

        // Put one message, then advance windows so it falls outside
        // the gossip window (history_gossip = 2 means last 2
        // windows are gossipable; advancing 3 windows pushes it out).
        let id = b"old".to_vec();
        mc.put(id.clone(), bm.clone(), b"d".to_vec(), make_peer());
        mc.shift();
        mc.shift();
        mc.shift();

        // Still in `messages` map (history_length = 10) but past
        // the gossip window.
        assert!(mc.get(&id).is_some(),
            "message should still be memory-resident");
        let gossip = mc.get_gossip_ids(&bm);
        assert!(!gossip.contains(&id),
            "message past history_gossip must NOT be advertised");
    }

    /// `put` deposits IDs into the current (latest) window — a
    /// subsequent `get_gossip_ids` (history_gossip ≥ 1) sees them.
    #[test]
    fn put_lands_in_current_window_and_is_gossipable() {
        let mut mc = MessageCache::new(5, 3);
        let bm = vec![0xC0];
        let id = b"fresh".to_vec();
        mc.put(id.clone(), bm.clone(), b"d".to_vec(), make_peer());

        let gossip = mc.get_gossip_ids(&bm);
        assert!(gossip.contains(&id),
            "fresh put must be reachable through gossip query");
    }
}

