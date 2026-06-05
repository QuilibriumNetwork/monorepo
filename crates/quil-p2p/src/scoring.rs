use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::PeerId;

// ---------------------------------------------------------------------------
// Per-bitmask scoring parameters (mirrors Go's BitmaskScoreParams)
// ---------------------------------------------------------------------------

/// Per-bitmask scoring configuration. Each parameter corresponds to a scoring
/// component (P1..P4) in the BlossomSub specification.
#[derive(Debug, Clone)]
pub struct BitmaskScoreParams {
    /// Overall weight for this bitmask's contribution to the score.
    pub bitmask_weight: f64,

    // P1: time in mesh
    pub time_in_mesh_weight: f64,
    pub time_in_mesh_quantum: Duration,
    pub time_in_mesh_cap: f64,

    // P2: first message deliveries
    pub first_message_deliveries_weight: f64,
    pub first_message_deliveries_decay: f64,
    pub first_message_deliveries_cap: f64,

    // P3: mesh message deliveries
    pub mesh_message_deliveries_weight: f64,
    pub mesh_message_deliveries_decay: f64,
    pub mesh_message_deliveries_threshold: f64,
    pub mesh_message_deliveries_cap: f64,
    pub mesh_message_deliveries_activation: Duration,

    // P3b: mesh failure penalty
    pub mesh_failure_penalty_weight: f64,
    pub mesh_failure_penalty_decay: f64,

    // P4: invalid message deliveries
    pub invalid_message_deliveries_weight: f64,
    pub invalid_message_deliveries_decay: f64,
}

impl Default for BitmaskScoreParams {
    fn default() -> Self {
        Self {
            bitmask_weight: 1.0,
            time_in_mesh_weight: 1.0 / 3600.0, // small positive
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 3600.0,
            first_message_deliveries_weight: 1.0,
            first_message_deliveries_decay: 0.5,
            first_message_deliveries_cap: 2000.0,
            mesh_message_deliveries_weight: -1.0,
            mesh_message_deliveries_decay: 0.5,
            mesh_message_deliveries_threshold: 20.0,
            mesh_message_deliveries_cap: 100.0,
            mesh_message_deliveries_activation: Duration::from_secs(5),
            mesh_failure_penalty_weight: -1.0,
            mesh_failure_penalty_decay: 0.5,
            invalid_message_deliveries_weight: -1.0,
            invalid_message_deliveries_decay: 0.9,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-bitmask stats for a peer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BitmaskStats {
    pub in_mesh: bool,
    pub graft_time: Option<Instant>,
    /// Accumulated mesh time, updated during `refresh_scores`.
    pub mesh_time: Duration,
    pub mesh_message_deliveries_active: bool,
    pub first_message_deliveries: f64,
    pub mesh_message_deliveries: f64,
    pub invalid_message_deliveries: f64,
    pub mesh_failure_penalty: f64,
}

impl Default for BitmaskStats {
    fn default() -> Self {
        Self {
            in_mesh: false,
            graft_time: None,
            mesh_time: Duration::ZERO,
            mesh_message_deliveries_active: false,
            first_message_deliveries: 0.0,
            mesh_message_deliveries: 0.0,
            invalid_message_deliveries: 0.0,
            mesh_failure_penalty: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-peer scoring state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub connected: bool,
    pub expire: Option<Instant>,
    pub bitmasks: HashMap<Vec<u8>, BitmaskStats>,
    pub ips: HashSet<IpAddr>,
    pub behaviour_penalty: f64,
}

impl Default for PeerStats {
    fn default() -> Self {
        Self {
            connected: false,
            expire: None,
            bitmasks: HashMap::new(),
            ips: HashSet::new(),
            behaviour_penalty: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Score thresholds
// ---------------------------------------------------------------------------

/// Score thresholds matching the Go implementation.
pub struct ScoreThresholds {
    pub gossip_threshold: f64,
    pub publish_threshold: f64,
    pub graylist_threshold: f64,
    pub accept_px_threshold: f64,
    pub opportunistic_graft_threshold: f64,
}

impl Default for ScoreThresholds {
    fn default() -> Self {
        Self {
            gossip_threshold: -500.0,
            publish_threshold: -1000.0,
            graylist_threshold: -2500.0,
            accept_px_threshold: 1000.0,
            opportunistic_graft_threshold: 3.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer score parameters (top-level, mirrors Go's PeerScoreParams)
// ---------------------------------------------------------------------------

pub struct PeerScoreParams {
    /// Per-bitmask parameters keyed by bitmask bytes.
    pub bitmasks: HashMap<Vec<u8>, BitmaskScoreParams>,
    /// Cap on the positive contribution from bitmask scores. 0 = no cap.
    pub bitmask_score_cap: f64,
    /// P6: IP colocation factor weight (must be negative or 0).
    pub ip_colocation_factor_weight: f64,
    /// P6: Number of peers at an IP before penalty applies.
    pub ip_colocation_factor_threshold: usize,
    /// P7: Behaviour penalty weight (must be negative or 0).
    pub behaviour_penalty_weight: f64,
    /// P7: Threshold before behaviour penalty kicks in.
    pub behaviour_penalty_threshold: f64,
    /// P7: Decay factor for behaviour penalty.
    pub behaviour_penalty_decay: f64,
    /// Decay interval for all counters.
    pub decay_interval: Duration,
    /// Counter values below this are zeroed.
    pub decay_to_zero: f64,
    /// How long to retain scores for disconnected peers.
    pub retain_score: Duration,
}

impl Default for PeerScoreParams {
    fn default() -> Self {
        Self {
            bitmasks: HashMap::new(),
            bitmask_score_cap: 0.0,
            ip_colocation_factor_weight: -10.0,
            ip_colocation_factor_threshold: 3,
            behaviour_penalty_weight: -10.0,
            behaviour_penalty_threshold: 0.0,
            behaviour_penalty_decay: 0.9,
            decay_interval: Duration::from_secs(1),
            decay_to_zero: 0.01,
            retain_score: Duration::from_secs(3600),
        }
    }
}

// ---------------------------------------------------------------------------
// PeerScorer — main scoring engine
// ---------------------------------------------------------------------------

pub struct PeerScorer {
    pub stats: HashMap<PeerId, PeerStats>,
    pub thresholds: ScoreThresholds,
    pub params: PeerScoreParams,
    /// IP colocation tracking: IP -> set of peers.
    peer_ips: HashMap<IpAddr, HashSet<PeerId>>,
    /// Externally-supplied per-peer score adjustment, summed into
    /// `score()` alongside the computed weighted score. Operators
    /// inject these via the proxy `SetPeerScore` / `AddPeerScore` RPCs
    /// to override or augment automatic scoring (e.g. boost a known
    /// archive, penalize a misbehaving peer).
    application_score: HashMap<PeerId, f64>,
}

impl PeerScorer {
    pub fn new(thresholds: ScoreThresholds, params: PeerScoreParams) -> Self {
        Self {
            stats: HashMap::new(),
            thresholds,
            params,
            peer_ips: HashMap::new(),
            application_score: HashMap::new(),
        }
    }

    /// Set the application-level score for a peer, replacing any prior
    /// value. Pass `0.0` to clear the override.
    pub fn set_application_score(&mut self, peer: PeerId, score: f64) {
        if score == 0.0 {
            self.application_score.remove(&peer);
        } else {
            self.application_score.insert(peer, score);
        }
    }

    /// Add `delta` to the peer's application score (creating the
    /// entry if missing).
    pub fn add_application_score(&mut self, peer: PeerId, delta: f64) {
        let entry = self.application_score.entry(peer).or_insert(0.0);
        *entry += delta;
        if *entry == 0.0 {
            self.application_score.remove(&peer);
        }
    }

    /// Application score for a peer, or 0.0 if unset.
    pub fn application_score(&self, peer: &PeerId) -> f64 {
        self.application_score.get(peer).copied().unwrap_or(0.0)
    }

    // -- Scoring ----------------------------------------------------------

    /// Compute the score for a peer using weighted parameters (P1..P7),
    /// plus any operator-supplied application score adjustment.
    pub fn score(&self, peer: &PeerId) -> f64 {
        let app = self.application_score.get(peer).copied().unwrap_or(0.0);
        let pstats = match self.stats.get(peer) {
            Some(s) => s,
            None => return app,
        };

        let mut score = app;

        for (bitmask, bstats) in &pstats.bitmasks {
            let bp = match self.params.bitmasks.get(bitmask) {
                Some(p) => p,
                None => continue,
            };

            let mut bitmask_score = 0.0;

            // P1: time in mesh
            if bstats.in_mesh {
                let quantum_secs = bp.time_in_mesh_quantum.as_secs_f64();
                let p1 = if quantum_secs > 0.0 {
                    (bstats.mesh_time.as_secs_f64() / quantum_secs).min(bp.time_in_mesh_cap)
                } else {
                    0.0
                };
                bitmask_score += p1 * bp.time_in_mesh_weight;
            }

            // P2: first message deliveries
            bitmask_score += bstats.first_message_deliveries * bp.first_message_deliveries_weight;

            // P3: mesh message deliveries (deficit penalty)
            if bstats.mesh_message_deliveries_active
                && bstats.mesh_message_deliveries < bp.mesh_message_deliveries_threshold
            {
                let deficit =
                    bp.mesh_message_deliveries_threshold - bstats.mesh_message_deliveries;
                bitmask_score += deficit * deficit * bp.mesh_message_deliveries_weight;
            }

            // P3b: mesh failure penalty
            bitmask_score += bstats.mesh_failure_penalty * bp.mesh_failure_penalty_weight;

            // P4: invalid message deliveries (squared)
            let p4 = bstats.invalid_message_deliveries * bstats.invalid_message_deliveries;
            bitmask_score += p4 * bp.invalid_message_deliveries_weight;

            score += bitmask_score * bp.bitmask_weight;
        }

        // Apply bitmask score cap
        if self.params.bitmask_score_cap > 0.0 && score > self.params.bitmask_score_cap {
            score = self.params.bitmask_score_cap;
        }

        // P6: IP colocation factor
        score += self.ip_colocation_factor(peer) * self.params.ip_colocation_factor_weight;

        // P7: behaviour penalty
        if pstats.behaviour_penalty > self.params.behaviour_penalty_threshold {
            let excess = pstats.behaviour_penalty - self.params.behaviour_penalty_threshold;
            score += excess * excess * self.params.behaviour_penalty_weight;
        }

        score
    }

    // -- IP colocation ----------------------------------------------------

    /// Compute IP colocation factor for a peer: sum of (surplus^2) for each
    /// IP where peers exceed the threshold.
    pub fn ip_colocation_factor(&self, peer: &PeerId) -> f64 {
        let pstats = match self.stats.get(peer) {
            Some(s) => s,
            None => return 0.0,
        };

        let mut result = 0.0;
        for ip in &pstats.ips {
            let count = self.peer_ips.get(ip).map_or(0, |s| s.len());
            if count > self.params.ip_colocation_factor_threshold {
                let surplus = (count - self.params.ip_colocation_factor_threshold) as f64;
                result += surplus * surplus;
            }
        }
        result
    }

    /// Read a peer's currently-known IP addresses. Empty if the peer
    /// has no tracking entry yet. Used by the mesh-graft path to
    /// compute subnet diversity caps.
    pub fn peer_ips(&self, peer: &PeerId) -> HashSet<IpAddr> {
        self.stats
            .get(peer)
            .map(|s| s.ips.clone())
            .unwrap_or_default()
    }

    /// Register IP addresses for a peer. Updates the global IP-to-peer map.
    pub fn set_peer_ips(&mut self, peer: &PeerId, ips: HashSet<IpAddr>) {
        // Remove old IPs
        if let Some(pstats) = self.stats.get(peer) {
            for old_ip in &pstats.ips {
                if let Some(peers) = self.peer_ips.get_mut(old_ip) {
                    peers.remove(peer);
                    if peers.is_empty() {
                        self.peer_ips.remove(old_ip);
                    }
                }
            }
        }
        // Add new IPs
        for ip in &ips {
            self.peer_ips.entry(*ip).or_default().insert(*peer);
        }
        // Store on peer stats
        let pstats = self.stats.entry(*peer).or_default();
        pstats.ips = ips;
    }

    // -- Decay / refresh --------------------------------------------------

    /// Apply exponential decay to all counters. Should be called at
    /// `params.decay_interval`. Mirrors Go's `refreshScores`.
    pub fn refresh_scores(&mut self) {
        let now = Instant::now();
        let decay_to_zero = self.params.decay_to_zero;

        let mut expired = Vec::new();

        for (peer, pstats) in self.stats.iter_mut() {
            if !pstats.connected {
                if let Some(exp) = pstats.expire {
                    if now >= exp {
                        expired.push(*peer);
                    }
                }
                // Don't decay retained (disconnected) scores.
                continue;
            }

            for (bitmask, bstats) in pstats.bitmasks.iter_mut() {
                let bp = match self.params.bitmasks.get(bitmask) {
                    Some(p) => p,
                    None => continue,
                };

                // Decay counters
                bstats.first_message_deliveries *= bp.first_message_deliveries_decay;
                if bstats.first_message_deliveries < decay_to_zero {
                    bstats.first_message_deliveries = 0.0;
                }

                bstats.mesh_message_deliveries *= bp.mesh_message_deliveries_decay;
                if bstats.mesh_message_deliveries < decay_to_zero {
                    bstats.mesh_message_deliveries = 0.0;
                }

                bstats.mesh_failure_penalty *= bp.mesh_failure_penalty_decay;
                if bstats.mesh_failure_penalty < decay_to_zero {
                    bstats.mesh_failure_penalty = 0.0;
                }

                bstats.invalid_message_deliveries *= bp.invalid_message_deliveries_decay;
                if bstats.invalid_message_deliveries < decay_to_zero {
                    bstats.invalid_message_deliveries = 0.0;
                }

                // Update mesh time & activate mesh message delivery tracking
                if bstats.in_mesh {
                    if let Some(graft) = bstats.graft_time {
                        bstats.mesh_time = now.duration_since(graft);
                        if bstats.mesh_time > bp.mesh_message_deliveries_activation {
                            bstats.mesh_message_deliveries_active = true;
                        }
                    }
                }
            }

            // Decay P7 behaviour penalty
            pstats.behaviour_penalty *= self.params.behaviour_penalty_decay;
            if pstats.behaviour_penalty < decay_to_zero {
                pstats.behaviour_penalty = 0.0;
            }
        }

        // Purge expired disconnected peers
        for peer in &expired {
            if let Some(pstats) = self.stats.remove(peer) {
                for ip in &pstats.ips {
                    if let Some(peers) = self.peer_ips.get_mut(ip) {
                        peers.remove(peer);
                        if peers.is_empty() {
                            self.peer_ips.remove(ip);
                        }
                    }
                }
            }
        }
    }

    // -- Mesh tracking (Graft / Prune) ------------------------------------

    /// Record that a peer has been grafted into the mesh for a bitmask.
    pub fn graft(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let pstats = self.stats.entry(*peer).or_default();
        let bstats = pstats.bitmasks.entry(bitmask.to_vec()).or_default();
        bstats.in_mesh = true;
        bstats.graft_time = Some(Instant::now());
        bstats.mesh_time = Duration::ZERO;
        bstats.mesh_message_deliveries_active = false;
    }

    /// Record that a peer has been pruned from the mesh for a bitmask.
    /// Applies sticky mesh failure penalty if message delivery was below
    /// threshold.
    pub fn prune(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let threshold = self
            .params
            .bitmasks
            .get(bitmask)
            .map(|bp| bp.mesh_message_deliveries_threshold)
            .unwrap_or(0.0);

        let pstats = self.stats.entry(*peer).or_default();
        let bstats = pstats.bitmasks.entry(bitmask.to_vec()).or_default();

        if bstats.mesh_message_deliveries_active
            && bstats.mesh_message_deliveries < threshold
        {
            let deficit = threshold - bstats.mesh_message_deliveries;
            bstats.mesh_failure_penalty += deficit * deficit;
        }
        bstats.in_mesh = false;
    }

    // -- Recording events -------------------------------------------------

    /// Record a valid first message delivery from a peer.
    pub fn add_delivery(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let cap = self
            .params
            .bitmasks
            .get(bitmask)
            .map(|bp| bp.first_message_deliveries_cap)
            .unwrap_or(f64::MAX);
        let mesh_cap = self
            .params
            .bitmasks
            .get(bitmask)
            .map(|bp| bp.mesh_message_deliveries_cap)
            .unwrap_or(f64::MAX);

        let pstats = self.stats.entry(*peer).or_default();
        let bstats = pstats.bitmasks.entry(bitmask.to_vec()).or_default();
        bstats.first_message_deliveries =
            (bstats.first_message_deliveries + 1.0).min(cap);
        if bstats.in_mesh {
            bstats.mesh_message_deliveries =
                (bstats.mesh_message_deliveries + 1.0).min(mesh_cap);
        }
    }

    /// Record an invalid message from a peer.
    pub fn add_invalid(&mut self, peer: &PeerId, bitmask: &[u8]) {
        let pstats = self.stats.entry(*peer).or_default();
        let bstats = pstats.bitmasks.entry(bitmask.to_vec()).or_default();
        bstats.invalid_message_deliveries += 1.0;
    }

    /// Record a behaviour penalty (protocol violation).
    pub fn add_penalty(&mut self, peer: &PeerId, penalty: f64) {
        let pstats = self.stats.entry(*peer).or_default();
        pstats.behaviour_penalty += penalty;
    }

    // -- Peer connection lifecycle ----------------------------------------

    /// Mark a peer as connected.
    pub fn add_peer(&mut self, peer: &PeerId) {
        let pstats = self.stats.entry(*peer).or_default();
        pstats.connected = true;
        pstats.expire = None;
    }

    /// Mark a peer as disconnected. Retains negative scores per
    /// `params.retain_score`.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        // Positive-scored peers: just drop.
        if self.score(peer) > 0.0 {
            if let Some(pstats) = self.stats.remove(peer) {
                for ip in &pstats.ips {
                    if let Some(peers) = self.peer_ips.get_mut(ip) {
                        peers.remove(peer);
                        if peers.is_empty() {
                            self.peer_ips.remove(ip);
                        }
                    }
                }
            }
            return;
        }

        if let Some(pstats) = self.stats.get_mut(peer) {
            // Reset first-message counters; apply mesh failure penalties.
            for (bitmask, bstats) in pstats.bitmasks.iter_mut() {
                bstats.first_message_deliveries = 0.0;
                let threshold = self
                    .params
                    .bitmasks
                    .get(bitmask)
                    .map(|bp| bp.mesh_message_deliveries_threshold)
                    .unwrap_or(0.0);
                if bstats.in_mesh
                    && bstats.mesh_message_deliveries_active
                    && bstats.mesh_message_deliveries < threshold
                {
                    let deficit = threshold - bstats.mesh_message_deliveries;
                    bstats.mesh_failure_penalty += deficit * deficit;
                }
                bstats.in_mesh = false;
            }

            pstats.connected = false;
            pstats.expire = Some(Instant::now() + self.params.retain_score);
        }
    }
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new(ScoreThresholds::default(), PeerScoreParams::default())
    }
}

// ---------------------------------------------------------------------------
// PeerGater — admission control based on peer scores
// ---------------------------------------------------------------------------

/// Rate-limited admission control for inbound RPCs.
pub struct PeerGater {
    /// Score threshold below which peers are rejected.
    pub accept_threshold: f64,
    /// Maximum inbound RPCs per peer per window.
    pub rate_limit: u32,
    /// Rate-limit window duration.
    pub rate_window: Duration,
    /// Per-peer RPC counters: (count, window_start).
    counters: HashMap<PeerId, (u32, Instant)>,
}

impl PeerGater {
    pub fn new(accept_threshold: f64, rate_limit: u32, rate_window: Duration) -> Self {
        Self {
            accept_threshold,
            rate_limit,
            rate_window,
            counters: HashMap::new(),
        }
    }

    /// Should we accept messages from this peer based on their score?
    pub fn accept_from(&self, peer: &PeerId, scorer: &PeerScorer) -> bool {
        scorer.score(peer) >= self.accept_threshold
    }

    /// Validate an inbound RPC against rate limits. Returns `true` if
    /// allowed, `false` if rate-limited.
    pub fn validate_inbound_rpc(&mut self, peer: &PeerId) -> bool {
        let now = Instant::now();
        let entry = self.counters.entry(*peer).or_insert((0, now));
        if now.duration_since(entry.1) >= self.rate_window {
            // Reset window
            *entry = (1, now);
            true
        } else {
            entry.0 += 1;
            entry.0 <= self.rate_limit
        }
    }
}

impl Default for PeerGater {
    fn default() -> Self {
        Self::new(-1000.0, 100, Duration::from_secs(10))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(id: u8) -> PeerId {
        // Deterministic PeerId from a single byte.
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = id;
        let key = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut key_bytes).unwrap();
        let kp = libp2p::identity::Keypair::from(
            libp2p::identity::ed25519::Keypair::from(key),
        );
        kp.public().to_peer_id()
    }

    fn scorer_with_bitmask(bitmask: &[u8]) -> PeerScorer {
        let mut params = PeerScoreParams::default();
        params.bitmasks.insert(bitmask.to_vec(), BitmaskScoreParams::default());
        PeerScorer::new(ScoreThresholds::default(), params)
    }

    #[test]
    fn test_unknown_peer_score_is_zero() {
        let scorer = scorer_with_bitmask(b"test");
        let peer = test_peer(1);
        assert_eq!(scorer.score(&peer), 0.0);
    }

    #[test]
    fn test_first_message_deliveries_positive() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);
        scorer.graft(&peer, &bitmask);

        scorer.add_delivery(&peer, &bitmask);
        scorer.add_delivery(&peer, &bitmask);
        let s = scorer.score(&peer);
        // P2: 2 deliveries * weight(1.0) * bitmask_weight(1.0) = 2.0
        assert!(s > 0.0, "score should be positive: {}", s);
    }

    #[test]
    fn test_invalid_messages_negative() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_invalid(&peer, &bitmask);
        scorer.add_invalid(&peer, &bitmask);
        let s = scorer.score(&peer);
        // P4: (2*2) * weight(-1.0) = -4.0
        assert!(s < 0.0, "score should be negative: {}", s);
        assert!((s - (-4.0)).abs() < 1e-9);
    }

    #[test]
    fn test_behaviour_penalty() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_penalty(&peer, 5.0);
        let s = scorer.score(&peer);
        // P7: (5.0 - 0.0)^2 * -10.0 = -250.0
        assert!((s - (-250.0)).abs() < 1e-9, "score was {}", s);
    }

    #[test]
    fn test_delivery_cap_applied() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        let mut bp = BitmaskScoreParams::default();
        bp.first_message_deliveries_cap = 5.0;
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        for _ in 0..100 {
            scorer.add_delivery(&peer, &bitmask);
        }
        let bstats = &scorer.stats[&peer].bitmasks[&bitmask];
        assert!(
            (bstats.first_message_deliveries - 5.0).abs() < 1e-9,
            "should be capped at 5.0, was {}",
            bstats.first_message_deliveries
        );
    }

    #[test]
    fn test_mesh_message_deliveries_deficit_penalty() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        let mut bp = BitmaskScoreParams::default();
        bp.mesh_message_deliveries_threshold = 10.0;
        bp.mesh_message_deliveries_weight = -1.0;
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);
        scorer.graft(&peer, &bitmask);

        // Force activation
        {
            let bstats = scorer.stats.get_mut(&peer).unwrap()
                .bitmasks.get_mut(&bitmask).unwrap();
            bstats.mesh_message_deliveries_active = true;
            bstats.mesh_message_deliveries = 3.0;
        }

        let s = scorer.score(&peer);
        // deficit = 10 - 3 = 7; penalty = 7^2 * -1.0 = -49.0
        // Plus P2 from first_message_deliveries=0 => 0
        // bitmask_weight = 1.0
        assert!((s - (-49.0)).abs() < 1e-9, "score was {}", s);
    }

    #[test]
    fn test_decay_reduces_counters() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        let mut bp = BitmaskScoreParams::default();
        bp.first_message_deliveries_decay = 0.5;
        bp.invalid_message_deliveries_decay = 0.5;
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);
        scorer.graft(&peer, &bitmask);

        scorer.add_delivery(&peer, &bitmask);
        scorer.add_delivery(&peer, &bitmask);
        scorer.add_invalid(&peer, &bitmask);

        scorer.refresh_scores();

        let bstats = &scorer.stats[&peer].bitmasks[&bitmask];
        assert!(
            (bstats.first_message_deliveries - 1.0).abs() < 1e-9,
            "expected 2*0.5=1.0, got {}",
            bstats.first_message_deliveries
        );
        assert!(
            (bstats.invalid_message_deliveries - 0.5).abs() < 1e-9,
            "expected 1*0.5=0.5, got {}",
            bstats.invalid_message_deliveries
        );
    }

    #[test]
    fn test_decay_to_zero() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        params.decay_to_zero = 0.1;
        let mut bp = BitmaskScoreParams::default();
        bp.first_message_deliveries_decay = 0.01; // aggressive decay
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_delivery(&peer, &bitmask);

        // After decay: 1.0 * 0.01 = 0.01 < 0.1 => zero
        scorer.refresh_scores();
        let bstats = &scorer.stats[&peer].bitmasks[&bitmask];
        assert_eq!(bstats.first_message_deliveries, 0.0);
    }

    #[test]
    fn test_prune_applies_mesh_failure_penalty() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        let mut bp = BitmaskScoreParams::default();
        bp.mesh_message_deliveries_threshold = 10.0;
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);
        scorer.graft(&peer, &bitmask);

        // Force activation with deficit
        {
            let bstats = scorer.stats.get_mut(&peer).unwrap()
                .bitmasks.get_mut(&bitmask).unwrap();
            bstats.mesh_message_deliveries_active = true;
            bstats.mesh_message_deliveries = 2.0;
        }

        scorer.prune(&peer, &bitmask);
        let bstats = &scorer.stats[&peer].bitmasks[&bitmask];
        // deficit = 10 - 2 = 8; penalty = 64.0
        assert!((bstats.mesh_failure_penalty - 64.0).abs() < 1e-9);
        assert!(!bstats.in_mesh);
    }

    #[test]
    fn test_ip_colocation_penalty() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        params.ip_colocation_factor_threshold = 2;
        params.ip_colocation_factor_weight = -10.0;
        params.bitmasks.insert(bitmask.clone(), BitmaskScoreParams::default());
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);

        let shared_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Three peers on the same IP — threshold is 2, so surplus = 1.
        for i in 0..3 {
            let peer = test_peer(i);
            scorer.add_peer(&peer);
            let mut ips = HashSet::new();
            ips.insert(shared_ip);
            scorer.set_peer_ips(&peer, ips);
        }

        let peer0 = test_peer(0);
        let factor = scorer.ip_colocation_factor(&peer0);
        // 3 peers, threshold 2, surplus = 1 => 1^2 = 1.0
        assert!((factor - 1.0).abs() < 1e-9, "factor was {}", factor);

        let s = scorer.score(&peer0);
        // IP penalty: 1.0 * -10.0 = -10.0
        assert!(s < 0.0);
    }

    #[test]
    fn test_bitmask_score_cap() {
        let bitmask = b"test".to_vec();
        let mut params = PeerScoreParams::default();
        params.bitmask_score_cap = 10.0;
        params.ip_colocation_factor_weight = 0.0; // disable IP penalty for this test
        params.behaviour_penalty_weight = 0.0;
        let mut bp = BitmaskScoreParams::default();
        bp.first_message_deliveries_weight = 100.0;
        bp.first_message_deliveries_cap = 1000.0;
        params.bitmasks.insert(bitmask.clone(), bp);
        let mut scorer = PeerScorer::new(ScoreThresholds::default(), params);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_delivery(&peer, &bitmask);
        let s = scorer.score(&peer);
        // 1 delivery * 100.0 weight = 100.0, capped at 10.0
        assert!((s - 10.0).abs() < 1e-9, "score was {}", s);
    }

    #[test]
    fn test_remove_peer_retains_negative() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_invalid(&peer, &bitmask);
        scorer.add_invalid(&peer, &bitmask);
        assert!(scorer.score(&peer) < 0.0);

        scorer.remove_peer(&peer);
        // Peer should be retained with negative score.
        assert!(scorer.stats.contains_key(&peer));
        assert!(!scorer.stats[&peer].connected);
    }

    #[test]
    fn test_remove_peer_drops_positive() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        scorer.add_delivery(&peer, &bitmask);
        assert!(scorer.score(&peer) > 0.0);

        scorer.remove_peer(&peer);
        assert!(!scorer.stats.contains_key(&peer));
    }

    #[test]
    fn test_peer_gater_accept_from() {
        let bitmask = b"test".to_vec();
        let mut scorer = scorer_with_bitmask(&bitmask);
        let peer = test_peer(1);
        scorer.add_peer(&peer);

        let gater = PeerGater::new(-5.0, 100, Duration::from_secs(10));

        // No penalty => score 0.0 >= -5.0 => accept
        assert!(gater.accept_from(&peer, &scorer));

        // Heavy invalids => score goes very negative
        for _ in 0..10 {
            scorer.add_invalid(&peer, &bitmask);
        }
        assert!(scorer.score(&peer) < -5.0);
        assert!(!gater.accept_from(&peer, &scorer));
    }

    #[test]
    fn test_peer_gater_rate_limit() {
        let peer = test_peer(1);
        let mut gater = PeerGater::new(-1000.0, 3, Duration::from_secs(60));

        assert!(gater.validate_inbound_rpc(&peer));
        assert!(gater.validate_inbound_rpc(&peer));
        assert!(gater.validate_inbound_rpc(&peer));
        // 4th call exceeds limit of 3
        assert!(!gater.validate_inbound_rpc(&peer));
    }

    #[test]
    fn test_default_bitmask_params() {
        let bp = BitmaskScoreParams::default();
        assert!(bp.bitmask_weight > 0.0);
        assert!(bp.time_in_mesh_weight > 0.0);
        assert!(bp.first_message_deliveries_weight > 0.0);
        assert!(bp.mesh_message_deliveries_weight < 0.0);
        assert!(bp.mesh_failure_penalty_weight < 0.0);
        assert!(bp.invalid_message_deliveries_weight < 0.0);
        assert!(bp.first_message_deliveries_decay > 0.0 && bp.first_message_deliveries_decay < 1.0);
    }

    #[test]
    fn test_unscored_bitmask_ignored() {
        // Bitmasks without params should not contribute to score.
        let mut scorer = PeerScorer::default();
        let peer = test_peer(1);
        scorer.add_peer(&peer);
        scorer.add_delivery(&peer, b"untracked");
        assert_eq!(scorer.score(&peer), 0.0);
    }

    // ---------------------------------------------------------------
    // Default-parameter invariants. These guard against accidental
    // sign flips or out-of-range tweaks in `Default::default()` for
    // `ScoreThresholds` and `PeerScoreParams`. The asserted
    // properties are derived from the protocol's semantic
    // requirements (penalty weights must not be positive, decay
    // factors must be in (0, 1], thresholds must order so that the
    // graylist cut sits below the publish cut, etc.).

    /// Penalty weights and the colocation factor must be non-
    /// positive — they exist to subtract from score, not add.
    #[test]
    fn default_penalty_weights_are_non_positive() {
        let p = PeerScoreParams::default();
        assert!(p.ip_colocation_factor_weight <= 0.0,
            "IP colocation factor must penalize, got {}", p.ip_colocation_factor_weight);
        assert!(p.behaviour_penalty_weight <= 0.0,
            "behaviour penalty weight must penalize, got {}", p.behaviour_penalty_weight);
    }

    /// Decay factor must sit in (0, 1] — values ≥ 1 would never
    /// decay (or amplify) the counter, values ≤ 0 would flip sign.
    #[test]
    fn default_behaviour_penalty_decay_in_unit_range() {
        let p = PeerScoreParams::default();
        assert!(p.behaviour_penalty_decay > 0.0 && p.behaviour_penalty_decay <= 1.0,
            "behaviour_penalty_decay must be in (0, 1], got {}", p.behaviour_penalty_decay);
    }

    /// `decay_to_zero` is the floor below which counters round to
    /// zero — must be non-negative, since the counter is non-
    /// negative by construction.
    #[test]
    fn default_decay_to_zero_non_negative() {
        let p = PeerScoreParams::default();
        assert!(p.decay_to_zero >= 0.0,
            "decay_to_zero must be non-negative, got {}", p.decay_to_zero);
    }

    /// Threshold ordering: graylist (most punitive) must sit at or
    /// below the publish cut, which must sit at or below the gossip
    /// cut — peers we won't gossip with shouldn't publish to us
    /// either, and peers we publish to shouldn't be graylisted.
    /// All three sit below zero (they're "negative-score" cutoffs).
    #[test]
    fn default_threshold_ordering() {
        let t = ScoreThresholds::default();
        assert!(t.graylist_threshold <= t.publish_threshold,
            "graylist ({}) must be ≤ publish ({})", t.graylist_threshold, t.publish_threshold);
        assert!(t.publish_threshold <= t.gossip_threshold,
            "publish ({}) must be ≤ gossip ({})", t.publish_threshold, t.gossip_threshold);
        assert!(t.gossip_threshold <= 0.0,
            "gossip threshold must be ≤ 0, got {}", t.gossip_threshold);
    }

    /// `accept_px_threshold` (the bar to accept peer-exchange hints
    /// from a peer) must be ≥ 0 — we only accept PX from peers in
    /// good standing.
    #[test]
    fn default_accept_px_threshold_non_negative() {
        let t = ScoreThresholds::default();
        assert!(t.accept_px_threshold >= 0.0,
            "accept_px_threshold must be ≥ 0, got {}", t.accept_px_threshold);
    }

    /// `retain_score` must be a non-zero duration — zero would
    /// reset the score immediately on disconnect, defeating the
    /// purpose of carrying punitive scores across reconnects.
    #[test]
    fn default_retain_score_nonzero() {
        let p = PeerScoreParams::default();
        assert!(p.retain_score > std::time::Duration::ZERO,
            "retain_score must be > 0");
    }

    /// `decay_interval` must be a non-zero duration — zero would
    /// produce divide-by-zero or infinite decay on `refresh_scores`.
    #[test]
    fn default_decay_interval_nonzero() {
        let p = PeerScoreParams::default();
        assert!(p.decay_interval > std::time::Duration::ZERO,
            "decay_interval must be > 0");
    }
}
