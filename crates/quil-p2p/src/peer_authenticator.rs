//! Peer authentication module.
//!
//! Manages peer identity verification using Ed448 challenge-response
//! authentication, mirroring the authentication and authorization logic from
//! `node/p2p/peer_authenticator.go`.
//!
//! The Go implementation uses mTLS with Ed448 cross-signatures embedded in
//! certificate DNS names, combined with prover-registry lookups and per-method
//! authorization policies. This Rust port captures the core authentication
//! state machine: challenge generation, Ed448 signature verification, per-peer
//! reputation tracking, and stale-entry cleanup.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use rand::RngCore;

/// Ed448 public key length in bytes.
const ED448_KEY_LENGTH: usize = 57;

/// Default challenge size in bytes.
const CHALLENGE_LENGTH: usize = 32;

/// Default reputation for newly authenticated peers.
const DEFAULT_REPUTATION: f64 = 1.0;

/// Minimum allowed reputation before a peer is considered untrusted.
const MIN_REPUTATION: f64 = -100.0;

/// Maximum allowed reputation.
const MAX_REPUTATION: f64 = 100.0;

/// Per-peer authentication state.
#[derive(Debug, Clone)]
pub struct AuthState {
    /// Whether the peer has been authenticated via challenge-response.
    pub authenticated: bool,
    /// The peer's Ed448 public key (57 bytes).
    pub public_key: Vec<u8>,
    /// When the peer was authenticated.
    pub authenticated_at: Instant,
    /// Reputation score, adjusted over time. Starts at `DEFAULT_REPUTATION`.
    pub reputation: f64,
}

impl AuthState {
    fn new(public_key: Vec<u8>) -> Self {
        Self {
            authenticated: true,
            public_key,
            authenticated_at: Instant::now(),
            reputation: DEFAULT_REPUTATION,
        }
    }
}

/// Authorization policy types, mirroring `channel.AllowedPeerPolicyType` from
/// Go. Each gRPC service or method is assigned a policy that controls which
/// peers may call it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedPeerPolicy {
    /// Any peer with a valid mTLS connection.
    AnyPeer,
    /// Only the node's own peer ID.
    OnlySelfPeer,
    /// Any peer registered as a prover (any shard or global).
    AnyProverPeer,
    /// Only peers registered as global provers.
    OnlyGlobalProverPeer,
    /// Only peers that are provers on the same shard.
    OnlyShardProverPeer,
    /// Only explicitly whitelisted peer IDs.
    OnlyWhitelistedPeers,
}

/// Manages peer authentication state, challenge-response flows, and reputation
/// tracking.
///
/// This mirrors the core fields from `PeerAuthenticator` in Go:
///
/// - **authenticated_peers** corresponds to the auth cache maps
///   (`anyProverCache`, `globalProverCache`, `shardProverCache`) but unified
///   into a single map keyed by `PeerId`.
/// - **auth_challenges** holds pending random challenges for peers that have
///   not yet completed authentication.
/// - **service_policies** / **method_policies** mirror the Go struct's
///   `servicePolicies` and `methodPolicies` for per-RPC authorization.
pub struct PeerAuthenticator {
    /// Peers that have completed authentication.
    authenticated_peers: HashMap<PeerId, AuthState>,
    /// Pending challenges awaiting a signed response.
    auth_challenges: HashMap<PeerId, Vec<u8>>,
    /// Per-service authorization policies (key: "package.Service").
    service_policies: HashMap<String, AllowedPeerPolicy>,
    /// Per-method authorization policies (key: "/package.Service/Method").
    method_policies: HashMap<String, AllowedPeerPolicy>,
    /// Whitelisted peer IDs that bypass prover checks.
    whitelisted_peers: HashMap<PeerId, ()>,
    /// This node's own peer ID.
    self_peer_id: Option<PeerId>,
}

impl PeerAuthenticator {
    /// Empty authenticator with no authenticated peers or pending challenges.
    pub fn new() -> Self {
        Self {
            authenticated_peers: HashMap::new(),
            auth_challenges: HashMap::new(),
            service_policies: HashMap::new(),
            method_policies: HashMap::new(),
            whitelisted_peers: HashMap::new(),
            self_peer_id: None,
        }
    }

    /// Create an authenticator pre-configured with policies and whitelisted
    /// peers, matching the Go constructor `NewPeerAuthenticator`.
    pub fn with_config(
        self_peer_id: PeerId,
        whitelisted_peers: &[PeerId],
        service_policies: HashMap<String, AllowedPeerPolicy>,
        method_policies: HashMap<String, AllowedPeerPolicy>,
    ) -> Self {
        let mut wl = HashMap::new();
        for p in whitelisted_peers {
            wl.insert(*p, ());
        }
        Self {
            authenticated_peers: HashMap::new(),
            auth_challenges: HashMap::new(),
            service_policies,
            method_policies,
            whitelisted_peers: wl,
            self_peer_id: Some(self_peer_id),
        }
    }

    /// Returns `true` if the peer has a valid, authenticated entry.
    pub fn is_authenticated(&self, peer: &PeerId) -> bool {
        self.authenticated_peers
            .get(peer)
            .map_or(false, |s| s.authenticated)
    }

    /// Generate a random 32-byte challenge for the given peer. The challenge
    /// is stored internally; the caller sends it to the peer who must return
    /// an Ed448 signature over the challenge bytes.
    ///
    /// If a challenge already exists for this peer it is replaced.
    pub fn create_challenge(&mut self, peer: &PeerId) -> Vec<u8> {
        let mut challenge = vec![0u8; CHALLENGE_LENGTH];
        rand::thread_rng().fill_bytes(&mut challenge);
        self.auth_challenges.insert(*peer, challenge.clone());
        challenge
    }

    /// Verify an Ed448 signature (`response`) over a previously issued
    /// challenge. On success the peer is marked as authenticated with the
    /// given `public_key`.
    ///
    /// Returns `false` if:
    /// - No pending challenge exists for this peer.
    /// - The public key is not exactly 57 bytes.
    /// - The Ed448 signature verification fails.
    pub fn verify_challenge_response(
        &mut self,
        peer: &PeerId,
        response: &[u8],
        public_key: &[u8],
    ) -> bool {
        // Retrieve and consume the pending challenge.
        let challenge = match self.auth_challenges.remove(peer) {
            Some(c) => c,
            None => return false,
        };

        if public_key.len() != ED448_KEY_LENGTH {
            return false;
        }

        // Attempt to construct the Ed448 public key and verify.
        let pk = match ed448_rust::PublicKey::try_from(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // The Go implementation uses ed448.Verify with an empty context string.
        // ed448_rust::PublicKey::verify uses None for no context (equivalent to
        // empty string "").
        if pk.verify(&challenge, response, None).is_ok() {
            self.authenticate(peer, public_key.to_vec());
            true
        } else {
            false
        }
    }

    /// Explicitly mark a peer as authenticated with the given Ed448 public
    /// key. This is the direct path (e.g., after mTLS certificate
    /// verification), bypassing challenge-response.
    pub fn authenticate(&mut self, peer: &PeerId, public_key: Vec<u8>) {
        self.authenticated_peers
            .insert(*peer, AuthState::new(public_key));
        // Clear any pending challenge since the peer is now authenticated.
        self.auth_challenges.remove(peer);
    }

    /// Remove a peer's authentication, equivalent to cache expiry in the Go
    /// implementation.
    pub fn deauthenticate(&mut self, peer: &PeerId) {
        self.authenticated_peers.remove(peer);
        self.auth_challenges.remove(peer);
    }

    /// Adjust the reputation of an authenticated peer by `delta`. The value
    /// is clamped to `[MIN_REPUTATION, MAX_REPUTATION]`.
    ///
    /// If the peer is not authenticated this is a no-op.
    pub fn update_reputation(&mut self, peer: &PeerId, delta: f64) {
        if let Some(state) = self.authenticated_peers.get_mut(peer) {
            state.reputation = (state.reputation + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        }
    }

    /// Query the reputation of a peer. Returns `0.0` if the peer is not
    /// authenticated.
    pub fn get_reputation(&self, peer: &PeerId) -> f64 {
        self.authenticated_peers
            .get(peer)
            .map_or(0.0, |s| s.reputation)
    }

    /// Remove authentication entries older than `max_age`, mirroring the
    /// 10-second `authCacheTTL` cleanup in Go's `cacheAllows`.
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.authenticated_peers
            .retain(|_, state| state.authenticated_at > cutoff);
    }

    /// Resolve the authorization policy for a fully-qualified gRPC method
    /// name (e.g., "/package.Service/Method"). Checks method-level policies
    /// first, then service-level, defaulting to `OnlySelfPeer` (strictest)
    /// if no policy is defined -- matching the Go fallthrough behavior.
    pub fn policy_for(&self, full_method: &str) -> AllowedPeerPolicy {
        // Check method-level policy first.
        if let Some(&pol) = self.method_policies.get(full_method) {
            return pol;
        }

        // Extract "package.Service" from "/package.Service/Method".
        let svc = full_method.strip_prefix('/').unwrap_or(full_method);
        let svc = match svc.find('/') {
            Some(i) => &svc[..i],
            None => svc,
        };

        if let Some(&pol) = self.service_policies.get(svc) {
            return pol;
        }

        // Strictest fallback -- same as Go.
        AllowedPeerPolicy::OnlySelfPeer
    }

    /// Check whether a peer is authorized under the given policy. This
    /// mirrors `authorize` in Go, unifying the various `is*Prover` checks
    /// into a single entry point.
    ///
    /// Note: `AnyProverPeer`, `OnlyGlobalProverPeer`, and
    /// `OnlyShardProverPeer` currently check `is_authenticated` as a proxy
    /// for prover-registry membership. Full prover-registry integration
    /// (poseidon address derivation, allocation filter matching) will be
    /// added when the prover registry crate is ported.
    pub fn authorize(&self, peer: &PeerId, policy: AllowedPeerPolicy) -> bool {
        match policy {
            AllowedPeerPolicy::AnyPeer => true,
            AllowedPeerPolicy::OnlySelfPeer => {
                self.self_peer_id.as_ref() == Some(peer)
            }
            AllowedPeerPolicy::AnyProverPeer
            | AllowedPeerPolicy::OnlyGlobalProverPeer
            | AllowedPeerPolicy::OnlyShardProverPeer => {
                // Placeholder: full prover-registry check will replace this.
                self.is_authenticated(peer)
            }
            AllowedPeerPolicy::OnlyWhitelistedPeers => {
                self.whitelisted_peers.contains_key(peer)
            }
        }
    }

    /// Convenience: resolve the policy for `full_method` and authorize `peer`
    /// against it.
    pub fn authorize_method(&self, peer: &PeerId, full_method: &str) -> bool {
        let policy = self.policy_for(full_method);
        self.authorize(peer, policy)
    }

    /// Returns the number of currently authenticated peers.
    pub fn authenticated_count(&self) -> usize {
        self.authenticated_peers.len()
    }

    /// Returns the number of pending (unanswered) challenges.
    pub fn pending_challenges(&self) -> usize {
        self.auth_challenges.len()
    }

    /// Register a service-level policy.
    pub fn set_service_policy(&mut self, service: String, policy: AllowedPeerPolicy) {
        self.service_policies.insert(service, policy);
    }

    /// Register a method-level policy.
    pub fn set_method_policy(&mut self, method: String, policy: AllowedPeerPolicy) {
        self.method_policies.insert(method, policy);
    }

    /// Set the node's own peer ID (used for `OnlySelfPeer` policy checks).
    pub fn set_self_peer_id(&mut self, peer_id: PeerId) {
        self.self_peer_id = Some(peer_id);
    }

    /// Add a peer to the whitelist.
    pub fn add_whitelisted_peer(&mut self, peer: PeerId) {
        self.whitelisted_peers.insert(peer, ());
    }
}

impl Default for PeerAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed448_rust::PrivateKey as Ed448PrivateKey;
    use ed448_rust::PublicKey as Ed448PublicKey;
    use rand::rngs::OsRng;

    /// Helper: generate an Ed448 keypair and return (private, public_bytes).
    fn gen_keypair() -> (Ed448PrivateKey, Vec<u8>) {
        let privkey = Ed448PrivateKey::new(&mut OsRng);
        let pubkey = Ed448PublicKey::from(&privkey);
        (privkey, pubkey.as_byte().to_vec())
    }

    /// Helper: produce a random PeerId for testing.
    fn test_peer_id(_index: u8) -> PeerId {
        PeerId::random()
    }

    // ---------------------------------------------------------------
    // Challenge-response flow
    // ---------------------------------------------------------------

    #[test]
    fn challenge_response_success() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(1);
        let (privkey, pubkey_bytes) = gen_keypair();

        // Issue challenge.
        let challenge = auth.create_challenge(&peer);
        assert_eq!(challenge.len(), CHALLENGE_LENGTH);
        assert_eq!(auth.pending_challenges(), 1);
        assert!(!auth.is_authenticated(&peer));

        // Sign challenge with Ed448 private key.
        let signature = privkey.sign(&challenge, None).expect("sign failed");

        // Verify.
        let ok = auth.verify_challenge_response(&peer, &signature, &pubkey_bytes);
        assert!(ok);
        assert!(auth.is_authenticated(&peer));
        assert_eq!(auth.pending_challenges(), 0);
    }

    #[test]
    fn challenge_response_wrong_key() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(2);
        let (privkey, _pubkey_bytes) = gen_keypair();
        let (_other_privkey, other_pubkey_bytes) = gen_keypair();

        let challenge = auth.create_challenge(&peer);
        let signature = privkey.sign(&challenge, None).expect("sign failed");

        // Verify with wrong public key -- should fail.
        let ok = auth.verify_challenge_response(&peer, &signature, &other_pubkey_bytes);
        assert!(!ok);
        assert!(!auth.is_authenticated(&peer));
        // Challenge was consumed even on failure.
        assert_eq!(auth.pending_challenges(), 0);
    }

    #[test]
    fn challenge_response_wrong_signature() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(3);
        let (_privkey, pubkey_bytes) = gen_keypair();

        let _challenge = auth.create_challenge(&peer);

        // Provide a garbage signature.
        let bad_sig = vec![0xAB; 114];
        let ok = auth.verify_challenge_response(&peer, &bad_sig, &pubkey_bytes);
        assert!(!ok);
        assert!(!auth.is_authenticated(&peer));
    }

    #[test]
    fn challenge_response_no_pending_challenge() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(4);
        let (privkey, pubkey_bytes) = gen_keypair();

        // No challenge was issued.
        let sig = privkey.sign(b"arbitrary", None).expect("sign failed");
        let ok = auth.verify_challenge_response(&peer, &sig, &pubkey_bytes);
        assert!(!ok);
    }

    #[test]
    fn challenge_response_bad_pubkey_length() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(5);

        let _challenge = auth.create_challenge(&peer);

        // Public key too short.
        let ok = auth.verify_challenge_response(&peer, &[0; 114], &[0; 32]);
        assert!(!ok);
    }

    #[test]
    fn challenge_replaces_previous() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(6);
        let (privkey, pubkey_bytes) = gen_keypair();

        // Issue two challenges -- second should replace first.
        let _challenge1 = auth.create_challenge(&peer);
        let challenge2 = auth.create_challenge(&peer);
        assert_eq!(auth.pending_challenges(), 1);

        // Sign the second challenge.
        let sig = privkey.sign(&challenge2, None).expect("sign failed");
        assert!(auth.verify_challenge_response(&peer, &sig, &pubkey_bytes));
    }

    // ---------------------------------------------------------------
    // Direct authenticate / deauthenticate
    // ---------------------------------------------------------------

    #[test]
    fn authenticate_and_deauthenticate() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(7);

        assert!(!auth.is_authenticated(&peer));
        auth.authenticate(&peer, vec![0; 57]);
        assert!(auth.is_authenticated(&peer));
        assert_eq!(auth.authenticated_count(), 1);

        auth.deauthenticate(&peer);
        assert!(!auth.is_authenticated(&peer));
        assert_eq!(auth.authenticated_count(), 0);
    }

    #[test]
    fn authenticate_clears_pending_challenge() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(8);

        let _challenge = auth.create_challenge(&peer);
        assert_eq!(auth.pending_challenges(), 1);

        auth.authenticate(&peer, vec![0; 57]);
        assert_eq!(auth.pending_challenges(), 0);
    }

    // ---------------------------------------------------------------
    // Reputation tracking
    // ---------------------------------------------------------------

    #[test]
    fn reputation_default() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(9);

        // Unauthenticated peer has 0.0 reputation.
        assert_eq!(auth.get_reputation(&peer), 0.0);

        // After authentication, starts at DEFAULT_REPUTATION.
        auth.authenticate(&peer, vec![0; 57]);
        assert!((auth.get_reputation(&peer) - DEFAULT_REPUTATION).abs() < f64::EPSILON);
    }

    #[test]
    fn reputation_update_positive() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(10);
        auth.authenticate(&peer, vec![0; 57]);

        auth.update_reputation(&peer, 5.0);
        assert!((auth.get_reputation(&peer) - (DEFAULT_REPUTATION + 5.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn reputation_update_negative() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(11);
        auth.authenticate(&peer, vec![0; 57]);

        auth.update_reputation(&peer, -10.0);
        assert!(
            (auth.get_reputation(&peer) - (DEFAULT_REPUTATION - 10.0)).abs() < f64::EPSILON
        );
    }

    #[test]
    fn reputation_clamped_at_max() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(12);
        auth.authenticate(&peer, vec![0; 57]);

        auth.update_reputation(&peer, 999.0);
        assert!((auth.get_reputation(&peer) - MAX_REPUTATION).abs() < f64::EPSILON);
    }

    #[test]
    fn reputation_clamped_at_min() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(13);
        auth.authenticate(&peer, vec![0; 57]);

        auth.update_reputation(&peer, -999.0);
        assert!((auth.get_reputation(&peer) - MIN_REPUTATION).abs() < f64::EPSILON);
    }

    #[test]
    fn reputation_noop_for_unauthenticated() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(14);

        // No-op for unauthenticated peer.
        auth.update_reputation(&peer, 5.0);
        assert_eq!(auth.get_reputation(&peer), 0.0);
    }

    // ---------------------------------------------------------------
    // Stale cleanup
    // ---------------------------------------------------------------

    #[test]
    fn cleanup_stale_removes_old_entries() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(15);
        auth.authenticate(&peer, vec![0; 57]);

        // With a zero max_age, everything is stale immediately.
        auth.cleanup_stale(Duration::from_secs(0));
        assert!(!auth.is_authenticated(&peer));
        assert_eq!(auth.authenticated_count(), 0);
    }

    #[test]
    fn cleanup_stale_keeps_recent() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(16);
        auth.authenticate(&peer, vec![0; 57]);

        // With a generous max_age, the entry remains.
        auth.cleanup_stale(Duration::from_secs(3600));
        assert!(auth.is_authenticated(&peer));
    }

    // ---------------------------------------------------------------
    // Policy resolution
    // ---------------------------------------------------------------

    #[test]
    fn policy_method_overrides_service() {
        let mut auth = PeerAuthenticator::new();
        auth.set_service_policy(
            "quilibrium.node.NodeService".to_string(),
            AllowedPeerPolicy::AnyPeer,
        );
        auth.set_method_policy(
            "/quilibrium.node.NodeService/GetFrameInfo".to_string(),
            AllowedPeerPolicy::OnlyGlobalProverPeer,
        );

        // Method-level wins.
        assert_eq!(
            auth.policy_for("/quilibrium.node.NodeService/GetFrameInfo"),
            AllowedPeerPolicy::OnlyGlobalProverPeer,
        );

        // Other methods fall back to service-level.
        assert_eq!(
            auth.policy_for("/quilibrium.node.NodeService/OtherMethod"),
            AllowedPeerPolicy::AnyPeer,
        );
    }

    #[test]
    fn policy_default_is_strictest() {
        let auth = PeerAuthenticator::new();
        assert_eq!(
            auth.policy_for("/unknown.Service/Method"),
            AllowedPeerPolicy::OnlySelfPeer,
        );
    }

    // ---------------------------------------------------------------
    // Authorization
    // ---------------------------------------------------------------

    #[test]
    fn authorize_any_peer() {
        let auth = PeerAuthenticator::new();
        let peer = test_peer_id(17);
        assert!(auth.authorize(&peer, AllowedPeerPolicy::AnyPeer));
    }

    #[test]
    fn authorize_self_peer() {
        let self_id = PeerId::random();
        let other_id = PeerId::random();
        let mut auth = PeerAuthenticator::new();
        auth.set_self_peer_id(self_id);
        assert!(auth.authorize(&self_id, AllowedPeerPolicy::OnlySelfPeer));
        assert!(!auth.authorize(&other_id, AllowedPeerPolicy::OnlySelfPeer));
    }

    #[test]
    fn authorize_whitelisted() {
        let wl_peer = PeerId::random();
        let other = PeerId::random();
        let mut auth = PeerAuthenticator::new();
        auth.add_whitelisted_peer(wl_peer);
        assert!(auth.authorize(&wl_peer, AllowedPeerPolicy::OnlyWhitelistedPeers));
        assert!(!auth.authorize(&other, AllowedPeerPolicy::OnlyWhitelistedPeers));
    }

    #[test]
    fn authorize_prover_requires_auth() {
        let mut auth = PeerAuthenticator::new();
        let peer = test_peer_id(18);

        // Not authenticated -> denied.
        assert!(!auth.authorize(&peer, AllowedPeerPolicy::AnyProverPeer));

        // Authenticated -> allowed (placeholder until prover registry).
        auth.authenticate(&peer, vec![0; 57]);
        assert!(auth.authorize(&peer, AllowedPeerPolicy::AnyProverPeer));
    }

    #[test]
    fn authorize_method_integration() {
        let self_id = PeerId::random();
        let mut auth = PeerAuthenticator::new();
        auth.set_self_peer_id(self_id);
        auth.set_service_policy(
            "quilibrium.node.NodeService".to_string(),
            AllowedPeerPolicy::AnyPeer,
        );

        let other = PeerId::random();
        assert!(auth.authorize_method(&other, "/quilibrium.node.NodeService/GetInfo"));

        // Undefined service falls back to OnlySelfPeer.
        assert!(!auth.authorize_method(&other, "/other.Service/Method"));
        assert!(auth.authorize_method(&self_id, "/other.Service/Method"));
    }
}
