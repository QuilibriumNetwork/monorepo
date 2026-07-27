//! Onion router — establishes multi-hop circuits through relay nodes
//! and sends/receives encrypted cells.
//!
//! Each hop uses a POST-QUANTUM sntrup761 KEM key agreement (replaces X448
//! ECDH) + AES-GCM for cell encryption. The outermost layer is peeled by each
//! relay, revealing the next hop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use super::CircuitId;

/// Circuits expire after this duration if not explicitly destroyed.
const CIRCUIT_TIMEOUT: Duration = Duration::from_secs(300);

/// A hop in an onion circuit.
#[derive(Debug, Clone, Default)]
pub struct CircuitHop {
    /// Peer ID of the relay node.
    pub peer_id: Vec<u8>,
    /// The relay's sntrup761 onion PUBLIC key. The initiator KEM-encapsulates to
    /// this to derive `shared_secret` (post-quantum; replaces X448).
    pub kem_public_key: Vec<u8>,
    /// Shared secret established via sntrup761 KEM encapsulation.
    pub shared_secret: Vec<u8>,
    /// KEM ciphertext to deliver in this hop's CREATE cell; the relay
    /// decapsulates it (with its onion secret key) to recover `shared_secret`.
    /// Empty until encapsulation runs in [`OnionRouter::create_circuit`].
    pub create_ciphertext: Vec<u8>,
    /// Multiaddr of the relay.
    pub addr: String,
}

/// Per-circuit byte counters.
#[derive(Debug, Default)]
pub struct CircuitStats {
    /// Total bytes sent through this circuit.
    pub total_bytes_sent: AtomicU64,
    /// Total bytes received through this circuit.
    pub total_bytes_received: AtomicU64,
}

/// An established onion circuit.
#[derive(Debug)]
pub struct Circuit {
    pub id: CircuitId,
    pub hops: Vec<CircuitHop>,
    pub created_at: Instant,
    /// Per-circuit traffic statistics.
    pub stats: CircuitStats,
}

impl Circuit {
    /// Returns true if this circuit has exceeded the timeout duration.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= CIRCUIT_TIMEOUT
    }

    /// Record bytes sent through this circuit.
    pub fn record_sent(&self, bytes: u64) {
        self.stats.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes received through this circuit.
    pub fn record_received(&self, bytes: u64) {
        self.stats.total_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get a snapshot of the current statistics.
    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.stats.total_bytes_sent.load(Ordering::Relaxed),
            self.stats.total_bytes_received.load(Ordering::Relaxed),
        )
    }
}

/// Onion router that manages circuits.
pub struct OnionRouter {
    circuits: Mutex<HashMap<CircuitId, Circuit>>,
    next_circuit_id: Mutex<CircuitId>,
}

impl OnionRouter {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(HashMap::new()),
            next_circuit_id: Mutex::new(1),
        }
    }

    /// Create a new circuit through the given relay hops, performing a
    /// POST-QUANTUM sntrup761 KEM key agreement at each hop.
    ///
    /// For each hop with a `kem_public_key`, encapsulates to it — deriving the
    /// per-hop `shared_secret` (which keys the AES-GCM layer) and the
    /// `create_ciphertext` that the (gRPC) transport delivers in the hop's CREATE
    /// cell, where the relay decapsulates it with its onion secret key. A hop that
    /// already carries a `shared_secret`, or has no `kem_public_key`, is left as
    /// is (test / pre-negotiated circuits).
    pub async fn create_circuit(&self, hops: Vec<CircuitHop>) -> super::CircuitId {
        let mut id_guard = self.next_circuit_id.lock().await;
        let id = *id_guard;
        *id_guard += 1;
        drop(id_guard);

        // Post-quantum per-hop key agreement: sntrup761 KEM encapsulation to the
        // relay's onion public key (replaces the classical X448 ECDH). The shared
        // secret never crosses the wire; only the ciphertext does.
        let mut resolved_hops = hops;
        for hop in &mut resolved_hops {
            if hop.shared_secret.is_empty() && !hop.kem_public_key.is_empty() {
                if let Some((ss, ct)) = super::onion_kem_encapsulate(&hop.kem_public_key) {
                    hop.shared_secret = ss;
                    hop.create_ciphertext = ct;
                } else {
                    tracing::warn!(
                        circuit_id = id,
                        "onion hop KEM encapsulation failed (bad onion public key)"
                    );
                }
            }
        }

        let hop_count = resolved_hops.len();
        let circuit = Circuit {
            id,
            hops: resolved_hops,
            created_at: Instant::now(),
            stats: CircuitStats::default(),
        };
        self.circuits.lock().await.insert(id, circuit);
        tracing::debug!(circuit_id = id, hops = hop_count, "onion circuit created");
        id
    }

    /// Destroy a circuit.
    pub async fn destroy_circuit(&self, id: CircuitId) {
        if let Some(circuit) = self.circuits.lock().await.remove(&id) {
            let (sent, recv) = circuit.get_stats();
            tracing::debug!(
                circuit_id = id,
                bytes_sent = sent,
                bytes_received = recv,
                "onion circuit destroyed"
            );
        }
    }

    /// Get the number of active circuits.
    pub async fn active_circuits(&self) -> usize {
        self.circuits.lock().await.len()
    }

    /// Look up a circuit by its ID. Returns a clone-friendly snapshot
    /// containing the circuit's id, hops, creation time, and current stats.
    pub async fn get_circuit(&self, id: CircuitId) -> Option<CircuitSnapshot> {
        let circuits = self.circuits.lock().await;
        let circuit = circuits.get(&id)?;
        let (sent, recv) = circuit.get_stats();
        Some(CircuitSnapshot {
            id: circuit.id,
            hops: circuit.hops.clone(),
            created_at: circuit.created_at,
            total_bytes_sent: sent,
            total_bytes_received: recv,
        })
    }

    /// Remove all circuits that have exceeded the timeout (5 minutes).
    /// Returns the number of circuits cleaned up.
    pub async fn cleanup_stale_circuits(&self) -> usize {
        let mut circuits = self.circuits.lock().await;
        let before = circuits.len();
        circuits.retain(|id, circuit| {
            let expired = circuit.is_expired();
            if expired {
                let (sent, recv) = circuit.get_stats();
                tracing::debug!(
                    circuit_id = id,
                    age_secs = circuit.created_at.elapsed().as_secs(),
                    bytes_sent = sent,
                    bytes_received = recv,
                    "stale circuit removed"
                );
            }
            !expired
        });
        let removed = before - circuits.len();
        if removed > 0 {
            tracing::debug!(removed, remaining = circuits.len(), "stale circuit cleanup");
        }
        removed
    }

    /// Encrypt data through all layers of a circuit (onion wrapping).
    /// Each layer uses AES-256-GCM with the hop's shared secret.
    /// Layers are applied in reverse order (last hop first).
    /// Updates the circuit's bytes_sent counter.
    pub async fn encrypt_cell(&self, circuit_id: CircuitId, plaintext: &[u8]) -> Option<Vec<u8>> {
        let circuits = self.circuits.lock().await;
        let circuit = circuits.get(&circuit_id)?;

        let mut data = plaintext.to_vec();

        // Wrap in reverse order — last hop's layer goes on first
        for hop in circuit.hops.iter().rev() {
            data = encrypt_layer(&hop.shared_secret, LAYER_FORWARD, &data)?;
        }

        circuit.record_sent(data.len() as u64);
        Some(data)
    }

    /// Decrypt ALL layers of a received cell, peeling each hop's encryption
    /// in forward order. Used by the circuit endpoint (originator) to
    /// fully unwrap a response that was wrapped by each relay on the
    /// return path.
    pub async fn decrypt_cell_layers(
        &self,
        circuit_id: CircuitId,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let circuits = self.circuits.lock().await;
        let circuit = circuits.get(&circuit_id)?;

        circuit.record_received(ciphertext.len() as u64);

        let mut data = ciphertext.to_vec();

        // Peel layers in forward order — first hop's layer is outermost
        for hop in &circuit.hops {
            data = decrypt_layer(&hop.shared_secret, LAYER_FORWARD, &data)?;
        }

        Some(data)
    }

    /// Decrypt one layer of a received cell (used by relays).
    pub fn decrypt_layer(shared_secret: &[u8], direction: u8, ciphertext: &[u8]) -> Option<Vec<u8>> {
        decrypt_layer(shared_secret, direction, ciphertext)
    }

    /// Get statistics for a specific circuit.
    pub async fn circuit_stats(&self, id: CircuitId) -> Option<(u64, u64)> {
        let circuits = self.circuits.lock().await;
        circuits.get(&id).map(|c| c.get_stats())
    }
}

/// A cloneable snapshot of a circuit's state, returned by `get_circuit`.
#[derive(Debug, Clone)]
pub struct CircuitSnapshot {
    pub id: CircuitId,
    pub hops: Vec<CircuitHop>,
    pub created_at: Instant,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Onion layer direction. FORWARD cells (originator → exit) and BACKWARD cells
/// (exit → originator) are encrypted under SEPARATE keys derived from the same
/// hop secret, so a captured cell cannot be reflected across directions and a
/// forward layer can't be replayed as a backward one (defeats the same-key
/// reflection where `decrypt(K, encrypt(K, x)) == x` regardless of direction).
pub const LAYER_FORWARD: u8 = 0;
pub const LAYER_BACKWARD: u8 = 1;

/// Directional, domain-separated AES-256-GCM key for an onion layer:
/// `SHA256("QOR-onion-layer-v1" ‖ direction ‖ hop_secret)`. The domain tag also
/// keeps this key distinct from the `created_confirmation` hash of the same
/// secret.
fn layer_key(shared_secret: &[u8], direction: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"QOR-onion-layer-v1");
    h.update([direction]);
    h.update(shared_secret);
    h.finalize().into()
}

/// Encrypt one onion layer using AES-256-GCM under the directional layer key.
///
/// A FRESH random 96-bit nonce is generated per call and PREPENDED to the
/// ciphertext. This is load-bearing: a hop's shared secret is static for the
/// life of the circuit and encrypts many cells, so a deterministic
/// (secret-derived) nonce would reuse `(key, nonce)` across cells — catastrophic
/// for AES-GCM (leaks plaintext XOR AND lets an attacker recover the GHASH key to
/// forge cells). The 12-byte overhead per layer is the cost of that safety.
pub fn encrypt_layer(shared_secret: &[u8], direction: u8, plaintext: &[u8]) -> Option<Vec<u8>> {
    let key = layer_key(shared_secret, direction);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let ct = cipher.encrypt(&nonce, plaintext).ok()?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt one onion layer: the first 12 bytes are the per-cell nonce, the rest
/// is the AES-256-GCM ciphertext under the directional layer key.
pub fn decrypt_layer(shared_secret: &[u8], direction: u8, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 12 {
        return None;
    }
    let key = layer_key(shared_secret, direction);
    let nonce = Nonce::from_slice(&ciphertext[..12]);

    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    cipher.decrypt(nonce, &ciphertext[12..]).ok()
}

impl Default for OnionRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hop(peer: &[u8], secret: &[u8]) -> CircuitHop {
        CircuitHop {
            peer_id: peer.to_vec(),
            shared_secret: secret.to_vec(),
            addr: "127.0.0.1:9000".to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn create_circuit_kem_encapsulates_to_onion_key() {
        // A hop that carries only the relay's sntrup761 onion public key (no
        // pre-set shared secret) must be filled in by KEM encapsulation.
        let (onion_pk, onion_sk) = crate::onion::onion_keypair();
        let router = OnionRouter::new();
        let hop = CircuitHop {
            peer_id: b"relay".to_vec(),
            kem_public_key: onion_pk,
            addr: "127.0.0.1:9000".to_string(),
            ..Default::default()
        };
        let cid = router.create_circuit(vec![hop]).await;

        let circuits = router.circuits.lock().await;
        let circuit = circuits.get(&cid).unwrap();
        let resolved = &circuit.hops[0];
        // Encapsulation produced a shared secret + a ciphertext of the right size.
        assert!(!resolved.shared_secret.is_empty());
        assert_eq!(
            resolved.create_ciphertext.len(),
            crate::onion::ONION_CIPHERTEXT_LEN
        );
        // The relay decapsulating that ciphertext recovers the identical secret.
        let relay_secret =
            crate::onion::onion_kem_decapsulate(&resolved.create_ciphertext, &onion_sk).unwrap();
        assert_eq!(relay_secret, resolved.shared_secret);
    }

    #[test]
    fn encrypt_decrypt_single_layer() {
        let secret = b"shared-secret-32-bytes-long!!!!";
        let plaintext = b"hello onion world";

        let encrypted = encrypt_layer(secret, LAYER_FORWARD, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_layer(secret, LAYER_FORWARD, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn directional_keys_prevent_cross_direction_reflection() {
        let secret = b"shared-secret-32-bytes-long!!!!";
        let fwd = encrypt_layer(secret, LAYER_FORWARD, b"cell").unwrap();
        // The matching direction peels.
        assert_eq!(decrypt_layer(secret, LAYER_FORWARD, &fwd).unwrap(), b"cell");
        // The opposite direction FAILS (different key) — a forward cell cannot be
        // reflected/replayed as a backward one under the same hop secret.
        assert!(decrypt_layer(secret, LAYER_BACKWARD, &fwd).is_none());
    }

    #[test]
    fn decrypt_wrong_secret_fails() {
        let secret = b"shared-secret-32-bytes-long!!!!";
        let wrong = b"wrong--secret-32-bytes-long!!!!";
        let plaintext = b"secret data";

        let encrypted = encrypt_layer(secret, LAYER_FORWARD, plaintext).unwrap();
        assert!(decrypt_layer(wrong, LAYER_FORWARD, &encrypted).is_none());
    }

    #[tokio::test]
    async fn circuit_lifecycle_create_and_destroy() {
        let router = OnionRouter::new();
        let hops = vec![
            make_hop(b"peer1", b"secret1-must-be-long-enough!!!!"),
            make_hop(b"peer2", b"secret2-must-be-long-enough!!!!"),
        ];

        let id = router.create_circuit(hops).await;
        assert_eq!(router.active_circuits().await, 1);

        let snapshot = router.get_circuit(id).await;
        assert!(snapshot.is_some());
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.hops.len(), 2);
        assert_eq!(snapshot.total_bytes_sent, 0);
        assert_eq!(snapshot.total_bytes_received, 0);

        router.destroy_circuit(id).await;
        assert_eq!(router.active_circuits().await, 0);
        assert!(router.get_circuit(id).await.is_none());
    }

    #[tokio::test]
    async fn circuit_encrypt_decrypt_roundtrip() {
        let router = OnionRouter::new();
        let secret1 = b"hop1-secret-32-bytes-long!!!!!!";
        let secret2 = b"hop2-secret-32-bytes-long!!!!!!";
        let secret3 = b"hop3-secret-32-bytes-long!!!!!!";

        let hops = vec![
            make_hop(b"peer1", secret1),
            make_hop(b"peer2", secret2),
            make_hop(b"peer3", secret3),
        ];

        let cid = router.create_circuit(hops).await;
        let plaintext = b"end-to-end secret message";

        // Encrypt through all layers (reverse order: 3, 2, 1)
        let encrypted = router.encrypt_cell(cid, plaintext).await.unwrap();
        assert_ne!(encrypted, plaintext.to_vec());

        // Simulate relay peeling: each relay peels one layer in forward order
        let after_hop1 = decrypt_layer(secret1, LAYER_FORWARD, &encrypted).unwrap();
        let after_hop2 = decrypt_layer(secret2, LAYER_FORWARD, &after_hop1).unwrap();
        let after_hop3 = decrypt_layer(secret3, LAYER_FORWARD, &after_hop2).unwrap();
        assert_eq!(after_hop3, plaintext);
    }

    #[tokio::test]
    async fn decrypt_cell_layers_full_unwrap() {
        let router = OnionRouter::new();
        let secret1 = b"hop1-secret-32-bytes-long!!!!!!";
        let secret2 = b"hop2-secret-32-bytes-long!!!!!!";

        let hops = vec![
            make_hop(b"peer1", secret1),
            make_hop(b"peer2", secret2),
        ];

        let cid = router.create_circuit(hops).await;
        let plaintext = b"response data from exit node";

        // Simulate a response wrapped by relays in reverse order (exit wraps
        // first, then intermediate) — same as encrypt_cell layering.
        let layer2 = encrypt_layer(secret2, LAYER_FORWARD, plaintext).unwrap();
        let layer1 = encrypt_layer(secret1, LAYER_FORWARD, &layer2).unwrap();

        // Originator peels all layers
        let result = router.decrypt_cell_layers(cid, &layer1).await.unwrap();
        assert_eq!(result, plaintext);
    }

    #[tokio::test]
    async fn circuit_stats_tracking() {
        let router = OnionRouter::new();
        let hops = vec![make_hop(b"peer1", b"secret1-must-be-long-enough!!!!")];
        let cid = router.create_circuit(hops).await;

        let plaintext = b"track these bytes";
        let _ = router.encrypt_cell(cid, plaintext).await.unwrap();

        let (sent, _recv) = router.circuit_stats(cid).await.unwrap();
        assert!(sent > 0, "bytes_sent should be nonzero after encrypt_cell");

        // Wrap a response so we can decrypt it
        let secret = b"secret1-must-be-long-enough!!!!";
        let response = encrypt_layer(secret, LAYER_FORWARD, b"response").unwrap();
        let _ = router.decrypt_cell_layers(cid, &response).await.unwrap();

        let (sent2, recv) = router.circuit_stats(cid).await.unwrap();
        assert_eq!(sent2, sent, "sent should not change from decrypt");
        assert!(recv > 0, "bytes_received should be nonzero after decrypt");
    }

    #[tokio::test]
    async fn get_circuit_nonexistent_returns_none() {
        let router = OnionRouter::new();
        assert!(router.get_circuit(999).await.is_none());
        assert!(router.circuit_stats(999).await.is_none());
    }

    #[tokio::test]
    async fn cleanup_stale_circuits_removes_expired() {
        let router = OnionRouter::new();
        let hops = vec![make_hop(b"peer1", b"secret1-must-be-long-enough!!!!")];
        let cid = router.create_circuit(hops).await;

        // Manually backdate the circuit's created_at to make it expired
        {
            let mut circuits = router.circuits.lock().await;
            let circuit = circuits.get_mut(&cid).unwrap();
            circuit.created_at = Instant::now() - Duration::from_secs(301);
        }

        let removed = router.cleanup_stale_circuits().await;
        assert_eq!(removed, 1);
        assert_eq!(router.active_circuits().await, 0);
    }

    #[tokio::test]
    async fn cleanup_keeps_fresh_circuits() {
        let router = OnionRouter::new();
        let hops = vec![make_hop(b"peer1", b"secret1-must-be-long-enough!!!!")];
        let _ = router.create_circuit(hops).await;

        let removed = router.cleanup_stale_circuits().await;
        assert_eq!(removed, 0);
        assert_eq!(router.active_circuits().await, 1);
    }

    #[tokio::test]
    async fn multiple_circuits_independent() {
        let router = OnionRouter::new();
        let id1 = router
            .create_circuit(vec![make_hop(b"p1", b"s1-must-be-long-enough-32bytes!")])
            .await;
        let id2 = router
            .create_circuit(vec![make_hop(b"p2", b"s2-must-be-long-enough-32bytes!")])
            .await;

        assert_ne!(id1, id2);
        assert_eq!(router.active_circuits().await, 2);

        router.destroy_circuit(id1).await;
        assert_eq!(router.active_circuits().await, 1);
        assert!(router.get_circuit(id2).await.is_some());
    }
}
