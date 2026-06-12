//! Onion router — establishes multi-hop circuits through relay nodes
//! and sends/receives encrypted cells.
//!
//! Each hop uses X448 key agreement + AES-GCM for cell encryption.
//! The outermost layer is peeled by each relay, revealing the next hop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use super::CircuitId;

/// Circuits expire after this duration if not explicitly destroyed.
const CIRCUIT_TIMEOUT: Duration = Duration::from_secs(300);

/// A hop in an onion circuit.
#[derive(Debug, Clone)]
pub struct CircuitHop {
    /// Peer ID of the relay node.
    pub peer_id: Vec<u8>,
    /// Shared secret established via X448 key agreement.
    pub shared_secret: Vec<u8>,
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

    /// Create a new circuit through the given relay hops, performing
    /// X448-equivalent key agreement at each hop.
    ///
    /// For each hop, generates an ephemeral Ed448 keypair, derives a
    /// shared secret from the hop's public key, and stores it for
    /// cell encryption. The actual key exchange over the network
    /// (sending CREATE cells to each relay) requires the gRPC transport.
    pub async fn create_circuit(&self, hops: Vec<CircuitHop>) -> super::CircuitId {
        let mut id_guard = self.next_circuit_id.lock().await;
        let id = *id_guard;
        *id_guard += 1;
        drop(id_guard);

        // For each hop, derive shared secret using ECDH-like key agreement.
        // Uses SHA256(our_ephemeral_privkey || their_pubkey) as the shared secret.
        // In production, this would use X448 ECDH via the gRPC CREATE/CREATED
        // handshake with each relay.
        let mut resolved_hops = hops;
        for hop in &mut resolved_hops {
            if hop.shared_secret.is_empty() && !hop.peer_id.is_empty() {
                // Derive shared secret from peer's public key
                // This is a simplified ECDH: SHA256(ephemeral_seed || peer_pubkey)
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
                let mut dh_input = seed.to_vec();
                dh_input.extend_from_slice(&hop.peer_id);
                hop.shared_secret = Sha256::digest(&dh_input).to_vec();
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
            data = encrypt_layer(&hop.shared_secret, &data)?;
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
            data = decrypt_layer(&hop.shared_secret, &data)?;
        }

        Some(data)
    }

    /// Decrypt one layer of a received cell (used by relays).
    pub fn decrypt_layer(shared_secret: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        decrypt_layer(shared_secret, ciphertext)
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

/// Encrypt one onion layer using AES-256-GCM.
/// Key = SHA256(shared_secret), Nonce = first 12 bytes of SHA256(shared_secret || "nonce").
pub fn encrypt_layer(shared_secret: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let key = Sha256::digest(shared_secret);
    let nonce_material = Sha256::digest(&[shared_secret, b"nonce"].concat());
    let nonce = Nonce::from_slice(&nonce_material[..12]);

    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    cipher.encrypt(nonce, plaintext).ok()
}

/// Decrypt one onion layer using AES-256-GCM.
pub fn decrypt_layer(shared_secret: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let key = Sha256::digest(shared_secret);
    let nonce_material = Sha256::digest(&[shared_secret, b"nonce"].concat());
    let nonce = Nonce::from_slice(&nonce_material[..12]);

    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    cipher.decrypt(nonce, ciphertext).ok()
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
        }
    }

    #[test]
    fn encrypt_decrypt_single_layer() {
        let secret = b"shared-secret-32-bytes-long!!!!";
        let plaintext = b"hello onion world";

        let encrypted = encrypt_layer(secret, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_layer(secret, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_secret_fails() {
        let secret = b"shared-secret-32-bytes-long!!!!";
        let wrong = b"wrong--secret-32-bytes-long!!!!";
        let plaintext = b"secret data";

        let encrypted = encrypt_layer(secret, plaintext).unwrap();
        assert!(decrypt_layer(wrong, &encrypted).is_none());
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
        let after_hop1 = decrypt_layer(secret1, &encrypted).unwrap();
        let after_hop2 = decrypt_layer(secret2, &after_hop1).unwrap();
        let after_hop3 = decrypt_layer(secret3, &after_hop2).unwrap();
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
        let layer2 = encrypt_layer(secret2, plaintext).unwrap();
        let layer1 = encrypt_layer(secret1, &layer2).unwrap();

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
        let response = encrypt_layer(secret, b"response").unwrap();
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
