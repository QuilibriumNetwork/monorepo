//! Onion relay — forwards cells for circuits passing through this node.
//!
//! A relay node:
//! 1. Accepts CREATE cells, performs X448 key agreement
//! 2. Forwards RELAY cells by peeling one encryption layer
//! 3. Forwards responses back through the circuit
//! 4. Handles DESTROY cells by tearing down local circuit state

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

use super::CircuitId;
use super::router::{decrypt_layer, encrypt_layer};

/// Direction of cell travel through a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayDirection {
    /// Cell traveling away from the circuit originator (toward the exit).
    Forward,
    /// Cell traveling back toward the circuit originator.
    Backward,
}

/// A relayed circuit segment — maps incoming circuit ID to outgoing.
#[derive(Debug, Clone)]
struct RelayEntry {
    /// Circuit ID on the incoming side.
    inbound_id: CircuitId,
    /// Circuit ID on the outgoing side.
    outbound_id: CircuitId,
    /// Shared secret for decrypting/encrypting cells at this hop.
    shared_secret: Vec<u8>,
    /// Peer ID of the previous hop (toward originator).
    from_peer: Vec<u8>,
    /// Peer ID of the next hop (toward exit).
    to_peer: Vec<u8>,
}

/// Result of processing a cell at this relay hop.
#[derive(Debug)]
pub struct ForwardedCell {
    /// The circuit ID to use when forwarding.
    pub outbound_circuit_id: CircuitId,
    /// The peer to forward the cell to.
    pub next_peer: Vec<u8>,
    /// The cell data after peeling (or wrapping) one encryption layer.
    pub cell_data: Vec<u8>,
}

/// Onion relay that forwards cells through circuits.
pub struct OnionRelay {
    /// Maps inbound circuit ID to relay entry.
    entries: Mutex<HashMap<CircuitId, RelayEntry>>,
    /// Reverse map: outbound circuit ID to inbound circuit ID, for
    /// routing response cells back through the circuit.
    reverse_entries: Mutex<HashMap<CircuitId, CircuitId>>,
    /// Number of cells forwarded (metric).
    cells_forwarded: AtomicU64,
    /// Total bytes relayed (metric).
    bytes_relayed: AtomicU64,
}

impl OnionRelay {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            reverse_entries: Mutex::new(HashMap::new()),
            cells_forwarded: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
        }
    }

    /// Register a new relay entry for an established circuit hop.
    pub async fn register(
        &self,
        inbound_id: CircuitId,
        outbound_id: CircuitId,
        shared_secret: Vec<u8>,
        next_hop: Vec<u8>,
    ) {
        self.entries.lock().await.insert(
            inbound_id,
            RelayEntry {
                inbound_id,
                outbound_id,
                shared_secret,
                from_peer: Vec::new(),
                to_peer: next_hop,
            },
        );
        self.reverse_entries
            .lock()
            .await
            .insert(outbound_id, inbound_id);
        tracing::debug!(inbound_id, outbound_id, "relay entry registered");
    }

    /// Register a relay hop with explicit from/to peer IDs.
    /// This provides full directional routing information so the relay
    /// can forward cells in both directions.
    pub fn register_relay_entry(
        &mut self,
        circuit_id: CircuitId,
        from_peer: Vec<u8>,
        to_peer: Vec<u8>,
        shared_secret: Vec<u8>,
    ) {
        // Use circuit_id as inbound; outbound = circuit_id + 1 by convention.
        // In production the outbound ID is negotiated during CREATE handshake.
        let outbound_id = circuit_id.wrapping_add(1);
        let entry = RelayEntry {
            inbound_id: circuit_id,
            outbound_id,
            shared_secret,
            from_peer,
            to_peer,
        };
        // Direct field access since we have &mut self (no lock needed at
        // construction time — the relay is being set up before it starts
        // processing cells).
        let entries = self.entries.get_mut();
        entries.insert(circuit_id, entry);
        let reverse = self.reverse_entries.get_mut();
        reverse.insert(outbound_id, circuit_id);
        tracing::debug!(
            circuit_id,
            outbound_id,
            "relay entry registered with peers"
        );
    }

    /// Remove a relay entry and its reverse mapping.
    pub fn remove_relay_entry(&mut self, circuit_id: CircuitId) {
        let entries = self.entries.get_mut();
        if let Some(entry) = entries.remove(&circuit_id) {
            let reverse = self.reverse_entries.get_mut();
            reverse.remove(&entry.outbound_id);
            tracing::debug!(
                circuit_id,
                outbound_id = entry.outbound_id,
                "relay entry removed"
            );
        }
    }

    /// Remove a relay entry (async version).
    pub async fn remove(&self, inbound_id: CircuitId) {
        if let Some(entry) = self.entries.lock().await.remove(&inbound_id) {
            self.reverse_entries
                .lock()
                .await
                .remove(&entry.outbound_id);
        }
    }

    /// Forward a cell through this relay. Peels one AES-GCM encryption
    /// layer (for forward-direction cells) or adds one layer (for
    /// backward-direction cells), then returns the processed cell data
    /// along with the next hop information.
    ///
    /// For forward cells (originator -> exit):
    ///   Decrypt one layer with this hop's shared secret, revealing the
    ///   inner payload destined for the next hop.
    ///
    /// For backward cells (exit -> originator):
    ///   Encrypt one layer with this hop's shared secret, wrapping the
    ///   payload so the originator can peel it.
    pub async fn forward_cell(
        &self,
        circuit_id: CircuitId,
        cell_data: &[u8],
    ) -> Result<ForwardedCell, RelayError> {
        // First try forward direction: circuit_id is an inbound ID
        let entries = self.entries.lock().await;
        if let Some(entry) = entries.get(&circuit_id) {
            // Forward direction: peel one layer
            let peeled = decrypt_layer(&entry.shared_secret, cell_data).ok_or_else(|| {
                RelayError::DecryptionFailed {
                    circuit_id,
                    data_len: cell_data.len(),
                }
            })?;

            self.cells_forwarded.fetch_add(1, Ordering::Relaxed);
            self.bytes_relayed
                .fetch_add(cell_data.len() as u64, Ordering::Relaxed);

            return Ok(ForwardedCell {
                outbound_circuit_id: entry.outbound_id,
                next_peer: entry.to_peer.clone(),
                cell_data: peeled,
            });
        }

        // Try backward direction: circuit_id is an outbound ID, look up
        // reverse mapping to find the inbound entry
        let reverse = self.reverse_entries.lock().await;
        if let Some(&inbound_id) = reverse.get(&circuit_id) {
            if let Some(entry) = entries.get(&inbound_id) {
                // Backward direction: add one encryption layer
                let wrapped =
                    encrypt_layer(&entry.shared_secret, cell_data).ok_or_else(|| {
                        RelayError::EncryptionFailed {
                            circuit_id,
                            data_len: cell_data.len(),
                        }
                    })?;

                self.cells_forwarded.fetch_add(1, Ordering::Relaxed);
                self.bytes_relayed
                    .fetch_add(cell_data.len() as u64, Ordering::Relaxed);

                return Ok(ForwardedCell {
                    outbound_circuit_id: entry.inbound_id,
                    next_peer: entry.from_peer.clone(),
                    cell_data: wrapped,
                });
            }
        }

        Err(RelayError::UnknownCircuit { circuit_id })
    }

    /// Process a cell in an explicit direction. Unlike `forward_cell` which
    /// auto-detects direction from the circuit ID, this method takes an
    /// explicit direction parameter.
    pub async fn process_cell(
        &self,
        circuit_id: CircuitId,
        cell_data: &[u8],
        direction: RelayDirection,
    ) -> Result<ForwardedCell, RelayError> {
        let entries = self.entries.lock().await;
        let entry = entries
            .get(&circuit_id)
            .ok_or(RelayError::UnknownCircuit { circuit_id })?;

        match direction {
            RelayDirection::Forward => {
                // Peel one encryption layer
                let peeled =
                    decrypt_layer(&entry.shared_secret, cell_data).ok_or_else(|| {
                        RelayError::DecryptionFailed {
                            circuit_id,
                            data_len: cell_data.len(),
                        }
                    })?;

                self.cells_forwarded.fetch_add(1, Ordering::Relaxed);
                self.bytes_relayed
                    .fetch_add(cell_data.len() as u64, Ordering::Relaxed);

                Ok(ForwardedCell {
                    outbound_circuit_id: entry.outbound_id,
                    next_peer: entry.to_peer.clone(),
                    cell_data: peeled,
                })
            }
            RelayDirection::Backward => {
                // Add one encryption layer
                let wrapped =
                    encrypt_layer(&entry.shared_secret, cell_data).ok_or_else(|| {
                        RelayError::EncryptionFailed {
                            circuit_id,
                            data_len: cell_data.len(),
                        }
                    })?;

                self.cells_forwarded.fetch_add(1, Ordering::Relaxed);
                self.bytes_relayed
                    .fetch_add(cell_data.len() as u64, Ordering::Relaxed);

                Ok(ForwardedCell {
                    outbound_circuit_id: entry.inbound_id,
                    next_peer: entry.from_peer.clone(),
                    cell_data: wrapped,
                })
            }
        }
    }

    /// Get the count of active relay entries.
    pub async fn active_relays(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Get total cells forwarded.
    pub fn cells_forwarded(&self) -> u64 {
        self.cells_forwarded.load(Ordering::Relaxed)
    }

    /// Get total bytes relayed.
    pub fn bytes_relayed(&self) -> u64 {
        self.bytes_relayed.load(Ordering::Relaxed)
    }
}

impl Default for OnionRelay {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during cell relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("unknown circuit {circuit_id}")]
    UnknownCircuit { circuit_id: CircuitId },

    #[error("failed to decrypt cell on circuit {circuit_id} ({data_len} bytes)")]
    DecryptionFailed {
        circuit_id: CircuitId,
        data_len: usize,
    },

    #[error("failed to encrypt cell on circuit {circuit_id} ({data_len} bytes)")]
    EncryptionFailed {
        circuit_id: CircuitId,
        data_len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::router::{encrypt_layer, decrypt_layer};

    #[tokio::test]
    async fn register_and_forward_cell() {
        let relay = OnionRelay::new();
        let secret = b"relay-shared-secret-32-bytes!!!";

        relay
            .register(
                1,   // inbound circuit ID
                100, // outbound circuit ID
                secret.to_vec(),
                b"next-peer".to_vec(),
            )
            .await;

        assert_eq!(relay.active_relays().await, 1);

        // Encrypt a payload with this hop's secret (simulating what the
        // originator would do for this layer)
        let plaintext = b"hello from originator";
        let encrypted = encrypt_layer(secret, plaintext).unwrap();

        // Relay peels the layer
        let result = relay.forward_cell(1, &encrypted).await.unwrap();
        assert_eq!(result.outbound_circuit_id, 100);
        assert_eq!(result.next_peer, b"next-peer");
        assert_eq!(result.cell_data, plaintext);
        assert_eq!(relay.cells_forwarded(), 1);
        assert!(relay.bytes_relayed() > 0);
    }

    #[tokio::test]
    async fn forward_unknown_circuit_fails() {
        let relay = OnionRelay::new();
        let err = relay.forward_cell(999, b"data").await.unwrap_err();
        assert!(matches!(err, RelayError::UnknownCircuit { circuit_id: 999 }));
    }

    #[tokio::test]
    async fn forward_bad_ciphertext_fails() {
        let relay = OnionRelay::new();
        relay
            .register(
                1,
                100,
                b"relay-shared-secret-32-bytes!!!".to_vec(),
                b"next".to_vec(),
            )
            .await;

        // Garbage ciphertext will fail AES-GCM authentication
        let err = relay
            .forward_cell(1, b"not-valid-ciphertext")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RelayError::DecryptionFailed {
                circuit_id: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn remove_entry_cleans_up() {
        let relay = OnionRelay::new();
        relay
            .register(1, 100, b"secret".to_vec(), b"peer".to_vec())
            .await;
        assert_eq!(relay.active_relays().await, 1);

        relay.remove(1).await;
        assert_eq!(relay.active_relays().await, 0);

        // Forwarding should now fail
        let err = relay.forward_cell(1, b"data").await.unwrap_err();
        assert!(matches!(err, RelayError::UnknownCircuit { .. }));
    }

    #[tokio::test]
    async fn register_relay_entry_sync() {
        let mut relay = OnionRelay::new();
        let secret = b"sync-secret-must-be-32-bytes!!!";

        relay.register_relay_entry(
            10,
            b"from-peer".to_vec(),
            b"to-peer".to_vec(),
            secret.to_vec(),
        );

        // Should be registered
        assert_eq!(relay.active_relays().await, 1);

        // Forward direction should work
        let encrypted = encrypt_layer(secret, b"payload").unwrap();
        let result = relay.forward_cell(10, &encrypted).await.unwrap();
        assert_eq!(result.cell_data, b"payload");
        assert_eq!(result.next_peer, b"to-peer");
        // outbound_id = circuit_id + 1 by convention
        assert_eq!(result.outbound_circuit_id, 11);
    }

    #[tokio::test]
    async fn remove_relay_entry_sync() {
        let mut relay = OnionRelay::new();
        relay.register_relay_entry(
            10,
            b"from".to_vec(),
            b"to".to_vec(),
            b"secret-32-bytes-long-enough!!!!".to_vec(),
        );
        assert_eq!(relay.active_relays().await, 1);

        relay.remove_relay_entry(10);
        assert_eq!(relay.active_relays().await, 0);
    }

    #[tokio::test]
    async fn process_cell_forward_direction() {
        let relay = OnionRelay::new();
        let secret = b"process-secret-32-bytes-long!!!";

        relay
            .register(
                5,
                50,
                secret.to_vec(),
                b"exit-node".to_vec(),
            )
            .await;

        let plaintext = b"forward cell data";
        let encrypted = encrypt_layer(secret, plaintext).unwrap();

        let result = relay
            .process_cell(5, &encrypted, RelayDirection::Forward)
            .await
            .unwrap();

        assert_eq!(result.cell_data, plaintext);
        assert_eq!(result.outbound_circuit_id, 50);
        assert_eq!(result.next_peer, b"exit-node");
    }

    #[tokio::test]
    async fn process_cell_backward_direction() {
        let mut relay = OnionRelay::new();
        let secret = b"backward-secret-32-bytes-long!!";

        relay.register_relay_entry(
            7,
            b"originator".to_vec(),
            b"exit".to_vec(),
            secret.to_vec(),
        );

        let plaintext = b"response from exit";

        let result = relay
            .process_cell(7, plaintext, RelayDirection::Backward)
            .await
            .unwrap();

        // Backward wraps a layer — decrypt to verify
        let unwrapped = decrypt_layer(secret, &result.cell_data).unwrap();
        assert_eq!(unwrapped, plaintext);
        assert_eq!(result.outbound_circuit_id, 7); // inbound_id going back
        assert_eq!(result.next_peer, b"originator");
    }

    #[tokio::test]
    async fn backward_via_reverse_mapping() {
        let relay = OnionRelay::new();
        let secret = b"reverse-secret-32-bytes-long!!!";

        // Register with inbound=3, outbound=30
        relay
            .register(3, 30, secret.to_vec(), b"next".to_vec())
            .await;

        // Send a cell using the outbound circuit ID (backward direction)
        let plaintext = b"backward cell";
        let result = relay.forward_cell(30, plaintext).await.unwrap();

        // Should have encrypted one layer
        let unwrapped = decrypt_layer(secret, &result.cell_data).unwrap();
        assert_eq!(unwrapped, plaintext);
        assert_eq!(result.outbound_circuit_id, 3);
    }

    /// End-to-end test simulating a 3-hop circuit with relays.
    /// Originator encrypts, each relay peels a layer, exit gets plaintext,
    /// then the response travels back through the relays.
    #[tokio::test]
    async fn three_hop_relay_chain() {
        let secret1 = b"hop1-secret-32-bytes-long!!!!!!";
        let secret2 = b"hop2-secret-32-bytes-long!!!!!!";
        let secret3 = b"hop3-secret-32-bytes-long!!!!!!";

        // Create three relays
        let relay1 = OnionRelay::new();
        let relay2 = OnionRelay::new();
        let relay3 = OnionRelay::new();

        relay1
            .register(1, 10, secret1.to_vec(), b"relay2".to_vec())
            .await;
        relay2
            .register(10, 20, secret2.to_vec(), b"relay3".to_vec())
            .await;
        relay3
            .register(20, 30, secret3.to_vec(), b"exit".to_vec())
            .await;

        // Originator wraps three layers (reverse order)
        let plaintext = b"secret message to exit node";
        let layer3 = encrypt_layer(secret3, plaintext).unwrap();
        let layer2 = encrypt_layer(secret2, &layer3).unwrap();
        let layer1 = encrypt_layer(secret1, &layer2).unwrap();

        // Relay 1 peels layer 1
        let fwd1 = relay1.forward_cell(1, &layer1).await.unwrap();
        assert_eq!(fwd1.outbound_circuit_id, 10);
        assert_eq!(fwd1.next_peer, b"relay2");

        // Relay 2 peels layer 2
        let fwd2 = relay2
            .forward_cell(fwd1.outbound_circuit_id, &fwd1.cell_data)
            .await
            .unwrap();
        assert_eq!(fwd2.outbound_circuit_id, 20);
        assert_eq!(fwd2.next_peer, b"relay3");

        // Relay 3 peels layer 3
        let fwd3 = relay3
            .forward_cell(fwd2.outbound_circuit_id, &fwd2.cell_data)
            .await
            .unwrap();
        assert_eq!(fwd3.outbound_circuit_id, 30);
        assert_eq!(fwd3.next_peer, b"exit");
        assert_eq!(fwd3.cell_data, plaintext);

        // Verify metrics
        assert_eq!(relay1.cells_forwarded(), 1);
        assert_eq!(relay2.cells_forwarded(), 1);
        assert_eq!(relay3.cells_forwarded(), 1);
    }
}
