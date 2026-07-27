//! Onion relay — forwards cells for circuits passing through this node.
//!
//! A relay:
//! 1. Accepts CREATE cells, runs the forward-secret sntrup761 KEM-ntor handshake
//! ([`handle_create_cell`](OnionRelay::handle_create_cell)), and registers the
//! circuit hop.
//! 2. Forwards RELAY cells one AES-256-GCM layer at a time, tunnels EXTEND, and
//! relays backward cells toward the originator.
//!
//! DEFENSE — circuits are keyed by `(upstream_peer, upstream_circ_id)`, NOT the
//! circuit id alone. A downstream id is allocated by THIS relay from a private
//! counter (unique), so the only cross-peer collision risk is on the upstream id
//! (chosen by the upstream peer); peer-scoping it means one peer can never clobber
//! or read another peer's circuit by reusing an id.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::cell;
use super::router::{decrypt_layer, encrypt_layer, LAYER_BACKWARD, LAYER_FORWARD};
use super::CircuitId;

/// Idle timeout after which a relay circuit is torn down (its entry dropped, which
/// zeroizes the hop key). Bounds how long secrets for abandoned circuits live.
pub const CIRCUIT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// First downstream circuit id a relay allocates when extending. High half of the
/// u32 space to avoid colliding with initiator-chosen upstream ids (which start
/// low), so a single relay's inbound/outbound id spaces don't overlap.
const FIRST_DOWN_CIRC_ID: u32 = 0x8000_0000;

/// DoS bound on the number of circuits a relay will hold. sntrup761 decapsulation
/// never fails (implicit rejection), so any well-formed CREATE registers an entry;
/// without a cap a flood grows the circuit table unboundedly. New CREATEs are
/// refused once this many circuits are live.
const MAX_RELAY_CIRCUITS: usize = 1 << 16;

/// Circuit-table key: `(upstream_peer_id, upstream_circ_id)`.
type UpKey = (Vec<u8>, CircuitId);

/// What a relay should do with a peeled forward cell.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayAction {
    /// Forward `cell` to `peer` on `circ_id` (a middle hop, or the CREATE an
    /// EXTEND produces for the next hop).
    Forward {
        peer: Vec<u8>,
        circ_id: CircuitId,
        cell: Vec<u8>,
    },
    /// This hop is the exit for the cell: deliver `payload` to the application.
    Deliver { payload: Vec<u8> },
    /// Nothing to do (unknown circuit, malformed, or non-actionable).
    None,
}

/// A relayed circuit segment (keyed externally by its upstream `(peer, circ)`).
#[derive(Clone)]
struct RelayEntry {
    /// Circuit id on the outgoing (downstream) side; 0 until an EXTEND runs.
    outbound_id: CircuitId,
    /// Per-hop AES-GCM key. `Zeroizing` wipes it from memory when the entry is
    /// dropped (circuit teardown / expiry), narrowing the disclosure window.
    shared_secret: Zeroizing<Vec<u8>>,
    /// Peer id of the next hop (toward exit); empty until an EXTEND runs.
    to_peer: Vec<u8>,
    /// Highest forward-DATA sequence delivered as the EXIT of this circuit; a cell
    /// with `seq <= this` is a replay and is dropped.
    fwd_recv_seq: u64,
    /// Next backward-DATA sequence to stamp when this hop (the exit) replies.
    bwd_send_seq: u64,
    /// Last time a cell used this circuit — for idle expiry.
    last_used: Instant,
}

/// Onion relay that forwards cells through circuits.
pub struct OnionRelay {
    /// `(upstream_peer, upstream_circ)` → relay entry.
    entries: Mutex<HashMap<UpKey, RelayEntry>>,
    /// Downstream circuit id (allocated by this relay during EXTEND) → the
    /// upstream `(peer, circ)` it belongs to, so CREATED / backward cells from the
    /// next hop route toward the originator.
    down_routes: Mutex<HashMap<CircuitId, UpKey>>,
    /// Counter for allocating downstream circuit ids.
    next_down_circ: AtomicU32,
    /// This relay's sntrup761 onion SECRET key (the `q-onion-key` secret half).
    /// `None` until set — the relay then rejects CREATE cells.
    onion_secret_key: std::sync::RwLock<Option<Zeroizing<Vec<u8>>>>,
    /// This relay's own peer id — DEFENSE: an EXTEND naming this peer as the next
    /// hop is rejected (no self-loop). Empty until set.
    self_peer_id: std::sync::RwLock<Vec<u8>>,
    /// DEFENSE: validates that an EXTEND's next hop is an in-network routing peer,
    /// never an open-web address. `None` ⇒ accept any (test default).
    peer_validator: std::sync::RwLock<Option<super::PeerValidator>>,
    /// Number of cells forwarded (metric).
    cells_forwarded: AtomicU64,
    /// Total bytes relayed (metric).
    bytes_relayed: AtomicU64,
}

impl OnionRelay {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            down_routes: Mutex::new(HashMap::new()),
            next_down_circ: AtomicU32::new(FIRST_DOWN_CIRC_ID),
            onion_secret_key: std::sync::RwLock::new(None),
            self_peer_id: std::sync::RwLock::new(Vec::new()),
            peer_validator: std::sync::RwLock::new(None),
            cells_forwarded: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
        }
    }

    /// Install this relay's sntrup761 onion secret key so it can decapsulate
    /// CREATE cells (see [`handle_create_cell`](Self::handle_create_cell)).
    pub fn set_onion_secret_key(&self, secret_key: Vec<u8>) {
        *self.onion_secret_key.write().unwrap() = Some(Zeroizing::new(secret_key));
    }

    /// DEFENSE inputs: this relay's own peer id (reject EXTEND to self) and a
    /// validator that an EXTEND's next hop is an in-network routing peer.
    pub fn set_self_peer_id(&self, peer_id: Vec<u8>) {
        *self.self_peer_id.write().unwrap() = peer_id;
    }

    pub fn set_peer_validator(&self, validator: super::PeerValidator) {
        *self.peer_validator.write().unwrap() = Some(validator);
    }

    /// True if `peer` is a permitted next hop: not this relay itself, and a valid
    /// in-network routing peer (when a validator is installed).
    fn next_hop_allowed(&self, peer: &[u8]) -> bool {
        if peer.is_empty() {
            return false;
        }
        if *self.self_peer_id.read().unwrap() == peer {
            return false; // DEFENSE 2: no self-connection
        }
        match &*self.peer_validator.read().unwrap() {
            Some(v) => v(peer), // DEFENSE 1: must be an in-network peer
            None => true,
        }
    }

    /// Accept a CREATE cell: the FORWARD-SECRET sntrup761 KEM-ntor handshake (PQ
    /// analogue of Go `Relay.handleCreate`). Decapsulates `ct_static` with this
    /// relay's static onion key (authenticating us), encapsulates BACK to the
    /// initiator's ephemeral key; the hop key is `kdf_ntor(ss_static ‖ ss_eph)`.
    /// Registers the circuit under `(src_peer, circ_id)` and returns the CREATED
    /// reply (`ct_ephemeral ‖ confirmation`) to send back to `src_peer` on
    /// `circ_id`. `None` if not a CREATE, malformed, carries a next hop, the table
    /// is full, no onion key, or KEM failure.
    pub async fn handle_create_cell(
        &self,
        src_peer: &[u8],
        circ_id: CircuitId,
        cell: &[u8],
    ) -> Option<Vec<u8>> {
        let (cmd, payload) = cell::parse_cell(cell)?;
        if cmd != cell::CMD_CREATE {
            return None;
        }
        let (_outbound_circ_id, next_hop, eph_public_key, ct_static) =
            cell::parse_create_payload(payload)?;

        // DEFENSE: a CREATE must NOT carry a downstream next hop — honest
        // initiators always send it empty and set the downstream later via a
        // validated EXTEND. An attacker-supplied `next_hop` here would bypass the
        // EXTEND path's `next_hop_allowed` guard.
        if !next_hop.is_empty() {
            tracing::debug!("onion CREATE rejected: non-empty next_hop");
            return None;
        }

        // DoS bound: refuse new circuits once the table is full.
        if self.entries.lock().await.len() >= MAX_RELAY_CIRCUITS {
            tracing::debug!("onion CREATE rejected: circuit table full");
            return None;
        }

        let onion_secret_key = self.onion_secret_key.read().unwrap().clone()?;
        // Authentication: only this relay can decapsulate `ct_static`.
        let ss_static = super::onion_kem_decapsulate(ct_static, &onion_secret_key)?;
        // Forward secrecy: encapsulate to the initiator's ephemeral key.
        let (ss_ephemeral, ct_ephemeral) = super::onion_kem_encapsulate(eph_public_key)?;
        let hop_secret = cell::kdf_ntor(
            &ss_static,
            &ss_ephemeral,
            eph_public_key,
            ct_static,
            &ct_ephemeral,
        );

        self.entries.lock().await.insert(
            (src_peer.to_vec(), circ_id),
            RelayEntry {
                outbound_id: 0,
                shared_secret: Zeroizing::new(hop_secret.to_vec()),
                to_peer: Vec::new(),
                fwd_recv_seq: 0,
                bwd_send_seq: 0,
                last_used: Instant::now(),
            },
        );

        let confirmation = cell::created_confirmation(&hop_secret);
        Some(cell::build_cell(
            cell::CMD_CREATED,
            &cell::build_created_payload(&ct_ephemeral, &confirmation),
        ))
    }

    /// Register a circuit hop with explicit peers/secret (test / setup helper),
    /// keyed by `(from_peer, inbound_id)`.
    pub async fn register_with_peers(
        &self,
        inbound_id: CircuitId,
        outbound_id: CircuitId,
        shared_secret: Vec<u8>,
        from_peer: Vec<u8>,
        to_peer: Vec<u8>,
    ) {
        self.entries.lock().await.insert(
            (from_peer, inbound_id),
            RelayEntry {
                outbound_id,
                shared_secret: Zeroizing::new(shared_secret),
                to_peer,
                fwd_recv_seq: 0,
                bwd_send_seq: 0,
                last_used: Instant::now(),
            },
        );
    }

    /// True if `(peer, circ_id)` names a forward-direction circuit through us.
    pub async fn is_forward_circ(&self, peer: &[u8], circ_id: CircuitId) -> bool {
        self.entries
            .lock()
            .await
            .contains_key(&(peer.to_vec(), circ_id))
    }

    /// True if `circ_id` is a DOWNSTREAM id this relay allocated during EXTEND —
    /// i.e. a cell (CREATED or backward data) arriving from the next hop. (Unique
    /// per relay, so peer-agnostic keying is safe here.)
    pub async fn is_down_circ(&self, circ_id: CircuitId) -> bool {
        self.down_routes.lock().await.contains_key(&circ_id)
    }

    /// Process a forward RELAY cell arriving from `up_peer` on `up_circ`: peel this
    /// hop's layer and act on the inner cell — FORWARD (ship inner ciphertext
    /// downstream), RELAY/DATA (exit → deliver), or RELAY/EXTEND (allocate a
    /// downstream circuit and emit the next hop's CREATE).
    pub async fn handle_relay_forward(
        &self,
        up_peer: &[u8],
        up_circ: CircuitId,
        ciphertext: &[u8],
    ) -> RelayAction {
        let key: UpKey = (up_peer.to_vec(), up_circ);
        let entry = {
            let mut entries = self.entries.lock().await;
            match entries.get_mut(&key) {
                Some(e) => {
                    e.last_used = Instant::now();
                    e.clone()
                }
                None => return RelayAction::None,
            }
        };
        let plain = match decrypt_layer(&entry.shared_secret, LAYER_FORWARD, ciphertext) {
            Some(p) => p,
            None => return RelayAction::None,
        };
        self.cells_forwarded.fetch_add(1, Ordering::Relaxed);
        self.bytes_relayed
            .fetch_add(ciphertext.len() as u64, Ordering::Relaxed);

        match cell::parse_inner(&plain) {
            Some(cell::Inner::Forward(next_ct)) => {
                if entry.to_peer.is_empty() {
                    return RelayAction::None; // no downstream established yet
                }
                RelayAction::Forward {
                    peer: entry.to_peer.clone(),
                    circ_id: entry.outbound_id,
                    cell: cell::build_cell(cell::CMD_RELAY, next_ct),
                }
            }
            Some(cell::Inner::Relay {
                rcmd: cell::RCMD_DATA,
                data,
            }) => {
                // REPLAY GUARD (exit): the seq rides inside this (authenticated)
                // layer; deliver only if strictly newer than the last, atomically.
                let (seq, payload) = match cell::parse_seq_data(data) {
                    Some(x) => x,
                    None => return RelayAction::None,
                };
                let mut entries = self.entries.lock().await;
                match entries.get_mut(&key) {
                    Some(e) if seq > e.fwd_recv_seq => {
                        e.fwd_recv_seq = seq;
                        RelayAction::Deliver {
                            payload: payload.to_vec(),
                        }
                    }
                    _ => RelayAction::None, // replay (or circuit gone) → drop
                }
            }
            Some(cell::Inner::Relay {
                rcmd: cell::RCMD_EXTEND,
                data,
            }) => {
                let (next_peer, eph_public_key, ct_static) = match cell::parse_extend_data(data) {
                    Some(x) => x,
                    None => return RelayAction::None,
                };
                // DEFENSE: refuse to extend to ourselves or a non-network peer.
                if !self.next_hop_allowed(next_peer) {
                    tracing::debug!("onion EXTEND rejected: next hop is self or not a network peer");
                    return RelayAction::None;
                }
                let down_circ = self.next_down_circ.fetch_add(1, Ordering::Relaxed);
                {
                    // EXTEND-once: reject a second EXTEND on an already-extended
                    // circuit (replay would spawn a duplicate downstream circuit).
                    let mut entries = self.entries.lock().await;
                    let e = match entries.get_mut(&key) {
                        Some(e) => e,
                        None => return RelayAction::None,
                    };
                    if !e.to_peer.is_empty() {
                        tracing::debug!("onion EXTEND rejected: circuit already extended");
                        return RelayAction::None;
                    }
                    e.to_peer = next_peer.to_vec();
                    e.outbound_id = down_circ;
                }
                self.down_routes.lock().await.insert(down_circ, key);
                let create = cell::build_cell(
                    cell::CMD_CREATE,
                    &cell::build_create_payload(0, b"", eph_public_key, ct_static),
                );
                RelayAction::Forward {
                    peer: next_peer.to_vec(),
                    circ_id: down_circ,
                    cell: create,
                }
            }
            _ => RelayAction::None,
        }
    }

    /// Handle a link CREATED from the next hop on `down_circ` (reply to an
    /// EXTEND-issued CREATE): wrap it as a backward RELAY/EXTENDED cell encrypted
    /// with this hop's key, and return `(up_peer, up_circ, cell)` to send toward
    /// the originator.
    pub async fn handle_link_created(
        &self,
        down_circ: CircuitId,
        created_payload: &[u8],
    ) -> Option<(Vec<u8>, CircuitId, Vec<u8>)> {
        let key = self.down_routes.lock().await.get(&down_circ)?.clone();
        let entry = self.entries.lock().await.get(&key).cloned()?;
        let inner = cell::build_relay_inner(cell::RCMD_EXTENDED, created_payload);
        let ct = encrypt_layer(&entry.shared_secret, LAYER_BACKWARD, &inner)?;
        Some((key.0, key.1, cell::build_cell(cell::CMD_RELAY, &ct)))
    }

    /// Handle a backward RELAY cell from the next hop on `down_circ`: add this
    /// hop's layer and return `(up_peer, up_circ, cell)` to send toward the
    /// originator (who peels every hop's layer).
    pub async fn handle_relay_backward(
        &self,
        down_circ: CircuitId,
        ciphertext: &[u8],
    ) -> Option<(Vec<u8>, CircuitId, Vec<u8>)> {
        let key = self.down_routes.lock().await.get(&down_circ)?.clone();
        let entry = self.entries.lock().await.get(&key).cloned()?;
        let ct = encrypt_layer(&entry.shared_secret, LAYER_BACKWARD, ciphertext)?;
        Some((key.0, key.1, cell::build_cell(cell::CMD_RELAY, &ct)))
    }

    /// Build a backward RELAY/DATA cell from the EXIT: wrap `payload`, encrypt with
    /// this hop's key, and return `(up_peer, up_circ, cell)` to send toward the
    /// originator. The exit answers a request that arrived via `on_data` with the
    /// `(up_peer, up_circ)` it was delivered under.
    pub async fn build_data_reply(
        &self,
        up_peer: &[u8],
        up_circ: CircuitId,
        payload: &[u8],
    ) -> Option<(Vec<u8>, CircuitId, Vec<u8>)> {
        // Bound the reply so the layered cell can't overflow the u16 length
        // prefix (F7). Oversized RPC responses are rejected (no chunking yet).
        if payload.len() > cell::MAX_ONION_PAYLOAD {
            tracing::debug!("onion reply dropped: payload exceeds max onion payload");
            return None;
        }
        let key: UpKey = (up_peer.to_vec(), up_circ);
        // Stamp the next backward-DATA sequence (for the originator's replay guard)
        // and read the hop key under one lock.
        let (shared_secret, seq) = {
            let mut entries = self.entries.lock().await;
            let e = entries.get_mut(&key)?;
            e.bwd_send_seq += 1;
            (e.shared_secret.clone(), e.bwd_send_seq)
        };
        let inner = cell::build_relay_inner(cell::RCMD_DATA, &cell::seq_data(seq, payload));
        let ct = encrypt_layer(&shared_secret, LAYER_BACKWARD, &inner)?;
        Some((key.0, key.1, cell::build_cell(cell::CMD_RELAY, &ct)))
    }

    /// Tear down circuits idle longer than `max_idle`: drop their entries (which
    /// zeroizes the hop keys) and the associated downstream routes. Bounds how
    /// long secrets for abandoned circuits persist. Call periodically (see
    /// [`spawn_expiry_sweeper`](super::spawn_expiry_sweeper)).
    pub async fn sweep_expired(&self, max_idle: Duration) {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let before = entries.len();
        entries.retain(|_, e| now.saturating_duration_since(e.last_used) <= max_idle);
        if entries.len() == before {
            return;
        }
        // Drop any downstream route whose upstream entry no longer exists.
        let mut down_routes = self.down_routes.lock().await;
        down_routes.retain(|_, up| entries.contains_key(up));
        tracing::debug!(
            removed = before - entries.len(),
            "onion relay swept expired circuits"
        );
    }

    /// Number of active relay entries.
    pub async fn active_relays(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Total cells forwarded.
    pub fn cells_forwarded(&self) -> u64 {
        self.cells_forwarded.load(Ordering::Relaxed)
    }

    /// Total bytes relayed.
    pub fn bytes_relayed(&self) -> u64 {
        self.bytes_relayed.load(Ordering::Relaxed)
    }
}

impl Default for OnionRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::cell;

    /// DEFENSE at the relay: an EXTEND naming this relay itself, or a peer the
    /// validator rejects, is refused; a valid network peer is forwarded a CREATE.
    #[tokio::test]
    async fn extend_rejects_self_and_non_network_peer() {
        let relay = OnionRelay::new();
        relay.set_self_peer_id(b"me".to_vec());
        relay.set_peer_validator(std::sync::Arc::new(|p: &[u8]| p == b"good-peer"));
        let secret = b"hop-secret-32-bytes-long!!!!!!!";
        relay
            .register_with_peers(1, 0, secret.to_vec(), b"up".to_vec(), Vec::new())
            .await;

        let eph = vec![0u8; crate::onion::ONION_PUBLIC_KEY_LEN];
        let ct = vec![0u8; crate::onion::ONION_CIPHERTEXT_LEN];
        let mk_extend = |next: &[u8]| {
            let inner = cell::build_relay_inner(
                cell::RCMD_EXTEND,
                &cell::build_extend_data(next, &eph, &ct),
            );
            encrypt_layer(secret, LAYER_FORWARD, &inner).unwrap()
        };

        // EXTEND to self / a non-network peer → rejected.
        assert!(matches!(
            relay.handle_relay_forward(b"up", 1, &mk_extend(b"me")).await,
            RelayAction::None
        ));
        assert!(matches!(
            relay.handle_relay_forward(b"up", 1, &mk_extend(b"stranger")).await,
            RelayAction::None
        ));
        // EXTEND to a valid network peer → forwarded as a CREATE.
        match relay.handle_relay_forward(b"up", 1, &mk_extend(b"good-peer")).await {
            RelayAction::Forward { peer, cell: c, .. } => {
                assert_eq!(peer, b"good-peer");
                assert_eq!(cell::parse_cell(&c).unwrap().0, cell::CMD_CREATE);
            }
            other => panic!("expected Forward, got {:?}", other),
        }
        // EXTEND-once: a SECOND EXTEND on the now-extended circuit is rejected
        // (a replayed EXTEND must not spawn a duplicate downstream circuit).
        assert!(matches!(
            relay.handle_relay_forward(b"up", 1, &mk_extend(b"good-peer")).await,
            RelayAction::None
        ));
    }

    /// F5 regression: idle circuits are torn down (entry dropped → hop key
    /// zeroized) by the expiry sweep.
    #[tokio::test]
    async fn sweep_expired_tears_down_idle_circuits() {
        let relay = OnionRelay::new();
        relay
            .register_with_peers(1, 0, b"secret-32-bytes-longenough!!!!!".to_vec(), b"up".to_vec(), Vec::new())
            .await;
        assert_eq!(relay.active_relays().await, 1);
        // A long idle window keeps it.
        relay.sweep_expired(Duration::from_secs(3600)).await;
        assert_eq!(relay.active_relays().await, 1);
        // A tiny window (after a brief pause) tears it down.
        tokio::time::sleep(Duration::from_millis(5)).await;
        relay.sweep_expired(Duration::from_millis(1)).await;
        assert_eq!(relay.active_relays().await, 0);
    }

    /// F2 regression: two peers reusing the SAME circuit id get independent
    /// entries — neither clobbers the other, and each only peels with its own key.
    #[tokio::test]
    async fn circuits_are_peer_scoped_no_cross_peer_clobber() {
        let relay = OnionRelay::new();
        let secret_a = b"peerA-secret-32-bytes-long!!!!!";
        let secret_b = b"peerB-secret-32-bytes-long!!!!!";
        // Both peers use circ id 1.
        relay
            .register_with_peers(1, 0, secret_a.to_vec(), b"peerA".to_vec(), b"exitA".to_vec())
            .await;
        relay
            .register_with_peers(1, 0, secret_b.to_vec(), b"peerB".to_vec(), b"exitB".to_vec())
            .await;

        // Both circuits coexist (no clobber).
        assert_eq!(relay.active_relays().await, 2);
        assert!(relay.is_forward_circ(b"peerA", 1).await);
        assert!(relay.is_forward_circ(b"peerB", 1).await);

        // A FORWARD cell from peerA (keyed by peerA's secret) routes to exitA;
        // the same circ id from peerB routes to exitB with peerB's key.
        let cell_a = encrypt_layer(secret_a, LAYER_FORWARD, &cell::build_forward_inner(b"inner-a")).unwrap();
        match relay.handle_relay_forward(b"peerA", 1, &cell_a).await {
            RelayAction::Forward { peer, .. } => assert_eq!(peer, b"exitA"),
            other => panic!("expected Forward to exitA, got {:?}", other),
        }
        let cell_b = encrypt_layer(secret_b, LAYER_FORWARD, &cell::build_forward_inner(b"inner-b")).unwrap();
        match relay.handle_relay_forward(b"peerB", 1, &cell_b).await {
            RelayAction::Forward { peer, .. } => assert_eq!(peer, b"exitB"),
            other => panic!("expected Forward to exitB, got {:?}", other),
        }

        // peerA's ciphertext presented under peerB's key fails to peel (wrong
        // secret) — a peer cannot read/route another's circuit even by guessing id.
        assert!(matches!(
            relay.handle_relay_forward(b"peerB", 1, &cell_a).await,
            RelayAction::None
        ));
    }
}
