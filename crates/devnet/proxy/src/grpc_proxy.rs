//! gRPC partition proxy config: per-backend identity material and the helpers
//! the serving loop ([`crate::grpc_serve`]) uses to enforce network partitions.
//!
//! Architecture: one PQNoise-terminating listener per backend archive (port
//! `9000 + ordinal`) gives port-based routing without inspecting payloads. The
//! proxy presents the *backend's* identity to callers and re-originates each
//! forwarded call with the *caller's* identity to the backend, so the backend
//! sees the true requester. The caller is identified by the peer ID the PQNoise
//! handshake verifies (not its IP — archives start after the proxy and their
//! IPs aren't known up front).
//!
//! Transport note: `:8340` carries no rustls/mTLS. Since the Falcon peer-id
//! migration the node authenticates that port with the sntrup761 PQNoise
//! handshake, whose identity is the node's Falcon `q-prover-key` signing key —
//! the same key that yields its libp2p peer ID. Impersonating a node therefore
//! means holding that key, which is why [`NodeWiring`] carries it.
//!
//! Because gRPC is just HTTP/2 with framed messages + a `grpc-status` trailer,
//! the serving loop forwards it transparently at the h2 level (no protobuf
//! codec needed); this module provides the inputs it consumes:
//!   * [`BackendSpec`] / [`build_backend_specs`] — per-backend identity
//!     material: the backend's own signing key (to answer callers as it) and
//!     each caller's signing key (to dial the backend as them).
//!   * [`partition_allows`] — the partition gate consulted per request.

use std::collections::HashMap;

use anyhow::bail;
use quil_p2p::PeerId;

use crate::partitioner::NetworkPartitioner;

// =====================================================================
// Per-backend identity material.
// =====================================================================

/// Identity material and routing for one backend archive node.
pub struct BackendSpec {
    /// TCP port the proxy listens on for this backend.
    pub listen_port: u16,
    /// Dial address of the archive node, e.g. `"archive-1:8340"`.
    pub backend_addr: String,
    /// The backend's peer ID — the destination in partition checks.
    pub backend_peer_id: PeerId,
    /// The backend's Falcon signing key. The proxy answers inbound handshakes
    /// with it, so callers see the backend's identity.
    pub backend_falcon_key: Vec<u8>,
    /// Per-caller Falcon signing key, used when the proxy dials the backend on
    /// that caller's behalf. Keyed by caller peer ID.
    pub caller_falcon_keys: HashMap<PeerId, Vec<u8>>,
}

/// One node's wiring inputs for [`build_backend_specs`] (as a backend and/or a caller).
#[derive(Clone)]
pub struct NodeWiring {
    pub peer_id: PeerId,
    /// The node's Falcon `q-prover-key` signing key — its `:8340` PQNoise
    /// identity.
    pub falcon_signing_key: Vec<u8>,
    pub backend_addr: String,
    pub listen_port: u16,
}

/// Build one [`BackendSpec`] per backend (archives): the backend's own signing
/// key, plus the signing key of *every* caller (all nodes — archives AND
/// clients, since a client frame-syncs from archives through the proxy).
pub fn build_backend_specs(
    backends: &[NodeWiring],
    callers: &[NodeWiring],
) -> anyhow::Result<Vec<BackendSpec>> {
    let mut specs = Vec::with_capacity(backends.len());
    for backend in backends {
        if backend.falcon_signing_key.is_empty() {
            bail!("no falcon signing key for backend {}", backend.backend_addr);
        }

        let mut caller_falcon_keys = HashMap::new();
        for caller in callers {
            if caller.falcon_signing_key.is_empty() {
                bail!("no falcon signing key for caller {}", caller.peer_id);
            }
            // A node may call itself (self-loops are harmless); include all.
            caller_falcon_keys.insert(caller.peer_id, caller.falcon_signing_key.clone());
        }

        specs.push(BackendSpec {
            listen_port: backend.listen_port,
            backend_addr: backend.backend_addr.clone(),
            backend_peer_id: backend.peer_id,
            backend_falcon_key: backend.falcon_signing_key.clone(),
            caller_falcon_keys,
        });
    }
    Ok(specs)
}

// =====================================================================
// Partition gate.
// =====================================================================

/// Whether the proxy may forward a call from `src` to `dst` right now.
/// Consulted before opening a stream, on every forwarded message, and by the
/// 50 ms background monitor so partitions take effect on in-flight streams.
pub fn partition_allows(partitioner: &NetworkPartitioner, src: &PeerId, dst: &PeerId) -> bool {
    partitioner.forward_filter(src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::ed448_identity::Ed448Identity;
    use std::str::FromStr;

    fn pid() -> PeerId {
        PeerId::from_str(&Ed448Identity::generate().unwrap().peer_id_base58()).unwrap()
    }

    /// A peer ID plus the base58 string `apply_partition` takes.
    fn pid_with_b58() -> (PeerId, String) {
        let b58 = Ed448Identity::generate().unwrap().peer_id_base58();
        (PeerId::from_str(&b58).unwrap(), b58)
    }

    #[test]
    fn partition_gate_reflects_partitioner() {
        let p = NetworkPartitioner::new();
        let (a, a58) = pid_with_b58();
        let (b, b58) = pid_with_b58();
        assert!(partition_allows(&p, &a, &b));
        p.apply_partition(&[a58], &[b58]);
        assert!(!partition_allows(&p, &a, &b));
        assert!(!partition_allows(&p, &b, &a), "partition is symmetric");
    }

    fn wiring(port: u16) -> NodeWiring {
        NodeWiring {
            peer_id: pid(),
            // Contents are opaque here — only the handshake interprets them.
            falcon_signing_key: vec![0x42; 1281],
            backend_addr: format!("archive:{port}"),
            listen_port: port,
        }
    }

    #[test]
    fn build_backend_specs_wires_backend_and_per_caller_keys() {
        // 2 archive backends, but 3 callers (the 2 archives + a client).
        let backends = vec![wiring(9001), wiring(9002)];
        let callers = vec![backends[0].clone(), backends[1].clone(), wiring(0)];
        let specs = build_backend_specs(&backends, &callers).expect("build specs");
        assert_eq!(specs.len(), 2);
        for (spec, backend) in specs.iter().zip(&backends) {
            // Every backend answers as itself...
            assert_eq!(spec.backend_falcon_key, backend.falcon_signing_key);
            // ...and can dial as every caller (archives + client).
            assert_eq!(spec.caller_falcon_keys.len(), 3);
            for caller in &callers {
                assert_eq!(
                    spec.caller_falcon_keys.get(&caller.peer_id),
                    Some(&caller.falcon_signing_key)
                );
            }
        }
    }

    #[test]
    fn build_backend_specs_rejects_missing_key() {
        let mut backend = wiring(9001);
        backend.falcon_signing_key.clear();
        let callers = vec![wiring(0)];
        assert!(build_backend_specs(&[backend], &callers).is_err());
    }
}
