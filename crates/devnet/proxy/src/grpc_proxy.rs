//! gRPC partition proxy config: per-backend TLS material and the helpers the
//! serving loop ([`crate::grpc_serve`]) uses to enforce network partitions.
//!
//! Architecture: one TLS-terminating listener
//! per backend archive (port `9000 + ordinal`) gives port-based routing without
//! inspecting payloads. The proxy presents the *backend's* identity to callers
//! and re-originates each forwarded call with the *caller's* identity to the
//! backend, so the backend sees the true requester. The caller is identified
//! from its mTLS client certificate (not its IP — archives start after the
//! proxy and their IPs aren't known up front).
//!
//! Because gRPC is just HTTP/2 with framed messages + a `grpc-status` trailer,
//! the serving loop forwards it transparently at the h2 level (no protobuf
//! codec needed); this module provides the inputs it consumes:
//!   * [`caller_peer_id_from_cert`] — caller peer ID from the presented client
//!     cert (reuses `quil_rpc::peer_auth_middleware::peer_identity_from_cert`).
//!   * [`BackendSpec`] / [`build_backend_specs`] — per-backend TLS material:
//!     the server config impersonating the backend and a per-caller client
//!     config carrying each caller's identity.
//!   * [`partition_allows`] — the partition gate consulted per request.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use quil_p2p::PeerId;
use quil_rpc::archive_client::build_quil_client_config;
use quil_rpc::quil_tls::build_quil_server_tls_config;

use crate::partitioner::NetworkPartitioner;

/// Derive the caller's peer ID from a DER-encoded client certificate (read off
/// the tokio-rustls connection after the mTLS handshake). Returns `None` if the
/// cert isn't a valid Quilibrium xsign cert.
pub fn caller_peer_id_from_cert(cert_der: &[u8]) -> Option<PeerId> {
    quil_rpc::peer_auth_middleware::peer_identity_from_cert(cert_der).map(|(_, id)| id)
}

// =====================================================================
// Per-backend TLS material.
// =====================================================================

/// TLS material and routing for one backend archive node.
pub struct BackendSpec {
    /// TCP port the proxy listens on for this backend.
    pub listen_port: u16,
    /// Dial address of the archive node, e.g. `"archive-1:8340"`.
    pub backend_addr: String,
    /// The backend's peer ID — the destination in partition checks.
    pub backend_peer_id: PeerId,
    /// rustls server config presenting the backend's identity to callers.
    pub server_tls: Arc<tokio_rustls::rustls::ServerConfig>,
    /// Per-caller rustls client config carrying that caller's identity when
    /// the proxy dials the backend on their behalf. Keyed by caller peer ID.
    pub client_tls: HashMap<PeerId, Arc<tokio_rustls::rustls::ClientConfig>>,
}

/// One node's wiring inputs for [`build_backend_specs`] (as a backend and/or a caller).
#[derive(Clone)]
pub struct NodeWiring {
    pub peer_id: PeerId,
    /// 57-byte Ed448 seed (the node's `peerPrivKey` seed half).
    pub ed448_seed: [u8; 57],
    /// 57-byte Ed448 public key (for identity pinning when dialing).
    pub ed448_pubkey: Vec<u8>,
    pub backend_addr: String,
    pub listen_port: u16,
}

/// Build one [`BackendSpec`] per backend (archives): a server config
/// impersonating that backend, plus a client config for *every* caller (all
/// nodes — archives AND clients, since a client frame-syncs from archives
/// through the proxy) carrying the caller's identity and pinning the backend's.
pub fn build_backend_specs(
    backends: &[NodeWiring],
    callers: &[NodeWiring],
) -> anyhow::Result<Vec<BackendSpec>> {
    let mut specs = Vec::with_capacity(backends.len());
    for backend in backends {
        let server_tls = build_quil_server_tls_config(&backend.ed448_seed)
            .with_context(|| format!("server TLS for {}", backend.backend_addr))?;

        let mut client_tls = HashMap::new();
        for caller in callers {
            // A node may call itself (self-loops are harmless); include all.
            let cfg = build_quil_client_config(&caller.ed448_seed).with_context(|| {
                format!(
                    "client TLS for caller {} -> {}",
                    caller.peer_id, backend.backend_addr
                )
            })?;
            client_tls.insert(caller.peer_id, cfg);
        }

        specs.push(BackendSpec {
            listen_port: backend.listen_port,
            backend_addr: backend.backend_addr.clone(),
            backend_peer_id: backend.peer_id,
            server_tls,
            client_tls,
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

    #[test]
    fn partition_gate_reflects_partitioner() {
        let p = NetworkPartitioner::new();
        let a = pid();
        let b = pid();
        assert!(partition_allows(&p, &a, &b));
        p.partition_peers(a, b);
        assert!(!partition_allows(&p, &a, &b));
        assert!(!partition_allows(&p, &b, &a), "partition is symmetric");
    }

    #[test]
    fn build_backend_specs_wires_server_and_per_caller_clients() {
        let mk = |port: u16| {
            let id = Ed448Identity::generate().unwrap();
            let seed: [u8; 57] = id.private_key.clone().try_into().unwrap();
            NodeWiring {
                peer_id: PeerId::from_str(&id.peer_id_base58()).unwrap(),
                ed448_seed: seed,
                ed448_pubkey: id.public_key.clone(),
                backend_addr: format!("archive:{port}"),
                listen_port: port,
            }
        };
        // 2 archive backends, but 3 callers (the 2 archives + a client).
        let backends = vec![mk(9001), mk(9002)];
        let callers = vec![backends[0].clone(), backends[1].clone(), mk(0)];
        let specs = build_backend_specs(&backends, &callers).expect("build specs");
        assert_eq!(specs.len(), 2);
        for spec in &specs {
            // Every backend has a client config for every caller (archives + client).
            assert_eq!(spec.client_tls.len(), 3);
            assert_eq!(spec.server_tls.alpn_protocols, vec![b"h2".to_vec()]);
        }
    }

    #[test]
    fn caller_id_none_for_garbage_cert() {
        assert!(caller_peer_id_from_cert(&[0x00, 0x01, 0x02]).is_none());
    }
}
