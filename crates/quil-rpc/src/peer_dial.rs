//! Open an mTLS gRPC connection to a peer discovered via the key
//! registry + peer info manager.

use std::sync::Arc;

use quil_engine::worker_node::multiaddr_to_socket_addr;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::GlobalFrame;
use quil_types::store::KeyStore;

use crate::archive_client::{ArchiveClient, ArchiveClientError};

/// `peer_info_lookup` returns candidate stream multiaddrs for the
/// given peer id (e.g. `/ip4/10.0.0.1/tcp/8340`). The first that
/// flattens to a parseable socket address wins.
pub async fn dial_latest_frame_prover<F>(
    frame: &GlobalFrame,
    key_store: Arc<dyn KeyStore>,
    peer_info_lookup: F,
    self_ed448_seed: &[u8; 57],
) -> Result<ArchiveClient>
where
    F: Fn(&[u8]) -> Vec<String> + Send + Sync,
{
    let header = frame
        .header
        .as_ref()
        .ok_or_else(|| QuilError::Internal("dial_latest_frame_prover: frame missing header".into()))?;
    let prover_addr = &header.prover;
    if prover_addr.is_empty() {
        return Err(QuilError::Internal(
            "dial_latest_frame_prover: header.prover is empty".into(),
        ));
    }

    let registry = key_store
        .get_key_registry_by_prover(prover_addr)
        .map_err(|e| QuilError::Internal(format!("get_key_registry_by_prover: {e}")))?;

    let identity_key = registry.identity_key.ok_or_else(|| {
        QuilError::Internal("dial_latest_frame_prover: identity_key missing".into())
    })?;
    if identity_key.key_value.is_empty() {
        return Err(QuilError::Internal(
            "dial_latest_frame_prover: identity_key.key_value empty".into(),
        ));
    }

    let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&identity_key.key_value);
    let candidates = peer_info_lookup(&peer_id);
    if candidates.is_empty() {
        return Err(QuilError::Internal(format!(
            "dial_latest_frame_prover: no peer info for prover (peer_id_len={})",
            peer_id.len()
        )));
    }

    let socket_addr = candidates
        .iter()
        .find_map(|ma| multiaddr_to_socket_addr(ma))
        .ok_or_else(|| {
            QuilError::Internal(format!(
                "dial_latest_frame_prover: no parseable stream multiaddrs (had {})",
                candidates.len()
            ))
        })?;

    ArchiveClient::connect_mtls(&socket_addr, self_ed448_seed)
        .await
        .map_err(|e: ArchiveClientError| QuilError::P2p(format!("dial frame prover: {e}")))
}
