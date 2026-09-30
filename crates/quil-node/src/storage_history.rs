//! Small historical GLOBAL proofs over the existing authenticated peer link.
use quil_engine::storage_history::GlobalVertexProofSource;
use quil_types::error::{QuilError, Result};
use std::sync::Arc;

async fn fetch(
    endpoint: &str,
    key: &[u8],
    root: [u8; 32],
    address: [u8; 32],
    forward: bool,
) -> Result<Option<Vec<u8>>> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut client = quil_rpc::ArchiveClient::connect_mtls(endpoint, key)
            .await
            .map_err(|e| QuilError::ExecutionUnavailable(format!("history peer connect: {e}")))?;
        client
            .get_global_vertex_proof(root, address, forward)
            .await
            .map_err(|e| QuilError::ExecutionUnavailable(format!("history peer proof: {e}")))
    })
    .await
    .map_err(|_| QuilError::ExecutionUnavailable("history peer timed out".into()))?
}

pub fn from_pool(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    key: Vec<u8>,
) -> GlobalVertexProofSource {
    Arc::new(move |root, address| {
        let pool = pool.clone();
        let key = key.clone();
        Box::pin(async move {
            for endpoint in pool.get_all().await.into_iter().take(3) {
                // Forwarding is disabled on the second hop, preventing cycles.
                if let Ok(Some(bytes)) = fetch(&endpoint, &key, root, address, false).await {
                    return Ok(Some(bytes));
                }
            }
            Err(QuilError::ExecutionUnavailable(
                "no archive retained the requested historical proof".into(),
            ))
        })
    })
}

pub fn from_master(endpoint: String, key: Vec<u8>) -> GlobalVertexProofSource {
    Arc::new(move |root, address| {
        let endpoint = endpoint.clone();
        let key = key.clone();
        Box::pin(async move {
            // The master has a bounded archive fallback; give that hop time.
            tokio::time::timeout(std::time::Duration::from_secs(12), async {
                let mut client = quil_rpc::ArchiveClient::connect_own_master(&endpoint, &key)
                    .await
                    .map_err(|e| {
                        QuilError::ExecutionUnavailable(format!("history master connect: {e}"))
                    })?;
                client
                    .get_global_vertex_proof(root, address, true)
                    .await
                    .map_err(|e| {
                        QuilError::ExecutionUnavailable(format!("history master proof: {e}"))
                    })
            })
            .await
            .map_err(|_| QuilError::ExecutionUnavailable("history master timed out".into()))?
        })
    })
}

/// The worker and master share a Falcon identity. Pin it before treating a
/// historical GLOBAL frame as canonical, just as with the master's live feed.
pub fn global_frames_from_master(endpoint: String, key: Vec<u8>) -> quil_engine::global_anchor::GlobalAnchorSource {
    Arc::new(move |number| {
        let endpoint = endpoint.clone();
        let key = key.clone();
        Box::pin(async move {
            let mut client = quil_rpc::ArchiveClient::connect_own_master(&endpoint, &key).await
                .map_err(|e| QuilError::ExecutionUnavailable(format!("GLOBAL anchor master connect: {e}")))?;
            client.get_global_frame(number).await
                .map_err(|e| QuilError::ExecutionUnavailable(format!("GLOBAL anchor master read: {e}")))
        })
    })
}

/// One page of a shard's outgoing records from `endpoint`, as the engine's type.
pub(crate) async fn outgoing_page_from(
    endpoint: &str,
    key: &[u8],
    filter: Vec<u8>,
    from: u64,
    through: u64,
) -> Result<Vec<quil_engine::app_handoff::FrameOutgoing>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut client = quil_rpc::ArchiveClient::connect_mtls(endpoint, key)
            .await
            .map_err(|e| QuilError::ExecutionUnavailable(format!("outgoing history peer connect: {e}")))?;
        let frames = client
            .get_shard_outgoing_history(filter, from, through)
            .await
            .map_err(|e| QuilError::ExecutionUnavailable(format!("outgoing history peer: {e}")))?;
        Ok(frames
            .into_iter()
            .map(|f| quil_engine::app_handoff::FrameOutgoing {
                frame: f.frame_number,
                fees: f.fee_total,
                settlements: f.settlements,
                spends: f.spends,
                digest: f.accumulator_digest,
                report: f.accumulator_report,
            })
            .collect())
    })
    .await
    .map_err(|_| QuilError::ExecutionUnavailable("outgoing history peer timed out".into()))?
}

/// Predecessor outgoing history from the first of up to three archives in
/// `pool` that serves a nonempty page. Unverified: the engine accepts it only
/// against the sealed history root.
pub fn outgoing_history_from_pool(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    key: Vec<u8>,
) -> quil_engine::app_handoff::OutgoingHistorySource {
    Arc::new(move |filter, from, through| {
        let pool = pool.clone();
        let key = key.clone();
        Box::pin(async move {
            for endpoint in pool.get_all().await.into_iter().take(3) {
                if let Ok(page) = outgoing_page_from(&endpoint, &key, filter.clone(), from, through).await {
                    if !page.is_empty() {
                        return Ok(page);
                    }
                }
            }
            Err(QuilError::ExecutionUnavailable(
                "no archive served the predecessor's outgoing history".into(),
            ))
        })
    })
}
