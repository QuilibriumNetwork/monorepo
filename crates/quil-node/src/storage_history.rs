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
async fn outgoing_page_from(
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

/// Predecessor outgoing history from the archives in `pool`. Unverified: the
/// engine accepts it only against the sealed history root.
pub fn outgoing_history_from_pool(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    key: Vec<u8>,
) -> quil_engine::app_handoff::OutgoingHistorySource {
    Arc::new(move |filter, from, through| {
        let pool = pool.clone();
        let key = key.clone();
        Box::pin(async move {
            let endpoints = pool.get_all().await;
            outgoing_history_from_endpoints(&endpoints, &key, filter, from, through).await
        })
    })
}

/// One page of outgoing records of `filter`'s frames `from..=through`, from
/// whichever of `endpoints` first serves a nonempty one. Every known archive
/// is asked at once: one that never executed the shard answers with nothing,
/// and asking only the first few in arrival order could miss every archive
/// that did. When none serves, the error names the range and each answer.
pub(crate) async fn outgoing_history_from_endpoints(
    endpoints: &[String],
    key: &[u8],
    filter: Vec<u8>,
    from: u64,
    through: u64,
) -> Result<Vec<quil_engine::app_handoff::FrameOutgoing>> {
    outgoing_history_with(endpoints, from, through, |endpoint| {
        let (key, filter) = (key.to_vec(), filter.clone());
        async move { outgoing_page_from(&endpoint, &key, filter, from, through).await }
    }).await
}

async fn outgoing_history_with<F, Fut>(
    endpoints: &[String],
    from: u64,
    through: u64,
    page: F,
) -> Result<Vec<quil_engine::app_handoff::FrameOutgoing>>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<quil_engine::app_handoff::FrameOutgoing>>>,
{
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut asked: FuturesUnordered<_> = endpoints.iter().cloned()
        .map(|endpoint| { let answer = page(endpoint.clone()); async move { (endpoint, answer.await) } })
        .collect();
    let mut answers = Vec::new();
    while let Some((endpoint, answer)) = asked.next().await {
        match answer {
            Ok(page) if !page.is_empty() => return Ok(page),
            Ok(_) => answers.push(format!("{endpoint}: holds none from frame {from}")),
            Err(error) => answers.push(format!("{endpoint}: {error}")),
        }
    }
    answers.sort();
    Err(QuilError::ExecutionUnavailable(if answers.is_empty() {
        format!("no archive is known to ask for outgoing records of frames {from}-{through}")
    } else {
        format!("no archive served outgoing records of frames {from}-{through} ({})", answers.join("; "))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing(frame: u64) -> quil_engine::app_handoff::FrameOutgoing {
        quil_engine::app_handoff::FrameOutgoing {
            frame, fees: Vec::new(), settlements: Vec::new(), spends: Vec::new(), digest: Vec::new(), report: Vec::new(),
        }
    }

    #[tokio::test]
    async fn every_archive_is_asked_and_each_answer_is_named_when_none_serves() {
        let endpoints: Vec<String> = (1..=5).map(|i| format!("192.0.2.{i}:8340")).collect();
        // Only the last archive in arrival order holds the records.
        let served = outgoing_history_with(&endpoints, 44, 597, |endpoint| async move {
            match endpoint.as_str() {
                "192.0.2.5:8340" => Ok(vec![outgoing(44), outgoing(45)]),
                "192.0.2.2:8340" => Err(QuilError::ExecutionUnavailable("outgoing history peer timed out".into())),
                _ => Ok(Vec::new()),
            }
        }).await.unwrap();
        assert_eq!(served.iter().map(|o| o.frame).collect::<Vec<_>>(), vec![44, 45]);

        let error = outgoing_history_with(&endpoints[..2], 44, 597, |endpoint| async move {
            if endpoint.ends_with(".2:8340") {
                Err(QuilError::ExecutionUnavailable("outgoing history peer timed out".into()))
            } else {
                Ok(Vec::new())
            }
        }).await.unwrap_err().to_string();
        assert!(error.contains("frames 44-597"), "{error}");
        assert!(error.contains("192.0.2.1:8340: holds none from frame 44"), "{error}");
        assert!(error.contains("192.0.2.2:8340: execution unavailable: outgoing history peer timed out"), "{error}");
        let none = outgoing_history_with(&[], 44, 597, |_| async { Ok(Vec::new()) }).await.unwrap_err().to_string();
        assert!(none.contains("no archive is known"), "{none}");
    }
}
