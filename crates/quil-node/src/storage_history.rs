//! Small historical GLOBAL proofs over the existing authenticated peer link.
use crate::prover_tree_syncer_prod::{
    read_breaks_connection, reap_frame_client, FrameClients, FRAME_CLIENTS,
};
use quil_engine::storage_history::GlobalVertexProofSource;
use quil_rpc::{ArchiveClient, ArchiveClientError};
use quil_types::error::{QuilError, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Where a source's successive proofs start: each one archive further on,
/// so a replay, which asks for one proof per frame, spreads its proofs over
/// every known archive instead of queueing them all at the first.
#[derive(Default)]
struct Rotation(AtomicUsize);

impl Rotation {
    /// The archives to ask for the next proof, in turn, at most three.
    fn next(&self, endpoints: &[String]) -> Vec<String> {
        if endpoints.is_empty() {
            return Vec::new();
        }
        let start = self.0.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        endpoints
            .iter()
            .cycle()
            .skip(start)
            .take(endpoints.len().min(3))
            .cloned()
            .collect()
    }
}

/// A historical proof from the first of `endpoints` that holds it. Each
/// archive's connection is kept in `clients`, as for shard frame reads:
/// every new one costs the archive a PQNoise handshake. A read that breaks
/// its connection or outlasts the attempt drops it; the next proof redials.
async fn proof_from<C, Dial, Dialed, Ask, Asked>(
    clients: &'static std::sync::Mutex<FrameClients<C>>,
    endpoints: Vec<String>,
    signing_key: &[u8],
    dial: Dial,
    ask: Ask,
) -> Result<Option<Vec<u8>>>
where
    C: Clone + Send + 'static,
    Dial: Fn(String) -> Dialed,
    Dialed: std::future::Future<Output = std::result::Result<C, ArchiveClientError>>,
    Ask: Fn(C) -> Asked,
    Asked: std::future::Future<Output = std::result::Result<Option<Vec<u8>>, ArchiveClientError>>,
{
    let kept = || {
        clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    for endpoint in endpoints {
        let key = (std::thread::current().id(), endpoint);
        // The error says whether the connection broke.
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let cached = kept().get(&key, signing_key, std::time::Instant::now());
            let client = match cached {
                Some(client) => client,
                None => {
                    let client = dial(key.1.clone()).await.map_err(|_| false)?;
                    let id = kept().insert(
                        key.clone(),
                        signing_key,
                        client.clone(),
                        std::time::Instant::now(),
                    );
                    tokio::spawn(reap_frame_client(clients, key.clone(), id));
                    client
                }
            };
            ask(client).await.map_err(|e| read_breaks_connection(&e))
        })
        .await;
        match attempt {
            Ok(Ok(Some(bytes))) => return Ok(Some(bytes)),
            Ok(Ok(None)) | Ok(Err(false)) => {}
            Ok(Err(true)) | Err(_) => {
                kept().evict(&key);
            }
        }
    }
    Err(QuilError::ExecutionUnavailable(
        "no archive retained the requested historical proof".into(),
    ))
}

pub fn from_pool(
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    key: Vec<u8>,
) -> GlobalVertexProofSource {
    let rotation = Arc::new(Rotation::default());
    Arc::new(move |root, address| {
        let pool = pool.clone();
        let key = key.clone();
        let rotation = rotation.clone();
        Box::pin(async move {
            let endpoints = rotation.next(&pool.get_all().await);
            let dial = |endpoint: String| {
                let key = key.clone();
                async move { ArchiveClient::connect_mtls(&endpoint, &key).await }
            };
            // Forwarding is disabled on the second hop, preventing cycles.
            let ask = |mut client: ArchiveClient| async move {
                client.get_global_vertex_proof(root, address, false).await
            };
            proof_from(&FRAME_CLIENTS, endpoints, &key, dial, ask).await
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
pub fn global_frames_from_master(
    endpoint: String,
    key: Vec<u8>,
) -> quil_engine::global_anchor::GlobalAnchorSource {
    Arc::new(move |number| {
        let endpoint = endpoint.clone();
        let key = key.clone();
        Box::pin(async move {
            let mut client = quil_rpc::ArchiveClient::connect_own_master(&endpoint, &key)
                .await
                .map_err(|e| {
                    QuilError::ExecutionUnavailable(format!("GLOBAL anchor master connect: {e}"))
                })?;
            client.get_global_anchor(number).await.map_err(|e| {
                QuilError::ExecutionUnavailable(format!("GLOBAL anchor master read: {e}"))
            })
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
            .map_err(|e| {
                QuilError::ExecutionUnavailable(format!("outgoing history peer connect: {e}"))
            })?;
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
    })
    .await
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
    let mut asked: FuturesUnordered<_> = endpoints
        .iter()
        .cloned()
        .map(|endpoint| {
            let answer = page(endpoint.clone());
            async move { (endpoint, answer.await) }
        })
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
        format!(
            "no archive served outgoing records of frames {from}-{through} ({})",
            answers.join("; ")
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing(frame: u64) -> quil_engine::app_handoff::FrameOutgoing {
        quil_engine::app_handoff::FrameOutgoing {
            frame,
            fees: Vec::new(),
            settlements: Vec::new(),
            spends: Vec::new(),
            digest: Vec::new(),
            report: Vec::new(),
        }
    }

    #[tokio::test]
    async fn every_archive_is_asked_and_each_answer_is_named_when_none_serves() {
        let endpoints: Vec<String> = (1..=5).map(|i| format!("192.0.2.{i}:8340")).collect();
        // Only the last archive in arrival order holds the records.
        let served = outgoing_history_with(&endpoints, 44, 597, |endpoint| async move {
            match endpoint.as_str() {
                "192.0.2.5:8340" => Ok(vec![outgoing(44), outgoing(45)]),
                "192.0.2.2:8340" => Err(QuilError::ExecutionUnavailable(
                    "outgoing history peer timed out".into(),
                )),
                _ => Ok(Vec::new()),
            }
        })
        .await
        .unwrap();
        assert_eq!(
            served.iter().map(|o| o.frame).collect::<Vec<_>>(),
            vec![44, 45]
        );

        let error = outgoing_history_with(&endpoints[..2], 44, 597, |endpoint| async move {
            if endpoint.ends_with(".2:8340") {
                Err(QuilError::ExecutionUnavailable(
                    "outgoing history peer timed out".into(),
                ))
            } else {
                Ok(Vec::new())
            }
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("frames 44-597"), "{error}");
        assert!(
            error.contains("192.0.2.1:8340: holds none from frame 44"),
            "{error}"
        );
        assert!(
            error
                .contains("192.0.2.2:8340: execution unavailable: outgoing history peer timed out"),
            "{error}"
        );
        let none = outgoing_history_with(&[], 44, 597, |_| async { Ok(Vec::new()) })
            .await
            .unwrap_err()
            .to_string();
        assert!(none.contains("no archive is known"), "{none}");
    }

    #[test]
    fn successive_proofs_start_at_successive_archives() {
        let endpoints: Vec<String> = (1..=4).map(|i| format!("192.0.2.{i}:8340")).collect();
        let rotation = Rotation::default();
        let turns: Vec<Vec<String>> = (0..5).map(|_| rotation.next(&endpoints)).collect();
        assert_eq!(turns[0], endpoints[..3]);
        assert_eq!(turns[1], endpoints[1..]);
        assert_eq!(turns[3], [&endpoints[3..], &endpoints[..2]].concat());
        assert_eq!(turns[4], turns[0]);
        // Fewer than three known: each is asked once.
        assert_eq!(
            rotation.next(&endpoints[..2]),
            [endpoints[1].clone(), endpoints[0].clone()]
        );
        assert!(rotation.next(&[]).is_empty());
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Reply {
        Held,
        Busy,
        Broken,
        Silent,
    }

    /// Proofs from one archive: a connection numbered by its dial serves
    /// every proof until a read breaks it or outlasts the attempt.
    #[tokio::test(start_paused = true)]
    async fn a_proof_reuses_its_archive_connection_until_a_read_breaks_it() {
        use Reply::*;
        static KEPT: std::sync::LazyLock<std::sync::Mutex<FrameClients<usize>>> =
            std::sync::LazyLock::new(|| std::sync::Mutex::new(FrameClients::new()));
        let dials = std::sync::Mutex::new(0);
        let served = std::sync::Mutex::new(Vec::new());
        let dial = |_endpoint: String| {
            let mut dials = dials.lock().unwrap();
            *dials += 1;
            std::future::ready(Ok::<_, ArchiveClientError>(*dials))
        };
        let ask = |reply: Reply| {
            let served = &served;
            move |connection: usize| {
                served.lock().unwrap().push(connection);
                async move {
                    match reply {
                        Held => Ok(Some(vec![7])),
                        Busy => Err(ArchiveClientError::Rpc(tonic::Status::resource_exhausted(
                            "busy",
                        ))),
                        Broken => Err(ArchiveClientError::Rpc(tonic::Status::unavailable("reset"))),
                        Silent => std::future::pending().await,
                    }
                }
            }
        };
        let endpoint = || vec!["192.0.2.1:8340".to_string()];
        for reply in [Held, Held, Busy, Broken, Held, Silent, Held] {
            let proof = proof_from(&KEPT, endpoint(), b"k", dial, ask(reply)).await;
            assert_eq!(proof.is_ok(), reply == Held);
        }
        assert_eq!(*dials.lock().unwrap(), 3, "one dial per broken connection");
        assert_eq!(*served.lock().unwrap(), [1, 1, 1, 1, 2, 2, 3]);
    }

    #[tokio::test]
    async fn a_proof_moves_on_until_an_archive_holds_it() {
        static KEPT: std::sync::LazyLock<std::sync::Mutex<FrameClients<String>>> =
            std::sync::LazyLock::new(|| std::sync::Mutex::new(FrameClients::new()));
        let endpoints: Vec<String> = (1..=3).map(|i| format!("192.0.2.{i}:8340")).collect();
        let dial = |endpoint: String| async move {
            if endpoint.ends_with(".1:8340") {
                Err(ArchiveClientError::InvalidEndpoint(endpoint))
            } else {
                Ok(endpoint)
            }
        };
        let ask = |connection: String| async move {
            Ok::<_, ArchiveClientError>(connection.ends_with(".3:8340").then(|| vec![7]))
        };
        let proof = proof_from(&KEPT, endpoints.clone(), b"k", dial, ask).await;
        assert_eq!(proof.unwrap(), Some(vec![7]));
        let error = proof_from(&KEPT, endpoints[..2].to_vec(), b"k", dial, ask)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no archive retained"), "{error}");
    }
}
