//! `qclient node prover join` — request the node to join shard filters.
//!
//! Port of `client/cmd/node/prover/proverJoin.go`. Unlike the other
//! lifecycle ops, join does NOT locally build/sign a message — it calls
//! `NodeService::RequestJoin`, and the node computes the VDF proof and
//! signs the join server-side.

use quil_types::proto::node::{GetWorkerInfoRequest, RequestJoinRequest, WorkerInfo};

use super::ProverCtx;

/// Why a join of `filters` should not go out, given the node's workers.
///
/// A join lands as a seat the node binds to a free manual worker first, then
/// to a free auto one, and at its confirm window decides by that worker: a
/// manual worker's confirms while the node has capacity, an auto worker's goes
/// to the score rule, which rejects a join scoring well below the best shard
/// with nothing reported here. The manager refuses the same joins
/// (`action_join`).
fn join_refusal(workers: &[WorkerInfo], filters: &[Vec<u8>]) -> Option<String> {
    if workers.is_empty() {
        return Some(
            "prover join not sent: cannot tell the worker modes, the node reports no workers; \
             it may still be starting, so try again shortly"
                .to_string(),
        );
    }
    let free_manual = workers
        .iter()
        .filter(|w| w.filter.is_empty() && w.manually_managed && !w.draining)
        .count();
    if free_manual >= filters.len() {
        return None;
    }
    Some(format!(
        "prover join not sent: {} filter(s) need that many free manual workers; the node has \
         {free_manual}.\nThe seat would bind to an auto worker, whose join the node's score rule \
         decides: it rejects one scoring well below the best shard.\nTo join, first switch free \
         workers to manual: in `qclient node prover manage`, put the cursor on an idle worker's \
         row, press Ctrl+O and confirm with Enter. Then send the join again.\nA manual worker \
         stays out of the node's planner until you switch it back.",
        filters.len()
    ))
}

pub async fn run(pc: &ProverCtx, filters: &[String], delegate: &str) -> anyhow::Result<()> {
    if filters.is_empty() {
        anyhow::bail!(
            "prover join not sent: name the shard filters, as an empty list reaches no shard; \
             `qclient node prover shards` lists them, then run \
             `qclient node prover join <filter>...`"
        );
    }
    let filters: Vec<Vec<u8>> = filters
        .iter()
        .map(|arg| hex::decode(arg).map_err(|e| anyhow::anyhow!("invalid filter hex {arg:?}: {e}")))
        .collect::<anyhow::Result<_>>()?;

    let delegate = if delegate.is_empty() {
        Vec::new()
    } else {
        hex::decode(delegate).map_err(|e| anyhow::anyhow!("invalid delegate address hex: {e}"))?
    };

    let mut client = pc.connect().await?;

    let workers = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
        .map_err(|e| {
            anyhow::anyhow!("prover join not sent: cannot read the worker modes from the node: {e}")
        })?
        .into_inner()
        .worker_info;
    if let Some(refusal) = join_refusal(&workers, &filters) {
        anyhow::bail!(refusal);
    }

    println!("Requesting join (VDF proof computation may take a while)...");
    client
        .request_join(tonic::Request::new(RequestJoinRequest {
            filters,
            delegate,
            worker_ids: Vec::new(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("failed to request join: {e}"))?;

    println!("Prover join submitted successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn worker(filter: &[u8], manually_managed: bool, draining: bool) -> WorkerInfo {
        WorkerInfo {
            filter: filter.to_vec(),
            manually_managed,
            draining,
            ..Default::default()
        }
    }

    /// Only a free manual worker that takes seats counts: one per filter.
    #[test]
    fn a_join_needs_a_free_manual_worker_per_filter() {
        let (a, b) = (vec![0xAA; 32], vec![0xBB; 32]);
        let free_manual = worker(&[], true, false);
        let free_auto = worker(&[], false, false);
        let seated_manual = worker(&[0xCC; 32], true, false);
        let draining_manual = worker(&[], true, true);

        assert_eq!(
            join_refusal(
                &[free_manual.clone(), free_auto.clone()],
                std::slice::from_ref(&a)
            ),
            None
        );
        let refusal = join_refusal(
            &[free_manual.clone(), free_auto.clone()],
            &[a.clone(), b.clone()],
        )
        .expect("two filters, one free manual worker");
        for text in [
            "2 filter(s)",
            "the node has 1",
            "score rule",
            "Ctrl+O",
            "stays out of the node's planner",
        ] {
            assert!(refusal.contains(text), "{text} in {refusal}");
        }
        for workers in [vec![free_auto], vec![seated_manual], vec![draining_manual]] {
            assert!(join_refusal(&workers, std::slice::from_ref(&a)).is_some());
        }
        let refusal = join_refusal(&[], &[a]).expect("no workers reported");
        assert!(refusal.contains("reports no workers"), "{refusal}");
    }

    struct Joins(Arc<AtomicUsize>);

    impl quil_rpc::WorkerControl for Joins {
        fn set_manually_managed(&self, _: u32, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn request_join<'a>(
            &'a self,
            _: Vec<Vec<u8>>,
            _: Vec<u32>,
            _: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    /// The command against a node: a join with no free manual worker asks the
    /// node for nothing, an empty list neither, and once a worker is switched
    /// the same join goes out.
    #[tokio::test]
    async fn a_join_without_a_free_manual_worker_sends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let entry = |manually_managed| quil_rpc::WorkerEntry {
            core_id: 1,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed,
            allocated: false,
            execution: None,
            draining: false,
        };
        let view = Arc::new(std::sync::RwLock::new(vec![entry(false)]));
        let joins = Arc::new(AtomicUsize::new(0));
        let server = quil_rpc::NodeRpcServer::default()
            .with_workers_view(view.clone())
            .with_worker_control(Arc::new(Joins(joins.clone())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let key_manager = Arc::new(
            quil_keys::FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        let pc = ProverCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.path().to_path_buf(),
            connect_opts: crate::rpc::ConnectOpts {
                listen_grpc_multiaddr: multiaddr,
                ..Default::default()
            },
            key_manager,
            epoch_waits: None,
        };
        let args = [hex::encode([0xAA; 32])];

        let refusal = run(&pc, &args, "").await.unwrap_err().to_string();
        assert!(refusal.contains("free manual workers"), "{refusal}");
        let refusal = run(&pc, &[], "").await.unwrap_err().to_string();
        assert!(refusal.contains("name the shard filters"), "{refusal}");
        assert_eq!(joins.load(Ordering::SeqCst), 0, "nothing goes out");

        *view.write().unwrap() = vec![entry(true)];
        run(&pc, &args, "").await.unwrap();
        assert_eq!(joins.load(Ordering::SeqCst), 1, "the join goes out");
        let _ = stop.send(());
    }
}
