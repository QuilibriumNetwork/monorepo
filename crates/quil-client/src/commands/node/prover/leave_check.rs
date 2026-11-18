//! Refuse a leave execution would drop whole.
//!
//! Execution applies a leave filter by filter and rolls the whole operation
//! back on the first one with no seat, or a seat it cannot leave, while the
//! command has already said the message went out. So the command checks the
//! seats first and leaves the choice to the operator: it names the filters and
//! gives the command for the others, never dropping a filter they typed.

use quil_types::proto::node::{GetNodeInfoRequest, ShardAllocationInfo};

use super::epoch::{compute_effective_status, raw_status, AllocationTiming};

/// What is wrong with `filter`'s seat, or `None` if it is Active. Raw status,
/// as execution reads it: a seat that missed its renewal can still leave. A
/// paused seat can leave only beside an active one in the same message; the
/// manager offers leave on active seats alone, and so does this.
fn seat_problem(
    allocations: &[ShardAllocationInfo],
    filter: &[u8],
    frame: u64,
    epoch_length: u64,
) -> Option<String> {
    let Some(seat) = allocations.iter().find(|a| a.filter == filter) else {
        return Some("no allocation".to_string());
    };
    if seat.status == raw_status::ACTIVE {
        return None;
    }
    if seat.status == raw_status::PAUSED {
        return Some("paused: resume it first".to_string());
    }
    let timing = AllocationTiming {
        raw_status: seat.status,
        filter: &seat.filter,
        join_frame: seat.join_frame_number,
        join_confirm_frame: seat.join_confirm_frame_number,
        leave_frame: seat.leave_frame_number,
        leave_confirm_frame: seat.leave_confirm_frame_number,
        epoch: seat.epoch,
    };
    Some(
        compute_effective_status(&timing, frame, epoch_length)
            .label()
            .to_string(),
    )
}

/// Why a leave of `filters` should not go out, given the node's allocations.
fn refusal(
    allocations: &[ShardAllocationInfo],
    filters: &[Vec<u8>],
    frame: u64,
    epoch_length: u64,
) -> Option<String> {
    if allocations.is_empty() {
        return Some(
            "prover leave not sent: cannot tell the filters' status, the node reports no \
             allocations; its registry may still be loading, or this prover holds none: check \
             `qclient node prover status`"
                .to_string(),
        );
    }
    let problems: Vec<(&Vec<u8>, String)> = filters
        .iter()
        .filter_map(|f| seat_problem(allocations, f, frame, epoch_length).map(|p| (f, p)))
        .collect();
    if problems.is_empty() {
        return None;
    }
    let named: Vec<String> = problems
        .iter()
        .map(|(f, problem)| format!("  {} ({problem})", hex::encode(f)))
        .collect();
    let mut message = format!(
        "prover leave not sent; no filter went out.\n{} of {} filters are not Active, and \
         execution can drop a whole leave for one of them with nothing reported:\n{}",
        problems.len(),
        filters.len(),
        named.join("\n")
    );
    let active: Vec<String> = filters
        .iter()
        .filter(|f| !problems.iter().any(|(p, _)| p == f))
        .map(hex::encode)
        .collect();
    if !active.is_empty() {
        message.push_str(&format!(
            "\nTo leave the {} Active filters: qclient node prover leave {}",
            active.len(),
            active.join(" ")
        ));
    }
    Some(message)
}

/// Fail unless every filter's seat is Active on the node's own reading.
pub(super) async fn require_active(
    client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<
        tonic::transport::Channel,
    >,
    filters: &[Vec<u8>],
) -> anyhow::Result<()> {
    let info = client
        .get_node_info(tonic::Request::new(GetNodeInfoRequest::default()))
        .await
        .map_err(|e| {
            anyhow::anyhow!("prover leave not sent: cannot read the filters' status: {e}")
        })?
        .into_inner();
    match refusal(
        &info.shard_allocations,
        filters,
        info.last_received_frame,
        info.epoch_length_frames,
    ) {
        Some(message) => anyhow::bail!(message),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{
        ProverAllocationInfo, ProverInfo, ProverRegistry, ProverShardSummary, ProverStatus,
    };
    use quil_types::error::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn seat(filter: &[u8], status: u32) -> ShardAllocationInfo {
        ShardAllocationInfo {
            filter: filter.to_vec(),
            status,
            epoch: u64::MAX,
            ..Default::default()
        }
    }

    /// Execution's reading: each filter's raw status decides; a filter with no
    /// seat, or one leaving, joining, paused or gone, is named with its state,
    /// and the Active ones come back as the command to send.
    #[test]
    fn a_leave_names_the_filters_that_are_not_active() {
        let (active, other, leaving, paused, absent) = (
            vec![0xA1; 32],
            vec![0xA2; 32],
            vec![0xB1; 32],
            vec![0xB2; 32],
            vec![0xB3; 32],
        );
        let seats = [
            seat(&active, raw_status::ACTIVE),
            seat(&other, raw_status::ACTIVE),
            seat(&leaving, raw_status::LEAVING),
            seat(&paused, raw_status::PAUSED),
        ];
        assert_eq!(
            refusal(&seats, &[active.clone(), other.clone()], 100, 720),
            None
        );

        let message = refusal(
            &seats,
            &[
                active.clone(),
                leaving.clone(),
                paused.clone(),
                absent.clone(),
                other.clone(),
            ],
            100,
            720,
        )
        .expect("refused");
        for text in [
            "no filter went out",
            "3 of 5 filters are not Active",
            &format!("{} (leaving)", hex::encode(&leaving)),
            &format!("{} (paused: resume it first)", hex::encode(&paused)),
            &format!("{} (no allocation)", hex::encode(&absent)),
            &format!(
                "To leave the 2 Active filters: qclient node prover leave {} {}",
                hex::encode(&active),
                hex::encode(&other)
            ),
        ] {
            assert!(message.contains(text), "{text} in {message}");
        }

        let message = refusal(&seats, std::slice::from_ref(&leaving), 100, 720).expect("refused");
        assert!(!message.contains("To leave"), "{message}");
    }

    /// A seat whose renewal lapsed still reads raw Active, and execution lets
    /// it leave: refusing it would strand the operator.
    #[test]
    fn a_lapsed_active_seat_can_leave() {
        let filter = vec![0xA1; 32];
        let mut lapsed = seat(&filter, raw_status::ACTIVE);
        lapsed.epoch = 0;
        assert_eq!(refusal(&[lapsed], &[filter], 7_200, 720), None);
    }

    /// With no allocations reported the node cannot tell; that fails closed.
    #[test]
    fn no_allocations_reported_refuses_with_the_reason() {
        let message = refusal(&[], &[vec![0xA1; 32]], 100, 720).expect("refused");
        assert!(message.contains("reports no allocations"), "{message}");
    }

    struct OneProver(Vec<ProverAllocationInfo>);

    impl ProverRegistry for OneProver {
        fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>> {
            Ok(Some(ProverInfo {
                public_key: vec![0xAA; 74],
                address: address.to_vec(),
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: self.0.clone(),
                available_storage: 0,
                seniority: 0,
                delegate_address: vec![],
            }))
        }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> {
            Ok(vec![])
        }
        fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> {
            Ok(vec![])
        }
        fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
            Ok(0)
        }
        fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> {
            Ok(vec![])
        }
        fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> {
            Ok(vec![])
        }
        fn get_prover_shard_summaries(&self, _: u64) -> Result<Vec<ProverShardSummary>> {
            Ok(vec![])
        }
    }

    fn allocation(filter: &[u8], status: ProverStatus) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status,
            confirmation_filter: filter.to_vec(),
            rejection_filter: vec![],
            join_frame_number: 1,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            epoch: u64::MAX,
            last_active_frame_number: 0,
            last_signed_frame_number: 0,
            ring: 0,
            vertex_address: vec![],
        }
    }

    /// The command against a node: a mixed leave sends nothing and names the
    /// filter, and the Active filter alone goes out. Manual workers serve both
    /// filters, so the leave reaches this check whatever else the command asks.
    #[tokio::test]
    async fn a_mixed_leave_sends_nothing_and_the_active_filter_goes_out() {
        let directory = tempfile::tempdir().unwrap();
        let (active, leaving) = (vec![0xA1; 32], vec![0xB1; 32]);
        let mut gone = allocation(&leaving, ProverStatus::Leaving);
        gone.leave_frame_number = 1;
        let registry = OneProver(vec![allocation(&active, ProverStatus::Active), gone]);
        let manual = |core_id, filter: &Vec<u8>| quil_rpc::WorkerEntry {
            core_id,
            filter: filter.clone(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: true,
            allocated: true,
            execution: None,
            draining: false,
        };
        let sends = Arc::new(AtomicUsize::new(0));
        let counted = sends.clone();
        let server = quil_rpc::NodeRpcServer::default()
            .with_prover_address(vec![1; 32])
            .with_prover_registry(Arc::new(registry))
            .with_workers_view(Arc::new(std::sync::RwLock::new(vec![
                manual(1, &active),
                manual(2, &leaving),
            ])))
            .with_send_handler_fn(Arc::new(move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }));
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
        key_manager.create_falcon_key("q-prover-key").unwrap();
        let seed = [55; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
        key_manager.set_peer_priv_key_hex(&hex::encode([&seed[..], &public[..]].concat()));
        let pc = super::super::ProverCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.path().to_path_buf(),
            connect_opts: crate::rpc::ConnectOpts {
                listen_grpc_multiaddr: multiaddr,
                ..Default::default()
            },
            key_manager,
            epoch_waits: super::super::tests::no_epoch_wait(),
        };

        let refusal = super::super::ops::leave(&pc, &[hex::encode(&active), hex::encode(&leaving)])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("1 of 2 filters are not Active"),
            "{refusal}"
        );
        assert!(refusal.contains(&hex::encode(&leaving)), "{refusal}");
        assert_eq!(sends.load(Ordering::SeqCst), 0, "nothing goes out");

        super::super::ops::leave(&pc, &[hex::encode(&active)])
            .await
            .unwrap();
        assert_eq!(
            sends.load(Ordering::SeqCst),
            1,
            "the active filter goes out"
        );
        let _ = stop.send(());
    }
}
