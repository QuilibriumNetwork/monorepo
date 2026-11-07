//! Prover lifecycle write ops: leave / confirm / reject / pause / resume /
//! delegate.
//!
//! Port of `proverLeave.go`, `proverConfirm.go`, `proverReject.go`,
//! `proverPause.go`, `proverResume.go`, `proverDelegate.go`. Each op:
//! 1. fetches the current global head frame,
//! 2. signs the op with `q-prover-key` (Falcon, [`super::sign`]),
//! 3. wraps it in the matching `MessageRequest` variant, and
//! 4. submits via `Send` with the `0xFF×32` global domain (outer Ed448
//!    `q-peer-key` auth).

use quil_types::crypto::Signer;
use quil_types::proto::global::{
    message_request::Request, AltShardUpdate, MessageRequest, ProverLeave, ProverPause,
    ProverReject, ProverResume, ProverUpdate,
};

use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::{GetWorkerInfoRequest, WorkerInfo};
use tonic::transport::Channel;

use super::{sign, ProverCtx};

/// All-0xFF 32-byte filter — the "all shards" default.
fn default_filter() -> Vec<u8> {
    vec![0xFFu8; 32]
}

/// Parse hex filter args. None is an error: the all-0xFF filter these ops once
/// sent for an empty list names no seat and nothing expands it to every shard,
/// so execution dropped the op while the command reported it sent.
fn parse_filters(op: &str, args: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    if args.is_empty() {
        anyhow::bail!(
            "prover {op} not sent: name the shard filters, as an empty list reaches no shard; \
             `qclient node prover status` lists this node's, then run \
             `qclient node prover {op} <filter>...`"
        );
    }
    args.iter()
        .map(|a| hex::decode(a).map_err(|e| anyhow::anyhow!("invalid filter hex {a:?}: {e}")))
        .collect()
}

/// Parse a single optional hex filter, defaulting to all-0xFF.
fn parse_single_filter(arg: Option<&str>) -> anyhow::Result<Vec<u8>> {
    match arg {
        None => Ok(default_filter()),
        Some(a) => hex::decode(a).map_err(|e| anyhow::anyhow!("invalid filter hex {a:?}: {e}")),
    }
}

/// Sign and send a multi-filter op as several ops when `filters` exceed what
/// one carries (see [`sign::op_chunks`]), each built by `build` over its own
/// filters at the same frame. Every op is signed before the first is sent, so
/// a filter no node decodes stops the command before anything goes out; a
/// failed send stops the rest and says how many filters went out.
async fn send_split(
    pc: &ProverCtx,
    client: &mut NodeServiceClient<Channel>,
    op: &str,
    filters: &[Vec<u8>],
    build: impl Fn(&[Vec<u8>]) -> anyhow::Result<Request>,
) -> anyhow::Result<()> {
    let chunks: Vec<&[Vec<u8>]> = sign::op_chunks(filters).collect();
    let requests = chunks
        .iter()
        .map(|chunk| build(*chunk))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let count = requests.len();
    let mut sent = 0;
    for (index, (request, chunk)) in requests.into_iter().zip(&chunks).enumerate() {
        pc.send_global(client, wrap(request))
            .await
            .map_err(|e| split_send_error(op, index, count, filters, sent, e))?;
        sent += chunk.len();
    }
    println!("{}", sent_text(op, count, filters.len()));
    Ok(())
}

/// What a sent op is known to have done: nothing yet. The node takes the
/// message and every node then judges it, with no answer back here.
fn sent_text(op: &str, messages: usize, filters: usize) -> String {
    let sent = if messages > 1 {
        format!("Prover {op} sent as {messages} messages for {filters} filters")
    } else {
        format!("Prover {op} sent")
    };
    format!(
        "{sent}; not yet included. `qclient node prover status` shows the change after this \
         node's next registry refresh, by the next epoch boundary; no change after that means \
         the network dropped it."
    )
}

/// The error of a split op whose message `index` (from 0) of `count` was not
/// sent after the first `sent` filters went out. After a partial send it
/// lists the unsent filters as the arguments of a follow-up command, so a
/// re-run does not resend the published ones.
fn split_send_error(
    op: &str,
    index: usize,
    count: usize,
    filters: &[Vec<u8>],
    sent: usize,
    err: impl std::fmt::Display,
) -> anyhow::Error {
    let mut message = format!(
        "prover {op} message {}/{count} not sent ({sent}/{} filters sent): {err}",
        index + 1,
        filters.len()
    );
    if sent > 0 {
        let unsent: Vec<String> = filters[sent..].iter().map(hex::encode).collect();
        message.push_str(&format!(
            "\nsend the {} unsent filters with: qclient node prover {op} {}",
            unsent.len(),
            unsent.join(" ")
        ));
    }
    anyhow::anyhow!(message)
}

/// Why a leave of `filters` should not go out, given the node's workers.
///
/// At a leave's confirm window the node decides it by the filter's workers,
/// and reports nothing back here. One any manual worker serves confirms (the
/// engine's `manually_managed_filters` reads the mode the same way). One only
/// auto workers serve goes to the score rule, which rejects it unless a much
/// better shard is free, and the seat returns to Active. One no worker serves
/// confirms as an orphan's, unless a free auto worker takes the seat first.
/// The manager refuses the same leaves (`manual_actions_allowed`).
fn leave_refusal(workers: &[WorkerInfo], filters: &[Vec<u8>]) -> Option<String> {
    if workers.is_empty() {
        return Some(
            "prover leave not sent: cannot tell the worker modes, the node reports no workers; \
             it may still be starting, so try again shortly"
                .to_string(),
        );
    }
    let free_auto = workers
        .iter()
        .any(|w| w.filter.is_empty() && !w.manually_managed && !w.draining);
    let mut auto = Vec::new();
    let mut unknown = Vec::new();
    for filter in filters {
        let serving: Vec<&WorkerInfo> = workers
            .iter()
            .filter(|w| !filter.is_empty() && &w.filter == filter)
            .collect();
        if serving.is_empty() {
            if free_auto {
                unknown.push(format!("  {}", hex::encode(filter)));
            }
        } else if !serving.iter().any(|w| w.manually_managed) {
            let cores: Vec<String> = serving.iter().map(|w| w.core_id.to_string()).collect();
            auto.push(format!(
                "  {} (worker {})",
                hex::encode(filter),
                cores.join(", ")
            ));
        }
    }
    if auto.is_empty() && unknown.is_empty() {
        return None;
    }
    let mut parts = vec!["prover leave not sent; no filter went out.".to_string()];
    if !auto.is_empty() {
        parts.push(format!(
            "{} of {} filters are on auto workers:\n{}\n\
             The node's score rule decides an auto worker's leave: unless a much better shard \
             is free it rejects the leave and the seat returns to Active.\n\
             To leave, first switch each worker to manual: in `qclient node prover manage`, on \
             the Allocations panel, put the cursor on its row, press Ctrl+O and confirm with \
             Enter. Then send the leave again.\n\
             A manual worker stays out of the node's planner until you switch it back: it idles \
             once the leave departs.",
            auto.len(),
            filters.len(),
            auto.join("\n")
        ));
    }
    if !unknown.is_empty() {
        parts.push(format!(
            "Cannot tell the worker mode of {} of {} filters: no worker serves them and an auto \
             worker is free, which may take the seat and leave the decision to the score rule:\n\
             {}\nCheck the filter, or wait for the node to bind it, and send the leave again.",
            unknown.len(),
            filters.len(),
            unknown.join("\n")
        ));
    }
    Some(parts.join("\n"))
}

pub async fn leave(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters("leave", filter_args)?;
    let mut client = pc.connect().await?;
    let workers = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "prover leave not sent: cannot read the worker modes from the node: {e}"
            )
        })?
        .into_inner()
        .worker_info;
    if let Some(refusal) = leave_refusal(&workers, &filters) {
        anyhow::bail!(refusal);
    }
    let frame = pc.last_global_head_frame(&mut client).await?;
    super::leave_check::require_active(&mut client, &filters).await?;
    send_split(pc, &mut client, "leave", &filters, |chunk| {
        let sig = sign::leave_sig(&pc.key_manager, chunk, frame)?;
        Ok(Request::Leave(ProverLeave {
            filters: chunk.to_vec(),
            frame_number: frame,
            public_key_signature_bls48581: Some(sig),
        }))
    })
    .await
}

pub async fn confirm(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters("confirm", filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.frame_in_this_epoch(&mut client, "confirm").await?;
    send_split(pc, &mut client, "confirm", &filters, |chunk| {
        Ok(Request::Confirm(sign::confirm_op(
            &pc.key_manager,
            chunk,
            frame,
        )?))
    })
    .await
}

// `filter` is deprecated in global.proto in favour of the repeated `filters`,
// but it is still on the wire: peers that predate the change send it, and
// dropping it here would change the encoded bytes. Carried through verbatim
// until the field is retired from the proto.
#[allow(deprecated)]
pub async fn reject(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters("reject", filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.frame_in_this_epoch(&mut client, "reject").await?;
    send_split(pc, &mut client, "reject", &filters, |chunk| {
        let sig = sign::reject_sig(&pc.key_manager, chunk, frame)?;
        Ok(Request::Reject(ProverReject {
            filter: Vec::new(), // deprecated field
            frame_number: frame,
            public_key_signature_bls48581: Some(sig),
            filters: chunk.to_vec(),
        }))
    })
    .await
}

pub async fn pause(pc: &ProverCtx, filter_arg: Option<&str>) -> anyhow::Result<()> {
    let filter = parse_single_filter(filter_arg)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::pause_sig(&pc.key_manager, &filter, frame)?;
    let op = ProverPause {
        filter,
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Pause(op)))
        .await?;
    println!("{}", sent_text("pause", 1, 1));
    Ok(())
}

pub async fn resume(pc: &ProverCtx, filter_arg: Option<&str>) -> anyhow::Result<()> {
    let filter = parse_single_filter(filter_arg)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::resume_sig(&pc.key_manager, &filter, frame)?;
    let op = ProverResume {
        filter,
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Resume(op)))
        .await?;
    println!("{}", sent_text("resume", 1, 1));
    Ok(())
}

pub async fn delegate(pc: &ProverCtx, address: &str) -> anyhow::Result<()> {
    let addr_hex = address.strip_prefix("0x").unwrap_or(address);
    let delegate_address = hex::decode(addr_hex)
        .map_err(|_| anyhow::anyhow!("Invalid delegate address: must be 32 bytes hex-encoded"))?;
    if delegate_address.len() != 32 {
        anyhow::bail!("Invalid delegate address: must be 32 bytes hex-encoded");
    }

    let mut client = pc.connect().await?;
    let info = client
        .get_node_info(tonic::Request::new(
            quil_types::proto::node::GetNodeInfoRequest::default(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    if info.epoch_length_frames > 0 {
        quil_types::consensus::set_epoch_length_frames(info.epoch_length_frames);
    }
    quil_types::consensus::init_prover_op_replay_guard_epoch(pc.node_config.p2p.network);
    // From the prover operation replay guard epoch the update signs the head
    // frame, so it cannot be submitted again later; before it the signature
    // covers the delegate address alone (frame 0).
    let head = pc.last_global_head_frame(&mut client).await?;
    let frame = quil_execution::global_intrinsic::prover_ops::ProverUpdate::signed_frame(head);
    let sig = sign::update_sig(&pc.key_manager, &delegate_address, frame)?;
    let op = ProverUpdate {
        delegate_address: delegate_address.clone(),
        public_key_signature_bls48581: Some(sig),
        frame_number: frame,
    };
    pc.send_global(&mut client, wrap(Request::Update(op)))
        .await?;
    println!(
        "Delegate address updated to 0x{}",
        hex::encode(&delegate_address)
    );
    Ok(())
}

/// `alt-shard-update <v-adds> <v-removes> <he-adds> <he-removes>` — an
/// external shard's signed root commitment. Signs `frame ‖ roots` with the
/// Falcon `q-prover-key` under the `ALT_SHARD_UPDATE` domain.
pub async fn alt_shard_update(pc: &ProverCtx, roots_hex: &[String]) -> anyhow::Result<()> {
    if roots_hex.len() != 4 {
        anyhow::bail!(
            "alt-shard-update requires 4 root args: <vertex-adds> <vertex-removes> \
             <hyperedge-adds> <hyperedge-removes>"
        );
    }
    let root_names = [
        "vertex-adds-root",
        "vertex-removes-root",
        "hyperedge-adds-root",
        "hyperedge-removes-root",
    ];
    let mut roots: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (i, arg) in roots_hex.iter().enumerate() {
        roots.push(
            hex::decode(arg).map_err(|e| anyhow::anyhow!("invalid {} hex: {e}", root_names[i]))?,
        );
    }

    let mut client = pc.connect().await?;
    let frame = pc.head_frame(&mut client).await?;

    let signer: Box<dyn Signer> = pc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key: {e}"))?;
    let public_key = signer.public_key().to_vec();

    // message = frame(8 BE) ‖ vAdds ‖ vRems ‖ heAdds ‖ heRems
    let mut message = Vec::with_capacity(8 + roots.iter().map(|r| r.len()).sum::<usize>());
    message.extend_from_slice(&frame.to_be_bytes());
    for r in &roots {
        message.extend_from_slice(r);
    }
    let domain =
        quil_execution::global_intrinsic::alt_shard_update_materialize::alt_shard_update_domain()
            .map_err(|e| anyhow::anyhow!("alt shard update domain: {e}"))?;
    let signature = signer
        .sign_with_domain(&message, &domain)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    let op = AltShardUpdate {
        public_key,
        frame_number: frame,
        vertex_adds_root: roots[0].clone(),
        vertex_removes_root: roots[1].clone(),
        hyperedge_adds_root: roots[2].clone(),
        hyperedge_removes_root: roots[3].clone(),
        signature,
    };
    pc.send_global(&mut client, wrap(Request::AltShardUpdate(op)))
        .await?;
    println!("Alt shard update sent successfully");
    Ok(())
}

fn wrap(request: Request) -> MessageRequest {
    MessageRequest {
        request: Some(request),
        timestamp: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn worker(core_id: u32, filter: &[u8], manually_managed: bool) -> WorkerInfo {
        WorkerInfo {
            core_id,
            filter: filter.to_vec(),
            manually_managed,
            ..Default::default()
        }
    }

    /// Each worker state the node decides a leave by: only a filter no manual
    /// worker serves goes to the score rule.
    #[test]
    fn a_leave_is_refused_by_the_mode_the_node_decides_it_by() {
        let (a, b, c) = (vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]);
        let auto_a = worker(1, &a, false);
        let manual_a = worker(2, &a, true);
        let manual_b = worker(3, &b, true);
        let free_auto = worker(4, &[], false);
        let free_manual = worker(5, &[], true);
        let only = |filter: &Vec<u8>| vec![filter.clone()];

        assert_eq!(
            leave_refusal(std::slice::from_ref(&manual_a), &only(&a)),
            None,
            "a manual worker's leave confirms"
        );
        assert_eq!(
            leave_refusal(&[auto_a.clone(), manual_a], &only(&a)),
            None,
            "any manual worker on the filter makes the node confirm it"
        );
        assert_eq!(
            leave_refusal(std::slice::from_ref(&manual_b), &only(&c)),
            None,
            "no worker and none free: the node confirms it as an orphan's"
        );
        assert_eq!(
            leave_refusal(&[manual_b.clone(), free_manual], &only(&c)),
            None,
            "a free manual worker taking the seat confirms it too"
        );
        let draining = WorkerInfo {
            draining: true,
            ..free_auto.clone()
        };
        assert_eq!(
            leave_refusal(&[manual_b.clone(), draining], &only(&c)),
            None,
            "a draining worker takes no seat"
        );

        // One auto filter stops the whole command and names only that filter,
        // with its worker, what would happen and the way to switch.
        let refusal = leave_refusal(&[auto_a, manual_b.clone()], &[a.clone(), b.clone()])
            .expect("an auto worker's leave is refused");
        for text in [
            "1 of 2 filters are on auto workers",
            &format!("{} (worker 1)", hex::encode(&a)),
            "the seat returns to Active",
            "Ctrl+O",
            "stays out of the node's planner",
        ] {
            assert!(refusal.contains(text), "{text} in {refusal}");
        }
        assert!(!refusal.contains(&hex::encode(&b)), "{refusal}");

        // What the worker list cannot settle fails closed, with the reason.
        let refusal = leave_refusal(&[manual_b, free_auto], &only(&c))
            .expect("a free auto worker may take the seat");
        assert!(
            refusal.contains("Cannot tell the worker mode of 1 of 1"),
            "{refusal}"
        );
        assert!(refusal.contains(&hex::encode(&c)), "{refusal}");
        let refusal = leave_refusal(&[], &only(&c)).expect("no workers reported");
        assert!(refusal.contains("reports no workers"), "{refusal}");
    }

    /// An empty filter names no seat; it must not match the free workers' own
    /// empty filters and read as served by them.
    #[test]
    fn an_empty_filter_is_not_served_by_the_free_workers() {
        let workers = [worker(1, &[], true), worker(2, &[0xAA; 32], true)];
        assert_eq!(leave_refusal(&workers, &[Vec::new()]), None);
        let workers = [worker(1, &[], false), worker(2, &[0xAA; 32], true)];
        let refusal = leave_refusal(&workers, &[Vec::new()]).expect("a free auto worker");
        assert!(!refusal.contains("on auto workers"), "{refusal}");
    }

    fn prover_ctx(directory: &std::path::Path, multiaddr: String) -> ProverCtx {
        let key_manager = Arc::new(
            quil_keys::FileKeyManager::new(
                directory.join("keys.yml"),
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
        ProverCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.to_path_buf(),
            connect_opts: crate::rpc::ConnectOpts {
                listen_grpc_multiaddr: multiaddr,
                ..Default::default()
            },
            key_manager,
            epoch_waits: super::super::tests::no_epoch_wait(),
        }
    }

    /// Serve `routes` on a local port; the multiaddr to reach them and their
    /// stop.
    async fn serve(routes: tonic::service::Routes) -> (String, tokio::sync::oneshot::Sender<()>) {
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
                .add_routes(routes)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        (multiaddr, stop)
    }

    struct OneSeat(Vec<u8>);

    impl quil_types::consensus::ProverRegistry for OneSeat {
        fn get_prover_info(
            &self,
            address: &[u8],
        ) -> quil_types::error::Result<Option<quil_types::consensus::ProverInfo>> {
            use quil_types::consensus::{ProverAllocationInfo, ProverInfo, ProverStatus};
            Ok(Some(ProverInfo {
                public_key: vec![0xAA; 74],
                address: address.to_vec(),
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: vec![ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: self.0.clone(),
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
                }],
                available_storage: 0,
                seniority: 0,
                delegate_address: vec![],
            }))
        }
        fn get_next_prover(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<u8>> {
            Ok(vec![])
        }
        fn get_ordered_provers(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<Vec<u8>>> {
            Ok(vec![])
        }
        fn get_active_provers(
            &self,
            _: &[u8],
            _: u64,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(vec![])
        }
        fn get_prover_count(&self, _: &[u8]) -> quil_types::error::Result<usize> {
            Ok(0)
        }
        fn get_provers(
            &self,
            _: &[u8],
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(vec![])
        }
        fn get_provers_by_status(
            &self,
            _: &[u8],
            _: quil_types::consensus::ProverStatus,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(vec![])
        }
        fn get_prover_shard_summaries(
            &self,
            _: u64,
        ) -> quil_types::error::Result<Vec<quil_types::consensus::ProverShardSummary>> {
            Ok(vec![])
        }
    }

    /// The command against a node: an auto worker's leave sends nothing, and
    /// the same leave goes out once the operator has switched the worker.
    #[tokio::test]
    async fn a_leave_on_an_auto_worker_sends_nothing_until_it_is_manual() {
        let directory = tempfile::tempdir().unwrap();
        let filter = vec![0xAA; 32];
        let entry = |manually_managed| quil_rpc::WorkerEntry {
            core_id: 1,
            filter: filter.clone(),
            available_storage: 0,
            total_storage: 0,
            manually_managed,
            allocated: true,
            execution: None,
            draining: false,
        };
        let view = Arc::new(std::sync::RwLock::new(vec![entry(false)]));
        let sends = Arc::new(AtomicUsize::new(0));
        let counted = sends.clone();
        let server = quil_rpc::NodeRpcServer::default()
            .with_prover_address(vec![1; 32])
            .with_prover_registry(Arc::new(OneSeat(filter.clone())))
            .with_workers_view(view.clone())
            .with_send_handler_fn(Arc::new(move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }));
        let (multiaddr, stop) = serve(tonic::service::Routes::new(
            quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
        ))
        .await;
        let pc = prover_ctx(directory.path(), multiaddr);
        let args = [hex::encode(&filter)];

        let refusal = leave(&pc, &args).await.unwrap_err().to_string();
        assert!(refusal.contains("on auto workers"), "{refusal}");
        assert_eq!(sends.load(Ordering::SeqCst), 0, "nothing goes out");

        view.write().unwrap().clear();
        let refusal = leave(&pc, &args).await.unwrap_err().to_string();
        assert!(refusal.contains("reports no workers"), "{refusal}");
        assert_eq!(sends.load(Ordering::SeqCst), 0, "nothing goes out");

        *view.write().unwrap() = vec![entry(true)];
        leave(&pc, &args).await.unwrap();
        assert_eq!(sends.load(Ordering::SeqCst), 1, "the leave goes out");
        let _ = stop.send(());
    }

    /// A node that cannot answer the read gets no leave, and the error says
    /// which read failed.
    #[tokio::test]
    async fn a_failed_worker_read_refuses_the_leave() {
        let directory = tempfile::tempdir().unwrap();
        // Only another service on the port: the node's calls answer unimplemented.
        let (multiaddr, stop) = serve(tonic::service::Routes::new(
            quil_types::proto::node::connectivity_service_server::ConnectivityServiceServer::new(
                quil_rpc::stub_services::ConnectivityRpcServer,
            ),
        ))
        .await;
        let pc = prover_ctx(directory.path(), multiaddr);
        let refusal = leave(&pc, &[hex::encode([0xAA; 32])])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refusal.starts_with("prover leave not sent: cannot read the worker modes"),
            "{refusal}"
        );
        let _ = stop.send(());
    }

    /// A send says what is known: sent, not included, and how to check.
    #[test]
    fn a_sent_op_does_not_claim_success() {
        for text in [sent_text("leave", 1, 1), sent_text("leave", 3, 250)] {
            assert!(!text.contains("successfully"), "{text}");
            assert!(text.contains("not yet included"), "{text}");
            assert!(text.contains("qclient node prover status"), "{text}");
            assert!(text.contains("by the next epoch boundary"), "{text}");
        }
        assert!(sent_text("leave", 3, 250).starts_with("Prover leave sent as 3 messages for 250"));
    }

    /// An empty list is refused with the fix, for each op that took the dead
    /// all-0xFF default; named filters parse, all-0xFF included if typed.
    #[test]
    fn an_empty_filter_list_is_refused_with_the_fix() {
        for op in ["leave", "confirm", "reject"] {
            let refusal = parse_filters(op, &[]).unwrap_err().to_string();
            assert!(
                refusal.starts_with(&format!("prover {op} not sent")),
                "{refusal}"
            );
            assert!(refusal.contains("qclient node prover status"), "{refusal}");
            assert!(
                refusal.contains(&format!("qclient node prover {op} <filter>")),
                "{refusal}"
            );
        }
        let typed = ["aabb".to_string(), "ff".repeat(32)];
        assert_eq!(
            parse_filters("leave", &typed).unwrap(),
            vec![vec![0xAA, 0xBB], vec![0xFF; 32]]
        );
        assert!(parse_filters("leave", &["zz".to_string()]).is_err());
    }

    /// A partial send names the unsent filters as follow-up arguments, so a
    /// re-run does not resend the published messages; a first failure has
    /// nothing to leave out.
    #[test]
    fn a_partial_split_send_lists_the_unsent_filters() {
        let filters: Vec<Vec<u8>> = (0..250u16).map(|n| n.to_be_bytes().to_vec()).collect();
        let error = split_send_error("leave", 1, 3, &filters, 100, "boom").to_string();
        let (head, follow_up) = error.split_once('\n').expect("a follow-up line");
        assert_eq!(
            head,
            "prover leave message 2/3 not sent (100/250 filters sent): boom"
        );
        let args: Vec<&str> = follow_up
            .strip_prefix("send the 150 unsent filters with: qclient node prover leave ")
            .expect("the follow-up command")
            .split(' ')
            .collect();
        assert_eq!(args.len(), 150);
        assert_eq!((args[0], args[149]), ("0064", "00f9"));
        let first = split_send_error("leave", 0, 3, &filters, 0, "boom").to_string();
        assert_eq!(
            first,
            "prover leave message 1/3 not sent (0/250 filters sent): boom"
        );
    }
}
