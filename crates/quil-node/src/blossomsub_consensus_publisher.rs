/// Bridges `quil_engine::consensus_glue::ConsensusPublisher` to BlossomSub.
/// Proposals go on `GLOBAL_FRAME`, votes and timeouts on `GLOBAL_CONSENSUS`.
pub(crate) struct BlossomsubConsensusPublisher {
    pub(crate) p2p_handle: quil_p2p::node::P2PHandle,
    /// Self-loopback for consensus messages so the local
    /// `vote_aggregator` / event-loop dispatcher sees the leader's
    /// own proposals (BlossomSub does not echo self-published
    /// messages).
    pub(crate) loopback_tx: tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
    pub(crate) self_peer_id: Vec<u8>,
    /// Supervisor-tracked fire-and-forget spawner. The trait API is
    /// sync, so we can't await inline; detached tasks are tracked so
    /// panics surface as `JoinError` instead of being swallowed.
    pub(crate) spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
}

impl quil_engine::consensus_glue::ConsensusPublisher for BlossomsubConsensusPublisher {
    fn publish_frame(&self, data: Vec<u8>) {
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_FRAME.to_vec();
        self.spawner.detach("blossomsub-publish-frame", async move {
            if let Err(e) = handle.publish(bitmask, data).await {
                tracing::warn!(error = %e, "publish_frame failed");
            }
            Ok(())
        });
    }

    fn publish_consensus(&self, data: Vec<u8>) {
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_CONSENSUS.to_vec();
        // Self-loopback: send the same payload onto the local receive
        // channel so the dispatcher's GLOBAL_CONSENSUS arm processes
        // it (vote_aggregator + event_loop). This is essential for the
        // proposer's own proposal/vote to reach its own aggregator,
        // since BlossomSub silently drops self-published messages.
        let loopback = self.loopback_tx.clone();
        let self_id = self.self_peer_id.clone();
        let data_for_loopback = data.clone();
        let bitmask_for_loopback = bitmask.clone();
        self.spawner.detach("blossomsub-loopback-consensus", async move {
            let _ = loopback
                .send(quil_p2p::node::ReceivedMessage {
                    bitmask: bitmask_for_loopback,
                    data: data_for_loopback,
                    from: self_id,
                })
                .await;
            Ok(())
        });
        self.spawner.detach("blossomsub-publish-consensus", async move {
            if let Err(e) = handle.publish(bitmask, data).await {
                tracing::warn!(error = %e, "publish_consensus failed");
            }
            Ok(())
        });
    }

    fn publish_prover_message(&self, data: Vec<u8>) {
        // `data` is a `MessageRequest`-wrapped inner payload (built by
        // `consensus_glue::wrap_message_request`). Wrap it in a
        // `MessageBundle` envelope and publish on the GLOBAL_PROVER
        // bitmask. Non-archive nodes can additionally route over
        // archive gRPC; the BlossomSub broadcast covers archive nodes.
        let handle = self.p2p_handle.clone();
        let bitmask = quil_engine::bitmasks::GLOBAL_PROVER.to_vec();
        self.spawner.detach("blossomsub-publish-prover", async move {
            // Decode the MessageRequest envelope so we can re-wrap
            // it inside a MessageBundle.
            let req = match quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(&data) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "publish_prover_message: bad MessageRequest envelope");
                    return Ok(());
                }
            };
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let bundle = quil_execution::message_envelope::CanonicalMessageBundle {
                requests: vec![Some(req)],
                timestamp,
            };
            match bundle.to_canonical_bytes() {
                Ok(bytes) => {
                    if let Err(e) = handle.publish(bitmask, bytes).await {
                        tracing::warn!(error = %e, "publish_prover_message failed");
                    }
                }
                Err(e) => tracing::error!(error = %e, "publish_prover_message: bundle encode failed"),
            }
            Ok(())
        });
    }
}
