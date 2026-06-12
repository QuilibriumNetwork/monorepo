//! `MixnetService` gRPC server — mixnet tag + round-stream RPCs.
//!
//! The mixnet is the privacy layer that moves messages through
//! multi-hop mix rounds before they surface on any prover's inbox.
//! A full implementation needs the onion crypto stack, a round
//! scheduler, and per-peer mix queues — all of which live as larger
//! subsystems. This module stands up the wire contract so peers
//! dialing `MixnetService.PutMessage` / `RoundStream` against a Rust
//! node don't hit tonic's `Unimplemented` — instead they get a
//! well-formed structured response.
//!
//! Go's server at `node/consensus/global/mixnet_service.go` gates
//! the RPCs on `AllowedPeerPolicyType::OnlyGlobalProverPeer` for the
//! round stream and `AnyPeer` for put/tag — we enforce neither here
//! since the master's peer_auth_interceptor already attaches peer
//! identity and callers can consult that extension when they need
//! policy-level gating.

use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use quil_types::proto::application::Message as AppMessage;
use quil_types::proto::global::{
    mixnet_service_server::MixnetService, PutMessageRequest, PutMessageResponse,
};

/// Stub MixnetService. Accepts `PutMessage` as a no-op (the message
/// never enters an actual mix round) and keeps `RoundStream` open
/// but silent until the peer disconnects.
pub struct MixnetRpcServer;

impl MixnetRpcServer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MixnetRpcServer {
    fn default() -> Self {
        Self
    }
}

type RoundStreamOut = Pin<Box<dyn Stream<Item = Result<AppMessage, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl MixnetService for MixnetRpcServer {
    async fn put_message(
        &self,
        _request: Request<PutMessageRequest>,
    ) -> Result<Response<PutMessageResponse>, Status> {
        // No-op: acknowledge the put so the caller proceeds, but we
        // don't join the mix round. When the full mix scheduler lands
        // this handler will fan the message into a per-round queue.
        Ok(Response::new(PutMessageResponse {}))
    }

    type RoundStreamStream = RoundStreamOut;

    async fn round_stream(
        &self,
        request: Request<Streaming<AppMessage>>,
    ) -> Result<Response<Self::RoundStreamStream>, Status> {
        // Drain any inbound traffic so the client's sender isn't
        // back-pressured, but emit nothing. Future mix-round
        // implementation will fan-in these messages to the mix queue
        // and fan-out shuffled ciphertexts.
        let mut inbound = request.into_inner();
        tokio::spawn(async move {
            while let Ok(Some(_msg)) = inbound.message().await {
                // Silently accept — permissive stub.
            }
        });

        let outbound = async_stream::stream! {
            // Park indefinitely — stream ends when the client hangs up.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                if false {
                    yield Err::<AppMessage, _>(Status::cancelled("unused"));
                }
            }
        };
        Ok(Response::new(Box::pin(outbound)))
    }
}
