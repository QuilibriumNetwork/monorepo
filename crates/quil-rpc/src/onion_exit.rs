//! Onion EXIT consumer — proxies a circuit's terminating payload to another
//! peer's gRPC, then relays the response back through the circuit.
//!
//! When a RELAY/DATA cell reaches this node as the exit, its payload is an onion
//! RPC request naming a TARGET PEER, a gRPC METHOD, and the request body. The
//! exit dials that peer's `:8340` service over pqnoise, invokes the method, and
//! sends the (status-prefixed) response back to the anonymous originator via the
//! circuit's reply path.
//!
//! Authorization is enforced at TWO layers:
//! 1. **Method allow-list** (here): only explicitly permitted method paths may be
//! proxied through the tunnel, so anonymous circuit traffic can't reach
//! arbitrary/sensitive RPCs. The operator configures the set.
//! 2. **Target-peer auth** (there): the dial's pqnoise handshake authenticates
//! THIS exit node's identity, so the target applies its normal per-caller RPC
//! authorization to the exit.
//!
//! DEFENSE 1 is also enforced: the target must be an in-network routing peer
//! (via the same PeerInfo-cache lookup the transport uses), never an open-web
//! address.
//!
//! Onion RPC request wire format:
//! `| target_peer_len(2 BE) | target_peer | method_len(2 BE) | method_utf8 | body |`
//! Reply: `| status(1) | payload |` — status 0 = ok (payload = response bytes),
//! 1 = error (payload = UTF-8 message).

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf, BufMut};

use crate::archive_client::QuilPqNoiseConnector;
use crate::onion_service::PeerRoutingLookup;
use quil_engine::worker_node::multiaddr_to_socket_addr;
use quil_p2p::onion::node::OnionReplyHandle;
use quil_p2p::onion::OnData;

/// Reply status byte: request succeeded, payload is the RPC response.
pub const STATUS_OK: u8 = 0;
/// Reply status byte: request failed, payload is a UTF-8 error message.
pub const STATUS_ERR: u8 = 1;

/// Build an onion RPC request payload (originator side / tests).
pub fn build_onion_rpc(target_peer: &[u8], method: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + target_peer.len() + method.len() + body.len());
    v.extend_from_slice(&(target_peer.len() as u16).to_be_bytes());
    v.extend_from_slice(target_peer);
    v.extend_from_slice(&(method.len() as u16).to_be_bytes());
    v.extend_from_slice(method.as_bytes());
    v.extend_from_slice(body);
    v
}

/// Parse an onion RPC request into `(target_peer, method, body)`.
fn parse_onion_rpc(payload: &[u8]) -> Option<(Vec<u8>, String, Vec<u8>)> {
    if payload.len() < 2 {
        return None;
    }
    let peer_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let after_peer = 2 + peer_len;
    if after_peer + 2 > payload.len() {
        return None;
    }
    let target_peer = payload[2..after_peer].to_vec();
    let method_len = u16::from_be_bytes([payload[after_peer], payload[after_peer + 1]]) as usize;
    let method_start = after_peer + 2;
    let body_start = method_start + method_len;
    if body_start > payload.len() {
        return None;
    }
    let method = String::from_utf8(payload[method_start..body_start].to_vec()).ok()?;
    let body = payload[body_start..].to_vec();
    Some((target_peer, method, body))
}

fn ok_reply(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(STATUS_OK);
    v.extend_from_slice(body);
    v
}

fn err_reply(msg: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + msg.len());
    v.push(STATUS_ERR);
    v.extend_from_slice(msg.as_bytes());
    v
}

/// Max concurrent proxied RPCs. Terminating cells arrive from anonymous circuit
/// traffic, each spawning a dial + RPC + reply; bound the fan-out so a flood
/// can't exhaust tasks / connections / memory. Excess requests are DROPPED (not
/// queued), which for an anonymous proxy is the right back-pressure.
const MAX_CONCURRENT_EXIT_RPCS: usize = 64;

/// The onion exit RPC proxy. Wire [`into_on_data`](Self::into_on_data) as the
/// `OnionNode` exit handler, and set the reply handle once the node exists.
pub struct OnionExitProxy {
    falcon_signing_key: Vec<u8>,
    peer_lookup: PeerRoutingLookup,
    allowed_methods: HashSet<String>,
    reply: OnceLock<OnionReplyHandle>,
    inflight: Arc<tokio::sync::Semaphore>,
}

impl OnionExitProxy {
    pub fn new(
        falcon_signing_key: Vec<u8>,
        peer_lookup: PeerRoutingLookup,
        allowed_methods: HashSet<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            falcon_signing_key,
            peer_lookup,
            allowed_methods,
            reply: OnceLock::new(),
            inflight: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_EXIT_RPCS)),
        })
    }

    /// Install the reply handle (from `OnionNode::reply_handle()`) so responses
    /// can be sent back through circuits. Call once, after node construction.
    pub fn set_reply_handle(&self, handle: OnionReplyHandle) {
        let _ = self.reply.set(handle);
    }

    /// Adapt this proxy into an `OnionNode` exit handler. Each terminating
    /// payload is processed on a spawned task (dial + RPC + reply are async).
    pub fn into_on_data(self: Arc<Self>) -> OnData {
        Arc::new(move |up_peer: &[u8], circ_id: u32, payload: Vec<u8>| {
            let this = Arc::clone(&self);
            let up_peer = up_peer.to_vec();
            tokio::spawn(async move {
                // Bound concurrency: drop (don't queue) when saturated.
                let _permit = match Arc::clone(&this.inflight).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::debug!("onion exit at capacity; dropping proxied request");
                        return;
                    }
                };
                this.handle(&up_peer, circ_id, payload).await;
            });
        })
    }

    async fn handle(&self, up_peer: &[u8], circ_id: u32, payload: Vec<u8>) {
        let reply = match self.process(payload).await {
            Ok(body) => ok_reply(&body),
            Err(e) => {
                tracing::debug!(error = %e, "onion exit rpc rejected/failed");
                err_reply(&e)
            }
        };
        if let Some(handle) = self.reply.get() {
            if let Err(e) = handle.send_reply(up_peer, circ_id, &reply).await {
                tracing::debug!(error = %e, "onion exit reply send failed");
            }
        }
    }

    async fn process(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let (target_peer, method, body) =
            parse_onion_rpc(&payload).ok_or_else(|| "malformed onion rpc request".to_string())?;

        // AUTHORIZATION: only allow-listed methods may be proxied anonymously.
        if !self.allowed_methods.contains(&method) {
            return Err(format!("method not authorized for onion proxy: {method}"));
        }
        self.dial_and_call(&target_peer, &method, body).await
    }

    async fn dial_and_call(
        &self,
        target_peer: &[u8],
        method: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        // DEFENSE 1: the target must be an in-network routing peer; use its
        // advertised stream multiaddr, never an arbitrary address.
        let addrs = (self.peer_lookup)(target_peer)
            .ok_or_else(|| "target is not an in-network routing peer".to_string())?;
        let socket_addr = addrs
            .iter()
            .find_map(|ma| multiaddr_to_socket_addr(ma))
            .ok_or_else(|| "target has no dialable stream multiaddr".to_string())?;

        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{socket_addr}"))
            .map_err(|e| e.to_string())?
            .connect_timeout(Duration::from_secs(10))
            .tcp_nodelay(true);
        let channel = endpoint
            .connect_with_connector(QuilPqNoiseConnector::new(self.falcon_signing_key.clone()))
            .await
            .map_err(|e| format!("dial: {e}"))?;

        let mut grpc = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(64 * 1024 * 1024)
            .max_encoding_message_size(64 * 1024 * 1024);
        grpc.ready().await.map_err(|e| format!("not ready: {e}"))?;

        let path = tonic::codegen::http::uri::PathAndQuery::from_maybe_shared(method.to_string())
            .map_err(|e| format!("bad method path: {e}"))?;
        let response = grpc
            .unary(tonic::Request::new(body), path, BytesCodec)
            .await
            .map_err(|e| format!("rpc {}: {}", e.code(), e.message()))?;
        Ok(response.into_inner())
    }
}

/// A tonic codec that passes raw bytes through unchanged — the onion request
/// body already IS the target method's serialized protobuf, and the response IS
/// its serialized protobuf, so the exit is a transparent proxy.
#[derive(Default, Clone)]
struct BytesCodec;

impl tonic::codec::Codec for BytesCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = BytesEncoder;
    type Decoder = BytesDecoder;
    fn encoder(&mut self) -> Self::Encoder {
        BytesEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        BytesDecoder
    }
}

struct BytesEncoder;
impl tonic::codec::Encoder for BytesEncoder {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn encode(
        &mut self,
        item: Vec<u8>,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), tonic::Status> {
        dst.put_slice(&item);
        Ok(())
    }
}

struct BytesDecoder;
impl tonic::codec::Decoder for BytesDecoder {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Vec<u8>>, tonic::Status> {
        let len = src.remaining();
        let mut out = vec![0u8; len];
        src.copy_to_slice(&mut out);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_rpc_request_round_trips() {
        let payload = build_onion_rpc(
            b"target-peer-id",
            "/quilibrium.node.global.pb.GlobalService/GetGlobalFrame",
            b"protobuf-request-bytes",
        );
        let (peer, method, body) = parse_onion_rpc(&payload).unwrap();
        assert_eq!(peer, b"target-peer-id");
        assert_eq!(method, "/quilibrium.node.global.pb.GlobalService/GetGlobalFrame");
        assert_eq!(body, b"protobuf-request-bytes");
    }

    #[test]
    fn malformed_requests_are_none() {
        assert!(parse_onion_rpc(&[0]).is_none());
        // peer_len says 100 but nothing follows
        assert!(parse_onion_rpc(&[0, 100]).is_none());
        // valid peer, method_len overflows
        assert!(parse_onion_rpc(&[0, 1, b'p', 0, 50]).is_none());
    }

    #[tokio::test]
    async fn unauthorized_method_is_rejected_without_dialing() {
        // Allow-list contains only one method; a different method is rejected
        // BEFORE any network dial (peer_lookup is never consulted).
        let mut allowed = HashSet::new();
        allowed.insert("/allowed/Method".to_string());
        let lookup: PeerRoutingLookup = Arc::new(|_| panic!("must not dial on auth failure"));
        let proxy = OnionExitProxy::new([7u8; 57], lookup, allowed);

        let req = build_onion_rpc(b"peer", "/forbidden/Method", b"x");
        let err = proxy.process(req).await.unwrap_err();
        assert!(err.contains("not authorized"), "got: {err}");
    }

    #[tokio::test]
    async fn malformed_payload_is_rejected() {
        let proxy = OnionExitProxy::new([0u8; 57], Arc::new(|_| None), HashSet::new());
        let err = proxy.process(vec![0x00]).await.unwrap_err();
        assert!(err.contains("malformed"), "got: {err}");
    }

    #[test]
    fn reply_framing() {
        assert_eq!(ok_reply(b"resp"), [&[STATUS_OK][..], b"resp"].concat());
        assert_eq!(err_reply("bad"), [&[STATUS_ERR][..], b"bad"].concat());
    }
}
