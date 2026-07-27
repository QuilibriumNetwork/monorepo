//! `Send` RPC helper — wrap a `MessageRequest` in a `MessageBundle`,
//! sign the bundle's canonical bytes with the Ed448 `q-peer-key`, and
//! submit via `NodeService::Send`.
//!
//! Port of `SendTransaction` (`client/cmd/token/send.go`). The outer
//! authentication signature is **Ed448** (`NODE_AUTHENTICATION ‖ domain`)
//! and is NOT part of the post-quantum migration — the node still
//! verifies this envelope with Ed448 (see
//! `crates/quil-rpc/tests/cross_language_signing.rs`).

use std::time::{SystemTime, UNIX_EPOCH};

use tonic::transport::Channel;

use quil_execution::message_envelope::proto_message_bundle_to_canonical_bytes;
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::{MessageBundle, MessageRequest};
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::SendRequest;

/// Current time in milliseconds since the Unix epoch (`time.Now().UnixMilli()`).
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The outer-auth signing domain: `"NODE_AUTHENTICATION" ‖ domain`.
pub fn node_auth_domain(domain: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(b"NODE_AUTHENTICATION".len() + domain.len());
    d.extend_from_slice(b"NODE_AUTHENTICATION");
    d.extend_from_slice(domain);
    d
}

/// Sign a already-built proto `MessageBundle` with `q-peer-key`, returning
/// the Ed448 authentication signature over the bundle's canonical bytes.
pub fn sign_bundle(
    key_manager: &FileKeyManager,
    domain: &[u8],
    bundle: &MessageBundle,
) -> anyhow::Result<Vec<u8>> {
    let payload = proto_message_bundle_to_canonical_bytes(bundle)
        .map_err(|e| anyhow::anyhow!("canonicalize bundle: {e}"))?;
    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-peer-key")
        .map_err(|e| anyhow::anyhow!("get q-peer-key: {e}"))?;
    let sig = signer
        .sign_with_domain(&payload, &node_auth_domain(domain))
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;
    Ok(sig)
}

/// Wrap `request` in a single-request `MessageBundle`, sign it, and submit
/// via `NodeService::Send`. Port of `SendTransaction`.
pub async fn send_message_request(
    client: &mut NodeServiceClient<Channel>,
    key_manager: &FileKeyManager,
    domain: Vec<u8>,
    request: MessageRequest,
) -> anyhow::Result<()> {
    let bundle = MessageBundle {
        requests: vec![request],
        timestamp: now_millis(),
    };

    let sig = sign_bundle(key_manager, &domain, &bundle)?;

    client
        .send(tonic::Request::new(SendRequest {
            domain,
            request: Some(bundle),
            authentication: sig,
            delivery_data: Vec::new(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("send rpc: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_auth_domain_prefixes() {
        let d = node_auth_domain(&[0xFFu8; 32]);
        assert_eq!(&d[..19], b"NODE_AUTHENTICATION");
        assert_eq!(&d[19..], &[0xFFu8; 32]);
    }
}
