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

/// Sign and submit an already-built bundle (its timestamp is kept, e.g. when
/// a settlement is bound to the bundle's exact canonical bytes).
pub async fn send_message_bundle(
    client: &mut NodeServiceClient<Channel>,
    key_manager: &FileKeyManager,
    domain: Vec<u8>,
    bundle: MessageBundle,
) -> anyhow::Result<()> {
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

/// Seconds a paid submission waits for its QUIL settlement to be certified.
pub const PAID_SUBMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(900);

/// Submit `request` executed under `execution_domain` in a bundle that opens
/// with a settlement claim paying its QUIL fee: build the bundle, pay a QUIL
/// settlement from this node's wallet bound to it, wait for certification, then
/// send claim and request together to `submit_domain`. Every write to an
/// application other than QUIL is priced and needs this.
#[cfg(feature = "native-proof")]
pub async fn send_paid_request(
    global: crate::context::GlobalArgs,
    client: &mut NodeServiceClient<Channel>,
    key_manager: &FileKeyManager,
    submit_domain: Vec<u8>,
    execution_domain: [u8; 32],
    request: MessageRequest,
) -> anyhow::Result<()> {
    use quil_execution::message_envelope::{proto_message_request_to_canonical_inner_bytes, CanonicalMessageBundle, CanonicalMessageRequest};
    use quil_types::proto::global::message_request::Request;
    let timestamp = now_millis();
    let inner = proto_message_request_to_canonical_inner_bytes(&request).map_err(|e| anyhow::anyhow!("canonical request: {e}"))?;
    let rest = CanonicalMessageBundle {
        requests: vec![None, Some(CanonicalMessageRequest::wrap(inner).map_err(|e| anyhow::anyhow!("wrap request: {e}"))?)],
        timestamp,
    };
    let (claim, global_execution) = crate::commands::token::pay_for_bundle(global, execution_domain, &rest, PAID_SUBMISSION_WAIT).await?;
    let bundle = MessageBundle {
        requests: vec![
            MessageRequest {
                request: Some(Request::TokenOperation(quil_types::proto::token::TokenOperation { canonical_bytes: claim })),
                timestamp: 0,
            },
            request,
        ],
        timestamp,
    };
    // The node sees exactly the bundle the settlement is bound to.
    let canonical = CanonicalMessageBundle::from_canonical_bytes(&proto_message_bundle_to_canonical_bytes(&bundle)
        .map_err(|e| anyhow::anyhow!("canonicalize paid bundle: {e}"))?)
        .map_err(|e| anyhow::anyhow!("decode paid bundle: {e}"))?;
    anyhow::ensure!(
        quil_execution::token_intrinsic::settlement_claim::bundle_context(&canonical)?
            == quil_execution::token_intrinsic::settlement_claim::bundle_context(&rest)?,
        "paid bundle does not match the settlement's binding"
    );
    send_to_venue(client, key_manager, submit_domain, global_execution, bundle).await
}

/// Publish a bundle to the venue that executes it: the global prover topic
/// when the global venue does (a deploy, or an application no shard covers,
/// which has no subscribers of its own), otherwise the application's shard
/// topic, where its provers are. The other topic is tried only if the first
/// publish finds nobody, since a bundle the global frame carries for a covered
/// application occupies the frame and executes nowhere.
pub async fn send_to_venue(
    client: &mut NodeServiceClient<Channel>,
    key_manager: &FileKeyManager,
    submit_domain: Vec<u8>,
    global_execution: bool,
    bundle: MessageBundle,
) -> anyhow::Result<()> {
    let global = vec![0xffu8; 32];
    if submit_domain == global || global_execution {
        return send_message_bundle(client, key_manager, global, bundle).await;
    }
    let shard = match send_message_bundle(client, key_manager, submit_domain.clone(), bundle.clone()).await {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    // Coverage can change between the quote and submission.
    eprintln!("warning: the application's shard topic did not accept the bundle ({shard}); trying the global venue");
    send_message_bundle(client, key_manager, global, bundle).await
        .map_err(|global| anyhow::anyhow!("shard topic: {shard}; global topic: {global}"))
}

#[cfg(not(feature = "native-proof"))]
pub async fn send_paid_request(
    _: crate::context::GlobalArgs, _: &mut NodeServiceClient<Channel>, _: &FileKeyManager,
    _: Vec<u8>, _: [u8; 32], _: MessageRequest,
) -> anyhow::Result<()> {
    anyhow::bail!("writes are paid in QUIL; this build lacks native proofs")
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
