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
    deliver(
        client,
        SendRequest {
            domain,
            request: Some(bundle),
            authentication: sig,
            delivery_data: Vec::new(),
        },
    )
    .await
}

/// Send `request`, resending it unchanged on a transient failure.
async fn deliver(
    client: &mut NodeServiceClient<Channel>,
    request: SendRequest,
) -> anyhow::Result<()> {
    crate::retry::deliver(client, request)
        .await
        .map_err(|e| anyhow::anyhow!("send rpc: {e}"))
}

/// Seconds a paid submission waits for its QUIL settlement to be certified.
pub const PAID_SUBMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(900);

/// The engine that executes `request` in an application, or `None` for a
/// request no application engine executes.
#[cfg(any(test, feature = "native-proof"))]
fn request_engine(request: &MessageRequest) -> Option<&'static str> {
    use quil_types::proto::global::message_request::Request;
    match request.request.as_ref()? {
        Request::TokenDeploy(_) | Request::TokenUpdate(_) | Request::TokenOperation(_) => {
            Some("token")
        }
        Request::HypergraphDeploy(_)
        | Request::HypergraphUpdate(_)
        | Request::VertexAdd(_)
        | Request::VertexRemove(_)
        | Request::HyperedgeAdd(_)
        | Request::HyperedgeRemove(_) => Some("hypergraph"),
        Request::ComputeDeploy(_)
        | Request::ComputeUpdate(_)
        | Request::CodeDeploy(_)
        | Request::CodeExecute(_)
        | Request::CodeFinalize(_) => Some("compute"),
        _ => None,
    }
}

/// Refuse a write to an application whose engine does not execute it. That
/// engine skips the operation, so its paid bundle succeeds, consumes the
/// settlement and writes nothing (a vertex add sent to a token's domain).
/// `route` is the application's type domain.
#[cfg(any(test, feature = "native-proof"))]
pub fn check_request_route(request: &MessageRequest, route: &[u8; 32]) -> anyhow::Result<()> {
    let Some(wanted) = request_engine(request) else {
        return Ok(());
    };
    let runs = quil_execution::manager::engine_for_route(route);
    anyhow::ensure!(
        runs == Some(wanted),
        "this application runs the {} engine, which does not execute this {wanted} write \
         (it would be charged and write nothing); address it to a {wanted} application",
        runs.unwrap_or("no known")
    );
    Ok(())
}

/// An application's type domain from its metadata vertex (the vertex at
/// `0xff*32`, key `0xff*32`), as the node routes it.
#[cfg(any(test, feature = "native-proof"))]
pub fn route_from_metadata(blob: &[u8]) -> anyhow::Result<[u8; 32]> {
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| anyhow::anyhow!("application metadata: {e}"))?,
    };
    let route = tree
        .get(&[0xFF; 32])
        .ok_or_else(|| anyhow::anyhow!("application metadata has no type domain"))?;
    route
        .get(..32)
        .and_then(|route| route.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("application type domain is shorter than 32 bytes"))
}

/// The type domain the node routes `application` by: a base domain routes as
/// itself, a deployed application by its metadata vertex.
#[cfg(feature = "native-proof")]
async fn application_route(
    client: &NodeServiceClient<Channel>,
    application: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    if quil_execution::manager::engine_for_route(application).is_some() {
        return Ok(*application);
    }
    let mut address = application.to_vec();
    address.extend_from_slice(&[0xFF; 32]);
    let response = client
        .clone()
        .max_decoding_message_size(64 << 20)
        .get_vertex_data(quil_types::proto::node::GetVertexDataRequest {
            address,
            full_data: true,
        })
        .await
        .map_err(|e| anyhow::anyhow!("application metadata: {e}"))?
        .into_inner();
    anyhow::ensure!(
        !response.raw_data.is_empty(),
        "application {} is not deployed",
        hex::encode(application)
    );
    route_from_metadata(&response.raw_data)
}

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
    use quil_execution::message_envelope::{
        proto_message_request_to_canonical_inner_bytes, CanonicalMessageBundle,
        CanonicalMessageRequest,
    };
    use quil_types::proto::global::message_request::Request;
    // Before paying: the settlement cannot be recovered once it funds a
    // bundle the application's engine skips.
    check_request_route(
        &request,
        &application_route(client, &execution_domain).await?,
    )?;
    let timestamp = now_millis();
    let inner = proto_message_request_to_canonical_inner_bytes(&request)
        .map_err(|e| anyhow::anyhow!("canonical request: {e}"))?;
    let rest = CanonicalMessageBundle {
        requests: vec![
            None,
            Some(
                CanonicalMessageRequest::wrap(inner)
                    .map_err(|e| anyhow::anyhow!("wrap request: {e}"))?,
            ),
        ],
        timestamp,
    };
    let (claim, global_execution) = crate::commands::token::pay_for_bundle(
        global,
        execution_domain,
        &rest,
        PAID_SUBMISSION_WAIT,
    )
    .await?;
    let bundle = MessageBundle {
        requests: vec![
            MessageRequest {
                request: Some(Request::TokenOperation(
                    quil_types::proto::token::TokenOperation {
                        canonical_bytes: claim,
                    },
                )),
                timestamp: 0,
            },
            request,
        ],
        timestamp,
    };
    // The node sees exactly the bundle the settlement is bound to.
    let canonical = CanonicalMessageBundle::from_canonical_bytes(
        &proto_message_bundle_to_canonical_bytes(&bundle)
            .map_err(|e| anyhow::anyhow!("canonicalize paid bundle: {e}"))?,
    )
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
    let shard =
        match send_message_bundle(client, key_manager, submit_domain.clone(), bundle.clone()).await
        {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
    // Coverage can change between the quote and submission.
    eprintln!("warning: the application's shard topic did not accept the bundle ({shard}); trying the global venue");
    send_message_bundle(client, key_manager, global, bundle)
        .await
        .map_err(|global| anyhow::anyhow!("shard topic: {shard}; global topic: {global}"))
}

#[cfg(not(feature = "native-proof"))]
pub async fn send_paid_request(
    _: crate::context::GlobalArgs,
    _: &mut NodeServiceClient<Channel>,
    _: &FileKeyManager,
    _: Vec<u8>,
    _: [u8; 32],
    _: MessageRequest,
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

    /// A/B reproducer: a vertex add sent to a token's domain was skipped by
    /// the token engine, so its paid bundle succeeded, consumed its
    /// settlement and wrote nothing (mainnet). A write whose application's
    /// engine does not execute it is refused before anything is paid.
    #[test]
    fn a_paid_write_is_refused_before_payment_where_its_engine_does_not_run() {
        use quil_types::proto::global::message_request::Request;
        const MSG: &str = "a write was let through to an engine that skips it";
        let of = |request| MessageRequest {
            request: Some(request),
            timestamp: 0,
        };
        let token = quil_execution::token_intrinsic::constants::token_base_domain();
        let hypergraph = quil_execution::hypergraph_intrinsic::hypergraph_base_domain();
        let compute = quil_execution::domains::COMPUTE;
        let vertex = of(Request::VertexAdd(Default::default()));
        assert!(
            check_request_route(&vertex, &token).is_err(),
            "{MSG}: a vertex add to a token"
        );
        assert!(
            check_request_route(&vertex, &quil_execution::domains::QUIL_TOKEN).is_err(),
            "{MSG}: a vertex add to QUIL"
        );
        assert!(
            check_request_route(&vertex, &compute).is_err(),
            "{MSG}: a vertex add to a compute application"
        );
        assert!(
            check_request_route(&vertex, &[7; 32]).is_err(),
            "{MSG}: a vertex add to no known engine"
        );
        let update = of(Request::TokenUpdate(Default::default()));
        assert!(
            check_request_route(&update, &hypergraph).is_err(),
            "{MSG}: a token update to a hypergraph"
        );
        let execute = of(Request::CodeExecute(Default::default()));
        assert!(
            check_request_route(&execute, &token).is_err(),
            "{MSG}: a code execution to a token"
        );
        // Each runs where its engine does; a request no application engine
        // executes is not checked.
        check_request_route(&vertex, &hypergraph).unwrap();
        check_request_route(&update, &token).unwrap();
        check_request_route(&execute, &compute).unwrap();
        check_request_route(&of(Request::Join(Default::default())), &token).unwrap();
        check_request_route(&MessageRequest::default(), &token).unwrap();
    }

    /// The application's route is read as the node reads it.
    #[test]
    fn an_application_route_is_read_from_its_metadata_vertex() {
        let blob = |value: &[u8]| {
            let mut tree = quil_tries::VectorCommitmentTree::new();
            tree.insert(
                &[0xFF; 32],
                value,
                &[],
                &num_bigint::BigInt::from(value.len()),
            )
            .unwrap();
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()
        };
        assert_eq!(route_from_metadata(&blob(&[5; 32])).unwrap(), [5; 32]);
        assert!(route_from_metadata(&blob(&[5; 31])).is_err());
        let empty = quil_tries::serialize_go_tree(None).unwrap();
        assert!(route_from_metadata(&empty).is_err());
    }
}
