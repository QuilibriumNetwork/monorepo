//! Peer-gRPC (:8340) request metrics.
//!
//! A tower middleware layered under the tonic server that counts every
//! inbound RPC by its gRPC path (`/package.Service/Method`), plus helpers
//! for the TLS accept pipeline (connections accepted, handshake outcomes).
//! Everything records into the `metrics` facade, so it lands in the same
//! prometheus exporter as the engine/execution metrics.
//!
//! Label cardinality is bounded: the path label is drawn from the fixed set
//! of RPC methods the services expose, and handshake outcomes are a 3-value
//! enum.

use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

/// Extra prometheus-text renderers appended to every metrics exposition
/// (HTTP `/metrics`, gRPC `GetMetrics`, `--metrics`). The p2p layer lives in
/// the `prometheus-client` ecosystem (its own Registry, per-node, created
/// deep inside master_node startup) while the exporter serves the `metrics`
/// facade recorder — the two only meet here, at exposition, where both are
/// prometheus text. master_node registers `P2PHandle::render_metrics` once
/// networking is up; before that, expositions simply omit the p2p families.
static EXTRA_RENDER: OnceLock<Arc<dyn Fn() -> String + Send + Sync>> = OnceLock::new();

/// Register an additional renderer (at most one; later calls are ignored).
pub fn set_extra_metrics_render(render: Arc<dyn Fn() -> String + Send + Sync>) {
    let _ = EXTRA_RENDER.set(render);
}

/// Render the extra families (empty before registration).
pub fn extra_metrics_render() -> String {
    EXTRA_RENDER.get().map(|f| f()).unwrap_or_default()
}

/// Describe the RPC metric families (call once after the metrics recorder
/// is installed, alongside `register_engine_metrics`).
pub fn register_rpc_metrics() {
    metrics::describe_counter!(
        "rpc_requests_total",
        "Inbound peer-gRPC requests by gRPC method path"
    );
    metrics::describe_counter!(
        "rpc_connections_accepted_total",
        "TCP connections accepted on the peer-gRPC listener"
    );
    metrics::describe_counter!(
        "rpc_tls_handshakes_total",
        "Ed448 mTLS handshake results on the peer-gRPC listener (outcome: ok|failed|timeout)"
    );
}

/// Count a TCP accept on the peer-gRPC listener.
#[inline]
pub fn inc_connection_accepted() {
    metrics::counter!("rpc_connections_accepted_total").increment(1);
}

/// Count a TLS handshake outcome on the peer-gRPC listener.
#[inline]
pub fn inc_tls_handshake(outcome: &'static str) {
    metrics::counter!("rpc_tls_handshakes_total", "outcome" => outcome).increment(1);
}

/// Tower layer: counts every inbound RPC by path.
#[derive(Clone, Default)]
pub struct RpcMetricsLayer;

impl<S> tower::Layer<S> for RpcMetricsLayer {
    type Service = RpcMetricsService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RpcMetricsService { inner }
    }
}

#[derive(Clone)]
pub struct RpcMetricsService<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for RpcMetricsService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        metrics::counter!(
            "rpc_requests_total",
            "path" => req.uri().path().to_owned()
        )
        .increment(1);
        self.inner.call(req)
    }
}
