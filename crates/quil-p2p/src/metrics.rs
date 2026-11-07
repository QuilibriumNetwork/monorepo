//! P2P-layer prometheus metrics.
//!
//! One `prometheus_client::Registry` per [`crate::node::P2PNode`] carries
//! BOTH metric families of the p2p stack:
//!
//! - **`blossomsub_*`** — the vendored gossipsub fork's full metrics module
//! (mesh peer counts, graft/prune inclusion+churn events, per-bitmask
//! sent/recv/published message counts and bytes, validation results, score
//! histograms, penalties, IWANT, heartbeat duration). Those are registered
//! by `blossomsub::Behaviour::new_with_metrics` into a `blossomsub`-prefixed
//! sub-registry (see `blossomsub_behaviour.rs`).
//! - **`libp2p_*`** — swarm-level connection metrics defined here and
//! recorded by the swarm event loop in `node.rs`.
//!
//! The registry is exposed through `P2PHandle::render_metrics()`, which the
//! node bridges into its unified metrics exposition (HTTP `/metrics`, gRPC
//! `GetMetrics`, and the metrics TUI). The rest of the node uses the
//! `metrics` facade crate; these two ecosystems only meet at exposition,
//! where both render to prometheus text and concatenate.

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

/// Shared handle to a node's p2p metrics registry.
pub type SharedRegistry = Arc<Mutex<Registry>>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DirectionLabels {
    pub direction: Direction,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Swarm-level connection metrics, recorded from the `SwarmEvent` arms of
/// the node event loop. Cheap to clone (prometheus-client metrics are
/// internally Arc-backed).
#[derive(Clone)]
pub struct SwarmMetrics {
    /// Connections fully established, by direction.
    pub connections_established: Family<DirectionLabels, Counter>,
    /// Connections closed (any cause), by direction.
    pub connections_closed: Family<DirectionLabels, Counter>,
    /// Current connected peer count (distinct peers, not connections).
    pub connected_peers: Gauge,
    /// Outbound dials that failed before a connection was established.
    pub dial_failures: Counter,
    /// Inbound connection attempts that failed (transport/upgrade errors).
    pub incoming_failures: Counter,
}

impl SwarmMetrics {
    /// Register the swarm metric families into `registry` (callers pass a
    /// `libp2p`-prefixed sub-registry).
    pub fn register(registry: &mut Registry) -> Self {
        let connections_established = Family::<DirectionLabels, Counter>::default();
        registry.register(
            "connections_established",
            "Connections fully established, by direction",
            connections_established.clone(),
        );
        let connections_closed = Family::<DirectionLabels, Counter>::default();
        registry.register(
            "connections_closed",
            "Connections closed (any cause), by direction",
            connections_closed.clone(),
        );
        let connected_peers = Gauge::default();
        registry.register(
            "connected_peers",
            "Current number of distinct connected peers",
            connected_peers.clone(),
        );
        let dial_failures = Counter::default();
        registry.register(
            "dial_failures",
            "Outbound dials that failed before establishment",
            dial_failures.clone(),
        );
        let incoming_failures = Counter::default();
        registry.register(
            "incoming_failures",
            "Inbound connection attempts that failed",
            incoming_failures.clone(),
        );
        Self {
            connections_established,
            connections_closed,
            connected_peers,
            dial_failures,
            incoming_failures,
        }
    }

    /// Direction labels for a libp2p `ConnectedPoint`.
    pub fn direction_of(endpoint: &libp2p::core::ConnectedPoint) -> DirectionLabels {
        match endpoint {
            libp2p::core::ConnectedPoint::Dialer { .. } => DirectionLabels {
                direction: Direction::Outbound,
            },
            libp2p::core::ConnectedPoint::Listener { .. } => DirectionLabels {
                direction: Direction::Inbound,
            },
        }
    }
}

/// Render the registry to prometheus text exposition format. Returns an
/// empty string on a poisoned lock or encode failure — metrics must never
/// take the node down.
pub fn render(registry: &SharedRegistry) -> String {
    let mut out = String::new();
    if let Ok(guard) = registry.lock() {
        if prometheus_client::encoding::text::encode(&mut out, &guard).is_err() {
            out.clear();
        }
    }
    out
}
