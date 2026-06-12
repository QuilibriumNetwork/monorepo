//! Prometheus-compatible metrics for the execution layer.
//!
//! Every metric is labeled by `engine_type` so that Global, Token, Compute,
//! and Hypergraph engines are distinguishable in dashboards.

use metrics::{counter, describe_counter, describe_histogram, histogram};

/// Describe and register all execution-layer metrics.
///
/// Call once at startup.
pub fn register_execution_metrics() {
    describe_counter!(
        "execution_requests_total",
        "Total execution requests processed"
    );
    describe_histogram!(
        "execution_request_duration_seconds",
        "Execution request latency in seconds"
    );
    describe_counter!(
        "execution_errors_total",
        "Total execution errors"
    );
}

/// Increment the request counter for the given engine type.
#[inline]
pub fn inc_execution_requests(engine_type: &'static str) {
    counter!("execution_requests_total", "engine_type" => engine_type).increment(1);
}

/// Record an execution request duration for the given engine type.
#[inline]
pub fn observe_execution_duration(engine_type: &'static str, seconds: f64) {
    histogram!("execution_request_duration_seconds", "engine_type" => engine_type)
        .record(seconds);
}

/// Increment the error counter for the given engine type.
#[inline]
pub fn inc_execution_errors(engine_type: &'static str) {
    counter!("execution_errors_total", "engine_type" => engine_type).increment(1);
}
