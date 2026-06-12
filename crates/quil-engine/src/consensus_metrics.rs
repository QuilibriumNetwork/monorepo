//! Metrics specific to the consensus protocol (proposal validation, QC/TC
//! construction, vote processing latency).

use metrics::{counter, describe_counter, describe_histogram, histogram};

/// Describe and register all consensus-protocol metrics.
///
/// Call once at startup (safe to call alongside [`super::metrics::register_engine_metrics`]).
pub fn register_consensus_metrics() {
    describe_counter!(
        "consensus_proposal_validation_total",
        "Proposal validation outcomes"
    );
    describe_histogram!(
        "consensus_vote_processing_duration_seconds",
        "Time spent processing a single vote"
    );
    describe_counter!(
        "consensus_qc_constructed_total",
        "Total quorum certificates constructed"
    );
    describe_counter!(
        "consensus_tc_constructed_total",
        "Total timeout certificates constructed"
    );
}

/// Record the outcome of a proposal validation.
///
/// `result` should be one of `"accept"`, `"ignore"`, or `"reject"`.
#[inline]
pub fn record_proposal_validation(result: &'static str) {
    counter!("consensus_proposal_validation_total", "result" => result).increment(1);
}

/// Record the duration of processing a single vote.
#[inline]
pub fn observe_vote_processing_duration(seconds: f64) {
    histogram!("consensus_vote_processing_duration_seconds").record(seconds);
}

/// Increment the quorum-certificate counter.
#[inline]
pub fn inc_qc_constructed() {
    counter!("consensus_qc_constructed_total").increment(1);
}

/// Increment the timeout-certificate counter.
#[inline]
pub fn inc_tc_constructed() {
    counter!("consensus_tc_constructed_total").increment(1);
}
