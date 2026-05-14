//! Prometheus-compatible metrics for the consensus engine.
//!
//! All metrics use the lightweight [`metrics`] crate facade so that any
//! compatible exporter (e.g. `metrics-exporter-prometheus`) can collect them
//! without changing this code.
//!
//! Mirror of the subset of Go's ~200 consensus/execution metric
//! definitions that matter most for observability:
//! - frame and rank progression
//! - proposals / votes / timeouts
//! - prover lifecycle transitions
//! - coverage halt dynamics
//! - archive submission throughput

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

/// Describe and register all engine-level metrics.
///
/// Call once at startup before any updates.
pub fn register_engine_metrics() {
    // --- Frame / consensus state (gauges) -----------------------------
    describe_gauge!(
        "engine_frame_number",
        "Current frame number being processed"
    );
    describe_gauge!(
        "engine_current_rank",
        "Current consensus rank of this node"
    );
    describe_gauge!(
        "engine_difficulty",
        "Current mining / VDF difficulty"
    );
    describe_gauge!(
        "engine_pending_messages",
        "Number of messages waiting to be processed"
    );
    describe_gauge!(
        "engine_active_shards",
        "Count of shards with at least one active prover"
    );
    describe_gauge!(
        "engine_halted_shards",
        "Count of shards currently in a CoverageHalt window"
    );

    // --- Consensus events (counters) ----------------------------------
    describe_counter!(
        "engine_proposals_total",
        "Total number of proposals produced"
    );
    describe_counter!(
        "engine_proposals_received_total",
        "Total number of proposals received from peers"
    );
    describe_counter!(
        "engine_votes_total",
        "Total number of votes produced"
    );
    describe_counter!(
        "engine_votes_received_total",
        "Total number of standalone votes received from peers"
    );
    describe_counter!(
        "engine_timeouts_received_total",
        "Total number of timeout states received from peers"
    );
    describe_counter!(
        "engine_qcs_submitted_total",
        "Quorum certificates submitted to the event loop"
    );
    describe_counter!(
        "engine_tcs_submitted_total",
        "Timeout certificates submitted to the event loop"
    );
    describe_counter!(
        "engine_frames_materialized_total",
        "Total number of frames materialized"
    );
    describe_counter!(
        "engine_frames_received_total",
        "Total number of frames received over BlossomSub"
    );
    describe_counter!(
        "engine_prover_root_matches_total",
        "Root verification successes"
    );
    describe_counter!(
        "engine_prover_root_mismatches_total",
        "Root verification failures"
    );

    // --- Prover lifecycle (counters) ----------------------------------
    describe_counter!(
        "engine_prover_joins_submitted_total",
        "ProverJoin canonical messages this node has submitted"
    );
    describe_counter!(
        "engine_prover_confirms_submitted_total",
        "ProverConfirm canonical messages this node has submitted"
    );
    describe_counter!(
        "engine_prover_rejects_submitted_total",
        "ProverReject canonical messages this node has submitted"
    );
    describe_counter!(
        "engine_prover_leaves_submitted_total",
        "ProverLeave canonical messages this node has submitted"
    );
    describe_counter!(
        "engine_shard_splits_submitted_total",
        "ShardSplit proposals this node has submitted"
    );
    describe_counter!(
        "engine_shard_merges_submitted_total",
        "ShardMerge proposals this node has submitted"
    );

    // --- Coverage (counters) ------------------------------------------
    describe_counter!(
        "engine_coverage_halts_entered_total",
        "Total CoverageHalt events observed"
    );
    describe_counter!(
        "engine_coverage_resumes_total",
        "Total CoverageResume events observed"
    );
    describe_counter!(
        "engine_coverage_warns_total",
        "Total CoverageWarn events observed"
    );
    describe_counter!(
        "engine_evictions_total",
        "Provers evicted by the archive-mode scheduler"
    );

    // --- Archive submission (counters + histogram) --------------------
    describe_counter!(
        "engine_grpc_submits_accepted_total",
        "Inbound gRPC submit_global_message calls accepted"
    );
    describe_counter!(
        "engine_grpc_submits_rejected_total",
        "Inbound gRPC submit_global_message calls rejected"
    );
    describe_histogram!(
        "engine_vdf_prove_seconds",
        "VDF proof computation duration"
    );
    describe_histogram!(
        "engine_archive_submit_seconds",
        "Round-trip duration of an outbound archive submit"
    );
}

/// Bulk-update the gauge metrics that change every frame.
pub fn update_engine_metrics(frame: u64, rank: u64, difficulty: u64, pending: u64) {
    gauge!("engine_frame_number").set(frame as f64);
    gauge!("engine_current_rank").set(rank as f64);
    gauge!("engine_difficulty").set(difficulty as f64);
    gauge!("engine_pending_messages").set(pending as f64);
}

#[inline]
pub fn set_active_shards(n: u64) {
    gauge!("engine_active_shards").set(n as f64);
}
#[inline]
pub fn set_halted_shards(n: u64) {
    gauge!("engine_halted_shards").set(n as f64);
}

#[inline]
pub fn inc_proposals() {
    counter!("engine_proposals_total").increment(1);
}
#[inline]
pub fn inc_proposals_received() {
    counter!("engine_proposals_received_total").increment(1);
}
#[inline]
pub fn inc_votes() {
    counter!("engine_votes_total").increment(1);
}
#[inline]
pub fn inc_votes_received() {
    counter!("engine_votes_received_total").increment(1);
}
#[inline]
pub fn inc_timeouts_received() {
    counter!("engine_timeouts_received_total").increment(1);
}
#[inline]
pub fn inc_qcs_submitted() {
    counter!("engine_qcs_submitted_total").increment(1);
}
#[inline]
pub fn inc_tcs_submitted() {
    counter!("engine_tcs_submitted_total").increment(1);
}
#[inline]
pub fn inc_frames_materialized() {
    counter!("engine_frames_materialized_total").increment(1);
}
#[inline]
pub fn inc_frames_received() {
    counter!("engine_frames_received_total").increment(1);
}
#[inline]
pub fn record_root_verification(matched: bool) {
    if matched {
        counter!("engine_prover_root_matches_total").increment(1);
    } else {
        counter!("engine_prover_root_mismatches_total").increment(1);
    }
}

#[inline]
pub fn inc_prover_joins_submitted() {
    counter!("engine_prover_joins_submitted_total").increment(1);
}
#[inline]
pub fn inc_prover_confirms_submitted() {
    counter!("engine_prover_confirms_submitted_total").increment(1);
}
#[inline]
pub fn inc_prover_rejects_submitted() {
    counter!("engine_prover_rejects_submitted_total").increment(1);
}
#[inline]
pub fn inc_prover_leaves_submitted() {
    counter!("engine_prover_leaves_submitted_total").increment(1);
}
#[inline]
pub fn inc_shard_splits_submitted() {
    counter!("engine_shard_splits_submitted_total").increment(1);
}
#[inline]
pub fn inc_shard_merges_submitted() {
    counter!("engine_shard_merges_submitted_total").increment(1);
}

#[inline]
pub fn inc_coverage_halts_entered() {
    counter!("engine_coverage_halts_entered_total").increment(1);
}
#[inline]
pub fn inc_coverage_resumes() {
    counter!("engine_coverage_resumes_total").increment(1);
}
#[inline]
pub fn inc_coverage_warns() {
    counter!("engine_coverage_warns_total").increment(1);
}
#[inline]
pub fn inc_evictions(n: u64) {
    counter!("engine_evictions_total").increment(n);
}

#[inline]
pub fn inc_grpc_submits_accepted() {
    counter!("engine_grpc_submits_accepted_total").increment(1);
}
#[inline]
pub fn inc_grpc_submits_rejected() {
    counter!("engine_grpc_submits_rejected_total").increment(1);
}

#[inline]
pub fn record_vdf_prove_duration(seconds: f64) {
    histogram!("engine_vdf_prove_seconds").record(seconds);
}
#[inline]
pub fn record_archive_submit_duration(seconds: f64) {
    histogram!("engine_archive_submit_seconds").record(seconds);
}
