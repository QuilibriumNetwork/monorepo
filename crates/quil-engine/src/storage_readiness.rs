//! Go/no-go arithmetic for a fully measured storage allocation. No sampled
//! sector, missing snapshot, debug build or reduced frame load can yield GO.
use crate::storage_snapshot::SnapshotMeasurement;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    GoForCheckpoint,
    NoGo,
    Incomplete,
}
#[derive(Debug, Serialize)]
pub struct Assessment {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub cold_measured_seconds: f64,
    pub cold_with_inclusion_and_headroom_seconds: f64,
    pub cold_budget_seconds: f64,
    pub worst_registration_seconds: f64,
    pub registration_with_headroom_seconds: f64,
    pub registration_budget_seconds: f64,
    pub worst_frame_openings_seconds: f64,
    pub frame_openings_with_headroom_seconds: f64,
    pub recurring_with_headroom_seconds: f64,
    pub epoch_budget_seconds: f64,
    pub worst_settlement_seconds: f64,
    pub settlement_with_headroom_seconds: f64,
    pub settlement_budget_seconds: f64,
    pub measured_allocation_seal_bytes: u64,
    pub measured_allocation_settlement_bytes: u64,
}
pub struct Evidence<'a> {
    pub measurements: &'a [SnapshotMeasurement],
    pub expected_shards: usize,
    pub roots_verified: bool,
    pub release_build: bool,
    pub expected_rounds: usize,
    pub frame_count: usize,
    pub expected_frame_count: usize,
    pub download_seconds: f64,
    pub frame_seconds: f64,
    pub warmup_frames: u64,
    pub registration_frames: u64,
    pub settlement_frames: u64,
    pub inclusion_frames_per_sector: u64,
    pub headroom: f64,
    pub resource_exceeded: bool,
}
pub fn assess(e: Evidence<'_>) -> Assessment {
    let mut out = Assessment {
        verdict: Verdict::GoForCheckpoint,
        reasons: Vec::new(),
        cold_measured_seconds: e.download_seconds,
        cold_with_inclusion_and_headroom_seconds: 0.,
        cold_budget_seconds: e.warmup_frames as f64 * e.frame_seconds,
        worst_registration_seconds: 0.,
        registration_with_headroom_seconds: 0.,
        registration_budget_seconds: e.registration_frames as f64 * e.frame_seconds,
        worst_frame_openings_seconds: 0.,
        frame_openings_with_headroom_seconds: 0.,
        recurring_with_headroom_seconds: 0.,
        epoch_budget_seconds: e.expected_frame_count as f64 * e.frame_seconds,
        worst_settlement_seconds: 0.,
        settlement_with_headroom_seconds: 0.,
        settlement_budget_seconds: e.settlement_frames as f64 * e.frame_seconds,
        measured_allocation_seal_bytes: 0,
        measured_allocation_settlement_bytes: 0,
    };
    let mut incomplete = Vec::new();
    if !e.roots_verified {
        incomplete.push("mainnet checkpoint/snapshot roots were not authenticated".into());
    }
    if !e.release_build {
        incomplete.push("debug build timings cannot qualify production hardware".into());
    }
    if e.expected_shards == 0 || e.measurements.len() != e.expected_shards {
        incomplete.push("the intended allocation was not fully measured".into());
    }
    if e.expected_rounds < 2
        || e.measurements
            .iter()
            .any(|m| m.rounds.len() != e.expected_rounds)
    {
        incomplete.push("all intended repeat rounds are required".into());
    }
    if e.frame_count != e.expected_frame_count || e.frame_count == 0 {
        incomplete.push("settlement frame workload is incomplete".into());
    }
    if !e.headroom.is_finite()
        || e.headroom < 1.
        || !e.frame_seconds.is_finite()
        || e.frame_seconds <= 0.
        || !e.download_seconds.is_finite()
        || e.download_seconds < 0.
        || [e.warmup_frames, e.registration_frames, e.settlement_frames].contains(&0)
    {
        incomplete.push("invalid headroom or deadline settings".into());
    }
    let mut sectors = 0;
    for m in e.measurements {
        let cold = [
            m.cold_label_seconds,
            m.certificate_witness_seconds,
            m.certificate_prove_seconds,
            m.certificate_verify_seconds,
        ];
        if cold.iter().any(|s| !s.is_finite() || *s < 0.) {
            incomplete.push("invalid cold timing".into());
        }
        out.cold_measured_seconds += cold.iter().sum::<f64>();
        sectors += m.sectors as u64;
        let (mut registration, mut settlement, mut frame_openings) = (0f64, 0f64, 0f64);
        let (mut seal_bytes, mut settle_bytes) = (0, 0);
        for round in &m.rounds {
            let registration_parts = [
                round.encode_seconds,
                round.binding_seconds,
                round.fresh_proof_seconds,
                round.fresh_verify_seconds,
            ];
            let settlement_parts = [
                round.settlement_prepare_seconds,
                round.settlement_prove_seconds,
                round.settlement_verify_seconds,
            ];
            if registration_parts
                .iter()
                .chain(settlement_parts.iter())
                .any(|s| !s.is_finite() || *s < 0.)
            {
                incomplete.push("invalid recurring timing".into());
            }
            if !round.frame_openings_seconds.is_finite() || round.frame_openings_seconds < 0. {
                incomplete.push("invalid frame opening timing".into());
            }
            frame_openings = frame_openings.max(round.frame_openings_seconds);
            registration = registration.max(registration_parts.iter().sum());
            settlement = settlement.max(settlement_parts.iter().sum());
            seal_bytes = seal_bytes.max(round.seal_message_bytes);
            settle_bytes = settle_bytes.max(round.settlement_message_bytes);
        }
        // Sum the slowest measurement of EACH shard. Using only the slowest
        // single shard, or the fastest round, would undercount a multi-seat node.
        out.worst_frame_openings_seconds += frame_openings;
        out.worst_registration_seconds += registration;
        out.worst_settlement_seconds += settlement;
        out.measured_allocation_seal_bytes += seal_bytes;
        out.measured_allocation_settlement_bytes += settle_bytes;
    }
    out.frame_openings_with_headroom_seconds = out.worst_frame_openings_seconds * e.headroom;
    out.recurring_with_headroom_seconds = (out.worst_frame_openings_seconds
        + out.worst_registration_seconds
        + out.worst_settlement_seconds)
        * e.headroom;
    out.registration_with_headroom_seconds = out.worst_registration_seconds * e.headroom;
    out.settlement_with_headroom_seconds = out.worst_settlement_seconds * e.headroom;
    out.cold_with_inclusion_and_headroom_seconds = (out.cold_measured_seconds
        + out.worst_registration_seconds
        + sectors as f64 * e.inclusion_frames_per_sector as f64 * e.frame_seconds)
        * e.headroom;
    if !incomplete.is_empty() {
        out.verdict = Verdict::Incomplete;
        out.reasons = incomplete;
        return out;
    }
    if e.resource_exceeded {
        out.reasons
            .push("measured RSS, disk or execution-time budget was exceeded".into());
    }
    if out.cold_with_inclusion_and_headroom_seconds > out.cold_budget_seconds {
        out.reasons
            .push("cold setup exceeds the coordinated warmup budget".into());
    }
    if out.registration_with_headroom_seconds > out.registration_budget_seconds {
        out.reasons
            .push("full-allocation encoding and sealing exceed renewal grace".into());
    }
    if out.settlement_with_headroom_seconds > out.settlement_budget_seconds {
        out.reasons
            .push("full-allocation settlement exceeds its window".into());
    }
    if out.recurring_with_headroom_seconds > out.epoch_budget_seconds {
        out.reasons
            .push("combined recurring storage work exceeds an epoch".into());
    }
    let frame_bytes = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME as u64;
    if out.measured_allocation_seal_bytes > e.registration_frames.saturating_mul(frame_bytes)
        || out.measured_allocation_settlement_bytes
            > e.settlement_frames.saturating_mul(frame_bytes)
    {
        out.reasons.push("allocation proof bytes exceed the available GLOBAL window even before other nodes' traffic".into());
    }
    if !out.reasons.is_empty() {
        out.verdict = Verdict::NoGo;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_snapshot::RoundMeasurement;
    fn measurements() -> Vec<SnapshotMeasurement> {
        (0..2)
            .map(|_| SnapshotMeasurement {
                sectors: 1,
                cold_label_seconds: 1.,
                rounds: vec![
                    RoundMeasurement {
                        encode_seconds: 2.,
                        ..Default::default()
                    },
                    RoundMeasurement {
                        encode_seconds: 3.,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            })
            .collect()
    }
    fn evidence(m: &[SnapshotMeasurement]) -> Evidence<'_> {
        Evidence {
            measurements: m,
            expected_shards: 2,
            roots_verified: true,
            release_build: true,
            expected_rounds: 2,
            frame_count: 720,
            expected_frame_count: 720,
            download_seconds: 1.,
            frame_seconds: 10.,
            warmup_frames: 100,
            registration_frames: 100,
            settlement_frames: 100,
            inclusion_frames_per_sector: 4,
            headroom: 2.,
            resource_exceeded: false,
        }
    }
    #[test]
    fn totals_the_worst_round_of_every_shard_and_reserves_consensus_time() {
        let m = measurements();
        let r = assess(evidence(&m));
        assert_eq!(r.verdict, Verdict::GoForCheckpoint);
        assert_eq!(r.worst_registration_seconds, 6.);
        assert_eq!(r.cold_with_inclusion_and_headroom_seconds, 178.);
    }
    #[test]
    fn partial_debug_or_reduced_workloads_never_pass() {
        let m = measurements();
        for case in 0..4 {
            let mut e = evidence(&m);
            match case {
                0 => e.expected_shards = 3,
                1 => e.release_build = false,
                2 => e.roots_verified = false,
                _ => e.frame_count = 1,
            };
            assert_eq!(assess(e).verdict, Verdict::Incomplete);
        }
    }
    #[test]
    fn resource_and_deadline_failures_are_no_go() {
        let m = measurements();
        let mut e = evidence(&m);
        e.registration_frames = 1;
        assert_eq!(assess(e).verdict, Verdict::NoGo);
        let mut e = evidence(&m);
        e.resource_exceeded = true;
        assert_eq!(assess(e).verdict, Verdict::NoGo);
    }
    #[test]
    fn frame_opening_work_counts_towards_the_epoch_budget() {
        let mut m = measurements();
        m[0].rounds[0].frame_openings_seconds = 4000.;
        let result = assess(evidence(&m));
        assert_eq!(result.verdict, Verdict::NoGo);
        assert_eq!(result.worst_frame_openings_seconds, 4000.);
    }
    #[test]
    fn missing_and_non_finite_timings_cannot_pass() {
        let mut m = measurements();
        m[0].rounds.clear();
        assert_eq!(assess(evidence(&m)).verdict, Verdict::Incomplete);
        let mut e = evidence(&m);
        e.headroom = f64::NAN;
        assert_eq!(assess(e).verdict, Verdict::Incomplete);
    }
}
