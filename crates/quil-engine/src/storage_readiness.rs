//! Go/no-go arithmetic for a fully measured storage allocation. No sampled
//! sector, missing snapshot, debug build or reduced frame load can yield GO.
use crate::storage_snapshot::SnapshotMeasurement;
use serde::Serialize;
mod network;
pub use network::{inclusion_model, NetworkModel};

#[derive(Debug, Clone, Serialize)]
pub struct CapacityInclusion {
    pub bucket: u8,
    pub precommit_bytes: u64,
    pub certificate_bytes: u64,
}

/// A single storage proof's canonical request and bundle overhead. The wire
/// format uses fixed-width lengths and timestamp; tested against the encoder.
pub fn storage_wire_bytes(payload: u64) -> u64 {
    payload.saturating_add(28)
}

/// Whether unfinished local setup has reached the two-hour deadline.
pub fn initial_setup_expired(elapsed: std::time::Duration, ready: bool) -> bool {
    !ready && elapsed.as_secs() >= quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS
}

/// Isolated benchmark cutoff: retain 0.1% free space (99.9% maximum used).
/// Production stores retain their existing free-space policy.
pub fn disk_floor(total_bytes: u64) -> u64 {
    total_bytes.div_ceil(1000)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AllocationRoundMeasurement {
    pub registration_wall_seconds: f64,
    pub frame_openings_wall_seconds: f64,
    pub settlement_wall_seconds: f64,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct AllocationMeasurement {
    pub parallel_jobs: usize,
    pub cold_wall_seconds: f64,
    pub rounds: Vec<AllocationRoundMeasurement>,
}

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
    pub local_startup_verdict: Verdict,
    pub initial_local_setup_seconds: Option<f64>,
    pub modeled_network_inclusion: Option<NetworkModel>,
    pub modeled_network_inclusion_seconds: f64,
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
    pub allocation: Option<&'a AllocationMeasurement>,
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
    pub initial_local_setup_seconds: Option<f64>,
    pub network_share_percent: u8,
    pub headroom: f64,
    pub resource_exceeded: bool,
}
pub fn assess(e: Evidence<'_>) -> Assessment {
    let mut out = Assessment {
        verdict: Verdict::GoForCheckpoint,
        reasons: Vec::new(),
        local_startup_verdict: Verdict::Incomplete,
        initial_local_setup_seconds: e.initial_local_setup_seconds,
        modeled_network_inclusion: None,
        modeled_network_inclusion_seconds: 0.,
        cold_measured_seconds: e.download_seconds,
        cold_with_inclusion_and_headroom_seconds: 0.,
        cold_budget_seconds: (e.warmup_frames as f64 * e.frame_seconds)
            .min(quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS as f64),
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
    let mut capacity = Vec::new();
    let mut registration_messages = Vec::new();
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
        if m.sectors == 0 || m.capacity_messages.len() != m.sectors {
            incomplete.push(
                "per-sector capacity message sizes and buckets were not fully measured".into(),
            );
        }
        capacity.extend(m.capacity_messages.iter().cloned());
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
        registration_messages.push(if seal_bytes == 0 {
            0
        } else {
            storage_wire_bytes(seal_bytes)
        });
        out.measured_allocation_seal_bytes += seal_bytes;
        out.measured_allocation_settlement_bytes += settle_bytes;
    }
    if let Some(allocation) = e.allocation {
        if allocation.parallel_jobs == 0
            || allocation.rounds.len() != e.expected_rounds
            || !allocation.cold_wall_seconds.is_finite()
            || allocation.cold_wall_seconds < 0.
            || allocation.rounds.iter().any(|r| {
                [
                    r.registration_wall_seconds,
                    r.frame_openings_wall_seconds,
                    r.settlement_wall_seconds,
                ]
                .iter()
                .any(|s| !s.is_finite() || *s < 0.)
            })
        {
            incomplete
                .push("parallel allocation phase measurements are incomplete or invalid".into());
        }
        out.cold_measured_seconds = e.download_seconds + allocation.cold_wall_seconds;
        out.worst_registration_seconds = allocation
            .rounds
            .iter()
            .map(|r| r.registration_wall_seconds)
            .fold(0., f64::max);
        out.worst_frame_openings_seconds = allocation
            .rounds
            .iter()
            .map(|r| r.frame_openings_wall_seconds)
            .fold(0., f64::max);
        out.worst_settlement_seconds = allocation
            .rounds
            .iter()
            .map(|r| r.settlement_wall_seconds)
            .fold(0., f64::max);
    }
    out.frame_openings_with_headroom_seconds = out.worst_frame_openings_seconds * e.headroom;
    out.recurring_with_headroom_seconds = (out.worst_frame_openings_seconds
        + out.worst_registration_seconds
        + out.worst_settlement_seconds)
        * e.headroom;
    out.registration_with_headroom_seconds = out.worst_registration_seconds * e.headroom;
    out.settlement_with_headroom_seconds = out.worst_settlement_seconds * e.headroom;
    match inclusion_model(
        &capacity,
        &registration_messages,
        e.network_share_percent,
        e.allocation.map_or(1, |a| a.parallel_jobs),
    ) {
        Ok(model) => {
            out.modeled_network_inclusion_seconds = model.frames as f64 * e.frame_seconds;
            out.modeled_network_inclusion = Some(model);
        }
        Err(error) => incomplete.push(error.into()),
    }
    let first_registration = e
        .allocation
        .and_then(|a| a.rounds.first())
        .map_or(out.worst_registration_seconds, |r| {
            r.registration_wall_seconds
        });
    let startup_overhead = e.initial_local_setup_seconds.unwrap_or(0.)
        - out.cold_measured_seconds
        - first_registration;
    // Fixed download and modeled network latency are not multiplied by CPU
    // headroom. This conservatively adds the network pipeline after local work;
    // it does not assume that all capacity messages wait four serial frames.
    out.cold_with_inclusion_and_headroom_seconds = e.download_seconds
        + startup_overhead.max(0.)
        + (out.cold_measured_seconds - e.download_seconds + out.worst_registration_seconds)
            * e.headroom
        + out.modeled_network_inclusion_seconds;
    match e.initial_local_setup_seconds {
        Some(seconds)
            if seconds.is_finite() && seconds >= 0. && e.roots_verified && e.release_build =>
        {
            out.local_startup_verdict =
                if seconds <= quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS as f64 {
                    Verdict::GoForCheckpoint
                } else {
                    Verdict::NoGo
                };
        }
        _ => incomplete.push("authenticated initial local setup milestone was not measured".into()),
    }
    if !incomplete.is_empty() {
        out.verdict = Verdict::Incomplete;
        out.reasons = incomplete;
        return out;
    }
    if e.resource_exceeded {
        out.reasons
            .push("measured RSS, disk or execution-time budget was exceeded".into());
    }
    if out.local_startup_verdict == Verdict::NoGo {
        out.reasons
            .push("measured initial local setup exceeds two hours".into());
    }
    if out.cold_with_inclusion_and_headroom_seconds > out.cold_budget_seconds {
        out.reasons.push(
            "modeled network-ready setup with compute headroom exceeds the initial setup budget"
                .into(),
        );
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
                capacity_messages: vec![CapacityInclusion {
                    bucket: 0,
                    precommit_bytes: 256,
                    certificate_bytes: 1024,
                }],
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
            allocation: None,
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
            initial_local_setup_seconds: Some(9.),
            network_share_percent: 25,
            headroom: 2.,
            resource_exceeded: false,
        }
    }
    #[test]
    fn benchmark_disk_floor_is_one_thousandth_without_the_node_minimum() {
        assert_eq!(disk_floor(2_000_000_000_000), 2_000_000_000);
        assert_eq!(disk_floor(2_000_000_000_001), 2_000_000_001);
        assert_eq!(disk_floor(20 << 30), (20u64 << 30).div_ceil(1000));
        assert_eq!(crate::storage_labels::disk_floor(20 << 30), 8 << 30);
    }

    #[test]
    fn parallel_verdict_uses_measured_allocation_wall_time_not_summed_cpu_time() {
        let mut m = measurements();
        for shard in &mut m {
            for round in &mut shard.rounds {
                round.encode_seconds = 800.;
            }
        }
        assert_eq!(assess(evidence(&m)).verdict, Verdict::NoGo);
        let allocation = AllocationMeasurement {
            parallel_jobs: 2,
            cold_wall_seconds: 10.,
            rounds: vec![
                AllocationRoundMeasurement {
                    registration_wall_seconds: 300.,
                    frame_openings_wall_seconds: 5.,
                    settlement_wall_seconds: 4.
                };
                2
            ],
        };
        let mut e = evidence(&m);
        e.allocation = Some(&allocation);
        let result = assess(e);
        assert_eq!(result.verdict, Verdict::GoForCheckpoint);
        assert_eq!(result.worst_registration_seconds, 300.);
        assert_eq!(result.cold_measured_seconds, 11.);
        let mut invalid = allocation.clone();
        invalid.rounds.pop();
        let mut e = evidence(&m);
        e.allocation = Some(&invalid);
        assert_eq!(assess(e).verdict, Verdict::Incomplete);
    }

    #[test]
    fn totals_the_worst_round_of_every_shard_and_reserves_consensus_time() {
        let m = measurements();
        let r = assess(evidence(&m));
        assert_eq!(r.verdict, Verdict::GoForCheckpoint);
        assert_eq!(r.worst_registration_seconds, 6.);
        assert_eq!(r.local_startup_verdict, Verdict::GoForCheckpoint);
        assert_eq!(r.cold_with_inclusion_and_headroom_seconds, 77.);
    }
    #[test]
    fn local_deadline_and_modeled_network_readiness_are_distinct() {
        let m = measurements();
        let mut e = evidence(&m);
        e.initial_local_setup_seconds = Some(7199.);
        let result = assess(e);
        assert_eq!(result.local_startup_verdict, Verdict::GoForCheckpoint);
        assert_eq!(result.verdict, Verdict::NoGo);
        let mut e = evidence(&m);
        e.initial_local_setup_seconds = Some(7201.);
        assert_eq!(assess(e).local_startup_verdict, Verdict::NoGo);
        let mut incomplete = measurements();
        incomplete[0].capacity_messages.clear();
        assert_eq!(assess(evidence(&incomplete)).verdict, Verdict::Incomplete);
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

#[cfg(test)]
mod startup_budget_tests {
    use super::*;
    #[test]
    fn startup_deadline_is_two_hours_and_stops_only_unfinished_startup() {
        assert!(!initial_setup_expired(
            std::time::Duration::from_secs(7199),
            false
        ));
        assert!(initial_setup_expired(
            std::time::Duration::from_secs(7200),
            false
        ));
        assert!(initial_setup_expired(
            std::time::Duration::from_secs(7201),
            false
        ));
        assert!(!initial_setup_expired(
            std::time::Duration::from_secs(99999),
            true
        ));
    }
}
