//! Checks for forecasts derived from node-owned cadence snapshots.
#[cfg(test)]
mod node_forecast_tests {
    use super::super::super::{
        committee_size, format_quil_daily_units, observed_quil_daily, quorum_signers,
    };
    use num_bigint::BigInt;
    use quil_types::proto::node::{FrameCadence, FrameWindow, ShardProverCounts, ShardRewardInfo};
    #[test]
    fn observed_forecasts_distinguish_zero_and_missing_coverage() {
        let mut c = FrameCadence {
            last_observed_unix_seconds: 1,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: 120,
                advanced_frames: 6,
            }),
            day: None,
        };
        let rate = observed_quil_daily(&BigInt::from(100_000_000), &c, false, 1, None).unwrap();
        assert_eq!(format_quil_daily_units(&rate), "~54.0");
        assert!(observed_quil_daily(&BigInt::from(1), &c, true, 1, None).is_none());
        c.hour.as_mut().unwrap().advanced_frames = 0;
        assert_eq!(
            observed_quil_daily(&BigInt::from(1), &c, false, 1, None),
            Some(BigInt::from(0))
        );
    }

    /// A shard frame credits only its certificate's quorum of signers,
    /// `n - (n - 1) / 3` of an `n`-member committee.
    #[test]
    fn a_frame_credits_only_its_quorum_of_signers() {
        let quorums: Vec<_> = [1, 2, 3, 4, 7, 16, 22, 23, 24, 28]
            .into_iter()
            .map(quorum_signers)
            .collect();
        assert_eq!(quorums, [1, 2, 3, 3, 5, 11, 15, 16, 17, 19]);
    }

    /// The observed estimates pay a seat the quorum share of the frames; a
    /// committee of one, or an unknown one, pays every frame.
    #[test]
    fn observed_forecasts_scale_by_the_quorum_share() {
        let c = FrameCadence {
            last_observed_unix_seconds: 1000,
            hour: Some(FrameWindow {
                window_seconds: 3600,
                observed_seconds: 600,
                advanced_frames: 30,
            }),
            day: None,
        };
        let daily = |committee| {
            observed_quil_daily(&BigInt::from(22_000), &c, false, committee, None).unwrap()
        };
        // Every frame paid: 22_000 * 30 * 86400 / 600.
        assert_eq!(daily(0), BigInt::from(95_040_000));
        assert_eq!(daily(1), BigInt::from(95_040_000));
        assert_eq!(daily(2), BigInt::from(95_040_000));
        assert_eq!(daily(4), BigInt::from(95_040_000 / 4 * 3));
        assert_eq!(daily(22), BigInt::from(95_040_000 / 22 * 15));
    }

    /// The committee is the active provers and seated leavers; a server
    /// without phase counts gives only the live count.
    #[test]
    fn the_committee_excludes_joining_and_paused_provers() {
        let mut shard = ShardRewardInfo {
            active_provers: 27,
            prover_counts: Some(ShardProverCounts {
                joining: 2,
                activating: 2,
                active: 20,
                paused: 1,
                leaving: 1,
                departing: 1,
            }),
            ..Default::default()
        };
        assert_eq!(committee_size(&shard), 22);
        shard.prover_counts = None;
        assert_eq!(committee_size(&shard), 27);
    }
}
