//! Checks for forecasts derived from node-owned cadence snapshots.
#[cfg(test)]
mod node_forecast_tests {
    use super::super::super::{observed_quil_daily, format_quil_daily_units};
    use quil_types::proto::node::{FrameCadence, FrameWindow};
    use num_bigint::BigInt;
    #[test]
    fn observed_forecasts_distinguish_zero_missing_and_stale_coverage() {
        let mut c = FrameCadence { last_observed_unix_seconds: 1000,
            hour: Some(FrameWindow { window_seconds: 3600, observed_seconds: 120, advanced_frames: 6 }), day: None };
        let rate = observed_quil_daily(&BigInt::from(100_000_000), &c, false, 1000).unwrap();
        assert_eq!(format_quil_daily_units(&rate), "~54.0");
        assert!(observed_quil_daily(&BigInt::from(1), &c, true, 1000).is_none());
        assert!(observed_quil_daily(&BigInt::from(1), &c, false, 1091).is_none());
        c.hour.as_mut().unwrap().advanced_frames = 0;
        assert_eq!(observed_quil_daily(&BigInt::from(1), &c, false, 1000), Some(BigInt::from(0)));
    }
}
