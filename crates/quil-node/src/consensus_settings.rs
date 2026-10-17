//! Consensus settings shared by master and separate worker processes.

fn epoch_length(network: u8, local_override: Option<&str>) -> u64 {
    if network == 0 {
        return quil_types::consensus::EPOCH_LENGTH_FRAMES;
    }
    local_override
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|frames| *frames > 0)
        .unwrap_or(quil_types::consensus::TESTNET_EPOCH_LENGTH_FRAMES)
}

pub(crate) fn initialize(network: u8) {
    let local_override = std::env::var("QUIL_EPOCH_LENGTH_FRAMES").ok();
    let frames = epoch_length(network, local_override.as_deref());
    quil_types::consensus::set_epoch_length_frames(frames);
    quil_types::consensus::init_committee_handoff_for_network(network);
    if network != 0 && frames != quil_types::consensus::TESTNET_EPOCH_LENGTH_FRAMES {
        tracing::warn!(
            frames,
            "QUIL_EPOCH_LENGTH_FRAMES override active (localnet only)"
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_epoch_override_is_shared_and_cannot_change_mainnet() {
        for network in [0, 1, 2] {
            for (setting, testnet_frames) in [
                (None, 60),
                (Some("30"), 30),
                (Some("1"), 1),
                (Some("0"), 60),
                (Some("bad"), 60),
                (Some("-1"), 60),
                (Some("18446744073709551616"), 60),
            ] {
                assert_eq!(
                    super::epoch_length(network, setting),
                    if network == 0 { 720 } else { testnet_frames }
                );
            }
        }
    }
}
