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
    let penalty_epoch = quil_types::consensus::init_seniority_penalty_epoch(network);
    if network != 0 && penalty_epoch != u64::MAX {
        tracing::warn!(
            epoch = penalty_epoch,
            "QUIL_SENIORITY_PENALTY_EPOCH override active (localnet only)"
        );
    }
    quil_types::consensus::init_committee_handoff_for_network(network);
    quil_types::consensus::init_global_committee_succession_for_network(network);
    let hash_epoch = quil_types::consensus::init_hash_storage_proof_epoch(network);
    if network != 0 && hash_epoch != u64::MAX {
        tracing::warn!(
            epoch = hash_epoch,
            "QUIL_HASH_STORAGE_PROOF_EPOCH override active (localnet only)"
        );
    }
    let binding_epoch = quil_types::consensus::init_vertex_value_binding_epoch(network);
    if network != 0 && binding_epoch != u64::MAX {
        tracing::warn!(
            epoch = binding_epoch,
            "QUIL_VERTEX_VALUE_BINDING_EPOCH override active (localnet only)"
        );
    }
    let succession_epoch = quil_types::consensus::init_seniority_succession_epoch(network);
    if network != 0 && succession_epoch != u64::MAX {
        tracing::warn!(
            epoch = succession_epoch,
            "QUIL_SENIORITY_SUCCESSION_EPOCH override active (localnet only)"
        );
    }
    if network != 0 && penalty_epoch < succession_epoch {
        tracing::warn!(
            penalty_epoch,
            succession_epoch,
            "seniority penalties apply only from the seniority succession epoch; set \
             QUIL_SENIORITY_SUCCESSION_EPOCH too to start them earlier (localnet only)"
        );
    }

    let kick_epoch = quil_types::consensus::init_kick_signed_slot_epoch(network);
    if network != 0 && kick_epoch != u64::MAX {
        tracing::warn!(
            epoch = kick_epoch,
            "QUIL_KICK_SIGNED_SLOT_EPOCH override active (localnet only)"
        );
    }
    let issuance_epoch = quil_types::consensus::init_anchored_issuance_epoch(network);
    if network != 0 && issuance_epoch != u64::MAX {
        tracing::warn!(
            epoch = issuance_epoch,
            "QUIL_ANCHORED_ISSUANCE_EPOCH override active (localnet only)"
        );
    }
    let sync_authentication = quil_types::consensus::init_global_sync_authentication_frame(network);
    if network != 0 && sync_authentication != u64::MAX {
        tracing::warn!(
            frame = sync_authentication,
            "QUIL_GLOBAL_SYNC_AUTHENTICATION_FRAME override active (localnet only)"
        );
    }
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
