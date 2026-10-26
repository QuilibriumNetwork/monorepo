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
    quil_types::consensus::init_global_committee_succession_for_network(network);
    let hash_epoch = quil_types::consensus::init_hash_storage_proof_epoch(network);
    if network != 0 && hash_epoch != u64::MAX {
        tracing::warn!(
            epoch = hash_epoch,
            "QUIL_HASH_STORAGE_PROOF_EPOCH override active (localnet only)"
        );
    }
    let succession_epoch = quil_types::consensus::init_seniority_succession_epoch(network);
    if network != 0 && succession_epoch != u64::MAX {
        tracing::warn!(
            epoch = succession_epoch,
            "QUIL_SENIORITY_SUCCESSION_EPOCH override active (localnet only)"
        );
    }
    if network != 0 && frames != quil_types::consensus::TESTNET_EPOCH_LENGTH_FRAMES {
        tracing::warn!(
            frames,
            "QUIL_EPOCH_LENGTH_FRAMES override active (localnet only)"
        );
    }
    let replay_guard_epoch = quil_types::consensus::init_prover_op_replay_guard_epoch(network);
    if network != 0 && replay_guard_epoch != u64::MAX {
        tracing::warn!(
            epoch = replay_guard_epoch,
            "QUIL_PROVER_OP_REPLAY_GUARD_EPOCH override active (localnet only)"
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

    /// A/B reproducer for replayed prover operations: a signed leave is
    /// accepted however long before the including GLOBAL frame it was
    /// signed. On a test network that sets
    /// `QUIL_PROVER_OP_REPLAY_GUARD_EPOCH=0`, a build with the replay guard
    /// refuses it; a build without the guard ignores the setting.
    #[test]
    fn reproduces_replayed_prover_leave() {
        use quil_execution::global_intrinsic::intrinsic::GlobalIntrinsic;
        use quil_execution::global_intrinsic::materialize::create_prover_vertex_tree;
        use quil_execution::global_intrinsic::{AddressedSignature, ProverLeave};
        use quil_types::crypto::{KeyManager, KeyType};

        struct AcceptAll;
        impl KeyManager for AcceptAll {
            fn validate_signature(
                &self,
                _: KeyType,
                _: &[u8],
                _: &[u8],
                _: &[u8],
                _: &[u8],
            ) -> quil_types::error::Result<bool> {
                Ok(true)
            }
        }

        std::env::set_var("QUIL_PROVER_OP_REPLAY_GUARD_EPOCH", "0");
        super::initialize(1);
        let gi = GlobalIntrinsic::new(std::sync::Arc::new(AcceptAll));
        let prover = create_prover_vertex_tree(&[0xAAu8; 585], 0).unwrap();
        let leave = |signed: u64| {
            ProverLeave {
                filters: vec![vec![0xAAu8; 32]],
                frame_number: signed,
                public_key_signature_bls48581: Some(AddressedSignature {
                    signature: vec![0xBBu8; 666],
                    address: vec![0xCCu8; 32],
                }),
            }
            .to_canonical_bytes()
            .unwrap()
        };
        let at = 20 * quil_types::consensus::epoch_length_frames() + 30;
        assert!(
            gi.validate(at, &leave(at - 5), Some(&prover), None)
                .unwrap(),
            "a fresh leave is accepted"
        );
        let replayed = gi.validate(at, &leave(at - 100), Some(&prover), None);
        assert!(
            !matches!(replayed, Ok(true)),
            "replayed leave accepted again: a leave signed at frame {} was accepted at frame {at}",
            at - 100
        );
    }
}
