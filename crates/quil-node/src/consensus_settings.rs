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

/// The shortest GLOBAL frame interval a local network may set. The VDF at
/// the difficulty floor takes about three seconds, so a shorter interval
/// only means the leader never waits.
const MIN_FRAME_TIME_MS: u64 = 500;

/// The GLOBAL frame-interval schedule `QUIL_FRAME_TIME_MS` sets, as
/// `(first frame, interval ms)` entries: empty (the ten-second default) on
/// mainnet whatever the setting, and when it is unset or empty. Elsewhere it is one
/// interval (`2500`) or comma-separated intervals keyed by the GLOBAL frame
/// they start at (`2500,10000@240`: 2.5 s from genesis, 10 s from frame 240
/// on), the first from frame 0 (no `@` or `@0`), frames strictly ascending;
/// each interval at least [`MIN_FRAME_TIME_MS`]. An invalid setting is
/// refused with its reason.
fn frame_time_schedule(
    network: u8,
    local_override: Option<&str>,
) -> Result<Vec<(u64, u64)>, String> {
    let Some(setting) = local_override.filter(|setting| network != 0 && !setting.trim().is_empty())
    else {
        return Ok(Vec::new());
    };
    let mut schedule: Vec<(u64, u64)> = Vec::new();
    for entry in setting.split(',').map(str::trim) {
        let (millis, from) = match entry.split_once('@') {
            Some((millis, from)) => (
                millis.trim(),
                from.trim()
                    .parse::<u64>()
                    .map_err(|_| format!("bad start frame in {entry:?}"))?,
            ),
            None => (entry, 0),
        };
        let millis = millis
            .parse::<u64>()
            .ok()
            .filter(|millis| *millis > 0)
            .ok_or_else(|| format!("bad interval in {entry:?}"))?;
        match schedule.last() {
            None if from != 0 => {
                return Err(format!(
                    "the first interval must start at frame 0, not {from}"
                ))
            }
            Some((last, _)) if from <= *last => {
                return Err(format!("start frame {from} does not follow {last}"))
            }
            _ => schedule.push((from, millis.max(MIN_FRAME_TIME_MS))),
        }
    }
    Ok(schedule)
}

pub(crate) fn initialize(network: u8) {
    let local_override = std::env::var("QUIL_EPOCH_LENGTH_FRAMES").ok();
    let frames = epoch_length(network, local_override.as_deref());
    quil_types::consensus::set_epoch_length_frames(frames);
    let frame_time_setting = std::env::var("QUIL_FRAME_TIME_MS").ok();
    match frame_time_schedule(network, frame_time_setting.as_deref()) {
        Ok(schedule) if schedule.is_empty() => {}
        Ok(schedule) => {
            let intervals = schedule
                .iter()
                .map(|(from, millis)| format!("{millis} ms from frame {from}"))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                intervals = %intervals,
                "QUIL_FRAME_TIME_MS override active: GLOBAL frame interval set instead of \
                 10000 ms (local networks only; mainnet ignores it)"
            );
            quil_types::consensus::set_frame_time_schedule(schedule);
        }
        Err(reason) => tracing::warn!(
            setting = frame_time_setting.as_deref().unwrap_or_default(),
            reason = %reason,
            "QUIL_FRAME_TIME_MS ignored: GLOBAL frames keep the 10000 ms default; set one \
             interval in ms or ascending entries like 2500,10000@240 (local networks only)"
        ),
    }
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
    let (pause_epoch, _) = quil_types::consensus::init_storage_attestation_pause(network);
    if network != 0 && pause_epoch != u64::MAX {
        tracing::warn!(
            epoch = pause_epoch,
            "QUIL_STORAGE_ATTESTATION_PAUSE_EPOCH override active (localnet only)"
        );
    }
    let binding_epoch = quil_types::consensus::init_vertex_value_binding_epoch(network);
    if network != 0 && binding_epoch != u64::MAX {
        tracing::warn!(
            epoch = binding_epoch,
            "QUIL_VERTEX_VALUE_BINDING_EPOCH override active (localnet only)"
        );
    }
    let strict_peer_info_epoch = quil_types::consensus::init_strict_peer_info_epoch(network);
    if network != 0 && strict_peer_info_epoch != u64::MAX {
        tracing::warn!(
            epoch = strict_peer_info_epoch,
            "QUIL_STRICT_PEER_INFO_EPOCH override active (localnet only)"
        );
    }
    let strict_shard_gossip_epoch = quil_types::consensus::init_strict_shard_gossip_epoch(network);
    if network != 0 && strict_shard_gossip_epoch != u64::MAX {
        tracing::warn!(
            epoch = strict_shard_gossip_epoch,
            "QUIL_STRICT_SHARD_GOSSIP_EPOCH override active (localnet only)"
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
    let exact_size_epoch = quil_types::consensus::init_exact_state_size_epoch(network);
    if network != 0 && exact_size_epoch != u64::MAX {
        tracing::warn!(
            epoch = exact_size_epoch,
            "QUIL_EXACT_STATE_SIZE_EPOCH override active (localnet only)"
        );
    }
    let padding_bound_epoch = quil_types::consensus::init_storage_padding_bound_epoch(network);
    if network != 0 && padding_bound_epoch != u64::MAX {
        tracing::warn!(
            epoch = padding_bound_epoch,
            "QUIL_STORAGE_PADDING_BOUND_EPOCH override active (localnet only)"
        );
    }

    let kick_epoch = quil_types::consensus::init_kick_signed_slot_epoch(network);
    if network != 0 && kick_epoch != u64::MAX {
        tracing::warn!(
            epoch = kick_epoch,
            "QUIL_KICK_SIGNED_SLOT_EPOCH override active (localnet only)"
        );
    }
    let anchor_epoch = quil_types::consensus::init_required_anchor_epoch(network);
    if network != 0 && anchor_epoch != u64::MAX {
        tracing::warn!(
            epoch = anchor_epoch,
            "QUIL_REQUIRED_ANCHOR_EPOCH override active (localnet only)"
        );
    }
    let issuance_epoch = quil_types::consensus::init_anchored_issuance_epoch(network);
    if network != 0 && issuance_epoch != u64::MAX {
        tracing::warn!(
            epoch = issuance_epoch,
            "QUIL_ANCHORED_ISSUANCE_EPOCH override active (localnet only)"
        );
    }
    let late_credit_epoch = quil_types::consensus::init_late_header_credit_epoch(network);
    if network != 0 && late_credit_epoch != u64::MAX {
        tracing::warn!(
            epoch = late_credit_epoch,
            "QUIL_LATE_HEADER_CREDIT_EPOCH override active (localnet only)"
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
    let replay_guard_epoch = quil_types::consensus::init_prover_op_replay_guard_epoch(network);
    if network != 0 && replay_guard_epoch != u64::MAX {
        tracing::warn!(
            epoch = replay_guard_epoch,
            "QUIL_PROVER_OP_REPLAY_GUARD_EPOCH override active (localnet only)"
        );
    }
    let sealed_epoch = quil_types::consensus::init_sealed_storage_epoch(network);
    if network != 0 && sealed_epoch != u64::MAX {
        tracing::warn!(
            epoch = sealed_epoch,
            "QUIL_SEALED_STORAGE_EPOCH override active (localnet only)"
        );
    }
    let shard_op_binding_epoch = quil_types::consensus::init_shard_op_binding_epoch(network);
    if network != 0 && shard_op_binding_epoch != u64::MAX {
        tracing::warn!(
            epoch = shard_op_binding_epoch,
            "QUIL_SHARD_OP_BINDING_EPOCH override active (localnet only)"
        );
    }
    let unsealed_epoch = quil_types::consensus::init_unsealed_issuance_epoch(network);
    if network != 0 && unsealed_epoch != u64::MAX {
        tracing::warn!(
            epoch = unsealed_epoch,
            "QUIL_UNSEALED_ISSUANCE_EPOCH override active (localnet only)"
        );
    }
    let kick_suspension_epoch = quil_types::consensus::init_storage_kick_suspension_epoch(network);
    if network != 0 && kick_suspension_epoch != u64::MAX {
        tracing::warn!(
            epoch = kick_suspension_epoch,
            "QUIL_STORAGE_KICK_SUSPENSION_EPOCH override active (localnet only)"
        );
    }
    let stable_key_epoch = quil_types::consensus::init_stable_replica_key_epoch(network);
    if network != 0 && stable_key_epoch != u64::MAX {
        tracing::warn!(
            epoch = stable_key_epoch,
            hash_storage_proof_epoch = hash_epoch,
            "QUIL_STABLE_REPLICA_KEY_EPOCH override active (localnet only; never before the hash \
             storage proof epoch)"
        );
    }
    let persistent_epoch = quil_types::consensus::init_persistent_storage_epoch(network);
    if persistent_epoch != u64::MAX {
        tracing::warn!(
            epoch = persistent_epoch,
            "persistent storage certificates activation configured"
        );
    }
    let signed_frame_activation =
        quil_types::consensus::init_signed_frame_activation_frame(network);
    if network != 0 && signed_frame_activation != u64::MAX {
        tracing::warn!(
            frame = signed_frame_activation,
            "QUIL_SIGNED_FRAME_ACTIVATION_FRAME override active (localnet only)"
        );
    }
    let (restoration_frame, restored_provers) =
        quil_types::consensus::init_kicked_seniority_restoration(network);
    if network != 0 && restoration_frame != u64::MAX {
        tracing::warn!(
            frame = restoration_frame,
            provers = restored_provers,
            "QUIL_KICKED_SENIORITY_RESTORATION_FRAME override active (localnet only)"
        );
    }
    let citation_window_epoch = quil_types::consensus::init_global_citation_window_epoch(network);
    if network != 0 && citation_window_epoch != u64::MAX {
        tracing::warn!(
            epoch = citation_window_epoch,
            "QUIL_GLOBAL_CITATION_WINDOW_EPOCH override active (localnet only)"
        );
    }
}

#[cfg(test)]
#[path = "anchored_issuance_tests.rs"]
mod anchored_issuance_tests;

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

    /// Mainnet keeps the ten-second GLOBAL frame interval whatever
    /// `QUIL_FRAME_TIME_MS` says, a single value or a schedule.
    #[test]
    fn local_frame_time_override_cannot_change_mainnet() {
        for setting in [
            None,
            Some("1000"),
            Some("2500"),
            Some("2500,10000@240"),
            Some("bad"),
        ] {
            assert_eq!(super::frame_time_schedule(0, setting), Ok(Vec::new()));
        }
    }

    /// Other networks take one interval or ascending entries keyed by start
    /// frame, each at least 500 ms; zero, garbage, a first entry after
    /// frame 0 and start frames out of order are refused.
    #[test]
    fn local_frame_time_schedule_parses_and_floors() {
        for network in [1, 2] {
            let schedule = |setting| super::frame_time_schedule(network, Some(setting));
            assert_eq!(super::frame_time_schedule(network, None), Ok(Vec::new()));
            assert_eq!(schedule(" "), Ok(Vec::new()), "empty is unset");
            assert_eq!(schedule("1000"), Ok(vec![(0, 1_000)]));
            assert_eq!(schedule("2500"), Ok(vec![(0, 2_500)]));
            assert_eq!(schedule("2500@0"), Ok(vec![(0, 2_500)]));
            assert_eq!(schedule("100"), Ok(vec![(0, 500)]));
            assert_eq!(schedule("499"), Ok(vec![(0, 500)]));
            assert_eq!(schedule("500"), Ok(vec![(0, 500)]));
            assert_eq!(
                schedule("2500,10000@240"),
                Ok(vec![(0, 2_500), (240, 10_000)])
            );
            assert_eq!(
                schedule(" 2500 , 100@240 , 3000@ 500"),
                Ok(vec![(0, 2_500), (240, 500), (500, 3_000)])
            );
            for invalid in [
                "0",
                "bad",
                "-1",
                "2500,",
                "2500,0@240",
                "2500,10000@x",
                "2500@10",
                "10000@240",
                "2500,10000@240,3000@240",
                "2500,10000@240,3000@100",
                "2500,10000@0",
                "18446744073709551616",
            ] {
                assert!(schedule(invalid).is_err(), "{invalid:?} is refused");
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

    /// A/B reproducer for ancient global citations: a mint claim may cite a
    /// global frame however far before its anchor, and a replica without
    /// that frame holds the claim's frame for retry while the others apply
    /// it. On a test network that sets `QUIL_GLOBAL_CITATION_WINDOW_EPOCH=0`,
    /// a build with the citation window refuses the claim outright; a build
    /// without it ignores the setting.
    #[cfg(feature = "native-proof")]
    #[test]
    fn reproduces_ancient_global_citation_stall() {
        use quil_execution::token_intrinsic::mint_claim::verify_from_clock;
        use quil_lattice_ct::confidential::{
            mint_claim::MintClaim,
            relation::membership::IDENTITY_BYTES,
            transfer::{parameter_context, Output, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        use quil_types::error::QuilError;
        use quil_types::execution::{FrameExecutionContext, ShardPath};

        std::env::set_var("QUIL_GLOBAL_CITATION_WINDOW_EPOCH", "0");
        super::initialize(1);
        let network = [1; 32];
        let app = quil_execution::domains::QUIL_TOKEN;
        let context = parameter_context(&network, &app);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let claim = MintClaim {
            network,
            application: app,
            cited_global_frame: 1,
            global_root: [3; 32],
            receipt: [4; 32],
            fee: 0,
            outputs: vec![Output {
                commitment: CommitmentKey::derive(&context).commit(5, &opening),
                owner: [6; IDENTITY_BYTES],
                memo: [7; MEMO_BYTES],
            }],
            forest_proof: vec![1],
        }
        .encode()
        .unwrap();
        // This replica holds no global frame below the anchor.
        let clock = quil_store::testing::InMemoryClockStore::new();
        let anchor = 1_000_000;
        let outcome = verify_from_clock(
            &clock,
            FrameExecutionContext {
                frame_number: 2,
                finalized_global_frame: Some(anchor),
                shard: ShardPath::WHOLE,
                venue: None,
            },
            &network,
            &app,
            &claim,
            2,
        )
        .err();
        assert!(
            matches!(outcome, Some(QuilError::InvalidArgument(_))),
            "a claim citing global frame 1 under anchor {anchor} stalls a replica without \
             that frame: {outcome:?} holds the frame for retry instead of refusing the claim"
        );
    }
}
