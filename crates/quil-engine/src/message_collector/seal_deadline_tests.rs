//! Held storage epoch proofs by the end of their window: a proposal takes
//! the proof due soonest first, a full share makes room for one due sooner,
//! and a proof past its window rides no frame.

use super::*;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::global_intrinsic::storage_seat::settlement_window;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// The epoch the settlements below settle.
const EPOCH: u64 = 1478;
/// About the size of a settlement proof on mainnet.
const LEN: usize = 650_000;

/// Member `id`'s proof for one seat of `epoch`: its settlement, or the seal
/// of its registration for `epoch + 2`. A settlement's window ends as epoch
/// `EPOCH + 2` begins; a seal of epoch `EPOCH + 1`'s seat an epoch later.
fn proof(id: u32, epoch: u64, settles: bool) -> Vec<u8> {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    let mut bytes = vec![0u8; LEN];
    bytes[..4].copy_from_slice(&id.to_be_bytes());
    let proof = StorageEpochProof {
        member,
        seats: vec![SeatProof {
            shard_filter: member.to_vec(),
            epoch,
            seals: !settles,
            settles,
            ..Default::default()
        }],
        proof: bytes,
    };
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: TYPE_STORAGE_EPOCH_PROOF,
            inner_bytes: proof.to_canonical_bytes(),
        })],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// A settlement due as `EPOCH + 2` begins.
fn soon(id: u32) -> Vec<u8> {
    proof(id, EPOCH, true)
}

/// A seal due an epoch later.
fn late(id: u32) -> Vec<u8> {
    proof(id, EPOCH + 1, false)
}

fn global_collector() -> MessageCollector {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    mc
}

/// The ids of the proofs in a proposal.
fn ids(taken: &[(Vec<u8>, bool)], of: &HashMap<[u8; 32], u32>) -> Vec<u32> {
    taken
        .iter()
        .filter_map(|(data, _)| of.get(&sha256(data)).copied())
        .collect()
}

/// Proofs held with frames to spare do not hold a frame's seal budget ahead
/// of settlements due sooner that arrived after them.
#[test]
fn a_proposal_carries_the_proofs_due_soonest_first() {
    let mc = global_collector();
    let per_frame = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME / soon(0).len();
    let mut of = HashMap::new();
    for id in 1..=per_frame as u32 {
        let bytes = late(id);
        of.insert(sha256(&bytes), id);
        assert_eq!(mc.add_message_outcome(1, bytes), SubmitOutcome::Accepted);
    }
    for id in [101, 102] {
        let bytes = soon(id);
        of.insert(sha256(&bytes), id);
        assert_eq!(mc.add_message_outcome(1, bytes), SubmitOutcome::Accepted);
    }
    let taken = mc
        .snapshot_for_proposal(1, 16 << 20, 10_000, None, &[])
        .unwrap();
    let taken = ids(&taken, &of);
    eprintln!("REACH seal-deadline order taken={taken:?}");
    assert!(
        taken.contains(&101) && taken.contains(&102),
        "seal-deadline order: the frame took {taken:?}, not the settlements 101 and 102 due before the seals"
    );
    assert_eq!(taken.len(), per_frame, "the budget still fills");
}

/// A full share of held proofs makes room for a proof due sooner than some
/// it holds: the one due latest, newest first, leaves. A proof due no sooner
/// than every held one is refused for now, as before.
#[test]
fn a_full_share_makes_room_for_a_proof_due_sooner() {
    let mc = global_collector();
    let mut of = HashMap::new();
    let mut held = 0u32;
    for id in 1..=40u32 {
        let bytes = late(id);
        of.insert(sha256(&bytes), id);
        match mc.add_message_outcome(1, bytes) {
            SubmitOutcome::Accepted => held = id,
            SubmitOutcome::Filtered(Refusal::RankFull) => break,
            other => panic!("seal {id}: {other:?}"),
        }
    }
    assert_eq!(
        held as usize,
        SEAL_BYTES_HELD / late(0).len(),
        "seal-deadline equal: a proof due with the held ones took room while filling the share"
    );
    assert_eq!(
        mc.add_message_outcome(1, late(1000)),
        SubmitOutcome::Filtered(Refusal::RankFull),
        "seal-deadline equal: a proof due with the held ones takes no room"
    );
    let bytes = soon(101);
    of.insert(sha256(&bytes), 101);
    let outcome = mc.add_message_outcome(1, bytes);
    eprintln!("REACH seal-deadline evict outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "seal-deadline evict: a settlement due before every held seal was refused"
    );
    assert_eq!(mc.pending_count(1), held as usize, "one seal left for it");
    let taken = mc
        .snapshot_for_proposal(1, 16 << 20, 10_000, None, &[])
        .unwrap();
    let taken = ids(&taken, &of);
    assert_eq!(taken.first(), Some(&1), "the oldest seal stays");
    assert!(
        taken.contains(&101) && !taken.contains(&held),
        "seal-deadline evict-latest: the frame took {taken:?}; the newest seal {held} should have left for 101"
    );
}

/// A proof whose window has ended at the frame proposed rides no frame
/// (GLOBAL refuses it), and leaves at the next finalization; it cannot make
/// room for itself either.
#[test]
fn a_proof_past_its_window_rides_no_frame() {
    let end = settlement_window(EPOCH).1;
    let mc = global_collector();
    assert_eq!(mc.add_message_outcome(50, soon(1)), SubmitOutcome::Accepted);
    let taken = mc
        .snapshot_for_proposal(50, 16 << 20, 10_000, Some(end), &[])
        .unwrap();
    eprintln!("REACH seal-deadline closed taken={}", taken.len());
    assert!(
        taken.is_empty(),
        "seal-deadline closed: a proposal of frame {end} carried a settlement whose window ended there"
    );
    for rank in 1..=RETENTION_WINDOW + 1 {
        mc.prune_after_finalization(rank);
    }
    assert_eq!(
        mc.pending_count(50),
        0,
        "seal-deadline closed-drop: a proof past its window is still held"
    );
}

/// A proof already past its window at the newest frame proposed takes no
/// room from held proofs.
#[test]
fn a_proof_past_its_window_makes_no_room() {
    let end = settlement_window(EPOCH).1;
    let mc = global_collector();
    for id in 1..=40u32 {
        if mc.add_message_outcome(1, late(id)) != SubmitOutcome::Accepted {
            break;
        }
    }
    let held = mc.pending_count(1);
    mc.snapshot_for_proposal(1, 0, 0, Some(end), &[]).unwrap();
    let outcome = mc.add_message_outcome(1, soon(101));
    eprintln!("REACH seal-deadline closed-room outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Filtered(Refusal::RankFull),
        "seal-deadline closed-room: a settlement past its window took room"
    );
    assert_eq!(mc.pending_count(1), held);
}

/// Settlements due at their window's end and seals with an epoch to spare
/// arrive over the window's first two thirds, together 110% of what its
/// frames carry (6 proofs of 650 KB in 4 MiB a frame). Archives take turns
/// to lead; a sender sends each proof not yet taken to every archive each
/// frame, and one taken again ten frames on while no frame carried it (a
/// worker's next attempt). Every settlement rides before its window ends;
/// the seals take the room left and the frames after.
#[test]
fn settlements_ride_before_their_window_ends_under_110_percent_demand() {
    const ARCHIVES: usize = 2;
    const WINDOW: u64 = 24;
    const RESEND: u64 = 10;
    let end = settlement_window(EPOCH).1;
    let start = end - WINDOW;
    let per_frame = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME / soon(0).len();
    let capacity = WINDOW as usize * per_frame;
    let demand = capacity * 11 / 10;
    struct Sent {
        id: u32,
        settles: bool,
        bytes: Vec<u8>,
        arrives: u64,
        taken_at: Option<u64>,
        carried_at: Option<u64>,
    }
    let mut proofs: Vec<Sent> = (0..demand as u32)
        .map(|id| {
            let settles = id % 5 < 3;
            let bytes = if settles { soon(id) } else { late(id) };
            let arrives = start + u64::from(sha256(&id.to_be_bytes())[0]) % (WINDOW * 2 / 3);
            Sent {
                id,
                settles,
                bytes,
                arrives,
                taken_at: None,
                carried_at: None,
            }
        })
        .collect();
    proofs.sort_by_key(|p| (p.arrives, p.id));
    let of: HashMap<[u8; 32], usize> = proofs
        .iter()
        .enumerate()
        .map(|(index, p)| (sha256(&p.bytes), index))
        .collect();
    let archives: Vec<MessageCollector> = (0..ARCHIVES).map(|_| global_collector()).collect();
    let mut submits = 0usize;
    for frame in start..end + 2 * WINDOW {
        // A refusal for now refuses every proof due no sooner this frame.
        let mut refused: HashSet<(usize, bool)> = HashSet::new();
        for p in proofs.iter_mut() {
            let due = p.carried_at.is_none()
                && p.arrives <= frame
                && (!p.settles || frame < end)
                && p.taken_at.is_none_or(|at| frame >= at + RESEND);
            if !due {
                continue;
            }
            for (a, archive) in archives.iter().enumerate() {
                if refused.contains(&(a, p.settles)) || (!p.settles && refused.contains(&(a, true)))
                {
                    continue;
                }
                submits += 1;
                match archive.add_message_outcome_from(frame, p.bytes.clone(), Provenance::Prover) {
                    SubmitOutcome::Accepted | SubmitOutcome::Duplicate => p.taken_at = Some(frame),
                    SubmitOutcome::Filtered(Refusal::RankFull) => {
                        refused.insert((a, p.settles));
                    }
                    other => panic!("proof {}: {other:?}", p.id),
                }
            }
        }
        let leader = &archives[frame as usize % ARCHIVES];
        let taken: Vec<Vec<u8>> = leader
            .snapshot_for_proposal(frame, 16 << 20, 10_000, Some(frame), &[])
            .unwrap()
            .into_iter()
            .map(|(data, _)| data)
            .collect();
        for data in &taken {
            if let Some(&index) = of.get(&sha256(data)) {
                proofs[index].carried_at.get_or_insert(frame);
            }
        }
        for archive in &archives {
            archive.mark_finalized(&taken);
            archive.prune_after_finalization(frame);
        }
    }
    let settles = proofs.iter().filter(|p| p.settles).count();
    let in_time = proofs
        .iter()
        .filter(|p| p.settles && p.carried_at.is_some_and(|at| at < end))
        .count();
    let seals = proofs.len() - settles;
    let seals_carried = proofs
        .iter()
        .filter(|p| !p.settles && p.carried_at.is_some())
        .count();
    eprintln!(
        "REACH seal-deadline sim capacity={capacity} demand={demand} settles={settles} settled_in_time={in_time} \
         missed={} seals={seals} seals_carried={seals_carried} submits={submits}",
        settles - in_time
    );
    assert_eq!(
        in_time,
        settles,
        "seal-deadline sim: {} of {settles} settlements missed their window at 110% demand",
        settles - in_time
    );
}
