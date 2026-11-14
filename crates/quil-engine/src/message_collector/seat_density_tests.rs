//! Held storage epoch proofs whose windows end together, by the seats they
//! carry per byte: a proposal takes first the denser of those their members
//! delivered as active provers, each member's first of at least
//! `SEAT_DENSITY_MIN_BYTES`, after any due sooner; every other proof
//! rides in arrival order.

use super::*;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::global_intrinsic::storage_seat::settlement_window;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// The epoch the seats below settle: each settlement's window ends as
/// `EPOCH + 2` begins, as does the window of a seal of `EPOCH + 2`.
const EPOCH: u64 = 1478;
/// About the size of a settlement proof on mainnet, of one seat or several.
const LEN: usize = 650_000;

/// Member `id`'s address.
fn member(id: u32) -> [u8; 32] {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    member
}

/// The identity member `id`'s node delivers with.
fn peer(id: u32) -> Vec<u8> {
    [&b"peer"[..], &id.to_be_bytes()].concat()
}

/// A seat of `EPOCH` on shard `shard` that settles, seals, or both.
fn seat(shard: u8, settles: bool, seals: bool) -> SeatProof {
    SeatProof {
        shard_filter: vec![shard; 32],
        epoch: EPOCH,
        settles,
        seals,
        ..Default::default()
    }
}

/// Member `id`'s proof of `seats`, `len` bytes long as a bundle.
fn sized(id: u32, seats: Vec<SeatProof>, len: usize) -> Vec<u8> {
    let bundle = |proof_len: usize| {
        let mut bytes = vec![0u8; proof_len];
        bytes[..4].copy_from_slice(&id.to_be_bytes());
        let proof = StorageEpochProof {
            member: member(id),
            seats: seats.clone(),
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
    };
    let overhead = bundle(4).len() - 4;
    let bytes = bundle(len - overhead);
    assert_eq!(bytes.len(), len);
    bytes
}

/// Member `id`'s proof settling `seats` of its seats of `EPOCH`, of
/// [`LEN`] bytes.
fn settling(id: u32, seats: u8) -> Vec<u8> {
    sized(id, (0..seats).map(|s| seat(s, true, false)).collect(), LEN)
}

/// Five settlements of `EPOCH`.
fn five() -> Vec<SeatProof> {
    (10..15).map(|s| seat(s, true, false)).collect()
}

/// A collector of GLOBAL messages that saw a frame of epoch `EPOCH + 1`
/// finalized, before the windows above end, and names member `id` the
/// sender `peer(id)`.
fn collector() -> MessageCollector {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    mc.note_finalized_frame(settlement_window(EPOCH).0);
    mc.set_sender_member(|peer| {
        let id: [u8; 4] = peer.strip_prefix(&b"peer"[..])?.try_into().ok()?;
        Some(member(u32::from_be_bytes(id)))
    });
    mc
}

/// `bytes` delivered by member `sender`, an active prover.
fn send(mc: &MessageCollector, sender: u32, bytes: &[u8]) -> SubmitOutcome {
    mc.add_message_outcome_by(1, bytes.to_vec(), Provenance::Prover, &peer(sender))
}

/// One-seat proofs from ids `first` on, each delivered through `submit`,
/// of [`LEN`] bytes and one of what is left, `bytes` in all; the next id.
fn one_seat_proofs(
    first: u32,
    bytes: usize,
    mut submit: impl FnMut(u32, Vec<u8>) -> SubmitOutcome,
) -> u32 {
    let (mut left, mut id) = (bytes, first);
    while left > 0 {
        let len = left.min(LEN);
        let proof = sized(id, vec![seat(0, true, false)], len);
        assert_eq!(submit(id, proof), SubmitOutcome::Accepted);
        left -= len;
        id += 1;
    }
    id
}

/// One-seat proofs their members delivered, ids from 1 on, filling a
/// proposal's storage proof budget but for 1,000 bytes; how many.
fn fill_frame(mc: &MessageCollector) -> u32 {
    let bytes = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME - 1_000;
    one_seat_proofs(1, bytes, |id, proof| send(mc, id, &proof)) - 1
}

/// The keys of the messages a proposal takes.
fn proposal(mc: &MessageCollector) -> HashSet<[u8; 32]> {
    mc.snapshot_for_proposal(1, 16 << 20, 10_000, None, &[])
        .unwrap()
        .iter()
        .map(|(data, _)| message_key(data))
        .collect()
}

/// Among proofs due at one frame, a proposal's storage proof budget goes
/// to those carrying more seats per byte first, one of exactly
/// `SEAT_DENSITY_MIN_BYTES` included: in arrival order, one-seat proofs
/// that came first filled it and members' proofs of five seats waited.
#[test]
fn a_proposal_carries_the_denser_proofs_due_together_first() {
    let mc = collector();
    let fillers = fill_frame(&mc);
    let dense = sized(101, five(), LEN);
    assert_eq!(send(&mc, 101, &dense), SubmitOutcome::Accepted);
    let at_minimum = sized(102, five(), SEAT_DENSITY_MIN_BYTES);
    assert_eq!(send(&mc, 102, &at_minimum), SubmitOutcome::Accepted);
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density order fillers={fillers} taken={}",
        taken.len()
    );
    assert!(
        taken.contains(&message_key(&dense)),
        "density_order: a proof of five seats waited behind one-seat proofs due at the same frame"
    );
    assert!(
        taken.contains(&message_key(&at_minimum)),
        "density_at_minimum: a proof of exactly the minimum size did not count its seats per byte"
    );
}

/// Only the oldest proof a member delivered itself rides ahead of others
/// due at the same frame by its seats per byte: a proof another sender
/// delivered, and a member's second, ride in arrival order.
#[test]
fn proofs_not_their_members_first_ride_in_arrival_order() {
    let mc = collector();
    let per_frame = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME / LEN;
    for id in 1..=per_frame as u32 {
        assert_eq!(send(&mc, id, &settling(id, 1)), SubmitOutcome::Accepted);
    }
    let relayed = settling(101, 5);
    assert_eq!(send(&mc, 700, &relayed), SubmitOutcome::Accepted);
    let second = sized(1, five(), LEN);
    assert_eq!(send(&mc, 1, &second), SubmitOutcome::Accepted);
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density arrival per_frame={per_frame} taken={}",
        taken.len()
    );
    assert!(
        !taken.contains(&message_key(&relayed)),
        "arrival_order: a proof another sender delivered rode ahead by its seats per byte"
    );
    assert!(
        !taken.contains(&message_key(&second)),
        "member_second_order: a member's second proof rode ahead by its seats per byte"
    );
}

/// The window's end orders before seats per byte: a member's denser proof
/// due later rides behind one-seat proofs due sooner.
#[test]
fn a_denser_proof_due_later_rides_behind_those_due_sooner() {
    let mc = collector();
    let fillers = fill_frame(&mc);
    let later_seats = (10..15)
        .map(|s| SeatProof {
            epoch: EPOCH + 1,
            ..seat(s, true, false)
        })
        .collect();
    let later = sized(101, later_seats, LEN);
    assert_eq!(send(&mc, 101, &later), SubmitOutcome::Accepted);
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density later_end fillers={fillers} taken={}",
        taken.len()
    );
    assert!(
        !taken.contains(&message_key(&later)),
        "later_end_order: a denser proof due later rode ahead of proofs due sooner"
    );
}

/// Seals count as settlements do: a proof sealing two seats, as long as a
/// settlement of one, rides ahead of one-seat settlements due with it.
#[test]
fn a_proof_of_seals_alone_counts_its_seals() {
    let mc = collector();
    let fillers = fill_frame(&mc);
    let seals = sized(600, vec![seat(0, false, true), seat(1, false, true)], LEN);
    assert_eq!(send(&mc, 600, &seals), SubmitOutcome::Accepted);
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density seals fillers={fillers} taken={}",
        taken.len()
    );
    assert!(
        taken.contains(&message_key(&seals)),
        "seals_counted: a proof of two seals waited behind one-seat settlements"
    );
}

/// A sender that is not an active prover rides in arrival order, though
/// its identity names the member whose proof it delivered: its proof of
/// five seats waits behind one-seat proofs that came first.
#[test]
fn a_sender_not_an_active_prover_rides_in_arrival_order() {
    let mc = collector();
    // An active prover's proof rides first and takes part of the budget.
    let ahead = settling(50, 1);
    assert_eq!(
        mc.add_message_outcome_from(1, ahead.clone(), Provenance::Prover),
        SubmitOutcome::Accepted
    );
    // Then proofs from senders no one names fill it but for 1,000 bytes.
    let bytes = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME - LEN - 1_000;
    let others = one_seat_proofs(1, bytes, |_, proof| {
        mc.add_message_outcome_from(1, proof, Provenance::Other)
    }) - 1;
    let named = sized(101, five(), 300_000);
    assert_eq!(
        mc.add_message_outcome_by(1, named.clone(), Provenance::Other, &peer(101)),
        SubmitOutcome::Accepted
    );
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density not_prover others={others} taken={}",
        taken.len()
    );
    assert!(taken.contains(&message_key(&ahead)));
    assert!(
        !taken.contains(&message_key(&named)),
        "not_prover_order: a proof from a sender not an active prover rode ahead by its seats per byte"
    );
}

/// A proof under `SEAT_DENSITY_MIN_BYTES` rides in arrival order, though
/// its member delivered it as an active prover: its five seats wait behind
/// one-seat proofs that came first.
#[test]
fn a_proof_under_the_minimum_size_rides_in_arrival_order() {
    let mc = collector();
    let fillers = fill_frame(&mc);
    let light = sized(101, five(), SEAT_DENSITY_MIN_BYTES - 1);
    assert_eq!(send(&mc, 101, &light), SubmitOutcome::Accepted);
    let taken = proposal(&mc);
    eprintln!(
        "REACH seat-density under_minimum fillers={fillers} taken={}",
        taken.len()
    );
    assert!(
        !taken.contains(&message_key(&light)),
        "under_minimum_order: a proof under the minimum size rode ahead by its seats per byte"
    );
}
