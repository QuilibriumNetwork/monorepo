//! A full share of held storage epoch proofs: its refusals name it, a large
//! proof gets the room frames free though smaller ones due with it keep
//! arriving, and proofs this archive's proposals keep passing over yield
//! their room to a proof due with them. Built from APIs every release of the
//! collector has, so each test runs, and fails, on a collector without them.

use super::*;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::global_intrinsic::storage_seat::settlement_window;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// The epoch the settlements below settle: each is due as `EPOCH + 2`
/// begins.
const EPOCH: u64 = 1478;

/// The proposals of this node that pass over a held proof before it yields
/// its room to one due with it (`SEAL_PASSES_TO_YIELD`).
const PASSES: u64 = 12;

/// Member `id`'s settlement of one seat of [`EPOCH`], with `len` proof bytes.
pub(super) fn settlement(id: u32, len: usize) -> Vec<u8> {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    let mut bytes = vec![0u8; len];
    bytes[..4].copy_from_slice(&id.to_be_bytes());
    let proof = StorageEpochProof {
        member,
        seats: vec![SeatProof {
            shard_filter: member.to_vec(),
            epoch: EPOCH,
            settles: true,
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

/// A GLOBAL collector that saw a frame of epoch `EPOCH + 1` finalized,
/// before the settlements' window ends.
pub(super) fn archive() -> MessageCollector {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    mc.note_finalized_frame(settlement_window(EPOCH).0);
    mc
}

/// Fill the provers' share with this node's settlements of `len` bytes,
/// ids from `first` on: those held, and the first refused.
pub(super) fn fill(mc: &MessageCollector, first: u32, len: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut held = Vec::new();
    for id in first..first + 100 {
        let proof = settlement(id, len);
        match mc.add_message_outcome(1, proof.clone()) {
            SubmitOutcome::Accepted => held.push(proof),
            SubmitOutcome::Filtered(_) => return (held, proof),
            other => panic!("settlement {id}: {other:?}"),
        }
    }
    panic!("100 settlements did not fill the share");
}

/// The reason `outcome` gives its sender, or what it was.
fn reason(outcome: SubmitOutcome) -> String {
    match outcome {
        SubmitOutcome::Filtered(refusal) => refusal.reason().to_string(),
        other => format!("not refused: {other:?}"),
    }
}

/// A refusal for a full share names the share, and keeps the text senders
/// of every release match to resend it.
#[test]
fn a_share_refusal_names_its_share() {
    let mc = archive();
    let (_, refused) = fill(&mc, 1, 1_000_000);
    let provers = reason(mc.add_message_outcome(1, refused));
    eprintln!("REACH share-name provers reason={provers:?}");
    assert!(
        provers.contains("rank buffer full")
            && provers.contains("active provers' storage epoch proof share"),
        "SHARE-NAME: the provers' share refused a proof as {provers:?}"
    );

    let mc = archive();
    let by =
        |id: u32| mc.add_message_outcome_by(1, settlement(id, 650_000), Provenance::Prover, b"a");
    let sender = (1..=10u32)
        .map(by)
        .find(|outcome| *outcome != SubmitOutcome::Accepted)
        .map(reason)
        .unwrap_or_default();
    eprintln!("REACH share-name sender reason={sender:?}");
    assert!(
        sender.contains("rank buffer full")
            && sender.contains("this sender's storage epoch proof share"),
        "SHARE-NAME: one sender's share refused a proof as {sender:?}"
    );
}

/// A 4 MB proof due with about 1 MB ones that fill the share is held once
/// the frames free its room, though a new 1 MB proof arrives each time one
/// rides: the refused proof gets the room freed, not the next to arrive.
#[test]
fn a_large_proof_gets_the_room_frames_free_before_smaller_ones() {
    let mc = archive();
    let (mut held, refused) = fill(&mc, 1, 1_000_000);
    assert!(
        held.len() >= 12
            && held.iter().map(Vec::len).sum::<usize>() + refused.len() > SEAL_BYTES_HELD,
        "premise: about 1 MB settlements fill the provers' share"
    );
    let large = settlement(1000, 4_000_000);
    assert!(
        matches!(
            mc.add_message_outcome(1, large.clone()),
            SubmitOutcome::Filtered(_)
        ),
        "premise: the share has no room for the large proof"
    );
    let mut next = 2000u32;
    let mut admitted = None;
    for round in 1..=20u32 {
        // A frame carries the oldest held proof, and a new one arrives.
        let carried = held.remove(0);
        mc.mark_finalized(std::slice::from_ref(&carried));
        next += 1;
        let small = settlement(next, 1_000_000);
        if mc.add_message_outcome(1, small.clone()) == SubmitOutcome::Accepted {
            held.push(small);
        }
        // Its sender sends the large one again.
        match mc.add_message_outcome(1, large.clone()) {
            SubmitOutcome::Accepted => {
                admitted = Some(round);
                break;
            }
            SubmitOutcome::Filtered(_) => {}
            other => panic!("round {round}: {other:?}"),
        }
    }
    eprintln!("REACH seal-starve admitted={admitted:?}");
    assert!(
        admitted.is_some_and(|round| round <= 8),
        "SEAL-STARVE: the 4 MB proof was held at round {admitted:?} of 20; 1 MB proofs took each freed megabyte"
    );
}

/// Held proofs passed over by [`PASSES`] of this node's proposals yield
/// their room to a proof due with them; one proposal fewer keeps them.
#[test]
fn proofs_passed_over_yield_to_a_proof_due_with_them() {
    let mc = archive();
    let (held, _) = fill(&mc, 1, 650_000);
    let start = settlement_window(EPOCH).0 + 1;
    let pass = |frame: u64| {
        // A proposal with no room left passes over every held proof.
        let taken = mc.snapshot_for_proposal(1, 0, 0, Some(frame), &[]).unwrap();
        assert!(taken.is_empty(), "premise: the proposal carried nothing");
    };
    for frame in start..start + PASSES - 1 {
        pass(frame);
    }
    let early = mc.add_message_outcome(1, settlement(500, 650_000));
    eprintln!("REACH seal-yield early outcome={early:?}");
    assert!(
        matches!(early, SubmitOutcome::Filtered(_)),
        "SEAL-YIELD-EDGE: proofs passed over {} times yielded: {early:?}",
        PASSES - 1
    );
    pass(start + PASSES - 1);
    let outcome = mc.add_message_outcome(1, settlement(501, 650_000));
    eprintln!("REACH seal-yield outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "SEAL-YIELD: proofs passed over by {PASSES} proposals kept their room from a proof due with them"
    );
    assert_eq!(
        mc.pending_count(1),
        held.len(),
        "one held proof yielded its room"
    );
}
