//! Whose storage epoch proof keeps room in a full share, or makes a held
//! proof yield its room: this node's own, or one its member delivers as an
//! active prover. Any other sender's proof is held or refused as the room
//! left allows. A wait keeps room only for a proof due within an epoch, and
//! ends once this node's proposals passed over it as many times as a held
//! proof yields after; that proof waits no more before its window ends.

use super::seal_starvation_tests::{archive, fill, settlement};
use super::*;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    CommittedFrame, SeatProof, StorageEpochProof, MAX_PROOF_LEN, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::global_intrinsic::storage_seat::settlement_window;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// The epoch the archive's settlements settle (`seal_starvation_tests`).
const EPOCH: u64 = 1478;

const LARGE: usize = 4_000_000;
const SMALL: usize = 1_000_000;

/// This node's proposals that pass over a waiting proof before its wait
/// ends (`SEAL_PASSES_TO_YIELD`).
const PASSES: u64 = 12;

/// The member settlement `id` names.
fn member(id: u32) -> [u8; 32] {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    member
}

/// Member `id`'s settlement of one seat of `epoch`, with `len` proof bytes
/// and `frames` committed frames.
fn settlement_of(id: u32, epoch: u64, len: usize, frames: usize) -> Vec<u8> {
    let frame = |n: usize| CommittedFrame {
        frame_number: n as u64,
        rho_n: [0; 32],
        root: [0; 32],
    };
    let proof = StorageEpochProof {
        member: member(id),
        seats: vec![SeatProof {
            shard_filter: member(id).to_vec(),
            epoch,
            settles: true,
            frames: (0..frames).map(frame).collect(),
            ..Default::default()
        }],
        proof: vec![id as u8; len],
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

/// Member `id`'s settlement of [`EPOCH`] as large as a proposal's seal
/// share, the largest proof an archive holds, and one it reads.
pub(super) fn largest(id: u32) -> Vec<u8> {
    let with = |frames| settlement_of(id, EPOCH, MAX_PROOF_LEN as usize, frames);
    let base = with(0).len();
    let frame = with(1).len() - base;
    let proof = with((SEAL_BYTES_PER_PROPOSAL - base) / frame);
    assert!(
        proof.len() <= SEAL_BYTES_PER_PROPOSAL && proof.len() + frame > SEAL_BYTES_PER_PROPOSAL,
        "premise: a proof of a proposal's seal share, {} bytes",
        proof.len()
    );
    assert_eq!(
        storage_kinds(&proof).window_end,
        Some(settlement_window(EPOCH).1),
        "premise: the archive reads the proof's window"
    );
    proof
}

/// The waiting proof, as (bytes, keeping room).
fn waiting(mc: &MessageCollector) -> Option<(usize, bool)> {
    let waiting = mc.seal_waiting.lock().unwrap().waiting();
    waiting.map(|(len, _, active)| (len, active))
}

/// The provers' share full of this node's 1 MB proofs, its 4 MB one
/// refused twice: it waits. Returns the held proofs and the large one.
fn large_waits(mc: &MessageCollector) -> (Vec<Vec<u8>>, Vec<u8>) {
    let (held, _) = fill(mc, 1, SMALL);
    let large = settlement(1000, LARGE);
    for _ in 0..2 {
        assert!(
            matches!(
                mc.add_message_outcome(1, large.clone()),
                SubmitOutcome::Filtered(_)
            ),
            "premise: the provers' share refuses the large proof"
        );
    }
    assert_eq!(
        waiting(mc),
        Some((large.len(), true)),
        "premise: the large proof waits"
    );
    (held, large)
}

/// The provers' share filled with this node's 1 MB proofs, short of a
/// refusal, so no proof waits yet. Returns the held proofs.
fn fill_quietly(mc: &MessageCollector) -> Vec<Vec<u8>> {
    let held: Vec<_> = (1..=14).map(|id| settlement(id, SMALL)).collect();
    for proof in &held {
        assert_eq!(
            mc.add_message_outcome(1, proof.clone()),
            SubmitOutcome::Accepted,
            "premise: the provers' share holds fourteen 1 MB proofs"
        );
    }
    assert_eq!(waiting(mc), None, "premise: no proof waits");
    held
}

/// A proposal of this node for `frame` that carries nothing.
fn pass(mc: &MessageCollector, frame: u64) {
    let taken = mc.snapshot_for_proposal(1, 0, 0, Some(frame), &[]).unwrap();
    assert!(taken.is_empty(), "premise: the proposal carried nothing");
}

/// A proof other senders send, sent twice while their share is full, keeps
/// no room there: one due with it is held in the room left.
#[test]
fn other_senders_proofs_keep_no_room_for_themselves() {
    let mc = archive();
    assert_eq!(
        mc.add_message_outcome_by(1, settlement(1, SMALL), Provenance::Other, b"o"),
        SubmitOutcome::Accepted,
        "premise: another sender's proof is held"
    );
    let big = largest(2);
    for _ in 0..2 {
        assert_eq!(
            mc.add_message_outcome_by(1, big.clone(), Provenance::Other, b"f"),
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::OtherSeals)),
            "premise: other senders' share refuses the large proof"
        );
    }
    let outcome = mc.add_message_outcome_by(1, settlement(3, SMALL), Provenance::Other, b"g");
    let waits = waiting(&mc);
    eprintln!("REACH seal-wait-sender other outcome={outcome:?} waiting={waits:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "SEAL-SENDER-OTHER: a proof other senders sent kept room from one due with it (waiting {waits:?})"
    );
}

/// An active prover's proof of another member, sent twice, does not take
/// the wait of this node's proof due with it: the room frames free stays
/// kept for this node's proof.
#[test]
fn a_proof_its_member_did_not_send_supersedes_no_waiting_proof() {
    let mc = archive();
    let (held, large) = large_waits(&mc);
    let big = largest(2000);
    for _ in 0..2 {
        assert_eq!(
            mc.add_message_outcome_by(1, big.clone(), Provenance::Prover, b"x"),
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals)),
            "premise: the provers' share refuses the other member's proof"
        );
    }
    mc.mark_finalized(&held[..4]);
    let small = mc.add_message_outcome(1, settlement(2001, SMALL));
    let outcome = mc.add_message_outcome(1, large.clone());
    let waits = waiting(&mc);
    eprintln!(
        "REACH seal-wait-sender supersede small={small:?} outcome={outcome:?} waiting={waits:?}"
    );
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "SEAL-SENDER-SUPERSEDE: a proof its member did not send took the 4 MB proof's wait (waiting {waits:?}, a 1 MB proof {small:?})"
    );
}

/// Held proofs passed over by twelve of this node's proposals yield their
/// room to a proof due with them its member sends as an active prover, not
/// to one another active prover sends.
#[test]
fn a_proof_its_member_did_not_send_makes_no_held_proof_yield() {
    let mc = archive();
    mc.set_sender_member(|peer| (peer == b"m").then(|| member(601)));
    let (held, _) = fill(&mc, 1, 650_000);
    let start = settlement_window(EPOCH).0 + 1;
    for frame in start..start + PASSES {
        pass(&mc, frame);
    }
    let outcome = mc.add_message_outcome_by(1, settlement(600, 650_000), Provenance::Prover, b"x");
    eprintln!("REACH seal-wait-sender yield other outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals)),
        "SEAL-SENDER-YIELD: a proof its member did not send made a held proof yield"
    );
    assert_eq!(mc.pending_count(1), held.len(), "no held proof yielded");
    let own = mc.add_message_outcome_by(1, settlement(601, 650_000), Provenance::Prover, b"m");
    eprintln!("REACH seal-wait-sender yield own outcome={own:?}");
    assert_eq!(
        own,
        SubmitOutcome::Accepted,
        "SEAL-MEMBER-YIELD: a proof its member sent as an active prover made no held proof yield"
    );
}

/// A proof its member sends as an active prover waits as this node's own
/// does; another active prover's copy of it does not refresh that wait.
#[test]
fn a_proof_its_member_sends_as_an_active_prover_waits() {
    let mc = archive();
    mc.set_sender_member(|peer| (peer == b"m").then(|| member(1000)));
    let held = fill_quietly(&mc);
    let large = settlement(1000, LARGE);
    let by = |peer: &[u8]| mc.add_message_outcome_by(1, large.clone(), Provenance::Prover, peer);
    assert!(
        matches!(by(b"x"), SubmitOutcome::Filtered(_)),
        "premise: the provers' share refuses another active prover's copy"
    );
    let first = waiting(&mc);
    eprintln!("REACH seal-wait-sender member first={first:?}");
    assert_eq!(
        first, None,
        "SEAL-MEMBER-WAITS: a copy another active prover sent started a wait"
    );
    assert!(
        matches!(by(b"m"), SubmitOutcome::Filtered(_)),
        "premise: the provers' share refuses the member's proof"
    );
    assert!(
        matches!(by(b"x"), SubmitOutcome::Filtered(_)),
        "premise: the provers' share refuses another active prover's copy"
    );
    let relayed = waiting(&mc);
    assert!(
        matches!(by(b"m"), SubmitOutcome::Filtered(_)),
        "premise: the provers' share refuses the member's proof again"
    );
    let waits = waiting(&mc);
    eprintln!("REACH seal-wait-sender member relayed={relayed:?} waiting={waits:?}");
    assert_eq!(
        (relayed, waits),
        (Some((large.len(), false)), Some((large.len(), true))),
        "SEAL-MEMBER-WAITS: the member's proof sent twice did not wait, or a copy another prover sent counted"
    );
    mc.mark_finalized(&held[..4]);
    assert!(
        matches!(
            mc.add_message_outcome(1, settlement(2001, SMALL)),
            SubmitOutcome::Filtered(_)
        ),
        "SEAL-MEMBER-WAITS: a proof due with the member's took its room"
    );
}

/// A proof whose window ends more than an epoch past the next frame keeps
/// no room, however often it is sent.
#[test]
fn a_proof_due_over_an_epoch_away_keeps_no_room() {
    let mc = archive();
    let _ = fill_quietly(&mc);
    let frame = settlement_window(EPOCH).0;
    let far = settlement_of(1000, EPOCH + 1, LARGE, 0);
    let end = settlement_window(EPOCH + 1).1;
    assert!(
        end - frame > quil_types::consensus::epoch_length_frames(),
        "premise: the proof is due over an epoch past the next frame"
    );
    for _ in 0..2 {
        assert_eq!(
            mc.add_message_outcome(1, far.clone()),
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals)),
            "premise: the provers' share refuses the proof"
        );
    }
    let waits = waiting(&mc);
    eprintln!("REACH seal-wait-sender far waiting={waits:?}");
    assert_eq!(
        waits,
        None,
        "SEAL-REACH: a proof due {} frames on kept room",
        end - frame
    );
}

/// A waiting proof stops keeping room once twelve of this node's
/// proposals, each of its own frame, passed over it while it was not held,
/// though it is sent again between them; eleven keep it waiting.
#[test]
fn a_wait_ends_once_this_nodes_proposals_pass_over_it() {
    let mc = archive();
    let (_, large) = large_waits(&mc);
    let start = settlement_window(EPOCH).0 + 1;
    for frame in start..start + PASSES - 1 {
        pass(&mc, frame);
        pass(&mc, frame);
        assert!(
            matches!(
                mc.add_message_outcome(1, large.clone()),
                SubmitOutcome::Filtered(_)
            ),
            "premise: the provers' share refuses the large proof"
        );
    }
    let early = waiting(&mc);
    eprintln!("REACH seal-wait-sender passes early={early:?}");
    assert_eq!(
        early,
        Some((large.len(), true)),
        "SEAL-WAIT-PASSES-EDGE: a wait ended after {} proposals passed over it",
        PASSES - 1
    );
    pass(&mc, start + PASSES - 1);
    let waits = waiting(&mc);
    eprintln!("REACH seal-wait-sender passes waiting={waits:?}");
    assert_eq!(
        waits, None,
        "SEAL-WAIT-PASSES: a wait outlived {PASSES} proposals passing over it"
    );
}

/// A proof whose wait this node's proposals ended by passing over it does
/// not wait again when its sender sends it twice more before its window
/// ends, into a share refilled with proofs no proposal passed over: it is
/// refused as the room left allows, and leaves the proof refused once there
/// as it was.
#[test]
fn a_proof_passed_over_waits_no_more_when_sent_again() {
    let mc = archive();
    let (held, large) = large_waits(&mc);
    let start = settlement_window(EPOCH).0 + 1;
    for frame in start..start + PASSES {
        pass(&mc, frame);
    }
    assert_eq!(waiting(&mc), None, "premise: the passes ended its wait");
    mc.mark_finalized(&held);
    let (refilled, refused) = fill(&mc, 100, SMALL);
    assert_eq!(
        refilled.len(),
        held.len(),
        "premise: the share is full again"
    );
    for _ in 0..2 {
        assert!(
            matches!(
                mc.add_message_outcome(1, large.clone()),
                SubmitOutcome::Filtered(_)
            ),
            "premise: the provers' share refuses the large proof"
        );
    }
    let waits = waiting(&mc);
    eprintln!("REACH seal-wait-sender passed-over waiting={waits:?}");
    assert_eq!(
        waits,
        Some((refused.len(), false)),
        "SEAL-PASSED-REARM: a passed-over proof sent twice more waited again"
    );
}
