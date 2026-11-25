//! A share's waiting proof stops keeping room however it comes to be held
//! or carried: an active prover's copy promoting another sender's, refused
//! first; a frame another archive led; a carried proposal's re-file. Until
//! 2026-11-25 only a plain submit's hold in its own share ended a wait, and
//! the others kept room for up to `SEAL_WAIT_STALE`, refusing proofs due
//! with it.

use super::seal_starvation_tests::{archive, fill, settlement};
use super::*;

const LARGE: usize = 4_000_000;
const SMALL: usize = 1_000_000;

/// The proof waiting in the `prover` share, as (bytes, keeping room).
fn waiting(mc: &MessageCollector, prover: bool) -> Option<(usize, bool)> {
    let waiting = mc.seal_waiting.lock().unwrap().waiting(prover);
    waiting.map(|(len, _, active)| (len, active))
}

/// The provers' share full of 1 MB proofs, a 4 MB one refused twice: it
/// waits. Returns the held proofs and the large one.
fn large_waits(mc: &MessageCollector) -> (Vec<Vec<u8>>, Vec<u8>) {
    let (held, _) = fill(mc, 1, SMALL);
    let large = settlement(1000, LARGE);
    for _ in 0..2 {
        assert!(
            matches!(
                mc.add_message_outcome(1, large.clone()),
                SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals))
            ),
            "premise: the provers' share refuses the large proof"
        );
    }
    assert_eq!(
        waiting(mc, true),
        Some((large.len(), true)),
        "premise: the large proof waits"
    );
    (held, large)
}

/// An active prover's copy refused for the provers' share while another
/// sender's copy is held waits as a plain submit's refusal does, and the
/// held copy does not end its wait.
#[test]
fn a_prover_copy_refused_beside_another_senders_waits() {
    let mc = archive();
    let (held, _) = fill(&mc, 1, SMALL);
    let large = settlement(1000, LARGE);
    let peer = b"another sender";
    assert_eq!(
        mc.add_message_outcome_by(1, large.clone(), Provenance::Other, peer),
        SubmitOutcome::Accepted,
        "premise: another sender's copy is held"
    );
    for _ in 0..2 {
        assert_eq!(
            mc.add_message_outcome(1, large.clone()),
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals)),
            "premise: the provers' share refuses the prover's copy"
        );
    }
    let waits = waiting(&mc, true);
    eprintln!("REACH seal-wait-end promote-refused waiting={waits:?}");
    assert_eq!(
        waits,
        Some((large.len(), true)),
        "SEAL-END-PROMOTE-REFUSED: a prover's copy refused twice keeps no room"
    );
    // A frame frees one proof's room: a proof due with the large one
    // leaves the large one's room free.
    mc.mark_finalized(&held[..1]);
    let outcome = mc.add_message_outcome(1, settlement(2000, SMALL));
    assert!(
        matches!(outcome, SubmitOutcome::Filtered(_)),
        "SEAL-END-PROMOTE-REFUSED: a proof due with the waiting one took its room: {outcome:?}"
    );
}

/// A waiting proof whose prover's copy promotes another sender's copy
/// stops keeping room.
#[test]
fn a_waiting_proof_promoted_from_another_senders_copy_frees_its_room() {
    let mc = archive();
    let (held, large) = large_waits(&mc);
    assert_eq!(
        mc.add_message_outcome_by(1, large.clone(), Provenance::Other, b"another sender"),
        SubmitOutcome::Accepted,
        "premise: another sender's copy is held"
    );
    assert_eq!(
        waiting(&mc, true),
        Some((large.len(), true)),
        "premise: another sender's copy leaves the prover's wait"
    );
    mc.mark_finalized(&held[..5]);
    assert_eq!(
        mc.add_message_outcome(1, large.clone()),
        SubmitOutcome::Duplicate,
        "premise: the prover's copy promotes the held one"
    );
    let outcome = mc.add_message_outcome(1, settlement(2000, SMALL));
    eprintln!("REACH seal-wait-end promoted outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "SEAL-END-PROMOTED: a promoted proof kept its room"
    );
    assert_eq!(waiting(&mc, true), None);
}

/// A waiting proof a frame carried, led by another archive, stops keeping
/// room.
#[test]
fn a_waiting_proof_a_frame_carried_frees_its_room() {
    let mc = archive();
    let (held, large) = large_waits(&mc);
    mc.mark_finalized(&held[..1]);
    assert!(
        matches!(
            mc.add_message_outcome(1, settlement(2000, SMALL)),
            SubmitOutcome::Filtered(_)
        ),
        "premise: a proof due with the waiting one leaves its room"
    );
    mc.mark_finalized(std::slice::from_ref(&large));
    let outcome = mc.add_message_outcome(1, settlement(2001, SMALL));
    eprintln!("REACH seal-wait-end carried outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "SEAL-END-CARRIED: a proof a frame carried kept its room"
    );
    assert_eq!(waiting(&mc, true), None);
}

/// A waiting proof a carried proposal re-files is held, and stops keeping
/// room on its share's next consult.
#[test]
fn a_waiting_proof_re_filed_by_a_carried_proposal_ends_its_wait() {
    let mc = archive();
    let (_, large) = large_waits(&mc);
    mc.carry_forward(2, std::slice::from_ref(&large));
    let hash = message_key(&large);
    assert!(
        mc.buffers
            .read()
            .unwrap()
            .values()
            .any(|b| b.contains(&hash)),
        "premise: the carried proof is held"
    );
    let _ = mc.add_message_outcome(1, settlement(2000, SMALL));
    let waits = waiting(&mc, true);
    eprintln!("REACH seal-wait-end re-filed waiting={waits:?}");
    assert!(
        waits.is_none_or(|(len, _)| len != large.len()),
        "SEAL-END-RE-FILED: a re-filed proof kept its wait: {waits:?}"
    );
}
