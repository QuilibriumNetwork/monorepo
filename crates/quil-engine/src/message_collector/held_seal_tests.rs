//! Held storage epoch proofs ride in turn: a proof a proposal passed over
//! rides the next one ahead of newer proofs due at the same frame, a proof
//! whose window ends within an epoch outlives the retention window, and
//! what is dropped or refused is counted once in bounded lines.

use super::seat_density_tests::{collector, peer, seat, send, settling, sized, EPOCH, LEN};
use super::*;
use crate::outage::test_logs::CapturedLogs;
use quil_execution::global_intrinsic::storage_epoch_proof::SeatProof;
use quil_execution::global_intrinsic::storage_seat::settlement_window;

/// The messages a proposal of `frame` at `rank` takes, within a GLOBAL
/// proposal's 12 MiB.
fn propose(mc: &MessageCollector, rank: u64, frame: u64) -> Vec<Vec<u8>> {
    propose_within(mc, rank, frame, 12 << 20)
}

/// As `propose`, within `max_bytes`.
fn propose_within(mc: &MessageCollector, rank: u64, frame: u64, max_bytes: usize) -> Vec<Vec<u8>> {
    mc.snapshot_for_proposal(rank, max_bytes, 10_000, Some(frame), &[])
        .unwrap()
        .into_iter()
        .map(|(data, _)| data)
        .collect()
}

/// Members' own first proofs from id `*next` on, until the share refuses
/// one.
fn fill_with_firsts(mc: &MessageCollector, next: &mut u32) {
    loop {
        let id = *next;
        *next += 1;
        if send(mc, id, &settling(id, 1)) != SubmitOutcome::Accepted {
            return;
        }
    }
}

/// The value of `name` in a log line, 0 if absent.
fn field(line: &str, name: &str) -> u64 {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .and_then(|value| value.trim_matches('"').parse().ok())
        .unwrap_or(0)
}

/// A share-full line's detail naming no seat and no refused proof.
fn no_detail() -> ShareFullDetail {
    ShareFullDetail {
        seat: String::new(),
        refused_held: (0, 0),
    }
}

/// `line` holds `name` with the text `value`.
fn has(line: &str, name: &str, value: &str) -> bool {
    line.split_whitespace()
        .filter_map(|part| part.strip_prefix(&format!("{name}=")))
        .any(|found| found.trim_matches('"') == value)
}

/// A proof no member delivered itself, passed over by a proposal while
/// members' own first proofs filled its storage proof budget, rides this
/// node's next proposal ahead of first proofs that arrived since: each
/// frame's room went to newer firsts, and it aged out though it was
/// accepted.
#[test]
fn a_proof_a_proposal_passed_over_rides_the_next_one() {
    let mc = collector();
    let start = settlement_window(EPOCH).0;
    let relayed = settling(101, 1);
    assert_eq!(send(&mc, 700, &relayed), SubmitOutcome::Accepted);
    let mut next = 1;
    fill_with_firsts(&mc, &mut next);
    let first = propose(&mc, 1, start + 1);
    assert!(
        !first.is_empty() && !first.contains(&relayed),
        "members' first proofs ride ahead of a relayed one in the first proposal"
    );
    // The frame finalizes; members' new first proofs fill the room it freed.
    mc.mark_finalized(&first);
    fill_with_firsts(&mc, &mut next);
    let second = propose(&mc, 1, start + 5);
    eprintln!(
        "REACH held-seal passed first={} second={} members={}",
        first.len(),
        second.len(),
        next - 1
    );
    assert!(
        second.contains(&relayed),
        "passed_over_rides: a proof the proposal of frame {} passed over waited behind {} newer first proofs in the next",
        start + 1,
        second.len()
    );
}

/// The ranks `1..=last` finalized at frames from `start` on.
fn finalize(mc: &MessageCollector, start: u64, last: u64) {
    for rank in 2..=last {
        mc.note_finalized_frame(start + rank);
        mc.prune_after_finalization(rank);
    }
}

/// A held proof whose window is open stays past `RETENTION_WINDOW`
/// finalized frames and rides the next proposal; one with no known window
/// still ages out.
#[test]
fn a_held_proof_with_an_open_window_outlives_the_retention_window() {
    let mc = collector();
    let start = settlement_window(EPOCH).0;
    let open = settling(1, 1);
    assert_eq!(send(&mc, 1, &open), SubmitOutcome::Accepted);
    let unknown = sized(2, Vec::new(), LEN);
    assert_eq!(send(&mc, 2, &unknown), SubmitOutcome::Accepted);
    let last = RETENTION_WINDOW + 3;
    finalize(&mc, start, last);
    let taken = propose(&mc, last + 1, start + last + 1);
    eprintln!(
        "REACH held-seal retention taken={} aged={}",
        taken.len(),
        mc.seals_aged_out()
    );
    assert!(
        taken.contains(&open),
        "retention_carry: a proof due after frame {} left after {} finalized frames",
        start + last,
        last - 1
    );
    assert!(
        !taken.contains(&unknown),
        "unknown_aged: a proof with no known window outlived the retention window"
    );
    assert_eq!(mc.seals_aged_out(), 1, "unknown_aged: aged-out count");
}

/// Proofs carried past the retention window keep their turn: the older
/// rides first.
#[test]
fn carried_proofs_keep_their_turn() {
    let mc = collector();
    let start = settlement_window(EPOCH).0;
    // One fits a proposal's bytes, two do not; both fit one sender's
    // share of held proofs (`SEAL_BYTES_PER_SENDER`).
    let len = 1_000_000;
    let older = sized(101, vec![seat(0, true, false)], len);
    let newer = sized(102, vec![seat(0, true, false)], len);
    let relay = peer(700);
    for (rank, proof) in [(1, &older), (2, &newer)] {
        assert_eq!(
            mc.add_message_outcome_by(rank, proof.clone(), Provenance::Prover, &relay),
            SubmitOutcome::Accepted
        );
    }
    let last = RETENTION_WINDOW + 3;
    finalize(&mc, start, last);
    let taken = propose_within(&mc, last + 1, start + last + 1, len * 3 / 2);
    eprintln!("REACH held-seal carried_order taken={}", taken.len());
    assert!(
        !taken.is_empty(),
        "retention_carry: both proofs aged out with their windows open"
    );
    assert!(
        taken.contains(&older) && !taken.contains(&newer),
        "carried_order: the frame took the newer of two carried proofs"
    );
}

/// A share full of held storage epoch proofs refuses and accepts in turn,
/// as each frame frees room the next submits fill: its lines count every
/// refusal once, by share, in at most one line per interval.
#[test]
fn share_full_lines_count_every_refusal_once() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mc = MessageCollector::new();
    let state = || ShareFullState {
        rank: 1,
        share: Share::Seals,
        unreserved: (0, 0),
        capacity: (0, 0),
        seals: Seals::default(),
        member: None,
        sender: None,
    };
    let t0 = Instant::now();
    let mut refused = 0u64;
    let stretches = [(0, 5, 7), (RANK_FULL_LOG_EVERY.as_secs() + 10, 3, 4)];
    for (at, turns, each) in stretches {
        for turn in 0..turns {
            let now = t0 + Duration::from_secs(at + turn * 5);
            for _ in 0..each {
                mc.note_share_full(now, state(), no_detail);
                refused += 1;
            }
            mc.note_share_accepting(now + Duration::from_secs(1), 1);
        }
    }
    mc.note_share_accepting(t0 + 4 * RANK_FULL_LOG_EVERY, 1);
    let refusing = logs.lines_with("refusing submits over their class share");
    let ended = logs.lines_with("refusals over class shares ended");
    let counted: u64 = refusing
        .iter()
        .chain(&ended)
        .map(|line| field(line, "seal_refused"))
        .sum();
    eprintln!(
        "REACH held-seal share_full refused={refused} counted={counted} lines={}+{}",
        refusing.len(),
        ended.len()
    );
    assert_eq!(
        counted, refused,
        "share_full_counts: the lines counted {counted} of {refused} refusals by share: {refusing:?} {ended:?}"
    );
    assert_eq!(
        refusing.len(),
        2,
        "share_full_bound: refusals over two intervals logged {refusing:?}"
    );
    assert_eq!(ended.len(), 1, "share_full_end: {ended:?}");
    assert_eq!(field(&ended[0], "refused_total"), refused, "{}", ended[0]);
}

/// A share-full line names the refused proof's share and first seat, and
/// the held proofs a GLOBAL proposal already refused that were sent again:
/// on mainnet about half of a median proposal's held proofs were ones
/// GLOBAL refuses, holding the seal share full (2026-11-19).
#[test]
fn a_share_full_line_names_the_seat_its_share_and_refused_held_bytes() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mc = collector();
    let refused = settling(1, 1);
    assert_eq!(send(&mc, 1, &refused), SubmitOutcome::Accepted);
    mc.remove_refused(std::slice::from_ref(&refused));
    assert_eq!(
        send(&mc, 1, &refused),
        SubmitOutcome::Accepted,
        "removed, its seat takes it again"
    );
    let mut next = 2;
    fill_with_firsts(&mc, &mut next);
    let last = next - 1;
    let lines = logs.lines_with("refusing submits over their class share");
    eprintln!("REACH share_full detail lines={}", lines.len());
    let [line] = lines.as_slice() else {
        panic!("share_full_line: one line expected, got {lines:?}");
    };
    let seat = format!(
        "{}/{}/{EPOCH}/settle",
        hex::encode(last.to_be_bytes()),
        "00000000"
    );
    assert!(
        has(line, "latest_share", "seals"),
        "share_full_share: {line}"
    );
    assert!(
        has(line, "latest_seat", &seat),
        "share_full_seat {seat}: {line}"
    );
    assert_eq!(
        (
            field(line, "refused_held_pending"),
            field(line, "refused_held_bytes")
        ),
        (1, refused.len() as u64),
        "share_full_refused_held: {line}"
    );
}

/// Proofs dropped without riding a frame are summarized in one line that
/// names, for one a proposal passed over, its rank, window end, how many
/// proposals left it and why; an active prover's proof lost so warns.
#[test]
fn a_dropped_proof_a_proposal_passed_over_is_named_in_the_summary() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mc = collector();
    let end = settlement_window(EPOCH).1;
    let relayed = settling(101, 1);
    assert_eq!(send(&mc, 700, &relayed), SubmitOutcome::Accepted);
    let mut next = 1;
    fill_with_firsts(&mc, &mut next);
    let taken = propose(&mc, 1, end - 3);
    assert!(!taken.contains(&relayed));
    // No frame carries them; the window ends with the next to finalize.
    mc.note_finalized_frame(end - 1);
    for rank in 2..=RETENTION_WINDOW + 2 {
        mc.prune_after_finalization(rank);
    }
    let lines = logs.lines_with("held storage epoch proofs dropped without riding a frame");
    eprintln!("REACH held-seal drop_line lines={}", lines.len());
    assert_eq!(lines.len(), 1, "drop_line: {lines:?}");
    let line = &lines[0];
    let held = u64::from(next - 2) + 1;
    let named = [
        has(line, "latest_drop", "closed"),
        has(line, "latest_skip", "seal_budget"),
        field(line, "latest_passed_by") == 1,
        field(line, "latest_first_passed") == end - 3,
        field(line, "latest_window_end") == end,
        field(line, "latest_rank") == 1,
        field(line, "closed") == held,
        field(line, "passed_over") == held - taken.len() as u64,
    ];
    assert!(
        named.iter().all(|ok| *ok),
        "drop_line_named: {named:?} in {line}"
    );
    assert!(line.contains("WARN"), "drop_line_warns: {line}");
}

/// Member 1's proof settling a seat of `EPOCH + 1`, held with the next
/// frame to finalize `past` frames before its window ends one epoch ahead,
/// through `prunes` finalized ranks: whether a proposal then takes it, and
/// how many held proofs aged out.
fn carried_with_lead(past: u64, prunes: u64) -> (bool, usize) {
    let mc = collector();
    let seat = SeatProof {
        shard_filter: vec![0; 32],
        epoch: EPOCH + 1,
        settles: true,
        ..Default::default()
    };
    let proof = sized(1, vec![seat], LEN);
    assert_eq!(send(&mc, 1, &proof), SubmitOutcome::Accepted);
    let end = settlement_window(EPOCH + 1).1;
    let frame = end - quil_types::consensus::epoch_length_frames() - past;
    mc.note_finalized_frame(frame - 1);
    for rank in 2..2 + prunes {
        mc.prune_after_finalization(rank);
    }
    let taken = propose(&mc, prunes + 2, settlement_window(EPOCH + 1).0);
    let aged = mc.seals_aged_out();
    eprintln!(
        "REACH held-seal lead past={past} prunes={prunes} taken={} aged={aged}",
        taken.len()
    );
    (taken.contains(&proof), aged)
}

/// A held proof whose window ends one epoch past the next frame to
/// finalize, the longest carried lead, is carried past the
/// retention window.
#[test]
fn a_held_proof_due_an_epoch_ahead_is_carried() {
    let (taken, aged) = carried_with_lead(0, RETENTION_WINDOW + 1);
    assert!(
        taken && aged == 0,
        "lead_carried: a proof due one epoch ahead was taken {taken}, aged out {aged}"
    );
}

/// A held proof whose window ends a frame beyond that lead ages out as
/// before, with its rank after `RETENTION_WINDOW` finalized frames.
#[test]
fn a_held_proof_due_beyond_an_epoch_ages_out_as_before() {
    let (held, before) = carried_with_lead(1, RETENTION_WINDOW);
    let (taken, aged) = carried_with_lead(1, RETENTION_WINDOW + 1);
    assert!(
        held && before == 0 && !taken && aged == 1,
        "lead_aged: a proof due beyond the lead was held {held} ({before} aged) within the retention window, then taken {taken} ({aged} aged)"
    );
}

/// After a restart, no frame known, a held proof with a known window ages
/// out with its rank as before.
#[test]
fn a_restarted_collector_ages_held_proofs_out_as_before() {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    mc.set_sender_member(|peer| {
        let id: [u8; 4] = peer.strip_prefix(&b"peer"[..])?.try_into().ok()?;
        let mut member = [0u8; 32];
        member[..4].copy_from_slice(&id);
        Some(member)
    });
    let proof = settling(1, 1);
    assert_eq!(
        mc.add_message_outcome_by(1, proof.clone(), Provenance::Prover, &peer(1)),
        SubmitOutcome::Accepted
    );
    for rank in 2..=RETENTION_WINDOW + 2 {
        mc.prune_after_finalization(rank);
    }
    let taken = propose(&mc, RETENTION_WINDOW + 3, settlement_window(EPOCH).0);
    let aged = mc.seals_aged_out();
    eprintln!("REACH held-seal restart taken={} aged={aged}", taken.len());
    assert!(
        !taken.contains(&proof) && aged == 1,
        "restart_aged: with no frame known, a proof with a known window stayed ({aged} aged)"
    );
}

/// Proofs carried from several ranks move to one, which holds no more than
/// a rank: the rest age out, counted.
#[test]
fn the_carried_rank_holds_no_more_than_a_rank() {
    let len = 1 << 20;
    let per_rank = 40u32;
    let mut buffers: HashMap<u64, RankBuffer> = HashMap::new();
    for rank in 1..=2u32 {
        let buffer = buffers
            .entry(u64::from(rank))
            .or_insert_with(RankBuffer::new);
        for i in 0..per_rank {
            let proof = sized(rank * 1_000 + i, vec![seat(0, true, false)], len);
            assert!(matches!(
                buffer.add(CollectedMessage::new(proof)),
                AddOutcome::Added
            ));
        }
    }
    let mut drops = SealDrops::default();
    age_ranks(
        &mut buffers,
        3,
        settlement_window(EPOCH).0 + 1,
        &mut drops,
        &mut Vec::new(),
    );
    let kept: usize = buffers.values().map(RankBuffer::len).sum();
    let fits = MAX_BYTES_PER_RANK / len;
    let aged = drops.aged.prover.0;
    eprintln!("REACH held-seal carried_cap kept={kept} aged={aged}");
    assert!(
        buffers.len() == 1 && kept == fits && aged == 2 * per_rank as usize - fits,
        "carried_cap: {} ranks kept {kept} proofs of {}, {aged} aged out",
        buffers.len(),
        2 * per_rank
    );
}

/// A carried proof past its window makes room in a full share for a proof
/// that can still ride.
#[test]
fn a_carried_proof_past_its_window_makes_room() {
    let mc = collector();
    let start = settlement_window(EPOCH).0;
    // As many as the held share takes: one more does not fit.
    let len = 2_500_000;
    let held = SEAL_BYTES_HELD / len;
    for id in 1..=held as u32 {
        let proof = sized(id, vec![seat(0, true, false)], len);
        assert_eq!(send(&mc, id, &proof), SubmitOutcome::Accepted);
    }
    let last = RETENTION_WINDOW + 3;
    finalize(&mc, start, last);
    let seat = SeatProof {
        shard_filter: vec![0; 32],
        epoch: EPOCH + 1,
        settles: true,
        ..Default::default()
    };
    // All carried with their window open: the share is full for a proof
    // due later.
    let early = sized(101, vec![seat.clone()], len);
    let full = mc.add_message_outcome_by(last + 1, early, Provenance::Prover, &peer(101));
    assert_ne!(
        full,
        SubmitOutcome::Accepted,
        "carried_full: the share took a proof due later beside {held} carried proofs due sooner"
    );
    // The frame of their window's end finalizes.
    mc.note_finalized_frame(settlement_window(EPOCH).1);
    let later = sized(100, vec![seat], len);
    let outcome = mc.add_message_outcome_by(last + 1, later, Provenance::Prover, &peer(100));
    eprintln!("REACH held-seal carried_evicted held={held} full={full:?} outcome={outcome:?}");
    assert_eq!(
        outcome,
        SubmitOutcome::Accepted,
        "carried_evicted: a full share kept carried proofs past their window"
    );
}

/// At an equal window end, a member's second proof a proposal passed over
/// rides the next one ahead of another member's only proof, though that
/// one carries more seats per byte.
#[test]
fn a_passed_over_second_rides_ahead_of_another_members_only_proof() {
    let mc = collector();
    let start = settlement_window(EPOCH).0;
    // One fits a proposal's bytes, two do not; both fit one sender's
    // share of held proofs (`SEAL_BYTES_PER_SENDER`).
    let len = 1_000_000;
    let first = sized(1, vec![seat(0, true, false)], len);
    let second = sized(1, vec![seat(1, true, false)], len);
    for proof in [&first, &second] {
        assert_eq!(send(&mc, 1, proof), SubmitOutcome::Accepted);
    }
    let taken = propose_within(&mc, 1, start + 1, len * 3 / 2);
    assert!(taken.contains(&first) && !taken.contains(&second));
    mc.mark_finalized(&taken);
    let only = sized(2, vec![seat(0, true, false), seat(1, true, false)], len);
    assert_eq!(send(&mc, 2, &only), SubmitOutcome::Accepted);
    let next = propose_within(&mc, 1, start + 5, len * 3 / 2);
    eprintln!("REACH held-seal passed_first taken={}", next.len());
    assert!(
        next.contains(&second) && !next.contains(&only),
        "passed_over_rides_first: the next proposal took another member's only proof ahead of a second passed over"
    );
}

/// An active prover's proof that reaches the end of its window held, with
/// no proposal of this node passing it over, warns.
#[test]
fn a_closed_active_provers_proof_warns() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mc = collector();
    assert_eq!(send(&mc, 1, &settling(1, 1)), SubmitOutcome::Accepted);
    mc.note_finalized_frame(settlement_window(EPOCH).1 - 1);
    for rank in 2..=RETENTION_WINDOW + 2 {
        mc.prune_after_finalization(rank);
    }
    let lines = logs.lines_with("held storage epoch proofs dropped without riding a frame");
    eprintln!("REACH held-seal closed_warns lines={}", lines.len());
    assert_eq!(lines.len(), 1, "closed_lines: {lines:?}");
    let line = &lines[0];
    assert!(
        field(line, "closed") == 1 && field(line, "passed_over") == 0,
        "closed_counts: {line}"
    );
    assert!(line.contains("WARN"), "closed_warns: {line}");
}

/// A refusal over a class share a whole interval after the last, with no
/// submit accepted in between, ends that episode and begins another.
#[test]
fn a_refusal_after_a_quiet_interval_begins_an_episode() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let mc = MessageCollector::new();
    let state = || ShareFullState {
        rank: 1,
        share: Share::Seals,
        unreserved: (0, 0),
        capacity: (0, 0),
        seals: Seals::default(),
        member: None,
        sender: None,
    };
    let t0 = Instant::now();
    for _ in 0..3 {
        mc.note_share_full(t0, state(), no_detail);
    }
    let later = t0 + RANK_FULL_LOG_EVERY + Duration::from_secs(5);
    for _ in 0..2 {
        mc.note_share_full(later, state(), no_detail);
    }
    mc.note_share_accepting(later + 2 * RANK_FULL_LOG_EVERY, 1);
    let refusing = logs.lines_with("refusing submits over their class share");
    let ended = logs.lines_with("refusals over class shares ended");
    eprintln!(
        "REACH held-seal quiet_episode lines={}+{}",
        refusing.len(),
        ended.len()
    );
    let totals: Vec<u64> = ended.iter().map(|l| field(l, "refused_total")).collect();
    assert_eq!(totals, [3, 2], "quiet_episode: {ended:?}");
    assert!(
        refusing.len() == 2 && field(&refusing[1], "for_secs") == 0,
        "quiet_episode_start: {refusing:?}"
    );
}

/// The refused keys a share-full line reads are bounded: past
/// [`REFUSED_KEYS_KEPT`] the oldest is forgotten first, a key noted again
/// takes no second place, and the set and its order name the same keys.
#[test]
fn refused_keys_forget_the_oldest_past_their_bound() {
    let key = |i: usize| -> [u8; 32] {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(i as u64).to_be_bytes());
        key
    };
    let mut refused = RefusedKeys::default();
    for i in 0..REFUSED_KEYS_KEPT {
        refused.note(key(i));
    }
    refused.note(key(0));
    assert_eq!(refused.order.len(), REFUSED_KEYS_KEPT, "a key noted again");
    refused.note(key(REFUSED_KEYS_KEPT));
    assert_eq!(
        (refused.keys.len(), refused.order.len()),
        (REFUSED_KEYS_KEPT, REFUSED_KEYS_KEPT),
        "REFUSED-BOUND: the refused keys outgrew their bound"
    );
    assert!(!refused.keys.contains(&key(0)), "the oldest is forgotten");
    assert!(refused.keys.contains(&key(1)) && refused.keys.contains(&key(REFUSED_KEYS_KEPT)));
    assert_eq!(refused.order.front(), Some(&key(1)));
    assert!(
        refused.order.iter().all(|key| refused.keys.contains(key)),
        "the set and its order name the same keys"
    );
}
