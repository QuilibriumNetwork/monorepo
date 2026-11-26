//! What a full share means, decided once per [`Share`] variant: whether a
//! storage epoch proof refused over it waits for room ([`Share::waits`]),
//! the reason an oversize proof's line gives, and the level of the
//! collector's line refusing submits over class shares
//! ([`Share::expected`]). Each variant is named explicitly, so a new one
//! cannot fall into another's meaning unseen.

use super::seal_starvation_tests::{archive, settlement};
use super::seal_wait_sender_tests::largest;
use super::*;

/// The reason an oversize proof refused over `share` gives.
fn oversize_reason(share: Share) -> &'static str {
    let message = CollectedMessage::new(settlement(1, 1_000));
    SenderSeals::default().oversize_refusal(&message, share)
}

/// The level of the collector's line for one refusal over `share`, from a
/// fresh collector.
fn line_level(share: Share) -> String {
    #[derive(Clone, Default)]
    struct Lines(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let lines = Lines::default();
    let writer = lines.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let mc = MessageCollector::new();
    let state = ShareFullState {
        rank: 1,
        share,
        unreserved: (0, 0),
        capacity: (0, 0),
        seals: Seals::default(),
        member: None,
        sender: None,
    };
    tracing::subscriber::with_default(subscriber, || {
        mc.note_share_full(Instant::now(), state, || ShareFullDetail {
            seat: String::new(),
            refused_held: (0, 0),
        });
    });
    let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
    let found: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("refusing submits over their class share"))
        .collect();
    assert_eq!(found.len(), 1, "premise: one collector line: {text:?}");
    let level = found[0].split_whitespace().next().unwrap_or_default();
    eprintln!("REACH share-meaning share={share:?} level={level}");
    level.to_owned()
}

/// A proof refused over the active provers' share waits for its room.
#[test]
fn a_full_seals_share_keeps_its_proof_waiting() {
    assert!(
        Share::Seals.waits(),
        "SHARE-WAITS-SEALS: a proof refused over the active provers' share does not wait"
    );
    assert_eq!(
        oversize_reason(Share::Seals),
        "the active provers' share is full"
    );
}

/// A proof refused over other senders' share keeps no room: that share
/// holds no proof that may wait ([`CollectedMessage::may_wait`]), so
/// a proof due with it is held in the room left.
#[test]
fn a_full_other_seals_share_keeps_no_proof_waiting() {
    let mc = archive();
    assert_eq!(
        mc.add_message_outcome_by(1, settlement(1, 1_000_000), Provenance::Other, b"o"),
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
    let waiting = mc.seal_waiting.lock().unwrap().waiting();
    let outcome = mc.add_message_outcome_by(1, settlement(3, 1_000_000), Provenance::Other, b"g");
    eprintln!("REACH share-meaning other-seals waiting={waiting:?} outcome={outcome:?}");
    assert_eq!(
        (waiting, outcome),
        (None, SubmitOutcome::Accepted),
        "SHARE-WAITS-OTHER-SEALS: a proof refused over other senders' share kept room"
    );
    assert!(
        !Share::OtherSeals.waits(),
        "SHARE-WAITS-OTHER-SEALS: a proof refused over other senders' share waits"
    );
    assert_eq!(
        oversize_reason(Share::OtherSeals),
        "other senders' share is full"
    );
}

/// A proof refused over its sender's share keeps no room in the share it
/// would be held in: only its sender's own proofs going frees that share.
#[test]
fn a_full_sender_share_keeps_no_proof_waiting() {
    let mc = archive();
    let peer = b"s";
    let first = settlement(1, 1_000_000);
    assert_eq!(
        mc.add_message_outcome_by(1, first, Provenance::Other, peer),
        SubmitOutcome::Accepted,
        "premise: the sender's first proof is held"
    );
    let second = settlement(2, 1_500_000);
    for _ in 0..2 {
        assert_eq!(
            mc.add_message_outcome_by(1, second.clone(), Provenance::Other, peer),
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::Sender)),
            "premise: the sender's share refuses its second proof"
        );
    }
    let waiting = mc.seal_waiting.lock().unwrap().waiting();
    eprintln!("REACH share-meaning sender waiting={waiting:?}");
    assert_eq!(
        waiting, None,
        "SHARE-WAITS-SENDER: a proof refused over its sender's share keeps room"
    );
    assert!(
        !Share::Sender.waits(),
        "SHARE-WAITS-SENDER: a proof refused over its sender's share waits"
    );
}

/// The room outside the reserve holds no storage epoch proof to wait.
#[test]
fn a_full_unreserved_share_keeps_no_proof_waiting() {
    assert!(
        !Share::Unreserved.waits(),
        "SHARE-WAITS-UNRESERVED: a refusal over the room outside the reserve waits"
    );
    assert_eq!(
        oversize_reason(Share::Unreserved),
        "its rank's share is full",
        "SHARE-OVERSIZE-UNRESERVED"
    );
}

/// The capacity messages' share holds no storage epoch proof to wait.
#[test]
fn a_full_capacity_share_keeps_no_proof_waiting() {
    assert!(
        !Share::Capacity.waits(),
        "SHARE-WAITS-CAPACITY: a refusal over the capacity messages' share waits"
    );
    assert_eq!(
        oversize_reason(Share::Capacity),
        "its rank's share is full",
        "SHARE-OVERSIZE-CAPACITY"
    );
}

/// One member's share holds no storage epoch proof to wait.
#[test]
fn a_full_member_share_keeps_no_proof_waiting() {
    assert!(
        !Share::Member.waits(),
        "SHARE-WAITS-MEMBER: a refusal over one member's share waits"
    );
    assert_eq!(
        oversize_reason(Share::Member),
        "its rank's share is full",
        "SHARE-OVERSIZE-MEMBER"
    );
}

/// Storage epoch proofs fill the active provers' share in each wave: the
/// collector's line logs at info.
#[test]
fn the_collector_line_for_a_full_seals_share_is_info() {
    assert_eq!(line_level(Share::Seals), "INFO", "LINE-LEVEL-SEALS");
}

/// Storage epoch proofs fill other senders' share in each wave: the
/// collector's line logs at info.
#[test]
fn the_collector_line_for_a_full_other_seals_share_is_info() {
    assert_eq!(
        line_level(Share::OtherSeals),
        "INFO",
        "LINE-LEVEL-OTHER-SEALS"
    );
}

/// A sender resending storage epoch proofs fills its own share: the
/// collector's line logs at info.
#[test]
fn the_collector_line_for_a_full_sender_share_is_info() {
    assert_eq!(line_level(Share::Sender), "INFO", "LINE-LEVEL-SENDER");
}

/// The room outside the reserve filling is a duty failing: the
/// collector's line warns.
#[test]
fn the_collector_line_for_a_full_unreserved_share_warns() {
    assert_eq!(
        line_level(Share::Unreserved),
        "WARN",
        "LINE-LEVEL-UNRESERVED"
    );
}

/// Capacity messages over their share are a duty failing: the collector's
/// line warns.
#[test]
fn the_collector_line_for_a_full_capacity_share_warns() {
    assert_eq!(line_level(Share::Capacity), "WARN", "LINE-LEVEL-CAPACITY");
}

/// Capacity messages over one member's share are a duty failing: the
/// collector's line warns.
#[test]
fn the_collector_line_for_a_full_member_share_warns() {
    assert_eq!(line_level(Share::Member), "WARN", "LINE-LEVEL-MEMBER");
}
