//! Fee vote fence ([`crate::global_intrinsic::handoff::fee_fence`]): the
//! sessions a frame voting out of bounds fences, the committee their
//! successor takes, and the sessions it leaves to their own change.

use super::*;

/// Shard `filter`'s first session, seating `keys`, with GLOBAL having
/// executed its frames through 4, committed at GLOBAL frame 2.
fn executed_through_4(
    db: &quil_store::RocksDb,
    filter: &[u8],
    keys: &[FalconPrivateKey],
) -> (HypergraphState, Session) {
    let (_, state) = make_state(db);
    let session = initial(filter.to_vec(), keys);
    initialize(&state, 1, &session).unwrap();
    record_session_tip(&state, 2, &session.id().unwrap(), &tip(4, 9, [0x55; 32])).unwrap();
    commit(&state, 2);
    (state, session)
}

/// The fence refused with `needle` in its reason and wrote nothing: the
/// session is still its shard's head, unfenced.
fn assert_refused(state: &HypergraphState, session: &Session, refused: Result<u64>, needle: &str) {
    let changes = state.changeset_len();
    let reason = refused
        .expect_err("a fee vote fence the session's own change must decide")
        .to_string();
    assert!(reason.contains(needle), "{reason}");
    assert_eq!(
        state.changeset_len(),
        changes,
        "a refused fence writes nothing"
    );
    let id = session.id().unwrap();
    assert!(!is_fenced(state, &id).unwrap());
    assert_eq!(
        head(state, &session.filter).unwrap().as_ref(),
        Some(session)
    );
}

/// A session closing for a membership change is fenced like an active one,
/// at its executed tip, and its successor takes the committee the pending
/// request names, not the closing session's.
#[test]
fn a_fee_vote_fence_of_a_session_closing_for_its_membership_takes_the_pending_committee() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (keys, next) = (keys(), keys());
    let filter = vec![0x51; 32];
    let (state, session) = executed_through_4(&db, &filter, &keys);
    let id = session.id().unwrap();
    let request = schedule(
        &state,
        3,
        vec![filter.clone()],
        vec![desired(&filter, &next)],
    )
    .unwrap();
    commit(&state, 3);
    assert_eq!(
        status(&state, &id).unwrap(),
        Status::Sealing(request.id().unwrap())
    );
    assert_eq!(
        fee_fence::check(&state, &id, &filter, 5).unwrap(),
        members(&next),
        "the pending committee"
    );
    assert_eq!(
        fee_fence::fence(&state, 6, &id, &filter, 5, 0, 3).unwrap(),
        4
    );
    commit(&state, 6);
    assert!(is_fenced(&state, &id).unwrap());
    assert_eq!(closed_checkpoint(&state, &id).unwrap().unwrap().frame, 4);
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!(
        (successor.generation, successor.base_frame),
        (2, 4),
        "authorized from the executed tip"
    );
    assert_eq!(successor.members, members(&next));
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
}

/// A session closing for a split or merge is not fenced: its header is
/// refused, and the change's own timeout fences it.
#[test]
fn a_fee_vote_fence_refuses_a_session_closing_for_a_split_or_merge() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let keys = keys();
    let filter = vec![0x52; 32];
    let (state, session) = executed_through_4(&db, &filter, &keys);
    let children: Vec<_> = [false, true]
        .iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&filter, &[*bit]))
        .collect();
    let split = schedule(
        &state,
        3,
        vec![filter.clone()],
        children.iter().map(|f| desired(f, &keys)).collect(),
    )
    .unwrap();
    commit(&state, 3);
    let id = session.id().unwrap();
    assert_eq!(
        status(&state, &id).unwrap(),
        Status::Sealing(split.id().unwrap())
    );
    let refused = fee_fence::fence(&state, 4, &id, &filter, 5, 0, 3);
    assert_refused(&state, &session, refused, "closing for a split or merge");
    assert!(!schedule::activated(&state, &split.id().unwrap()).unwrap());
}

/// An active session whose shard a pending split or merge reserves as a
/// target is not fenced: a successor would make that change's activation
/// fail for good.
#[test]
fn a_fee_vote_fence_refuses_a_shard_a_pending_change_reserves() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let keys = keys();
    let filter = vec![0x53; 32];
    let (state, session) = executed_through_4(&db, &filter, &keys);
    schedule::reserve(&state, 3, &[desired(&filter, &keys)], &[0x99; 32]).unwrap();
    commit(&state, 3);
    let id = session.id().unwrap();
    assert_eq!(status(&state, &id).unwrap(), Status::Active);
    let refused = fee_fence::fence(&state, 4, &id, &filter, 5, 0, 3);
    assert_refused(&state, &session, refused, "reserved");
}

/// Only the head session, above its executed tip, and only once: a frame at
/// or below the tip, a session no longer the head (the fenced one, once its
/// successor is authorized) and a session that is not the shard's are all
/// refused.
#[test]
fn a_fee_vote_fence_refuses_a_frame_at_the_tip_and_a_session_no_longer_the_head() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let keys = keys();
    let filter = vec![0x54; 32];
    let (state, session) = executed_through_4(&db, &filter, &keys);
    let id = session.id().unwrap();
    for frame in [3, 4] {
        let refused = fee_fence::fence(&state, 3, &id, &filter, frame, 0, 3);
        assert_refused(&state, &session, refused, "at or above");
    }
    let refused = fee_fence::fence(&state, 3, &[0x77; 32], &filter, 5, 0, 3);
    assert_refused(&state, &session, refused, "not its shard's head");
    assert_eq!(
        fee_fence::fence(&state, 3, &id, &filter, 5, 0, 3).unwrap(),
        4
    );
    commit(&state, 3);
    assert_eq!(head(&state, &filter).unwrap().unwrap().generation, 2);
    let again = fee_fence::check(&state, &id, &filter, 6)
        .expect_err("a fenced session fenced again")
        .to_string();
    assert!(again.contains("not its shard's head"), "{again}");
}
