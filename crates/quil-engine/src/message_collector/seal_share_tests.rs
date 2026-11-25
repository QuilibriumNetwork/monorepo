//! A GLOBAL proposal's share of storage epoch proofs: 8 MiB beside the
//! shard proofs' floor of a third of 12 MiB, the room every other message
//! leaves past it, and an archive holding what two proposals carry of
//! active provers' proofs and one share of other senders'. Until
//! 2026-11-15 a proposal took 4 MiB of them and no more, and an epoch
//! boundary's settlements took 10-25 minutes to ride. The sizes are written
//! out, not read from the constants, so the tests also run on a build
//! without them.

use super::*;
use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
use quil_execution::global_intrinsic::storage_epoch_proof::{
    SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// About the size of a settlement proof on mainnet: thirteen fit 8 MiB.
const LEN: usize = 620_000;
/// The epoch whose seats the proofs below seal.
const EPOCH: u64 = 1478;
/// A GLOBAL proposal's message bytes and its storage epoch proofs' share.
const PROPOSAL: usize = 12 << 20;
const SHARE: usize = 8 << 20;
/// The largest finalized GLOBAL frame its proposer gossips
/// (`MAX_GOSSIP_GLOBAL_FRAME`); a larger one reaches regular nodes only
/// through the archive poller.
const GOSSIP: usize = 15 << 20;
/// The GLOBAL frame proposed, and the GLOBAL frame the shard headers anchor
/// to: the newest a proposal of `FRAME` may carry.
const FRAME: u64 = 100;
const ANCHOR: u64 = FRAME - 1;

fn bundle(inner_type_prefix: u32, inner_bytes: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix,
            inner_bytes,
        })],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Member `id`'s seal proof for one seat, of `LEN` proof bytes.
fn seal(id: u32) -> Vec<u8> {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    let mut proof = vec![0u8; LEN];
    proof[..4].copy_from_slice(&id.to_be_bytes());
    let proof = StorageEpochProof {
        member,
        seats: vec![SeatProof {
            shard_filter: member.to_vec(),
            epoch: EPOCH,
            seals: true,
            ..Default::default()
        }],
        proof,
    };
    bundle(TYPE_STORAGE_EPOCH_PROOF, proof.to_canonical_bytes())
}

/// A shard frame header (a shard proof) for shard `addr`, about 1 MiB.
fn header(addr: u8) -> Vec<u8> {
    sized_header(addr, 1 << 20)
}

/// A shard frame header for shard `addr` with `output` bytes of output.
fn sized_header(addr: u8, output: usize) -> Vec<u8> {
    let header = FrameHeader {
        address: vec![addr; 32],
        frame_number: 1,
        global_frame_number: ANCHOR,
        output: vec![addr; output],
        ..Default::default()
    };
    bundle(TYPE_FRAME_HEADER, header.to_canonical_bytes().unwrap())
}

/// How many of `seals` and of `headers` `taken` holds.
fn counted(taken: &[(Vec<u8>, bool)], seals: &[Vec<u8>], headers: &[Vec<u8>]) -> (usize, usize) {
    let count = |of: &[Vec<u8>]| {
        taken
            .iter()
            .filter(|(data, _)| of.iter().any(|m| m == data))
            .count()
    };
    (count(seals), count(headers))
}

/// A GLOBAL proposal carries 8 MiB of storage epoch proofs while shard
/// proofs would fill all of it, and the shard proofs still keep their floor
/// of a third (4 MiB of 12): thirteen proofs ride, and four headers.
#[test]
fn a_global_proposal_carries_eight_mib_of_storage_epoch_proofs_beside_shard_proofs() {
    let mc = MessageCollector::new();
    let seals: Vec<Vec<u8>> = (1..=13).map(seal).collect();
    let headers: Vec<Vec<u8>> = (1..=8).map(header).collect();
    assert!(seals.iter().map(Vec::len).sum::<usize>() <= SHARE);
    // The headers may ride the proposal: anchored outside its window, they
    // would leave the floor untested.
    assert!(anchor_in_lockstep(ANCHOR, FRAME));
    for message in seals.iter().chain(&headers) {
        assert!(mc.add_message(1, message.clone()));
    }
    let taken = mc
        .snapshot_for_proposal(1, PROPOSAL, 100_000, Some(FRAME), &[])
        .unwrap();
    let (seals_taken, headers_taken) = counted(&taken, &seals, &headers);
    eprintln!("REACH seal-share global seals={seals_taken} headers={headers_taken}");
    assert_eq!(
        seals_taken, 13,
        "seal-share global: the proposal carried {seals_taken} of 13 storage epoch proofs (8 MiB) beside shard proofs"
    );
    assert!(
        headers_taken >= 4,
        "seal-share floor: the proposal carried {headers_taken} shard headers of 1 MiB, under the shard floor of 4 MiB"
    );
}

/// The proposal line counts the storage epoch proofs a GLOBAL proposal
/// carries and their bytes (`pool_seals`, `pool_seal_bytes`), so archives
/// can be compared by what the frames they lead carry.
#[test]
fn a_global_proposal_counts_the_storage_epoch_proofs_it_carries() {
    let mc = MessageCollector::new();
    let seals: Vec<Vec<u8>> = (1..=3).map(seal).collect();
    for message in &seals {
        assert!(mc.add_message(1, message.clone()));
    }
    let taken = mc
        .snapshot_for_proposal(1, PROPOSAL, 100_000, Some(FRAME), &[])
        .unwrap();
    let pool = mc.take_proposal_pool().unwrap();
    eprintln!(
        "REACH seal-count taken={} seals={} bytes={}",
        taken.len(),
        pool.seals,
        pool.seal_bytes
    );
    let bytes: usize = seals.iter().map(Vec::len).sum();
    assert_eq!(taken.len(), 3, "premise: the proposal carried every proof");
    assert_eq!(
        (pool.seals, pool.seal_bytes),
        (3, bytes),
        "SEAL-COUNT: the proposal line's storage epoch proofs and bytes"
    );
}

/// Storage epoch proofs past their share ride in the room every other
/// message leaves, in the same proposal.
#[test]
fn storage_epoch_proofs_past_their_share_ride_in_the_room_left() {
    let mc = MessageCollector::new();
    let seals: Vec<Vec<u8>> = (1..=16).map(seal).collect();
    for message in &seals {
        assert!(mc.add_message(1, message.clone()));
    }
    assert!(mc.add_message(1, b"other".to_vec()));
    assert!(seals.iter().map(Vec::len).sum::<usize>() > SHARE);
    let taken = mc
        .snapshot_for_proposal(1, 16 << 20, 100_000, None, &[])
        .unwrap();
    let (seals_taken, _) = counted(&taken, &seals, &[]);
    eprintln!("REACH seal-share leftover seals={seals_taken}");
    assert!(taken.iter().any(|(data, _)| data == b"other"));
    assert_eq!(
        seals_taken, 16,
        "seal-share leftover: {seals_taken} of 16 storage epoch proofs rode a proposal with room for all"
    );
}

/// A storage epoch proof past its share waits behind shard proofs: they
/// take the room first, and the proofs within the share all ride.
#[test]
fn a_storage_epoch_proof_past_its_share_waits_behind_shard_proofs() {
    let mc = MessageCollector::new();
    let seals: Vec<Vec<u8>> = (1..=16).map(seal).collect();
    let headers: Vec<Vec<u8>> = (1..=2).map(header).collect();
    for message in seals.iter().chain(&headers) {
        assert!(mc.add_message(1, message.clone()));
    }
    let taken = mc
        .snapshot_for_proposal(1, 10 << 20, 100_000, None, &[])
        .unwrap();
    let (seals_taken, headers_taken) = counted(&taken, &seals, &headers);
    eprintln!("REACH seal-share behind seals={seals_taken} headers={headers_taken}");
    assert_eq!(
        (seals_taken, headers_taken),
        (13, 2),
        "seal-share behind: the proposal took {seals_taken} storage epoch proofs and {headers_taken} of 2 shard headers"
    );
}

/// A GLOBAL archive holds what two proposals of its own carry: 2 × (8 MiB
/// − 1 MiB) of active provers' storage epoch proofs, then refuses for room.
#[test]
fn an_archive_holds_two_proposals_share_of_storage_epoch_proofs() {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    let mut held = 0usize;
    for id in 1..=40u32 {
        let proof = seal(id);
        let len = proof.len();
        match mc.add_message_outcome(1, proof) {
            SubmitOutcome::Accepted => held += len,
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::Seals)) => break,
            other => panic!("seal {id}: {other:?}"),
        }
    }
    eprintln!("REACH seal-share held bytes={held}");
    let pool = 2 * (SHARE - (1 << 20));
    assert!(
        held <= pool && held + seal(0).len() > pool,
        "seal-share held: the archive held {held} bytes of storage epoch proofs, not up to {pool}"
    );
}

/// A GLOBAL archive holds one proposal's share of storage epoch proofs
/// from senders it does not know as active provers: 8 MiB, then refuses for
/// room.
#[test]
fn an_archive_holds_one_proposals_share_of_other_senders_storage_epoch_proofs() {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    let mut held = 0usize;
    for id in 1..=40u32 {
        let proof = seal(id);
        let len = proof.len();
        // Each sender is a peer of its own, within its share.
        match mc.add_message_outcome_by(1, proof, Provenance::Other, &id.to_be_bytes()) {
            SubmitOutcome::Accepted => held += len,
            SubmitOutcome::Filtered(Refusal::ShareFull(Share::OtherSeals)) => break,
            other => panic!("seal {id}: {other:?}"),
        }
    }
    eprintln!("REACH seal-share other-held bytes={held}");
    assert!(
        held <= SHARE && held + seal(0).len() > SHARE,
        "seal-share other-held: the archive held {held} bytes of other senders' storage epoch proofs, not up to {SHARE}"
    );
}

/// A storage epoch proof within its share that misses the room other
/// messages leave waits behind shard proofs; once the waiting proofs taken
/// fill the share, the rest ride in the room left, in their order. Here a
/// 2 MiB message and ten proofs fill the 8 MiB the shard floor leaves, and
/// a 5 MiB shard proof does not fit the rest: three waiting proofs fill
/// the share, three more ride in the room left, and the last of seventeen
/// waits.
#[test]
fn storage_epoch_proofs_that_waited_past_their_share_ride_in_the_room_left() {
    let mc = MessageCollector::new();
    let other = vec![b'o'; 2 << 20];
    let seals: Vec<Vec<u8>> = (1..=17).map(seal).collect();
    let headers = vec![sized_header(1, 5 << 20)];
    let bytes = |of: &[Vec<u8>]| of.iter().map(Vec::len).sum::<usize>();
    let others_room = PROPOSAL - (4 << 20);
    // Ten proofs fill the room the shard floor leaves beside the message,
    // and the shard proof does not fit what is left.
    assert!(
        other.len() + bytes(&seals[..10]) <= others_room
            && other.len() + bytes(&seals[..11]) > others_room
    );
    assert!(other.len() + bytes(&seals[..10]) + bytes(&headers) > PROPOSAL);
    // The share holds thirteen, and the proposal sixteen beside the message.
    assert!(bytes(&seals[..13]) <= SHARE && bytes(&seals[..14]) > SHARE);
    assert!(other.len() + bytes(&seals[..16]) <= PROPOSAL);
    assert!(other.len() + bytes(&seals) > PROPOSAL);
    assert!(anchor_in_lockstep(ANCHOR, FRAME));
    assert!(mc.add_message(1, other.clone()));
    for message in seals.iter().chain(&headers) {
        assert!(mc.add_message(1, message.clone()));
    }
    let taken = mc
        .snapshot_for_proposal(1, PROPOSAL, 100_000, Some(FRAME), &[])
        .unwrap();
    let (seals_taken, headers_taken) = counted(&taken, &seals, &headers);
    let last_waits = !taken.iter().any(|(data, _)| data == &seals[16]);
    eprintln!(
        "REACH seal-share waited-beyond seals={seals_taken} headers={headers_taken} last_waits={last_waits}"
    );
    assert!(taken.iter().any(|(data, _)| data == &other));
    assert_eq!(
        (seals_taken, headers_taken, last_waits),
        (16, 0, true),
        "seal-share waited-beyond: the proposal took {seals_taken} of 17 storage epoch proofs and {headers_taken} of 1 shard proof (the last proof waits: {last_waits})"
    );
}

/// On a GLOBAL proposal of 12 MiB, storage epoch proofs past their share
/// wait behind shard proofs, then ride in the room those leave, in their
/// order: thirteen proofs (8 MiB) and three shard headers of 1 MiB leave
/// room for two more of the sixteen, and the last waits.
#[test]
fn a_global_proposal_carries_storage_epoch_proofs_past_their_share_after_shard_proofs() {
    let mc = MessageCollector::new();
    let seals: Vec<Vec<u8>> = (1..=16).map(seal).collect();
    let headers: Vec<Vec<u8>> = (1..=3).map(header).collect();
    let bytes = |of: &[Vec<u8>]| of.iter().map(Vec::len).sum::<usize>();
    // Thirteen proofs fill the share, and the headers leave room for
    // fifteen, not sixteen.
    assert!(bytes(&seals[..13]) <= SHARE && bytes(&seals[..14]) > SHARE);
    assert!(bytes(&seals[..15]) + bytes(&headers) <= PROPOSAL);
    assert!(bytes(&seals) + bytes(&headers) > PROPOSAL);
    assert!(anchor_in_lockstep(ANCHOR, FRAME));
    for message in seals.iter().chain(&headers) {
        assert!(mc.add_message(1, message.clone()));
    }
    let taken = mc
        .snapshot_for_proposal(1, PROPOSAL, 100_000, Some(FRAME), &[])
        .unwrap();
    let (seals_taken, headers_taken) = counted(&taken, &seals, &headers);
    let last_waits = !taken.iter().any(|(data, _)| data == &seals[15]);
    eprintln!(
        "REACH seal-share global-beyond seals={seals_taken} headers={headers_taken} last_waits={last_waits}"
    );
    assert_eq!(
        (seals_taken, headers_taken, last_waits),
        (15, 3, true),
        "seal-share global-beyond: the proposal took {seals_taken} of 16 storage epoch proofs and {headers_taken} of 3 shard headers (the last proof waits: {last_waits})"
    );
}

/// A GLOBAL proposal's message budget holds the storage epoch proofs' share
/// beside the shard proofs' 4 MiB, and its frame stays under the gossip
/// ceiling: the header (256 commitments of 64 bytes and a signature, about
/// 20 KB) and a 4-byte length per message take under 1 MiB of the rest.
#[test]
fn a_global_proposal_budget_holds_the_seal_share_and_the_shard_floor() {
    let limits = crate::frame_materializer::GlobalParentLimits::default();
    let bytes = limits.max_proposal_message_bytes;
    let framing = 4 * limits.max_proposal_message_items + (64 << 10);
    eprintln!("REACH seal-share budget bytes={bytes} framing={framing}");
    assert!(
        framing <= 1 << 20,
        "seal-share budget: a frame's header and lengths take {framing} bytes"
    );
    assert!(
        bytes >= SHARE + (4 << 20) && bytes + (1 << 20) <= GOSSIP,
        "seal-share budget: proposal message bytes {bytes}"
    );
}
