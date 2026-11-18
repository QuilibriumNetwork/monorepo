//! Presence exclusion ([`crate::global_intrinsic::handoff::exclusion`]) and
//! the early fence it leads to ([`schedule::fence_absent`]).

use super::*;
use crate::global_intrinsic::handoff::exclusion::{self, Exclusion};
use crate::global_intrinsic::handoff::presence;

/// Presence reports, records, exclusion and fenced successors from current
/// eligibility active for the test's thread, and inactive again after.
struct Gates;

impl Gates {
    fn on() -> Self {
        set_presence_report_frame_for_thread(Some(0));
        set_presence_credit_frame_for_thread(Some(0));
        set_presence_exclusion_frame_for_thread(Some(0));
        set_fenced_successor_eligibility_frame_for_thread(Some(0));
        Self
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        set_presence_report_frame_for_thread(None);
        set_presence_credit_frame_for_thread(None);
        set_presence_exclusion_frame_for_thread(None);
        set_fenced_successor_eligibility_frame_for_thread(None);
    }
}

fn epoch_start(epoch: u64) -> u64 {
    epoch * quil_types::consensus::epoch_length_frames()
}

/// The epoch a shard's first session starts in.
const FIRST: u64 = 10;

/// The first frame of the epoch after [`FIRST`], whose first pass judges the
/// session's presence in [`FIRST`].
fn boundary() -> u64 {
    epoch_start(FIRST + 1)
}

fn private_keys(signers: &[quil_crypto::FalconSigner]) -> Vec<FalconPrivateKey> {
    signers
        .iter()
        .map(|signer| {
            FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap()
        })
        .collect()
}

fn refused_for<T: std::fmt::Debug>(result: Result<T>, reason: &str) {
    match result {
        Err(QuilError::InvalidArgument(message)) => assert!(message.contains(reason), "{message}"),
        other => panic!("expected refusal for {reason}, got {other:?}"),
    }
}

/// A shard whose first session of `size` members starts at the first frame
/// of epoch [`FIRST`] and never advances its tip.
struct Shard {
    _db: quil_store::RocksDb,
    state: HypergraphState,
    filter: Vec<u8>,
    signers: Vec<quil_crypto::FalconSigner>,
    session: Session,
}

impl Shard {
    fn new(size: usize) -> Self {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        commit(&state, 1);
        let filter = vec![0x7e; 32];
        let signers: Vec<_> = (0..size)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let start = epoch_start(FIRST);
        let keys = private_keys(&signers);
        let scan = scan_of(&[(filter.as_slice(), keys.as_slice())]);
        assert_eq!(
            schedule::reconcile_membership(&state, start, &policy(), &[filter.clone()], &scan)
                .unwrap(),
            1
        );
        commit(&state, start);
        let session = head(&state, &filter).unwrap().unwrap();
        Self {
            _db: db,
            state,
            filter,
            signers,
            session,
        }
    }

    fn id(&self) -> [u8; 32] {
        self.session.id().unwrap()
    }

    /// The session's members at `indexes`.
    fn members(&self, indexes: std::ops::Range<usize>) -> Vec<Vec<u8>> {
        indexes
            .map(|index| self.session.members[index].clone())
            .collect()
    }

    fn signer_of(&self, member: &[u8]) -> &quil_crypto::FalconSigner {
        self.signers
            .iter()
            .find(|signer| signer.public_key() == member)
            .unwrap()
    }

    /// Record the session's members at `present` (member indexes) present
    /// in `epoch`, as accepted reports of their notarizes would.
    fn mark(&self, epoch: u64, present: &[usize]) {
        self.record(b"presence", epoch, present);
    }

    /// Record the session's members at `protected` (member indexes)
    /// protected in `epoch`, as accepted reports of their nullifies would.
    fn protect(&self, epoch: u64, protected: &[usize]) {
        self.record(b"protected", epoch, protected);
    }

    fn record(&self, kind: &[u8], epoch: u64, indexes: &[usize]) {
        let mut marks = vec![false; self.session.members.len()];
        for &index in indexes {
            marks[index] = true;
        }
        presence::set_marks(
            &self.state,
            epoch_start(epoch) + 1,
            kind,
            &self.session,
            epoch,
            &marks,
        )
        .unwrap();
    }

    /// Member `index`'s nullify of round (`epoch`, `view`), signed under
    /// `signing`'s namespace: this session's, or another's for a forgery.
    fn nullify_by(
        &self,
        signing: &Session,
        epoch: u64,
        view: u64,
        index: usize,
    ) -> presence::NullifyVote {
        let keys = private_keys(&self.signers);
        let participants: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let member = &self.session.members[index];
        let key = keys
            .iter()
            .find(|key| key.public_key().as_ref() == member.as_slice())
            .unwrap()
            .clone();
        let scheme: Generic<Namespace> =
            Generic::signer(&signing.namespace().unwrap(), participants, key).unwrap();
        let round = Round::new(Epoch::new(epoch), View::new(view));
        let vote = scheme
            .sign::<SimplexFalconScheme, Digest>(Subject::Nullify { round })
            .unwrap();
        assert_eq!(vote.signer.get() as usize, index);
        presence::NullifyVote {
            view,
            signer: vote.signer.get(),
            signature: vote.signature.get().unwrap().to_vec(),
        }
    }

    /// A report of nullify votes alone.
    fn nullify_report(
        &self,
        mut nullifies: Vec<presence::NullifyVote>,
    ) -> presence::PresenceReport {
        nullifies.sort_by_key(|vote| vote.signer);
        presence::PresenceReport {
            session: self.id(),
            filter: self.filter.clone(),
            proposals: Vec::new(),
            nullifies,
        }
    }

    /// The exclusion pass alone at `frame`, with `desired` eligible.
    fn evaluate(&self, frame: u64, desired: &[Vec<u8>]) -> Vec<exclusion::Decision> {
        let desired = desired.to_vec();
        let mut eligible = |_: &[u8]| -> Result<Vec<Vec<u8>>> { Ok(desired.clone()) };
        exclusion::evaluate(&self.state, frame, &[self.filter.clone()], &mut eligible).unwrap()
    }

    /// The first maintenance pass of an epoch at `frame`, as GLOBAL runs it
    /// (`GlobalIntrinsic::reconcile_committee_sessions`) with `eligible`
    /// allocated: the exclusion pass and its early fences, then due fences
    /// and the membership pass seating eligibility less exclusions. Returns
    /// the decisions and how many sessions were fenced early.
    fn pass(
        &self,
        frame: u64,
        eligible: &[quil_crypto::FalconSigner],
    ) -> (Vec<exclusion::Decision>, usize) {
        let keys = private_keys(eligible);
        let scan = scan_of(&[(self.filter.as_slice(), keys.as_slice())]);
        let filters = vec![self.filter.clone()];
        let mut desired = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            Ok(schedule::desired_members(&scan, filter, frame))
        };
        let decisions = exclusion::evaluate(&self.state, frame, &filters, &mut desired).unwrap();
        let fenced = schedule::fence_absent(&self.state, frame, &decisions).unwrap();
        let mut seated = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            exclusion::seated(
                &self.state,
                frame,
                filter,
                schedule::desired_members(&scan, filter, frame),
            )
        };
        schedule::fence_stalled_sources(&self.state, frame, &filters, Some(&mut seated)).unwrap();
        schedule::reconcile_membership(&self.state, frame, &policy(), &filters, &scan).unwrap();
        commit(&self.state, frame);
        (decisions, fenced)
    }

    fn excluded(&self, member: &[u8]) -> Option<Exclusion> {
        exclusion::exclusion(&self.state, &self.filter, member).unwrap()
    }
}

/// Exclusion is GLOBAL consensus and not scheduled on mainnet; a process
/// that never fixed its network reads no setting.
#[test]
fn presence_exclusion_is_not_scheduled_by_default() {
    assert_eq!(MAINNET_PRESENCE_EXCLUSION_FRAME, None);
    assert_eq!(presence_exclusion_frame_for(0, None), u64::MAX);
    assert_eq!(presence_exclusion_frame_for(0, Some("7")), u64::MAX);
    assert_eq!(presence_exclusion_frame_for(1, Some("7")), 7);
    assert_eq!(presence_exclusion_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(presence_exclusion_frame_for(1, None), u64::MAX);
    set_presence_exclusion_frame_for_thread(None);
    assert_eq!(
        presence_exclusion_frame(),
        u64::MAX,
        "without init, the mainnet value"
    );
    assert!(!exclusion::evaluates(epoch_start(FIRST)));
    assert!(exclusion::require_claims_active(u64::MAX - 1).is_err());
}

/// Simplex quorum and the back-off: 1, 2, 4, 8, then 16 epochs for strikes
/// in a row; a strike long after the last exclusion starts again at one.
#[test]
fn exclusions_back_off_and_reset_after_a_clean_spell() {
    assert_eq!(
        [0, 1, 2, 3, 4, 5, 6, 7, 24].map(exclusion::quorum),
        [1, 1, 2, 3, 3, 4, 5, 5, 17]
    );
    assert_eq!(
        (1..=6).map(exclusion::exclusion_epochs).collect::<Vec<_>>(),
        vec![1, 2, 4, 8, 16, 16]
    );
    let first = exclusion::strike(None, 20);
    assert_eq!(
        first,
        Exclusion {
            strikes: 1,
            from: 20,
            until: 21
        }
    );
    assert!(first.covers(20) && !first.covers(19) && !first.covers(21));
    let second = exclusion::strike(Some(first), 22);
    assert_eq!(
        second,
        Exclusion {
            strikes: 2,
            from: 22,
            until: 24
        }
    );
    let third = exclusion::strike(Some(second), second.until + exclusion::RELAPSE_EPOCHS - 1);
    assert_eq!(
        (third.strikes, third.until - third.from),
        (3, 4),
        "a relapse within the window doubles"
    );
    let fresh = exclusion::strike(Some(third), third.until + exclusion::RELAPSE_EPOCHS);
    assert_eq!(fresh.strikes, 1, "a clean spell starts again");
    let mut last = exclusion::strike(None, 0);
    for _ in 0..8 {
        last = exclusion::strike(Some(last), last.until);
    }
    assert_eq!(last.until - last.from, exclusion::MAX_EXCLUSION_EPOCHS);
}

/// A session that stalled through an epoch below its quorum, whose present
/// members reach quorum without its absent ones, has those excluded and is
/// fenced early at the next epoch's first pass; its successor seats the
/// present members, and the excluded are seated again once the exclusion
/// ends. Not before the exclusion frame, nor at a later pass of the epoch.
#[test]
fn absent_members_of_a_stalled_session_are_excluded_and_it_is_fenced_early() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let b = boundary();
    shard.mark(FIRST, &[0, 1, 2, 3]);
    set_presence_exclusion_frame_for_thread(Some(b + 1));
    assert!(
        shard.evaluate(b, &shard.session.members).is_empty(),
        "not before the exclusion frame"
    );
    set_presence_exclusion_frame_for_thread(Some(0));
    assert!(
        shard
            .evaluate(b + schedule::SESSION_PASS_FRAMES, &shard.session.members)
            .is_empty(),
        "only at the epoch's first pass"
    );
    let (present, absent) = (shard.members(0..4), shard.members(4..7));
    let (decisions, fenced) = shard.pass(b, &shard.signers);
    let first = Exclusion {
        strikes: 1,
        from: FIRST + 1,
        until: FIRST + 2,
    };
    assert_eq!(
        decisions,
        vec![exclusion::Decision {
            filter: shard.filter.clone(),
            session: shard.id(),
            committee: present.clone(),
            excluded: absent.clone(),
            strikes: vec![first; 3],
        }]
    );
    assert_eq!(fenced, 1);
    for member in &absent {
        assert_eq!(
            shard.excluded(member),
            Some(Exclusion {
                strikes: 1,
                from: FIRST + 1,
                until: FIRST + 2
            })
        );
    }
    for member in &present {
        assert_eq!(shard.excluded(member), None);
    }
    assert!(is_fenced(&shard.state, &shard.id()).unwrap());
    assert_eq!(
        schedule::fence_frame(&shard.state, &shard.id()).unwrap(),
        Some(b),
        "dated at the early fence"
    );
    let successor = head(&shard.state, &shard.filter).unwrap().unwrap();
    assert_eq!(
        (successor.generation, successor.members.clone()),
        (2, present.clone())
    );
    assert_eq!(
        status(&shard.state, &successor.id().unwrap()).unwrap(),
        Status::Active
    );
    let everyone = shard.session.members.clone();
    assert_eq!(
        exclusion::seated(&shard.state, b + 8, &shard.filter, everyone.clone()).unwrap(),
        present
    );
    assert_eq!(
        exclusion::seated(
            &shard.state,
            epoch_start(FIRST + 2),
            &shard.filter,
            everyone.clone()
        )
        .unwrap(),
        everyone,
        "seated again once the exclusion ends"
    );
    set_presence_exclusion_frame_for_thread(Some(u64::MAX));
    assert_eq!(
        exclusion::seated(&shard.state, b + 8, &shard.filter, everyone.clone()).unwrap(),
        everyone,
        "nothing is left out before the exclusion frame"
    );
}

/// A session closing for a membership change it cannot seal is fenced early
/// too; its successor seats the eligible provers less the excluded, not the
/// committee its request named. An eligible prover that was not a member is
/// seated but not counted present.
#[test]
fn a_closing_session_is_fenced_early_with_its_present_members_and_new_eligibility() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let joiner = quil_crypto::FalconSigner::generate();
    let mut eligible = shard
        .signers
        .iter()
        .map(|signer| {
            quil_crypto::FalconSigner::from_bytes(signer.private_key(), signer.public_key())
        })
        .collect::<Vec<_>>();
    eligible.push(quil_crypto::FalconSigner::from_bytes(
        joiner.private_key(),
        joiner.public_key(),
    ));
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let requested = epoch_start(FIRST) + schedule::SESSION_PASS_FRAMES;
    let keys = private_keys(&eligible);
    let scan = scan_of(&[(shard.filter.as_slice(), keys.as_slice())]);
    assert_eq!(
        schedule::reconcile_membership(
            &shard.state,
            requested,
            &policy(),
            &[shard.filter.clone()],
            &scan
        )
        .unwrap(),
        1
    );
    commit(&shard.state, requested);
    assert!(matches!(
        status(&shard.state, &shard.id()).unwrap(),
        Status::Sealing(_)
    ));
    let (decisions, fenced) = shard.pass(boundary(), &eligible);
    let mut committee = shard.members(0..4);
    committee.push(joiner.public_key().to_vec());
    committee.sort();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        (
            decisions[0].committee.clone(),
            decisions[0].excluded.clone()
        ),
        (committee.clone(), shard.members(4..7))
    );
    assert_eq!(fenced, 1);
    let successor = head(&shard.state, &shard.filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.members), (2, committee));
}

/// Below quorum of the committee without the absent members, or below the
/// consensus minimum, nothing is excluded and nothing is fenced early: the
/// session waits for its timeout, as without presence records.
#[test]
fn nothing_changes_when_exclusion_would_not_unlock_quorum() {
    let _gates = Gates::on();
    // Four present of seven, but three new eligible provers would make the
    // committee seven again, whose quorum (5) the four do not reach.
    let shard = Shard::new(7);
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let mut eligible = shard
        .signers
        .iter()
        .map(|signer| {
            quil_crypto::FalconSigner::from_bytes(signer.private_key(), signer.public_key())
        })
        .collect::<Vec<_>>();
    eligible.extend((0..3).map(|_| quil_crypto::FalconSigner::generate()));
    let (decisions, fenced) = shard.pass(boundary(), &eligible);
    assert!(decisions.is_empty());
    assert_eq!(fenced, 0);
    for member in &shard.session.members {
        assert_eq!(shard.excluded(member), None);
    }
    assert_eq!(
        head(&shard.state, &shard.filter).unwrap().unwrap(),
        shard.session,
        "no early fence"
    );
    assert!(
        matches!(
            status(&shard.state, &shard.id()).unwrap(),
            Status::Sealing(_)
        ),
        "the ordinary successor request"
    );
    assert_eq!(
        schedule::fence_frame(&shard.state, &shard.id()).unwrap(),
        Some(schedule::fence_due_frame(boundary())),
        "fenced at its timeout"
    );
    // Three present of five: without the two absent, three members, below
    // the consensus minimum.
    let small = Shard::new(5);
    small.mark(FIRST, &[0, 1, 2]);
    let (decisions, fenced) = small.pass(boundary(), &small.signers);
    assert!(decisions.is_empty());
    assert_eq!(fenced, 0);
    assert_eq!(small.excluded(&small.session.members[4]), None);
    assert_eq!(
        status(&small.state, &small.id()).unwrap(),
        Status::Active,
        "the committee is unchanged"
    );
}

/// Only a session whose stall absence explains is judged: one with a
/// presence record, a tip that stood still through the epoch, present
/// members below its quorum, eligible provers, and not closing for a split
/// or merge.
#[test]
fn only_a_session_stalled_by_absence_is_judged() {
    let _gates = Gates::on();
    let b = boundary();
    // No presence record: missing reports exclude no one.
    let unreported = Shard::new(7);
    assert!(unreported
        .evaluate(b, &unreported.session.members)
        .is_empty());
    // Present members exceed the session's quorum (5 of 7).
    let quorate = Shard::new(7);
    quorate.mark(FIRST, &[0, 1, 2, 3]);
    quorate.protect(FIRST, &[3, 4, 5]);
    assert!(quorate.evaluate(b, &quorate.session.members).is_empty());
    // The tip advanced during the epoch.
    let advanced = Shard::new(7);
    advanced.mark(FIRST, &[0, 1, 2, 3]);
    record_session_tip(
        &advanced.state,
        epoch_start(FIRST) + 20,
        &advanced.id(),
        &tip(3, 4, [0x33; 32]),
    )
    .unwrap();
    commit(&advanced.state, epoch_start(FIRST) + 20);
    assert!(advanced.evaluate(b, &advanced.session.members).is_empty());
    // Nobody is eligible.
    let deserted = Shard::new(7);
    deserted.mark(FIRST, &[0, 1, 2, 3]);
    assert!(deserted.evaluate(b, &[]).is_empty());
    // Closing for a split.
    let split = Shard::new(7);
    split.mark(FIRST, &[0, 1, 2, 3]);
    let (left, right) = (
        [split.filter.clone(), vec![0, 1, 0]].concat(),
        [split.filter.clone(), vec![0, 1, 128]].concat(),
    );
    schedule(
        &split.state,
        epoch_start(FIRST) + 8,
        vec![split.filter.clone()],
        vec![
            DesiredCommittee {
                filter: left,
                members: split.members(0..4),
            },
            DesiredCommittee {
                filter: right,
                members: split.members(4..7),
            },
        ],
    )
    .unwrap();
    commit(&split.state, epoch_start(FIRST) + 8);
    assert!(split.evaluate(b, &split.session.members).is_empty());
    for shard in [&unreported, &quorate, &advanced, &deserted, &split] {
        for member in &shard.session.members {
            assert_eq!(shard.excluded(member), None);
        }
    }
    // The same stall that absence explains is judged.
    let stalled = Shard::new(7);
    stalled.mark(FIRST, &[0, 1, 2, 3]);
    assert_eq!(stalled.evaluate(b, &stalled.session.members).len(), 1);
}

/// A member struck again within the relapse window gets twice the previous
/// exclusion; one already excluded is not struck twice.
#[test]
fn a_relapse_doubles_the_exclusion() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let b = boundary();
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let (relapsed, excluded) = (
        shard.session.members[4].clone(),
        shard.session.members[5].clone(),
    );
    exclusion::set_exclusion(
        &shard.state,
        b,
        &shard.filter,
        &relapsed,
        &Exclusion {
            strikes: 1,
            from: FIRST - 1,
            until: FIRST,
        },
    )
    .unwrap();
    exclusion::set_exclusion(
        &shard.state,
        b,
        &shard.filter,
        &excluded,
        &Exclusion {
            strikes: 2,
            from: FIRST,
            until: FIRST + 2,
        },
    )
    .unwrap();
    commit(&shard.state, b);
    let decisions = shard.evaluate(b, &shard.session.members);
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].excluded,
        vec![relapsed.clone(), shard.session.members[6].clone()]
    );
    assert_eq!(
        decisions[0].strikes,
        vec![
            Exclusion {
                strikes: 2,
                from: FIRST + 1,
                until: FIRST + 3
            },
            Exclusion {
                strikes: 1,
                from: FIRST + 1,
                until: FIRST + 2
            },
        ]
    );
    assert_eq!(
        schedule::fence_absent(&shard.state, b, &decisions).unwrap(),
        1
    );
    assert_eq!(
        shard.excluded(&relapsed),
        Some(Exclusion {
            strikes: 2,
            from: FIRST + 1,
            until: FIRST + 3
        })
    );
    assert_eq!(
        shard.excluded(&excluded),
        Some(Exclusion {
            strikes: 2,
            from: FIRST,
            until: FIRST + 2
        }),
        "unchanged"
    );
    assert_eq!(
        shard.excluded(&shard.session.members[6]),
        Some(Exclusion {
            strikes: 1,
            from: FIRST + 1,
            until: FIRST + 2
        })
    );
}

/// Exclusions that would leave fewer than the consensus minimum are
/// suspended rather than seat too small a committee.
#[test]
fn exclusions_never_seat_fewer_than_the_consensus_minimum() {
    let _gates = Gates::on();
    let shard = Shard::new(5);
    let everyone = shard.session.members.clone();
    let frame = epoch_start(FIRST) + 8;
    let exclude = |index: usize| {
        exclusion::set_exclusion(
            &shard.state,
            frame,
            &shard.filter,
            &everyone[index],
            &Exclusion {
                strikes: 1,
                from: FIRST,
                until: FIRST + 1,
            },
        )
        .unwrap();
    };
    exclude(4);
    assert_eq!(
        exclusion::seated(&shard.state, frame, &shard.filter, everyone.clone()).unwrap(),
        everyone[..4].to_vec()
    );
    exclude(3);
    assert_eq!(
        exclusion::seated(&shard.state, frame, &shard.filter, everyone.clone()).unwrap(),
        everyone,
        "three would remain: suspended"
    );
}

/// The way back: a claim signed by an excluded member's key over a recent
/// GLOBAL frame's beacon ends its exclusion at the next boundary and keeps
/// its strikes, so a relapse doubles the next exclusion. Claims are refused
/// before the exclusion frame, for a member with no exclusion to end, with
/// an anchor outside the inclusion epoch, or under another key.
#[test]
fn a_presence_claim_ends_an_exclusion_at_the_next_boundary() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let epoch = FIRST + 1;
    let frame = epoch_start(epoch) + 30;
    let anchor = frame - 10;
    let output = vec![0x5a; 516];
    let outputs = |_: u64| -> Result<Vec<u8>> { Ok(output.clone()) };
    let member = shard.session.members[4].clone();
    let claim = |signer: &quil_crypto::FalconSigner, anchor: u64| exclusion::PresenceClaim {
        filter: shard.filter.clone(),
        member: member.clone(),
        anchor,
        signature: signer
            .sign_with_domain(
                &exclusion::claim_message(&shard.filter, anchor, &output).unwrap(),
                exclusion::CLAIM_DOMAIN,
            )
            .unwrap(),
    };
    let valid = claim(shard.signer_of(&member), anchor);
    let bytes = valid.to_canonical_bytes().unwrap();
    assert_eq!(&bytes[..4], &TYPE_PRESENCE_REPORT.to_be_bytes());
    assert_eq!(
        exclusion::PresenceClaim::from_canonical_bytes(&bytes).unwrap(),
        valid
    );
    assert_eq!(
        presence::PresenceOp::from_canonical_bytes(&bytes).unwrap(),
        presence::PresenceOp::Claim(valid.clone())
    );
    for n in 0..bytes.len() {
        assert!(presence::check_encoding(&bytes[..n], None).is_err());
    }
    assert!(
        presence::PresenceReport::from_canonical_bytes(&bytes).is_err(),
        "not a report"
    );
    refused_for(
        exclusion::verify_claim(&shard.state, frame, &valid, outputs),
        "no exclusion",
    );
    exclusion::set_exclusion(
        &shard.state,
        frame,
        &shard.filter,
        &member,
        &Exclusion {
            strikes: 1,
            from: epoch,
            until: epoch + 1,
        },
    )
    .unwrap();
    refused_for(
        exclusion::verify_claim(&shard.state, frame, &valid, outputs),
        "no exclusion",
    );
    exclusion::set_exclusion(
        &shard.state,
        frame,
        &shard.filter,
        &member,
        &Exclusion {
            strikes: 3,
            from: epoch,
            until: epoch + 4,
        },
    )
    .unwrap();
    commit(&shard.state, frame);
    let bare = crate::global_intrinsic::intrinsic::GlobalIntrinsic::new(Arc::new(
        crate::testing::NoopKeyManager,
    ));
    set_presence_exclusion_frame_for_thread(Some(frame + 1));
    refused_for(
        exclusion::verify_claim(&shard.state, frame, &valid, outputs),
        "presence exclusion frame",
    );
    assert!(
        matches!(
            bare.validate(frame, &bytes, None, None),
            Err(QuilError::InvalidArgument(_))
        ),
        "refused before any state is read, as an older build refuses it"
    );
    set_presence_exclusion_frame_for_thread(Some(0));
    assert!(matches!(
        bare.validate(frame, &bytes, None, None),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    refused_for(
        exclusion::verify_claim(
            &shard.state,
            frame,
            &claim(shard.signer_of(&member), epoch_start(epoch) - 1),
            outputs,
        ),
        "inclusion epoch",
    );
    refused_for(
        exclusion::verify_claim(
            &shard.state,
            frame,
            &claim(shard.signer_of(&member), frame),
            outputs,
        ),
        "inclusion epoch",
    );
    let other = shard.signer_of(&shard.session.members[0]);
    refused_for(
        exclusion::verify_claim(&shard.state, frame, &claim(other, anchor), outputs),
        "signature",
    );
    let elsewhere = |_: u64| -> Result<Vec<u8>> { Ok(vec![0x5b; 516]) };
    refused_for(
        exclusion::verify_claim(&shard.state, frame, &valid, elsewhere),
        "signature",
    );
    exclusion::apply_claim(&shard.state, frame, &valid, outputs).unwrap();
    assert_eq!(
        shard.excluded(&member),
        Some(Exclusion {
            strikes: 3,
            from: epoch,
            until: epoch + 1
        })
    );
    refused_for(
        exclusion::apply_claim(&shard.state, frame + 1, &valid, outputs),
        "no exclusion",
    );
    let everyone = shard.session.members.clone();
    assert!(
        !exclusion::seated(&shard.state, frame, &shard.filter, everyone.clone())
            .unwrap()
            .contains(&member)
    );
    assert_eq!(
        exclusion::seated(
            &shard.state,
            epoch_start(epoch + 1),
            &shard.filter,
            everyone.clone()
        )
        .unwrap(),
        everyone
    );
    assert_eq!(
        exclusion::strike(shard.excluded(&member), epoch + 1),
        Exclusion {
            strikes: 4,
            from: epoch + 1,
            until: epoch + 9
        },
        "a relapse doubles the next exclusion"
    );
}

/// The stalls seen on mainnet: no member notarizes (no proposal they accept
/// reaches them), present members only nullify, and the absent send
/// nothing. Sixteen of 23 nullify, seven are silent: their nullifies are
/// reported and recorded as protection (no credit), and the next epoch's
/// first pass excludes the seven and fences the session early, its
/// successor seating the sixteen. Nullify reports are refused before the
/// exclusion frame, as an older build refuses them, and they keep their own
/// codec version.
#[test]
fn a_stall_of_nullifies_alone_excludes_the_silent_members_and_fences_early() {
    let _gates = Gates::on();
    let shard = Shard::new(23);
    let frame = epoch_start(FIRST) + 40;
    let report = shard.nullify_report(
        (0..16)
            .map(|index| shard.nullify_by(&shard.session, 1, 1, index))
            .collect(),
    );
    let bytes = report.to_canonical_bytes().unwrap();
    assert_eq!(bytes[4], presence::VERSION_NULLIFY);
    assert_eq!(
        presence::PresenceReport::from_canonical_bytes(&bytes).unwrap(),
        report
    );
    for n in 0..bytes.len() {
        assert!(presence::PresenceReport::from_canonical_bytes(&bytes[..n]).is_err());
    }
    let mut empty =
        bytes[..bytes.len() - 16 * (8 + 4 + quil_crypto::FALCON_SIGNATURE_LEN) - 4].to_vec();
    empty.extend_from_slice(&0u32.to_be_bytes());
    assert!(
        presence::PresenceReport::from_canonical_bytes(&empty).is_err(),
        "version 3 carries a nullify"
    );
    let outputs = |_: u64| -> Result<Vec<u8>> { panic!("a nullify report reads no anchor") };
    set_presence_exclusion_frame_for_thread(Some(frame + 1));
    refused_for(
        presence::verify(&shard.state, frame, &report, outputs),
        "presence exclusion frame",
    );
    let bare = crate::global_intrinsic::intrinsic::GlobalIntrinsic::new(Arc::new(
        crate::testing::NoopKeyManager,
    ));
    assert!(matches!(
        bare.validate(frame, &bytes, None, None),
        Err(QuilError::InvalidArgument(_))
    ));
    set_presence_exclusion_frame_for_thread(Some(0));
    let applied = presence::apply(&shard.state, frame, &report, outputs).unwrap();
    assert_eq!(
        (applied.marked, applied.credited, applied.protected),
        (0, 0, 16),
        "protection, never credit"
    );
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    assert_eq!(
        presence::present(&shard.state, &shard.session, epoch).unwrap(),
        None
    );
    let protected = presence::protected(&shard.state, &shard.session, epoch)
        .unwrap()
        .unwrap();
    assert_eq!(protected.iter().filter(|&&mark| mark).count(), 16);
    refused_for(
        presence::apply(&shard.state, frame + 1, &report, outputs),
        "marks no member",
    );
    commit(&shard.state, frame);
    let (silent, nullifying) = (shard.members(16..23), shard.members(0..16));
    let (decisions, fenced) = shard.pass(boundary(), &shard.signers);
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        (
            decisions[0].committee.clone(),
            decisions[0].excluded.clone()
        ),
        (nullifying.clone(), silent.clone())
    );
    assert_eq!(fenced, 1);
    let successor = head(&shard.state, &shard.filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.members), (2, nullifying));
    for member in &silent {
        assert_eq!(
            shard.excluded(member).map(|excluded| excluded.strikes),
            Some(1)
        );
    }
}

/// A nullify signed under another session's namespace, or for a round of
/// another generation (one signed ahead for a successor), proves nothing of
/// this session: its report is refused, and its signer stays absent.
#[test]
fn a_foreign_or_presigned_nullify_does_not_protect() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let frame = epoch_start(FIRST) + 40;
    let outputs = |_: u64| -> Result<Vec<u8>> { panic!("a nullify report reads no anchor") };
    let foreign = Session {
        filter: vec![0x7f; 32],
        ..shard.session.clone()
    };
    let generation = shard.session.generation;
    refused_for(
        presence::apply(
            &shard.state,
            frame,
            &shard.nullify_report(vec![shard.nullify_by(&foreign, generation, 1, 4)]),
            outputs,
        ),
        "nullify",
    );
    refused_for(
        presence::apply(
            &shard.state,
            frame,
            &shard.nullify_report(vec![shard.nullify_by(&shard.session, generation + 1, 1, 5)]),
            outputs,
        ),
        "nullify",
    );
    let mut forged = shard.nullify_by(&shard.session, generation, 1, 6);
    forged.signature[20] ^= 1;
    refused_for(
        presence::apply(
            &shard.state,
            frame,
            &shard.nullify_report(vec![forged]),
            outputs,
        ),
        "nullify",
    );
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    assert_eq!(
        presence::protected(&shard.state, &shard.session, epoch).unwrap(),
        None
    );
    let honest = shard.nullify_report(
        (0..4)
            .map(|index| shard.nullify_by(&shard.session, generation, 2, index))
            .collect(),
    );
    presence::apply(&shard.state, frame, &honest, outputs).unwrap();
    commit(&shard.state, frame);
    let (decisions, _) = shard.pass(boundary(), &shard.signers);
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].excluded,
        shard.members(4..7),
        "the refused signers stay absent"
    );
}

/// One reporter's partial view decides nothing: the present members must be
/// a strict majority of the session's. Four of 23 reported present (a
/// submitter carrying only its friends', or seeing only them) exclude
/// nobody; fifteen of 23, one short of the quorum of 16, exclude the eight
/// others.
#[test]
fn only_a_majority_of_present_members_excludes_the_rest() {
    let _gates = Gates::on();
    let minority = Shard::new(23);
    minority.protect(FIRST, &[0, 1, 2, 3]);
    assert!(minority
        .evaluate(boundary(), &minority.session.members)
        .is_empty());
    let (decisions, fenced) = minority.pass(boundary(), &minority.signers);
    assert!(decisions.is_empty());
    assert_eq!(fenced, 0);
    assert!(minority
        .session
        .members
        .iter()
        .all(|member| minority.excluded(member).is_none()));
    let short = Shard::new(23);
    short.protect(FIRST, &(0..15).collect::<Vec<_>>());
    let (decisions, fenced) = short.pass(boundary(), &short.signers);
    assert_eq!(fenced, 1);
    assert_eq!(
        (
            decisions[0].committee.clone(),
            decisions[0].excluded.clone()
        ),
        (short.members(0..15), short.members(15..23))
    );
    assert_eq!(
        head(&short.state, &short.filter).unwrap().unwrap().members,
        short.members(0..15)
    );
}

/// No early fence without an exclusion: a stalled session whose only
/// missing member is no longer eligible is left to the membership pass.
#[test]
fn no_early_fence_without_an_absent_eligible_member() {
    let _gates = Gates::on();
    let shard = Shard::new(5);
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let eligible: Vec<quil_crypto::FalconSigner> = shard
        .members(0..4)
        .iter()
        .map(|member| {
            let signer = shard.signer_of(member);
            quil_crypto::FalconSigner::from_bytes(signer.private_key(), signer.public_key())
        })
        .collect();
    assert!(shard.evaluate(boundary(), &shard.members(0..4)).is_empty());
    let (decisions, fenced) = shard.pass(boundary(), &eligible);
    assert!(decisions.is_empty());
    assert_eq!(fenced, 0);
    assert_eq!(
        head(&shard.state, &shard.filter).unwrap().unwrap(),
        shard.session,
        "not fenced early"
    );
    assert!(
        matches!(
            status(&shard.state, &shard.id()).unwrap(),
            Status::Sealing(_)
        ),
        "the ordinary successor request"
    );
}

/// Strikes are written only with the early fence: evaluating writes
/// nothing, and a decision whose fence fails, or whose session has moved
/// on, leaves no exclusion and no request behind.
#[test]
fn strikes_are_written_only_with_the_early_fence() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let decisions = shard.evaluate(boundary(), &shard.session.members);
    assert_eq!(decisions.len(), 1);
    assert!(
        shard
            .session
            .members
            .iter()
            .all(|member| shard.excluded(member).is_none()),
        "evaluation writes nothing"
    );
    // A committee no session can seat: the fence is undone whole.
    let mut broken = decisions[0].clone();
    broken.committee = vec![vec![7; 5]];
    let before = shard.state.changeset_len();
    assert_eq!(
        schedule::fence_absent(&shard.state, boundary(), &[broken]).unwrap(),
        0
    );
    assert_eq!(shard.state.changeset_len(), before);
    assert_eq!(status(&shard.state, &shard.id()).unwrap(), Status::Active);
    assert!(shard
        .session
        .members
        .iter()
        .all(|member| shard.excluded(member).is_none()));
    // Fenced: the strikes are written with it.
    assert_eq!(
        schedule::fence_absent(&shard.state, boundary(), &decisions).unwrap(),
        1
    );
    let struck = Exclusion {
        strikes: 1,
        from: FIRST + 1,
        until: FIRST + 2,
    };
    for member in &shard.members(4..7) {
        assert_eq!(shard.excluded(member), Some(struck));
    }
    // A decision for a session that has moved on writes nothing.
    let mut stale = decisions[0].clone();
    stale.strikes = vec![
        Exclusion {
            strikes: 5,
            from: FIRST + 1,
            until: FIRST + 17
        };
        3
    ];
    assert_eq!(
        schedule::fence_absent(&shard.state, boundary(), &[stale]).unwrap(),
        0
    );
    for member in &shard.members(4..7) {
        assert_eq!(shard.excluded(member), Some(struck));
    }
}

/// A nullify stays valid for its session's life, so one recorded in an
/// earlier epoch cannot protect anyone again: a later epoch's nullifies
/// must name a higher view than any recorded before it.
#[test]
fn a_replayed_nullify_does_not_protect_in_a_later_epoch() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    let generation = shard.session.generation;
    let outputs = |_: u64| -> Result<Vec<u8>> { panic!("a nullify report reads no anchor") };
    let first = epoch_start(FIRST) + 40;
    let report = shard.nullify_report(
        (0..4)
            .map(|index| shard.nullify_by(&shard.session, generation, 1, index))
            .collect(),
    );
    presence::apply(&shard.state, first, &report, outputs).unwrap();
    assert_eq!(
        presence::nullify_floor(&shard.state, &shard.session, FIRST).unwrap(),
        0
    );
    commit(&shard.state, first);
    let later = epoch_start(FIRST + 1) + 40;
    assert_eq!(
        presence::nullify_floor(&shard.state, &shard.session, FIRST + 1).unwrap(),
        1
    );
    refused_for(
        presence::apply(&shard.state, later, &report, outputs),
        "earlier epochs",
    );
    let unseen = shard.nullify_report(vec![shard.nullify_by(&shard.session, generation, 1, 5)]);
    refused_for(
        presence::apply(&shard.state, later, &unseen, outputs),
        "earlier epochs",
    );
    let fresh = shard.nullify_report(
        (0..4)
            .map(|index| shard.nullify_by(&shard.session, generation, 2, index))
            .collect(),
    );
    assert_eq!(
        presence::apply(&shard.state, later, &fresh, outputs)
            .unwrap()
            .protected,
        4
    );
    assert_eq!(
        presence::nullify_floor(&shard.state, &shard.session, FIRST + 1).unwrap(),
        1,
        "the floor holds within the epoch"
    );
    assert_eq!(
        presence::nullify_floor(&shard.state, &shard.session, FIRST + 2).unwrap(),
        2
    );
}

/// A shard that a pending split or merge reserves as a target is not
/// fenced early: another session there would make that change's activation
/// fail for good. Nobody is excluded.
#[test]
fn a_shard_reserved_by_a_pending_split_or_merge_is_not_fenced_early() {
    let _gates = Gates::on();
    let shard = Shard::new(7);
    shard.mark(FIRST, &[0, 1, 2, 3]);
    let pending = DesiredCommittee {
        filter: shard.filter.clone(),
        members: shard.session.members.clone(),
    };
    schedule::reserve(
        &shard.state,
        epoch_start(FIRST) + 8,
        &[pending],
        &[0x55; 32],
    )
    .unwrap();
    let decisions = shard.evaluate(boundary(), &shard.session.members);
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        schedule::fence_absent(&shard.state, boundary(), &decisions).unwrap(),
        0
    );
    assert_eq!(status(&shard.state, &shard.id()).unwrap(), Status::Active);
    assert!(shard
        .session
        .members
        .iter()
        .all(|member| shard.excluded(member).is_none()));
}

/// The exclusion rule's quorum is commonware's own N3f1 quorum.
#[test]
fn the_exclusion_quorum_is_n3f1() {
    use quil_cw_consensus::_utils::Faults as _;
    for members in 1..=64u32 {
        assert_eq!(
            exclusion::quorum(members as usize),
            N3f1::quorum(members) as usize,
            "{members} members"
        );
    }
}
