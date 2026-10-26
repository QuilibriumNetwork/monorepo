//! Presence report validation and recording
//! ([`crate::global_intrinsic::handoff::presence`]).

use super::*;
use crate::global_intrinsic::frame_header::FrameHeader;
use crate::global_intrinsic::handoff::presence::{
    NotarizeVote, PresenceProposal, PresenceReport, MAX_PRESENCE_PROPOSALS, MAX_PRESENCE_VOTES,
};
use crate::global_intrinsic::intrinsic::GlobalIntrinsic;
use quil_types::store::ClockStore as _;

fn anchor_output(frame: u64) -> Vec<u8> {
    vec![(frame % 251) as u8 + 1; 516]
}

fn put_anchor(clock: &quil_store::RocksClockStore, frame: u64) {
    let txn = clock.new_transaction(false).unwrap();
    clock
        .put_global_clock_frame(
            &quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: frame,
                    output: anchor_output(frame),
                    ..Default::default()
                }),
                ..Default::default()
            },
            txn.as_ref(),
        )
        .unwrap();
    txn.commit().unwrap();
}

/// The producer's output stamp (`porep::deterministic_app_frame_output`).
fn stamp(header: &mut FrameHeader, anchor_output: &[u8]) {
    let rho_n = quil_crypto::porep::derive_storage_beacon(header.global_frame_number, anchor_output);
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector, &header.requests_root, &header.state_roots, &rho_n,
        header.frame_number, header.rank, &header.prover, header.difficulty,
        header.fee_multiplier_vote as u64, header.timestamp, &header.storage_attestation_root,
        header.fee_total_value(), &header.settlements, &header.accumulator, &header.spends,
    );
}

fn refused(result: Result<()>) {
    assert!(matches!(result, Err(QuilError::InvalidArgument(_))), "{result:?}");
}

fn refused_for(result: Result<()>, reason: &str) {
    match result {
        Err(QuilError::InvalidArgument(message)) => assert!(message.contains(reason), "{message}"),
        other => panic!("expected refusal for {reason}, got {other:?}"),
    }
}

/// A committed four-member session, an anchor in the clock store, and an
/// inclusion frame later in the anchor's epoch. Reports are active.
struct Fixture {
    state: HypergraphState,
    clock: Arc<quil_store::RocksClockStore>,
    keys: Vec<FalconPrivateKey>,
    session: Session,
    frame: u64,
    anchor: u64,
    _db: quil_store::RocksDb,
}

fn fixture() -> Fixture {
    fixture_with(keys())
}

/// [`fixture`] for the members `keys`: two fixtures of the same keys hold
/// the same session.
fn fixture_with(keys: Vec<FalconPrivateKey>) -> Fixture {
    set_presence_report_frame_for_thread(Some(0));
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let session = initial(vec![0x61; 32], &keys);
    initialize(&state, 1, &session).unwrap();
    commit(&state, 1);
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let anchor = 3 * quil_types::consensus::epoch_length_frames() + 5;
    put_anchor(&clock, anchor);
    Fixture { state, clock, keys, session, frame: anchor + 6, anchor, _db: db }
}

impl Fixture {
    fn intrinsic(&self) -> GlobalIntrinsic {
        GlobalIntrinsic::new(Arc::new(crate::testing::NoopKeyManager))
            .with_clock_store(self.clock.clone())
            .with_hypergraph(self.state.crdt().clone())
    }

    fn verify(&self, report: &PresenceReport) -> Result<()> {
        self.intrinsic().verify_presence_report(self.frame, report, &self.state)
    }

    fn report(&self, proposals: Vec<PresenceProposal>) -> PresenceReport {
        PresenceReport {
            session: self.session.id().unwrap(),
            filter: self.session.filter.clone(),
            proposals,
            nullifies: Vec::new(),
        }
    }

    /// A proposal at `view` anchored to `anchor`, notarized by `signers`
    /// (indexes into `keys`).
    fn proposal(&self, view: u64, anchor: u64, signers: &[usize]) -> PresenceProposal {
        let header = FrameHeader {
            address: self.session.filter.clone(),
            frame_number: view + 1,
            rank: view,
            difficulty: 100,
            parent_selector: vec![0x31; 32],
            global_frame_number: anchor,
            ..Default::default()
        };
        let mut proposal = PresenceProposal {
            header, epoch: self.session.generation, view, parent: view - 1, payload: [0; 32], votes: Vec::new(),
        };
        self.reissue(&mut proposal, signers);
        proposal
    }

    /// Restamp the header's output, take its digest as the payload, and
    /// notarize the result by `signers`.
    fn reissue(&self, proposal: &mut PresenceProposal, signers: &[usize]) {
        let anchor = anchor_output(proposal.header.global_frame_number);
        stamp(&mut proposal.header, &anchor);
        proposal.payload = quil_crypto::poseidon::hash_bytes_to_32(&proposal.header.output).unwrap();
        self.sign(proposal, signers);
    }

    /// Replace the votes by notarizes of `signers` over the proposal as it is.
    fn sign(&self, proposal: &mut PresenceProposal, signers: &[usize]) {
        let participants: Set<_> = self
            .keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let subject = Proposal::new(
            Round::new(Epoch::new(proposal.epoch), View::new(proposal.view)),
            View::new(proposal.parent),
            Digest(proposal.payload),
        );
        let mut votes: Vec<NotarizeVote> = signers
            .iter()
            .map(|&signer| {
                let scheme: Generic<Namespace> = Generic::signer(
                    &self.session.namespace().unwrap(), participants.clone(), self.keys[signer].clone(),
                )
                .unwrap();
                let vote = scheme
                    .sign::<SimplexFalconScheme, Digest>(Subject::Notarize { proposal: &subject })
                    .unwrap();
                NotarizeVote { signer: vote.signer.get(), signature: vote.signature.get().unwrap().to_vec() }
            })
            .collect();
        votes.sort_by_key(|vote| vote.signer);
        proposal.votes = votes;
    }
}

#[test]
fn valid_presence_report_is_accepted_and_writes_nothing() {
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1]), f.proposal(6, f.anchor, &[2])]);
    f.verify(&report).unwrap();
    let bytes = report.to_canonical_bytes().unwrap();
    assert_eq!(&bytes[..4], &TYPE_PRESENCE_REPORT.to_be_bytes());
    assert_eq!(PresenceReport::from_canonical_bytes(&bytes).unwrap(), report);
    for n in 0..bytes.len() {
        assert!(PresenceReport::from_canonical_bytes(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PresenceReport::from_canonical_bytes(&trailing).is_err());
    let intrinsic = f.intrinsic();
    assert!(intrinsic.validate(f.frame, &bytes, None, None).unwrap());
    assert_eq!(f.state.changeset_len(), 0);
    intrinsic.invoke_step(f.frame, &bytes, &f.state).unwrap();
    assert_eq!(f.state.changeset_len(), 0, "a validated report writes nothing");
}

#[test]
fn forged_presence_votes_are_refused() {
    let f = fixture();
    let valid = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&valid).unwrap();
    let mut flipped = valid.clone();
    flipped.proposals[0].votes[0].signature[20] ^= 1;
    refused(f.verify(&flipped));
    // Two members' votes, each under the other's index.
    let mut swapped = valid.clone();
    swapped.proposals[0].votes[0].signature = valid.proposals[0].votes[1].signature.clone();
    swapped.proposals[0].votes[1].signature = valid.proposals[0].votes[0].signature.clone();
    refused(f.verify(&swapped));
    // Votes for another parent view than the one carried.
    let mut parent = valid.clone();
    parent.proposals[0].parent -= 1;
    refused(f.verify(&parent));
}

#[test]
fn presence_anchor_outside_the_inclusion_epoch_is_refused_before_lookup() {
    let f = fixture();
    let epoch = quil_types::consensus::epoch_length_frames();
    // Another earlier frame of the epoch is a valid anchor.
    put_anchor(&f.clock, f.frame - 1);
    f.verify(&f.report(vec![f.proposal(5, f.frame - 1, &[0, 1])])).unwrap();
    // Stale: the last frame of the previous epoch, held or not.
    let stale = 3 * epoch - 1;
    put_anchor(&f.clock, stale);
    refused_for(f.verify(&f.report(vec![f.proposal(5, stale, &[0, 1])])), "inclusion epoch");
    refused_for(f.verify(&f.report(vec![f.proposal(5, stale - 1, &[0, 1])])), "inclusion epoch");
    // Future: the inclusion frame itself, held or not, and a later one.
    put_anchor(&f.clock, f.frame);
    refused_for(f.verify(&f.report(vec![f.proposal(5, f.frame, &[0, 1])])), "inclusion epoch");
    refused_for(f.verify(&f.report(vec![f.proposal(5, f.frame + 1, &[0, 1])])), "inclusion epoch");
    // One out-of-epoch proposal refuses the report.
    let mixed = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, stale, &[1])]);
    refused_for(f.verify(&mixed), "inclusion epoch");
    // An in-epoch anchor this node does not hold is unavailable, not refused.
    let missing = f.report(vec![f.proposal(5, f.anchor + 1, &[0, 1])]);
    assert!(matches!(f.verify(&missing), Err(QuilError::ExecutionUnavailable(_))));
}

/// Signatures are checked before proposal outputs: a forged vote is refused
/// without the output check, and so without reading its anchor, which a
/// node lacking that anchor could not complete.
#[test]
fn forged_presence_vote_is_refused_before_its_anchor_is_read() {
    let f = fixture();
    let mut missing = f.report(vec![f.proposal(5, f.anchor + 1, &[0, 1])]);
    assert!(matches!(f.verify(&missing), Err(QuilError::ExecutionUnavailable(_))));
    missing.proposals[0].votes[0].signature[20] ^= 1;
    refused_for(f.verify(&missing), "notarize of the proposal");
}

#[test]
fn presence_report_of_a_foreign_session_or_filter_is_refused() {
    let f = fixture();
    let other = initial(vec![0x62; 32], &keys());
    initialize(&f.state, 2, &other).unwrap();
    commit(&f.state, 2);
    let valid = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&valid).unwrap();
    let mut unknown = valid.clone();
    unknown.session = [0x77; 32];
    refused_for(f.verify(&unknown), "unknown session");
    let mut filter = valid.clone();
    filter.filter = other.filter.clone();
    refused_for(f.verify(&filter), "another filter");
    let mut foreign = valid.clone();
    foreign.session = other.id().unwrap();
    foreign.filter = other.filter.clone();
    refused_for(f.verify(&foreign), "header belongs to another filter");
    // Votes for a header of the other filter.
    let mut header = valid.clone();
    header.proposals[0].header.address = other.filter.clone();
    f.reissue(&mut header.proposals[0], &[0, 1]);
    refused_for(f.verify(&header), "header belongs to another filter");
}

#[test]
fn presence_report_of_a_superseded_session_is_refused() {
    let f = fixture();
    let filter = f.session.filter.clone();
    let request = schedule(&f.state, 2, vec![filter.clone()], vec![desired(&filter, &f.keys)]).unwrap();
    commit(&f.state, 2);
    // A closing session still votes.
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&report).unwrap();
    apply_submission(&f.state, 3, &submission(&request, 0, &f.keys, 2)).unwrap();
    commit(&f.state, 3);
    assert_ne!(head(&f.state, &filter).unwrap().unwrap(), f.session);
    refused_for(f.verify(&report), "not the current head");
}

#[test]
fn presence_round_epoch_must_be_the_session_generation() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&report).unwrap();
    // Valid votes over the wrong epoch.
    report.proposals[0].epoch += 1;
    f.sign(&mut report.proposals[0], &[0, 1]);
    refused_for(f.verify(&report), "round epoch");
}

#[test]
fn presence_proposal_must_match_its_header() {
    let f = fixture();
    f.verify(&f.report(vec![f.proposal(5, f.anchor, &[0, 1])])).unwrap();
    let mut rank = f.proposal(5, f.anchor, &[0, 1]);
    rank.header.rank = 6;
    f.reissue(&mut rank, &[0, 1]);
    refused_for(f.verify(&f.report(vec![rank])), "header rank");
    let mut base = f.proposal(5, f.anchor, &[0, 1]);
    base.header.frame_number = f.session.base_frame;
    f.reissue(&mut base, &[0, 1]);
    refused_for(f.verify(&f.report(vec![base])), "session base");
    // A changed header field no longer reproduces the voted output.
    let mut output = f.proposal(5, f.anchor, &[0, 1]);
    output.header.timestamp = 9;
    refused_for(f.verify(&f.report(vec![output])), "header output");
    // Valid votes over a payload that is not the header's output digest.
    let mut payload = f.proposal(5, f.anchor, &[0, 1]);
    payload.payload[0] ^= 1;
    f.sign(&mut payload, &[0, 1]);
    refused_for(f.verify(&f.report(vec![payload])), "payload");
    // A header carrying its certificate.
    let mut certified = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    certified.proposals[0].header.public_key_signature_bls48581 = vec![1; 8];
    refused(f.verify(&certified));
    assert!(certified.to_canonical_bytes().is_err());
}

#[test]
fn presence_vote_of_a_non_member_index_is_refused() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0])]);
    f.verify(&report).unwrap();
    report.proposals[0].votes[0].signer = f.session.members.len() as u32;
    refused_for(f.verify(&report), "notarize");
}

#[test]
fn presence_duplicate_signer_is_refused() {
    let f = fixture();
    f.verify(&f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[1])])).unwrap();
    let mut within = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let bytes = within.to_canonical_bytes().unwrap();
    within.proposals[0].votes[1] = within.proposals[0].votes[0].clone();
    refused_for(f.verify(&within), "duplicate signer");
    assert!(within.to_canonical_bytes().is_err());
    // The same bytes with the second vote's signer index replaced by the first's.
    let mut patched = bytes.clone();
    let vote = 4 + quil_crypto::FALCON_SIGNATURE_LEN;
    let first = patched[patched.len() - 2 * vote..patched.len() - 2 * vote + 4].to_vec();
    let len = patched.len();
    patched[len - vote..len - vote + 4].copy_from_slice(&first);
    assert!(PresenceReport::from_canonical_bytes(&patched).is_err());
    // One member's votes on two proposals.
    let across = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[0])]);
    refused_for(f.verify(&across), "duplicate signer");
    assert!(across.to_canonical_bytes().is_err());
}

#[test]
fn oversize_presence_report_is_refused() {
    let f = fixture();
    // More votes than the session has members (checked before any signature).
    let mut members = f.report(vec![f.proposal(5, f.anchor, &[0, 1, 2, 3])]);
    f.verify(&members).unwrap();
    let signature = members.proposals[0].votes[0].signature.clone();
    members.proposals[0].votes.push(NotarizeVote { signer: 4, signature: signature.clone() });
    refused_for(f.verify(&members), "more votes than session members");
    // More votes than any report carries.
    let mut votes = f.report(vec![f.proposal(5, f.anchor, &[0])]);
    votes.proposals[0].votes = (0..=MAX_PRESENCE_VOTES as u32)
        .map(|signer| NotarizeVote { signer, signature: signature.clone() })
        .collect();
    refused_for(f.verify(&votes), "too many votes");
    assert!(votes.to_canonical_bytes().is_err());
    // More proposals than a report carries.
    let proposals = f.report(
        (0..=MAX_PRESENCE_PROPOSALS as u64).map(|i| f.proposal(5 + i, f.anchor, &[0])).collect(),
    );
    refused_for(f.verify(&proposals), "proposal count");
    assert!(proposals.to_canonical_bytes().is_err());
}

#[test]
fn presence_proposal_without_votes_is_refused() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[1])]);
    f.verify(&report).unwrap();
    report.proposals[1].votes.clear();
    refused_for(f.verify(&report), "no votes");
    assert!(report.to_canonical_bytes().is_err());
}

#[test]
fn presence_report_is_refused_before_its_activation_frame() {
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let bytes = report.to_canonical_bytes().unwrap();
    f.verify(&report).unwrap();
    set_presence_report_frame_for_thread(Some(f.frame + 1));
    refused_for(f.verify(&report), "presence report frame");
    // Refused before any state is needed, as an older build would.
    let bare = GlobalIntrinsic::new(Arc::new(crate::testing::NoopKeyManager));
    assert!(matches!(bare.validate(f.frame, &bytes, None, None), Err(QuilError::InvalidArgument(_))));
    assert!(f.intrinsic().invoke_step(f.frame, &bytes, &f.state).is_err());
    set_presence_report_frame_for_thread(Some(f.frame));
    f.verify(&report).unwrap();
    // Without a setting, never (assumes QUIL_PRESENCE_REPORT_FRAME is unset).
    set_presence_report_frame_for_thread(None);
    refused_for(f.verify(&report), "presence report frame");
    assert_eq!(MAINNET_PRESENCE_REPORT_FRAME, None);
    assert_eq!(presence_report_frame_for(0, None), u64::MAX);
    assert_eq!(presence_report_frame_for(0, Some("7")), u64::MAX);
    assert_eq!(presence_report_frame_for(1, Some("7")), 7);
    assert_eq!(presence_report_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(presence_report_frame_for(1, None), u64::MAX);
}

#[test]
fn engine_validates_a_lone_presence_report_and_refuses_it_beside_other_requests() {
    use crate::{
        engines::GlobalExecutionEngine,
        message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
    };
    use quil_types::execution::ShardExecutionEngine as _;
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let request = || Some(CanonicalMessageRequest::wrap(report.to_canonical_bytes().unwrap()).unwrap());
    let bundle = |requests| CanonicalMessageBundle { timestamp: 0, requests }.to_canonical_bytes().unwrap();
    let lone = bundle(vec![request()]);
    let engine = GlobalExecutionEngine::new_with_intrinsic(
        Arc::new(StubProver),
        Arc::new(crate::testing::NoopKeyManager),
        f.state.crdt().clone(),
        f.clock.clone(),
        None,
        None,
    );
    engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone).unwrap();
    engine.process_message(f.frame, &BigInt::from(0), &GLOBAL_INTRINSIC_ADDRESS, &lone).unwrap();
    for other in [bundle(vec![request(), request()]), bundle(vec![request(), None]), bundle(vec![None, request()])] {
        assert!(matches!(
            engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &other),
            Err(QuilError::InvalidArgument(_))
        ));
    }
    let stateless = GlobalExecutionEngine::new(Arc::new(StubProver));
    assert!(matches!(
        stateless.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    // Before activation every engine refuses it, with or without state.
    set_presence_report_frame_for_thread(Some(f.frame + 1));
    for engine in [&engine, &stateless] {
        assert!(matches!(
            engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone),
            Err(QuilError::InvalidArgument(_))
        ));
    }
}

/// The notarize of `signer` (an index into the fixture's keys) replaced by
/// its nullify of the same round, which a member can sign ahead for every
/// view.
fn nullify_signature(f: &Fixture, proposal: &PresenceProposal, signer: usize) -> Vec<u8> {
    let participants: Set<_> = f.keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
    let scheme: Generic<Namespace> =
        Generic::signer(&f.session.namespace().unwrap(), participants, f.keys[signer].clone()).unwrap();
    let round = Round::new(Epoch::new(proposal.epoch), View::new(proposal.view));
    let vote = scheme.sign::<SimplexFalconScheme, Digest>(Subject::Nullify { round }).unwrap();
    vote.signature.get().unwrap().to_vec()
}

/// An allocation of `member` on `filter` with `last_active` recorded.
fn seed_allocation(state: &HypergraphState, member: &[u8], filter: &[u8], last_active: Option<u64>) {
    use crate::global_schema::write_field;
    let mut tree = quil_tries::VectorCommitmentTree::new();
    write_field(&mut tree, "allocation:ProverAllocation", "Status", &[1]).unwrap();
    if let Some(frame) = last_active {
        write_field(&mut tree, "allocation:ProverAllocation", "LastActiveFrameNumber", &frame.to_be_bytes()).unwrap();
    }
    let address = crate::global_intrinsic::materialize::allocation_address(member, filter).unwrap();
    state
        .set(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &vertex_adds_discriminator().unwrap(), 1,
            crate::prover_registry::vertex_tree_to_blob(&tree))
        .unwrap();
}

/// The allocation blob of `member` on `filter`, if any.
fn allocation_blob(state: &HypergraphState, member: &[u8], filter: &[u8]) -> Option<Vec<u8>> {
    let address = crate::global_intrinsic::materialize::allocation_address(member, filter).unwrap();
    state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &vertex_adds_discriminator().unwrap()).unwrap()
}

/// `LastActiveFrameNumber` of `member`'s allocation on `filter`.
fn last_active(state: &HypergraphState, member: &[u8], filter: &[u8]) -> Option<u64> {
    let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&allocation_blob(state, member, filter)?);
    crate::global_schema::read_field(&tree, "allocation:ProverAllocation", "LastActiveFrameNumber")
        .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
}

/// The member indexes a report carries votes of.
fn voters(report: &PresenceReport) -> BTreeSet<usize> {
    report.proposals.iter().flat_map(|proposal| &proposal.votes).map(|vote| vote.signer as usize).collect()
}

fn marked(present: &[bool]) -> BTreeSet<usize> {
    present.iter().enumerate().filter(|(_, &member)| member).map(|(index, _)| index).collect()
}

impl Fixture {
    fn apply(&self, report: &PresenceReport) -> Result<presence::Applied> {
        presence::apply(&self.state, self.frame, report, |frame| self.intrinsic_anchor(frame))
    }

    fn intrinsic_anchor(&self, frame: u64) -> Result<Vec<u8>> {
        self.clock
            .get_global_clock_frame_header(frame)
            .map(|header| header.output)
            .map_err(|_| QuilError::ExecutionUnavailable(format!("anchor {frame} not held")))
    }

    fn epoch(&self) -> u64 {
        quil_types::consensus::epoch_for_frame(self.frame)
    }

    fn present(&self) -> Option<Vec<bool>> {
        presence::present(&self.state, &self.session, self.epoch()).unwrap()
    }

    /// An allocation for every member, last active at `last_active`, committed.
    fn seed_members(&self, last_active: u64) {
        for member in &self.session.members {
            seed_allocation(&self.state, member, &self.session.filter, Some(last_active));
        }
        commit(&self.state, 2);
    }
}

/// Credit for presence is GLOBAL consensus and not scheduled on mainnet; a
/// process that never fixed its network reads no setting.
#[test]
fn presence_credit_is_not_scheduled_by_default() {
    assert_eq!(MAINNET_PRESENCE_CREDIT_FRAME, None);
    assert_eq!(presence_credit_frame_for(0, None), u64::MAX);
    assert_eq!(presence_credit_frame_for(0, Some("7")), u64::MAX);
    assert_eq!(presence_credit_frame_for(1, Some("7")), 7);
    assert_eq!(presence_credit_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(presence_credit_frame_for(1, None), u64::MAX);
    set_presence_credit_frame_for_thread(None);
    assert_eq!(presence_credit_frame(), u64::MAX, "without init, the mainnet value");
}

/// Before the credit frame an accepted report writes nothing, as an older
/// build that accepts it; from it the report's voters are recorded present
/// for the inclusion epoch, and only for it.
#[test]
fn an_accepted_report_is_recorded_only_from_the_credit_frame() {
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let bytes = report.to_canonical_bytes().unwrap();
    set_presence_credit_frame_for_thread(Some(f.frame + 1));
    f.intrinsic().invoke_step(f.frame, &bytes, &f.state).unwrap();
    assert_eq!(f.state.changeset_len(), 0, "before the credit frame nothing is written");
    assert_eq!(f.present(), None);
    set_presence_credit_frame_for_thread(Some(f.frame));
    f.intrinsic().invoke_step(f.frame, &bytes, &f.state).unwrap();
    assert_eq!(marked(&f.present().unwrap()), voters(&report));
    assert_eq!(presence::present(&f.state, &f.session, f.epoch() + 1).unwrap(), None, "kept per epoch");
    set_presence_credit_frame_for_thread(None);
}

/// The record is the union of the epoch's reports, and each voter's credit
/// the latest anchor it voted at, whatever order the reports arrive in.
#[test]
fn the_presence_record_is_the_union_of_reports_in_any_order() {
    set_presence_credit_frame_for_thread(Some(0));
    let keys = keys();
    let one = fixture_with(keys.clone());
    let other = fixture_with(keys);
    assert_eq!(one.session, other.session);
    for f in [&one, &other] {
        put_anchor(&f.clock, f.anchor + 1);
        f.seed_members(1);
    }
    // Two votes each, enough for credit in a committee of four.
    let first = one.report(vec![one.proposal(5, one.anchor, &[0, 1])]);
    let second = one.report(vec![one.proposal(6, one.anchor + 1, &[2, 3])]);
    one.apply(&first).unwrap();
    let applied = one.apply(&second).unwrap();
    assert_eq!(applied.marked, voters(&second).difference(&voters(&first)).count());
    other.apply(&second).unwrap();
    other.apply(&first).unwrap();
    let union: BTreeSet<usize> = voters(&first).union(&voters(&second)).copied().collect();
    assert_eq!(marked(&one.present().unwrap()), union);
    assert_eq!(one.present(), other.present());
    for (index, member) in one.session.members.iter().enumerate() {
        let filter = &one.session.filter;
        assert_eq!(allocation_blob(&one.state, member, filter), allocation_blob(&other.state, member, filter));
        let expected = if voters(&second).contains(&index) {
            one.anchor + 1
        } else if voters(&first).contains(&index) {
            one.anchor
        } else {
            1
        };
        assert_eq!(last_active(&one.state, member, filter), Some(expected), "member {index}");
    }
    set_presence_credit_frame_for_thread(None);
}

/// A voter's activity is raised to its vote's anchor, not to the inclusion
/// frame, and never lowered; a voter without an allocation on the filter is
/// marked present but not credited.
#[test]
fn presence_credit_raises_activity_to_the_vote_anchor_and_never_lowers_it() {
    set_presence_credit_frame_for_thread(Some(0));
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1, 2])]);
    let votes: Vec<usize> = voters(&report).into_iter().collect();
    let member = |index: usize| f.session.members[index].clone();
    let filter = f.session.filter.clone();
    seed_allocation(&f.state, &member(votes[0]), &filter, Some(3));
    seed_allocation(&f.state, &member(votes[1]), &filter, Some(f.frame + 100));
    commit(&f.state, 2);
    let applied = f.apply(&report).unwrap();
    assert_eq!(applied, presence::Applied {
        marked: 3, credited: 1, present: 3, members: f.session.members.len(), ..presence::Applied::default()
    });
    assert_eq!(last_active(&f.state, &member(votes[0]), &filter), Some(f.anchor), "the anchor, not the inclusion frame");
    assert_eq!(last_active(&f.state, &member(votes[1]), &filter), Some(f.frame + 100), "never lowered");
    assert_eq!(allocation_blob(&f.state, &member(votes[2]), &filter), None, "no allocation is created");
    assert_eq!(marked(&f.present().unwrap()), voters(&report));
    set_presence_credit_frame_for_thread(None);
}

/// Forged, stale, foreign-session and nullify evidence is refused and
/// changes nothing; a report that marks no new member is refused, so the
/// epoch's reports of a session are bounded by its members.
#[test]
fn presence_credit_refuses_forged_stale_foreign_duplicate_and_nullify_evidence() {
    set_presence_credit_frame_for_thread(Some(0));
    let f = fixture();
    f.seed_members(1);
    // Every state change so far is committed: a refused report stages none.
    let unchanged = |result: Result<presence::Applied>, reason: &str| {
        match result {
            Err(QuilError::InvalidArgument(message)) => assert!(message.contains(reason), "{message}"),
            other => panic!("expected refusal for {reason}, got {other:?}"),
        }
        assert_eq!(f.state.changeset_len(), 0, "{reason}: nothing staged");
        assert_eq!(f.present(), None, "{reason}: nothing recorded");
        for member in &f.session.members {
            assert_eq!(last_active(&f.state, member, &f.session.filter), Some(1), "{reason}: nothing credited");
        }
    };
    let valid = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    // Forged: a flipped signature bit.
    let mut forged = valid.clone();
    forged.proposals[0].votes[0].signature[20] ^= 1;
    unchanged(f.apply(&forged), "notarize");
    // Stale: anchored in the previous epoch.
    let stale = 3 * quil_types::consensus::epoch_length_frames() - 1;
    put_anchor(&f.clock, stale);
    unchanged(f.apply(&f.report(vec![f.proposal(5, stale, &[0, 1])])), "inclusion epoch");
    // Foreign session: valid votes of this session named for another.
    let other = initial(vec![0x62; 32], &keys());
    initialize(&f.state, 3, &other).unwrap();
    commit(&f.state, 3);
    let mut foreign = valid.clone();
    foreign.session = other.id().unwrap();
    foreign.filter = other.filter.clone();
    unchanged(f.apply(&foreign), "another filter");
    assert_eq!(presence::present(&f.state, &other, f.epoch()).unwrap(), None);
    // A pre-signed nullify presented as a notarize.
    let mut nullified = f.report(vec![f.proposal(5, f.anchor, &[0])]);
    nullified.proposals[0].votes[0].signature = nullify_signature(&f, &nullified.proposals[0], 0);
    unchanged(f.apply(&nullified), "notarize");
    // Duplicate: the same voters again mark nothing new.
    let applied = f.apply(&valid).unwrap();
    assert_eq!(applied.marked, 2);
    let recorded = f.present();
    let before = f.state.changeset_len();
    match f.apply(&valid) {
        Err(QuilError::InvalidArgument(message)) => assert!(message.contains("marks no member"), "{message}"),
        other => panic!("a duplicate report was not refused: {other:?}"),
    }
    let mut again = f.report(vec![f.proposal(7, f.anchor, &[0, 1])]);
    assert!(voters(&again) == voters(&valid));
    assert!(f.apply(&again).is_err(), "other proposals of the same voters mark nothing new");
    assert_eq!((f.state.changeset_len(), f.present()), (before, recorded));
    // One new voter beside recorded ones is accepted, and marks only it.
    again = f.report(vec![f.proposal(7, f.anchor, &[0, 1, 2])]);
    assert_eq!(f.apply(&again).unwrap().marked, 1);
    set_presence_credit_frame_for_thread(None);
}

/// A filter's mark record holds its current and previous epoch in two
/// slots: a slot holding another epoch reads as no record, a corrupt one is a
/// store error, and a later epoch's write replaces the slot it reuses.
#[test]
fn presence_records_cycle_through_two_epoch_slots() {
    set_presence_credit_frame_for_thread(Some(0));
    let f = fixture();
    let epoch = f.epoch();
    let key = |epoch: u64| {
        let mut key = (f.session.filter.len() as u32).to_be_bytes().to_vec();
        key.extend_from_slice(&f.session.filter);
        key.push((epoch % 2) as u8);
        key
    };
    let record = |version: u8, epoch: u64, bitmap: &[u8]| {
        let mut value = vec![version];
        value.extend_from_slice(&epoch.to_be_bytes());
        value.extend_from_slice(&1u32.to_be_bytes());
        value.extend_from_slice(&f.session.id().unwrap());
        value.extend_from_slice(&(bitmap.len() as u32).to_be_bytes());
        value.extend_from_slice(bitmap);
        value
    };
    // Four members fit one byte: a bit past the last member, a second byte,
    // another version or a truncated record is not one this build writes.
    for value in [record(1, epoch, &[0b0001_0011]), record(1, epoch, &[0, 0]), record(2, epoch, &[0]), vec![1]] {
        write(&f.state, f.frame, b"presence", &key(epoch), &value).unwrap();
        assert!(matches!(presence::present(&f.state, &f.session, epoch), Err(QuilError::Store(_))), "{value:?}");
    }
    write(&f.state, f.frame, b"presence", &key(epoch), &record(1, epoch, &[0b0000_1001])).unwrap();
    assert_eq!(f.present(), Some(vec![true, false, false, true]));
    assert_eq!(presence::present(&f.state, &f.session, epoch + 2).unwrap(), None, "the slot holds another epoch");
    // A report two epochs on reuses the slot and replaces it.
    let later = f.frame + 2 * quil_types::consensus::epoch_length_frames();
    let anchor = later - 3;
    put_anchor(&f.clock, anchor);
    let report = f.report(vec![f.proposal(5, anchor, &[0])]);
    presence::apply(&f.state, later, &report, |frame| f.intrinsic_anchor(frame)).unwrap();
    assert_eq!(f.present(), None, "the older epoch is gone");
    assert_eq!(marked(&presence::present(&f.state, &f.session, epoch + 2).unwrap().unwrap()), voters(&report));
    set_presence_credit_frame_for_thread(None);
}

/// Only a proposal that more members notarized than the committee's
/// tolerated faults earns its voters credit: one of them is honest, and an
/// honest member notarizes only its leader's real proposal. A member
/// notarizing a header it made up, at a view it picked, proves its key
/// alive and is marked present, but earns nothing.
#[test]
fn presence_credit_needs_more_notarizes_than_the_committee_tolerates_faults() {
    assert_eq!([1, 4, 7, 23, 26].map(presence::credited_votes), [1, 2, 3, 8, 9]);
    set_presence_credit_frame_for_thread(Some(0));
    let f = fixture();
    f.seed_members(1);
    let alone = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(9, f.anchor, &[1])]);
    let applied = f.apply(&alone).unwrap();
    assert_eq!((applied.marked, applied.credited), (2, 0), "one vote each: marked, not credited");
    for member in &f.session.members {
        assert_eq!(last_active(&f.state, member, &f.session.filter), Some(1));
    }
    let pair = f.report(vec![f.proposal(6, f.anchor, &[0, 2])]);
    let applied = f.apply(&pair).unwrap();
    assert_eq!((applied.marked, applied.credited), (1, 2), "two of four: one is honest");
    set_presence_credit_frame_for_thread(None);
}

/// A report whose new marks are forged is refused after one signature
/// check, whatever else it carries: new marks are verified first.
#[test]
fn a_report_with_forged_new_marks_is_refused_at_its_first_signature() {
    set_presence_credit_frame_for_thread(Some(0));
    let f = fixture();
    f.apply(&f.report(vec![f.proposal(5, f.anchor, &[0, 1, 2])])).unwrap();
    let recorded = marked(&f.present().unwrap());
    // Recorded members' votes on an earlier view, the one new member's,
    // forged, on a later one.
    let mut report = f.report(vec![f.proposal(6, f.anchor, &[0, 1, 2]), f.proposal(7, f.anchor, &[3])]);
    assert!(!recorded.contains(&(report.proposals[1].votes[0].signer as usize)));
    report.proposals[1].votes[0].signature[20] ^= 1;
    let checks = std::cell::Cell::new(0);
    let result = presence::verify(&f.state, f.frame, &report, |frame| {
        checks.set(checks.get() + 1);
        f.intrinsic_anchor(frame)
    });
    assert!(matches!(result, Err(QuilError::InvalidArgument(_))), "{result:?}");
    // The forged vote is the first checked, and its signature before
    // any proposal's output lookup.
    assert_eq!(checks.get(), 0);
    set_presence_credit_frame_for_thread(None);
}

/// One slot holds at most sixteen sessions of a filter in an epoch; a
/// seventeenth is refused, and a recorded session can still be updated.
#[test]
fn a_presence_slot_holds_at_most_sixteen_sessions() {
    let f = fixture();
    let epoch = f.epoch();
    let session = |generation: u64| Session { generation, ..f.session.clone() };
    for generation in 1..=16 {
        presence::set_marks(&f.state, f.frame, b"presence", &session(generation), epoch, &[true, false, false, false])
            .unwrap();
    }
    let overflow = presence::set_marks(&f.state, f.frame, b"presence", &session(17), epoch, &[true, false, false, false]);
    assert!(matches!(overflow, Err(QuilError::InvalidArgument(_))), "{overflow:?}");
    presence::set_marks(&f.state, f.frame, b"presence", &session(16), epoch, &[true, true, false, false]).unwrap();
    assert_eq!(presence::present(&f.state, &session(16), epoch).unwrap(), Some(vec![true, true, false, false]));
    assert_eq!(presence::present(&f.state, &session(1), epoch).unwrap(), Some(vec![true, false, false, false]));
    assert_eq!(presence::present(&f.state, &session(17), epoch).unwrap(), None);
}

/// The credit threshold is one more than the faults commonware's own N3f1
/// rule tolerates, the rule the session's Simplex quorum follows.
#[test]
fn credited_votes_is_one_more_than_the_tolerated_faults_of_n3f1() {
    use quil_cw_consensus::_utils::Faults as _;
    for members in 1..=64u32 {
        let faults = N3f1::max_faults(members);
        assert_eq!(members - N3f1::quorum(members), faults);
        assert_eq!(presence::credited_votes(members as usize), faults as usize + 1, "{members} members");
    }
}
