//! Silent-prover early successor
//! ([`crate::global_intrinsic::handoff::silence`]): a stalled session fenced
//! early without the members silent on every shard they serve.

use super::*;
use crate::global_intrinsic::handoff::exclusion;
use crate::global_intrinsic::handoff::silence::{self, Settings};
use quil_types::consensus::{ProverAllocationInfo, ProverStatus};
use std::collections::HashMap;

const K: u64 = silence::WINDOW_FRAMES;
const PASS: u64 = schedule::SESSION_PASS_FRAMES;

/// The epoch the shards' first sessions start in.
const FIRST: u64 = 10;

fn epoch_start(epoch: u64) -> u64 {
    epoch * quil_types::consensus::epoch_length_frames()
}

fn start() -> u64 {
    epoch_start(FIRST)
}

/// The first session pass at or after `frame`.
fn pass_at(frame: u64) -> u64 {
    frame.div_ceil(PASS) * PASS
}

/// Signed-frame recording at `signed`, the silent fence at `silent`, and
/// fenced successors from current eligibility, for the test's thread.
struct Gates;

impl Gates {
    fn on() -> Self {
        Self::with(Some(0), Some(0))
    }

    fn with(signed: Option<u64>, silent: Option<u64>) -> Self {
        quil_types::consensus::set_signed_frame_activation_frame_for_thread(signed);
        set_silent_frame(silent);
        set_fenced_successor_eligibility_frame_for_thread(Some(0));
        Self
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        quil_types::consensus::set_signed_frame_activation_frame_for_thread(None);
        silence::set_settings_for_thread(None);
        set_fenced_successor_eligibility_frame_for_thread(None);
    }
}

fn set_silent_frame(frame: Option<u64>) {
    silence::set_settings_for_thread(Some(Settings {
        frame: frame.unwrap_or(u64::MAX),
        window: K,
        evidence: silence::EVIDENCE_SHARDS,
    }));
}

/// Membership and first sessions frozen to the epoch's first pass, as on
/// mainnet.
fn frozen_policy() -> quil_types::consensus::CommitteeHandoffPolicy {
    quil_types::consensus::CommitteeHandoffPolicy {
        membership_boundary_frame: 0,
        first_session_boundary_frame: 0,
        ..policy()
    }
}

struct Prover {
    key: Vec<u8>,
    /// The filters it holds an allocation on.
    shards: Vec<Vec<u8>>,
    /// The latest GLOBAL frame any of its allocations signed at.
    last_signed: u64,
}

/// One stalled shard and `others` shards beside it, each with a first
/// session from [`start`] seating the provers allocated on it.
struct Net {
    _db: quil_store::RocksDb,
    state: HypergraphState,
    stalled: Vec<u8>,
    others: Vec<Vec<u8>>,
    provers: Vec<Prover>,
    data_frames: std::cell::RefCell<HashMap<Vec<u8>, u64>>,
}

impl Net {
    /// `n` provers on the stalled shard; prover `i` also holds the other
    /// shards `holdings(i)` (indexes below `others`).
    fn new(n: usize, others: usize, holdings: &dyn Fn(usize) -> Vec<usize>) -> Self {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        commit(&state, 1);
        let stalled = vec![0x30; 32];
        let others: Vec<Vec<u8>> = (0..others).map(|j| vec![0x40 + j as u8; 32]).collect();
        let provers = (0..n)
            .map(|i| {
                let signer = quil_crypto::FalconSigner::generate();
                let mut shards = vec![stalled.clone()];
                shards.extend(holdings(i).into_iter().map(|j| others[j].clone()));
                Prover {
                    key: signer.public_key().to_vec(),
                    shards,
                    last_signed: start() - 1,
                }
            })
            .collect();
        let net = Self {
            _db: db,
            state,
            stalled,
            others,
            provers,
            data_frames: Default::default(),
        };
        let created = schedule::reconcile_membership(
            &net.state,
            start(),
            &frozen_policy(),
            &net.filters(),
            &net.scan(),
        )
        .unwrap();
        assert!(created >= 1);
        commit(&net.state, start());
        assert_eq!(net.head().members.len(), n);
        net
    }

    fn filters(&self) -> Vec<Vec<u8>> {
        let mut filters = self.others.clone();
        filters.push(self.stalled.clone());
        filters.sort();
        filters
    }

    fn scan(&self) -> crate::prover_registry::CommittedProverScan {
        let mut pubkeys = HashMap::new();
        let mut allocations = Vec::new();
        for prover in &self.provers {
            let address = quil_crypto::poseidon::hash_bytes_to_32(&prover.key)
                .unwrap()
                .to_vec();
            pubkeys.insert(address.clone(), prover.key.clone());
            for filter in &prover.shards {
                allocations.push((
                    address.clone(),
                    ProverAllocationInfo {
                        status: ProverStatus::Active,
                        confirmation_filter: filter.clone(),
                        rejection_filter: vec![],
                        join_frame_number: 0,
                        leave_frame_number: 0,
                        pause_frame_number: 0,
                        resume_frame_number: 0,
                        kick_frame_number: 0,
                        join_confirm_frame_number: 0,
                        join_reject_frame_number: 0,
                        leave_confirm_frame_number: 0,
                        leave_reject_frame_number: 0,
                        last_active_frame_number: 0,
                        last_signed_frame_number: prover.last_signed,
                        epoch: u64::MAX,
                        ring: 0,
                        vertex_address: vec![],
                    },
                ));
            }
        }
        crate::prover_registry::CommittedProverScan::from_parts(pubkeys, allocations)
    }

    fn key(&self, index: usize) -> Vec<u8> {
        self.provers[index].key.clone()
    }

    /// The keys of `indexes`, sorted.
    fn keys(&self, indexes: impl IntoIterator<Item = usize>) -> Vec<Vec<u8>> {
        let mut keys: Vec<_> = indexes.into_iter().map(|index| self.key(index)).collect();
        keys.sort();
        keys
    }

    fn head(&self) -> Session {
        head(&self.state, &self.stalled).unwrap().unwrap()
    }

    /// GLOBAL executes a new data frame of `filter`'s head session at
    /// `frame`.
    fn advance(&self, filter: &[u8], frame: u64) {
        let id = head(&self.state, filter).unwrap().unwrap().id().unwrap();
        let mut frames = self.data_frames.borrow_mut();
        let next = frames.entry(filter.to_vec()).or_insert(0);
        *next += 1;
        record_session_tip(
            &self.state,
            frame,
            &id,
            &tip(*next, *next, [*next as u8; 32]),
        )
        .unwrap();
        commit(&self.state, frame);
    }

    /// The other shards at `indexes` produce at `frame`.
    fn produce(&self, indexes: impl IntoIterator<Item = usize>, frame: u64) {
        for index in indexes {
            self.advance(&self.others[index].clone(), frame);
        }
    }

    /// Provers at `indexes` sign an included frame at `frame`.
    fn sign(&mut self, indexes: impl IntoIterator<Item = usize>, frame: u64) {
        for index in indexes {
            self.provers[index].last_signed = frame;
        }
    }

    /// The seats of provers at `indexes` on the stalled shard lapse.
    fn lapse(&mut self, indexes: impl IntoIterator<Item = usize>) {
        for index in indexes {
            let stalled = self.stalled.clone();
            self.provers[index]
                .shards
                .retain(|filter| *filter != stalled);
        }
    }

    /// A new prover allocated on the stalled shard alone; its index.
    fn join(&mut self) -> usize {
        let signer = quil_crypto::FalconSigner::generate();
        self.provers.push(Prover {
            key: signer.public_key().to_vec(),
            shards: vec![self.stalled.clone()],
            last_signed: 0,
        });
        self.provers.len() - 1
    }

    /// A session pass at `frame` as GLOBAL runs it
    /// (`GlobalIntrinsic::reconcile_committee_sessions`) without presence
    /// exclusion: the silent-prover evaluator and its fences, due fences,
    /// then the membership pass. Returns the decisions and how many sessions
    /// the evaluator fenced.
    fn pass(&self, frame: u64) -> (Vec<silence::Decision>, usize) {
        let scan = self.scan();
        let filters = self.filters();
        let stalled = silence::stalled(&self.state, frame, &filters).unwrap();
        let mut desired = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            let desired = schedule::desired_members(&scan, filter, frame);
            let desired = exclusion::seated(&self.state, frame, filter, desired)?;
            silence::seated(&self.state, frame, filter, desired, &scan)
        };
        let decisions =
            silence::evaluate(&self.state, frame, &stalled, &scan, &mut desired).unwrap();
        let fenced = silence::fence(&self.state, frame, &decisions).unwrap();
        schedule::fence_stalled_sources(&self.state, frame, &filters, Some(&mut desired)).unwrap();
        schedule::reconcile_membership(&self.state, frame, &frozen_policy(), &filters, &scan)
            .unwrap();
        commit(&self.state, frame);
        (decisions, fenced)
    }

    /// [`Self::pass`] with release-base APIs only: due fences and the
    /// membership pass.
    fn base_pass(&self, frame: u64) {
        let scan = self.scan();
        let filters = self.filters();
        let mut desired = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            let desired = schedule::desired_members(&scan, filter, frame);
            exclusion::seated(&self.state, frame, filter, desired)
        };
        schedule::fence_stalled_sources(&self.state, frame, &filters, Some(&mut desired)).unwrap();
        schedule::reconcile_membership(&self.state, frame, &frozen_policy(), &filters, &scan)
            .unwrap();
        commit(&self.state, frame);
    }

    /// Every other shard produces and the provers at `present` sign, just
    /// before the pass at `frame`.
    fn live_before(&mut self, present: impl IntoIterator<Item = usize> + Clone, frame: u64) {
        self.produce(0..self.others.len(), frame - 5);
        self.sign(present, frame - 5);
    }

    fn excluded(&self, index: usize) -> Option<silence::Exclusion> {
        silence::exclusion(&self.state, &self.stalled, &self.key(index)).unwrap()
    }

    fn excluded_keys(decision: &silence::Decision) -> Vec<Vec<u8>> {
        decision
            .excluded
            .iter()
            .map(|(key, _)| key.clone())
            .collect()
    }
}

fn all(others: usize) -> impl Fn(usize) -> Vec<usize> {
    move |_| (0..others).collect()
}

fn sorted(mut keys: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    keys.sort();
    keys
}

/// Release-base behaviour (base APIs only): a 17-member session whose 5
/// members went silent on every shard stays the shard's head at stall + K,
/// and is fenced only at the timeout of the membership request the next
/// epoch boundary makes once their seats lapse.
#[test]
fn a_session_stalled_by_silent_provers_waits_for_its_timeout_fence() {
    let _gates = Gates::with(None, None);
    let mut net = Net::new(17, 4, &all(4));
    let first = net.head();
    let id = first.id().unwrap();
    let f = pass_at(start() + K);
    net.live_before(0..12, f);
    net.base_pass(f);
    assert_eq!(net.head(), first, "nothing changes at stall + K");
    assert_eq!(status(&net.state, &id).unwrap(), Status::Active);
    net.lapse(12..17);
    let boundary = epoch_start(FIRST + 1);
    net.base_pass(boundary);
    let Status::Sealing(request_id) = status(&net.state, &id).unwrap() else {
        panic!("the boundary asks the session to close");
    };
    let requested = request(&net.state, &request_id).unwrap().unwrap().frame;
    assert_eq!(requested, boundary);
    let due = schedule::fence_due_frame(requested);
    net.base_pass(due - PASS);
    assert!(
        !is_fenced(&net.state, &id).unwrap(),
        "not before its timeout"
    );
    net.base_pass(due);
    assert!(is_fenced(&net.state, &id).unwrap());
    assert_eq!(schedule::fence_frame(&net.state, &id).unwrap(), Some(due));
    assert_eq!(net.head().members, net.keys(0..12));
}

/// With the silent fence scheduled, the same session is fenced at the first
/// pass after K frames of stall, not before; its successor seats the 12
/// present members, who reach its quorum, and the 5 silent ones are
/// recorded excluded at the fence.
#[test]
fn a_session_stalled_by_silent_provers_is_fenced_after_k_frames_without_them() {
    let _gates = Gates::on();
    let mut net = Net::new(17, 4, &all(4));
    let first = net.head();
    let id = first.id().unwrap();
    let f = pass_at(start() + K);
    net.live_before(0..12, f - PASS);
    assert_eq!(net.pass(f - PASS), (vec![], 0), "not before K frames");
    net.live_before(0..12, f);
    let (decisions, fenced) = net.pass(f);
    assert_eq!(fenced, 1);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].session, id);
    assert_eq!(sorted(Net::excluded_keys(&decisions[0])), net.keys(12..17));
    assert!(is_fenced(&net.state, &id).unwrap());
    assert_eq!(
        schedule::fence_frame(&net.state, &id).unwrap(),
        Some(f),
        "dated at the early fence"
    );
    let successor = net.head();
    assert_eq!(successor.generation, 2);
    assert_eq!(successor.members, net.keys(0..12));
    assert!(exclusion::quorum(successor.members.len()) <= 12);
    assert_eq!(
        status(&net.state, &successor.id().unwrap()).unwrap(),
        Status::Active
    );
    for index in 12..17 {
        assert_eq!(
            net.excluded(index),
            Some(silence::Exclusion {
                excluded_at: f,
                ended_at: 0
            })
        );
    }
    for index in 0..12 {
        assert_eq!(net.excluded(index), None);
    }
}

/// One step removes at most ⌊(n−1)/3⌋ silent members, the longest silent
/// first; the rest stay seated.
#[test]
fn one_step_removes_at_most_a_third_longest_silent_first() {
    let _gates = Gates::on();
    let mut net = Net::new(7, 4, &all(4));
    let s = start();
    net.provers[4].last_signed = s - 30;
    net.provers[5].last_signed = s - 10;
    net.provers[6].last_signed = s - 20;
    let f = pass_at(s + K);
    net.live_before(0..4, f);
    let (decisions, fenced) = net.pass(f);
    assert_eq!(fenced, 1);
    assert_eq!(
        decisions[0].excluded,
        vec![(net.key(4), s - 30), (net.key(6), s - 20)],
        "two of three, longest silent first"
    );
    assert_eq!(net.head().members, net.keys([0, 1, 2, 3, 5]));
    assert_eq!(net.excluded(5), None);
}

/// A step that would leave fewer than the consensus minimum is skipped; a
/// prover that joins the shard later makes it possible at the next
/// evaluation, K frames on.
#[test]
fn a_step_never_cuts_a_committee_below_the_minimum() {
    let _gates = Gates::on();
    let mut net = Net::new(4, 4, &all(4));
    let first = net.head();
    let f = pass_at(start() + K);
    net.live_before(0..3, f);
    assert_eq!(net.pass(f), (vec![], 0));
    assert_eq!(net.head(), first);
    let joiner = net.join();
    let f2 = pass_at(start() + 2 * K);
    net.live_before(0..3, f2);
    let (decisions, fenced) = net.pass(f2);
    assert_eq!(fenced, 1);
    assert_eq!(Net::excluded_keys(&decisions[0]), vec![net.key(3)]);
    assert_eq!(net.head().members, net.keys([0, 1, 2, joiner]));
}

/// A step after which the members that signed in the window would not
/// reach the successor's quorum is skipped; the session is fenced at its
/// normal timeout instead.
#[test]
fn a_step_needs_the_present_members_to_reach_the_new_quorum() {
    let _gates = Gates::on();
    let mut net = Net::new(7, 4, &all(4));
    let id = net.head().id().unwrap();
    let f = pass_at(start() + K);
    net.live_before(0..3, f);
    assert_eq!(net.pass(f), (vec![], 0));
    assert_eq!(status(&net.state, &id).unwrap(), Status::Active);
    net.lapse(3..7);
    let boundary = epoch_start(FIRST + 1);
    net.live_before(0..3, boundary);
    assert_eq!(net.pass(boundary).1, 0);
    let Status::Sealing(request_id) = status(&net.state, &id).unwrap() else {
        panic!("the boundary asks the session to close");
    };
    let due = schedule::fence_due_frame(request(&net.state, &request_id).unwrap().unwrap().frame);
    net.live_before(0..3, due - PASS);
    net.pass(due - PASS);
    assert!(!is_fenced(&net.state, &id).unwrap());
    net.live_before(0..3, due);
    assert_eq!(net.pass(due).1, 0, "the timeout fence, not an early one");
    assert!(is_fenced(&net.state, &id).unwrap());
    assert_eq!(schedule::fence_frame(&net.state, &id).unwrap(), Some(due));
    assert_eq!(net.head().members, net.keys(0..3));
}

/// A member silent with fewer than M other producing shards counts as
/// present, so the stall is not explained and nothing is fenced; once its
/// third shard produces, the next evaluation fences the session.
#[test]
fn silence_needs_m_other_producing_shards() {
    let _gates = Gates::on();
    // Shard 3 is held by provers 0..4 and 16 only; 16 lacks shard 2.
    let holdings = |i: usize| match i {
        0..=3 => vec![0, 1, 2, 3],
        16 => vec![0, 1, 3],
        _ => vec![0, 1, 2],
    };
    let mut net = Net::new(17, 4, &holdings);
    let first = net.head();
    let f = pass_at(start() + K);
    net.produce(0..3, f - 5);
    net.sign(0..12, f - 5);
    assert_eq!(
        net.pass(f),
        (vec![], 0),
        "four silent: 13 others exceed the quorum"
    );
    assert_eq!(net.head(), first);
    let f2 = pass_at(start() + 2 * K);
    net.live_before(0..12, f2);
    let (decisions, fenced) = net.pass(f2);
    assert_eq!(fenced, 1);
    assert_eq!(sorted(Net::excluded_keys(&decisions[0])), net.keys(12..17));
}

/// A member with no allocation but the stalled one has no evidence of
/// silence: it is never excluded, while silent members with evidence are.
#[test]
fn a_single_allocation_member_is_never_excluded() {
    let _gates = Gates::on();
    let holdings = |i: usize| if i == 9 { vec![] } else { vec![0, 1, 2, 3] };
    let mut net = Net::new(10, 4, &holdings);
    let s = start();
    net.provers[6].last_signed = s - 30;
    net.provers[7].last_signed = s - 20;
    net.provers[8].last_signed = s - 10;
    net.provers[9].last_signed = 0;
    let f = pass_at(s + K);
    net.live_before(0..6, f);
    let (decisions, fenced) = net.pass(f);
    assert_eq!(fenced, 1);
    assert_eq!(sorted(Net::excluded_keys(&decisions[0])), net.keys(6..9));
    assert_eq!(net.excluded(9), None);
    assert!(net.head().members.contains(&net.key(9)));
}

/// Six members (quorum 5): S (4) and four others on all four other shards,
/// U (5) on two of them only; and a newcomer allocated on the stalled shard
/// alone, whose index is returned.
fn unproven_and_newcomer() -> (Net, usize) {
    let holdings = |i: usize| if i == 5 { vec![0, 1] } else { vec![0, 1, 2, 3] };
    let mut net = Net::new(6, 4, &holdings);
    let newcomer = net.join();
    (net, newcomer)
}

/// S silent with evidence, U without a signature in the window but with
/// too few other shards to show it silent (unproven), four signing. Without
/// S the committee is six again (the newcomer joins; quorum 5) and only the
/// four that signed count towards it: U is not counted on, so nothing is
/// fenced early and the session waits for its timeout.
#[test]
fn an_unproven_member_does_not_count_towards_the_new_quorum() {
    let _gates = Gates::on();
    let (mut net, _) = unproven_and_newcomer();
    let first = net.head();
    let id = first.id().unwrap();
    let f = pass_at(start() + K);
    assert_eq!(
        schedule::desired_members(&net.scan(), &net.stalled, f).len(),
        7,
        "setup: the six members and the newcomer are eligible"
    );
    net.live_before(0..4, f);
    assert_eq!(
        net.pass(f),
        (vec![], 0),
        "four signed: under quorum 5 of the six-seat successor"
    );
    assert_eq!(net.head(), first);
    assert_eq!(status(&net.state, &id).unwrap(), Status::Active);
    assert_eq!(net.excluded(4), None);
}

/// The same session with U signing at the window's first frame: five
/// members signed, so the successor (S out, the newcomer in) is seated at
/// once with U kept.
#[test]
fn a_member_that_signed_in_the_window_counts_towards_the_new_quorum() {
    let _gates = Gates::on();
    let (mut net, newcomer) = unproven_and_newcomer();
    let id = net.head().id().unwrap();
    let f = pass_at(start() + K);
    net.live_before(0..4, f);
    net.sign([5], f - K + 1);
    let (decisions, fenced) = net.pass(f);
    assert_eq!(fenced, 1);
    assert_eq!(decisions[0].session, id);
    assert_eq!(Net::excluded_keys(&decisions[0]), vec![net.key(4)]);
    let committee = net.keys([0, 1, 2, 3, 5, newcomer]);
    assert_eq!(decisions[0].committee, committee);
    assert_eq!(net.head().members, committee);
}

/// A stall that silence does not explain (more than a quorum not silent) is
/// left alone, whatever the silent members are.
#[test]
fn a_stall_not_explained_by_silence_is_left_alone() {
    let _gates = Gates::on();
    let mut net = Net::new(7, 4, &all(4));
    let first = net.head();
    let f = pass_at(start() + K);
    net.live_before(0..6, f);
    assert_eq!(
        net.pass(f),
        (vec![], 0),
        "six of seven signing: quorum 5 exceeded"
    );
    assert_eq!(net.head(), first);
    assert_eq!(net.excluded(6), None);
}

/// The shape of shard …0005f8 on 2026-11-04: 10 members, 5 silent. The
/// first step removes three (the cap), leaving 7 at quorum 5; the second,
/// once that successor itself stalled K frames and not before, removes the
/// other two, leaving the 5 present members at quorum 4.
#[test]
fn a_small_committee_recovers_in_two_steps() {
    let _gates = Gates::on();
    let mut net = Net::new(10, 4, &all(4));
    let s = start();
    for (index, back) in [(5, 50), (6, 40), (7, 30), (8, 20), (9, 10)] {
        net.provers[index].last_signed = s - back;
    }
    let f1 = pass_at(s + K);
    net.live_before(0..5, f1);
    let (decisions, fenced) = net.pass(f1);
    assert_eq!(fenced, 1);
    assert_eq!(
        Net::excluded_keys(&decisions[0]),
        vec![net.key(5), net.key(6), net.key(7)]
    );
    let step = net.head();
    assert_eq!(step.members, net.keys([0, 1, 2, 3, 4, 8, 9]));
    net.live_before(0..5, f1 + PASS);
    assert_eq!(net.pass(f1 + PASS), (vec![], 0), "one step per K frames");
    let f2 = pass_at(f1 + K);
    net.live_before(0..5, f2);
    let (decisions, fenced) = net.pass(f2);
    assert_eq!(fenced, 1);
    assert_eq!(decisions[0].session, step.id().unwrap());
    assert_eq!(
        Net::excluded_keys(&decisions[0]),
        vec![net.key(8), net.key(9)]
    );
    let last = net.head();
    assert_eq!(last.generation, 3);
    assert_eq!(last.members, net.keys(0..5));
    assert_eq!(net.excluded(8).unwrap().excluded_at, f2);
    assert_eq!(net.excluded(5).unwrap().excluded_at, f1);
}

/// An excluded member that signs again anywhere is seated again by the
/// membership successor of the next epoch boundary, which the live
/// successor seals (no fence); not mid-epoch. Its exclusion closes there,
/// once; members still silent stay excluded.
#[test]
fn an_excluded_member_is_seated_again_at_the_boundary_after_it_signs() {
    let _gates = Gates::on();
    let mut net = Net::new(17, 4, &all(4));
    let f = pass_at(start() + K);
    net.live_before(0..12, f);
    assert_eq!(net.pass(f).1, 1);
    let successor = net.head();
    let id = successor.id().unwrap();
    net.advance(&net.stalled.clone(), f + 10);
    net.sign([12], f + 10);
    let middle = pass_at(f + 50);
    net.live_before(0..12, middle);
    net.advance(&net.stalled.clone(), middle - 2);
    assert_eq!(net.pass(middle), (vec![], 0));
    assert_eq!(net.head(), successor, "not mid-epoch");
    assert_eq!(status(&net.state, &id).unwrap(), Status::Active);
    let boundary = epoch_start(FIRST + 1);
    net.live_before(0..13, boundary);
    net.advance(&net.stalled.clone(), boundary - 2);
    assert_eq!(net.pass(boundary), (vec![], 0));
    let Status::Sealing(request_id) = status(&net.state, &id).unwrap() else {
        panic!("the boundary asks the live successor to seal");
    };
    let pending = request(&net.state, &request_id).unwrap().unwrap();
    assert_eq!(pending.targets[0].committee.members, net.keys(0..13));
    assert!(!is_fenced(&net.state, &id).unwrap());
    assert_eq!(
        net.excluded(12),
        Some(silence::Exclusion {
            excluded_at: f,
            ended_at: boundary
        })
    );
    assert_eq!(net.excluded(13).unwrap().ended_at, 0);
    let scan = net.scan();
    let everyone = net.keys(0..17);
    assert_eq!(
        silence::seated(&net.state, boundary + PASS, &net.stalled, everyone, &scan).unwrap(),
        net.keys(0..13)
    );
}

/// The schedule: not on mainnet, whatever the settings say; elsewhere the
/// settings, with K and M at their defaults when unset or zero; never
/// before one epoch after the signed-frame activation frame, nor without
/// it.
#[test]
fn the_silent_fence_is_not_scheduled_by_default() {
    assert_eq!(silence::MAINNET_SILENT_FENCE_FRAME, None);
    assert_eq!(
        silence::settings(),
        Settings {
            frame: u64::MAX,
            window: 90,
            evidence: 3
        },
        "without init, the mainnet settings"
    );
    assert_eq!(silence::first_frame(), u64::MAX);
    let epoch = quil_types::consensus::epoch_length_frames();
    quil_types::consensus::set_signed_frame_activation_frame_for_thread(Some(100));
    assert_eq!(
        silence::first_frame(),
        u64::MAX,
        "the fence itself unscheduled"
    );
    set_silent_frame(Some(0));
    assert_eq!(silence::first_frame(), 100 + epoch);
    set_silent_frame(Some(100 + epoch + 1));
    assert_eq!(silence::first_frame(), 100 + epoch + 1);
    quil_types::consensus::set_signed_frame_activation_frame_for_thread(Some(u64::MAX));
    assert_eq!(silence::first_frame(), u64::MAX, "no signatures recorded");
    quil_types::consensus::set_signed_frame_activation_frame_for_thread(None);
    silence::set_settings_for_thread(None);
}

/// Until its frame, the evaluator writes nothing, even with signatures and
/// tip frames recorded; from it, the next evaluation acts.
#[test]
fn a_stalled_session_is_left_alone_before_the_silent_fence_frame() {
    let _gates = Gates::with(Some(0), None);
    let mut net = Net::new(17, 4, &all(4));
    let first = net.head();
    let f = pass_at(start() + K);
    net.live_before(0..12, f);
    assert_eq!(net.pass(f), (vec![], 0));
    assert_eq!(net.head(), first);
    assert_eq!(net.excluded(12), None);
    let f2 = pass_at(start() + 2 * K);
    set_silent_frame(Some(f2 + 1));
    net.live_before(0..12, f2);
    assert_eq!(net.pass(f2), (vec![], 0), "one frame before it");
    let f3 = pass_at(start() + 3 * K);
    net.live_before(0..12, f3);
    assert_eq!(net.pass(f3).1, 1);
    assert_eq!(net.head().members, net.keys(0..12));
}

/// From the signed-frame activation frame GLOBAL records each session's
/// creation and tip-advance frames, apart from presence reports; before it
/// nothing.
#[test]
fn tip_frames_are_recorded_from_the_signed_frame_activation_frame() {
    let keys = keys();
    let first = initial(vec![0x31; 32], &keys);
    let id = first.id().unwrap();
    for (activation, created, advanced) in [
        (Some(1), Some(1), Some(3)),
        (Some(3), None, Some(3)),
        (Some(4), None, None),
        (Some(u64::MAX), None, None),
    ] {
        quil_types::consensus::set_signed_frame_activation_frame_for_thread(activation);
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        initialize(&state, 1, &first).unwrap();
        assert_eq!(
            session_tip_frame(&state, &id).unwrap(),
            created,
            "{activation:?}"
        );
        record_session_tip(&state, 3, &id, &tip(5, 5, [0x55; 32])).unwrap();
        assert_eq!(
            session_tip_frame(&state, &id).unwrap(),
            advanced,
            "{activation:?}"
        );
    }
    quil_types::consensus::set_signed_frame_activation_frame_for_thread(None);
}
