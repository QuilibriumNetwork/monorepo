//! Finalize votes that arrive after this node holds a view's finalization
//! certificate, and the certificate it publishes to GLOBAL with them.
//!
//! Falcon votes are verified one by one as they arrive, so the batcher builds
//! a finalization from the first quorum it verifies and verifies no later
//! finalize vote. GLOBAL pays a shard frame's reward share only to its
//! certificate's signers, so a member whose vote came a moment later earns
//! nothing for the frame. The reporter keeps each view's finalize votes here;
//! the application engine finalizes at quorum as before, and only the copy it
//! publishes to GLOBAL waits for the view's window to close: until a later
//! view notarizes, at most [`LATE_VOTE_WINDOW`] after the certificate. That
//! copy is then signed also by the members whose valid votes came inside the
//! window ([`crate::app_cert::extend_finalization`]). Every build verifies a
//! certificate of more than a quorum, so nothing activates.
//!
//! [`LateVoteCensus`] counts, per interval, how late the votes left out of
//! certificates came and how many the published copies added.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use commonware_consensus::simplex::types::{Finalize, Proposal};
use commonware_cryptography::certificate::Scheme as _;
use commonware_utils::{ordered::Quorum as _, N3f1};

use crate::adapters::Digest;
use crate::app_cert::{encode_finalization, extend_finalization, AppFinalization};
use crate::falcon_simplex::SimplexFalconScheme;

/// The longest a view's window stays open after this node holds its
/// certificate. A later view's notarization closes it earlier.
pub const LATE_VOTE_WINDOW: Duration = Duration::from_secs(2);

/// Views whose votes are kept, the newest. The batcher reports a view's votes
/// from its activity timeout (10 views) below the last finalized view to one
/// view above the current one, each member's first vote once.
pub const VIEWS_KEPT: usize = 64;

/// The interval of the census line ([`LateVoteCensus::take_due`]).
pub const LATE_VOTE_SUMMARY: Duration = Duration::from_secs(3600);

/// A member's finalize vote, as the batcher reports it: not yet verified.
pub type FinalizeVote = Finalize<SimplexFalconScheme, Digest>;

/// What closed a view's window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// A later view notarized or finalized.
    Notarization,
    /// [`LATE_VOTE_WINDOW`] passed.
    Window,
}

struct Window {
    proposal: Proposal<Digest>,
    /// The members the certificate this node holds counts.
    signers: BTreeSet<u32>,
    certified_at: Instant,
    /// When a later view notarized or finalized.
    notarized_at: Option<Instant>,
    /// Its votes were taken for the published certificate.
    published: bool,
}

impl Window {
    fn closes(&self, window: Duration) -> (Instant, Closed) {
        let cap = self.certified_at + window;
        match self.notarized_at {
            Some(at) if at < cap => (at, Closed::Notarization),
            _ => (cap, Closed::Window),
        }
    }
}

#[derive(Default)]
struct ViewVotes {
    /// Each member's first finalize vote of the view, with its arrival.
    votes: BTreeMap<u32, (FinalizeVote, Instant)>,
    window: Option<Window>,
}

#[derive(Default)]
struct State {
    views: BTreeMap<u64, ViewVotes>,
    /// The highest view notarized or finalized so far.
    notarized: u64,
}

impl State {
    /// A view above `view` notarized or finalized at `now`: the windows
    /// below it close.
    fn close_below(&mut self, view: u64, now: Instant) {
        self.notarized = self.notarized.max(view);
        for votes in self.views.range_mut(..view).map(|(_, votes)| votes) {
            if let Some(window) = votes.window.as_mut() {
                window.notarized_at.get_or_insert(now);
            }
        }
    }

    fn prune(&mut self) {
        while self.views.len() > VIEWS_KEPT {
            self.views.pop_first();
        }
    }
}

/// One consensus host's finalize votes and windows. The reporter feeds it
/// ([`Self::vote`], [`Self::finalized`], [`Self::notarized`]); the
/// application engine asks when a certificate's window closes
/// ([`Self::open_until`]) and then takes the extended copy ([`Self::extend`]).
pub struct LateFinalizes {
    /// The committee that certifies this host's views.
    scheme: SimplexFalconScheme,
    window: Duration,
    census: Arc<LateVoteCensus>,
    state: Mutex<State>,
}

impl LateFinalizes {
    pub fn new(scheme: SimplexFalconScheme, census: Arc<LateVoteCensus>) -> Self {
        Self {
            scheme,
            window: LATE_VOTE_WINDOW,
            census,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A member's finalize vote arrived at `now`.
    pub fn vote(&self, vote: FinalizeVote, now: Instant) {
        let view = vote.proposal.round.view().get();
        let signer = vote.attestation.signer.get();
        let mut state = self.state();
        let votes = state.views.entry(view).or_default();
        if votes.votes.contains_key(&signer) {
            return;
        }
        if let Some(window) = votes.window.as_ref() {
            if window.signers.contains(&signer) {
                return;
            }
            if vote.proposal != window.proposal {
                self.census.update(now, |c| c.other_proposal += 1);
            } else {
                let delay = now.saturating_duration_since(window.certified_at);
                self.census.update(now, |c| c.late(delay));
            }
            // Past the window nothing reads it.
            if window.published || now > window.closes(self.window).0 {
                return;
            }
        }
        votes.votes.insert(signer, (vote, now));
        state.prune();
    }

    /// This node holds `finalization` from `now`: built from its votes, or
    /// adopted from a peer. A later report of the same view changes nothing.
    pub fn finalized(&self, finalization: &AppFinalization, now: Instant) {
        let view = finalization.proposal.round.view().get();
        let mut state = self.state();
        let lagging = state.notarized > view;
        state.close_below(view, now);
        let votes = state.views.entry(view).or_default();
        if votes.window.is_some() {
            return;
        }
        let signers: BTreeSet<u32> = finalization
            .certificate
            .signers
            .iter()
            .map(|signer| signer.get())
            .collect();
        let (mut early, mut other) = (0, 0);
        for (signer, (vote, _)) in &votes.votes {
            if signers.contains(signer) {
                continue;
            }
            if vote.proposal == finalization.proposal {
                early += 1;
            } else {
                other += 1;
            }
        }
        if early + other > 0 {
            self.census.update(now, |c| {
                c.early += early;
                c.other_proposal += other;
            });
        }
        votes.window = Some(Window {
            proposal: finalization.proposal.clone(),
            signers,
            certified_at: now,
            // A later view notarized before this one finalized: the window
            // holds only the votes already here.
            notarized_at: lagging.then_some(now),
            published: false,
        });
        state.prune();
    }

    /// `view` notarized at `now`.
    pub fn notarized(&self, view: u64, now: Instant) {
        self.state().close_below(view, now);
    }

    fn decode(&self, cert: &[u8]) -> Option<AppFinalization> {
        let mut cursor = cert;
        let members = self.scheme.participants().len();
        let finalization =
            <AppFinalization as commonware_codec::Read>::read_cfg(&mut cursor, &members).ok()?;
        cursor.is_empty().then_some(finalization)
    }

    /// While the window of the view `cert` finalizes is open at `now`, the
    /// latest it closes; `None` once it closed, its copy was taken, or this
    /// host does not know the view (publish it as it is).
    pub fn open_until(&self, cert: &[u8], now: Instant) -> Option<Instant> {
        let finalization = self.decode(cert)?;
        let view = finalization.proposal.round.view().get();
        let state = self.state();
        let window = state.views.get(&view)?.window.as_ref()?;
        if window.published || window.proposal != finalization.proposal {
            return None;
        }
        (now < window.closes(self.window).0).then_some(window.certified_at + self.window)
    }

    /// `cert` signed also by every member whose valid finalize vote for its
    /// proposal arrived before its window closed (or `now`, if earlier), and
    /// its census entry. `None` when no vote adds a signer: publish `cert`.
    /// A view's votes are taken once.
    pub fn extend(&self, cert: &[u8], now: Instant) -> Option<Vec<u8>> {
        let finalization = self.decode(cert)?;
        let view = finalization.proposal.round.view().get();
        let (votes, closed) = {
            let mut state = self.state();
            let entry = state.views.get_mut(&view)?;
            let window = entry.window.as_mut()?;
            if window.published || window.proposal != finalization.proposal {
                return None;
            }
            window.published = true;
            let (closes, closed) = window.closes(self.window);
            let until = closes.min(now);
            let votes: Vec<FinalizeVote> = entry
                .votes
                .values()
                .filter(|(_, arrived)| *arrived <= until)
                .map(|(vote, _)| vote.clone())
                .collect();
            entry.votes.clear();
            (votes, closed)
        };
        let before = finalization.certificate.signers.count() as u64;
        let (extended, extension) = extend_finalization(&self.scheme, &finalization, votes);
        let participants = self.scheme.participants();
        let (committee, quorum) = (
            participants.len() as u64,
            participants.quorum::<N3f1>() as u64,
        );
        self.census.update(now, |c| {
            c.frames += 1;
            c.committee = committee;
            c.quorum = quorum;
            c.quorum_signers += before;
            c.published_signers += before + extension.added as u64;
            c.added += extension.added as u64;
            c.invalid += extension.invalid as u64;
            match closed {
                Closed::Notarization => c.closed_by_notarization += 1,
                Closed::Window => c.closed_by_window += 1,
            }
        });
        (extension.added > 0).then(|| encode_finalization(&extended))
    }

    /// How many views it holds votes or a window for.
    pub fn views(&self) -> usize {
        self.state().views.len()
    }
}

/// Late finalize votes and published certificates of one shard over an
/// interval ([`LateVoteCensus`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LateVoteCounts {
    /// Certificates published after their window.
    pub frames: u64,
    /// The size and quorum of the latest committee.
    pub committee: u64,
    pub quorum: u64,
    /// Their signers as this node held them, and as published.
    pub quorum_signers: u64,
    pub published_signers: u64,
    /// Members the published copies added.
    pub added: u64,
    /// Votes inside a window whose signature did not verify.
    pub invalid: u64,
    /// Votes that arrived before the certificate but are not in it.
    pub early: u64,
    /// Votes for the finalized proposal that arrived after the certificate,
    /// by delay since it: at most 250 ms, 1 s, 2 s, and later.
    pub within_250ms: u64,
    pub within_1s: u64,
    pub within_2s: u64,
    pub after_2s: u64,
    /// Votes for another proposal of a finalized view.
    pub other_proposal: u64,
    /// Windows a later view's notarization closed, and windows that ran out.
    pub closed_by_notarization: u64,
    pub closed_by_window: u64,
}

impl LateVoteCounts {
    fn late(&mut self, delay: Duration) {
        let bucket = if delay <= Duration::from_millis(250) {
            &mut self.within_250ms
        } else if delay <= Duration::from_secs(1) {
            &mut self.within_1s
        } else if delay <= Duration::from_secs(2) {
            &mut self.within_2s
        } else {
            &mut self.after_2s
        };
        *bucket += 1;
    }
}

/// A shard's [`LateVoteCounts`] across its consensus hosts, summarized once
/// per [`LATE_VOTE_SUMMARY`].
#[derive(Default)]
pub struct LateVoteCensus {
    inner: Mutex<(Option<Instant>, LateVoteCounts)>,
}

impl LateVoteCensus {
    pub fn new() -> Self {
        Self::default()
    }

    fn update(&self, now: Instant, change: impl FnOnce(&mut LateVoteCounts)) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.0.get_or_insert(now);
        change(&mut inner.1);
    }

    /// The interval's counts and length once it has lasted
    /// [`LATE_VOTE_SUMMARY`]; the next interval starts at the next count.
    pub fn take_due(&self, now: Instant) -> Option<(Duration, LateVoteCounts)> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let started = inner.0?;
        let span = now.saturating_duration_since(started);
        if span < LATE_VOTE_SUMMARY {
            return None;
        }
        let counts = std::mem::take(&mut inner.1);
        inner.0 = None;
        Some((span, counts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_base::FalconPrivateKey;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::Signer as _;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, TryCollect as _};
    use quil_types::crypto::Signer as _;

    const NAMESPACE: &[u8] = b"appshard-late-votes";

    /// Seven members (quorum five), each scheme at its member's index.
    struct Committee {
        schemes: Vec<SimplexFalconScheme>,
        members: Vec<Vec<u8>>,
    }

    fn committee() -> Committee {
        let keys: Vec<_> = (0..7)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect();
        let set: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .try_collect()
            .unwrap();
        let members = set.iter().map(|key| key.as_ref().to_vec()).collect();
        let mut schemes: Vec<_> = keys
            .into_iter()
            .map(|key| SimplexFalconScheme::signer(NAMESPACE, set.clone(), key).unwrap())
            .collect();
        schemes.sort_by_key(|scheme| scheme.me().unwrap());
        Committee { schemes, members }
    }

    fn proposal(view: u64, payload: u8) -> Proposal<Digest> {
        Proposal::new(
            Round::new(Epoch::new(0), View::new(view)),
            View::new(view - 1),
            commonware_cryptography::sha256::Digest([payload; 32]),
        )
    }

    fn vote(committee: &Committee, member: usize, proposal: &Proposal<Digest>) -> FinalizeVote {
        Finalize::sign(&committee.schemes[member], proposal.clone()).unwrap()
    }

    /// The certificate of the first five members' votes.
    fn quorum(committee: &Committee, proposal: &Proposal<Digest>) -> AppFinalization {
        let votes: Vec<_> = (0..5).map(|m| vote(committee, m, proposal)).collect();
        AppFinalization::from_finalizes(&committee.schemes[0], &votes, &Sequential).unwrap()
    }

    /// The signers of `cert` as the release's verifier reads them.
    fn signers(cert: &[u8], committee: &Committee, payload: u8) -> Vec<u32> {
        let verified = crate::app_cert::verify_finalization_details(
            cert,
            &committee.members,
            NAMESPACE,
            [payload; 32],
        )
        .expect("the release verifier accepts the published certificate");
        verified
            .finalization
            .certificate
            .signers
            .iter()
            .map(|signer| signer.get())
            .collect()
    }

    /// Late votes inside the window join the published certificate, which the
    /// unchanged verifier accepts with quorum plus two signers; the census
    /// counts them by delay.
    #[test]
    fn late_finalize_votes_inside_the_window_join_the_published_certificate() {
        let c = committee();
        let census = Arc::new(LateVoteCensus::new());
        let late = LateFinalizes::new(c.schemes[0].clone(), census.clone());
        let p = proposal(9, 4);
        let t0 = Instant::now();
        for m in 0..5 {
            late.vote(vote(&c, m, &p), t0);
        }
        let finalization = quorum(&c, &p);
        late.finalized(&finalization, t0);
        let cert = encode_finalization(&finalization);
        assert_eq!(signers(&cert, &c, 4).len(), 5, "built at quorum");
        late.vote(vote(&c, 5, &p), t0 + Duration::from_millis(100));
        late.vote(vote(&c, 6, &p), t0 + Duration::from_millis(900));
        assert_eq!(
            late.open_until(&cert, t0 + Duration::from_secs(1)),
            Some(t0 + LATE_VOTE_WINDOW)
        );
        assert_eq!(late.open_until(&cert, t0 + LATE_VOTE_WINDOW), None);
        let extended = late
            .extend(&cert, t0 + LATE_VOTE_WINDOW)
            .expect("two members added");
        assert_eq!(signers(&extended, &c, 4), vec![0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(
            late.extend(&cert, t0 + LATE_VOTE_WINDOW),
            None,
            "taken once"
        );
        let (_, counts) = census
            .take_due(t0 + LATE_VOTE_SUMMARY * 2)
            .expect("an hour of counts");
        assert_eq!((counts.frames, counts.committee, counts.quorum), (1, 7, 5));
        assert_eq!((counts.quorum_signers, counts.published_signers), (5, 7));
        assert_eq!((counts.within_250ms, counts.within_1s), (1, 1));
        assert_eq!((counts.added, counts.closed_by_window), (2, 1));
    }

    /// A vote after the window, or after a later view notarized, stays out;
    /// a vote at the window's end is in.
    #[test]
    fn votes_after_the_window_or_the_next_notarization_are_left_out() {
        let c = committee();
        let census = Arc::new(LateVoteCensus::new());
        let late = LateFinalizes::new(c.schemes[0].clone(), census.clone());
        let t0 = Instant::now();
        let p = proposal(9, 4);
        let finalization = quorum(&c, &p);
        let cert = encode_finalization(&finalization);
        late.finalized(&finalization, t0);
        late.vote(vote(&c, 5, &p), t0 + LATE_VOTE_WINDOW);
        late.vote(
            vote(&c, 6, &p),
            t0 + LATE_VOTE_WINDOW + Duration::from_millis(1),
        );
        let extended = late
            .extend(&cert, t0 + Duration::from_secs(3))
            .expect("the vote at the window's end");
        assert_eq!(signers(&extended, &c, 4), vec![0, 1, 2, 3, 4, 5]);

        // The next view notarizes 300 ms after view 10's certificate.
        let q = proposal(10, 5);
        let next = quorum(&c, &q);
        let next_cert = encode_finalization(&next);
        late.finalized(&next, t0);
        late.vote(vote(&c, 5, &q), t0 + Duration::from_millis(200));
        late.notarized(11, t0 + Duration::from_millis(300));
        assert_eq!(
            late.open_until(&next_cert, t0 + Duration::from_millis(301)),
            None,
            "the notarization closed it"
        );
        late.vote(vote(&c, 6, &q), t0 + Duration::from_millis(400));
        let extended = late
            .extend(&next_cert, t0 + Duration::from_millis(500))
            .expect("the vote before the notarization");
        assert_eq!(signers(&extended, &c, 5), vec![0, 1, 2, 3, 4, 5]);
        let (_, counts) = census.take_due(t0 + LATE_VOTE_SUMMARY * 2).unwrap();
        assert_eq!(
            (
                counts.within_250ms,
                counts.within_1s,
                counts.within_2s,
                counts.after_2s
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(
            (counts.closed_by_window, counts.closed_by_notarization),
            (1, 1)
        );
    }

    /// An invalid signature, a vote for another proposal and a member already
    /// counted add nothing; the valid vote beside them does.
    #[test]
    fn invalid_and_other_proposal_votes_are_excluded() {
        let c = committee();
        let p = proposal(9, 4);
        let finalization = quorum(&c, &p);
        let other = proposal(9, 8);
        // Member 6's signature under member 5's index.
        let mut forged = vote(&c, 5, &p);
        forged.attestation.signature = vote(&c, 6, &p).attestation.signature;
        let (extended, extension) = crate::app_cert::extend_finalization(
            &c.schemes[1],
            &finalization,
            [
                forged.clone(),
                vote(&c, 6, &other),
                vote(&c, 0, &p),
                vote(&c, 6, &p),
            ],
        );
        assert_eq!(
            extension,
            crate::app_cert::Extension {
                added: 1,
                invalid: 1,
                other_proposal: 1,
                duplicate: 1,
            }
        );
        let cert = encode_finalization(&extended);
        assert_eq!(signers(&cert, &c, 4), vec![0, 1, 2, 3, 4, 6]);

        // Through the window: both are counted and left out.
        let census = Arc::new(LateVoteCensus::new());
        let late = LateFinalizes::new(c.schemes[0].clone(), census.clone());
        let t0 = Instant::now();
        late.finalized(&finalization, t0);
        late.vote(forged, t0);
        late.vote(vote(&c, 6, &other), t0);
        let quorum_cert = encode_finalization(&finalization);
        assert_eq!(late.extend(&quorum_cert, t0 + LATE_VOTE_WINDOW), None);
        let (_, counts) = census.take_due(t0 + LATE_VOTE_SUMMARY).unwrap();
        assert_eq!(
            (counts.invalid, counts.other_proposal, counts.added),
            (1, 1, 0)
        );
    }

    /// The votes of at most [`VIEWS_KEPT`] views are held: the oldest go.
    #[test]
    fn at_most_views_kept_views_are_held() {
        let c = committee();
        let late = LateFinalizes::new(c.schemes[0].clone(), Arc::new(LateVoteCensus::new()));
        let t0 = Instant::now();
        for view in 1..=(VIEWS_KEPT as u64 + 10) {
            late.vote(vote(&c, 1, &proposal(view, 1)), t0);
        }
        assert_eq!(late.views(), VIEWS_KEPT);
        // A pruned view has no window: its certificate is published as it is.
        let first = quorum(&c, &proposal(1, 1));
        late.finalized(&first, t0);
        assert_eq!(late.views(), VIEWS_KEPT);
        assert_eq!(late.open_until(&encode_finalization(&first), t0), None);
    }

    /// A late signer whose index is below the certificate's signers joins it
    /// in index order, which the release verifier accepts.
    #[test]
    fn a_late_signer_below_the_held_ones_joins_in_order() {
        let c = committee();
        let late = LateFinalizes::new(c.schemes[0].clone(), Arc::new(LateVoteCensus::new()));
        let p = proposal(9, 4);
        let votes: Vec<_> = (2..7).map(|m| vote(&c, m, &p)).collect();
        let finalization =
            AppFinalization::from_finalizes(&c.schemes[0], &votes, &Sequential).unwrap();
        let t0 = Instant::now();
        late.finalized(&finalization, t0);
        late.vote(vote(&c, 0, &p), t0 + Duration::from_millis(100));
        let extended = late
            .extend(&encode_finalization(&finalization), t0 + LATE_VOTE_WINDOW)
            .expect("member 0 added");
        assert_eq!(signers(&extended, &c, 4), vec![0, 2, 3, 4, 5, 6]);
    }

    /// A certificate it cannot read, or of another proposal of a view it
    /// holds, gets no window and no extension, and takes nothing from the
    /// view's own certificate.
    #[test]
    fn an_unreadable_or_other_proposal_certificate_gets_none() {
        let c = committee();
        let late = LateFinalizes::new(c.schemes[0].clone(), Arc::new(LateVoteCensus::new()));
        let p = proposal(9, 4);
        let finalization = quorum(&c, &p);
        let cert = encode_finalization(&finalization);
        let t0 = Instant::now();
        late.finalized(&finalization, t0);
        late.vote(vote(&c, 5, &p), t0 + Duration::from_millis(100));
        let mut trailing = cert.clone();
        trailing.push(0);
        let other = encode_finalization(&quorum(&c, &proposal(9, 8)));
        for unknown in [&b"not a certificate"[..], &trailing[..], &other[..]] {
            assert_eq!(late.open_until(unknown, t0), None);
            assert_eq!(late.extend(unknown, t0 + LATE_VOTE_WINDOW), None);
        }
        let extended = late
            .extend(&cert, t0 + LATE_VOTE_WINDOW)
            .expect("the view's own certificate");
        assert_eq!(signers(&extended, &c, 4), vec![0, 1, 2, 3, 4, 5]);
    }

    /// A view pruned while its window is open has no window left: its
    /// certificate is published as it is.
    #[test]
    fn a_view_pruned_with_its_window_open_publishes_its_certificate_as_it_is() {
        let c = committee();
        let late = LateFinalizes::new(c.schemes[0].clone(), Arc::new(LateVoteCensus::new()));
        let t0 = Instant::now();
        let p = proposal(1, 1);
        let first = quorum(&c, &p);
        let cert = encode_finalization(&first);
        late.finalized(&first, t0);
        late.vote(vote(&c, 5, &p), t0);
        assert_eq!(late.open_until(&cert, t0), Some(t0 + LATE_VOTE_WINDOW));
        for view in 2..=(VIEWS_KEPT as u64 + 1) {
            late.vote(vote(&c, 1, &proposal(view, 1)), t0);
        }
        assert_eq!(late.views(), VIEWS_KEPT);
        assert_eq!(late.open_until(&cert, t0), None, "pruned");
        assert_eq!(late.extend(&cert, t0 + LATE_VOTE_WINDOW), None);
    }

    /// The census reports once per interval, then starts again.
    #[test]
    fn the_census_reports_hourly() {
        let census = LateVoteCensus::new();
        let t0 = Instant::now();
        assert_eq!(census.take_due(t0), None);
        census.update(t0, |c| c.late(Duration::from_millis(1_500)));
        assert_eq!(census.take_due(t0 + LATE_VOTE_SUMMARY / 2), None);
        let (span, counts) = census.take_due(t0 + LATE_VOTE_SUMMARY).unwrap();
        assert_eq!((span, counts.within_2s), (LATE_VOTE_SUMMARY, 1));
        assert_eq!(census.take_due(t0 + LATE_VOTE_SUMMARY * 3), None);
    }
}
