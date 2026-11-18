//! A GLOBAL member that learns a notarization or finalization from its
//! certificate before it verified the block hands its finalizer a body held
//! under the certified digest. The digest names only the header's output, so
//! another member can send, ahead of the leader's block, a body with the
//! leader's output and rank but its own frame number. That body is not the
//! block the committee certified: it must not become a candidate or the
//! canonical frame.

use super::*;
use quil_cw_consensus::{
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Activity, Finalization, Notarization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
        Reporter as _,
    },
    _crypto::Signer as _,
    _utils::{ordered::Set, N3f1},
    adapters::{BlockStore, FalconReporter},
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
};
use quil_types::crypto::{FrameProver as _, Signer as _};

/// The frame number another member's body claims.
const OTHER_NUMBER: u64 = u64::MAX / 2;

/// The leader's frame 7 at view 7, with a real header proof, and another
/// member's body under its digest: the same output and rank, another frame
/// number.
fn bodies() -> (GlobalFrame, GlobalFrame) {
    let prover = quil_crypto::WesolowskiFrameProver::new(2048);
    let parent = GlobalFrameHeader {
        frame_number: 6,
        output: vec![3; 516],
        ..Default::default()
    };
    let requests_root =
        crate::leader_provider::compute_global_requests_root(&[], &quil_tries::ShaInclusionProver);
    let signer = quil_crypto::FalconSigner::generate();
    let mut header = prover
        .prove_global_frame_header(
            &parent,
            &[],
            &[],
            &[],
            &requests_root,
            0,
            &signer,
            1_700_000_000_000,
            1_000,
            0,
        )
        .unwrap();
    // Consensus proposals carry no signature: the certificate is attached
    // at finalization.
    header.public_key_signature_bls48581 = None;
    header.rank = 7;
    let leader = GlobalFrame {
        header: Some(header),
        ..Default::default()
    };
    let mut other = leader.clone();
    other.header.as_mut().unwrap().frame_number = OTHER_NUMBER;
    (leader, other)
}

/// Four members, of which three sign each certificate.
fn committee() -> Vec<Generic<Namespace>> {
    let mut keys: Vec<FalconPrivateKey> = (0..4)
        .map(|_| {
            let key = quil_crypto::FalconSigner::generate();
            FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
        })
        .collect();
    keys.sort_by_key(|key| key.public_key().as_ref().to_vec());
    let participants: Set<_> = keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    keys.into_iter()
        .map(|key| Generic::signer(b"global", participants.clone(), key).unwrap())
        .collect()
}

fn proposal(digest: Digest) -> Proposal<Digest> {
    Proposal::new(
        Round::new(Epoch::new(0), View::new(7)),
        View::new(6),
        digest,
    )
}

fn notarization(digest: Digest) -> Notarization<SimplexFalconScheme, Digest> {
    let members = committee();
    let proposal = proposal(digest);
    let votes: Vec<_> = members[..3]
        .iter()
        .map(|member| {
            member
                .sign::<SimplexFalconScheme, Digest>(Subject::Notarize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = members[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    Notarization {
        proposal,
        certificate,
    }
}

fn finalization(digest: Digest) -> Finalization<SimplexFalconScheme, Digest> {
    let members = committee();
    let proposal = proposal(digest);
    let votes: Vec<_> = members[..3]
        .iter()
        .map(|member| {
            member
                .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = members[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    Finalization {
        proposal,
        certificate,
    }
}

/// A member that never verified the block: another member's body arrived
/// under the leader's digest first, the leader's second.
struct Replica {
    digest: Digest,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    heads: Arc<Mutex<Vec<u64>>>,
    store: BlockStore,
}

impl Replica {
    fn new() -> Self {
        let (leader, other) = bodies();
        let digest = frame_digest(leader.header.as_ref().unwrap()).unwrap();
        assert_eq!(
            frame_digest(other.header.as_ref().unwrap()),
            Some(digest),
            "harness check: both bodies are under the leader's digest"
        );
        let store = BlockStore::new();
        store.put_from(digest, encode_global_frame(&other).unwrap(), b"member");
        store.put_from(digest, encode_global_frame(&leader).unwrap(), b"leader");
        assert_eq!(store.candidates(&digest).len(), 2, "harness check");
        Self {
            digest,
            clock: Arc::new(quil_store::testing::InMemoryClockStore::new()),
            heads: Arc::new(Mutex::new(Vec::new())),
            store,
        }
    }

    /// The finalizer an archive's consensus host builds over this replica's
    /// clock; its head hook records each frame it announces.
    fn finalizer(&self) -> GlobalSeamFinalizer {
        let heads = self.heads.clone();
        GlobalSeamFinalizer::new(
            self.clock.clone(),
            tokio::sync::mpsc::unbounded_channel().0,
            Arc::new(move |frame, _| heads.lock().unwrap().push(frame)),
            None,
            vec![],
        )
    }

    /// Consensus reports `activity` to `finalizer` over this replica's
    /// block store.
    fn report_to(
        &self,
        finalizer: GlobalSeamFinalizer,
        activity: quil_cw_consensus::adapters::FalconActivity,
    ) {
        let mut reporter = FalconReporter::new(Arc::new(finalizer), self.store.clone());
        let _ = reporter.report(activity);
    }

    fn report(&self, activity: quil_cw_consensus::adapters::FalconActivity) {
        self.report_to(self.finalizer(), activity);
    }

    fn candidate(&self, number: u64) -> bool {
        self.clock
            .get_global_clock_frame_candidate(number, self.digest.as_ref())
            .is_ok()
    }

    fn canonical(&self) -> Option<u64> {
        self.clock
            .get_latest_global_clock_frame()
            .ok()
            .and_then(|frame| frame.header)
            .map(|header| header.frame_number)
    }
}

#[test]
fn reproduces_a_notarized_global_candidate_from_another_members_body() {
    let replica = Replica::new();
    replica.report(Activity::Notarization(notarization(replica.digest)));
    assert!(
        !replica.candidate(OTHER_NUMBER),
        "VULNERABLE: the reporter handed the finalizer the first body held under the \
         notarized digest, another member's; it was written as the GLOBAL candidate of \
         frame {OTHER_NUMBER}, which the committee never notarized"
    );
}

#[test]
fn reproduces_a_finalized_global_frame_from_another_members_body() {
    let replica = Replica::new();
    replica.report(Activity::Finalization(finalization(replica.digest)));
    assert_ne!(
        replica.canonical(),
        Some(OTHER_NUMBER),
        "VULNERABLE: the reporter handed the finalizer the first body held under the \
         finalized digest, another member's; frame {OTHER_NUMBER} became the canonical \
         GLOBAL head (head hook {:?})",
        replica.heads.lock().unwrap()
    );
}

// Fix-only tests below (the base copy of this file ends here).

fn verifier() -> Arc<GlobalFrameVerifier> {
    Arc::new(GlobalFrameVerifier::new(Arc::new(
        quil_crypto::WesolowskiFrameProver::new(2048),
    )))
}

impl Replica {
    /// [`Self::report`] to a finalizer that checks header proofs, as
    /// [`activate_global_consensus_cw`] builds it.
    fn report_verified(&self, activity: quil_cw_consensus::adapters::FalconActivity) {
        self.report_to(self.finalizer().with_verifier(verifier()), activity);
    }
}

/// With the header proof checked, the leader's body is the one taken, though
/// another came first under its digest.
#[test]
fn a_certified_body_this_node_did_not_verify_is_the_one_that_authenticates() {
    let replica = Replica::new();
    replica.report_verified(Activity::Notarization(notarization(replica.digest)));
    assert!(replica.candidate(7), "the leader's body is the candidate");
    assert!(!replica.candidate(OTHER_NUMBER));
    replica.report_verified(Activity::Finalization(finalization(replica.digest)));
    assert_eq!(
        replica.canonical(),
        Some(7),
        "the leader's frame is canonical"
    );
    assert_eq!(*replica.heads.lock().unwrap(), vec![7]);
}

/// Without a verifier no body this node did not verify is taken: the
/// finalization waits for its body as one reported without it.
#[test]
fn without_a_verifier_no_unverified_body_is_taken() {
    let replica = Replica::new();
    replica.report(Activity::Notarization(notarization(replica.digest)));
    replica.report(Activity::Finalization(finalization(replica.digest)));
    assert!(!replica.candidate(7) && !replica.candidate(OTHER_NUMBER));
    assert_eq!(replica.canonical(), None);
    assert!(replica.heads.lock().unwrap().is_empty());
}

/// A body this node verified is taken as it is.
#[test]
fn a_verified_body_is_taken_without_the_header_check() {
    let (leader, _) = bodies();
    let replica = Replica::new();
    replica
        .store
        .seal(replica.digest, encode_global_frame(&leader).unwrap());
    replica.report(Activity::Finalization(finalization(replica.digest)));
    assert_eq!(replica.canonical(), Some(7));
}

/// What a voter checks of a body before executing it: its digest, view,
/// requests and header proof. The other member's body fails on the proof.
#[test]
fn a_body_authenticates_only_with_its_own_header_proof() {
    let (leader, other) = bodies();
    let digest = frame_digest(leader.header.as_ref().unwrap()).unwrap();
    let verifier = verifier();
    let leader = encode_global_frame(&leader).unwrap();
    assert!(global_body_authenticates(
        &verifier,
        Some(7),
        &digest,
        &leader
    ));
    assert!(global_body_authenticates(&verifier, None, &digest, &leader));
    assert!(!global_body_authenticates(
        &verifier,
        Some(8),
        &digest,
        &leader
    ));
    let other = encode_global_frame(&other).unwrap();
    assert!(
        !global_body_authenticates(&verifier, Some(7), &digest, &other),
        "another frame number fails the header proof"
    );
    assert!(!global_body_authenticates(
        &verifier,
        None,
        &digest,
        &[0xff]
    ));
}

/// The cheapest substitution keeps the leader's whole header, so its digest,
/// view, frame number and header proof are the leader's, and swaps the
/// requests: only the requests root tells it apart.
#[test]
fn a_body_with_the_leaders_header_and_other_requests_does_not_authenticate() {
    let (leader, _) = bodies();
    let digest = frame_digest(leader.header.as_ref().unwrap()).unwrap();
    let mut swapped = leader.clone();
    swapped.requests = vec![quil_types::proto::global::MessageBundle::default()];
    let verifier = verifier();
    assert!(global_body_authenticates(
        &verifier,
        Some(7),
        &digest,
        &encode_global_frame(&leader).unwrap()
    ));
    assert!(
        !global_body_authenticates(
            &verifier,
            Some(7),
            &digest,
            &encode_global_frame(&swapped).unwrap()
        ),
        "a body with the leader's header and other requests authenticates"
    );
}

/// The finalizer a GLOBAL host builds checks the certified bodies it did
/// not verify: it takes the leader's, though another came first.
#[test]
fn a_global_hosts_finalizer_authenticates_certified_bodies() {
    let replica = Replica::new();
    let heads = replica.heads.clone();
    let finalizer = host_finalizer(
        replica.clock.clone(),
        tokio::sync::mpsc::unbounded_channel().0,
        Arc::new(move |frame, _| heads.lock().unwrap().push(frame)),
        None,
        vec![],
        None,
        verifier(),
    );
    replica.report_to(
        finalizer,
        Activity::Finalization(finalization(replica.digest)),
    );
    assert_eq!(
        replica.canonical(),
        Some(7),
        "the host's finalizer took no certified body it did not verify"
    );
}
