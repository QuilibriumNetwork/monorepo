//! A shard frame credits only the signers its certificate names, and any
//! holder of a published copy can drop signatures from it down to a quorum
//! (each is a separate Falcon signature over the same subject; nothing else
//! binds them to the header). These tests run GLOBAL's intake of the copies
//! of one shard frame (collector admission, then the leader's tip choice)
//! with the production header verifier, and read who that frame pays.

use crate::leader_provider::{select_shard_tips, TipCheck};
use crate::message_collector::{
    bundle_shard_frames_in_lockstep, MessageCollector, Provenance, ShardFrameVerdict,
    ShardFrameVerifier, SubmitOutcome,
};
use quil_cw_consensus::{
    _codec::Read as _,
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{certificate::Signers, sha256::Digest, Signer as _},
    _utils::{ordered::Set, N3f1},
    app_cert::{
        encode_finalization, unwrap_cert_from_header, wrap_cert_for_header, AppFinalization,
    },
    falcon_base::{FalconPrivateKey, FalconPublicKey},
    falcon_scheme::{Certificate, Generic},
    falcon_simplex::SimplexFalconScheme,
};
use quil_execution::global_intrinsic::frame_header::{
    FrameHeader, STORAGE_ANCHOR_LOCKSTEP_WINDOW, TYPE_FRAME_HEADER,
};
use quil_execution::global_intrinsic::prover_shard_update::verify_frame_header_attestation;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_types::consensus::{ProverInfo, ProverStatus};
use quil_types::crypto::Signer as _;

const MEMBERS: usize = 7;
const FRAME: u64 = 10;
const VIEW: u64 = 12;
const RANK: u64 = 3;

/// One shard committee of seven Falcon members (quorum five), in the order
/// the certificate's bitmap indexes them.
struct Shard {
    address: Vec<u8>,
    members: Vec<Generic<Namespace>>,
    active: Vec<ProverInfo>,
    proposal: Proposal<Digest>,
    output: Vec<u8>,
}

fn keys() -> &'static Vec<FalconPrivateKey> {
    static KEYS: std::sync::OnceLock<Vec<FalconPrivateKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        (0..MEMBERS)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect()
    })
}

impl Shard {
    fn new(addr: u8) -> Self {
        let address = vec![addr; 32];
        let mut namespace = b"appshard".to_vec();
        namespace.extend_from_slice(&address);
        let set: Set<FalconPublicKey> = keys()
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // Members in the set's order, so member i signs as participant i.
        let mut members: Vec<Generic<Namespace>> = keys()
            .iter()
            .map(|key| Generic::<Namespace>::signer(&namespace, set.clone(), key.clone()).unwrap())
            .collect();
        members.sort_by_key(|m| m.me().unwrap().get());
        let active = set
            .iter()
            .enumerate()
            .map(|(i, key)| ProverInfo {
                public_key: key.as_ref().to_vec(),
                address: vec![i as u8 + 1; 32],
                status: ProverStatus::Active,
                kick_frame_number: 0,
                allocations: Vec::new(),
                available_storage: 0,
                seniority: 0,
                delegate_address: Vec::new(),
            })
            .collect();
        let output = vec![addr; 516];
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(VIEW)),
            View::new(VIEW - 1),
            Digest(quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap()),
        );
        Self {
            address,
            members,
            active,
            proposal,
            output,
        }
    }

    /// The certified header a member publishes, its certificate signed by
    /// `signers`.
    fn header(&self, signers: &[usize]) -> FrameHeader {
        let votes = signers.iter().map(|&i| {
            self.members[i]
                .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                    proposal: &self.proposal,
                })
                .unwrap()
        });
        let certificate = self.members[0]
            .assemble::<SimplexFalconScheme, _, N3f1>(votes)
            .unwrap();
        self.with_certificate(&encode_finalization(&Finalization {
            proposal: self.proposal.clone(),
            certificate,
        }))
    }

    fn with_certificate(&self, cert: &[u8]) -> FrameHeader {
        FrameHeader {
            address: self.address.clone(),
            frame_number: FRAME,
            rank: VIEW,
            global_frame_number: 99,
            output: self.output.clone(),
            public_key_signature_bls48581: wrap_cert_for_header(cert),
            ..Default::default()
        }
    }

    /// Who GLOBAL pays for `header`: the production verifier's bitmap.
    fn paid(&self, header: &FrameHeader) -> Result<Vec<usize>, String> {
        let prover = quil_crypto::WesolowskiFrameProver::new(2048);
        verify_frame_header_attestation(
            header,
            &prover,
            &quil_crypto::FalconKeyConstructor,
            &self.active,
        )
        .map(|bitmask| quil_consensus::bitmask::set_bit_indices(&bitmask).collect())
        .map_err(|e| e.to_string())
    }
}

/// What anyone holding `header` can publish: the same certificate without
/// the signatures of `drop`. No key is needed.
fn strip(header: &FrameHeader, drop: &[usize]) -> FrameHeader {
    let bytes = unwrap_cert_from_header(&header.public_key_signature_bls48581).unwrap();
    let full = AppFinalization::read_cfg(&mut &bytes[..], &MEMBERS).unwrap();
    let kept: Vec<_> = full
        .certificate
        .signers
        .iter()
        .zip(full.certificate.signatures.iter().cloned())
        .filter(|(signer, _)| !drop.contains(&(signer.get() as usize)))
        .collect();
    let certificate = Certificate {
        signers: Signers::from(MEMBERS, kept.iter().map(|(signer, _)| *signer)),
        signatures: kept
            .into_iter()
            .map(|(_, signature)| signature)
            .collect::<Vec<_>>()
            .into(),
    };
    let mut stripped = header.clone();
    stripped.public_key_signature_bls48581 =
        wrap_cert_for_header(&encode_finalization(&Finalization {
            proposal: full.proposal,
            certificate,
        }));
    stripped
}

fn bundle(headers: &[&FrameHeader]) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: headers
            .iter()
            .map(|header| {
                Some(CanonicalMessageRequest {
                    inner_type_prefix: TYPE_FRAME_HEADER,
                    inner_bytes: header.to_canonical_bytes().unwrap(),
                })
            })
            .collect(),
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

fn headers_of(raw: &[u8]) -> Vec<FrameHeader> {
    CanonicalMessageBundle::from_canonical_bytes(raw)
        .unwrap()
        .requests
        .into_iter()
        .flatten()
        .filter(|request| request.inner_type_prefix == TYPE_FRAME_HEADER)
        .map(|request| FrameHeader::from_canonical_bytes(&request.inner_bytes).unwrap())
        .collect()
}

/// Every header of a bundle must pass the production certificate check of
/// its shard.
fn verdict(shards: &[Shard], raw: &[u8]) -> Result<(), String> {
    for header in headers_of(raw) {
        let shard = shards
            .iter()
            .find(|shard| shard.address == header.address)
            .ok_or("unknown shard")?;
        shard.paid(&header)?;
    }
    Ok(())
}

fn collector(shards: Vec<Shard>) -> (MessageCollector, std::sync::Arc<Vec<Shard>>) {
    let shards = std::sync::Arc::new(shards);
    let mc = MessageCollector::new();
    let held = shards.clone();
    let verifier: ShardFrameVerifier =
        std::sync::Arc::new(move |raw: &[u8]| match verdict(&held, raw) {
            Ok(()) => ShardFrameVerdict::Valid,
            Err(reason) => ShardFrameVerdict::Invalid(reason),
        });
    mc.set_shard_frame_verifier(verifier);
    (mc, shards)
}

/// Who each copy of `shard`'s frame that a GLOBAL proposal carries from
/// `mc` would pay, in the leader's order.
fn riding(mc: &MessageCollector, shards: &[Shard], shard: &Shard) -> Vec<Vec<usize>> {
    let tips = select_shard_tips(
        mc.collect_for_rank(RANK),
        |raw| mc.is_verified(raw),
        |raw| match verdict(shards, raw) {
            Ok(()) => TipCheck::Valid,
            Err(reason) => TipCheck::Invalid(reason),
        },
    );
    tips.kept
        .iter()
        .flat_map(|raw| headers_of(raw.as_slice()))
        .filter(|header| header.address == shard.address && header.frame_number == FRAME)
        .map(|header| shard.paid(&header).unwrap())
        .collect()
}

/// The signers of `superset` each riding copy leaves unpaid.
fn excluded(riding: &[Vec<usize>], superset: &[usize]) -> Vec<Vec<usize>> {
    riding
        .iter()
        .map(|paid| {
            superset
                .iter()
                .copied()
                .filter(|member| !paid.contains(member))
                .collect()
        })
        .collect()
}

/// Control: the members' own copy, alone, pays every member that signed it.
#[test]
fn sca_control_the_superset_copy_alone_pays_every_signer() {
    let (mc, shards) = collector(vec![Shard::new(0xA5)]);
    let shard = &shards[0];
    let all: Vec<usize> = (0..MEMBERS).collect();
    let full = shard.header(&all);
    assert_eq!(
        shard.paid(&full).unwrap(),
        all,
        "SCA SETUP: the full copy pays all"
    );
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle(&[&full]), Provenance::Prover),
        SubmitOutcome::Accepted
    );
    let riding = riding(&mc, &shards, shard);
    assert_eq!(
        riding,
        vec![all],
        "SCA SETUP: the full copy rides and pays all"
    );
}

/// A copy stripped to quorum by someone holding only a published copy,
/// arriving before the members' superset copy, decides who is paid.
#[test]
fn sca_a_stripped_copy_arriving_first_decides_who_is_paid() {
    let (mc, shards) = collector(vec![Shard::new(0xA5)]);
    let shard = &shards[0];
    let all: Vec<usize> = (0..MEMBERS).collect();
    let full = shard.header(&all);
    let stripped = strip(&full, &[5, 6]);
    assert_eq!(
        shard.paid(&stripped).unwrap(),
        vec![0, 1, 2, 3, 4],
        "SCA SETUP: the stripped copy verifies with five of seven"
    );
    assert_eq!(
        shard.paid(&full).unwrap(),
        all,
        "SCA SETUP: the full copy verifies"
    );
    // Any sender: the stripped copy needs no key and no prover identity.
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle(&[&stripped]), Provenance::Other),
        SubmitOutcome::Accepted,
        "SCA SETUP: the stripped copy is admitted"
    );
    let superset = mc.add_message_outcome_from(RANK, bundle(&[&full]), Provenance::Prover);
    let riding = riding(&mc, &shards, shard);
    let missed = excluded(&riding, &all);
    assert!(
        !riding.is_empty() && missed.iter().all(|m| m.is_empty()),
        "SCA EXCLUDED: a stripped certificate (5 of 7 signers, built without any key from a \
         published copy) arriving first excluded signers {missed:?} from the frame's pay \
         although a superset copy signed by all 7 for the same frame verifies and reached \
         GLOBAL before inclusion (its submit: {superset:?}); riding copies pay {riding:?}"
    );
}

/// The stripped copy carried in a bundle with a second shard's header: a
/// bundle of several shard frames is not compared by signers.
#[test]
fn sca_a_stripped_copy_in_a_two_shard_bundle_decides_who_is_paid() {
    let (mc, shards) = collector(vec![Shard::new(0xA5), Shard::new(0xB6)]);
    let (a, b) = (&shards[0], &shards[1]);
    let all: Vec<usize> = (0..MEMBERS).collect();
    let full_a = a.header(&all);
    let stripped_a = strip(&full_a, &[5, 6]);
    let stripped_b = strip(&b.header(&all), &[5, 6]);
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle(&[&stripped_a, &stripped_b]), Provenance::Other),
        SubmitOutcome::Accepted,
        "SCA SETUP: the two-shard bundle is admitted"
    );
    let superset = mc.add_message_outcome_from(RANK, bundle(&[&full_a]), Provenance::Prover);
    let riding = riding(&mc, &shards, a);
    let missed = excluded(&riding, &all);
    assert!(
        !riding.is_empty() && missed.iter().all(|m| m.is_empty()),
        "SCA EXCLUDED: a stripped certificate (5 of 7 signers) carried in a two-shard bundle \
         arriving first excluded signers {missed:?} from the frame's pay although a superset \
         copy signed by all 7 for the same frame verifies and reached GLOBAL before inclusion \
         (its submit: {superset:?}); riding copies pay {riding:?}"
    );
}

/// `headers` in one bundle stamped `timestamp`: the same headers from
/// another sender are a distinct message.
fn bundle_at(headers: &[&FrameHeader], timestamp: i64) -> Vec<u8> {
    let mut raw = CanonicalMessageBundle::from_canonical_bytes(&bundle(headers)).unwrap();
    raw.timestamp = timestamp;
    raw.to_canonical_bytes().unwrap()
}

/// Who each copy of `shard`'s frame that GLOBAL frame `global` carries from
/// `mc` would pay. As the leader does, a bundle with a shard frame outside
/// the anchor window is first dropped whole from the collector.
fn riding_at(
    mc: &MessageCollector,
    shards: &[Shard],
    shard: &Shard,
    global: u64,
) -> Vec<Vec<usize>> {
    let (in_window, out): (Vec<_>, Vec<_>) = mc
        .collect_for_rank(RANK)
        .into_iter()
        .partition(|raw| bundle_shard_frames_in_lockstep(raw, global));
    mc.remove(&out);
    let tips = select_shard_tips(
        in_window,
        |raw| mc.is_verified(raw),
        |raw| match verdict(shards, raw) {
            Ok(()) => TipCheck::Valid,
            Err(reason) => TipCheck::Invalid(reason),
        },
    );
    tips.kept
        .iter()
        .flat_map(|raw| headers_of(raw.as_slice()))
        .filter(|header| header.address == shard.address && header.frame_number == FRAME)
        .map(|header| shard.paid(&header).unwrap())
        .collect()
}

/// A held frame and a second shard's frame anchored at the window's old
/// edge (both published headers, no key needed), sent as one bundle that
/// verifies, must not take the held frame's place: the next GLOBAL frame
/// drops the bundle whole for its companion, and the held frame rides.
#[test]
fn sca_a_two_shard_bundle_dropped_whole_leaves_the_held_frame_riding() {
    let (mc, shards) = collector(vec![Shard::new(0xA5), Shard::new(0xB6)]);
    let (a, b) = (&shards[0], &shards[1]);
    let all: Vec<usize> = (0..MEMBERS).collect();
    let full_a = a.header(&all);
    let mut edge_b = b.header(&all);
    edge_b.global_frame_number = full_a.global_frame_number - STORAGE_ANCHOR_LOCKSTEP_WINDOW;
    // GLOBAL frames whose window holds both anchors, then A's only.
    let (now, next) = (
        full_a.global_frame_number + 1,
        full_a.global_frame_number + 2,
    );
    assert!(b.paid(&edge_b).is_ok(), "SCA SETUP: the companion verifies");
    assert!(
        bundle_shard_frames_in_lockstep(&bundle(&[&full_a, &edge_b]), now)
            && !bundle_shard_frames_in_lockstep(&bundle(&[&edge_b]), next)
            && bundle_shard_frames_in_lockstep(&bundle(&[&full_a]), next),
        "SCA SETUP: the companion leaves the window one GLOBAL frame later, A does not"
    );
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle(&[&full_a]), Provenance::Prover),
        SubmitOutcome::Accepted,
        "SCA SETUP: a member's copy of A is admitted"
    );
    assert!(
        mc.is_verified(&bundle(&[&full_a])),
        "SCA SETUP: the member's copy of A is held verified"
    );
    // Any sender: both headers are on public shard-frame gossip.
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle_at(&[&full_a, &edge_b], 7), Provenance::Other),
        SubmitOutcome::Accepted,
        "SCA SETUP: the two-shard bundle is admitted"
    );
    // Another member's copy of A arrives after the bundle.
    let late = mc.add_message_outcome_from(RANK, bundle_at(&[&full_a], 1), Provenance::Prover);
    let riding = riding_at(&mc, &shards, a, next);
    assert!(
        riding.contains(&all),
        "SCA FRAME LOST: a verified two-shard bundle carrying a copy of A's held frame and a \
         companion anchored at the window's old edge took the held copy's place; the next \
         GLOBAL frame dropped the bundle whole for its companion, and no copy of A rides \
         (a later member copy: {late:?}); riding copies pay {riding:?}"
    );
}

/// Control: the same copy of A sent alone takes nothing, and the held copy
/// rides.
#[test]
fn sca_control_a_one_shard_copy_of_a_held_frame_takes_nothing() {
    let (mc, shards) = collector(vec![Shard::new(0xA5)]);
    let a = &shards[0];
    let all: Vec<usize> = (0..MEMBERS).collect();
    let full_a = a.header(&all);
    let next = full_a.global_frame_number + 2;
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle(&[&full_a]), Provenance::Prover),
        SubmitOutcome::Accepted,
        "SCA SETUP: a member's copy of A is admitted"
    );
    assert_eq!(
        mc.add_message_outcome_from(RANK, bundle_at(&[&full_a], 7), Provenance::Other),
        SubmitOutcome::Duplicate,
        "SCA SETUP: a copy of a held verified frame adds nothing"
    );
    assert_eq!(
        riding_at(&mc, &shards, a, next),
        vec![all],
        "SCA SETUP: the held copy rides"
    );
}
