//! Real Falcon committees, the production certificate check as the collector's
//! verifier and as the reader of who a frame pays.

use super::*;
use crate::leader_provider::{select_shard_tips, TipCheck};
use quil_cw_consensus::{
    _codec::{types::lazy::Lazy, Read as _},
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{
        certificate::{Attestation, Signers},
        sha256::Digest,
        Signer as _,
    },
    _utils::{ordered::Set, N3f1, Participant},
    app_cert::{
        encode_finalization, unwrap_cert_from_header, wrap_cert_for_header, AppFinalization,
    },
    falcon_base::{FalconPrivateKey, FalconPublicKey, FalconSignature},
    falcon_scheme::{Certificate, Generic},
    falcon_simplex::SimplexFalconScheme,
};
use quil_execution::global_intrinsic::prover_shard_update::verify_frame_header_attestation;
use quil_types::consensus::{ProverInfo, ProverStatus};
use quil_types::crypto::Signer as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const FRAME: u64 = 10;
const VIEW: u64 = 12;
const RANK: u64 = 3;
const ALL: [usize; 7] = [0, 1, 2, 3, 4, 5, 6];

fn keys(members: usize) -> Vec<FalconPrivateKey> {
    static KEYS: std::sync::OnceLock<Vec<FalconPrivateKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        (0..16)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect()
    })[..members]
        .to_vec()
}

/// One shard committee, with one finalize vote per member, as each member
/// sends it: any copy naming a member carries these same bytes.
struct Shard {
    address: Vec<u8>,
    members: Vec<Generic<Namespace>>,
    active: Vec<ProverInfo>,
    committee: Arc<Committee>,
    proposal: Proposal<Digest>,
    votes: Vec<(Participant, Lazy<FalconSignature>)>,
    output: Vec<u8>,
}

impl Shard {
    fn new(addr: u8, size: usize) -> Self {
        let address = vec![addr; 32];
        let mut namespace = b"appshard".to_vec();
        namespace.extend_from_slice(&address);
        let set: Set<FalconPublicKey> = keys(size)
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mut members: Vec<Generic<Namespace>> = keys(size)
            .into_iter()
            .map(|key| Generic::<Namespace>::signer(&namespace, set.clone(), key).unwrap())
            .collect();
        members.sort_by_key(|member| member.me().unwrap().get());
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
        let committee = Arc::new(Committee {
            members: set.iter().map(|key| key.as_ref().to_vec()).collect(),
            namespace,
        });
        let output = vec![addr; 516];
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(VIEW)),
            View::new(VIEW - 1),
            Digest(quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap()),
        );
        let votes = members
            .iter()
            .map(|member| {
                let vote = member
                    .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap();
                (vote.signer, vote.signature)
            })
            .collect();
        Self {
            address,
            members,
            active,
            committee,
            proposal,
            votes,
            output,
        }
    }

    /// The certified header whose certificate `signers` signed.
    fn header(&self, signers: &[usize]) -> FrameHeader {
        let votes = signers.iter().map(|&i| Attestation::<SimplexFalconScheme> {
            signer: self.votes[i].0,
            signature: self.votes[i].1.clone(),
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

    /// Whom GLOBAL pays for `header`: the production verifier's bitmap.
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

    /// A bundle of the certified header `signers` signed.
    fn copy(&self, signers: &[usize]) -> Vec<u8> {
        bundle(&[&self.header(signers)])
    }

    /// Whom the one copy of this shard's frame held in `mc` pays.
    fn held_pays(&self, mc: &MessageCollector) -> Vec<usize> {
        let copies: Vec<Vec<u8>> = mc
            .collect_for_rank(RANK)
            .into_iter()
            .filter(|raw| {
                headers_of(raw)
                    .iter()
                    .any(|header| header.address == self.address)
            })
            .collect();
        assert_eq!(copies.len(), 1, "one copy of the frame is held");
        assert!(mc.is_verified(&copies[0]), "the held copy is verified");
        self.paid(&headers_of(&copies[0])[0]).unwrap()
    }
}

/// Whom the one verified copy of `shard`'s frame held in `mc` pays, whatever
/// unverified copies are held beside it.
fn verified_copy_pays(shard: &Shard, mc: &MessageCollector) -> Vec<usize> {
    let verified: Vec<Vec<u8>> = mc
        .collect_for_rank(RANK)
        .into_iter()
        .filter(|raw| mc.is_verified(raw))
        .collect();
    assert_eq!(verified.len(), 1, "one verified copy of the frame is held");
    shard.paid(&headers_of(&verified[0])[0]).unwrap()
}

/// `header` with the signature of `forged` replaced by another signer's.
fn forge(header: &FrameHeader, forged: usize) -> FrameHeader {
    let bytes = unwrap_cert_from_header(&header.public_key_signature_bls48581).unwrap();
    let full = AppFinalization::read_cfg(&mut &bytes[..], &quil_cw_consensus::handoff::MAX_MEMBERS)
        .unwrap();
    let signers: Vec<Participant> = full.certificate.signers.iter().collect();
    let other = signers
        .iter()
        .position(|signer| signer.get() as usize != forged)
        .unwrap();
    let signatures: Vec<_> = signers
        .iter()
        .enumerate()
        .map(|(i, signer)| {
            if signer.get() as usize == forged {
                full.certificate.signatures[other].clone()
            } else {
                full.certificate.signatures[i].clone()
            }
        })
        .collect();
    let certificate = Certificate {
        signers: Signers::from(full.certificate.signers.len(), signers),
        signatures: signatures.into(),
    };
    let mut copy = header.clone();
    copy.public_key_signature_bls48581 =
        wrap_cert_for_header(&encode_finalization(&Finalization {
            proposal: full.proposal,
            certificate,
        }));
    copy
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
    let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(raw) else {
        return Vec::new();
    };
    bundle
        .requests
        .into_iter()
        .flatten()
        .filter(|request| request.inner_type_prefix == TYPE_FRAME_HEADER)
        .map(|request| FrameHeader::from_canonical_bytes(&request.inner_bytes).unwrap())
        .collect()
}

fn verdict(shards: &[Arc<Shard>], raw: &[u8]) -> Result<(), String> {
    for header in headers_of(raw) {
        let shard = shards
            .iter()
            .find(|shard| shard.address == header.address)
            .ok_or("unknown shard")?;
        shard.paid(&header)?;
    }
    Ok(())
}

/// What the collector verifiers below were asked.
#[derive(Default)]
struct Calls {
    verifier: AtomicUsize,
    committees: AtomicUsize,
}

/// A collector verifying with the production check; `committees` also reads
/// the committee, so added signers are verified alone.
fn collector(
    shards: &[Arc<Shard>],
    committees: bool,
) -> (MessageCollector, Arc<Calls>, Arc<AtomicBool>) {
    let mc = MessageCollector::new();
    let calls = Arc::new(Calls::default());
    let available = Arc::new(AtomicBool::new(true));
    {
        let (shards, calls, available) = (shards.to_vec(), calls.clone(), available.clone());
        let verifier: super::super::ShardFrameVerifier = Arc::new(move |raw: &[u8]| {
            calls.verifier.fetch_add(1, Ordering::SeqCst);
            if !available.load(Ordering::SeqCst) {
                return ShardFrameVerdict::Unavailable("state".into());
            }
            match verdict(&shards, raw) {
                Ok(()) => ShardFrameVerdict::Valid,
                Err(reason) => ShardFrameVerdict::Invalid(reason),
            }
        });
        mc.set_shard_frame_verifier(verifier);
    }
    if committees {
        let (shards, calls) = (shards.to_vec(), calls.clone());
        mc.set_certificate_committees(Arc::new(move |address: &[u8], _| {
            calls.committees.fetch_add(1, Ordering::SeqCst);
            shards
                .iter()
                .find(|shard| shard.address == address)
                .map(|shard| shard.committee.clone())
        }));
    }
    (mc, calls, available)
}

fn one_shard(committees: bool) -> (Arc<Shard>, MessageCollector, Arc<Calls>, Arc<AtomicBool>) {
    let shard = Arc::new(Shard::new(0xA5, 7));
    let (mc, calls, available) = collector(std::slice::from_ref(&shard), committees);
    (shard, mc, calls, available)
}

fn submit(mc: &MessageCollector, raw: Vec<u8>) -> SubmitOutcome {
    mc.add_message_outcome_from(RANK, raw, Provenance::Other)
}

/// No copy names them all, yet the held one ends up paying every signer: only
/// a union can, a comparison of copies cannot. Whatever arrives first.
#[test]
fn sca_the_union_of_copies_pays_signers_no_single_copy_names() {
    for committees in [true, false] {
        let (shard, mc, _, _) = one_shard(committees);
        for signers in [&[0, 1, 2, 3, 4], &[1, 2, 3, 4, 5], &[2, 3, 4, 5, 6]] {
            assert_eq!(submit(&mc, shard.copy(signers)), SubmitOutcome::Accepted);
        }
        assert_eq!(shard.held_pays(&mc), ALL);
        assert_eq!(mc.total_pending(), 1);
    }
}

/// With the session's committee, a copy has only its new signatures read: a
/// wrong signature for a signer already held costs nothing and does not count.
#[test]
fn sca_only_the_signers_a_copy_adds_are_verified() {
    let (shard, mc, calls, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    assert_eq!(calls.verifier.load(Ordering::SeqCst), 1);
    let forged_held = forge(&shard.header(&[0, 1, 2, 3, 5]), 0);
    assert_eq!(
        submit(&mc, bundle(&[&forged_held])),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        calls.verifier.load(Ordering::SeqCst),
        1,
        "the whole-frame verifier runs for the first copy only"
    );
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
}

/// A forged signature for a new signer refuses the copy and changes nothing,
/// and the frame still takes that signer's real vote afterwards. Each path.
#[test]
fn sca_a_forged_new_signer_is_refused_and_the_real_one_still_counts() {
    for committees in [true, false] {
        let (shard, mc, _, _) = one_shard(committees);
        assert_eq!(
            submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
            SubmitOutcome::Accepted
        );
        let forged = forge(&shard.header(&[0, 1, 2, 3, 5]), 5);
        assert_eq!(
            submit(&mc, bundle(&[&forged])),
            SubmitOutcome::Filtered(Refusal::InvalidShardFrame)
        );
        assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4]);
        assert_eq!(
            submit(&mc, shard.copy(&[1, 2, 3, 4, 5])),
            SubmitOutcome::Accepted
        );
        assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
    }
}

/// A copy naming nobody new costs no verification and runs on the caller's
/// thread; one naming somebody new goes off the runtime.
#[test]
fn sca_a_copy_naming_nobody_new_is_a_duplicate_without_verification() {
    let (shard, mc, calls, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4, 5])),
        SubmitOutcome::Accepted
    );
    let (verifier, committees) = (
        calls.verifier.load(Ordering::SeqCst),
        calls.committees.load(Ordering::SeqCst),
    );
    let fewer = shard.copy(&[1, 2, 3, 4, 5]);
    assert!(!mc.requires_verification(&fewer));
    assert_eq!(submit(&mc, fewer), SubmitOutcome::Duplicate);
    assert_eq!(calls.verifier.load(Ordering::SeqCst), verifier);
    assert_eq!(calls.committees.load(Ordering::SeqCst), committees);
    assert!(mc.requires_verification(&shard.copy(&[2, 3, 4, 5, 6])));
    assert!(mc.requires_verification(&bundle(&[&shard.header(&[0, 1, 2, 3, 4]); 2])));
}

/// Signatures merge only into the same header under the same proposal: over
/// anything else they sign something else.
#[test]
fn sca_a_copy_of_another_header_or_proposal_does_not_merge() {
    let (shard, mc, calls, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    let mut other_field = shard.header(&[1, 2, 3, 4, 5]);
    other_field.requests_root = vec![0x77; 32];
    assert_eq!(
        submit(&mc, bundle(&[&other_field])),
        SubmitOutcome::Duplicate
    );
    let moved = Proposal::new(
        Round::new(Epoch::new(0), View::new(VIEW + 1)),
        View::new(VIEW - 1),
        shard.proposal.payload,
    );
    let vote = |member: &Generic<Namespace>| {
        member
            .sign::<SimplexFalconScheme, Digest>(Subject::Finalize { proposal: &moved })
            .unwrap()
    };
    let certificate = shard.members[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(shard.members[1..6].iter().map(vote))
        .unwrap();
    let other_proposal = shard.with_certificate(&encode_finalization(&Finalization {
        proposal: moved,
        certificate,
    }));
    assert_eq!(
        submit(&mc, bundle(&[&other_proposal])),
        SubmitOutcome::Duplicate
    );
    assert_eq!(calls.committees.load(Ordering::SeqCst), 0, "not judged");
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4]);
}

/// A finalized frame carrying the frame ends the union: its copies leave, a
/// later one is a duplicate, and the shard's next frame is held as ever.
#[test]
fn sca_inclusion_ends_the_union() {
    let (shard, mc, calls, _) = one_shard(true);
    let first = shard.copy(&[0, 1, 2, 3, 4]);
    assert_eq!(submit(&mc, first), SubmitOutcome::Accepted);
    assert_eq!(
        submit(&mc, shard.copy(&[1, 2, 3, 4, 5])),
        SubmitOutcome::Accepted
    );
    // The frame rides with a copy other than the one held here.
    let included = shard.copy(&[0, 1, 2, 3, 4]);
    mc.mark_finalized(std::slice::from_ref(&included));
    {
        let log = mc.union.log.lock().unwrap();
        assert_eq!(log.counts.frames_included, 1);
        assert_eq!(log.counts.frames_included_short, 1);
        assert_eq!(log.counts.signers_left_out, 1, "member 5");
    }
    assert_eq!(mc.total_pending(), 0);
    let committees = calls.committees.load(Ordering::SeqCst);
    let late = shard.copy(&[2, 3, 4, 5, 6]);
    assert!(!mc.requires_verification(&late));
    assert_eq!(submit(&mc, late), SubmitOutcome::Duplicate);
    assert_eq!(calls.committees.load(Ordering::SeqCst), committees);
    assert_eq!(mc.total_pending(), 0);
    let mut next = shard.header(&[0, 1, 2, 3, 4]);
    next.frame_number = FRAME + 1;
    assert_eq!(submit(&mc, bundle(&[&next])), SubmitOutcome::Accepted);
}

/// An honest leader's bundle of several shards is served, each frame held alone
/// and verified, and each then takes later copies' signers.
#[test]
fn sca_a_bundle_of_several_shards_is_admitted_frame_by_frame() {
    let (a, b) = (Arc::new(Shard::new(0xA5, 7)), Arc::new(Shard::new(0xB6, 7)));
    let (mc, _, _) = collector(&[a.clone(), b.clone()], true);
    let raw = bundle(&[&a.header(&[0, 1, 2, 3, 4]), &b.header(&[0, 1, 2, 3, 4])]);
    assert!(mc.requires_verification(&raw));
    assert_eq!(submit(&mc, raw.clone()), SubmitOutcome::Accepted);
    let held = mc.collect_for_rank(RANK);
    assert_eq!(held.len(), 2);
    assert!(held
        .iter()
        .all(|raw| { headers_of(raw).len() == 1 && mc.is_verified(raw) }));
    assert_eq!(submit(&mc, raw), SubmitOutcome::Duplicate, "sent again");
    assert_eq!(
        submit(&mc, a.copy(&[2, 3, 4, 5, 6])),
        SubmitOutcome::Accepted
    );
    assert_eq!(a.held_pays(&mc), ALL);
    assert_eq!(b.held_pays(&mc), vec![0, 1, 2, 3, 4]);
    assert_eq!(mc.union.log.lock().unwrap().counts.bundles_split, 2);
}

/// Two frames of one shard in a bundle: the higher one stands, the lower adds
/// nothing, in either order. Other requests stay together as one message.
#[test]
fn sca_a_bundle_of_one_shards_frames_and_other_requests_is_taken_apart() {
    for reversed in [false, true] {
        let (shard, mc, _, _) = one_shard(true);
        let lower = shard.header(&[0, 1, 2, 3, 4]);
        let mut higher = lower.clone();
        higher.frame_number = FRAME + 1;
        let mut requests: Vec<_> = (if reversed {
            [&higher, &lower]
        } else {
            [&lower, &higher]
        })
        .iter()
        .map(|header| {
            Some(CanonicalMessageRequest {
                inner_type_prefix: TYPE_FRAME_HEADER,
                inner_bytes: header.to_canonical_bytes().unwrap(),
            })
        })
        .collect();
        let other = CanonicalMessageRequest {
            inner_type_prefix: 0x0301,
            inner_bytes: vec![0, 0, 3, 1, 9, 9],
        };
        requests.push(Some(other));
        let raw = CanonicalMessageBundle {
            requests,
            timestamp: 5,
        }
        .to_canonical_bytes()
        .unwrap();
        assert_eq!(submit(&mc, raw), SubmitOutcome::Accepted);
        let held = mc.collect_for_rank(RANK);
        assert_eq!(held.len(), 2, "the higher frame and the other request");
        let rest: Vec<_> = held
            .iter()
            .filter(|raw| headers_of(raw).is_empty())
            .collect();
        assert_eq!(rest.len(), 1);
        let rest = CanonicalMessageBundle::from_canonical_bytes(rest[0]).unwrap();
        assert_eq!(rest.timestamp, 5);
        assert_eq!(rest.requests.len(), 1);
        let tip: Vec<_> = held.iter().flat_map(|raw| headers_of(raw)).collect();
        assert_eq!(tip[0].frame_number, FRAME + 1);
    }
}

/// A forged frame ends a bundle: nothing after it costs a verification, and the
/// real frames come in on their own.
#[test]
fn sca_a_forged_frame_ends_a_bundle_at_no_more_cost_than_judging_it_whole() {
    let (a, b) = (Arc::new(Shard::new(0xA5, 7)), Arc::new(Shard::new(0xB6, 7)));
    let (mc, calls, _) = collector(&[a.clone(), b.clone()], true);
    let forged = forge(&a.header(&[0, 1, 2, 3, 4]), 2);
    assert_eq!(
        submit(&mc, bundle(&[&forged, &b.header(&[0, 1, 2, 3, 4])])),
        SubmitOutcome::Filtered(Refusal::InvalidShardFrame)
    );
    assert_eq!(calls.verifier.load(Ordering::SeqCst), 1);
    assert_eq!(mc.total_pending(), 0);
    assert_eq!(
        submit(&mc, b.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        submit(&mc, a.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
}

/// A union past the rank's byte cap is refused retryably, the held copy stands,
/// and it succeeds once there is room.
#[test]
fn sca_the_rank_byte_cap_refuses_a_union_retryably_and_it_recovers() {
    let (shard, mc, _, _) = one_shard(true);
    // As the GLOBAL collector, which cert unions reach.
    mc.set_class_shares();
    let held = shard.copy(&[0, 1, 2, 3, 4]);
    let held_len = held.len();
    assert_eq!(submit(&mc, held), SubmitOutcome::Accepted);
    // Storage epoch proofs fill part of the reserved room, and another
    // message the rest of the rank up to 16 bytes.
    let mut proofs = 0usize;
    for member in 0..5u8 {
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
        };
        let proof = StorageEpochProof {
            member: [member; 32],
            seats: vec![SeatProof {
                shard_filter: vec![member; 32],
                seals: true,
                ..Default::default()
            }],
            proof: vec![member; 7 << 19],
        };
        let raw = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest {
                inner_type_prefix: TYPE_STORAGE_EPOCH_PROOF,
                inner_bytes: proof.to_canonical_bytes(),
            })],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();
        proofs += raw.len();
        assert_eq!(submit(&mc, raw), SubmitOutcome::Accepted);
    }
    assert!(proofs + held_len + 16 > super::super::RESERVED_BYTES_PER_RANK);
    let filler = vec![0u8; MAX_BYTES_PER_RANK - proofs - held_len - 16];
    assert_eq!(submit(&mc, filler.clone()), SubmitOutcome::Accepted);
    let copy = shard.copy(&[1, 2, 3, 4, 5]);
    assert_eq!(
        submit(&mc, copy.clone()),
        SubmitOutcome::Filtered(Refusal::RankFull)
    );
    assert!(Refusal::RankFull.retryable());
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4]);
    assert_eq!(mc.union.log.lock().unwrap().counts.copies_rank_full, 1);
    mc.remove(std::slice::from_ref(&filler));
    assert_eq!(submit(&mc, copy), SubmitOutcome::Accepted);
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
}

/// With every place taken a copy waits, then leaves counted; the next copy
/// naming its signers restores them.
#[test]
fn sca_a_copy_finding_every_union_busy_is_counted_and_the_next_one_recovers() {
    let (shard, mc, calls, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    let slots: Vec<_> = (0..MAX_CONCURRENT_UNIONS)
        .map(|_| mc.union.slot().unwrap())
        .collect();
    let copy = shard.copy(&[1, 2, 3, 4, 5]);
    let started = Instant::now();
    assert_eq!(submit(&mc, copy.clone()), SubmitOutcome::Duplicate);
    assert!(started.elapsed() >= VERIFICATION_WAIT);
    assert_eq!(calls.committees.load(Ordering::SeqCst), 0, "not judged");
    assert_eq!(mc.union.log.lock().unwrap().counts.copies_busy, 1);
    drop(slots);
    assert_eq!(submit(&mc, copy), SubmitOutcome::Accepted);
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
}

/// A place freed while a copy waits serves it.
#[test]
fn sca_a_copy_waiting_for_a_union_place_gets_the_one_freed() {
    let (shard, mc, _, _) = one_shard(true);
    let mc = Arc::new(mc);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    let slots: Vec<_> = (0..MAX_CONCURRENT_UNIONS)
        .map(|_| mc.union.slot().unwrap())
        .collect();
    let waiter = {
        let (mc, copy) = (mc.clone(), shard.copy(&[1, 2, 3, 4, 5]));
        std::thread::spawn(move || submit(&mc, copy))
    };
    std::thread::sleep(VERIFICATION_WAIT / 8);
    drop(slots);
    assert_eq!(waiter.join().unwrap(), SubmitOutcome::Accepted);
    assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
}

/// Copies held because nothing could verify them give their signers to the
/// first copy that verifies, rather than leaving as superseded. A copy whose
/// new signer is forged gives nothing and stops nothing, and the real vote
/// counts when it comes.
#[test]
fn sca_a_verified_copy_takes_the_signers_of_unverified_ones() {
    for committees in [true, false] {
        let (shard, mc, _, available) = one_shard(committees);
        available.store(false, Ordering::SeqCst);
        assert_eq!(
            submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
            SubmitOutcome::Accepted
        );
        let forged = forge(&shard.header(&[0, 1, 2, 3, 6]), 6);
        assert_eq!(submit(&mc, bundle(&[&forged])), SubmitOutcome::Accepted);
        assert_eq!(mc.total_pending(), 2, "held unverified");
        available.store(true, Ordering::SeqCst);
        assert_eq!(
            submit(&mc, shard.copy(&[1, 2, 3, 4, 5])),
            SubmitOutcome::Accepted
        );
        assert_eq!(shard.held_pays(&mc), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(
            submit(&mc, shard.copy(&[2, 3, 4, 5, 6])),
            SubmitOutcome::Accepted
        );
        assert_eq!(shard.held_pays(&mc), ALL);
    }
}

/// The verified copy with an unverified source's very bytes as its union is
/// filed, not refused as a duplicate of that source.
#[test]
fn sca_a_union_equal_to_a_held_unverified_copy_is_filed_verified() {
    let (shard, mc, _, available) = one_shard(true);
    available.store(false, Ordering::SeqCst);
    let full = shard.copy(&ALL);
    assert_eq!(submit(&mc, full.clone()), SubmitOutcome::Accepted);
    available.store(true, Ordering::SeqCst);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    assert!(mc.is_verified(&full), "the union is those bytes, verified");
    assert_eq!(shard.held_pays(&mc), ALL);
}

/// At most `MAX_ABSORBED_COPIES` unverified copies are read, however many
/// forged ones are held. One beyond them leaves superseded and its signer comes
/// back with the next copy naming it.
#[test]
fn sca_absorption_is_bounded_and_the_next_copy_recovers() {
    let (shard, mc, calls, available) = one_shard(true);
    available.store(false, Ordering::SeqCst);
    let mut forged = Vec::new();
    for new in [5, 6] {
        for dropped in 0..5 {
            // Six named, one of them forged, each copy other bytes.
            let signers: Vec<usize> = (0..5).filter(|i| *i != dropped).chain([5, 6]).collect();
            let header = forge(&shard.header(&signers), new);
            forged.push(bundle(&[&header]));
        }
    }
    let forged_count = forged.len();
    assert!(forged_count > MAX_ABSORBED_COPIES);
    for raw in forged {
        assert_eq!(submit(&mc, raw), SubmitOutcome::Accepted);
    }
    let honest = shard.copy(&[1, 2, 3, 4, 6]);
    assert_eq!(submit(&mc, honest.clone()), SubmitOutcome::Accepted);
    available.store(true, Ordering::SeqCst);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        calls.committees.load(Ordering::SeqCst),
        MAX_ABSORBED_COPIES,
        "each read copy ends at its first forged signature"
    );
    assert_eq!(verified_copy_pays(&shard, &mc), vec![0, 1, 2, 3, 4]);
    assert_eq!(submit(&mc, honest), SubmitOutcome::Accepted);
    assert_eq!(verified_copy_pays(&shard, &mc), vec![0, 1, 2, 3, 4, 6]);
}

/// Copies nothing verified on arrival: the leader tries, and a proposal copies,
/// those naming the most signers first, whatever arrived first.
#[test]
fn sca_a_leader_tries_the_unverified_copy_naming_the_most_signers_first() {
    let (shard, mc, _, available) = one_shard(true);
    available.store(false, Ordering::SeqCst);
    let copies: Vec<Vec<u8>> = [
        vec![0, 1, 2, 3, 4],
        vec![1, 2, 3, 4, 5],
        vec![2, 3, 4, 5, 6],
        vec![0, 2, 3, 4, 6],
        ALL.to_vec(),
    ]
    .iter()
    .map(|signers| shard.copy(signers))
    .collect();
    for copy in &copies {
        assert_eq!(submit(&mc, copy.clone()), SubmitOutcome::Accepted);
    }
    let taken: Vec<Vec<u8>> = mc
        .snapshot_for_proposal(RANK, 1 << 24, 1000, None, &[])
        .unwrap()
        .into_iter()
        .map(|(raw, _)| raw)
        .collect();
    assert_eq!(taken.len(), crate::leader_provider::MAX_TIP_VERIFICATIONS);
    assert!(
        taken.contains(&copies[4]),
        "the copy naming most signers arrived last and is still examined"
    );
    let mut messages = copies.clone();
    order_copies_by_signers(&mut messages);
    let tips = select_shard_tips(messages, |_| false, |_: &[u8]| TipCheck::Valid);
    assert_eq!(tips.kept, vec![copies[4].clone()]);
    // Copies naming as many keep arrival order.
    let mut ties = copies[..4].to_vec();
    order_copies_by_signers(&mut ties);
    assert_eq!(ties, copies[..4].to_vec());
}

/// A union is what a leader may carry: its encoding survives the proposal's
/// round trip, and the production check pays each signer, at every size up to
/// the whole committee.
#[test]
fn sca_a_union_is_a_canonical_header_the_production_check_accepts() {
    let shard = Arc::new(Shard::new(0xA5, 16));
    let (mc, _, _) = collector(std::slice::from_ref(&shard), true);
    let quorum: Vec<usize> = (0..11).collect();
    let first = shard.copy(&quorum);
    assert_eq!(submit(&mc, first.clone()), SubmitOutcome::Accepted);
    let mut grown = first.len();
    for new in 11..16 {
        let signers: Vec<usize> = (new - 10..=new).collect();
        assert_eq!(submit(&mc, shard.copy(&signers)), SubmitOutcome::Accepted);
        let held = mc.collect_for_rank(RANK);
        assert_eq!(held.len(), 1);
        let canonical = crate::consensus_wire::decode_message_bundle_at(&held[0], Some(100))
            .and_then(|bundle| {
                crate::consensus_wire::proto_message_bundle_to_canonical_bytes_at(
                    &bundle,
                    Some(100),
                )
            })
            .unwrap();
        assert_eq!(canonical, held[0]);
        assert!(held[0].len() > grown);
        grown = held[0].len();
        assert_eq!(
            shard.held_pays(&mc),
            (0..=new).collect::<Vec<_>>(),
            "pays each signer so far"
        );
    }
}

/// Copies arriving at once lose no signer, however their checks interleave.
#[test]
fn sca_copies_arriving_at_once_lose_no_signer() {
    let shard = Arc::new(Shard::new(0xA5, 16));
    let (mc, _, _) = collector(std::slice::from_ref(&shard), true);
    let mc = Arc::new(mc);
    assert_eq!(
        submit(&mc, shard.copy(&(0..11).collect::<Vec<_>>())),
        SubmitOutcome::Accepted
    );
    let threads: Vec<_> = (11..16)
        .map(|new| {
            let (mc, shard) = (mc.clone(), shard.clone());
            std::thread::spawn(move || {
                let copy = shard.copy(&(new - 10..=new).collect::<Vec<_>>());
                submit(&mc, copy)
            })
        })
        .collect();
    for thread in threads {
        // A copy finding its signers taken already is a duplicate.
        assert!(!matches!(
            thread.join().unwrap(),
            SubmitOutcome::Filtered(_)
        ));
    }
    assert_eq!(shard.held_pays(&mc), (0..16).collect::<Vec<_>>());
}

/// A union stays where the copy it extends was filed: it buys no more retention.
#[test]
fn sca_a_union_ages_out_with_the_copy_it_extended() {
    let (shard, mc, _, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    for rank in RANK + 1..RANK + 4 {
        mc.prune_after_finalization(rank);
    }
    assert_eq!(
        submit(&mc, shard.copy(&[1, 2, 3, 4, 5])),
        SubmitOutcome::Accepted
    );
    assert_eq!(mc.pending_count(RANK), 1, "filed where it was");
    for rank in RANK + 4..RANK + 20 {
        mc.prune_after_finalization(rank);
    }
    assert_eq!(mc.total_pending(), 0);
}

/// A proposal's private copy keeps a union verified, and has no verifier of its
/// own to merge with.
#[test]
fn sca_a_private_proposal_copy_keeps_a_union_verified() {
    let (shard, mc, _, _) = one_shard(true);
    assert_eq!(
        submit(&mc, shard.copy(&[0, 1, 2, 3, 4])),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        submit(&mc, shard.copy(&[1, 2, 3, 4, 5])),
        SubmitOutcome::Accepted
    );
    let (raw, verified) = mc
        .snapshot_for_proposal(RANK, 1 << 24, 100, None, &[])
        .unwrap()
        .remove(0);
    assert!(verified);
    let private = MessageCollector::new();
    assert!(private.add_verified_message(RANK, raw.clone()));
    assert!(private.is_verified(&raw));
    assert!(!private.add_verified_message(RANK, shard.copy(&[2, 3, 4, 5, 6])));
    assert_eq!(private.total_pending(), 1, "a private copy merges nothing");
    assert!(private.is_verified(&raw));
}

/// The cache of committees is bounded and works after it was cleared.
#[test]
fn sca_remembered_committees_are_bounded() {
    let committee = Arc::new(Committee {
        members: Vec::new(),
        namespace: Vec::new(),
    });
    let mut cache = HashMap::new();
    for generation in 0..MAX_COMMITTEES as u64 {
        remember_committee(&mut cache, (vec![1], generation), committee.clone());
    }
    assert_eq!(cache.len(), MAX_COMMITTEES);
    remember_committee(&mut cache, (vec![2], 1), committee);
    assert_eq!(cache.len(), 1);
    assert!(cache.contains_key(&(vec![2], 1)));
}

/// CPU this process has used.
fn cpu() -> Duration {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `t` is a valid out parameter for the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) };
    assert_eq!(rc, 0);
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
}

/// Run `submit_all` over `copies` on four threads, as admissions run at once.
fn admit_all(mc: &MessageCollector, copies: &[Vec<u8>]) -> (Duration, Duration, usize) {
    let (cpu_before, wall_before) = (cpu(), Instant::now());
    let next = AtomicUsize::new(0);
    let accepted = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(copy) = copies.get(i) else { return };
                if submit(mc, copy.clone()) == SubmitOutcome::Accepted {
                    accepted.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    (
        cpu() - cpu_before,
        wall_before.elapsed(),
        accepted.load(Ordering::Relaxed),
    )
}

/// One GLOBAL frame's intake at full scale: 109 shards of 16 members (quorum
/// 11), each member publishing the first quorum it saw, real Falcon signatures
/// and the production certificate check. Run with `--run-ignored only`; the
/// numbers are the result (CPU, so a shared host does not skew them).
#[test]
#[ignore = "a measurement, run on purpose"]
fn sca_full_scale_cost_at_109_shards() {
    const SHARDS: usize = 109;
    const MEMBERS: usize = 16;
    const QUORUM: usize = 11;
    let start = Instant::now();
    let shards: Vec<Arc<Shard>> = (0..SHARDS)
        .map(|i| Arc::new(Shard::new(i as u8, MEMBERS)))
        .collect();
    let copy_of = |shard: &Shard, member: usize| {
        let signers: Vec<usize> = {
            let mut s: Vec<usize> = (0..QUORUM).map(|i| (member + i) % MEMBERS).collect();
            s.sort_unstable();
            s
        };
        shard.copy(&signers)
    };
    let first: Vec<Vec<u8>> = shards.iter().map(|shard| copy_of(shard, 0)).collect();
    let mut rest: Vec<Vec<u8>> = Vec::with_capacity(SHARDS * (MEMBERS - 1));
    for member in 1..MEMBERS {
        rest.extend(shards.iter().map(|shard| copy_of(shard, member)));
    }
    println!("SCA-COST setup_secs={}", start.elapsed().as_secs());

    let held_bytes = |mc: &MessageCollector| {
        mc.collect_for_rank(RANK)
            .iter()
            .map(|raw| raw.len())
            .sum::<usize>()
    };
    for committees in [true, false] {
        let (mc, calls, _) = collector(&shards, committees);
        let (cpu_first, wall_first, accepted) = admit_all(&mc, &first);
        assert_eq!(accepted, SHARDS);
        let first_bytes = held_bytes(&mc);
        let (cpu_rest, wall_rest, merged) = admit_all(&mc, &rest);
        let union_bytes = held_bytes(&mc);
        let paid: usize = shards.iter().map(|shard| shard.held_pays(&mc).len()).sum();
        assert_eq!(paid, SHARDS * MEMBERS, "the union of copies pays everyone");
        println!(
            "SCA-COST committees={committees} shards={SHARDS} members={MEMBERS} quorum={QUORUM} \
             first_copies={} first_cpu_ms={} first_wall_ms={} \
             other_copies={} merged={merged} union_cpu_ms={} union_wall_ms={} \
             whole_frame_verifications={} first_bytes={first_bytes} union_bytes={union_bytes}",
            first.len(),
            cpu_first.as_millis(),
            wall_first.as_millis(),
            rest.len(),
            cpu_rest.as_millis(),
            wall_rest.as_millis(),
            calls.verifier.load(Ordering::SeqCst),
        );
        if committees {
            // The flood a peer can send: every shard's frame, a forged new signer.
            let (mc, _, _) = collector(&shards, true);
            admit_all(&mc, &first);
            let forged_new: Vec<Vec<u8>> = shards
                .iter()
                .map(|shard| {
                    let signers: Vec<usize> = (5..MEMBERS).collect();
                    bundle(&[&forge(&shard.header(&signers), 15)])
                })
                .collect();
            let (cpu_forged, wall_forged, _) = admit_all(&mc, &forged_new);
            println!(
                "SCA-COST forged_new_signer copies={} cpu_ms={} wall_ms={}",
                forged_new.len(),
                cpu_forged.as_millis(),
                wall_forged.as_millis(),
            );
            // Copies naming nobody new, the steady state of a frame's intake.
            let (mc2, _, _) = collector(&shards, true);
            admit_all(&mc2, &first);
            admit_all(&mc2, &rest);
            let (cpu_dup, wall_dup, _) = admit_all(&mc2, &rest);
            println!(
                "SCA-COST no_new_signer copies={} cpu_ms={} wall_ms={}",
                rest.len(),
                cpu_dup.as_millis(),
                wall_dup.as_millis(),
            );
            // A leader ordering the frame's shard proofs.
            let mut proofs = mc2.collect_for_rank(RANK);
            let before = cpu();
            order_copies_by_signers(&mut proofs);
            println!(
                "SCA-COST leader_order proofs={} cpu_us={}",
                proofs.len(),
                (cpu() - before).as_micros(),
            );
            // Finalization comparing what rode with what is held.
            let before = cpu();
            mc2.note_included(&first);
            println!(
                "SCA-COST note_included frames={} cpu_us={}",
                first.len(),
                (cpu() - before).as_micros(),
            );
            assert!(
                cpu_rest < Duration::from_secs(1),
                "a union of every shard's copies must take a small part of a 10 s frame"
            );
        }
    }
}

/// A union takes the place of the verified copy it extends, and a coin that
/// copy's shield held stays held by the union: no other shield of the coin is
/// taken while it is pending.
#[test]
fn a_union_keeps_the_coin_the_copy_it_extended_held() {
    let (shard, mc, _, _) = one_shard(true);
    let first = shard.copy(&[0, 1, 2, 3, 4]);
    assert_eq!(submit(&mc, first.clone()), SubmitOutcome::Accepted);
    let claim = |statement: u8| {
        [quil_execution::manager::ShieldClaim {
            coin: [9; 32],
            statement: [statement; 32],
        }]
    };
    let now = Instant::now();
    mc.shield_claims
        .lock()
        .unwrap()
        .hold(super::super::message_key(&first), &claim(1), now);
    assert_eq!(
        submit(&mc, shard.copy(&[2, 3, 4, 5, 6])),
        SubmitOutcome::Accepted
    );
    assert_eq!(shard.held_pays(&mc), ALL);
    let held: Vec<[u8; 32]> = mc
        .collect_for_rank(RANK)
        .iter()
        .map(|raw| super::super::message_key(raw))
        .collect();
    let taken = mc.shield_claims.lock().unwrap().taken(
        &[5; 32],
        &claim(2),
        now,
        |key| held.contains(key),
        |_| None,
    );
    assert!(
        taken,
        "VULNERABLE: the union gave up the coin its copy held, and another shield of it was taken"
    );
}
