//! A/B reproducers for a rewritten field of a shard frame header at GLOBAL's
//! sequenced ingest (`sequenced_ingest_hook`). Before a GLOBAL frame executes,
//! each archive materializes every shard through the highest header the frame
//! vouches for, and execution waits until it can. A certificate binds a
//! header's view and the digest of its output; the output binds the frame
//! number and every other field, and only execution recomputed it. So anyone
//! holding a genuine certified header (GLOBAL frames carry them in the clear)
//! could rewrite its frame number: the certificate still verifies, the hook
//! waits for bodies no committee made, and execution, which would skip the
//! header, is never reached. Only release-base APIs are used. The rig is an
//! archive's: real Falcon certificates, an authorized session, the real
//! ingest, the real materializer and finalization pipeline; only the VDF is a
//! stub.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use quil_cw_consensus::{
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{sha256::Digest as CwDigest, Signer as _},
    _utils::{ordered::Set, N3f1},
    adapters::{digest_from_identity, Digest},
    app_cert::{encode_finalization, wrap_cert_for_header},
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
    handoff::Session,
};
use quil_engine::{
    archive_ingest::{lock_ingest, ArchiveAppShardIngest},
    frame_materializer::{FrameMaterializer, GlobalParentExecutor, GlobalParentLimits},
    frame_validator::GlobalFrameVerifier,
    global_finalization::{
        FinalizationStep, FinalizedFrameAnnouncer, GlobalFinalizationLimits,
        GlobalFinalizationPipeline, SequencedIngest,
    },
    leader_provider::GlobalLeaderProvider,
    message_collector::MessageCollector,
};
use quil_execution::{
    global_intrinsic::{conversions, handoff, prover_shard_update},
    hypergraph_state::HypergraphState,
    SharedProverRegistry,
};
use quil_types::{
    crypto::{FrameProver, Signer},
    error::{QuilError, Result},
    proto::{
        global::{
            message_request::Request, AppShardFrame, FrameHeader, GlobalFrame, GlobalFrameHeader,
            MessageBundle, MessageRequest,
        },
        keys::Bls48581AggregateSignature,
    },
    store::ClockStore,
};

use super::{sequenced_ingest_hook, AppIngestCell};

/// The frame number a forged copy claims: no committee will reach it.
const REWRITTEN: u64 = 1 << 60;

/// Structure-only VDF: these tests exercise certificates, ingest and
/// execution, not the VDF.
pub(super) struct StubFrameProver;
impl FrameProver for StubFrameProver {
    fn prove_frame_header(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[Vec<u8>],
        _: &[u8],
        _: i64,
        _: u32,
        _: u64,
        _: u64,
        _: &[u8],
        _: u64,
    ) -> Result<FrameHeader> {
        unreachable!()
    }
    fn prove_global_frame_header(
        &self,
        _: &GlobalFrameHeader,
        _: &[Vec<u8>],
        _: &[u8],
        _: &[Vec<u8>],
        _: &[u8],
        _: u64,
        _: &dyn Signer,
        _: i64,
        _: u32,
        _: u8,
    ) -> Result<GlobalFrameHeader> {
        unreachable!()
    }
    fn verify_global_frame_header(&self, header: &GlobalFrameHeader) -> Result<Vec<u8>> {
        if header.output.len() != 516 {
            return Err(QuilError::InvalidArgument("test VDF rejected".into()));
        }
        Ok(header.output.clone())
    }
    fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> {
        Ok(true)
    }
}

/// The output every GLOBAL frame `number` has in these rigs.
fn global_output(number: u64) -> Vec<u8> {
    vec![number as u8; 516]
}

fn identity(frame: &GlobalFrame) -> Digest {
    digest_from_identity(
        quil_crypto::poseidon::hash_bytes_to_32(&frame.header.as_ref().unwrap().output).unwrap(),
    )
}

pub(super) fn single(header: FrameHeader) -> MessageBundle {
    MessageBundle {
        requests: vec![MessageRequest {
            request: Some(Request::Shard(header)),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn save(clock: &dyn ClockStore, frame: &GlobalFrame) {
    let txn = clock.new_transaction(false).unwrap();
    clock.put_global_clock_frame(frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
}

fn falcon_key(signer: &quil_crypto::FalconSigner) -> FalconPrivateKey {
    FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap()
}

/// A finalization of `digest` at `view` over `parent` by three of `keys`.
fn sign_finalization(
    namespace: &[u8],
    epoch: u64,
    keys: &[FalconPrivateKey],
    quorum: usize,
    view: u64,
    parent: u64,
    digest: [u8; 32],
) -> Vec<u8> {
    let proposal = Proposal::new(
        Round::new(Epoch::new(epoch), View::new(view)),
        View::new(parent),
        CwDigest(digest),
    );
    let participants: Set<_> = keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let schemes: Vec<Generic<Namespace>> = keys
        .iter()
        .cloned()
        .map(|key| Generic::signer(namespace, participants.clone(), key).unwrap())
        .collect();
    let votes: Vec<_> = schemes[..quorum]
        .iter()
        .map(|scheme| {
            scheme
                .sign::<SimplexFalconScheme, CwDigest>(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = schemes[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    encode_finalization(&Finalization {
        proposal,
        certificate,
    })
}

/// GLOBAL frame `number` on the current state, as a leader builds it, with no
/// certificate yet.
fn state_frame(
    crdt: &quil_hypergraph::HypergraphCrdt,
    number: u64,
    rank: u64,
    parent: Digest,
    requests: Vec<MessageBundle>,
) -> GlobalFrame {
    let bytes: Vec<_> = requests
        .iter()
        .map(|bundle| {
            quil_engine::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle).unwrap()
        })
        .collect();
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: number,
            rank,
            difficulty: 200_000,
            prover: vec![0x42; 32],
            output: global_output(number),
            parent_selector: parent.as_ref().to_vec(),
            prover_tree_commitment: crdt
                .current_forest_phase_root(&[0xff; 32], 0)
                .unwrap()
                .to_vec(),
            prover_tree_aux_roots: vec![
                crdt.current_forest_phase_root(&[0xff; 32], 1)
                    .unwrap()
                    .to_vec(),
                Vec::new(),
                crdt.current_forest_phase_root(&[0xff; 32], 3)
                    .unwrap()
                    .to_vec(),
            ],
            global_commitments: crdt.global_commitments_checked().unwrap(),
            world_state_size: u64::try_from(&crdt.total_size()).unwrap(),
            requests_root: quil_engine::leader_provider::compute_global_requests_root(
                &bytes,
                &quil_tries::ShaInclusionProver,
            ),
            ..Default::default()
        }),
        requests,
    }
}

/// An archive at the genesis of GLOBAL, its one-member GLOBAL committee, one
/// shard's authorized session of four members (generation 1, base frame 0),
/// and the hook as `spawn_all` builds it.
pub(super) struct Rig {
    pub(super) db: Arc<quil_store::RocksDb>,
    pub(super) clock: Arc<quil_store::RocksClockStore>,
    pub(super) crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub(super) registry: Arc<SharedProverRegistry>,
    signer: Arc<quil_crypto::FalconSigner>,
    keys: Vec<FalconPrivateKey>,
    pub(super) session: Session,
    pub(super) ingest: AppIngestCell,
    pub(super) hook: SequencedIngest,
    executor: Arc<GlobalParentExecutor>,
    verifier: Arc<GlobalFrameVerifier>,
    pub(super) source: Arc<FrameMaterializer>,
    genesis: GlobalFrame,
}

impl Rig {
    pub(super) fn new() -> Self {
        crate::consensus_settings::initialize(1);
        let signer = Arc::new(quil_crypto::FalconSigner::generate());
        let members: Vec<_> = (0..4)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let keys: Vec<_> = members.iter().map(falcon_key).collect();
        let mut sorted: Vec<_> = members.iter().map(|m| m.public_key().to_vec()).collect();
        sorted.sort();
        let session = Session {
            chain_id: [0x21; 32],
            filter: vec![0x68; 32],
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0,
            authorization: [0x34; 32],
            members: sorted,
        };
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let inclusion = Arc::new(quil_tries::ShaInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            inclusion.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        crdt.warm_sizes(&[]).unwrap();
        quil_engine::genesis::seed_active_prover_on_filter(
            &crdt,
            signer.public_key(),
            1000,
            0,
            &[],
        )
        .unwrap();
        for member in &session.members {
            quil_engine::genesis::seed_active_prover_on_filter(
                &crdt,
                member,
                1000,
                0,
                &session.filter,
            )
            .unwrap();
        }
        let state = HypergraphState::new(crdt.clone());
        handoff::initialize(&state, 0, &session).unwrap();
        state.commit().unwrap();
        state.abort();
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(
            quil_execution::ExecutionEngineManager::new_with_shards(
                inclusion.clone(),
                stubs.key_manager,
                crdt.clone(),
                stubs.circuit_compiler,
                clock.clone(),
                Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
                true,
                Some(Arc::new(quil_store::RocksShardsStore::new(db.inner()))),
                Some(db.clone()),
            )
            .with_pricing_network(1),
        );
        crdt.commit_with_global_cursor(0, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        let root = crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap();
        crdt.record_prover_root(0, root.to_vec());
        let registry = Arc::new(SharedProverRegistry::new());
        registry.refresh_from_store(store.as_ref()).unwrap();
        let stub_prover: Arc<dyn FrameProver> = Arc::new(StubFrameProver);
        manager
            .install_global_frame_header_deps(
                registry.clone(),
                Arc::new(quil_engine::OptRewardIssuance),
                Arc::new(quil_crypto::FalconKeyConstructor),
                inclusion.clone(),
                stub_prover.clone(),
            )
            .unwrap();
        let source = Arc::new(
            FrameMaterializer::new(
                manager.clone(),
                registry.clone(),
                clock.clone(),
                crdt.clone(),
                store,
                Arc::new(quil_engine::OptRewardIssuance),
                vec![8; 32],
                true,
            )
            .with_eviction_registry(registry.clone())
            .with_shard_admission_refresh(Arc::new(|_| Ok(()))),
        );
        let ingest = ArchiveAppShardIngest::new(
            registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            stub_prover.clone(),
            manager.clone(),
            inclusion.clone(),
            crdt.clone(),
            clock.clone(),
        )
        .sequenced();
        let cell: AppIngestCell = Default::default();
        assert!(cell.set(Arc::new(Mutex::new(ingest))).is_ok());
        let hook = sequenced_ingest_hook(
            cell.clone(),
            crdt.clone(),
            stub_prover.clone(),
            registry.clone(),
            clock.clone(),
        );
        let collector = Arc::new(MessageCollector::new());
        let leader = Arc::new(GlobalLeaderProvider::new(
            registry.clone(),
            stub_prover.clone(),
            Arc::new(quil_engine::AsertDifficultyAdjuster::new(0, 0, 100)),
            clock.clone(),
            collector,
            quil_crypto::poseidon::hash_bytes_to_32(signer.public_key())
                .unwrap()
                .to_vec(),
            signer.public_key().to_vec(),
            signer.clone(),
            inclusion,
            Some(manager),
            Some(crdt.clone()),
        ));
        let verifier = Arc::new(
            GlobalFrameVerifier::new(stub_prover)
                .with_global_committee(vec![signer.public_key().to_vec()]),
        );
        let genesis = state_frame(&crdt, 0, 0, digest_from_identity([0; 32]), Vec::new());
        save(clock.as_ref(), &genesis);
        let executor = Arc::new(GlobalParentExecutor::new(
            source.clone(),
            leader,
            0,
            0,
            identity(&genesis),
            GlobalParentLimits::default(),
        ));
        Self {
            db,
            clock,
            crdt,
            registry,
            signer,
            keys,
            session,
            ingest: cell,
            hook,
            executor,
            verifier,
            source,
            genesis,
        }
    }

    /// `frame` with its GLOBAL committee's finalization.
    fn certify(&self, frame: &mut GlobalFrame, parent_view: u64) {
        let header = frame.header.as_mut().unwrap();
        let certificate = sign_finalization(
            b"global",
            0,
            &[falcon_key(&self.signer)],
            1,
            header.rank,
            parent_view,
            quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
        );
        header.public_key_signature_bls48581 = Some(Bls48581AggregateSignature {
            signature: wrap_cert_for_header(&certificate),
            ..Default::default()
        });
    }

    /// The finalization pipeline of an archive: the hook runs before each
    /// frame executes.
    pub(super) fn pipeline(&self) -> GlobalFinalizationPipeline {
        GlobalFinalizationPipeline::new(
            self.executor.clone(),
            self.verifier.clone(),
            self.clock.clone(),
            FinalizedFrameAnnouncer::new(Arc::new(|_, _| {}), None, vec![]),
            GlobalFinalizationLimits {
                max_queued: 8,
                max_attempts: 3,
                busy_patience: Duration::from_secs(60),
                retry: Duration::from_millis(1),
                max_ahead: 32,
            },
        )
        .with_sequenced_ingest(self.hook.clone())
    }

    /// Publish GLOBAL frames 1 through `through` with no requests, each after
    /// the last, through `pipeline`; returns the last.
    pub(super) fn publish_through(
        &self,
        pipeline: &GlobalFinalizationPipeline,
        through: u64,
    ) -> GlobalFrame {
        let mut parent = self.genesis.clone();
        for number in 1..=through {
            let input = self.next_frame(&parent, Vec::new());
            assert!(pipeline.offer(input.clone()));
            let step = pipeline.step(number);
            assert!(
                matches!(step, FinalizationStep::Published { .. }),
                "FH-R1 SETUP: GLOBAL frame {number} with no requests must publish"
            );
            parent = input;
        }
        parent
    }

    /// The certified child of `parent` carrying `requests`.
    pub(super) fn next_frame(
        &self,
        parent: &GlobalFrame,
        requests: Vec<MessageBundle>,
    ) -> GlobalFrame {
        let header = parent.header.as_ref().unwrap();
        let mut input = state_frame(
            &self.crdt,
            header.frame_number + 1,
            header.rank + 41,
            identity(parent),
            requests,
        );
        self.certify(&mut input, header.rank);
        input
    }

    /// A GLOBAL frame record this archive holds, as an anchor.
    pub(super) fn hold(&self, number: u64) {
        save(
            self.clock.as_ref(),
            &GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: number,
                    output: global_output(number),
                    difficulty: 160_000,
                    ..Default::default()
                }),
                requests: Vec::new(),
            },
        );
    }

    /// The header of the session's frame `frame` as its committee made it:
    /// anchored to GLOBAL frame `anchor`, proving it carried no requests,
    /// certified by three of its four members.
    pub(super) fn certified(&self, frame: u64, anchor: u64) -> FrameHeader {
        let beacon = quil_crypto::porep::derive_storage_beacon(anchor, &global_output(anchor));
        let first = frame == self.session.base_frame + 1;
        let view = 5 + frame;
        let mut header = FrameHeader {
            address: self.session.filter.clone(),
            frame_number: frame,
            rank: view,
            difficulty: 50_000,
            timestamp: 1_700_000_000_000,
            global_frame_number: anchor,
            parent_selector: if first {
                self.session.genesis.to_vec()
            } else {
                vec![0x33; 32]
            },
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        header.output = quil_crypto::porep::deterministic_app_frame_output(
            &header.parent_selector,
            &header.requests_root,
            &header.state_roots,
            &beacon,
            header.frame_number,
            header.rank,
            &header.prover,
            header.difficulty,
            header.fee_multiplier_vote,
            header.timestamp,
            &header.storage_attestation_root,
            0,
            &header.settlements,
            &header.accumulator,
            &header.spends,
        );
        let certificate = sign_finalization(
            &self.session.namespace().unwrap(),
            self.session.generation,
            &self.keys,
            3,
            view,
            if first { 0 } else { view - 1 },
            quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
        );
        header.public_key_signature_bls48581 = Some(Bls48581AggregateSignature {
            signature: wrap_cert_for_header(&certificate),
            ..Default::default()
        });
        header
    }

    /// `header` as a leader carrying a tampered copy rewrites it.
    pub(super) fn rewritten(header: &FrameHeader, frame: u64) -> FrameHeader {
        FrameHeader {
            frame_number: frame,
            ..header.clone()
        }
    }

    /// Hand the ingest a frame's body, as the gap fetch does.
    pub(super) fn admit_body(&self, header: &FrameHeader) {
        lock_ingest(self.ingest.get().unwrap()).admit_verified(
            AppShardFrame {
                header: Some(header.clone()),
                requests: Vec::new(),
                storage_attestation: None,
            },
            true,
        );
    }

    pub(super) fn height(&self) -> u64 {
        lock_ingest(self.ingest.get().unwrap())
            .materialized_height(&self.session.filter)
            .unwrap()
    }

    /// The certificate check the hook has always applied: the forged copy
    /// must pass it and fail its output, or a test would pass for another
    /// reason.
    pub(super) fn check_forged_setup(&self, forged: &FrameHeader, frame: u64) {
        let op = conversions::frame_header_from_proto(forged);
        let state = HypergraphState::new(self.crdt.clone());
        let session = prover_shard_update::verify_frame_header_session(
            &state,
            &op,
            &StubFrameProver,
            &quil_crypto::FalconKeyConstructor,
            self.registry.as_ref(),
            forged.global_frame_number,
            frame,
        );
        assert!(
            session.is_ok(),
            "FH-R1 SETUP: the certificate of a header with its frame number rewritten must \
             still verify: {:?}",
            session.err()
        );
        let output = prover_shard_update::verify_app_frame_output(
            &op,
            &global_output(op.global_frame_number),
        );
        assert!(
            output.is_err(),
            "FH-R1 SETUP: the output must bind the frame number, or execution would accept it"
        );
    }
}

/// A GLOBAL frame `number` carrying `headers`, for tests of the hook alone.
pub(super) fn frame_carrying(number: u64, headers: Vec<FrameHeader>) -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: number,
            ..Default::default()
        }),
        requests: headers.into_iter().map(single).collect(),
    }
}

/// The hook vouches a header by certificate alone and waits for bodies
/// through its number, though the certificate does not bind the number. A
/// frame that carries a rewritten copy waits for ever on every archive.
#[test]
fn fh_r1_hook_must_not_wait_for_a_rewritten_frame_number() {
    let rig = Rig::new();
    let anchor = 2;
    rig.hold(anchor);
    let forged = Rig::rewritten(&rig.certified(2, anchor), REWRITTEN);
    rig.check_forged_setup(&forged, 3);
    let input = frame_carrying(3, vec![forged]);
    for attempt in 1..=3 {
        match (rig.hook)(&input) {
            Ok(true) => {}
            other => panic!(
                "FH-R1 HALT: a certified shard header with its frame number rewritten to \
                 {REWRITTEN} makes sequenced ingest wait for GLOBAL frame 3 (attempt {attempt}: \
                 {other:?}, shard height {}); no committee will make those bodies, and execution, \
                 which skips the header, is never reached",
                rig.height()
            ),
        }
    }
    assert_eq!(rig.height(), 0, "a forged header materializes nothing");
    eprintln!("FH-R1 FIX: a rewritten frame number makes sequenced ingest wait for nothing");
}

/// The whole path: consensus finalized the frame (voters do not execute it),
/// and the finalization pipeline retries it at the hook for ever, without
/// reaching its atomic attempts or the legacy fallback. A deterministic
/// refusal skips the header and the frame publishes.
#[test]
fn fh_r1_finalization_must_publish_a_frame_carrying_a_rewritten_frame_number() {
    let rig = Rig::new();
    let pipeline = rig.pipeline();
    let parent = rig.publish_through(&pipeline, 2);
    let forged = Rig::rewritten(&rig.certified(2, 2), REWRITTEN);
    rig.check_forged_setup(&forged, 3);
    let input = rig.next_frame(&parent, vec![single(forged)]);
    assert!(pipeline.offer(input));
    let mut retries = 0;
    loop {
        match pipeline.step(3) {
            FinalizationStep::Published { result, .. } => {
                assert_eq!(
                    (result.processed, result.skipped),
                    (0, 1),
                    "the refused header is skipped and the frame publishes"
                );
                break;
            }
            FinalizationStep::Retry(_) if retries < 8 => retries += 1,
            FinalizationStep::Retry(_) => panic!(
                "FH-R1 HALT: the finalization pipeline retried GLOBAL frame 3 {retries} times at \
                 sequenced ingest, past its 3 atomic attempts: the frame never executes and no \
                 legacy fallback is reached (executed cursor {}, shard height {})",
                rig.source.last_materialized_frame(),
                rig.height()
            ),
            _ => panic!("FH-R1 UNEXPECTED: GLOBAL frame 3 neither published nor retried"),
        }
    }
    assert_eq!(rig.source.last_materialized_frame(), 3);
    assert_eq!(rig.height(), 0, "a forged header materializes nothing");
    eprintln!("FH-R1 FIX: the frame carrying a rewritten header publishes, skipping it");
}

/// A rewritten copy beside the genuine header: the genuine one still decides
/// what the frame sequences, and the frame waits only for its real body.
#[test]
fn fh_r1_a_rewritten_copy_must_not_hold_up_the_genuine_header() {
    let rig = Rig::new();
    let pipeline = rig.pipeline();
    let parent = rig.publish_through(&pipeline, 2);
    let genuine = rig.certified(1, 2);
    let second = rig.certified(2, 2);
    let forged = Rig::rewritten(&second, REWRITTEN);
    let input = rig.next_frame(&parent, vec![single(genuine.clone()), single(forged)]);
    assert!(pipeline.offer(input));
    assert!(
        matches!(pipeline.step(3), FinalizationStep::Retry(_)),
        "control: the genuine header still waits for its body"
    );
    rig.admit_body(&genuine);
    let mut retries = 0;
    loop {
        match pipeline.step(3) {
            FinalizationStep::Published { .. } => break,
            FinalizationStep::Retry(_) if retries < 8 => retries += 1,
            _ => panic!(
                "FH-R1 HALT: GLOBAL frame 3 carries a genuine header whose body is held and a \
                 rewritten copy of another; it never publishes (shard height {})",
                rig.height()
            ),
        }
    }
    assert_eq!(rig.height(), 1, "materialized through the genuine header");
    eprintln!("FH-R1 FIX: a rewritten copy does not hold up the genuine header");
}

/// Below the real tip the rewritten number stalls nothing but moves shard
/// state: an archive that holds the bodies materializes through a number no
/// certified header of the frame names, and one that does not waits for them,
/// though execution reads the shard sizes this state makes up.
#[test]
fn fh_r1_hook_must_not_materialize_ahead_through_a_rewritten_frame_number() {
    let rig = Rig::new();
    rig.hold(2);
    let bodies: Vec<_> = (1..=3).map(|frame| rig.certified(frame, 2)).collect();
    for body in &bodies {
        rig.admit_body(body);
    }
    let forged = Rig::rewritten(&bodies[1], 3);
    rig.check_forged_setup(&forged, 3);
    let ready = (rig.hook)(&frame_carrying(3, vec![forged]));
    assert!(
        matches!(ready, Ok(true)),
        "control: every body is held: {ready:?}"
    );
    assert_eq!(
        rig.height(),
        0,
        "FH-R1 AHEAD: the frame carries only a rewritten copy of frame 2's header, numbered 3, \
         and the archive materialized the shard through what it claims"
    );
    eprintln!("FH-R1 FIX: a rewritten frame number moves no shard state");
}

/// Control on both builds: a genuine header waits for its body, however long,
/// and the frame then publishes with the shard at exactly that frame.
#[test]
fn fh_control_a_genuine_header_waits_for_its_body_then_publishes() {
    let rig = Rig::new();
    let pipeline = rig.pipeline();
    let parent = rig.publish_through(&pipeline, 2);
    let genuine = rig.certified(1, 2);
    let input = rig.next_frame(&parent, vec![single(genuine.clone())]);
    assert!(pipeline.offer(input));
    for _ in 0..8 {
        assert!(
            matches!(pipeline.step(3), FinalizationStep::Retry(_)),
            "control: a genuine header waits for its body"
        );
    }
    assert_eq!(rig.source.last_materialized_frame(), 2);
    rig.admit_body(&genuine);
    let FinalizationStep::Published { result, .. } = pipeline.step(3) else {
        panic!("control: GLOBAL frame 3 must publish once the body is held");
    };
    assert_eq!(
        result.processed + result.skipped,
        1,
        "control: the frame executes its header"
    );
    assert_eq!(rig.height(), 1, "control: materialized through its header");
    assert_eq!(rig.source.last_materialized_frame(), 3);
    eprintln!(
        "FH CONTROL: a genuine header waits for its body, then the frame publishes \
         (processed {}, skipped {})",
        result.processed, result.skipped
    );
}

/// Control on both builds: a header certified by keys its session does not
/// name requires nothing, whatever its fields reproduce.
#[test]
fn fh_control_a_certificate_of_other_keys_requires_nothing() {
    let rig = Rig::new();
    rig.hold(2);
    let header = Rig::new().certified(1, 2);
    let ready = (rig.hook)(&frame_carrying(3, vec![header]));
    assert!(
        matches!(ready, Ok(true)),
        "control: only a header its session certified requires a body: {ready:?}"
    );
    assert_eq!(rig.height(), 0);
    eprintln!("FH CONTROL: a certificate of other keys requires nothing");
}

/// The frame's map keeps the last copy of a number, so a tampered copy
/// replaces the genuine header. A frame that carried no requests is rebuilt
/// from its header once no endpoint served its body for 90 s: rebuilt from
/// the copy, it fails authentication and the wait goes on. It waits out that
/// real grace, so it stays out of the default run.
#[test]
#[ignore = "waits out the ingest's 90 s empty-frame grace; run by the base reproduction"]
fn fh_r5_a_tampered_copy_must_not_keep_an_empty_frame_waiting() {
    let genuine_only = Rig::new();
    genuine_only.hold(2);
    let tampered = Rig::new();
    tampered.hold(2);
    let genuine = |rig: &Rig| rig.certified(1, 2);
    let control = frame_carrying(3, vec![genuine(&genuine_only)]);
    let header = genuine(&tampered);
    let copy = FrameHeader {
        timestamp: header.timestamp + 1,
        ..header.clone()
    };
    let input = frame_carrying(3, vec![header, copy]);
    for (name, rig, frame) in [
        ("control", &genuine_only, &control),
        ("tampered", &tampered, &input),
    ] {
        assert!(
            matches!((rig.hook)(frame), Ok(false)),
            "FH-R5 SETUP: the {name} frame's body is missing"
        );
    }
    std::thread::sleep(Duration::from_secs(91));
    let control_ready = (genuine_only.hook)(&control);
    assert!(
        matches!(control_ready, Ok(true)),
        "FH-R5 SETUP: past the grace the genuine header rebuilds the empty frame: \
         {control_ready:?}"
    );
    let ready = (tampered.hook)(&input);
    assert!(
        matches!(ready, Ok(true)),
        "FH-R5 HALT: a tampered copy of an empty frame's header keeps GLOBAL frame 3 waiting \
         past the grace ({ready:?}): the rebuild fails authentication on the copy"
    );
    eprintln!("FH-R5 FIX: a tampered copy does not replace the genuine header");
}
