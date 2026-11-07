//! Operations the global commit can only reject, or that execution refuses
//! before their proof, are refused or held before any proof work on arrival
//! and by the shard proposal filter: otherwise this node verifies them on
//! arrival, the shard and every archive verify them once a frame carries
//! them (minutes of CPU each, GLOBAL waiting on the archives), and nothing
//! is paid for it. None of these needs a coin of the submitter's own. Only
//! interfaces of the release base are used, so the same tests show the
//! vulnerable outcome there.
use super::*;
use crate::hypergraph_state::HypergraphState;
use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use crate::token_intrinsic::{
    dispatch::TokenPolicy, global_commit, spend_entries, spend_relay, state::SnapshotLimits,
};
use quil_hypergraph::testing::MemStore;
use quil_lattice_ct::confidential::{
    relation::{
        backend::{native::NativeBudget, worker_client::WorkerVerifier},
        membership::{Node, IDENTITY_BYTES, NODE_BYTES},
    },
    transfer::{parameter_context, CompileLimits, Output, MEMO_BYTES},
    AmountOpening, CommitmentKey,
};
use quil_types::crypto::NoopInclusionProver;

pub(super) const NETWORK: [u8; 32] = [1; 32];
pub(super) const APPLICATION: [u8; 32] = domains::QUIL_TOKEN;

pub(super) fn context() -> [u8; 32] {
    parameter_context(&NETWORK, &APPLICATION)
}

pub(super) fn proof() -> Vec<u8> {
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    proof
}

pub(super) fn output(seed: u8) -> Output {
    let context = context();
    Output {
        commitment: CommitmentKey::derive(&context)
            .commit(10, &AmountOpening::from_seed(&context, &[seed; 32])),
        owner: [seed; IDENTITY_BYTES],
        memo: [6; MEMO_BYTES],
    }
}

/// The token policy of the nodes these tests run.
pub(super) fn policy() -> TokenPolicy {
    TokenPolicy {
        network: NETWORK,
        limits: CompileLimits {
            max_inputs: 2,
            max_outputs: 2,
            max_depth: 3,
        },
        snapshots: SnapshotLimits {
            max_coins: 8,
            max_depth: 3,
            max_nodes: 24,
        },
        native_budget: NativeBudget {
            max_native_bytes: 0,
        },
    }
}

/// A proof worker that appends a line to `directory/runs` each time it is
/// started and rejects every proof (a verdict, cached), and that file.
pub(super) fn counting_worker(directory: &std::path::Path) -> (WorkerVerifier, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let runs = directory.join("runs");
    let script = directory.join("counting-worker");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\necho run >> {}\nexit 81\n",
            runs.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let worker = WorkerVerifier::new(script, 5, std::time::Duration::from_secs(30)).unwrap();
    (worker, runs)
}

/// How many times the [`counting_worker`] writing `runs` was started.
pub(super) fn worker_runs(runs: &std::path::Path) -> usize {
    std::fs::read_to_string(runs).map_or(0, |text| text.lines().count())
}

/// A node's execution manager with a token policy over a worker that cannot
/// run: what arrival reads, without verifying anything.
pub(super) fn token_manager(directory: &std::path::Path) -> ExecutionEngineManager {
    let worker = WorkerVerifier::new(
        directory.join("absent-worker"),
        1,
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    token_manager_with(worker)
}

/// [`token_manager`] over `worker`.
pub(super) fn token_manager_with(worker: WorkerVerifier) -> ExecutionEngineManager {
    let policy = policy();
    let prover: Arc<dyn InclusionProver> = Arc::new(NoopInclusionProver);
    let stubs = crate::testing::NoopExecutionCrypto::new();
    ExecutionEngineManager::new(
        prover.clone(),
        stubs.key_manager.clone(),
        Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            prover,
        )),
        stubs.circuit_compiler,
        stubs.clock_store,
        Arc::new(crate::testing::NoopHypergraphConfigResolver),
        false,
    )
    .with_token_worker(policy, worker)
    .unwrap()
}

/// GLOBAL state as a node holds it.
pub(super) fn global_view() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(MemStore::new()),
        Arc::new(NoopInclusionProver),
    ))
}

pub(super) fn bundle(inner: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest::wrap(inner).unwrap())],
        timestamp: 1,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// A transfer of the QUIL token proving membership against root `root`,
/// spending image `image`, told apart by `seed`; structurally valid, no
/// valid proof (nothing before the worker reads it).
pub(super) fn transfer(root: u8, image: u8, seed: u8) -> Vec<u8> {
    transfer_on(NETWORK, root, image, seed)
}

/// [`transfer`] naming network `network`.
pub(super) fn transfer_on(network: [u8; 32], root: u8, image: u8, seed: u8) -> Vec<u8> {
    use quil_lattice_ct::confidential::transfer::{Transfer, TransferStatement};
    Transfer {
        statement: TransferStatement {
            network,
            application: APPLICATION,
            depth: 1,
            root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
            images: vec![[image; IDENTITY_BYTES]],
            outputs: vec![output(seed)],
            fee: 2,
        },
        proof: proof(),
    }
    .encode()
    .unwrap()
}

/// Publish root `root` (depth 1) into the QUIL token's canonical root
/// history in `global`.
pub(super) fn publish_root(global: &Arc<quil_hypergraph::HypergraphCrdt>, root: u8) {
    use crate::token_intrinsic::{global_accumulator as records, roots};
    let state = HypergraphState::new(global.clone());
    let record = quil_lattice_ct::confidential::coin_tree::RootRecord {
        context: context(),
        depth: 1,
        coins: 1,
        root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
    };
    let existing = records::read_root_history(&state, &APPLICATION).unwrap();
    let history = roots::publish_history(existing.as_deref(), record).unwrap();
    records::write_record(
        &state,
        1,
        &records::root_history_address(&APPLICATION).unwrap(),
        &[
            (
                vec![0xff; 32],
                records::kind("quil/accumulator/root-history-record/v1\0")
                    .unwrap()
                    .to_vec(),
            ),
            (vec![0], history),
        ],
    )
    .unwrap();
    state.commit().unwrap();
    state.abort();
}

/// Commit operation `bytes` of type `tp`, executed by shard frame 40 and
/// carried by header 41, in GLOBAL frame `frame`: the fees credited, and
/// the decision recorded.
pub(super) fn commit(
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    frame: u64,
    tp: u32,
    bytes: &[u8],
) -> (u128, Option<global_commit::Decision>) {
    let state = HypergraphState::new(global.clone());
    let entry = spend_entries::spend_entry(&NETWORK, &APPLICATION, tp, bytes, 40).unwrap();
    let relay = spend_relay::encode_relay(&[(40, vec![entry.encode().unwrap()])]).unwrap();
    let fees = global_commit::materialize_relay(&state, frame, &APPLICATION, 41, &relay).unwrap();
    state.commit().unwrap();
    state.abort();
    let decision = state
        .get(
            &crate::global_schema::GLOBAL_INTRINSIC_ADDRESS,
            &global_commit::decision_address(&APPLICATION, &entry.tx_id).unwrap(),
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
        )
        .unwrap()
        .and_then(|blob| global_commit::decode_decision(&blob).unwrap());
    (fees, decision)
}

/// The owner field a legacy coin of the Ed448 key of `key` carries.
pub(super) fn key_address(key: u8) -> [u8; 32] {
    let public = quil_crypto::Ed448Signer::derive_public(&[key; 57]).unwrap();
    quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap()
}

/// A legacy coin of `amount` whose owner field is `owner_address`, in
/// `crdt` (a shard's store), told apart by `salt`: its address.
pub(super) fn legacy_coin(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    owner_address: [u8; 32],
    amount: u128,
    salt: u8,
) -> [u8; 32] {
    use crate::token_intrinsic::{legacy_migration, materialize};
    let tree = legacy_migration::create_transparent_coin_tree(
        &legacy_migration::TransparentCoin {
            owner_address,
            amount,
        },
        &legacy_migration::transparent_type_hash(&APPLICATION).unwrap(),
        &[salt; 32],
    )
    .unwrap();
    let address = materialize::coin_content_address(&tree).unwrap();
    let state = HypergraphState::new(crdt.clone());
    state
        .set(
            &APPLICATION,
            &address,
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    state.abort();
    address
}

/// A shield of legacy coin `source` (amount 12) by the Ed448 key of
/// `signer`, told apart by `seed`; signed by that key when `signed`. No
/// valid proof.
pub(super) fn shield(signer: u8, source: [u8; 32], seed: u8, signed: bool) -> Vec<u8> {
    use quil_lattice_ct::confidential::shield::{Shield, ShieldStatement};
    use quil_types::crypto::Signer as _;
    let public = quil_crypto::Ed448Signer::derive_public(&[signer; 57]).unwrap();
    let statement = ShieldStatement {
        network: NETWORK,
        application: APPLICATION,
        transparent_address: source,
        owner_public_key: public.clone().try_into().unwrap(),
        amount: 12,
        fee: 2,
        outputs: vec![output(seed)],
    };
    let signature = if signed {
        quil_crypto::Ed448Signer::from_bytes(&[signer; 57], &public)
            .unwrap()
            .sign(&statement.context_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        [0; 114]
    };
    Shield {
        statement,
        signature,
        proof: proof(),
    }
    .encode()
    .unwrap()
}

/// The Falcon keys of every escrow here: its recipient's and its refund's.
fn escrow_authorities() -> &'static (quil_crypto::FalconSigner, quil_crypto::FalconSigner) {
    static KEYS: std::sync::OnceLock<(quil_crypto::FalconSigner, quil_crypto::FalconSigner)> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        (
            quil_crypto::FalconSigner::generate(),
            quil_crypto::FalconSigner::generate(),
        )
    })
}

/// A claim of escrow `escrow` (its recipient's, or its refund when
/// `refund`), told apart by `seed`, under a policy refundable from GLOBAL
/// frame `refund_after`, signed by its branch's authority; no valid proof.
pub(super) fn claim(escrow: u8, seed: u8, refund: bool, refund_after: u64) -> Vec<u8> {
    claim_signed(escrow, seed, refund, refund_after, true)
}

/// [`claim`], signed by its branch's authority only when `signed`.
pub(super) fn claim_signed(
    escrow: u8,
    seed: u8,
    refund: bool,
    refund_after: u64,
    signed: bool,
) -> Vec<u8> {
    use quil_lattice_ct::confidential::pending_claim::{
        ClaimBranch, EscrowPolicy, PendingClaim, PendingClaimStatement,
    };
    use quil_types::crypto::Signer as _;
    let context = context();
    let (recipient, refunder) = escrow_authorities();
    let statement = PendingClaimStatement {
        network: NETWORK,
        application: APPLICATION,
        escrow_address: [escrow; 32],
        source: CommitmentKey::derive(&context)
            .commit(12, &AmountOpening::from_seed(&context, &[escrow; 32])),
        policy: EscrowPolicy {
            recipient: recipient.public_key().try_into().unwrap(),
            refund: refunder.public_key().try_into().unwrap(),
            refund_after_global_frame: refund_after,
        },
        branch: if refund {
            ClaimBranch::Refund
        } else {
            ClaimBranch::Recipient
        },
        fee: 2,
        outputs: vec![output(seed)],
    };
    let signature = if signed {
        let signer = if refund { refunder } else { recipient };
        signer
            .sign_with_domain(&statement.context_bytes().unwrap(), &context)
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        std::array::from_fn(|_| 0)
    };
    PendingClaim {
        statement,
        signature,
        proof: proof(),
    }
    .encode()
    .unwrap()
}

/// A settlement of the QUIL token funded by a spend against root `root` of
/// image `image`, told apart by `seed`, pre-funded for a claimant key of
/// type `key_type`; no valid proof.
pub(super) fn settlement(root: u8, image: u8, seed: u8, key_type: u32) -> Vec<u8> {
    use quil_lattice_ct::confidential::{
        settlement::{Claimant, Settlement, SettlementStatement},
        transfer::TransferStatement,
    };
    Settlement {
        statement: SettlementStatement {
            funding: TransferStatement {
                network: NETWORK,
                application: APPLICATION,
                depth: 1,
                root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
                images: vec![[image; IDENTITY_BYTES]],
                outputs: vec![output(seed)],
                fee: 12,
            },
            fee: 2,
            settlement: 10,
            destination: [0x77; 32],
            context: [0; 32],
            claimant: Some(Claimant {
                key_type,
                public_key: vec![0x42; 897],
            }),
            payment: None,
        },
        proof: proof(),
    }
    .encode()
    .unwrap()
}

/// Commit, in GLOBAL frame `frame`, the creation of the escrow `claim_bytes`
/// claims, refundable from `refund_after`, under the binding `binding` (the
/// claim's own when `None`).
pub(super) fn create_escrow(
    global: &Arc<quil_hypergraph::HypergraphCrdt>,
    frame: u64,
    claim_bytes: &[u8],
    refund_after: u64,
    binding: Option<[u8; 32]>,
) {
    let claim = spend_entries::spend_entry(
        &NETWORK,
        &APPLICATION,
        crate::token_engine::TYPE_LATTICE_PENDING_CLAIM,
        claim_bytes,
        40,
    )
    .unwrap()
    .escrow_claim
    .unwrap();
    let mut output = [frame as u8; 32];
    output[0] = 0b0000_0100;
    let entry = global_commit::SpendEntry {
        kind: crate::token_engine::TYPE_LATTICE_PENDING,
        tx_id: [frame as u8; 32],
        source_frame: 40,
        context: context(),
        root_digest: None,
        consumptions: vec![[frame as u8; 32]],
        outputs: vec![output],
        escrow_create: Some(global_commit::EscrowCreate {
            address: claim.address,
            binding: binding.unwrap_or(claim.binding),
            refund_after_global_frame: refund_after,
        }),
        escrow_claim: None,
        fee: 2,
        settlement: None,
    };
    let state = HypergraphState::new(global.clone());
    assert!(matches!(
        global_commit::commit_entry(
            &state,
            frame,
            &APPLICATION,
            &entry,
            quil_types::execution::ShardPath::WHOLE,
        )
        .unwrap(),
        global_commit::Outcome::Committed { .. }
    ));
    state.commit().unwrap();
    state.abort();
}

/// A transfer proving membership against a root GLOBAL never published (a
/// tree of the submitter's own making) passes every check before its proof
/// on arrival, on the base; only the global commit refuses it, after the
/// shard and every archive verified its proof, crediting no fee.
#[test]
fn a_transfer_citing_a_root_global_never_held_is_not_verified_on_arrival() {
    let directory = tempfile::tempdir().unwrap();
    let manager = token_manager(directory.path());
    let global = global_view();
    // This node follows GLOBAL: it holds the token's canonical roots.
    publish_root(&global, 3);
    assert!(
        manager
            .arrival_operations(&global, &APPLICATION, &bundle(transfer(3, 4, 5)))
            .is_ok_and(|sizes| !sizes.is_empty()),
        "a transfer against a published root is verified on arrival"
    );
    let forged = transfer(9, 6, 7);
    let arrival = manager.arrival_operations(&global, &APPLICATION, &bundle(forged.clone()));
    let (fees, decision) = commit(
        &global,
        101,
        crate::token_engine::TYPE_LATTICE_TRANSACTION,
        &forged,
    );
    assert_eq!(fees, 0, "a rejected transfer credits no fee");
    assert!(
        arrival.is_err(),
        "VULNERABLE: a transfer citing a root GLOBAL never held passed arrival \
         (arrival_operations: {arrival:?}) and was queued for proof verification; only the \
         global commit refused it, after its proof was verified, crediting fees {fees} \
         ({decision:?})"
    );
}

/// A shield of a legacy coin its key does not own passes every check before
/// its proof on arrival, on the base, though execution refuses it before
/// verifying its proof: any coin in the shard serves, none of the
/// submitter's own.
#[test]
fn a_shield_of_a_coin_its_key_does_not_own_is_refused_before_any_proof_work() {
    let directory = tempfile::tempdir().unwrap();
    let manager = token_manager(directory.path());
    let global = global_view();
    let source = legacy_coin(&manager.crdt(), key_address(9), 12, 1);
    let theirs = shield(8, source, 2, true);
    let arrival = manager.arrival_operations(&global, &APPLICATION, &bundle(theirs.clone()));
    let refused = crate::token_intrinsic::shield::check_sources(
        &HypergraphState::new(manager.crdt()),
        quil_types::execution::ShardPath::WHOLE,
        false,
        false,
        &APPLICATION,
        &quil_lattice_ct::confidential::shield::AnyShield::decode(&theirs, &NETWORK, &APPLICATION)
            .unwrap(),
    );
    assert!(refused.is_err(), "execution refuses it");
    assert!(
        arrival.is_err(),
        "VULNERABLE: a shield of a legacy coin its key does not own passed arrival \
         (arrival_operations: {arrival:?}) and was queued for proof verification; execution \
         refuses it before its proof ({refused:?})"
    );
}

/// A claim of an escrow its recipient already claimed passes every check
/// before its proof on arrival and the shard proposal filter, on the base;
/// only the global commit refuses it, after the shard and every archive
/// verified its proof, crediting no fee.
#[test]
fn a_claim_of_a_claimed_escrow_is_refused_before_any_proof_work() {
    let directory = tempfile::tempdir().unwrap();
    let manager = token_manager(directory.path());
    let global = global_view();
    let tp = crate::token_engine::TYPE_LATTICE_PENDING_CLAIM;
    let first = claim(30, 1, false, 300);
    create_escrow(&global, 100, &first, 300, None);
    let (fees, decision) = commit(&global, 101, tp, &first);
    assert!(
        fees == 2 && matches!(decision, Some(global_commit::Decision::Committed { .. })),
        "the first claim commits: {fees} {decision:?}"
    );
    let again = bundle(claim(30, 2, false, 300));
    let arrival = manager.arrival_operations(&global, &APPLICATION, &again);
    let proposal_drops =
        ExecutionEngineManager::decided_globally(global.clone(), &APPLICATION, &again);
    let (fees, decision) = commit(&global, 102, tp, &claim(30, 2, false, 300));
    assert_eq!(fees, 0, "a rejected claim credits no fee");
    assert!(
        arrival.is_err() && proposal_drops,
        "VULNERABLE: a claim of a claimed escrow passed arrival (arrival_operations: \
         {arrival:?}; dropped by the shard proposal filter: {proposal_drops}); only the global \
         commit refused it, after its proof was verified, crediting fees {fees} ({decision:?})"
    );
}

/// A claim its branch's authority did not sign passes every check before
/// its proof on arrival and in a pre-verification (an archive's, a
/// shard's), on the base, though execution refuses it before verifying its
/// proof: the claim names its escrow's address, source and policy, all
/// public, so any open escrow serves for any number of them, and no coin of
/// the submitter's own is needed. A refund is refused so at any frame:
/// before its deadline for the deadline, after it for the signature. The
/// worker here counts its runs.
#[test]
fn a_claim_its_authority_did_not_sign_is_refused_before_any_proof_work() {
    use crate::token_intrinsic::pending_claim;
    use quil_lattice_ct::confidential::pending_claim::PendingClaim;
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker);
    let global = global_view();
    create_escrow(&global, 100, &claim(33, 1, false, 300), 300, None);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    // Signed by its authority: verified on arrival and ahead, as before.
    let signed = claim(33, 1, false, 300);
    assert!(manager
        .arrival_operations(&global, &APPLICATION, &bundle(signed.clone()))
        .is_ok_and(|sizes| !sizes.is_empty()));
    manager.preverify_bundles(&pairs(signed));
    assert_eq!(worker_runs(&runs), 1, "the counting worker never ran");
    let mut passed = Vec::new();
    for (name, forged) in [
        ("recipient", claim_signed(33, 2, false, 300, false)),
        ("refund", claim_signed(33, 3, true, 300, false)),
    ] {
        let tx = PendingClaim::decode(&forged, &NETWORK, &APPLICATION).unwrap();
        let s = &tx.statement;
        for frame in [Some(200), Some(400)] {
            assert!(
                pending_claim::check_authorization(
                    &tx,
                    &NETWORK,
                    &APPLICATION,
                    &s.escrow_address,
                    &s.source,
                    &s.policy,
                    frame,
                )
                .is_err(),
                "{name}: execution refuses it before its proof at {frame:?}"
            );
        }
        let arrival = manager.arrival_operations(&global, &APPLICATION, &bundle(forged.clone()));
        let before = worker_runs(&runs);
        manager.preverify_bundles(&pairs(forged));
        let verified = worker_runs(&runs) - before;
        if arrival.is_ok() || verified > 0 {
            passed.push(format!(
                "{name}: arrival {arrival:?}, {verified} verified ahead"
            ));
        }
    }
    assert!(
        passed.is_empty(),
        "VULNERABLE: claims their authority did not sign passed arrival or were verified \
         ahead, though execution refuses them before their proof: {passed:?}"
    );
}

/// A settlement whose pre-funded claimant key is not post-quantum passes
/// every check before its proof on arrival and in a pre-verification, on
/// the base, though execution refuses it before verifying its proof. A spend
/// against a published root with fresh images needs no coin of the
/// submitter's own to get there. One naming a Falcon key is verified.
#[test]
fn a_settlement_execution_refuses_before_its_proof_is_not_verified_ahead() {
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker);
    let global = global_view();
    publish_root(&global, 3);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    let falcon = quil_types::crypto::KeyType::Falcon512 as u32;
    let open = settlement(3, 0x81, 1, falcon);
    assert!(manager
        .arrival_operations(&global, &APPLICATION, &bundle(open.clone()))
        .is_ok_and(|sizes| !sizes.is_empty()));
    manager.preverify_bundles(&pairs(open));
    assert_eq!(worker_runs(&runs), 1, "the counting worker never ran");
    let classical = settlement(3, 0x82, 2, quil_types::crypto::KeyType::Ed448 as u32);
    let tx = quil_lattice_ct::confidential::settlement::Settlement::decode(
        &classical,
        &NETWORK,
        &APPLICATION,
    )
    .unwrap();
    assert!(
        !crate::token_intrinsic::signature::is_post_quantum_authority(
            tx.statement.claimant.as_ref().unwrap().key_type
        ),
        "execution refuses it before its proof"
    );
    let arrival = manager.arrival_operations(&global, &APPLICATION, &bundle(classical.clone()));
    manager.preverify_bundles(&pairs(classical));
    let verified = worker_runs(&runs) - 1;
    assert!(
        arrival.is_err() && verified == 0,
        "VULNERABLE: a settlement naming a classical claimant key passed arrival \
         ({arrival:?}) and was verified ahead ({verified} runs), though execution refuses it \
         before its proof"
    );
}

/// What the global commit may still accept is never refused ahead of it. A
/// node holding no GLOBAL roots cannot tell and holds nothing; one whose
/// view lacks a root or an escrow GLOBAL may yet publish holds the operation
/// unverified (its view may lag GLOBAL) and verifies and proposes it once
/// the view holds it; a refund is the commit's to time. Only what no later
/// GLOBAL frame lifts is refused: a spent image, an escrow claimed or under
/// another binding.
#[test]
fn a_view_behind_global_holds_what_it_lacks_and_refuses_only_what_no_frame_lifts() {
    let directory = tempfile::tempdir().unwrap();
    let manager = token_manager(directory.path());
    let global = global_view();
    let outlook = |bytes: Vec<u8>| manager.commit_outlook(&global, &APPLICATION, &bundle(bytes));
    let arrival =
        |bytes: Vec<u8>| manager.arrival_operations(&global, &APPLICATION, &bundle(bytes));
    assert_eq!(outlook(transfer(9, 6, 7)), CommitOutlook::Open);
    assert_eq!(outlook(claim(31, 1, false, 300)), CommitOutlook::Open);
    publish_root(&global, 3);
    for pending in [transfer(9, 6, 7), claim(31, 1, false, 300)] {
        assert_eq!(outlook(pending.clone()), CommitOutlook::Pending);
        assert_eq!(arrival(pending.clone()), Err(ArrivalRefusal::Pending));
        assert!(!ExecutionEngineManager::decided_globally(
            global.clone(),
            &APPLICATION,
            &bundle(pending)
        ));
    }
    // The view catches up.
    publish_root(&global, 9);
    create_escrow(&global, 100, &claim(31, 1, false, 300), 300, None);
    for open in [
        transfer(9, 6, 7),
        claim(31, 1, false, 300),
        claim(31, 2, true, 300),
    ] {
        assert_eq!(outlook(open.clone()), CommitOutlook::Open);
        assert!(arrival(open).is_ok_and(|sizes| !sizes.is_empty()));
    }
    create_escrow(&global, 101, &claim(32, 1, false, 300), 300, Some([0; 32]));
    let (fees, _) = commit(
        &global,
        102,
        crate::token_engine::TYPE_LATTICE_TRANSACTION,
        &transfer(9, 6, 7),
    );
    assert_eq!(fees, 2, "the transfer commits, spending image 6");
    for lasting in [claim(32, 1, false, 300), transfer(3, 6, 8)] {
        assert_eq!(outlook(lasting.clone()), CommitOutlook::Settled);
        assert_eq!(arrival(lasting), Err(ArrivalRefusal::Rejected));
    }
}

/// A shield stands as execution finds it before its proof, under either
/// form of its owner: its key's coin of its amount, signed, is open; a coin
/// of another key or amount, or a signature of another key, can only be
/// refused (legacy coins never change); a source this store does not hold
/// (another shard's, or one still syncing) is held, not refused.
#[test]
fn a_shield_stands_as_execution_finds_it_before_its_proof() {
    use crate::token_intrinsic::legacy_migration::migrated_owner;
    let directory = tempfile::tempdir().unwrap();
    let manager = token_manager(directory.path());
    let global = global_view();
    let store = manager.crdt();
    let outlook = |bytes: Vec<u8>| manager.commit_outlook(&global, &APPLICATION, &bundle(bytes));
    let mine = legacy_coin(&store, key_address(9), 12, 1);
    let migrated = legacy_coin(&store, migrated_owner(&key_address(9)), 12, 2);
    let more = legacy_coin(&store, key_address(9), 13, 3);
    assert_eq!(outlook(shield(9, mine, 1, true)), CommitOutlook::Open);
    assert_eq!(outlook(shield(9, migrated, 2, true)), CommitOutlook::Open);
    for (name, refused) in [
        ("unsigned", shield(9, mine, 3, false)),
        ("another key's coin", shield(8, mine, 4, true)),
        ("another amount", shield(9, more, 5, true)),
    ] {
        assert_eq!(outlook(refused.clone()), CommitOutlook::Settled, "{name}");
        assert_eq!(
            manager.arrival_operations(&global, &APPLICATION, &bundle(refused)),
            Err(ArrivalRefusal::Rejected),
            "{name}"
        );
    }
    let elsewhere = shield(9, [0x5a; 32], 6, true);
    assert_eq!(outlook(elsewhere.clone()), CommitOutlook::Pending);
    assert_eq!(
        manager.arrival_operations(&global, &APPLICATION, &bundle(elsewhere)),
        Err(ArrivalRefusal::Pending)
    );
}

/// The global venue executes the operations of an application no shard
/// covers and commits each inline. On the base it verifies an operation's
/// proof before its commit refuses it from GLOBAL state alone (a transfer
/// citing a root GLOBAL never held, a re-spend of a spent key image), so
/// every node executing GLOBAL verifies it, and nothing is paid. The worker
/// here counts its runs.
#[test]
fn the_global_venue_refuses_what_its_commit_refuses_before_any_proof_work() {
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let global = global_view();
    publish_root(&global, 3);
    let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    let (fees, _) = commit(&global, 101, tp, &transfer(3, 0x61, 0x62));
    assert_eq!(fees, 2, "setup: a transfer spending image 0x61 commits");
    let state = HypergraphState::new(global.clone());
    let clock = crate::testing::NoopExecutionCrypto::new().clock_store;
    let context = quil_types::execution::FrameExecutionContext {
        frame_number: 102,
        finalized_global_frame: Some(101),
        shard: quil_types::execution::ShardPath::WHOLE,
        venue: Some(quil_types::execution::Venue::Global),
    };
    let refused: Vec<String> = [transfer(9, 0x64, 0x65), transfer(3, 0x61, 0x63)]
        .iter()
        .map(|bytes| {
            policy()
                .dispatch_commit_inline(
                    &state,
                    context,
                    clock.as_ref(),
                    &APPLICATION,
                    bytes,
                    tp,
                    Some(&worker),
                    None,
                )
                .expect_err("the commit refuses it")
                .to_string()
        })
        .collect();
    let verified = worker_runs(&runs);
    assert_eq!(
        verified, 0,
        "VULNERABLE: the global venue verified {verified} proofs of operations its commit \
         refuses from GLOBAL state alone ({refused:?})"
    );
    assert!(
        refused[0].contains("root is not in the application's canonical history")
            && refused[1].contains("already consumed"),
        "{refused:?}"
    );
}

/// An operation naming another network cannot reach proof work: arrival,
/// a pre-verification and the global venue refuse it as dispatch decodes
/// it, against this node's network. So the commit's refusal of a context
/// other than the application's is never met past that check, and nothing
/// ahead of the commit needs to read it.
#[test]
fn an_operation_of_another_network_never_reaches_proof_work() {
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker.clone());
    let global = global_view();
    publish_root(&global, 3);
    let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    let foreign = transfer_on([9; 32], 3, 0x66, 0x67);
    assert_eq!(
        manager.arrival_operations(&global, &APPLICATION, &bundle(foreign.clone())),
        Err(ArrivalRefusal::Malformed)
    );
    manager.preverify_bundles(&[(APPLICATION.to_vec(), bundle(foreign.clone()))]);
    let state = HypergraphState::new(global.clone());
    let clock = crate::testing::NoopExecutionCrypto::new().clock_store;
    let context = quil_types::execution::FrameExecutionContext {
        frame_number: 102,
        finalized_global_frame: Some(101),
        shard: quil_types::execution::ShardPath::WHOLE,
        venue: Some(quil_types::execution::Venue::Global),
    };
    let inline = policy().dispatch_commit_inline(
        &state,
        context,
        clock.as_ref(),
        &APPLICATION,
        &foreign,
        tp,
        Some(&worker),
        None,
    );
    assert!(inline.is_err());
    assert_eq!(
        worker_runs(&runs),
        0,
        "an operation of another network reached the proof worker"
    );
    // The same transfer of this network reaches it: the worker counts.
    manager.preverify_bundles(&[(APPLICATION.to_vec(), bundle(transfer(3, 0x66, 0x67)))]);
    assert_eq!(worker_runs(&runs), 1, "the counting worker never ran");
}

/// Ahead of a GLOBAL frame the global venue executes, what the frame's
/// commit refuses from GLOBAL state alone is not verified (the venue
/// refuses it before the proof), and what it may accept is. A shard's or an
/// archive's pre-verification does not judge the GLOBAL commit: execution
/// there verifies such an operation's proof whatever GLOBAL holds, so
/// leaving it out would only move its verification into the frame's own.
#[test]
fn the_global_venue_verifies_ahead_only_what_its_commit_may_accept() {
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker);
    // The venue's store holds GLOBAL state.
    publish_root(&manager.crdt(), 3);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    let counts = manager.preverify_global_bundles(102, &pairs(transfer(9, 0x71, 0x72)));
    assert_eq!(
        (counts.operations, worker_runs(&runs)),
        (1, 0),
        "the venue verified ahead a transfer its commit refuses ({counts:?})"
    );
    manager.preverify_global_bundles(102, &pairs(transfer(3, 0x73, 0x74)));
    assert_eq!(
        worker_runs(&runs),
        1,
        "the venue left out a transfer its commit may accept"
    );
    manager.preverify_bundles(&pairs(transfer(9, 0x75, 0x76)));
    assert_eq!(
        worker_runs(&runs),
        2,
        "a shard's pre-verification judged the GLOBAL commit"
    );
}

/// What execution refuses before its proof (a shield of another key's
/// coin, one its key did not sign, one of a source this store does not
/// hold) is neither verified by a pre-verification (an archive's, a
/// shard's, a vote's warm-up) nor awaited by a frame as still unverified,
/// which would hold the frame for a verification nothing runs. A shield
/// execution may accept is both.
#[test]
fn what_execution_refuses_before_its_proof_is_neither_verified_ahead_nor_awaited() {
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker);
    let mine = legacy_coin(&manager.crdt(), key_address(9), 12, 1);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    for (name, refused) in [
        ("another key's coin", shield(8, mine, 1, true)),
        ("unsigned", shield(9, mine, 2, false)),
        ("absent source", shield(9, [0x5a; 32], 3, true)),
    ] {
        let counts = manager.preverify_bundles(&pairs(refused.clone()));
        assert_eq!(
            (counts.operations, worker_runs(&runs)),
            (1, 0),
            "{name}: verified ahead though execution refuses it before its proof"
        );
        assert!(
            manager
                .unverified_confidential_operations(&pairs(refused))
                .is_empty(),
            "{name}: a frame carrying it would wait for a verification nothing runs"
        );
    }
    let owned = pairs(shield(9, mine, 4, true));
    assert_eq!(manager.unverified_confidential_operations(&owned).len(), 1);
    manager.preverify_bundles(&owned);
    assert_eq!(
        worker_runs(&runs),
        1,
        "a shield execution accepts was left out"
    );
    assert!(manager
        .unverified_confidential_operations(&owned)
        .is_empty());
}

/// [`transfer`] creating a coin whose owner is not a canonical identity.
fn noncanonical_transfer(root: u8, image: u8, seed: u8) -> Vec<u8> {
    use quil_lattice_ct::confidential::transfer::{Transfer, TransferStatement};
    Transfer {
        statement: TransferStatement {
            network: NETWORK,
            application: APPLICATION,
            depth: 1,
            root: Node::from_bytes(&[root; NODE_BYTES]).unwrap(),
            images: vec![[image; IDENTITY_BYTES]],
            outputs: vec![Output {
                owner: [0xff; IDENTITY_BYTES],
                ..output(seed)
            }],
            fee: 2,
        },
        proof: proof(),
    }
    .encode()
    .unwrap()
}

/// A transfer creating a coin whose owner is not a canonical identity is
/// refused by execution before its proof once canonical owners are required
/// (`dispatch_for_commit`). On the base it passes arrival and is verified
/// ahead, as it is by every member and archive, and only then refused, for
/// free. The gate's frame is set for this thread only, and the latest GLOBAL
/// frame this process saw only grows: no other test can undo either.
#[test]
fn a_noncanonical_owner_execution_refuses_before_its_proof_is_not_verified_ahead() {
    global_commit::set_canonical_owner_frame_for_thread(Some(0));
    quil_types::consensus::note_frame_time_head(1_000);
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker);
    let global = global_view();
    publish_root(&global, 3);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    let honest = transfer(3, 0x51, 1);
    assert!(manager
        .arrival_operations(&global, &APPLICATION, &bundle(honest.clone()))
        .is_ok_and(|sizes| !sizes.is_empty()));
    manager.preverify_bundles(&pairs(honest));
    assert_eq!(worker_runs(&runs), 1, "the counting worker never ran");
    let forged = noncanonical_transfer(3, 0x52, 2);
    let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    assert!(
        spend_entries::check_owners(&NETWORK, &APPLICATION, tp, &forged).is_err(),
        "execution refuses its owner before its proof"
    );
    let arrival = manager.arrival_operations(&global, &APPLICATION, &bundle(forged.clone()));
    manager.preverify_bundles(&pairs(forged));
    let verified = worker_runs(&runs) - 1;
    global_commit::set_canonical_owner_frame_for_thread(None);
    assert!(
        arrival.is_err() && verified == 0,
        "READ-AHEAD GAP: a transfer creating a coin whose owner is not a canonical identity \
         passed arrival ({arrival:?}) and was verified ahead ({verified} runs), though \
         execution refuses it before its proof"
    );
}

/// Near the canonical owner frame G, the read-ahead refuses an owner that
/// is not a canonical identity only where execution refuses it before its
/// proof at every frame that can still carry it: from GLOBAL frame G + 1 in
/// the global venue (anchored at G), from an app-shard frame anchored at G,
/// never in one without an anchor, and for a frame not known yet only once
/// the latest GLOBAL frame seen is far enough past G that no such frame is
/// anchored before G. A frame's own pre-verification judges it at that
/// frame's anchor, whatever GLOBAL frame this node saw since.
#[test]
fn the_owner_read_ahead_refuses_only_where_every_executing_frame_does() {
    use global_commit::Standing;
    const G: u64 = 1_000;
    let lag = LATER_ANCHOR_LAG;
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker.clone());
    let store = HypergraphState::new(manager.crdt());
    let clock = crate::testing::NoopExecutionCrypto::new().clock_store;
    let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    let forged = noncanonical_transfer(3, 0x75, 0x20);
    global_commit::set_canonical_owner_frame_for_thread(Some(G));
    // Whether execution refuses it for its owner, before its proof, in a
    // frame anchored at `anchor`.
    let refuses = |anchor: Option<u64>| {
        policy()
            .dispatch_for_commit(
                &store,
                quil_types::execution::FrameExecutionContext {
                    frame_number: 1,
                    finalized_global_frame: anchor,
                    shard: quil_types::execution::ShardPath::WHOLE,
                    venue: None,
                },
                clock.as_ref(),
                &APPLICATION,
                &forged,
                tp,
                Some(&worker),
                None,
            )
            .is_err_and(|error| error.to_string().contains("not a canonical identity"))
    };
    let owner = Some(Standing::Lasting("an owner is not a canonical identity"));
    let read_ahead = ExecutionEngineManager::execution_standing;
    let ahead = |frame: ExecutingFrame, head: u64| {
        let anchor = frame.anchor_floor(head);
        read_ahead(&store, &NETWORK, &APPLICATION, tp, &forged, anchor) == owner
    };
    let (global, app) = (ExecutingFrame::Global, ExecutingFrame::App);
    let later = ExecutingFrame::Later;
    // (executing frame, latest GLOBAL frame seen, the anchors a frame
    // executing it can have, whether execution refuses it at all of them)
    let rows: [(ExecutingFrame, u64, &[Option<u64>], bool); 9] = [
        (global(G), G, &[Some(G - 1)], false),
        (global(G + 1), G, &[Some(G)], true),
        (app(Some(G - 1)), G + lag, &[Some(G - 1)], false),
        (app(Some(G)), G, &[Some(G)], true),
        (app(None), G + lag, &[None], false),
        (later, 0, &[Some(0)], false),
        (later, G, &[Some(G - lag), Some(G)], false),
        (later, G + lag - 1, &[Some(G - 1), Some(G + lag - 1)], false),
        (later, G + lag, &[Some(G), Some(G + lag)], true),
    ];
    for (frame, head, anchors, refused) in rows {
        assert_eq!(
            anchors.iter().all(|anchor| refuses(*anchor)),
            refused,
            "{frame:?} seen at {head}: execution"
        );
        assert_eq!(
            ahead(frame, head),
            refused,
            "READ-AHEAD: {frame:?} seen at {head}: the read-ahead and execution differ"
        );
    }
    // Through the pre-verifications: a frame's own at its anchor, however
    // far past G this process saw GLOBAL; the global venue's at its frame;
    // one for a frame not known yet at the latest GLOBAL frame seen.
    quil_types::consensus::note_frame_time_head(G + lag);
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    let before = worker_runs(&runs);
    manager.preverify_app_frame_bundles(Some(G - 1), &pairs(noncanonical_transfer(3, 0x61, 0x21)));
    let admitted = worker_runs(&runs) - before;
    manager.preverify_app_frame_bundles(Some(G), &pairs(noncanonical_transfer(3, 0x64, 0x22)));
    manager.preverify_global_bundles(G + 1, &pairs(noncanonical_transfer(3, 0x66, 0x23)));
    manager.preverify_bundles(&pairs(noncanonical_transfer(3, 0x71, 0x24)));
    let refused = worker_runs(&runs) - before - admitted;
    global_commit::set_canonical_owner_frame_for_thread(None);
    assert_eq!(
        (admitted, refused),
        (1, 0),
        "READ-AHEAD: a frame anchored before G must verify ahead what it admits, and none \
         of the others what they refuse"
    );
}

/// What execution refuses before its proof for an owner that is not a
/// canonical identity, once that check is active at the executing frame's
/// anchor (`dispatch_for_commit` and `dispatch_global_mint` call
/// `spend_entries::check_owners`), the read-ahead refuses too, and only
/// that: every type naming owners, each owner slot made non-canonical in
/// turn and none, at anchors before, at and past the gate's frame and
/// without one.
#[test]
fn every_owner_execution_refuses_before_its_proof_is_read_ahead() {
    use crate::token_intrinsic::spend_entries::owner_fixtures::{self, cases, encode};
    use global_commit::Standing;
    const G: u64 = 1_000;
    let network = owner_fixtures::NETWORK;
    let store = HypergraphState::new(global_view());
    let owner = Some(Standing::Lasting("an owner is not a canonical identity"));
    let read_ahead = ExecutionEngineManager::execution_standing;
    global_commit::set_canonical_owner_frame_for_thread(Some(G));
    let mut gaps = Vec::new();
    for (case, (tp, application, coins)) in cases().iter().enumerate() {
        for slot in 0..=coins.len() {
            let mut owners = vec![[3; IDENTITY_BYTES]; coins.len()];
            if let Some(named) = owners.get_mut(slot) {
                *named = [0xff; IDENTITY_BYTES];
            }
            let bytes = encode(case, &owners);
            for anchor in [None, Some(G - 1), Some(G), Some(G + 1)] {
                // What execution decides at that anchor, before the proof.
                let refuses = global_commit::canonical_owners_active(anchor)
                    && spend_entries::check_owners(&network, application, *tp, &bytes).is_err();
                assert_eq!(
                    refuses,
                    slot < coins.len() && anchor >= Some(G),
                    "case {case} slot {slot} at {anchor:?}: the fixture misses the check"
                );
                let standing = read_ahead(&store, &network, application, *tp, &bytes, anchor);
                if (standing == owner) != refuses {
                    gaps.push((case, slot, anchor, refuses));
                }
            }
        }
    }
    global_commit::set_canonical_owner_frame_for_thread(None);
    assert!(
        gaps.is_empty(),
        "READ-AHEAD GAP: (case, slot, anchor, execution refuses) where the read-ahead \
         decides otherwise: {gaps:?}"
    );
}

/// What execution refuses for a spend's key images before its proof (none,
/// more than a spend may carry, one twice: `commit_verify::funding_shape`)
/// no transfer, pending create or settlement that decodes carries: decoding
/// refuses it, so arrival refuses such bytes as malformed and no
/// pre-verification sends them to the worker. The read-ahead needs no copy
/// of that check.
#[test]
fn a_spend_naming_a_key_image_twice_never_reaches_proof_work() {
    use quil_lattice_ct::confidential::transfer::{Transfer, TransferStatement};
    let directory = tempfile::tempdir().unwrap();
    let (worker, runs) = counting_worker(directory.path());
    let manager = token_manager_with(worker.clone());
    let global = global_view();
    publish_root(&global, 3);
    let tp = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    let images = [[0x71; IDENTITY_BYTES], [0x73; IDENTITY_BYTES]];
    let distinct = Transfer {
        statement: TransferStatement {
            network: NETWORK,
            application: APPLICATION,
            depth: 1,
            root: Node::from_bytes(&[3; NODE_BYTES]).unwrap(),
            images: images.to_vec(),
            outputs: vec![output(9)],
            fee: 2,
        },
        proof: proof(),
    }
    .encode()
    .unwrap();
    // The same bytes naming the first image twice.
    let first = distinct
        .windows(IDENTITY_BYTES)
        .position(|window| window == images[0].as_slice())
        .unwrap();
    let second = first + IDENTITY_BYTES;
    assert_eq!(
        &distinct[second..second + IDENTITY_BYTES],
        images[1].as_slice()
    );
    let mut twice = distinct.clone();
    twice.copy_within(first..second, second);
    assert!(
        Transfer::decode(&twice, &NETWORK, &APPLICATION).is_err(),
        "READ-AHEAD GAP: a transfer naming a key image twice decodes; execution refuses it \
         before its proof, the read-ahead does not"
    );
    let state = HypergraphState::new(global.clone());
    let clock = crate::testing::NoopExecutionCrypto::new().clock_store;
    let executed = policy().dispatch_for_commit(
        &state,
        quil_types::execution::FrameExecutionContext {
            frame_number: 102,
            finalized_global_frame: Some(101),
            shard: quil_types::execution::ShardPath::WHOLE,
            venue: None,
        },
        clock.as_ref(),
        &APPLICATION,
        &twice,
        tp,
        Some(&worker),
        None,
    );
    assert!(
        executed.is_err() && worker_runs(&runs) == 0,
        "execution verified its proof: {executed:?}"
    );
    let pairs = |bytes: Vec<u8>| vec![(APPLICATION.to_vec(), bundle(bytes))];
    assert_eq!(
        manager.arrival_operations(&global, &APPLICATION, &bundle(twice.clone())),
        Err(ArrivalRefusal::Malformed),
        "READ-AHEAD GAP: arrival took a transfer naming a key image twice"
    );
    manager.preverify_bundles(&pairs(twice));
    assert_eq!(
        worker_runs(&runs),
        0,
        "READ-AHEAD GAP: a transfer naming a key image twice was verified ahead"
    );
    // The same spend of two images reaches the worker: it counts.
    assert!(manager
        .arrival_operations(&global, &APPLICATION, &bundle(distinct.clone()))
        .is_ok_and(|sizes| !sizes.is_empty()));
    manager.preverify_bundles(&pairs(distinct));
    assert_eq!(worker_runs(&runs), 1, "the counting worker never ran");
}
