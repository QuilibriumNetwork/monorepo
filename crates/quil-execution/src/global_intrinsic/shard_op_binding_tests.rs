//! A `ShardSplit` or `ShardMerge` signature must cover what GLOBAL executes,
//! cannot be replayed, and a due merge collapses exactly live siblings.
//!
//! Every op here is signed by a real Falcon key over the bytes this build's
//! own verifier checks (learned by verifying a first time), the way an honest
//! GLOBAL prover running this build signs. A test then changes what an
//! attacker holding that op can change (the children, the frame it lands in)
//! and asserts the safe outcome; its failure message names the vulnerable one.
//! The tests above the fix-only marker use only APIs the release base has.

use std::sync::{Arc, Mutex};

use quil_hypergraph::HypergraphCrdt;
use quil_types::crypto::{
    BlsConstructor, InclusionProver, KeyManager, KeyType, Multiproof, Signer,
};
use quil_types::error::{QuilError, Result};
use quil_types::store::{KvDb, ShardInfo, ShardsStore};

use super::addressed_signature::AddressedSignature;
use super::intrinsic::GlobalIntrinsic;
use super::prover_ops::{ShardMerge, ShardSplit};
use crate::global_schema::{write_field, write_type, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};

/// The fix's activation for this thread.
fn activate() {
    quil_types::consensus::set_shard_op_binding_epoch_for_thread(Some(EPOCH));
}

const EPOCH: u64 = 1000;
const LEN: u64 = quil_types::consensus::EPOCH_LENGTH_FRAMES;
/// A frame in epoch 1000, after the unified tree cutover.
const F: u64 = EPOCH * LEN + 10;
/// The first frame a change proposed at `F` is due (epoch + 2).
const DUE: u64 = (EPOCH + 2) * LEN + 10;

struct StubProver;
impl InclusionProver for StubProver {
    fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> {
        Ok(vec![0u8; 64])
    }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> {
        Ok(true)
    }
    fn prove_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
    ) -> Result<Box<dyn Multiproof>> {
        Err(QuilError::Internal("batch not supported".into()))
    }
    fn verify_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
        _: &[u8],
        _: &[u8],
    ) -> bool {
        true
    }
}

/// The production verifier, recording what it was asked to verify.
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}
impl KeyManager for Recorder {
    fn validate_signature(
        &self,
        key_type: KeyType,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        domain: &[u8],
    ) -> Result<bool> {
        self.calls
            .lock()
            .unwrap()
            .push((message.to_vec(), domain.to_vec()));
        quil_crypto::DefaultKeyManager
            .validate_signature(key_type, public_key, message, signature, domain)
    }
}

struct Net {
    app: [u8; 32],
    signer: Box<dyn Signer>,
    address: [u8; 32],
    keys: Arc<Recorder>,
    tree: quil_tries::VectorCommitmentTree,
    gi: GlobalIntrinsic,
    state: HypergraphState,
    shards: Arc<dyn ShardsStore>,
    _db: Arc<quil_store::RocksDb>,
}

fn grid_key(app: &[u8; 32]) -> Vec<u8> {
    let mut key = quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3).to_vec();
    key.extend_from_slice(app);
    key
}

/// A GLOBAL prover with a real Falcon key, and an app whose grid holds
/// `grid` (bit-paths).
fn net(grid: &[&[bool]]) -> Net {
    let app = [0x5au8; 32];
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let shards: Arc<dyn ShardsStore> = Arc::new(quil_store::RocksShardsStore::new(db.inner()));
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(StubProver)));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    let state = HypergraphState::new(crdt);
    let (signer, public_key) = quil_crypto::FalconKeyConstructor.new_key().unwrap();
    let address = super::materialize::prover_address_from_pubkey(&public_key).unwrap();
    let mut tree = quil_tries::VectorCommitmentTree::new();
    write_type(&mut tree, "prover:Prover").unwrap();
    write_field(&mut tree, "prover:Prover", "PublicKey", &public_key).unwrap();
    write_field(&mut tree, "prover:Prover", "Status", &[1u8]).unwrap();
    state
        .set(
            &GLOBAL_INTRINSIC_ADDRESS,
            &address,
            &vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    state.abort();
    let txn = db.new_batch(false).unwrap();
    for bits in grid {
        shards
            .put_app_shard(
                txn.as_ref(),
                &ShardInfo {
                    shard_key: grid_key(&app),
                    prefix: quil_forest::bit_path_to_prefix(bits),
                    size: vec![],
                    data_shards: 0,
                    commitment: vec![],
                },
            )
            .unwrap();
    }
    txn.commit().unwrap();
    let keys = Arc::new(Recorder::default());
    let gi = GlobalIntrinsic::new(keys.clone())
        .with_shards_store(shards.clone())
        .with_shards_db(db.clone());
    Net {
        app,
        signer,
        address,
        keys,
        tree,
        gi,
        state,
        shards,
        _db: db,
    }
}

impl Net {
    fn filter(&self, bits: &[bool]) -> Vec<u8> {
        if bits.is_empty() {
            self.app.to_vec()
        } else {
            quil_forest::encode_shard_bit_path(&self.app, bits)
        }
    }

    /// Sign `bytes(sig)` over what this build's verifier checks at the op's
    /// own frame, as an honest prover of this build does.
    fn sign<B: Fn(Option<AddressedSignature>) -> Vec<u8>>(&self, frame: u64, bytes: B) -> Vec<u8> {
        let placeholder = AddressedSignature {
            address: self.address.to_vec(),
            signature: vec![0u8; 666],
        };
        self.keys.calls.lock().unwrap().clear();
        let _ = self
            .gi
            .validate(frame, &bytes(Some(placeholder)), Some(&self.tree), None);
        let (message, domain) = self
            .keys
            .calls
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the verifier reached the signature check");
        let signature = self.signer.sign_with_domain(&message, &domain).unwrap();
        bytes(Some(AddressedSignature {
            address: self.address.to_vec(),
            signature,
        }))
    }

    fn split(&self, frame: u64, parent: &[bool], children: &[&[bool]]) -> ShardSplit {
        let op = ShardSplit {
            shard_address: self.filter(parent),
            proposed_shards: children.iter().map(|c| self.filter(c)).collect(),
            frame_number: frame,
            public_key_signature_bls48581: None,
        };
        let signed = self.sign(frame, |sig| {
            let mut op = op.clone();
            op.public_key_signature_bls48581 = sig;
            op.to_canonical_bytes().unwrap()
        });
        ShardSplit::from_canonical_bytes(&signed).unwrap()
    }

    fn merge(&self, frame: u64, parent: &[bool], children: &[&[bool]]) -> ShardMerge {
        let op = ShardMerge {
            shard_addresses: children.iter().map(|c| self.filter(c)).collect(),
            parent_address: self.filter(parent),
            frame_number: frame,
            public_key_signature_bls48581: None,
        };
        let signed = self.sign(frame, |sig| {
            let mut op = op.clone();
            op.public_key_signature_bls48581 = sig;
            op.to_canonical_bytes().unwrap()
        });
        ShardMerge::from_canonical_bytes(&signed).unwrap()
    }

    fn accepted(&self, frame: u64, bytes: &[u8]) -> bool {
        matches!(
            self.gi.validate(frame, bytes, Some(&self.tree), None),
            Ok(true)
        )
    }

    fn invoked(&self, frame: u64, bytes: &[u8]) -> bool {
        self.gi.invoke_step(frame, bytes, &self.state).is_ok()
    }

    /// The app's grid as this frame's staged view sees it, sorted.
    fn grid(&self) -> Vec<Vec<bool>> {
        let view =
            quil_store::ShardMetadataBatch::new(self.shards.clone(), self.state.pending_records());
        let key = grid_key(&self.app);
        let mut out: Vec<Vec<bool>> = view
            .range_app_shards()
            .unwrap()
            .into_iter()
            .filter(|row| row.shard_key == key)
            .map(|row| {
                quil_forest::shard_bit_path_from_prefix(&row.prefix)
                    .unwrap_or_else(|| quil_forest::prefix_to_bits(&row.prefix, 6))
            })
            .collect();
        out.sort();
        out
    }
}

fn show(grid: &[Vec<bool>]) -> String {
    let path = |bits: &Vec<bool>| -> String {
        if bits.is_empty() {
            "root".into()
        } else {
            bits.iter().map(|b| if *b { '1' } else { '0' }).collect()
        }
    };
    grid.iter().map(path).collect::<Vec<_>>().join(",")
}

const O: bool = false;
const I: bool = true;

#[test]
fn repro_split_rewrapped_with_other_children_is_refused() {
    activate();
    let net = net(&[&[]]);
    let honest = net.split(F, &[], &[&[O], &[I]]);
    assert!(
        net.accepted(F, &honest.to_canonical_bytes().unwrap()),
        "the honest split must verify (harness check)"
    );
    // Same signature, children the signer never chose: a deep descent that
    // leaves three empty spine shards.
    let mut forged = honest.clone();
    forged.proposed_shards = vec![net.filter(&[O, I, O, O]), net.filter(&[O, I, O, I])];
    let bytes = forged.to_canonical_bytes().unwrap();
    let validated = net.accepted(F, &bytes);
    let invoked = net.invoked(F, &bytes);
    assert!(
        !validated && !invoked,
        "VULNERABLE: a split re-wrapped with children its signer never signed was accepted \
         (validate {validated}, invoke {invoked})"
    );
}

#[test]
fn repro_split_replayed_in_a_later_epoch_is_refused() {
    activate();
    let net = net(&[&[]]);
    let honest = net.split(F, &[], &[&[O], &[I]]);
    let bytes = honest.to_canonical_bytes().unwrap();
    assert!(
        net.accepted(F, &bytes),
        "the honest split must verify (harness check)"
    );
    let later = F + 2 * LEN;
    let validated = net.accepted(later, &bytes);
    let invoked = net.invoked(later, &bytes);
    assert!(
        !validated && !invoked,
        "VULNERABLE: a split signed at frame {F} was accepted at frame {later} \
         (validate {validated}, invoke {invoked})"
    );
}

#[test]
fn repro_merge_replayed_in_a_later_epoch_is_refused() {
    activate();
    let net = net(&[&[O], &[I]]);
    let honest = net.merge(F, &[], &[&[O], &[I]]);
    let bytes = honest.to_canonical_bytes().unwrap();
    assert!(
        net.accepted(F, &bytes),
        "the honest merge must verify (harness check)"
    );
    let later = F + 2 * LEN;
    let validated = net.accepted(later, &bytes);
    let invoked = net.invoked(later, &bytes);
    assert!(
        !validated && !invoked,
        "VULNERABLE: a merge signed at frame {F} was accepted at frame {later} \
         (validate {validated}, invoke {invoked})"
    );
}

#[test]
fn repro_merge_rewrapped_onto_live_non_siblings_is_refused() {
    activate();
    // The grid after `0` split again: 00, 01, 1. The merge was signed for the
    // root when its children were 0 and 1.
    let net = net(&[&[O, O], &[O, I], &[I]]);
    let honest = net.merge(F, &[], &[&[O], &[I]]);
    let mut forged = honest.clone();
    forged.shard_addresses = vec![net.filter(&[O, O]), net.filter(&[I])];
    let bytes = forged.to_canonical_bytes().unwrap();
    let before = net.grid();
    let validated = net.accepted(F, &bytes);
    let invoked = net.invoked(F, &bytes);
    net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
    let after = net.grid();
    assert!(
        !validated && !invoked && after == before,
        "VULNERABLE: a merge re-wrapped onto the live non-siblings 00 and 1 was accepted \
         (validate {validated}, invoke {invoked}) and changed the grid from [{}] to [{}]",
        show(&before),
        show(&after)
    );
}

#[test]
fn repro_merge_whose_children_are_not_live_leaves_the_grid_whole() {
    activate();
    // A correctly signed, fresh merge of the root's children 0 and 1, while 0
    // is no longer a shard (it split into 00 and 01).
    let net = net(&[&[O, O], &[O, I], &[I]]);
    let merge = net.merge(F, &[], &[&[O], &[I]]);
    let bytes = merge.to_canonical_bytes().unwrap();
    let before = net.grid();
    let invoked = net.invoked(F, &bytes);
    net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
    let after = net.grid();
    assert_eq!(
        after,
        before,
        "VULNERABLE: a merge naming the child 0, which is not live, deleted live shards and \
         left the grid overlapping: [{}] became [{}] (invoke {invoked})",
        show(&before),
        show(&after)
    );
}

// ---- fix-only tests below ----

mod fixed {
    use super::*;
    use crate::global_intrinsic::verify::{
        shard_op_signing_payload, verify_shard_merge, verify_shard_split, ShardOpKind,
    };

    #[test]
    fn before_the_binding_epoch_splits_and_merges_verify_as_before() {
        quil_types::consensus::set_shard_op_binding_epoch_for_thread(Some(u64::MAX));
        let net = net(&[&[]]);
        let split = net.split(F, &[], &[&[O], &[I]]);
        let mut rewrapped = split.clone();
        rewrapped.proposed_shards = vec![net.filter(&[I, O]), net.filter(&[I, I])];
        let later = F + 2 * LEN;
        assert!(verify_shard_split(&split, &net.tree, net.keys.as_ref(), F).unwrap());
        assert!(
            verify_shard_split(&rewrapped, &net.tree, net.keys.as_ref(), later).unwrap(),
            "before the epoch the old rule stands, so every build agrees"
        );
        let merge = net.merge(F, &[], &[&[O], &[I]]);
        assert!(verify_shard_merge(&merge, &net.tree, net.keys.as_ref(), later).unwrap());
        // From the epoch the same old signatures no longer verify.
        activate();
        assert!(!verify_shard_split(&split, &net.tree, net.keys.as_ref(), F).unwrap());
        assert!(!verify_shard_merge(&merge, &net.tree, net.keys.as_ref(), F).unwrap());
    }

    #[test]
    fn the_bound_payload_covers_every_field_the_executor_reads() {
        activate();
        let parent = vec![7u8; 32];
        let c0 = quil_forest::encode_shard_bit_path(&parent, &[O]);
        let c1 = quil_forest::encode_shard_bit_path(&parent, &[I]);
        let other = quil_forest::encode_shard_bit_path(&parent, &[I, O]);
        let payload = |kind, frame, parent: &[u8], children: &[Vec<u8>]| {
            shard_op_signing_payload(kind, F, frame, parent, children).unwrap()
        };
        let base = payload(ShardOpKind::Split, F, &parent, &[c0.clone(), c1.clone()]);
        for (what, changed) in [
            (
                "frame",
                payload(
                    ShardOpKind::Split,
                    F + 1,
                    &parent,
                    &[c0.clone(), c1.clone()],
                ),
            ),
            (
                "parent",
                payload(ShardOpKind::Split, F, &[8u8; 32], &[c0.clone(), c1.clone()]),
            ),
            (
                "first child",
                payload(ShardOpKind::Split, F, &parent, &[other.clone(), c1.clone()]),
            ),
            (
                "second child",
                payload(ShardOpKind::Split, F, &parent, &[c0.clone(), other.clone()]),
            ),
            (
                "order",
                payload(ShardOpKind::Split, F, &parent, &[c1.clone(), c0.clone()]),
            ),
            (
                "count",
                payload(
                    ShardOpKind::Split,
                    F,
                    &parent,
                    &[c0.clone(), c1.clone(), other.clone()],
                ),
            ),
            (
                "kind",
                payload(ShardOpKind::Merge, F, &parent, &[c0.clone(), c1.clone()]),
            ),
        ] {
            assert_ne!(
                base, changed,
                "the signed bytes must change with the {what}"
            );
        }
        quil_types::consensus::set_shard_op_binding_epoch_for_thread(Some(u64::MAX));
        let legacy = payload(ShardOpKind::Split, F, &parent, &[c0, c1]);
        assert_ne!(base.1, legacy.1, "the bound bytes sign under a new domain");
    }

    #[test]
    fn children_must_be_one_branch_of_siblings() {
        activate();
        let net = net(&[&[]]);
        let refused = |parent: &[bool], children: Vec<Vec<u8>>, merge: bool| {
            let sig = Some(AddressedSignature {
                address: net.address.to_vec(),
                signature: vec![0u8; 666],
            });
            if merge {
                let op = ShardMerge {
                    shard_addresses: children,
                    parent_address: net.filter(parent),
                    frame_number: F,
                    public_key_signature_bls48581: sig,
                };
                verify_shard_merge(&op, &net.tree, net.keys.as_ref(), F).is_err()
            } else {
                let op = ShardSplit {
                    shard_address: net.filter(parent),
                    proposed_shards: children,
                    frame_number: F,
                    public_key_signature_bls48581: sig,
                };
                verify_shard_split(&op, &net.tree, net.keys.as_ref(), F).is_err()
            }
        };
        let f = |bits: &[bool]| net.filter(bits);
        assert!(
            refused(&[], vec![f(&[O]), f(&[I]), f(&[I, O])], false),
            "three children"
        );
        assert!(
            refused(&[], vec![f(&[O, O]), f(&[I])], false),
            "non-siblings"
        );
        assert!(
            refused(&[], vec![f(&[I]), f(&[O])], false),
            "siblings out of order"
        );
        assert!(
            refused(&[], vec![f(&[O, O]), f(&[O, I])], true),
            "a merge of grandchildren"
        );
        let deep = vec![O; 17];
        let mut deep1 = deep.clone();
        deep1.push(I);
        let mut deep0 = deep;
        deep0.push(O);
        assert!(
            refused(&[], vec![f(&deep0), f(&deep1)], false),
            "a descent past the limit"
        );
        let mut padded = f(&[I]);
        *padded.last_mut().unwrap() |= 1;
        assert!(
            refused(&[], vec![f(&[O]), padded], false),
            "a non-canonical encoding"
        );
        assert!(
            !refused(&[], vec![f(&[O, I, O]), f(&[O, I, I])], false),
            "a deep split"
        );
        assert!(
            !refused(&[O], vec![f(&[O, O]), f(&[O, I])], true),
            "a merge of children"
        );
    }

    #[test]
    fn honest_splits_and_merges_still_apply_after_the_binding_epoch() {
        activate();
        let net = net(&[&[]]);
        let split = net.split(F, &[], &[&[O], &[I]]);
        let bytes = split.to_canonical_bytes().unwrap();
        assert!(net.accepted(F + 3, &bytes) && net.invoked(F + 3, &bytes));
        net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
        assert_eq!(net.grid(), vec![vec![O], vec![I]]);

        let net = super::net(&[&[O], &[I]]);
        let merge = net.merge(F, &[], &[&[O], &[I]]);
        let bytes = merge.to_canonical_bytes().unwrap();
        assert!(net.accepted(F + 3, &bytes) && net.invoked(F + 3, &bytes));
        net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
        assert_eq!(net.grid(), vec![Vec::<bool>::new()]);
    }

    #[test]
    fn a_split_included_before_the_binding_epoch_is_checked_when_due() {
        // The epoch starts between inclusion (epoch 1000) and the due frame
        // (epoch 1002), so validate and invoke still run the old rule.
        quil_types::consensus::set_shard_op_binding_epoch_for_thread(Some(EPOCH + 1));
        let net = net(&[&[]]);
        // Re-wrapped onto 00 and 1, which are not the two siblings of one
        // branch: applied, they leave 01 uncovered. Apply cannot recheck a
        // signature that never covered the children, only their shape, so a
        // re-wrap onto siblings within the descent limit (say 0100, 0101)
        // still lands: the residual the advisory states for ops included
        // before the epoch.
        let mut forged = net.split(F, &[], &[&[O], &[I]]);
        forged.proposed_shards = vec![net.filter(&[O, O]), net.filter(&[I])];
        let bytes = forged.to_canonical_bytes().unwrap();
        assert!(
            net.accepted(F, &bytes) && net.invoked(F, &bytes),
            "before the epoch the old rule admits the re-wrapped split (harness check)"
        );
        net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![Vec::<bool>::new()],
            "a split included before the binding epoch with non-sibling children changed the \
             grid when due, from [root] to [{}]",
            show(&after)
        );

        // An honest split in flight across the epoch still applies.
        let net = super::net(&[&[]]);
        let bytes = net
            .split(F, &[], &[&[O], &[I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(net.accepted(F, &bytes) && net.invoked(F, &bytes));
        net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
        assert_eq!(
            net.grid(),
            vec![vec![O], vec![I]],
            "an honest split included before the epoch applies when due"
        );
    }

    #[test]
    fn honest_merges_beside_a_deep_split_spine_apply_after_the_binding_epoch() {
        activate();
        let net = net(&[&[O], &[I]]);
        // A deep split of 1 into 110 and 111 also registers the spine 10.
        let split = net
            .split(F, &[I], &[&[I, I, O], &[I, I, I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(net.accepted(F, &split) && net.invoked(F, &split));
        net.gi.apply_due_shard_changes(DUE, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![vec![O], vec![I, O], vec![I, I, O], vec![I, I, I]],
            "the honest deep split of 1 into 110 and 111 left the grid [{}]",
            show(&after)
        );

        // The merge of 110 and 111 into 11, beside the spine 10.
        let at = DUE + 1;
        let merge = net
            .merge(at, &[I, I], &[&[I, I, O], &[I, I, I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(net.accepted(at, &merge) && net.invoked(at, &merge));
        let due = at + 2 * LEN;
        net.gi.apply_due_shard_changes(due, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![vec![O], vec![I, O], vec![I, I]],
            "the honest merge of 110 and 111 into 11 beside the spine 10 left the grid [{}]",
            show(&after)
        );

        // The spine 10 and the branch 11 back into 1.
        let at = at + 2 * LEN + 1;
        let merge = net
            .merge(at, &[I], &[&[I, O], &[I, I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(net.accepted(at, &merge) && net.invoked(at, &merge));
        let due = at + 2 * LEN;
        net.gi.apply_due_shard_changes(due, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![vec![O], vec![I]],
            "the honest merge of the spine 10 and 11 into 1 left the grid [{}]",
            show(&after)
        );
    }

    #[test]
    fn a_change_needing_a_shard_another_due_change_adds_waits_a_frame() {
        activate();
        // The grid after a deep split of 1: 0, the spine 10, 110 and 111.
        let net = net(&[&[O], &[I, O], &[I, I, O], &[I, I, I]]);
        // Due in one frame: the merge of 110 and 111 into 11, then a split
        // of 11, which is a shard only once that merge applies. The gate
        // and the reassignment read the committed grid, so the split must
        // wait for the next frame rather than apply ungated.
        let merge = net
            .merge(F, &[I, I], &[&[I, I, O], &[I, I, I]])
            .to_canonical_bytes()
            .unwrap();
        let split = net
            .split(F + LEN, &[I, I], &[&[I, I, O], &[I, I, I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(
            net.invoked(F, &merge) && net.invoked(F + LEN, &split),
            "both changes must be staged (harness check)"
        );
        let due = DUE + LEN;
        net.gi.apply_due_shard_changes(due, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![vec![O], vec![I, O], vec![I, I]],
            "the split of 11 applied, ungated and unreassigned, in the frame the merge creating \
             11 applied: the grid became [{}]",
            show(&after)
        );
        let next = due + 1;
        net.gi.apply_due_shard_changes(next, &net.state).unwrap();
        let after = net.grid();
        assert_eq!(
            after,
            vec![vec![O], vec![I, O], vec![I, I, O], vec![I, I, I]],
            "the deferred split of 11 did not apply the next frame: the grid is [{}]",
            show(&after)
        );
    }

    #[test]
    fn two_splits_of_one_parent_due_in_one_frame_apply_once() {
        activate();
        let net = net(&[&[]]);
        // Due in one frame: a split of the root into 0 and 1, then one into
        // 10 and 11 (spine 0) signed an epoch later. The first removes the
        // root, so the second must be consumed, not layered over it.
        let first = net
            .split(F, &[], &[&[O], &[I]])
            .to_canonical_bytes()
            .unwrap();
        let second = net
            .split(F + LEN, &[], &[&[I, O], &[I, I]])
            .to_canonical_bytes()
            .unwrap();
        assert!(
            net.invoked(F, &first) && net.invoked(F + LEN, &second),
            "both splits must be staged (harness check)"
        );
        let due = DUE + LEN;
        net.gi.apply_due_shard_changes(due, &net.state).unwrap();
        let after = net.grid();
        let view =
            quil_store::ShardMetadataBatch::new(net.shards.clone(), net.state.pending_records());
        let pending = view.all_pending_shard_changes().unwrap().len();
        assert!(
            after == vec![vec![O], vec![I]] && pending == 0,
            "two splits of the root due in one frame layered the grid [{}] ({pending} pending \
             left)",
            show(&after)
        );
    }

    #[test]
    fn the_proposer_signs_what_the_verifier_checks() {
        activate();
        let net = net(&[&[]]);
        let children = vec![net.filter(&[O]), net.filter(&[I])];
        let (message, domain) =
            shard_op_signing_payload(ShardOpKind::Split, F, F, &net.app, &children).unwrap();
        let op = ShardSplit {
            shard_address: net.app.to_vec(),
            proposed_shards: children.clone(),
            frame_number: F,
            public_key_signature_bls48581: Some(AddressedSignature {
                address: net.address.to_vec(),
                signature: net.signer.sign_with_domain(&message, &domain).unwrap(),
            }),
        };
        assert!(verify_shard_split(&op, &net.tree, net.keys.as_ref(), F + 9).unwrap());
        let (message, domain) =
            shard_op_signing_payload(ShardOpKind::Merge, F, F, &net.app, &children).unwrap();
        let op = ShardMerge {
            shard_addresses: children,
            parent_address: net.app.to_vec(),
            frame_number: F,
            public_key_signature_bls48581: Some(AddressedSignature {
                address: net.address.to_vec(),
                signature: net.signer.sign_with_domain(&message, &domain).unwrap(),
            }),
        };
        assert!(verify_shard_merge(&op, &net.tree, net.keys.as_ref(), F + 9).unwrap());
    }
}
