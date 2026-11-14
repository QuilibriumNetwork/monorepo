//! A `ProverKick` built from one honest GLOBAL vote and a copy of it whose
//! output gains a zero byte. The vote signs only `Poseidon(output) ‖ rank`,
//! and the Poseidon sponge pads its last chunk with zeros, so the one
//! signature verifies on both frames although their outputs differ. Such a
//! pair is not two votes in one slot, so GLOBAL must not accept it as
//! equivocation once the signed-slot rule is active.
//!
//! The kick is processed in GLOBAL frame `u64::MAX` with one-frame epochs:
//! its epoch, `u64::MAX`, lies at or after every activation epoch. One test
//! per binary: the epoch length is process-global.

use std::sync::Arc;

use quil_execution::global_intrinsic::frame_header::GlobalFrameHeader;
use quil_execution::global_intrinsic::kick_verify::verify_prover_kick_full;
use quil_execution::global_intrinsic::materialize::create_prover_vertex_tree;
use quil_execution::global_intrinsic::prover_ops::ProverKick;
use quil_execution::global_schema::{write_field, GLOBAL_INTRINSIC_ADDRESS};
use quil_execution::hypergraph_intrinsic::canonical::{AggregateSignature, Bls48581G2PublicKey};
use quil_execution::prover_registry::vertex_tree_to_blob;
use quil_types::consensus::{ProverInfo, ProverRegistry, ProverShardSummary, ProverStatus};
use quil_types::crypto::Signer as _;
use quil_types::error::Result;

/// The GLOBAL frame the kick is processed in.
const KICK_FRAME: u64 = u64::MAX;

/// The rank of the victim's vote.
const RANK: u64 = 7;

/// The committee of the GLOBAL frames: the victim alone.
struct Committee {
    active: Vec<ProverInfo>,
}

impl ProverRegistry for Committee {
    fn get_prover_info(&self, _: &[u8]) -> Result<Option<ProverInfo>> {
        Ok(None)
    }
    fn get_next_prover(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8], _: u64) -> Result<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    fn get_active_provers(&self, _: &[u8], _: u64) -> Result<Vec<ProverInfo>> {
        Ok(self.active.clone())
    }
    fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
        Ok(self.active.len())
    }
    fn get_provers(&self, _: &[u8]) -> Result<Vec<ProverInfo>> {
        Ok(self.active.clone())
    }
    fn get_provers_by_status(&self, _: &[u8], _: ProverStatus) -> Result<Vec<ProverInfo>> {
        Ok(vec![])
    }
    fn get_prover_shard_summaries(&self, _: u64) -> Result<Vec<ProverShardSummary>> {
        Ok(vec![])
    }
}

/// Restores the mainnet epoch length when the test ends.
struct MainnetEpochLength;

impl Drop for MainnetEpochLength {
    fn drop(&mut self) {
        quil_types::consensus::set_epoch_length_frames(0);
    }
}

/// A GLOBAL frame carrying `signer`'s vote for `output` in [`RANK`]:
/// `Poseidon(output) ‖ rank` under `"global"`.
fn voted_global_frame(signer: &quil_crypto::FalconSigner, output: Vec<u8>) -> GlobalFrameHeader {
    let identity = quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap();
    let payload = [identity.as_slice(), &RANK.to_be_bytes()].concat();
    let signature = signer.sign_with_domain(&payload, b"global").unwrap();
    GlobalFrameHeader {
        frame_number: 100,
        rank: RANK,
        output,
        public_key_signature_bls48581: AggregateSignature {
            signature,
            public_key: Some(Bls48581G2PublicKey {
                key_value: signer.public_key().to_vec(),
            }),
            bitmask: vec![0b1],
        }
        .to_canonical_bytes()
        .unwrap(),
        ..Default::default()
    }
}

/// Everything GLOBAL needs to verify a kick of `victim` in [`KICK_FRAME`]:
/// the victim active in the prover tree of the previous frame, and a
/// membership proof of its prover vertex.
struct Network {
    clock: quil_store::testing::InMemoryClockStore,
    hypergraph: quil_hypergraph::HypergraphCrdt,
    committee: Committee,
    membership_proof: Vec<u8>,
}

impl Network {
    fn with_active(victim: &quil_crypto::FalconSigner) -> Self {
        let public_key = victim.public_key().to_vec();
        let address = quil_crypto::poseidon::hash_bytes_to_32(&public_key).unwrap();
        let mut tree = create_prover_vertex_tree(&public_key, 0).unwrap();
        write_field(&mut tree, "prover:Prover", "Status", &[1]).unwrap();
        let blob = vertex_tree_to_blob(&tree);

        let forest = quil_forest::Forest::in_memory();
        let shard = b"prover-tree";
        let root = forest
            .commit_shard_phase_raw(
                shard,
                quil_forest::Phase::VertexAdds,
                0,
                [(
                    address.to_vec(),
                    quil_tries::vertex_leaf_value(&blob).unwrap(),
                )],
            )
            .unwrap();
        let vertex = forest
            .build_vertex_membership_proof(
                shard,
                quil_forest::Phase::VertexAdds,
                0,
                &[GLOBAL_INTRINSIC_ADDRESS.as_slice(), &address].concat(),
                &blob,
            )
            .unwrap();

        let clock = quil_store::testing::InMemoryClockStore::new();
        clock.seed_frame(quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: KICK_FRAME - 1,
                prover_tree_commitment: root.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        });
        Network {
            clock,
            hypergraph: quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_tries::ShaInclusionProver),
            ),
            committee: Committee {
                active: vec![ProverInfo {
                    public_key,
                    address: address.to_vec(),
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: vec![],
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: vec![],
                }],
            },
            membership_proof: quil_forest::MembershipProof {
                inputs: vec![vertex],
            }
            .to_bytes(),
        }
    }

    /// GLOBAL's verdict on a kick of `victim` between two frames.
    fn verify_kick(
        &self,
        victim: &quil_crypto::FalconSigner,
        frame_1: &GlobalFrameHeader,
        frame_2: &GlobalFrameHeader,
    ) -> Result<()> {
        let kick = ProverKick {
            frame_number: KICK_FRAME,
            kicked_prover_public_key: victim.public_key().to_vec(),
            conflicting_frame_1: frame_1.to_canonical_bytes().unwrap(),
            conflicting_frame_2: frame_2.to_canonical_bytes().unwrap(),
            commitment: vec![],
            proof: vec![],
            traversal_proof: self.membership_proof.clone(),
        };
        verify_prover_kick_full(
            &kick,
            KICK_FRAME,
            &self.clock,
            &quil_crypto::WesolowskiFrameProver::new(2048),
            &quil_crypto::FalconKeyConstructor,
            &self.hypergraph,
            &quil_types::crypto::NoopInclusionProver,
            Some(&self.committee as &dyn ProverRegistry),
        )
    }
}

#[test]
fn reproduces_kick_from_one_padded_vote() {
    quil_types::consensus::set_epoch_length_frames(1);
    let _restore = MainnetEpochLength;
    let victim = quil_crypto::FalconSigner::generate();
    let network = Network::with_active(&victim);

    // Control: two votes for different frames in one rank are equivocation.
    let first = voted_global_frame(&victim, vec![0x01; 516]);
    let second = voted_global_frame(&victim, vec![0x02; 516]);
    if let Err(e) = network.verify_kick(&victim, &first, &second) {
        panic!("a kick for two votes in one rank must be accepted: {e}");
    }

    // One honest vote and a copy whose output gains a zero byte: the outputs
    // differ, the signed identity does not.
    let mut padded = first.clone();
    padded.output.push(0);
    assert_eq!(
        quil_crypto::poseidon::hash_bytes_to_32(&first.output).unwrap(),
        quil_crypto::poseidon::hash_bytes_to_32(&padded.output).unwrap()
    );
    match network.verify_kick(&victim, &first, &padded) {
        Ok(()) => panic!(
            "a kick built from one honest vote with a padded output was accepted: \
             GLOBAL would kick an honest prover"
        ),
        Err(e) => assert!(
            e.to_string().contains("no equivocation detected"),
            "the padded vote must be rejected as no equivocation, not by: {e}"
        ),
    }
}
