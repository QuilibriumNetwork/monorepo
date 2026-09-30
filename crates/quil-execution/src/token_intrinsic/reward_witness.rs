//! Bounded QUIL reward witnesses checked against a canonical global frame.
use crate::{
    domains, global_schema,
    hypergraph_state::{vertex_adds_discriminator, HypergraphState},
};
use quil_types::{
    error::{QuilError, Result},
    store::{ClockStore, RewardWitnessData},
};

pub const MAX_REWARD_PROOF_BYTES: usize = 32 * 1024;
const REWARD: &str = "reward:ProverReward";

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(format!("reward witness: {message}"))
}

/// Check all fields used by mint admission, not only inclusion of an address.
pub fn verify_reward_membership(
    owner: &[u8; 32],
    value: u128,
    root: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    if value == 0
        || bytes.len() > MAX_REWARD_PROOF_BYTES
        || bytes.get(..4) != Some([1u8, 0, 0, 0].as_slice())
    {
        return Err(QuilError::InvalidArgument(
            "invalid reward witness dimensions".into(),
        ));
    }
    let proof = quil_forest::MembershipProof::from_bytes(bytes)
        .map_err(|_| QuilError::InvalidArgument("invalid reward witness encoding".into()))?;
    let address = crate::global_intrinsic::materialize::reward_address(owner)?;
    let mut vertex = [0; 64];
    vertex[..32].copy_from_slice(&domains::GLOBAL);
    vertex[32..].copy_from_slice(&address);
    if proof.inputs.len() != 1 || proof.inputs[0].vertex_address != vertex {
        return Err(QuilError::InvalidArgument(
            "reward witness address mismatch".into(),
        ));
    }
    let mut balance = [0; 32];
    balance[16..].copy_from_slice(&value.to_be_bytes());
    let expected = vec![
        (
            vec![0xff; 32],
            global_schema::compute_type_hash(REWARD).to_vec(),
        ),
        (
            global_schema::field_key(REWARD, "DelegateAddress")
                .ok_or_else(|| unavailable("missing delegate schema"))?,
            owner.to_vec(),
        ),
        (
            global_schema::field_key(REWARD, "Balance")
                .ok_or_else(|| unavailable("missing balance schema"))?,
            balance.to_vec(),
        ),
    ];
    quil_forest::verify_vertex_membership(root, &proof.inputs[0], &expected)
        .map_err(|_| QuilError::InvalidArgument("reward witness root or fields mismatch".into()))
}

/// Read the historical reward state named by the latest canonical header.
/// Missing/pruned history remains unavailable; admission rechecks current funds.
/// How far back from the latest global frame a reward witness may cite. A node
/// that syncs the prover tree rather than materializing every global frame only
/// retains the roots it synced, so the newest frame's root is usually absent.
pub const REWARD_WITNESS_LOOKBACK_FRAMES: u64 = 1440;

/// The newest stored global frame (within the lookback) whose prover root this
/// node retains, with that root. Witnesses cite it: the mint and the mint
/// claim admit any cited frame at or before their finalized anchor.
/// `max_frame` caps the citation: the reward mint executes in the global venue
/// (no cap), a mint claim in an app-shard frame that rejects citations after
/// that frame's global anchor.
pub fn newest_retained_global_root(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    max_frame: Option<u64>,
) -> Result<([u8; 32], quil_types::proto::global::GlobalFrameHeader)> {
    let latest = clock
        .get_latest_global_clock_frame()?
        .header
        .ok_or_else(|| unavailable("latest global frame has no header"))?;
    let newest = max_frame.map_or(latest.frame_number, |cap| cap.min(latest.frame_number));
    for number in (newest.saturating_sub(REWARD_WITNESS_LOOKBACK_FRAMES)..=newest).rev() {
        let header = if number == latest.frame_number {
            latest.clone()
        } else {
            match clock.get_global_clock_frame(number).ok().and_then(|frame| frame.header) {
                Some(header) => header,
                None => continue,
            }
        };
        let root: [u8; 32] = header
            .prover_tree_commitment
            .as_slice()
            .try_into()
            .map_err(|_| unavailable("global reward root is not 32 bytes"))?;
        if state.crdt().global_root_available(&root)? {
            return Ok((root, header));
        }
    }
    Err(unavailable("historical global reward root unavailable"))
}

pub fn quil_reward_witness(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    owner: &[u8; 32],
) -> Result<RewardWitnessData> {
    let (root, header) = newest_retained_global_root(state, clock, None)?;
    let address = crate::global_intrinsic::materialize::reward_address(owner)?;
    let membership = match state
        .crdt()
        .global_vertex_membership_at_root(&root, &address)?
    {
        Some(proof) => proof,
        None => return Ok(RewardWitnessData::default()),
    };
    let blob = &membership.vertex_blob;
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob)
            .map_err(|_| unavailable("corrupt reward record"))?,
    };
    let balance = global_schema::read_field(&tree, REWARD, "Balance")
        .ok_or_else(|| unavailable("missing reward balance"))?;
    if balance.len() != 32 || balance[..16].iter().any(|b| *b != 0) {
        return Err(unavailable("reward balance does not fit canonical u128"));
    }
    let value = u128::from_be_bytes(balance[16..].try_into().unwrap());
    if value == 0 {
        return Ok(RewardWitnessData::default());
    }
    let proof = quil_forest::MembershipProof {
        inputs: vec![membership],
    }
    .to_bytes();
    verify_reward_membership(owner, value, &root, &proof)
        .map_err(|_| unavailable("historical reward witness does not match cited global frame"))?;
    Ok(RewardWitnessData {
        found: true,
        forest_proof: proof,
        value,
        cited_frame: header.frame_number,
        reward_root: root.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_hypergraph::addressing::{shard_key_for_location, Location};
    use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
    use std::sync::Arc;

    #[test]
    fn reward_witness_binds_committed_state_to_cited_root_without_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let open = || {
            let db = quil_store::RocksDb::open(directory.path()).unwrap();
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ));
            crdt.set_forest(quil_forest::Forest::new(db.inner()));
            crdt
        };
        let crdt = open();
        let state = HypergraphState::new(crdt.clone());
        let clock = quil_store::testing::InMemoryClockStore::new();
        let owner = [7; 32];
        let address = crate::global_intrinsic::materialize::reward_address(&owner).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        global_schema::write_type(&mut tree, REWARD).unwrap();
        global_schema::write_field(&mut tree, REWARD, "DelegateAddress", &owner).unwrap();
        let mut balance = [0; 32];
        balance[16..].copy_from_slice(&u128::MAX.to_be_bytes());
        global_schema::write_field(&mut tree, REWARD, "Balance", &balance).unwrap();
        let put = |tree: &quil_tries::VectorCommitmentTree| {
            state
                .set(
                    &domains::GLOBAL,
                    &address,
                    &disc,
                    1,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap()
        };
        put(&tree);
        state.commit().unwrap();
        crdt.commit(1).unwrap();
        let shard = shard_key_for_location(&Location {
            app_address: domains::GLOBAL,
            data_address: address,
        });
        let root = crdt.compute_shard_root("vertex", "adds", &shard);
        let seed = |frame_number, root| {
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number,
                    prover_tree_commitment: root,
                    ..Default::default()
                }),
                ..Default::default()
            })
        };
        seed(2, root.clone());
        let witness = quil_reward_witness(&state, &clock, &owner).unwrap();
        assert!(witness.found);
        assert_eq!(witness.value, u128::MAX);
        assert_eq!(witness.cited_frame, 2);
        verify_reward_membership(
            &owner,
            witness.value,
            &root.clone().try_into().unwrap(),
            &witness.forest_proof,
        )
        .unwrap();
        assert!(verify_reward_membership(
            &owner,
            witness.value - 1,
            &root.clone().try_into().unwrap(),
            &witness.forest_proof
        )
        .is_err());
        seed(2, vec![99; 32]);
        assert!(matches!(
            quil_reward_witness(&state, &clock, &owner),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        seed(2, root.clone());
        balance[0] = 1;
        global_schema::write_field(&mut tree, REWARD, "Balance", &balance).unwrap();
        put(&tree);
        // An uncommitted or newer committed state must not replace the cited
        // parent's blob. Frame 2 still binds post-frame-1 state.
        assert_eq!(
            quil_reward_witness(&state, &clock, &owner).unwrap().value,
            u128::MAX
        );
        state.commit().unwrap();
        crdt.commit(2).unwrap();
        assert_eq!(
            quil_reward_witness(&state, &clock, &owner).unwrap().value,
            u128::MAX
        );
        let oversized_root = crdt.compute_shard_root("vertex", "adds", &shard);
        seed(3, oversized_root);
        assert!(
            matches!(quil_reward_witness(&state,&clock,&owner),Err(QuilError::ExecutionUnavailable(e)) if e.contains("u128"))
        );
        balance[0] = 0;
        balance[31] -= 1;
        global_schema::write_field(&mut tree, REWARD, "Balance", &balance).unwrap();
        put(&tree);
        state.commit().unwrap();
        crdt.commit(3).unwrap();
        let new_root = crdt.compute_shard_root("vertex", "adds", &shard);
        seed(4, new_root.clone());
        assert_eq!(
            quil_reward_witness(&state, &clock, &owner).unwrap().value,
            u128::MAX - 1
        );
        let frame4_witness = quil_reward_witness(&state, &clock, &owner).unwrap();
        balance[31] -= 1;
        global_schema::write_field(&mut tree, REWARD, "Balance", &balance).unwrap();
        put(&tree);
        state.commit().unwrap();
        crdt.commit(4).unwrap();
        drop(state);
        drop(crdt);
        let reopened = open();
        let state = HypergraphState::new(reopened.clone());
        let historical = quil_reward_witness(&state, &clock, &owner).unwrap();
        assert_eq!(historical.value, u128::MAX - 1);
        assert_eq!(historical.reward_root, new_root);
        assert_eq!(historical.forest_proof, frame4_witness.forest_proof);
        // A newer global frame whose root this node does not retain (a node
        // that synced rather than materialized it) falls back to the newest
        // frame whose root it holds.
        seed(5, vec![0xAB; 32]);
        let fallback = quil_reward_witness(&state, &clock, &owner).unwrap();
        assert_eq!(fallback.cited_frame, 4);
        assert_eq!(fallback.reward_root, new_root);
        assert_eq!(fallback.value, u128::MAX - 1);
        reopened.prune_to_frame(5).unwrap();
        assert!(quil_reward_witness(&state, &clock, &owner).is_err());
    }
}

/// Derive the reward-root domain and owner-bound reward vertex address.
/// QUIL rewards reside in the global domain; other applications use the
/// prover address directly. Spend authority is checked separately.
pub fn derive_pomw_addressing(
    tx_domain: &[u8],
    owner_prover_address: &[u8],
) -> Result<(/* prover_root_domain */ [u8; 32], /* leaf_owner_address */ [u8; 32])> {
    if tx_domain.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: tx domain must be 32 bytes, got {}",
            tx_domain.len()
        )));
    }
    if owner_prover_address.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: owner prover address must be {} bytes, got {}",
            32,
            owner_prover_address.len()
        )));
    }

    let mut prover_root_domain = [0u8; 32];
    prover_root_domain.copy_from_slice(&tx_domain[..32]);

    if tx_domain == domains::QUIL_TOKEN {
        // QUIL special case: reward leaves live under the global
        // intrinsic domain at `poseidon(domains::QUIL_TOKEN ‖ owner)`
        // — exactly where `materialize::reward_address` writes them
        // at join time.
        prover_root_domain = domains::GLOBAL;
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&domains::QUIL_TOKEN);
        preimage.extend_from_slice(owner_prover_address);
        let leaf_owner_address = quil_crypto::poseidon::hash_bytes_to_32(&preimage)?;
        Ok((prover_root_domain, leaf_owner_address))
    } else {
        // Non-QUIL: the leaf-owner address is the owner prover
        // address directly under the token's domain.
        let mut leaf_owner_address = [0u8; 32];
        leaf_owner_address.copy_from_slice(owner_prover_address);
        Ok((prover_root_domain, leaf_owner_address))
    }
}
