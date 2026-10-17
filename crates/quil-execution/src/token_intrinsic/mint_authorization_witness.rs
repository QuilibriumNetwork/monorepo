//! Historical receipt lookup. The caller verifies authorization fields; this
//! endpoint cannot attest whether the app has already consumed the receipt.
use crate::hypergraph_state::HypergraphState;
use quil_types::{
    error::{QuilError, Result},
    store::{ClockStore, MintAuthorizationWitnessData},
};

pub fn witness(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    // The QUIL shard's latest certified global anchor, when this node runs
    // or reaches a QUIL shard engine. Later frames anchor at or after it.
    shard_anchor: Option<u64>,
) -> Result<MintAuthorizationWitnessData> {
    let unavailable = |message: &str| {
        QuilError::ExecutionUnavailable(format!("mint authorization witness: {message}"))
    };
    // Same citation rule as the reward witness: the newest global frame whose
    // root this node retains (a syncing node rarely holds the latest root).
    // The claim executes in an app-shard frame and is rejected if it cites a
    // global frame after that frame's anchor. Anchors only grow, so citing at
    // or before the shard's latest certified anchor is always admissible.
    // Without a shard view, fall back to a lag behind the global head.
    let cap = match shard_anchor {
        Some(anchor) => anchor,
        None => clock.get_latest_global_clock_frame()?.header
            .map(|h| h.frame_number)
            .unwrap_or(0)
            .saturating_sub(super::constants::MINT_CLAIM_CITATION_LAG),
    };
    let (root, header) = super::reward_witness::newest_retained_global_root(state, clock, Some(cap))
        .map_err(|e| unavailable(&e.to_string()))?;
    let Some(proof) = state
        .crdt()
        .global_vertex_membership_at_root(&root, receipt)?
    else {
        return Ok(MintAuthorizationWitnessData::default());
    };
    let cap = super::reward_witness::MAX_REWARD_PROOF_BYTES;
    if proof.vertex_blob.len() > cap {
        return Err(unavailable("receipt record exceeds witness limit"));
    }
    let proof = quil_forest::MembershipProof {
        inputs: vec![proof],
    }
    .to_bytes();
    if proof.len() > cap {
        return Err(unavailable("membership proof exceeds witness limit"));
    }
    Ok(MintAuthorizationWitnessData {
        found: true,
        forest_proof: proof,
        cited_frame: header.frame_number,
        global_root: root.to_vec(),
    })
}
