//! Restoration of the seniority storage epoch proof kicks took.
//!
//! Before the storage kick suspension epoch
//! ([`quil_types::consensus::storage_kicks_suspended`]) a seat that closed an
//! epoch with committed roots its member never proved kicked the member:
//! Status 4, `KickFrameNumber`, and `Seniority` set to 0. From that epoch
//! such a kick no longer bars a rejoin, and the rejoin keeps what the vertex
//! holds, which is the accrual after the kick at most. At the restoration
//! frame ([`quil_types::consensus::kicked_seniority_restoration_frame`]) each
//! listed prover gains `before_kick − at_rejoin`
//! ([`quil_types::consensus::SeniorityRestoration`]): what it held before its
//! first kick, less what its vertex held when it rejoined, so seniority
//! earned since the rejoin is kept and the accrual between kick and rejoin
//! is not counted twice. A prover not yet rejoined ends at `before_kick`,
//! and its later rejoin keeps that.
//!
//! The restoration never lowers seniority, saturates, skips a prover whose
//! vertex is absent and stamps `SeniorityRestorationFrame` on each vertex it
//! restores, which a rejoin keeps: GLOBAL frame execution gives it once,
//! also when the frame is executed again over state that holds it.
//!
//! Status, `KickFrameNumber` and the allocations stay as the kick left them:
//! a rejoin from the suspension epoch clears them, with the committee's
//! confirmation. `LastSeniorityFrameNumber` (the accrual's once-per-frame
//! key), the retro ledger and `SeniorityPenalty` were not changed by the kick.

use quil_types::consensus::{kicked_seniority_restoration_frame, kicked_seniority_restorations};
use quil_types::error::Result;

use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

const PROVER: &str = "prover:Prover";

/// The prover field that records the restoration frame.
pub const RESTORATION_FIELD: &str = "SeniorityRestorationFrame";

fn read_u64(tree: &quil_tries::VectorCommitmentTree, field: &str) -> Option<u64> {
    read_field(tree, PROVER, field)
        .and_then(|bytes| bytes.get(..8).and_then(|head| head.try_into().ok()))
        .map(u64::from_be_bytes)
}

/// At the restoration frame, give each listed prover back the seniority its
/// storage kick took (see the module docs). Does nothing at any other
/// frame. Returns how many provers it restored.
pub fn restore_kicked_seniority(state: &HypergraphState, frame: u64) -> Result<usize> {
    if frame != kicked_seniority_restoration_frame() {
        return Ok(0);
    }
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
    let va_disc = vertex_adds_discriminator()?;
    let table = kicked_seniority_restorations();
    let (mut restored, mut already, mut absent, mut added) = (0usize, 0usize, 0usize, 0u64);
    for entry in &table {
        let prover = hex::encode(&entry.prover[26..]);
        let Some(blob) = state
            .get(domain, &entry.prover, &va_disc)?
            .filter(|blob| !blob.is_empty())
        else {
            absent += 1;
            tracing::warn!(
                frame,
                prover = %prover,
                "kicked seniority restoration: prover vertex absent from this node's GLOBAL \
                 state, skipped; a network that holds it restores it"
            );
            continue;
        };
        let mut tree = rebuild_vertex_tree_from_blob(&blob);
        if let Some(restored_at) = read_u64(&tree, RESTORATION_FIELD) {
            already += 1;
            tracing::info!(
                frame,
                prover = %prover,
                restored_at,
                "kicked seniority restoration: already restored, skipped"
            );
            continue;
        }
        let old = read_u64(&tree, "Seniority").unwrap_or(0);
        let new = old.saturating_add(entry.before_kick.saturating_sub(entry.at_rejoin));
        write_field(&mut tree, PROVER, "Seniority", &new.to_be_bytes())?;
        write_field(&mut tree, PROVER, RESTORATION_FIELD, &frame.to_be_bytes())?;
        state.set(
            domain,
            &entry.prover,
            &va_disc,
            frame,
            vertex_tree_to_blob(&tree),
        )?;
        restored += 1;
        added = added.saturating_add(new - old);
        tracing::info!(
            frame,
            prover = %prover,
            old,
            new,
            before_kick = entry.before_kick,
            at_rejoin = entry.at_rejoin,
            "kicked seniority restored"
        );
    }
    tracing::info!(
        frame,
        listed = table.len(),
        restored,
        already,
        absent,
        added,
        "kicked seniority restoration done"
    );
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{
        set_kicked_seniority_restoration_frame_for_thread,
        set_kicked_seniority_restorations_for_thread, SeniorityRestoration,
    };

    struct StubProver;
    impl quil_types::crypto::InclusionProver for StubProver {
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
        ) -> Result<Box<dyn quil_types::crypto::Multiproof>> {
            Err(quil_types::error::QuilError::Internal(
                "batch not supported".into(),
            ))
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

    fn make_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(crate::hypergraph_state::InMemoryHypergraphStore::new()),
            std::sync::Arc::new(StubProver),
        )))
    }

    /// A prover vertex with `seniority`, its address.
    fn seed(state: &HypergraphState, seed: u8, seniority: u64) -> [u8; 32] {
        let pubkey = vec![seed; 585];
        let address = super::super::materialize::prover_address_from_pubkey(&pubkey).unwrap();
        let tree =
            super::super::materialize::create_prover_vertex_tree(&pubkey, seniority).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                &address,
                &vertex_adds_discriminator().unwrap(),
                1,
                vertex_tree_to_blob(&tree),
            )
            .unwrap();
        address
    }

    fn vertex(
        state: &HypergraphState,
        address: &[u8; 32],
    ) -> Option<quil_tries::VectorCommitmentTree> {
        state
            .get(
                &GLOBAL_INTRINSIC_ADDRESS[..],
                address,
                &vertex_adds_discriminator().unwrap(),
            )
            .unwrap()
            .filter(|blob| !blob.is_empty())
            .map(|blob| rebuild_vertex_tree_from_blob(&blob))
    }

    fn seniority(state: &HypergraphState, address: &[u8; 32]) -> u64 {
        read_u64(&vertex(state, address).unwrap(), "Seniority").unwrap()
    }

    fn restored_at(state: &HypergraphState, address: &[u8; 32]) -> Option<u64> {
        read_u64(&vertex(state, address).unwrap(), RESTORATION_FIELD)
    }

    fn configure(frame: Option<u64>, table: Option<Vec<SeniorityRestoration>>) {
        set_kicked_seniority_restoration_frame_for_thread(frame);
        set_kicked_seniority_restorations_for_thread(table);
    }

    /// At the restoration frame a prover gains what it held before its
    /// first kick less what it held at its rejoin, keeping what it earned
    /// since; at no other frame, and only once.
    #[test]
    fn the_restoration_frame_adds_the_lost_seniority_once_and_keeps_what_was_earned_since() {
        let state = make_state();
        // Held 2,420 before its first kick, 30 when it rejoined, and
        // earned 170 since.
        let rejoined = seed(&state, 0xB1, 30 + 170);
        // Never rejoined: holds the 30 it accrued after the kick.
        let kicked = seed(&state, 0xB2, 30);
        let unlisted = seed(&state, 0xB3, 500);
        configure(
            Some(700),
            Some(vec![
                SeniorityRestoration {
                    prover: rejoined,
                    before_kick: 2_420,
                    at_rejoin: 30,
                },
                SeniorityRestoration {
                    prover: kicked,
                    before_kick: 900,
                    at_rejoin: 30,
                },
            ]),
        );
        for frame in [1, 699, 701, u64::MAX] {
            assert_eq!(restore_kicked_seniority(&state, frame).unwrap(), 0);
        }
        assert_eq!(
            seniority(&state, &rejoined),
            200,
            "restored before its frame"
        );
        assert_eq!(restored_at(&state, &rejoined), None);

        assert_eq!(restore_kicked_seniority(&state, 700).unwrap(), 2);
        assert_eq!(seniority(&state, &rejoined), 2_420 + 170);
        assert_eq!(seniority(&state, &kicked), 900);
        assert_eq!(
            seniority(&state, &unlisted),
            500,
            "an unlisted prover changed"
        );
        assert_eq!(restored_at(&state, &rejoined), Some(700));
        assert_eq!(restored_at(&state, &kicked), Some(700));
        assert_eq!(restored_at(&state, &unlisted), None);

        // Executing the frame again over state that holds the restoration,
        // and the frames after it, give nothing more.
        state.commit().unwrap();
        for frame in [700, 701] {
            assert_eq!(restore_kicked_seniority(&state, frame).unwrap(), 0);
        }
        assert_eq!(seniority(&state, &rejoined), 2_420 + 170, "restored twice");
        assert_eq!(seniority(&state, &kicked), 900, "restored twice");
        configure(None, None);
    }

    /// A rejoin that kept more than the prover held before its kick loses
    /// nothing, an absent prover is not created, and the sum saturates.
    #[test]
    fn the_restoration_never_lowers_seniority_nor_creates_a_prover() {
        let state = make_state();
        let ahead = seed(&state, 0xC1, 1_000);
        let near_max = seed(&state, 0xC2, u64::MAX - 5);
        let absent = [0xC3; 32];
        configure(
            Some(40),
            Some(vec![
                SeniorityRestoration {
                    prover: ahead,
                    before_kick: 100,
                    at_rejoin: 400,
                },
                SeniorityRestoration {
                    prover: absent,
                    before_kick: 100,
                    at_rejoin: 0,
                },
                SeniorityRestoration {
                    prover: near_max,
                    before_kick: 100,
                    at_rejoin: 0,
                },
            ]),
        );
        assert_eq!(restore_kicked_seniority(&state, 40).unwrap(), 2);
        assert_eq!(
            seniority(&state, &ahead),
            1_000,
            "a restoration lowered seniority"
        );
        assert_eq!(restored_at(&state, &ahead), Some(40));
        assert_eq!(seniority(&state, &near_max), u64::MAX);
        assert!(
            vertex(&state, &absent).is_none(),
            "an absent prover was created"
        );
        configure(None, None);
    }
}
