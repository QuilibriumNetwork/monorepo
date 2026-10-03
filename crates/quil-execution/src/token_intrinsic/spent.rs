//! Spent-image index. These checks do not verify a spend proof.
//! Admission must serialize its checks and writes, and stage these markers
//! with outputs/root publication in the same rollback-capable changeset.
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{transfer::parameter_context, MAX_PRIVATE_COINS};
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

/// Context and suite separation prevent unrelated image encodings from sharing
/// marker addresses. The application also scopes the underlying vertex store.
pub fn marker_address(
    network: &[u8; 32],
    application: &[u8; 32],
    image: &[u8; IDENTITY_BYTES],
) -> Result<[u8; 32]> {
    let mut bytes = Vec::from(b"quil/coin/spent-image/v4\0".as_slice());
    bytes.extend_from_slice(&parameter_context(network, application));
    bytes.extend_from_slice(image);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

pub fn is_unspent(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    image: &[u8; IDENTITY_BYTES],
) -> Result<bool> {
    let address = marker_address(network, application, image)?;
    Ok(state
        .get(application, &address, &vertex_adds_discriminator()?)?
        .is_none())
}

/// Validate the whole image set before returning any marker writes. Any existing
/// vertex occupies the marker address; malformed marker data cannot make a
/// previously occupied address spendable. The caller must recheck if it releases
/// admission serialization before applying these prepared writes.
pub(crate) fn prepare_markers(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    images: &[[u8; IDENTITY_BYTES]],
) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    if images.is_empty()
        || images.len() > MAX_PRIVATE_COINS
        || images.iter().collect::<BTreeSet<_>>().len() != images.len()
    {
        return Err(QuilError::InvalidArgument(
            "spend: invalid image set".into(),
        ));
    }
    let disc = vertex_adds_discriminator()?;
    let mut addresses = BTreeSet::new();
    for image in images {
        let address = marker_address(network, application, image)?;
        if !addresses.insert(address) || state.get(application, &address, &disc)?.is_some() {
            return Err(QuilError::InvalidArgument(
                "spend: image already spent or address occupied".into(),
            ));
        }
    }
    let tree = super::materialize::create_spent_marker_tree()?;
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|e| QuilError::Internal(format!("spend: marker encoding: {e}")))?;
    Ok(addresses
        .into_iter()
        .map(|address| (address, blob.clone()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;
    use std::sync::Arc;
    fn state() -> HypergraphState {
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )))
    }
    #[test]
    fn marker_addresses_are_suite_and_context_bound() {
        let address = marker_address(&[1; 32], &[2; 32], &[3; IDENTITY_BYTES]).unwrap();
        assert_ne!(
            address,
            marker_address(&[2; 32], &[2; 32], &[3; IDENTITY_BYTES]).unwrap()
        );
        assert_ne!(
            address,
            marker_address(&[1; 32], &[1; 32], &[3; IDENTITY_BYTES]).unwrap()
        );
        assert_ne!(
            address,
            marker_address(&[1; 32], &[2; 32], &[4; IDENTITY_BYTES]).unwrap()
        );
        assert_ne!(
            address,
            super::super::spent_check::key_image_spent_address(&[3; IDENTITY_BYTES]).unwrap()
        );
    }
    #[test]
    fn database_read_errors_do_not_report_images_as_unspent() {
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let network = [1; 32];
        let application = [2; 32];
        let image = [3; IDENTITY_BYTES];
        assert!(is_unspent(&state, &network, &application, &image).unwrap());
        for phase in ["adds", "removes"] {
            store.fail_vertex_reads(Some(phase));
            assert!(is_unspent(&state, &network, &application, &image).is_err());
            assert!(prepare_markers(&state, &network, &application, &[image]).is_err());
            assert_eq!(state.changeset_len(), 0);
        }
        store.fail_vertex_reads(None);
        let markers = prepare_markers(&state, &network, &application, &[image]).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        for (address, value) in markers {
            state.set(&application, &address, &disc, 1, value).unwrap();
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        assert!(!is_unspent(&state, &network, &application, &image).unwrap());
        for phase in ["adds", "removes"] {
            store.fail_vertex_reads(Some(phase));
            assert!(is_unspent(&state, &network, &application, &image).is_err());
            assert!(prepare_markers(&state, &network, &application, &[image]).is_err());
        }
        store.fail_vertex_reads(None);
        assert!(!is_unspent(&state, &network, &application, &image).unwrap());
    }

    #[test]
    fn image_checks_cover_pending_live_committed_and_rollback_state() {
        let state = state();
        let network = [1; 32];
        let application = [2; 32];
        let disc = vertex_adds_discriminator().unwrap();
        let images = [[3; IDENTITY_BYTES], [4; IDENTITY_BYTES]];
        for bad in [
            vec![],
            vec![images[0], images[0]],
            vec![[5; IDENTITY_BYTES]; MAX_PRIVATE_COINS + 1],
        ] {
            assert!(prepare_markers(&state, &network, &application, &bad).is_err());
            assert_eq!(state.changeset_len(), 0);
        }
        let prepared = prepare_markers(&state, &network, &application, &images).unwrap();
        assert_eq!(state.changeset_len(), 0, "preparation must not write state");
        for (address, blob) in &prepared {
            state
                .set(&application, address, &disc, 1, blob.clone())
                .unwrap();
        }
        for image in &images {
            assert!(!is_unspent(&state, &network, &application, image).unwrap());
        }
        assert!(prepare_markers(&state, &network, &application, &images).is_err());
        state.rollback_to(0);
        for image in &images {
            assert!(is_unspent(&state, &network, &application, image).unwrap());
        }
        for (address, blob) in &prepared {
            state
                .set(&application, address, &disc, 1, blob.clone())
                .unwrap();
        }
        state.commit().unwrap();
        state.abort();
        assert!(prepare_markers(&state, &network, &application, &images).is_err());
        state.crdt().commit(1).unwrap();
        assert!(prepare_markers(&state, &network, &application, &images).is_err());
        assert!(is_unspent(&state, &[9; 32], &application, &images[0]).unwrap());
        // Marker vertices are ignored by coin snapshot and root construction.
        let limits = super::super::state::SnapshotLimits {
            max_coins: 0,
            max_depth: 1,
            max_nodes: 4,
        };
        let root =
            super::super::roots::refresh_root(&state, &network, &application, limits)
                .unwrap();
        assert_eq!(root.coins, 0);
        let occupied = marker_address(&network, &application, &[8; IDENTITY_BYTES]).unwrap();
        state
            .set(&application, &occupied, &disc, 1, vec![255])
            .unwrap();
        assert!(prepare_markers(&state, &network, &application, &[[8; IDENTITY_BYTES]]).is_err());
    }
}
