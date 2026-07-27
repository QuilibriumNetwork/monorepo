//! Assemble the global-consensus committee for commonware simplex from Falcon
//! `q-consensus-key` material.
//!
//! Every node builds the SAME ordered committee (`commonware_utils::ordered::Set`
//! sorts deterministically), and produces its own `SimplexFalconScheme` signer
//! from its consensus private key. The result feeds `activate_global_consensus_cw`.

use std::sync::Arc;

use commonware_utils::ordered::Set;

use crate::falcon_base::{FalconPrivateKey, FalconPublicKey};
use crate::falcon_simplex::SimplexFalconScheme;

/// The assembled committee: the ordered peer list (for the p2p sender) and this
/// node's signing scheme (its identity + the committee participant set).
pub struct GlobalCommittee {
    pub peers: Arc<[FalconPublicKey]>,
    pub scheme: SimplexFalconScheme,
}

/// Build the committee from raw Falcon material.
///
/// - `committee_pubkeys`: every member's 897-byte `q-consensus-key` public key
///   (including this node's).
/// - `my_signing_key` / `my_public_key`: this node's `q-consensus-key` bytes.
/// - `namespace`: the consensus domain (`b"global"`).
///
/// Returns `None` if any key is malformed, the set is empty, or this node's key
/// is not in the committee.
pub fn build_global_committee(
    committee_pubkeys: &[Vec<u8>],
    my_signing_key: &[u8],
    my_public_key: &[u8],
    namespace: &[u8],
) -> Option<GlobalCommittee> {
    let pks: Vec<FalconPublicKey> = committee_pubkeys
        .iter()
        .map(|b| FalconPublicKey::from_bytes(b))
        .collect::<Option<_>>()?;
    if pks.is_empty() {
        return None;
    }
    let set: Set<FalconPublicKey> = pks.clone().try_into().ok()?;

    let private_key = FalconPrivateKey::from_bytes(my_signing_key, my_public_key)?;
    // `signer` returns None if our key isn't in the participant set.
    let scheme = SimplexFalconScheme::signer(namespace, set, private_key)?;

    Some(GlobalCommittee {
        peers: Arc::from(pks),
        scheme,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;

    #[test]
    fn builds_committee_and_scheme() {
        // We are one of 4 members.
        let me = quil_crypto::FalconSigner::generate();
        let my_signing = me.private_key().to_vec();
        let my_public = me.public_key().to_vec();
        let others: Vec<quil_crypto::FalconSigner> =
            (0..3).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut committee: Vec<Vec<u8>> =
            others.iter().map(|s| s.public_key().to_vec()).collect();
        committee.push(my_public.clone());

        let c = build_global_committee(&committee, &my_signing, &my_public, b"global")
            .expect("committee builds");
        assert_eq!(c.peers.len(), 4);

        // A node whose key is NOT in the committee cannot build a signer.
        let outsider = quil_crypto::FalconSigner::generate();
        assert!(build_global_committee(
            &committee,
            outsider.private_key(),
            outsider.public_key(),
            b"global",
        )
        .is_none());

        // Malformed pubkey → None.
        assert!(
            build_global_committee(&[vec![0u8; 10]], &my_signing, &my_public, b"global").is_none()
        );
    }
}
