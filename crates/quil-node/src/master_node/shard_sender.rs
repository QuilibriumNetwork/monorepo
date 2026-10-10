//! Recover authenticated shard sender identities without waiting for PeerInfo.
use std::collections::HashMap;

const MAX_KEYS: usize = quil_cw_consensus::handoff::MAX_MEMBERS;

#[derive(Default)]
pub(super) struct ShardSenderKeys {
    keys: HashMap<Vec<u8>, Vec<u8>>,
    pub peer_info: u64,
    pub session: u64,
    pub cached: u64,
    pub unresolved: u64,
}

impl ShardSenderKeys {
    /// `members` must come from an authenticated committed GLOBAL session.
    /// This resolves an immutable peer identity, not membership authorization;
    /// the worker still verifies the vote/certificate in its own session.
    pub fn resolve(
        &mut self,
        peer: &[u8],
        peer_info_key: Option<Vec<u8>>,
        members: impl FnOnce() -> Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        let bound = |key: &[u8]| {
            quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(key).is_some()
                && quil_p2p::peer_id_from_falcon_pubkey(key) == peer
        };
        if let Some(key) = peer_info_key.filter(|key| bound(key)) {
            self.peer_info += 1;
            return key;
        }
        if let Some(key) = self.keys.get(peer) {
            self.cached += 1;
            return key.clone();
        }
        if let Some(key) = members().and_then(|keys| keys.into_iter().find(|key| bound(key))) {
            // The mapping never changes for a given peer ID. Keep a bounded
            // positive cache across session transitions; unknown peers cannot
            // insert entries or cause evictions.
            if self.keys.len() == MAX_KEYS {
                if let Some(evicted) = self.keys.keys().next().cloned() {
                    self.keys.remove(&evicted);
                }
            }
            self.keys.insert(peer.to_vec(), key.clone());
            self.session += 1;
            return key;
        }
        self.unresolved += 1;
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer;

    #[test]
    fn empty_peer_info_resolves_only_the_authenticated_session_identity() {
        let signer = quil_crypto::FalconSigner::generate();
        let key = signer.public_key().to_vec();
        let peer = quil_p2p::peer_id_from_falcon_pubkey(&key);
        let mut cache = ShardSenderKeys::default();
        assert!(cache.resolve(&peer, None, || None).is_empty());
        assert_eq!(cache.resolve(&peer, None, || Some(vec![key.clone()])), key);
        assert_eq!(cache.resolve(&peer, None, || panic!("positive cache avoids another state read")), key);
        assert!(cache.resolve(&[0; 34], None, || Some(vec![key])).is_empty());
        assert_eq!((cache.session, cache.cached, cache.unresolved), (1, 1, 2));
    }

    #[test]
    fn mismatched_peer_info_and_malformed_session_keys_cannot_spoof_a_sender() {
        let signer = quil_crypto::FalconSigner::generate();
        let key = signer.public_key().to_vec();
        let peer = quil_p2p::peer_id_from_falcon_pubkey(&key);
        let mut cache = ShardSenderKeys::default();
        assert!(cache.resolve(&[0; 34], Some(key.clone()), || None).is_empty());
        assert!(cache.resolve(&peer, Some(vec![1]), || Some(vec![vec![1]])).is_empty());
        assert_eq!(cache.resolve(&peer, Some(key.clone()), || panic!("valid PeerInfo needs no fallback")), key);
        assert_eq!(cache.peer_info, 1);
        assert!(cache.keys.is_empty());
    }

    #[test]
    fn unknown_senders_cannot_grow_or_evict_the_bounded_identity_cache() {
        let signer = quil_crypto::FalconSigner::generate();
        let key = signer.public_key().to_vec();
        let peer = quil_p2p::peer_id_from_falcon_pubkey(&key);
        let mut cache = ShardSenderKeys::default();
        for i in 0..MAX_KEYS {
            cache.keys.insert(i.to_be_bytes().to_vec(), key.clone());
        }
        assert!(cache.resolve(&[0; 34], None, || Some(vec![key.clone()])).is_empty());
        assert_eq!(cache.keys.len(), MAX_KEYS);
        assert_eq!(cache.resolve(&peer, None, || Some(vec![key.clone()])), key);
        assert_eq!(cache.keys.len(), MAX_KEYS);
        assert!(cache.keys.contains_key(&peer));
    }
}
