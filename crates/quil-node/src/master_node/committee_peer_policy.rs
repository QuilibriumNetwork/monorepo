//! IP-colocation exemptions come from committed session heads for shards this
//! node serves. Self-reported PeerInfo and transport subscriptions cannot grant
//! an exemption; all other peer-score terms remain active.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use quil_cw_consensus::handoff::Session;
use quil_p2p::PeerId;
use quil_types::error::{QuilError, Result};

pub(super) struct RefreshGuard(pub Arc<AtomicBool>);
impl Drop for RefreshGuard {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

pub(super) fn collect(
    filters: &BTreeSet<Vec<u8>>,
    head: impl Fn(&[u8]) -> Result<Option<Session>>,
) -> Result<HashSet<PeerId>> {
    if filters.len() > 4096 {
        return Err(QuilError::P2p("committee peer policy exceeds its shard bounds".into()));
    }
    let mut peers = HashSet::new();
    for filter in filters {
        let Some(session) = head(filter)? else { continue; };
        if session.filter != *filter {
            return Err(QuilError::P2p("committee peer policy session filter mismatch".into()));
        }
        session.validate()?;
        for key in &session.members {
            let id = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(key))
                .map_err(|_| QuilError::P2p("invalid committee network identity".into()))?;
            peers.insert(id);
            if peers.len() > 16_384 {
                return Err(QuilError::P2p("committee peer policy exceeds its peer bounds".into()));
            }
        }
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer;

    fn session(filter: Vec<u8>, signer: &quil_crypto::FalconSigner) -> Session {
        Session { chain_id: [0;32], filter, generation: 1, genesis: [0;32],
            base_frame: 0, authorization: [0;32], members: vec![signer.public_key().to_vec()] }
    }

    #[test]
    fn selection_tracks_served_committed_heads_and_removes_departed_members() {
        let a = quil_crypto::FalconSigner::generate();
        let b = quil_crypto::FalconSigner::generate();
        let fa = vec![1;32]; let fb = vec![2;32];
        let sa = session(fa.clone(), &a); let sb = session(fb.clone(), &b);
        let pa = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(a.public_key())).unwrap();
        let pb = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(b.public_key())).unwrap();
        let lookup = |filter: &[u8]| Ok(if filter == fa {Some(sa.clone())} else {Some(sb.clone())});
        assert_eq!(collect(&[fa.clone(),fb].into_iter().collect(), lookup).unwrap(), [pa,pb].into_iter().collect());
        assert_eq!(collect(&[fa.clone()].into_iter().collect(), lookup).unwrap(), [pa].into_iter().collect());
        assert!(collect(&[fa].into_iter().collect(), |_| Ok(None)).unwrap().is_empty());
        assert!(collect(&BTreeSet::new(), |_| panic!("no unserved head lookup")).unwrap().is_empty());
    }

    #[test]
    fn corrupt_or_unavailable_head_cannot_grant_an_exemption() {
        let a = quil_crypto::FalconSigner::generate();
        let filter = vec![1;32]; let filters = [filter.clone()].into_iter().collect();
        let wrong = session(vec![2;32], &a);
        assert!(collect(&filters, |_| Ok(Some(wrong.clone()))).is_err());
        let mut invalid = session(filter, &a); invalid.members = vec![vec![1]];
        assert!(collect(&filters, |_| Ok(Some(invalid.clone()))).is_err());
        assert!(collect(&filters, |_| Err(QuilError::Store("read failure".into()))).is_err());
    }
}
