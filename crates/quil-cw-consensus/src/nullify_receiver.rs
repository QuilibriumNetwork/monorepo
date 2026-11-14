//! Preserve a verified nullify's first attestation across Falcon re-signing.
//!
//! Simplex compares duplicate nullifies by signature bytes. A restarted Falcon
//! signer can produce another valid signature for the same epoch/view. Present
//! the first verified attestation for that subject instead of a false conflict.
//! Other votes and invalid input remain unchanged. This bounded, session-local
//! cache does not recover attestations from a prior receiver or engine journal.
use crate::{adapters::Digest, falcon_base::FalconPublicKey, falcon_simplex::SimplexFalconScheme};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    simplex::types::{Attributable, Nullify, Vote},
    Epochable, Viewable,
};
use commonware_cryptography::certificate::Scheme as _;
use commonware_p2p::{Message, Receiver};
use commonware_utils::ordered::Quorum as _;
use std::collections::BTreeMap;

const MAX_NULLIFIES: usize = 4096;

#[derive(Debug)]
pub(crate) struct NullifyReceiver<R> {
    receiver: R,
    scheme: SimplexFalconScheme,
    epoch: u64,
    verified: BTreeMap<(u64, u32), Nullify<SimplexFalconScheme>>,
}

impl<R> NullifyReceiver<R> {
    pub(crate) fn new(receiver: R, scheme: SimplexFalconScheme, epoch: u64) -> Self {
        Self {
            receiver,
            scheme,
            epoch,
            verified: BTreeMap::new(),
        }
    }

    fn normalize(&mut self, message: &mut Message<FalconPublicKey>) {
        let Ok(Vote::Nullify(vote)) =
            Vote::<SimplexFalconScheme, Digest>::decode(message.1.as_ref())
        else {
            return;
        };
        if vote.epoch().get() != self.epoch
            || self.scheme.participants().index(&message.0) != Some(vote.signer())
        {
            return;
        }
        let key = (vote.view().get(), usize::from(vote.signer()) as u32);
        if let Some(previous) = self.verified.get(&key) {
            if previous != &vote && self.scheme.verify_nullify(&vote) {
                message.1 = Vote::<_, Digest>::Nullify(previous.clone())
                    .encode()
                    .to_vec()
                    .into();
            }
            return;
        }
        if self.scheme.verify_nullify(&vote) {
            self.verified.insert(key, vote);
            while self.verified.len() > MAX_NULLIFIES {
                self.verified.pop_first();
            }
        }
    }
}

impl<R: Receiver<PublicKey = FalconPublicKey>> Receiver for NullifyReceiver<R> {
    type Error = R::Error;
    type PublicKey = FalconPublicKey;

    async fn recv(&mut self) -> Result<Message<FalconPublicKey>, Self::Error> {
        let mut message = self.receiver.recv().await?;
        self.normalize(&mut message);
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        falcon_base::FalconPrivateKey,
        p2p_bridge::{build_channel, inbound_message},
    };
    use commonware_consensus::simplex::types::{Finalize, Notarize, Proposal};
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::Signer as _;
    use commonware_utils::ordered::Set;
    use quil_types::crypto::Signer as _;
    use std::sync::Arc;

    fn signers() -> (SimplexFalconScheme, SimplexFalconScheme, FalconPublicKey) {
        let key = quil_crypto::FalconSigner::generate();
        let first = FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap();
        let restarted = FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap();
        let peer = first.public_key();
        let participants: Set<_> = vec![peer.clone()].try_into().unwrap();
        (
            SimplexFalconScheme::signer(b"test", participants.clone(), first).unwrap(),
            SimplexFalconScheme::signer(b"test", participants, restarted).unwrap(),
            peer,
        )
    }

    #[tokio::test]
    async fn real_receiver_canonicalizes_valid_restarted_signer_only() {
        let (first, restarted, peer) = signers();
        let round = Round::new(Epoch::new(3), View::new(1));
        let a = Nullify::sign::<Digest>(&first, round).unwrap();
        let b = Nullify::sign::<Digest>(&restarted, round).unwrap();
        assert_ne!(a, b);
        assert!(first.verify_nullify(&a) && first.verify_nullify(&b));
        let original = Vote::<_, Digest>::Nullify(a).encode().to_vec();
        let variant = Vote::<_, Digest>::Nullify(b).encode().to_vec();
        let (out, _) = tokio::sync::mpsc::unbounded_channel();
        let raw = build_channel(0, Arc::from(vec![peer.clone()]), out.clone());
        let fixed = build_channel(0, Arc::from(vec![peer.clone()]), out);
        let mut baseline = raw.receiver;
        let mut receiver = NullifyReceiver::new(fixed.receiver, first.clone(), 3);
        for bytes in [&original, &variant] {
            raw.inbound_tx
                .send(inbound_message(peer.clone(), bytes.clone()))
                .unwrap();
            fixed
                .inbound_tx
                .send(inbound_message(peer.clone(), bytes.clone()))
                .unwrap();
            assert_eq!(baseline.recv().await.unwrap().1.as_ref(), bytes.as_slice());
            assert_eq!(
                receiver.recv().await.unwrap().1.as_ref(),
                original.as_slice()
            );
        }
        let mut invalid =
            Nullify::sign::<Digest>(&restarted, Round::new(Epoch::new(3), View::new(2))).unwrap();
        invalid.round = round;
        assert!(!first.verify_nullify(&invalid));
        let wrong_epoch =
            Nullify::sign::<Digest>(&first, Round::new(Epoch::new(2), View::new(1))).unwrap();
        for bytes in [
            Vote::<_, Digest>::Nullify(invalid).encode().to_vec(),
            Vote::<_, Digest>::Nullify(wrong_epoch).encode().to_vec(),
            vec![255],
        ] {
            fixed
                .inbound_tx
                .send(inbound_message(peer.clone(), bytes.clone()))
                .unwrap();
            assert_eq!(receiver.recv().await.unwrap().1.as_ref(), bytes.as_slice());
        }
        assert_eq!(receiver.verified.len(), 1);
        let other = signers().2;
        fixed
            .inbound_tx
            .send(inbound_message(other.clone(), variant.clone()))
            .unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.0, other);
        assert_eq!(received.1.as_ref(), variant.as_slice());

        // Genuine proposal conflicts and finalize/nullify incompatibility must
        // remain visible to Simplex rather than being canonicalized away.
        for payload in [[1; 32], [2; 32]] {
            let proposal = Proposal::new(round, View::new(0), payload.into());
            for vote in [
                Vote::Notarize(Notarize::sign(&first, proposal.clone()).unwrap()),
                Vote::Finalize(Finalize::sign(&first, proposal).unwrap()),
            ] {
                let bytes = Vote::<_, Digest>::encode(&vote).to_vec();
                fixed
                    .inbound_tx
                    .send(inbound_message(peer.clone(), bytes.clone()))
                    .unwrap();
                assert_eq!(receiver.recv().await.unwrap().1.as_ref(), bytes.as_slice());
            }
        }
    }

    #[test]
    fn invalid_first_vote_cannot_poison_verified_cache() {
        let (scheme, restarted, peer) = signers();
        let round = Round::new(Epoch::new(3), View::new(1));
        let mut invalid =
            Nullify::sign::<Digest>(&scheme, Round::new(Epoch::new(3), View::new(2))).unwrap();
        invalid.round = round;
        let invalid = Vote::<_, Digest>::Nullify(invalid).encode().to_vec();
        let mut receiver = NullifyReceiver::new((), scheme, 3);
        let mut message = inbound_message(peer.clone(), invalid.clone());
        receiver.normalize(&mut message);
        assert_eq!(message.1.as_ref(), invalid.as_slice());
        assert!(receiver.verified.is_empty());
        let valid = Vote::<_, Digest>::Nullify(Nullify::sign::<Digest>(&restarted, round).unwrap())
            .encode()
            .to_vec();
        let mut message = inbound_message(peer, valid.clone());
        receiver.normalize(&mut message);
        assert_eq!(message.1.as_ref(), valid.as_slice());
        assert_eq!(receiver.verified.len(), 1);
    }
}
