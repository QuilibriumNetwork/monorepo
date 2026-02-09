//! Protocols for refreshing key shares when wanted/needed.
//!
//! This file implements a refresh protocol: periodically, all parties
//! engage in a protocol to re-randomize their secret values (while, of
//! course, still maintaining the same public key).
//!
//! The most direct way of doing this is simply executing DKG and restricting
//! the possible random values so that we don't change our address. We
//! implement this procedure under the name of "complete refresh".
//!
//! DKG also initializes the multiplication protocol, but we may take
//! advantage of the fact the we have already initialized this protocol
//! before. If we use this data for refresh, we don't need to execute
//! the OT protocols and we may save some time and some rounds. This
//! approach is implemented in another refresh protocol.
//!
//! ATTENTION: The protocols here work for any instance of Party, including
//! for derived addresses. However, refreshing a derivation is not such a
//! good idea because the refreshed derivation becomes essentially independent
//! of the master node. We recommend that only master nodes are refreshed
//! and derivations are calculated as needed afterwards.
//!
//! # Complete refresh
//!
//! In this case, we recompute all data from the parties. Hence, we essentially
//! rerun DKG but we force the final public key to be the original one.
//!
//! To adapt the DKG protocol, we change [Step 1](super::dkg::step1): instead of sampling any random
//! polynomial, each party generates a polynomial whose constant term is zero.
//! In this way, the key generation provides each party with a point on a polynomial
//! whose constant term (the "secret key") is zero. This new point is just a correction
//! factor and must be added to the original `poly_point` variable. This refreshes each
//! key share while preserving the same public key.
//!
//! Each party cannot trust that their adversaries really chose a polynomial
//! with zero constant term. Therefore, we must add a new consistency check in
//! [Phase 4](super::dkg::phase4): after recovering the auxiliary public key, each party must check that
//! it is equal to the zero point on the curve. This ensures that the correction
//! factors will not change the public key.
//!
//! # A faster refresh
//!
//! During a complete refresh, we initialize the multiplication protocol
//! from scratch. Instead, we can use our previous data to more efficiently
//! refresh this initialization. This results in a faster refresh and,
//! depending on the multiplication protocol, fewer communication rounds.
//!
//! We will base this implementation on the article "Refresh When You Wake Up:
//! Proactive Threshold Wallets with Offline Devices" (<https://eprint.iacr.org/2019/1328.pdf>)
//! More specifically, we use their ideas from Section 8 (and Appendix E).
//!
//! In their protocol, a common random string is sampled by each pair of
//! parties. They achieve this by using their "coin tossing functionality".
//! Note that their suggestion of implementation for this functionality is
//! very similar to the way our zero shares protocol computes its seeds.
//!
//! Hence, our new refresh protocol will work as follows: we run DKG
//! ignoring any procedure related to the multiplication protocol (and we
//! do the same modifications we did for the complete refresh). During
//! the fourth phase, the initialization for the zero shares protocol
//! generates its seeds. We reuse them to apply the Beaver trick (described
//! in the article) to refresh the OT instances used for multiplication.
//!
//! # Nomenclature
//!
//! For the messages structs, we will use the following nomenclature:
//!
//! **Transmit** messages refer to only one counterparty, hence
//! we must produce a whole vector of them. Each message in this
//! vector contains the party index to whom we should send it.
//!
//! **Broadcast** messages refer to all counterparties at once,
//! hence we only need to produce a unique instance of it.
//! This message is broadcasted to all parties.
//!
//! ATTENTION: we broadcast the message to ourselves as well!
//!
//! **Keep** messages refer to only one counterparty, hence
//! we must keep a whole vector of them. In this implementation,
//! we use a `BTreeMap` instead of a vector, where one can put
//! some party index in the key to retrieve the corresponding data.
//!
//! **Unique keep** messages refer to all counterparties at once,
//! hence we only need to keep a unique instance of it.

use std::collections::BTreeMap;

use elliptic_curve::bigint::U256;
use elliptic_curve::ops::Reduce;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::{Field, PrimeField};
use serde::{Deserialize, Serialize};

use crate::utilities::hashes::{hash, HashOutput};
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot;
use crate::utilities::rng;
use crate::utilities::zero_shares::{self, ZeroShare};
use crate::DklsCurve;

use crate::protocols::derivation::DerivData;
use crate::protocols::dkg::{
    step2, step3, step5, KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3,
    KeepInitZeroSharePhase3to4, ProofCommitment, TransmitInitMulPhase3to4,
    TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use crate::protocols::{Abort, PartiesMessage, Party};

// STRUCTS FOR MESSAGES TO TRANSMIT IN COMMUNICATION ROUNDS.

// "Transmit" messages refer to only one counterparty, hence
// we must send a whole vector of them.

/// Transmit - (Faster) Refresh.
///
/// The message is produced/sent during Phase 2 and used in Phase 4.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransmitRefreshPhase2to4 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
}

/// Transmit - (Faster) Refresh.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransmitRefreshPhase3to4 {
    pub parties: PartiesMessage,
    pub seed: zero_shares::Seed,
    pub salt: Vec<u8>,
}

// STRUCTS FOR MESSAGES TO KEEP BETWEEN PHASES.

/// Keep - (Faster) Refresh.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeepRefreshPhase2to3 {
    pub seed: zero_shares::Seed,
    pub salt: Vec<u8>,
}

/// Keep - (Faster) Refresh.
///
/// The message is produced during Phase 3 and used in Phase 4.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeepRefreshPhase3to4 {
    pub seed: zero_shares::Seed,
}

/// Implementations related to refresh protocols ([read more](self)).
impl<C: DklsCurve> Party<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: Default + elliptic_curve::group::GroupEncoding,
{
    // COMPLETE REFRESH

    /// Works as [Phase 1](super::dkg::phase1) in DKG, but with
    /// the alterations needed for the refresh protocol.
    ///
    /// The output should be dealt in the same way.
    #[must_use]
    pub fn refresh_complete_phase1(&self) -> Vec<C::Scalar> {
        // We run Phase 1 in DKG, but we force the constant term in Step 1 to be zero.

        // DKG
        let mut secret_polynomial: Vec<C::Scalar> =
            Vec::with_capacity(self.parameters.threshold as usize);
        secret_polynomial.push(C::Scalar::ZERO);
        for _ in 1..self.parameters.threshold {
            secret_polynomial.push(C::Scalar::random(rng::get_rng()));
        }

        step2::<C>(&self.parameters, &secret_polynomial)
    }

    /// Works as [Phase 2](super::dkg::phase2) in DKG, but the
    /// derivation part is omitted.
    ///
    /// The output should be dealt in the same way. The only
    /// difference is that we will refer to the scalar`poly_point`
    /// as `correction_value`.
    #[must_use]
    pub fn refresh_complete_phase2(
        &self,
        refresh_sid: &[u8],
        poly_fragments: &[C::Scalar],
    ) -> (
        C::Scalar,
        ProofCommitment<C>,
        BTreeMap<u8, KeepInitZeroSharePhase2to3>,
        Vec<TransmitInitZeroSharePhase2to4>,
    ) {
        // We run Phase 2 in DKG, but we omit the derivation part.
        // Note that "poly_point" is now called "correction_value".
        // It will be used to correct self.poly_point.

        // DKG
        let (correction_value, proof_commitment) =
            step3::<C>(self.party_index, refresh_sid, poly_fragments);

        // Initialization - Zero shares.

        // We will use BTreeMap to keep messages: the key indicates the party to whom the message refers.
        let mut zero_keep: BTreeMap<u8, KeepInitZeroSharePhase2to3> = BTreeMap::new();
        let mut zero_transmit: Vec<TransmitInitZeroSharePhase2to4> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for i in 1..=self.parameters.share_count {
            if i == self.party_index {
                continue;
            }

            // Generate initial seeds.
            let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

            // We first send the commitments. We keep the rest to send later.
            let keep = KeepInitZeroSharePhase2to3 { seed, salt };
            let transmit = TransmitInitZeroSharePhase2to4 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: i,
                },
                commitment,
            };

            zero_keep.insert(i, keep);
            zero_transmit.push(transmit);
        }

        (correction_value, proof_commitment, zero_keep, zero_transmit)
    }

    /// Works as [Phase 3](super::dkg::phase3) in DKG, but the
    /// derivation part is omitted.
    ///
    /// The output should be dealt in the same way.
    #[must_use]
    pub fn refresh_complete_phase3(
        &self,
        refresh_sid: &[u8],
        zero_kept: &BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    ) -> (
        BTreeMap<u8, KeepInitZeroSharePhase3to4>,
        Vec<TransmitInitZeroSharePhase3to4>,
        BTreeMap<u8, KeepInitMulPhase3to4<C>>,
        Vec<TransmitInitMulPhase3to4<C>>,
    ) {
        // We run Phase 3 in DKG, but we omit the derivation part.

        // Initialization - Zero shares.
        let mut zero_keep: BTreeMap<u8, KeepInitZeroSharePhase3to4> = BTreeMap::new();
        let mut zero_transmit: Vec<TransmitInitZeroSharePhase3to4> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for (target_party, message_kept) in zero_kept {
            // The messages kept contain the seed and the salt.
            // They have to be transmitted to the target party.
            // We keep the seed with us for the next phase.
            let keep = KeepInitZeroSharePhase3to4 {
                seed: message_kept.seed,
            };
            let transmit = TransmitInitZeroSharePhase3to4 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: *target_party,
                },
                seed: message_kept.seed,
                salt: message_kept.salt.clone(),
            };

            zero_keep.insert(*target_party, keep);
            zero_transmit.push(transmit);
        }

        // Initialization - Two-party multiplication.
        // Each party prepares initialization both as
        // a receiver and as a sender.
        let mut mul_keep: BTreeMap<u8, KeepInitMulPhase3to4<C>> = BTreeMap::new();
        let mut mul_transmit: Vec<TransmitInitMulPhase3to4<C>> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for i in 1..=self.parameters.share_count {
            if i == self.party_index {
                continue;
            }

            // RECEIVER
            // We are the receiver and i = sender.

            // We first compute a new session id.
            // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
            let mul_sid_receiver = [
                "Multiplication protocol".as_bytes(),
                &self.party_index.to_be_bytes(),
                &i.to_be_bytes(),
                refresh_sid,
            ]
            .concat();

            let (ot_sender, dlog_proof, nonce) = MulReceiver::<C>::init_phase1(&mul_sid_receiver);

            // SENDER
            // We are the sender and i = receiver.

            // New session id as above.
            // Note that the indexes are now in the opposite order.
            let mul_sid_sender = [
                "Multiplication protocol".as_bytes(),
                &i.to_be_bytes(),
                &self.party_index.to_be_bytes(),
                refresh_sid,
            ]
            .concat();

            let (ot_receiver, correlation, vec_r, enc_proofs) =
                MulSender::<C>::init_phase1(&mul_sid_sender);

            // We gather these values.

            let transmit = TransmitInitMulPhase3to4 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: i,
                },

                // Us = Receiver
                dlog_proof,
                nonce,

                // Us = Sender
                enc_proofs,
                seed: ot_receiver.seed,
            };
            let keep = KeepInitMulPhase3to4 {
                // Us = Receiver
                ot_sender,
                nonce,

                // Us = Sender
                ot_receiver,
                correlation,
                vec_r,
            };

            mul_keep.insert(i, keep);
            mul_transmit.push(transmit);
        }

        (zero_keep, zero_transmit, mul_keep, mul_transmit)
    }

    /// Works as [Phase 4](super::dkg::phase4) in DKG, but the
    /// derivation part is omitted. Moreover, the variable
    /// `poly_point` is now called `correction_value`.
    ///
    /// The output is a new instance of [`Party`] which is the
    /// previous one refreshed.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the verifying public key is not trivial,
    /// if a message is not meant for the party, if the zero shares
    /// protocol fails when verifying the seeds or if the multiplication
    /// protocol fails.
    pub fn refresh_complete_phase4(
        &self,
        refresh_sid: &[u8],
        correction_value: &C::Scalar,
        proofs_commitments: &[ProofCommitment<C>],
        zero_kept: &BTreeMap<u8, KeepInitZeroSharePhase3to4>,
        zero_received_phase2: &[TransmitInitZeroSharePhase2to4],
        zero_received_phase3: &[TransmitInitZeroSharePhase3to4],
        mul_kept: &BTreeMap<u8, KeepInitMulPhase3to4<C>>,
        mul_received: &[TransmitInitMulPhase3to4<C>],
    ) -> Result<Party<C>, Abort> {
        // We run Phase 4, but now we don't check if the resulting public key is zero.
        // Actually, we have to do the opposite: it must be the zero point!
        // After this, we use the values computed to update our values.
        // Again, the derivation part is omitted.

        // DKG
        let verifying_pk = step5::<C>(
            &self.parameters,
            self.party_index,
            refresh_sid,
            proofs_commitments,
        )?;

        // The public key calculated above should be the zero point on the curve.
        if verifying_pk != crate::identity::<C>() {
            return Err(Abort::new(
                self.party_index,
                "The auxiliary public key is not the zero point!",
            ));
        }

        // Initialization - Zero shares.
        let mut seeds: Vec<zero_shares::SeedPair> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for (target_party, message_kept) in zero_kept {
            for message_received_2 in zero_received_phase2 {
                for message_received_3 in zero_received_phase3 {
                    let my_index = message_received_2.parties.receiver;
                    let their_index = message_received_2.parties.sender;

                    // Confirm that the message is for us.
                    if my_index != self.party_index {
                        return Err(Abort::new(
                            self.party_index,
                            "Received a message not meant for me!",
                        ));
                    }

                    // We first check if the messages relate to the same party.
                    if *target_party != their_index
                        || message_received_3.parties.sender != their_index
                    {
                        continue;
                    }

                    // We verify the commitment.
                    let verification = ZeroShare::verify_seed(
                        &message_received_3.seed,
                        &message_received_2.commitment,
                        &message_received_3.salt,
                    );
                    if !verification {
                        return Err(Abort::new(self.party_index, &format!("Initialization for zero shares protocol failed because Party {their_index} cheated when sending the seed!")));
                    }

                    // We form the final seed pairs.
                    seeds.push(ZeroShare::generate_seed_pair(
                        my_index,
                        their_index,
                        &message_kept.seed,
                        &message_received_3.seed,
                    ));
                }
            }
        }

        // This finishes the initialization.
        let zero_share = ZeroShare::initialize(seeds);

        // Initialization - Two-party multiplication.
        let mut mul_receivers: BTreeMap<u8, MulReceiver<C>> = BTreeMap::new();
        let mut mul_senders: BTreeMap<u8, MulSender<C>> = BTreeMap::new();
        for (target_party, message_kept) in mul_kept {
            for message_received in mul_received {
                let my_index = message_received.parties.receiver;
                let their_index = message_received.parties.sender;

                // Confirm that the message is for us.
                if my_index != self.party_index {
                    return Err(Abort::new(
                        self.party_index,
                        "Received a message not meant for me!",
                    ));
                }

                // We first check if the messages relate to the same party.
                if their_index != *target_party {
                    continue;
                }

                // RECEIVER
                // We are the receiver and target_party = sender.

                // We retrieve the id used for multiplication. Note that the first party
                // is the receiver and the second, the sender.
                let mul_sid_receiver = [
                    "Multiplication protocol".as_bytes(),
                    &my_index.to_be_bytes(),
                    &their_index.to_be_bytes(),
                    refresh_sid,
                ]
                .concat();

                let receiver_result = MulReceiver::<C>::init_phase2(
                    &message_kept.ot_sender,
                    &mul_sid_receiver,
                    &message_received.seed,
                    &message_received.enc_proofs,
                    &message_kept.nonce,
                );

                let mul_receiver: MulReceiver<C> = match receiver_result {
                    Ok(r) => r,
                    Err(error) => {
                        return Err(Abort::new(self.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
                    }
                };

                // SENDER
                // We are the sender and target_party = receiver.

                // We retrieve the id used for multiplication. Note that the first party
                // is the receiver and the second, the sender.
                let mul_sid_sender = [
                    "Multiplication protocol".as_bytes(),
                    &their_index.to_be_bytes(),
                    &my_index.to_be_bytes(),
                    refresh_sid,
                ]
                .concat();

                let sender_result = MulSender::<C>::init_phase2(
                    &message_kept.ot_receiver,
                    &mul_sid_sender,
                    message_kept.correlation.clone(),
                    &message_kept.vec_r,
                    &message_received.dlog_proof,
                    &message_received.nonce,
                );

                let mul_sender: MulSender<C> = match sender_result {
                    Ok(s) => s,
                    Err(error) => {
                        return Err(Abort::new(self.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
                    }
                };

                // We finish the initialization.
                mul_receivers.insert(their_index, mul_receiver);
                mul_senders.insert(their_index, mul_sender.clone());
            }
        }

        // For key derivation, we just update poly_point.
        let derivation_data = DerivData {
            depth: self.derivation_data.depth,
            child_number: self.derivation_data.child_number,
            parent_fingerprint: self.derivation_data.parent_fingerprint,
            poly_point: self.poly_point + correction_value, // We update poly_point.
            pk: self.pk,
            chain_code: self.derivation_data.chain_code,
        };

        let party = Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(), // We replace the old session id by the new one.

            poly_point: self.poly_point + correction_value, // We update poly_point.
            pk: self.pk,

            zero_share,

            mul_senders,
            mul_receivers,

            derivation_data,

            eth_address: self.eth_address.clone(),
        };

        Ok(party)
    }

    // A FASTER REFRESH

    /// Works as [Phase 1](super::dkg::phase1) in DKG, but with
    /// the alterations needed for the refresh protocol.
    ///
    /// The output should be dealt in the same way.
    #[must_use]
    pub fn refresh_phase1(&self) -> Vec<C::Scalar> {
        // We run Phase 1 in DKG, but we force the constant term in Step 1 to be zero.

        // DKG
        let mut secret_polynomial: Vec<C::Scalar> =
            Vec::with_capacity(self.parameters.threshold as usize);
        secret_polynomial.push(C::Scalar::ZERO);
        for _ in 1..self.parameters.threshold {
            secret_polynomial.push(C::Scalar::random(rng::get_rng()));
        }

        step2::<C>(&self.parameters, &secret_polynomial)
    }

    /// Works as [Phase 2](super::dkg::phase2) in DKG, but the
    /// derivation part is omitted.
    ///
    /// The output should be dealt in the same way. The only
    /// difference is that we will refer to the scalar`poly_point`
    /// as `correction_value`.
    #[must_use]
    pub fn refresh_phase2(
        &self,
        refresh_sid: &[u8],
        poly_fragments: &[C::Scalar],
    ) -> (
        C::Scalar,
        ProofCommitment<C>,
        BTreeMap<u8, KeepRefreshPhase2to3>,
        Vec<TransmitRefreshPhase2to4>,
    ) {
        // We run Phase 2 in DKG, but we omit the derivation part.
        // Note that "poly_point" is now called "correction_value".
        // It will be used to correct self.poly_point.

        // DKG
        let (correction_value, proof_commitment) =
            step3::<C>(self.party_index, refresh_sid, poly_fragments);

        // Initialization - Zero shares.

        // We will use BTreeMap to keep messages: the key indicates the party to whom the message refers.
        let mut keep: BTreeMap<u8, KeepRefreshPhase2to3> = BTreeMap::new();
        let mut transmit: Vec<TransmitRefreshPhase2to4> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for i in 1..=self.parameters.share_count {
            if i == self.party_index {
                continue;
            }

            // Generate initial seeds.
            let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

            // We first send the commitments. We keep the rest to send later.
            keep.insert(i, KeepRefreshPhase2to3 { seed, salt });
            transmit.push(TransmitRefreshPhase2to4 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: i,
                },
                commitment,
            });
        }

        (correction_value, proof_commitment, keep, transmit)
    }

    /// Works as [Phase 3](super::dkg::phase3) in DKG, but the
    /// multiplication and derivation parts are omitted.
    ///
    /// The output should be dealt in the same way.
    #[must_use]
    pub fn refresh_phase3(
        &self,
        kept: &BTreeMap<u8, KeepRefreshPhase2to3>,
    ) -> (
        BTreeMap<u8, KeepRefreshPhase3to4>,
        Vec<TransmitRefreshPhase3to4>,
    ) {
        // We run Phase 3 in DKG, but we omit the multiplication and the derivation parts.

        // Initialization - Zero shares.
        let mut keep: BTreeMap<u8, KeepRefreshPhase3to4> = BTreeMap::new();
        let mut transmit: Vec<TransmitRefreshPhase3to4> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for (target_party, message_kept) in kept {
            // The messages kept contain the seed and the salt.
            // They have to be transmitted to the target party.
            // We keep the seed with us for the next phase.
            keep.insert(
                *target_party,
                KeepRefreshPhase3to4 {
                    seed: message_kept.seed,
                },
            );
            transmit.push(TransmitRefreshPhase3to4 {
                parties: PartiesMessage {
                    sender: self.party_index,
                    receiver: *target_party,
                },
                seed: message_kept.seed,
                salt: message_kept.salt.clone(),
            });
        }

        (keep, transmit)
    }

    /// Works as [Phase 4](super::dkg::phase4) in DKG, but the
    /// multiplication and derivation parts are omitted. Moreover,
    /// the variable `poly_point` is now called `correction_value`.
    ///
    /// The output is a new instance of [`Party`] which is the
    /// previous one refreshed.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the verifying public key is not trivial,
    /// if a message is not meant for the party or if the zero shares
    /// protocol fails when verifying the seeds.
    ///
    /// # Panics
    ///
    /// Will panic if the indices of the parties are different
    /// from the ones used in DKG.
    pub fn refresh_phase4(
        &self,
        refresh_sid: &[u8],
        correction_value: &C::Scalar,
        proofs_commitments: &[ProofCommitment<C>],
        kept: &BTreeMap<u8, KeepRefreshPhase3to4>,
        received_phase2: &[TransmitRefreshPhase2to4],
        received_phase3: &[TransmitRefreshPhase3to4],
    ) -> Result<Party<C>, Abort> {
        // We run Phase 4, but now we don't check if the resulting public key is zero.
        // Actually, we have to do the opposite: it must be the zero point!
        // After this, we use the values computed to update our values.
        // Again, the derivation part is omitted.

        // DKG
        let verifying_pk = step5::<C>(
            &self.parameters,
            self.party_index,
            refresh_sid,
            proofs_commitments,
        )?;

        // The public key calculated above should be the zero point on the curve.
        if verifying_pk != crate::identity::<C>() {
            return Err(Abort::new(
                self.party_index,
                "The auxiliary public key is not the zero point!",
            ));
        }

        // Initialization - Zero shares.
        let mut seeds: Vec<zero_shares::SeedPair> =
            Vec::with_capacity((self.parameters.share_count - 1) as usize);
        for (target_party, message_kept) in kept {
            for message_received_2 in received_phase2 {
                for message_received_3 in received_phase3 {
                    let my_index = message_received_2.parties.receiver;
                    let their_index = message_received_2.parties.sender;

                    // Confirm that the message is for us.
                    if my_index != self.party_index {
                        return Err(Abort::new(
                            self.party_index,
                            "Received a message not meant for me!",
                        ));
                    }

                    // We first check if the messages relate to the same party.
                    if *target_party != their_index
                        || message_received_3.parties.sender != their_index
                    {
                        continue;
                    }

                    // We verify the commitment.
                    let verification = ZeroShare::verify_seed(
                        &message_received_3.seed,
                        &message_received_2.commitment,
                        &message_received_3.salt,
                    );
                    if !verification {
                        return Err(Abort::new(self.party_index, &format!("Initialization for zero shares protocol failed because Party {their_index} cheated when sending the seed!")));
                    }

                    // We form the final seed pairs.
                    seeds.push(ZeroShare::generate_seed_pair(
                        my_index,
                        their_index,
                        &message_kept.seed,
                        &message_received_3.seed,
                    ));
                }
            }
        }

        // Having the seeds, we can update the data for multiplication.

        let mut mul_senders: BTreeMap<u8, MulSender<C>> = BTreeMap::new();
        let mut mul_receivers: BTreeMap<u8, MulReceiver<C>> = BTreeMap::new();

        for seed_pair in &seeds {
            // This is the same as running through the counterparties.

            let their_index = seed_pair.index_counterparty;
            let seed = seed_pair.seed;

            let mul_sender = self.mul_senders.get(&their_index).unwrap();
            let mul_receiver = self.mul_receivers.get(&their_index).unwrap();

            // We update the OT data.

            let mut new_ote_sender = mul_sender.ote_sender.clone();
            let mut new_ote_receiver = mul_receiver.ote_receiver.clone();

            for i in 0..(ot::extension::KAPPA) {
                // We expand the seed into r0_prime, r1_prime and b_prime, as in the paper.
                // There will be two sets of constants: one for the sender and one
                // for the receiver. For the salts, note that the sender comes first.

                // Then, we apply the trick described in the paper.

                // Sender
                let salt_r0 = [
                    &(0u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();
                let salt_r1 = [
                    &(1u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();
                let salt_b = [
                    &(2u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();

                let r0_prime = hash(&seed, &salt_r0);
                let r1_prime = hash(&seed, &salt_r1);
                let b_prime = (hash(&seed, &salt_b)[0] % 2) == 1; // We take the first digit.

                let b_double_prime = new_ote_sender.correlation[i as usize] ^ b_prime;
                let r_prime_b_double_prime = if b_double_prime { r1_prime } else { r0_prime };

                let mut r_double_prime: HashOutput = [0; crate::SECURITY as usize];
                for j in 0..crate::SECURITY {
                    r_double_prime[j as usize] = new_ote_sender.seeds[i as usize][j as usize]
                        ^ r_prime_b_double_prime[j as usize];
                }

                // Updates new_ote_sender with the new values.
                new_ote_sender.correlation[i as usize] = b_double_prime;
                new_ote_sender.seeds[i as usize] = r_double_prime;

                // Receiver
                let salt_r0 = [
                    &(0u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();
                let salt_r1 = [
                    &(1u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();
                let salt_b = [
                    &(2u16).to_be_bytes(),
                    &i.to_be_bytes(),
                    &u16::from(their_index).to_be_bytes(),
                    &u16::from(self.party_index).to_be_bytes(),
                    refresh_sid,
                ]
                .concat();

                let r0_prime = hash(&seed, &salt_r0);
                let r1_prime = hash(&seed, &salt_r1);
                let b_prime = (hash(&seed, &salt_b)[0] % 2) == 1; // We take the first digit.

                let r_b_prime = if b_prime {
                    new_ote_receiver.seeds1[i as usize]
                } else {
                    new_ote_receiver.seeds0[i as usize]
                };
                let r_opposite_b_prime = if b_prime {
                    new_ote_receiver.seeds0[i as usize]
                } else {
                    new_ote_receiver.seeds1[i as usize]
                };

                let mut r0_double_prime: HashOutput = [0; crate::SECURITY as usize];
                let mut r1_double_prime: HashOutput = [0; crate::SECURITY as usize];
                for j in 0..crate::SECURITY {
                    r0_double_prime[j as usize] = r_b_prime[j as usize] ^ r0_prime[j as usize];
                    r1_double_prime[j as usize] =
                        r_opposite_b_prime[j as usize] ^ r1_prime[j as usize];
                }

                // Updates new_ote_receiver with the new values.
                new_ote_receiver.seeds0[i as usize] = r0_double_prime;
                new_ote_receiver.seeds1[i as usize] = r1_double_prime;
            }

            // We will not change the public gadget vector (well, it is "public" after all).
            mul_senders.insert(
                their_index,
                MulSender {
                    public_gadget: mul_sender.public_gadget.clone(),
                    ote_sender: new_ote_sender,
                },
            );
            mul_receivers.insert(
                their_index,
                MulReceiver {
                    public_gadget: mul_receiver.public_gadget.clone(),
                    ote_receiver: new_ote_receiver,
                },
            );
        }

        // This finishes the initialization for the zero shares protocol.
        let zero_share = ZeroShare::initialize(seeds);

        // For key derivation, we just update poly_point.
        let derivation_data = DerivData {
            depth: self.derivation_data.depth,
            child_number: self.derivation_data.child_number,
            parent_fingerprint: self.derivation_data.parent_fingerprint,
            poly_point: self.poly_point + correction_value, // We update poly_point.
            pk: self.pk,
            chain_code: self.derivation_data.chain_code,
        };

        // We can finally create the new party.
        let party = Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: refresh_sid.to_vec(), // We replace the old session id by the new one.

            poly_point: self.poly_point + correction_value, // We update poly_point.
            pk: self.pk,

            zero_share,

            mul_senders,
            mul_receivers,

            derivation_data,

            eth_address: self.eth_address.clone(),
        };

        Ok(party)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;
    use crate::protocols::Parameters;

    use rand::Rng;

    type C = k256::Secp256k1;

    /// Tests if the complete refresh protocol generates parties
    /// still capable of running the signing protocol.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_refresh_complete() {
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let secret_key = <C as CurveArithmetic>::Scalar::random(rng::get_rng());
        let parties = re_key::<C>(&parameters, &session_id, &secret_key, None);

        // REFRESH (it follows test_dkg_initialization closely)

        let refresh_sid = rng::get_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<<C as CurveArithmetic>::Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let out1 = parties[i as usize].refresh_complete_phase1();

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments = vec![
            Vec::<<C as CurveArithmetic>::Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2
        let mut correction_values: Vec<<C as CurveArithmetic>::Scalar> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment<C>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_kept_2to3: Vec<BTreeMap<u8, KeepInitZeroSharePhase2to3>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4) = parties[i as usize]
                .refresh_complete_phase2(&refresh_sid, &poly_fragments[i as usize]);

            correction_values.push(out1);
            proofs_commitments.push(out2);
            zero_kept_2to3.push(out3);
            zero_transmit_2to4.push(out4);
        }

        // Communication round 2
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase2to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_2to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(new_row);
        }

        // Phase 3
        let mut zero_kept_3to4: Vec<BTreeMap<u8, KeepInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_kept_3to4: Vec<BTreeMap<u8, KeepInitMulPhase3to4<C>>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4) = parties[i as usize]
                .refresh_complete_phase3(&refresh_sid, &zero_kept_2to3[i as usize]);

            zero_kept_3to4.push(out1);
            zero_transmit_3to4.push(out2);
            mul_kept_3to4.push(out3);
            mul_transmit_3to4.push(out4);
        }

        // Communication round 3
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the proofs because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitInitZeroSharePhase3to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &zero_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(new_row);

            let mut new_row: Vec<TransmitInitMulPhase3to4<C>> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &mul_transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(new_row);
        }

        // Phase 4
        let mut refreshed_parties: Vec<Party<C>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let result = parties[i as usize].refresh_complete_phase4(
                &refresh_sid,
                &correction_values[i as usize],
                &proofs_commitments,
                &zero_kept_3to4[i as usize],
                &zero_received_2to4[i as usize],
                &zero_received_3to4[i as usize],
                &mul_kept_3to4[i as usize],
                &mul_received_3to4[i as usize],
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok(party) => {
                    refreshed_parties.push(party);
                }
            }
        }

        let parties = refreshed_parties;

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2<C>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2<C>>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap());

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, messages_for_party);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3<C>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3<C>>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3 = BTreeMap::new();

        for &party_index in &executing_parties {
            let filtered_messages: Vec<_> = transmit_2to3
                .values()
                .flatten()
                .filter(|msg| msg.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, filtered_messages);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<C>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }

    /// Tests if the faster refresh protocol generates parties
    /// still capable of running the signing protocol.
    ///
    /// In this case, parties are sampled via the [`re_key`] function.
    #[test]
    fn test_refresh() {
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let secret_key = <C as CurveArithmetic>::Scalar::random(rng::get_rng());
        let parties = re_key::<C>(&parameters, &session_id, &secret_key, None);

        // REFRESH (faster version)

        let refresh_sid = rng::get_rng().gen::<[u8; 32]>();

        // Phase 1
        let mut dkg_1: Vec<Vec<<C as CurveArithmetic>::Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let out1 = parties[i as usize].refresh_phase1();

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments = vec![
            Vec::<<C as CurveArithmetic>::Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2
        let mut correction_values: Vec<<C as CurveArithmetic>::Scalar> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment<C>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut kept_2to3: Vec<BTreeMap<u8, KeepRefreshPhase2to3>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut transmit_2to4: Vec<Vec<TransmitRefreshPhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4) =
                parties[i as usize].refresh_phase2(&refresh_sid, &poly_fragments[i as usize]);

            correction_values.push(out1);
            proofs_commitments.push(out2);
            kept_2to3.push(out3);
            transmit_2to4.push(out4);
        }

        // Communication round 2
        let mut received_2to4: Vec<Vec<TransmitRefreshPhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the commitments because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitRefreshPhase2to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &transmit_2to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            received_2to4.push(new_row);
        }

        // Phase 3
        let mut kept_3to4: Vec<BTreeMap<u8, KeepRefreshPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut transmit_3to4: Vec<Vec<TransmitRefreshPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let (out1, out2) = parties[i as usize].refresh_phase3(&kept_2to3[i as usize]);

            kept_3to4.push(out1);
            transmit_3to4.push(out2);
        }

        // Communication round 3
        let mut received_3to4: Vec<Vec<TransmitRefreshPhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 1..=parameters.share_count {
            // We don't need to transmit the proofs because proofs_commitments is already what we need.
            // In practice, this should be done here.

            let mut new_row: Vec<TransmitRefreshPhase3to4> =
                Vec::with_capacity((parameters.share_count - 1) as usize);
            for party in &transmit_3to4 {
                for message in party {
                    // Check if this message should be sent to us.
                    if message.parties.receiver == i {
                        new_row.push(message.clone());
                    }
                }
            }
            received_3to4.push(new_row);
        }

        // Phase 4
        let mut refreshed_parties: Vec<Party<C>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let result = parties[i as usize].refresh_phase4(
                &refresh_sid,
                &correction_values[i as usize],
                &proofs_commitments,
                &kept_3to4[i as usize],
                &received_2to4[i as usize],
                &received_3to4[i as usize],
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok(party) => {
                    refreshed_parties.push(party);
                }
            }
        }

        let parties = refreshed_parties;

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2<C>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2<C>>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap());

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2 = BTreeMap::new();

        for &party_index in &executing_parties {
            let filtered_messages: Vec<_> = transmit_1to2
                .values()
                .flatten()
                .filter(|msg| msg.parties.receiver == party_index)
                .cloned()
                .collect();

            received_1to2.insert(party_index, filtered_messages);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3<C>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3<C>>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();

        for &party_index in &executing_parties {
            let messages_for_party: Vec<TransmitPhase2to3<C>> = transmit_2to3
                .values()
                .flatten()
                .filter(|message| message.parties.receiver == party_index)
                .cloned()
                .collect();

            received_2to3.insert(party_index, messages_for_party);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<C>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}
