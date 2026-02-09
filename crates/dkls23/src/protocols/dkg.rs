//! Distributed Key Generation protocol.
//!
//!  This file implements Protocol 9.1 in <https://eprint.iacr.org/2023/602.pdf>,
//! as instructed in `DKLs23` (<https://eprint.iacr.org/2023/765.pdf>). It is
//! the distributed key generation which setups the main signing protocol.
//!
//! During the protocol, we also initialize the functionalities that will
//! be used during signing.
//!
//! # Phases
//!
//! We group the steps in phases. A phase consists of all steps that can be
//! executed in order without the need of communication. Phases should be
//! intercalated with communication rounds: broadcasts and/or private messages
//! containing the session id.
//!
//! We also include here the initialization procedures of Functionalities 3.4
//! and 3.5 of `DKLs23`. The first one comes from [here](crate::utilities::zero_shares)
//! and needs two communication rounds (hence, it starts on Phase 2). The second one
//! comes from [here](crate::utilities::multiplication) and needs one communication round
//! (hence, it starts on Phase 3).
//!
//! For key derivation (following BIP-32: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>),
//! parties must agree on a common chain code for their shared master key. Using the
//! commitment functionality, we need two communication rounds, so this part starts
//! only on Phase 2.
//!
//! # Nomenclature
//!
//! For the initialization structs, we will use the following nomenclature:
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
use elliptic_curve::group::{Curve as _, GroupEncoding};
use elliptic_curve::ops::Reduce;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::{Field, PrimeField};
use hex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::protocols::derivation::{ChainCode, DerivData};
use crate::protocols::{Abort, Parameters, PartiesMessage, Party};
use crate::DklsCurve;

use crate::utilities::commits;
use crate::utilities::hashes::HashOutput;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot;
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::rng;
use crate::utilities::zero_shares::{self, ZeroShare};

/// Used during key generation.
///
/// After Phase 2, only the values `index` and `commitment` are broadcasted.
///
/// The `proof` is broadcasted after Phase 3.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound(
    serialize = "C::AffinePoint: Serialize, C::Scalar: Serialize",
    deserialize = "C::AffinePoint: Deserialize<'de>, C::Scalar: Deserialize<'de>"
))]
pub struct ProofCommitment<C: CurveArithmetic> {
    pub index: u8,
    pub proof: DLogProof<C>,
    pub commitment: HashOutput,
}

/// Data needed to start key generation and is used during the phases.
#[derive(Clone, Deserialize, Serialize)]
pub struct SessionData {
    pub parameters: Parameters,
    pub party_index: u8,
    pub session_id: Vec<u8>,
}

// INITIALIZING ZERO SHARES PROTOCOL.

/// Transmit - Initialization of zero shares protocol.
///
/// The message is produced/sent during Phase 2 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransmitInitZeroSharePhase2to4 {
    pub parties: PartiesMessage,
    pub commitment: HashOutput,
}

/// Transmit - Initialization of zero shares protocol.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransmitInitZeroSharePhase3to4 {
    pub parties: PartiesMessage,
    pub seed: zero_shares::Seed,
    pub salt: Vec<u8>,
}

/// Keep - Initialization of zero shares protocol.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeepInitZeroSharePhase2to3 {
    pub seed: zero_shares::Seed,
    pub salt: Vec<u8>,
}

/// Keep - Initialization of zero shares protocol.
///
/// The message is produced during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeepInitZeroSharePhase3to4 {
    pub seed: zero_shares::Seed,
}

// INITIALIZING TWO-PARTY MULTIPLICATION PROTOCOL.

/// Transmit - Initialization of multiplication protocol.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::AffinePoint: Serialize, C::Scalar: Serialize",
    deserialize = "C::AffinePoint: Deserialize<'de>, C::Scalar: Deserialize<'de>"
))]
pub struct TransmitInitMulPhase3to4<C: CurveArithmetic> {
    pub parties: PartiesMessage,

    pub dlog_proof: DLogProof<C>,
    pub nonce: C::Scalar,

    pub enc_proofs: Vec<EncProof<C>>,
    pub seed: ot::base::Seed,
}

/// Keep - Initialization of multiplication protocol.
///
/// The message is produced during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::AffinePoint: Serialize, C::Scalar: Serialize",
    deserialize = "C::AffinePoint: Deserialize<'de>, C::Scalar: Deserialize<'de>"
))]
pub struct KeepInitMulPhase3to4<C: CurveArithmetic> {
    pub ot_sender: ot::base::OTSender<C>,
    pub nonce: C::Scalar,

    pub ot_receiver: ot::base::OTReceiver,
    pub correlation: Vec<bool>,
    pub vec_r: Vec<C::Scalar>,
}

// INITIALIZING KEY DERIVATION (VIA BIP-32).

/// Broadcast - Initialization for key derivation.
///
/// The message is produced/sent during Phase 2 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastDerivationPhase2to4 {
    pub sender_index: u8,
    pub cc_commitment: HashOutput,
}

/// Broadcast - Initialization for key derivation.
///
/// The message is produced/sent during Phase 3 and used in Phase 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastDerivationPhase3to4 {
    pub sender_index: u8,
    pub aux_chain_code: ChainCode,
    pub cc_salt: Vec<u8>,
}

/// Unique keep - Initialization for key derivation.
///
/// The message is produced during Phase 2 and used in Phase 3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniqueKeepDerivationPhase2to3 {
    pub aux_chain_code: ChainCode,
    pub cc_salt: Vec<u8>,
}

// DISTRIBUTED KEY GENERATION (DKG)

// STEPS
// We implement each step of the DKLs23 protocol.

/// Generates a random polynomial of degree t-1.
///
/// This is Step 1 from Protocol 9.1 in <https://eprint.iacr.org/2023/602.pdf>.
#[must_use]
pub fn step1<C: DklsCurve>(parameters: &Parameters) -> Vec<C::Scalar> {
    // We represent the polynomial by its coefficients.
    let mut rng = rng::get_rng(); // Reuse RNG
    let mut polynomial: Vec<C::Scalar> = Vec::with_capacity(parameters.threshold as usize);
    for _ in 0..parameters.threshold {
        polynomial.push(C::Scalar::random(&mut rng)); // Pass the RNG explicitly
    }
    polynomial
}

/// Evaluates the polynomial from the previous step at every point.
///
/// If `p_i` denotes such polynomial, then the output is of the form
/// \[`p_i(1)`, `p_i(2)`, ..., `p_i(n)`\] in this order, where `n` = `parameters.share_count`.
///
/// The value `p_i(j)` should be transmitted to the party with index `j`.
/// Here, `i` denotes our index, so we should keep `p_i(i)` for the future.
///
/// This is Step 2 from Protocol 9.1 in <https://eprint.iacr.org/2023/602.pdf>.
#[must_use]
pub fn step2<C: DklsCurve>(parameters: &Parameters, polynomial: &[C::Scalar]) -> Vec<C::Scalar>
where
    C::Scalar: PrimeField,
{
    let mut points: Vec<C::Scalar> = Vec::with_capacity(parameters.share_count as usize);
    let last_index = (parameters.threshold - 1) as usize;

    for j in 1..=parameters.share_count {
        let j_scalar = C::Scalar::from(u64::from(j)); // Direct conversion

        // Using Horner's method for polynomial evaluation
        let mut evaluation_at_j = polynomial[last_index];

        for &coefficient in polynomial[..last_index].iter().rev() {
            evaluation_at_j = evaluation_at_j * j_scalar + coefficient;
        }

        points.push(evaluation_at_j);
    }

    points
}

/// Computes `poly_point` and the corresponding "public key" together with a zero-knowledge proof.
///
/// The variable `poly_fragments` is just a vector containing (in any order)
/// the scalars received from the other parties after the previous step.
///
/// The commitment from [`ProofCommitment`] should be broadcasted at this point.
///
/// This is Step 3 from Protocol 9.1 in <https://eprint.iacr.org/2023/602.pdf>.
/// There, `poly_point` is denoted by `p(i)` and the "public key" is `P(i)`.
///
/// The Step 4 of the protocol is broadcasting the rest of [`ProofCommitment`] after
/// having received all commitments.
#[must_use]
pub fn step3<C: DklsCurve>(
    party_index: u8,
    session_id: &[u8],
    poly_fragments: &[C::Scalar],
) -> (C::Scalar, ProofCommitment<C>)
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding,
{
    let poly_point: C::Scalar = poly_fragments.iter().sum();

    let (proof, commitment) = DLogProof::<C>::prove_commit(&poly_point, session_id);
    let proof_commitment = ProofCommitment {
        index: party_index,
        proof,
        commitment,
    };

    (poly_point, proof_commitment)
}

/// Validates the other proofs, runs a consistency check
/// and computes the public key.
///
/// The variable `proofs_commitments` is just a vector containing (in any order)
/// the instances of [`ProofCommitment`] received from the other parties after the
/// previous step (including ours).
///
/// This is Step 5 from Protocol 9.1 in <https://eprint.iacr.org/2023/602.pdf>.
/// Step 6 is essentially the same, so it is also done here.
///
/// # Errors
///
/// Will return `Err` if one of the proofs/commitments doesn't
/// verify or if the consistency check for the public key fails.
///
/// # Panics
///
/// Will panic if the list of indices in `proofs_commitments`
/// are not the numbers from 1 to `parameters.share_count`.
pub fn step5<C: DklsCurve>(
    parameters: &Parameters,
    party_index: u8,
    session_id: &[u8],
    proofs_commitments: &[ProofCommitment<C>],
) -> Result<C::AffinePoint, Abort>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding + Default,
{
    let mut committed_points: BTreeMap<u8, C::AffinePoint> = BTreeMap::new(); //The "public key fragments"

    // Verify the proofs and gather the committed points.
    for party_j in proofs_commitments {
        if party_j.index != party_index {
            let verification =
                DLogProof::<C>::decommit_verify(&party_j.proof, &party_j.commitment, session_id);
            if !verification {
                return Err(Abort::new(
                    party_index,
                    &format!("Proof from Party {} failed!", party_j.index),
                ));
            }
        }
        committed_points.insert(party_j.index, party_j.proof.point);
    }

    // Initializes what will be the public key.
    let mut pk = crate::identity::<C>();

    // Verify that all points come from the same polynomial. To do so, for each contiguous set of parties,
    // perform Shamir reconstruction in the exponent and check if the results agree.
    // The common value calculated is the public key.
    for i in 1..=(parameters.share_count - parameters.threshold + 1) {
        let mut current_pk = crate::identity::<C>();
        for j in i..(i + parameters.threshold) {
            // We find the Lagrange coefficient l(j) corresponding to j (and the contiguous set of parties).
            // It is such that the sum of l(j) * p(j) over all j is p(0), where p is the polynomial from Step 3.
            let j_scalar = C::Scalar::from(u64::from(j));
            let mut lj_numerator = C::Scalar::ONE;
            let mut lj_denominator = C::Scalar::ONE;

            for k in i..(i + parameters.threshold) {
                if k != j {
                    let k_scalar = C::Scalar::from(u64::from(k));
                    lj_numerator *= k_scalar;
                    lj_denominator *= k_scalar - j_scalar;
                }
            }

            let lj = lj_numerator * (lj_denominator.invert().unwrap());
            let lj_times_point =
                (C::ProjectivePoint::from(*committed_points.get(&j).unwrap()) * lj).to_affine();

            current_pk = (C::ProjectivePoint::from(lj_times_point)
                + C::ProjectivePoint::from(current_pk))
            .to_affine();
        }

        // The first value is taken as the public key. It should coincide with the next values.
        if i == 1 {
            pk = current_pk;
        } else if pk != current_pk {
            return Err(Abort::new(
                party_index,
                &format!("Verification for public key reconstruction failed in iteration {i}"),
            ));
        }
    }
    Ok(pk)
}

// PHASES

/// Phase 1 = [`step1`] and [`step2`].
///
/// # Input
///
/// Parameters for the key generation.
///
/// # Output
///
/// Evaluation of a random polynomial at every party index.
/// The j-th coordinate of the output vector must be sent
/// to the party with index j.
///
/// ATTENTION: In particular, we keep the coordinate corresponding
/// to our party index for the next phase.
#[must_use]
pub fn phase1<C: DklsCurve>(data: &SessionData) -> Vec<C::Scalar>
where
    C::Scalar: PrimeField,
{
    // DKG
    let secret_polynomial = step1::<C>(&data.parameters);

    step2::<C>(&data.parameters, &secret_polynomial)
}

// Communication round 1
// DKG: Party i keeps the i-th point and sends the j-th point to Party j for j != i.
// At the end, Party i should have received all fragments indexed by i.
// They should add up to p(i), where p is a polynomial not depending on i.

/// Phase 2 = [`step3`].
///
/// # Input
///
/// Fragments received from the previous phase.
///
/// # Output
///
/// The variable `poly_point` (= `p(i)`), which should be kept, and a proof of
/// discrete logarithm with commitment. You should transmit the commitment
/// now and, after finishing Phase 3, you send the rest. Remember to also
/// save a copy of your [`ProofCommitment`] for the final phase.
///
/// There is also some initialization data to keep and to transmit, following the
/// conventions [here](self).
#[must_use]
pub fn phase2<C: DklsCurve>(
    data: &SessionData,
    poly_fragments: &[C::Scalar],
) -> (
    C::Scalar,
    ProofCommitment<C>,
    BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    Vec<TransmitInitZeroSharePhase2to4>,
    UniqueKeepDerivationPhase2to3,
    BroadcastDerivationPhase2to4,
)
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding,
{
    // DKG
    let (poly_point, proof_commitment) =
        step3::<C>(data.party_index, &data.session_id, poly_fragments);

    // Initialization - Zero shares.

    // We will use BTreeMap to keep messages: the key indicates the party to whom the message refers.
    let mut zero_keep = BTreeMap::new();
    let mut zero_transmit = Vec::with_capacity((data.parameters.share_count - 1) as usize);

    for i in 1..=data.parameters.share_count {
        if i == data.party_index {
            continue;
        }

        // Generate initial seeds.
        let (seed, commitment, salt) = ZeroShare::generate_seed_with_commitment();

        // We first send the commitments. We keep the rest to send later.
        zero_keep.insert(i, KeepInitZeroSharePhase2to3 { seed, salt });
        zero_transmit.push(TransmitInitZeroSharePhase2to4 {
            parties: PartiesMessage {
                sender: data.party_index,
                receiver: i,
            },
            commitment,
        });
    }

    // Initialization - BIP-32.

    // Each party samples a random auxiliary chain code.
    let aux_chain_code: ChainCode = rng::get_rng().gen();
    let (cc_commitment, cc_salt) = commits::commit(&aux_chain_code);

    let bip_keep = UniqueKeepDerivationPhase2to3 {
        aux_chain_code,
        cc_salt,
    };

    // For simplicity, this message should be sent to us too.
    let bip_broadcast = BroadcastDerivationPhase2to4 {
        sender_index: data.party_index,
        cc_commitment,
    };

    (
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    )
}

// Communication round 2
// DKG: Party i broadcasts his commitment to the proof and receive the other commitments.
//
// Init: Each party transmits messages for the zero shares protocol (one for each party)
// and broadcasts a message for key derivation (the same for every party).

/// Phase 3 = No steps in DKG (just initialization).
///
/// # Input
///
/// Initialization data kept from the previous phase.
///
/// # Output
///
/// Some initialization data to keep and to transmit, following the
/// conventions [here](self).
#[must_use]
pub fn phase3<C: DklsCurve>(
    data: &SessionData,
    zero_kept: &BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    bip_kept: &UniqueKeepDerivationPhase2to3,
) -> (
    BTreeMap<u8, KeepInitZeroSharePhase3to4>,
    Vec<TransmitInitZeroSharePhase3to4>,
    BTreeMap<u8, KeepInitMulPhase3to4<C>>,
    Vec<TransmitInitMulPhase3to4<C>>,
    BroadcastDerivationPhase3to4,
)
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding + Default,
{
    // Initialization - Zero shares.
    let share_count = (data.parameters.share_count - 1) as usize;
    let mut zero_keep = BTreeMap::new();
    let mut zero_transmit = Vec::with_capacity(share_count);

    for (&target_party, message_kept) in zero_kept.iter() {
        // The messages kept contain the seed and the salt.
        // They have to be transmitted to the target party.
        // We keep the seed with us for the next phase.
        let keep = KeepInitZeroSharePhase3to4 {
            seed: message_kept.seed,
        };
        let transmit = TransmitInitZeroSharePhase3to4 {
            parties: PartiesMessage {
                sender: data.party_index,
                receiver: target_party,
            },
            seed: message_kept.seed,
            salt: message_kept.salt.clone(),
        };

        zero_keep.insert(target_party, keep);
        zero_transmit.push(transmit);
    }

    // Initialization - Two-party multiplication.
    // Each party prepares initialization both as
    // a receiver and as a sender.
    // Initialization - Two-party multiplication.
    let mut mul_keep = BTreeMap::new();
    let mut mul_transmit = Vec::with_capacity(share_count);

    for i in 1..=data.parameters.share_count {
        if i == data.party_index {
            continue;
        }

        // RECEIVER
        // We are the receiver and i = sender.

        // We first compute a new session id.
        // As in Protocol 3.6 of DKLs23, we include the indexes from the parties.
        let mul_sid_receiver = [
            "Multiplication protocol".as_bytes(),
            &data.party_index.to_be_bytes(),
            &i.to_be_bytes(),
            &data.session_id[..],
        ]
        .concat();

        let (ot_sender, dlog_proof, nonce) =
            MulReceiver::<C>::init_phase1(&mul_sid_receiver);

        // SENDER
        // We are the sender and i = receiver.

        // New session id as above.
        // Note that the indexes are now in the opposite order.
        let mul_sid_sender = [
            "Multiplication protocol".as_bytes(),
            &i.to_be_bytes(),
            &data.party_index.to_be_bytes(),
            &data.session_id[..],
        ]
        .concat();

        let (ot_receiver, correlation, vec_r, enc_proofs) =
            MulSender::<C>::init_phase1(&mul_sid_sender);

        // We gather these values.

        let transmit = TransmitInitMulPhase3to4 {
            parties: PartiesMessage {
                sender: data.party_index,
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

    // Initialization - BIP-32.
    // After having transmitted the commitment, we broadcast
    // our auxiliary chain code and the corresponding salt.
    // For simplicity, this message should be sent to us too.
    let bip_broadcast = BroadcastDerivationPhase3to4 {
        sender_index: data.party_index,
        aux_chain_code: bip_kept.aux_chain_code,
        cc_salt: bip_kept.cc_salt.clone(),
    };

    (
        zero_keep,
        zero_transmit,
        mul_keep,
        mul_transmit,
        bip_broadcast,
    )
}

// Communication round 3
// DKG: We execute Step 4 of the protocol: after having received all commitments, each party broadcasts his proof.
//
// Init: Each party transmits messages for the zero shares and multiplication protocols (one for each party)
// and broadcasts a message for key derivation (the same for every party).

/// Phase 4 = [`step5`].
///
/// # Input
///
/// The `poly_point` scalar generated in Phase 2;
///
/// A vector containing (in any order) the [`ProofCommitment`]'s
/// received from the other parties (including ours);
///
/// The initialization data kept from the previous phases;
///
/// The initialization data received from the other parties in
/// the previous phases. They must be grouped in vectors (in any
/// order) according to the type or, in the case of the messages
/// related to derivation BIP-32, in a `BTreeMap` where the key
/// represents the index of the party that transmitted the message.
///
/// # Output
///
/// An instance of [`Party`] ready to execute the other protocols.
///
/// # Errors
///
/// Will return `Err` if a message is not meant for the party
/// or if one of the initializations fails. With very low probability,
/// it may also fail if the secret data is trivial.
///
/// # Panics
///
/// Will panic if the list of keys in the `BTreeMap`'s are incompatible
/// with the party indices in the received vectors.
pub fn phase4<C: DklsCurve>(
    data: &SessionData,
    poly_point: &C::Scalar,
    proofs_commitments: &[ProofCommitment<C>],
    zero_kept: &BTreeMap<u8, KeepInitZeroSharePhase3to4>,
    zero_received_phase2: &[TransmitInitZeroSharePhase2to4],
    zero_received_phase3: &[TransmitInitZeroSharePhase3to4],
    mul_kept: &BTreeMap<u8, KeepInitMulPhase3to4<C>>,
    mul_received: &[TransmitInitMulPhase3to4<C>],
    bip_received_phase2: &BTreeMap<u8, BroadcastDerivationPhase2to4>,
    bip_received_phase3: &BTreeMap<u8, BroadcastDerivationPhase3to4>,
) -> Result<Party<C>, Abort>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding + Default,
{
    // DKG
    let pk = step5::<C>(
        &data.parameters,
        data.party_index,
        &data.session_id,
        proofs_commitments,
    )?;

    // The public key cannot be the point at infinity.
    // This is practically impossible, but easy to check.
    // We also verify that pk is not the generator point, because
    // otherwise it would be trivial to find the "total" secret key.
    if pk == crate::identity::<C>() || pk == crate::generator::<C>() {
        return Err(Abort::new(
            data.party_index,
            "Initialization failed because the resulting public key was trivial! (Very improbable)",
        ));
    }

    // Our key share (that is, poly_point), should not be trivial.
    // Note that the other parties can deduce the triviality from
    // the corresponding proof in proofs_commitments.
    if *poly_point == C::Scalar::ZERO || *poly_point == C::Scalar::ONE {
        return Err(Abort::new(
            data.party_index,
            "Initialization failed because the resulting key share was trivial! (Very improbable)",
        ));
    }

    // Initialization - Zero shares.
    let mut seeds: Vec<zero_shares::SeedPair> =
        Vec::with_capacity((data.parameters.share_count - 1) as usize);
    for (target_party, message_kept) in zero_kept {
        for message_received_2 in zero_received_phase2 {
            for message_received_3 in zero_received_phase3 {
                let my_index = message_received_2.parties.receiver;
                let their_index = message_received_2.parties.sender;

                // Confirm that the message is for us.
                if my_index != data.party_index {
                    return Err(Abort::new(
                        data.party_index,
                        "Received a message not meant for me!",
                    ));
                }

                // We first check if the messages relate to the same party.
                if *target_party != their_index || message_received_3.parties.sender != their_index
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
                    return Err(Abort::new(data.party_index, &format!("Initialization for zero shares protocol failed because Party {their_index} cheated when sending the seed!")));
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
            if my_index != data.party_index {
                return Err(Abort::new(
                    data.party_index,
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
                &data.session_id[..],
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
                    return Err(Abort::new(data.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
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
                &data.session_id[..],
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
                    return Err(Abort::new(data.party_index, &format!("Initialization for multiplication protocol failed because of Party {}: {:?}", their_index, error.description)));
                }
            };

            // We finish the initialization.
            mul_receivers.insert(their_index, mul_receiver);
            mul_senders.insert(their_index, mul_sender.clone());
        }
    }

    // Initialization - BIP-32.
    // We check the commitments and create the final chain code.
    // It will be given by the XOR of the auxiliary chain codes.
    let mut chain_code: ChainCode = [0; 32];
    for i in 1..=data.parameters.share_count {
        // We take the messages in the correct order (that's why the BTreeMap).
        let verification = commits::verify_commitment(
            &bip_received_phase3.get(&i).unwrap().aux_chain_code,
            &bip_received_phase2.get(&i).unwrap().cc_commitment,
            &bip_received_phase3.get(&i).unwrap().cc_salt,
        );
        if !verification {
            return Err(Abort::new(data.party_index, &format!("Initialization for key derivation failed because Party {} cheated when sending the auxiliary chain code!", i+1)));
        }

        // We XOR this auxiliary chain code to the final result.
        let current_aux_chain_code = bip_received_phase3.get(&i).unwrap().aux_chain_code;
        for j in 0..32 {
            chain_code[j] ^= current_aux_chain_code[j];
        }
    }

    // We can finally finish key generation!

    let derivation_data = DerivData {
        depth: 0,
        child_number: 0, // These three values are initialized as zero for the master node.
        parent_fingerprint: [0; 4],
        poly_point: *poly_point,
        pk,
        chain_code,
    };

    let eth_address = compute_eth_address::<C>(&pk); // We compute the Ethereum address.

    let party = Party {
        parameters: data.parameters.clone(),
        party_index: data.party_index,
        session_id: data.session_id.clone(),

        poly_point: *poly_point,
        pk,

        zero_share,

        mul_senders,
        mul_receivers,

        derivation_data,

        eth_address,
    };

    Ok(party)
}

/// Computes the Ethereum address given a public key.
///
/// This is only meaningful for secp256k1 (used by Ethereum). For other
/// curves, an empty string is returned.
#[must_use]
pub fn compute_eth_address<C: CurveArithmetic + 'static>(pk: &C::AffinePoint) -> String
where
    C::AffinePoint: GroupEncoding,
{
    use std::any::TypeId;

    // Only compute ETH address for secp256k1
    if TypeId::of::<C>() == TypeId::of::<k256::Secp256k1>() {
        // Convert the generic point to bytes, then parse as a k256 public key
        // so we can get the uncompressed representation.
        let point_bytes = pk.to_bytes();
        let k256_pk = match k256::PublicKey::from_sec1_bytes(point_bytes.as_ref()) {
            Ok(pk) => pk,
            Err(_) => return String::new(),
        };

        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let uncompressed_pk = k256_pk.to_encoded_point(false);

        // Compute the Keccak256 hash of the serialized public key
        // Skip the "04" SEC-1 prefix, see: https://www.secg.org/sec1-v2.pdf sec 3.3.3 page 11
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed_pk.as_bytes()[1..]);

        // Take the last 20 bytes of the hash and convert to a hex string
        let full_hash = hasher.finalize_reset();
        let address = hex::encode(&full_hash[12..]);

        // Compute the Keccak256 hash of the lowercase hexadecimal address
        hasher.update(address.to_lowercase().as_bytes());
        let hash_bytes = hasher.finalize();

        // ERC-55: Mixed-case checksum address encoding: https://eips.ethereum.org/EIPS/eip-55
        format!(
            "0x{}",
            address
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if c.is_alphabetic()
                        && (hash_bytes[i / 2] >> (4 * (1 - i % 2)) & 0x0f) >= 8
                    {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect::<String>()
        )
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use elliptic_curve::bigint::U256;
    use elliptic_curve::group::Curve as _;
    use elliptic_curve::ops::Reduce;
    use elliptic_curve::CurveArithmetic;
    use rand::Rng;

    type C = k256::Secp256k1;
    type Scalar = <C as CurveArithmetic>::Scalar;
    type AffinePoint = <C as CurveArithmetic>::AffinePoint;

    // DISTRIBUTED KEY GENERATION (without initializations)

    // We are not testing in the moment the initializations for zero shares
    // and multiplication here because they are only used during signing.

    // The initializations are checked after these tests (see below).

    /// Tests if the main steps of the protocol do not generate
    /// an unexpected [`Abort`] in the 2-of-2 scenario.
    #[test]
    fn test_dkg_t2_n2() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        let p1_phase1 = step2::<C>(&parameters, &step1::<C>(&parameters)); //p1 = Party 1
        let p2_phase1 = step2::<C>(&parameters, &step1::<C>(&parameters)); //p2 = Party 2

        assert_eq!(p1_phase1.len(), 2);
        assert_eq!(p2_phase1.len(), 2);

        // Communication round 1
        let p1_poly_fragments = vec![p1_phase1[0], p2_phase1[0]];
        let p2_poly_fragments = vec![p1_phase1[1], p2_phase1[1]];

        // Phase 2 (Step 3)
        let p1_phase2 = step3::<C>(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = step3::<C>(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = step5::<C>(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = step5::<C>(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());
    }

    /// Tests if the main steps of the protocol do not generate
    /// an unexpected [`Abort`] in the t-of-n scenario, where
    /// t and n are small random values.
    #[test]
    fn test_dkg_random() {
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // Phase 1 (Steps 1 and 2)
        // Matrix of polynomial points
        let mut phase1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for _ in 0..parameters.share_count {
            let party_phase1 = step2::<C>(&parameters, &step1::<C>(&parameters));
            assert_eq!(party_phase1.len(), parameters.share_count as usize);
            phase1.push(party_phase1);
        }

        // Communication round 1
        // We transpose the matrix
        let mut poly_fragments = vec![
            Vec::<Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in phase1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment<C>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let party_i_phase2 = step3::<C>(i + 1, &session_id, &poly_fragments[i as usize]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut result_parties: Vec<Result<AffinePoint, Abort>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            result_parties.push(step5::<C>(
                &parameters,
                i + 1,
                &session_id,
                &proofs_commitments,
            ));
        }

        for result in result_parties {
            assert!(result.is_ok());
        }
    }

    /// Tests if the main steps of the protocol generate
    /// the expected public key.
    ///
    /// In this case, we remove the randomness of [Step 1](step1)
    /// by providing fixed values.
    ///
    /// This functions treats the 2-of-2 scenario.
    #[test]
    fn test1_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::from(1u64), Scalar::from(3u64)];
        let p2_poly_fragments = vec![Scalar::from(2u64), Scalar::from(4u64)];

        // In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 1+3 = 4 and p(2) = 2+4 = 6
        // In particular, we must have p(0) = 2, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be 2 * generator.

        // Phase 2 (Step 3)
        let p1_phase2 = step3::<C>(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = step3::<C>(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = step5::<C>(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = step5::<C>(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());

        let p1_pk = p1_result.unwrap();
        let p2_pk = p2_result.unwrap();

        // Verifying the public key
        let expected_pk = (<C as CurveArithmetic>::ProjectivePoint::from(crate::generator::<C>())
            * Scalar::from(2u64))
        .to_affine();
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    /// Variation on [`test1_dkg_t2_n2_fixed_polynomials`].
    #[test]
    fn test2_dkg_t2_n2_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let p1_poly_fragments = vec![Scalar::from(12u64), Scalar::from(2u64)];
        let p2_poly_fragments = vec![Scalar::from(2u64), Scalar::from(3u64)];

        // In this case, the secret polynomial p is of degree 1 and satisfies p(1) = 12+2 = 14 and p(2) = 2+3 = 5
        // In particular, we must have p(0) = 23, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be 23 * generator.

        // Phase 2 (Step 3)
        let p1_phase2 = step3::<C>(1, &session_id, &p1_poly_fragments);
        let p2_phase2 = step3::<C>(2, &session_id, &p2_poly_fragments);

        let (_, p1_proof_commitment) = p1_phase2;
        let (_, p2_proof_commitment) = p2_phase2;

        // Communication rounds 2 and 3
        // For tests, they can be done simultaneously
        let proofs_commitments = vec![p1_proof_commitment, p2_proof_commitment];

        // Phase 4 (Step 5)
        let p1_result = step5::<C>(&parameters, 1, &session_id, &proofs_commitments);
        let p2_result = step5::<C>(&parameters, 2, &session_id, &proofs_commitments);

        assert!(p1_result.is_ok());
        assert!(p2_result.is_ok());

        let p1_pk = p1_result.unwrap();
        let p2_pk = p2_result.unwrap();

        // Verifying the public key
        let expected_pk = (<C as CurveArithmetic>::ProjectivePoint::from(crate::generator::<C>())
            * Scalar::from(23u64))
        .to_affine();
        assert_eq!(p1_pk, expected_pk);
        assert_eq!(p2_pk, expected_pk);
    }

    /// The same as [`test1_dkg_t2_n2_fixed_polynomials`]
    /// but in the 3-of-5 scenario.
    #[test]
    fn test_dkg_t3_n5_fixed_polynomials() {
        let parameters = Parameters {
            threshold: 3,
            share_count: 5,
        };
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // We will define the fragments directly
        let poly_fragments = vec![
            vec![
                Scalar::from(5u64),
                Scalar::from(1u64),
                Scalar::from(5u64).negate(),
                Scalar::from(2u64).negate(),
                Scalar::from(3u64).negate(),
            ],
            vec![
                Scalar::from(9u64),
                Scalar::from(3u64),
                Scalar::from(4u64).negate(),
                Scalar::from(5u64).negate(),
                Scalar::from(7u64).negate(),
            ],
            vec![
                Scalar::from(15u64),
                Scalar::from(7u64),
                Scalar::from(1u64).negate(),
                Scalar::from(10u64).negate(),
                Scalar::from(13u64).negate(),
            ],
            vec![
                Scalar::from(23u64),
                Scalar::from(13u64),
                Scalar::from(4u64),
                Scalar::from(17u64).negate(),
                Scalar::from(21u64).negate(),
            ],
            vec![
                Scalar::from(33u64),
                Scalar::from(21u64),
                Scalar::from(11u64),
                Scalar::from(26u64).negate(),
                Scalar::from(31u64).negate(),
            ],
        ];

        // In this case, the secret polynomial p is of degree 2 and satisfies:
        // p(1) = -4, p(2) = -4, p(3) = -2, p(4) = 2, p(5) = 8.
        // Hence we must have p(x) = x^2 - 3x - 2.
        // In particular, we must have p(0) = -2, which is the "hypothetical" secret key.
        // For this reason, we should expect the public key to be (-2) * generator.

        // Phase 2 (Step 3) + Communication rounds 2 and 3
        let mut proofs_commitments: Vec<ProofCommitment<C>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let party_i_phase2 =
                step3::<C>(i + 1, &session_id, &poly_fragments[i as usize]);
            let (_, party_i_proof_commitment) = party_i_phase2;
            proofs_commitments.push(party_i_proof_commitment);
        }

        // Phase 4 (Step 5)
        let mut results: Vec<Result<AffinePoint, Abort>> =
            Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            results.push(step5::<C>(
                &parameters,
                i + 1,
                &session_id,
                &proofs_commitments,
            ));
        }

        let mut public_keys: Vec<AffinePoint> =
            Vec::with_capacity(parameters.share_count as usize);
        for result in results {
            match result {
                Ok(pk) => {
                    public_keys.push(pk);
                }
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
            }
        }

        // Verifying the public key
        let expected_pk = (<C as CurveArithmetic>::ProjectivePoint::from(crate::generator::<C>())
            * Scalar::from(2u64).negate())
        .to_affine();
        for pk in public_keys {
            assert_eq!(pk, expected_pk);
        }
    }

    // DISTRIBUTED KEY GENERATION (with initializations)

    // We now test if the initialization procedures don't abort.
    // The verification that they really work is done in signing.rs.

    // Disclaimer: this implementation is not the most efficient,
    // we are only testing if everything works! Note as well that
    // parties are being simulated one after the other, but they
    // should actually execute the protocol simultaneously.

    /// Tests if the whole DKG protocol (with initializations)
    /// does not generate an unexpected [`Abort`].
    ///
    /// The correctness of the protocol is verified on `test_dkg_and_signing`.
    #[test]
    fn test_dkg_initialization() {
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // Each party prepares their data for this DKG.
        let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            all_data.push(SessionData {
                parameters: parameters.clone(),
                party_index: i + 1,
                session_id: session_id.to_vec(),
            });
        }

        // Phase 1
        let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let out1 = phase1::<C>(&all_data[i as usize]);

            dkg_1.push(out1);
        }

        // Communication round 1 - Each party receives a fragment from each counterparty.
        // They also produce a fragment for themselves.
        let mut poly_fragments = vec![
            Vec::<Scalar>::with_capacity(parameters.share_count as usize);
            parameters.share_count as usize
        ];
        for row_i in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row_i[j as usize]);
            }
        }

        // Phase 2
        let mut poly_points: Vec<Scalar> = Vec::with_capacity(parameters.share_count as usize);
        let mut proofs_commitments: Vec<ProofCommitment<C>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_kept_2to3: Vec<BTreeMap<u8, KeepInitZeroSharePhase2to3>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4> = BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5, out6) =
                phase2::<C>(&all_data[i as usize], &poly_fragments[i as usize]);

            poly_points.push(out1);
            proofs_commitments.push(out2);
            zero_kept_2to3.push(out3);
            zero_transmit_2to4.push(out4);
            bip_kept_2to3.push(out5);
            bip_broadcast_2to4.insert(i + 1, out6); // This variable should be grouped into a BTreeMap.
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

        // bip_transmit_2to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 3
        let mut zero_kept_3to4: Vec<BTreeMap<u8, KeepInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_kept_3to4: Vec<BTreeMap<u8, KeepInitMulPhase3to4<C>>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> =
            Vec::with_capacity(parameters.share_count as usize);
        let mut bip_broadcast_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4> = BTreeMap::new();
        for i in 0..parameters.share_count {
            let (out1, out2, out3, out4, out5) = phase3::<C>(
                &all_data[i as usize],
                &zero_kept_2to3[i as usize],
                &bip_kept_2to3[i as usize],
            );

            zero_kept_3to4.push(out1);
            zero_transmit_3to4.push(out2);
            mul_kept_3to4.push(out3);
            mul_transmit_3to4.push(out4);
            bip_broadcast_3to4.insert(i + 1, out5); // This variable should be grouped into a BTreeMap.
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

        // bip_transmit_3to4 is already in the format we need.
        // In practice, the messages received should be grouped into a BTreeMap.

        // Phase 4
        let mut parties: Vec<Party<C>> =
            Vec::with_capacity((parameters.share_count) as usize);
        for i in 0..parameters.share_count {
            let result = phase4::<C>(
                &all_data[i as usize],
                &poly_points[i as usize],
                &proofs_commitments,
                &zero_kept_3to4[i as usize],
                &zero_received_2to4[i as usize],
                &zero_received_3to4[i as usize],
                &mul_kept_3to4[i as usize],
                &mul_received_3to4[i as usize],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok(party) => {
                    parties.push(party);
                }
            }
        }

        // We check if the public keys and chain codes are the same.
        let expected_pk = parties[0].pk;
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }
    }

    /// Tests if [`compute_eth_address`] correctly
    /// computes the Ethereum address for a fixed public key.
    #[test]
    fn test_compute_eth_address() {
        // You should test different values using, for example,
        // https://www.rfctools.com/ethereum-address-test-tool/.
        let sk = <Scalar as Reduce<U256>>::reduce(U256::from_be_hex(
            "0249815B0D7E186DB61E7A6AAD6226608BB1C48B309EA8903CAB7A7283DA64A5",
        ));
        let pk = (<C as CurveArithmetic>::ProjectivePoint::from(crate::generator::<C>()) * sk)
            .to_affine();

        let address = compute_eth_address::<C>(&pk);
        assert_eq!(
            address,
            "0x2afDdfDF813E567A6f357Da818B16E2dae08599F".to_string()
        );
    }
}
