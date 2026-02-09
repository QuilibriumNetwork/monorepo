//! Extension protocol.
//!
//! This file implements an Oblivious Transfer Extension (OTE) that realizes
//! Functionality 3 in `DKLs19` (<https://eprint.iacr.org/2019/523.pdf>). It is
//! used for the multiplication protocol (see multiplication.rs).
//!
//! As `DKLs23` suggested, we use Roy's `SoftSpokenOT` (<https://eprint.iacr.org/2022/192.pdf>).
//! However, we do not follow this paper directly. Instead, we use the `KOS` paper
//! available at <https://eprint.iacr.org/2015/546.pdf>. In the corrected version,
//! they present an alternative for their original protocol (which was used by `DKLs`,
//! but was not as secure as expected) using `SoftSpokenOT` (see Fig. 10 in `KOS`).
//!
//! In order to reduce the round count, we apply the Fiat-Shamir heuristic, as `DKLs23`
//! instructs. We also include an additional step in the protocol given by `KOS`. It
//! comes from Protocol 9 of the `DKLs18` paper (<https://eprint.iacr.org/2018/499.pdf>).
//! It is needed to transform the outputs to the desired form.
//!
//! # Remark: the OT width
//!
//! We implement the "forced-reuse" technique suggested in `DKLs23`.
//! As they say: "Alice performs the steps of the protocol for each input in
//! her vector, but uses a single batch of Bob's OT instances for all of them,
//! concatenating the corresponding OT payloads to form one batch of payloads
//! with lengths proportionate to her input vector length."
//!
//! Actually, this approach is implicitly used in `DKLs19`. This can be seen,
//! for example, in the two following implementations:
//!
//! <https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos.go>
//!
//! <https://github.com/docknetwork/crypto/blob/main/oblivious_transfer/src/ot_extensions/kos_ote.rs>
//!
//! In both of them, the sender supplies a vector of 2-tuples of correlations against
//! a unique vector of choice bits by the receiver. This number "2" is called in the
//! first implementation as the "OT width". We shall use the same terminology. Here,
//! instead of taking a vector of k-tuples of correlations, we equivalently deal with
//! k vectors of single correlations, where k is the OT width.

use elliptic_curve::bigint::U256;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::Reduce;
use elliptic_curve::PrimeField;
use rand::Rng;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DklsCurve;
use crate::{RAW_SECURITY, STAT_SECURITY};

use crate::utilities::hashes::{hash, hash_as_scalar, HashOutput};
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::rng;

use crate::utilities::ot::base::{OTReceiver, OTSender, Seed};
use crate::utilities::ot::ErrorOT;

// CONSTANTS
// You should not change these numbers!
// If you do, some parts of the code must be changed.

/// Computational security parameter.
pub const KAPPA: u16 = RAW_SECURITY;
/// Statistical security parameter used in `KOS`.
///
/// This particular number comes from the implementation of `DKLs19`:
/// <https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs>.
///
/// It has to divide [`BATCH_SIZE`]!
pub const OT_SECURITY: u16 = 128 + STAT_SECURITY;
/// The extension execute this number of OT's.
///
/// This particular number is the one used in the [multiplication protocol](super::super::multiplication).
pub const BATCH_SIZE: u16 = RAW_SECURITY + 2 * STAT_SECURITY;
/// Constant `l'` as in Fig. 10 of `KOS`.
pub const EXTENDED_BATCH_SIZE: u16 = BATCH_SIZE + OT_SECURITY;

/// Output of pseudo-random generator.
pub type PRGOutput = [u8; (EXTENDED_BATCH_SIZE / 8) as usize];
/// Encodes an element in the field of 2^`OT_SECURITY` elements.
pub type FieldElement = [u8; (OT_SECURITY / 8) as usize];

pub fn serialize_vec_prg<S>(data: &[[u8; 78]], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let concatenated: Vec<u8> = data.iter().flat_map(|&b| b.to_vec()).collect();
    serde_bytes::Serialize::serialize(&concatenated, serializer)
}

pub fn deserialize_vec_prg<'de, D>(deserializer: D) -> Result<Vec<[u8; 78]>, D::Error>
where
    D: Deserializer<'de>,
{
    let concatenated: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;

    concatenated
        .chunks(78)
        .map(|chunk| {
            let array: [u8; 78] = chunk.try_into().map_err(D::Error::custom)?;
            Ok(array)
        })
        .collect()
}

/// Sender's data and methods for the OTE protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OTESender {
    pub correlation: Vec<bool>, // We will deal with bits separately
    pub seeds: Vec<HashOutput>,
}

/// Receiver's data and methods for the OTE protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OTEReceiver {
    pub seeds0: Vec<HashOutput>,
    pub seeds1: Vec<HashOutput>,
}

/// Data transmitted by the receiver to the sender after his first phase.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OTEDataToSender {
    #[serde(
        serialize_with = "serialize_vec_prg",
        deserialize_with = "deserialize_vec_prg"
    )]
    pub u: Vec<PRGOutput>,
    pub verify_x: FieldElement,
    pub verify_t: Vec<FieldElement>,
}

impl OTESender {
    // INITIALIZE

    // According to KOS (Fig. 10), the initialization is done by applying the OT protocol
    // KAPPA times and considering the outputs as "seeds".

    // Attention: The roles are reversed during this part!
    // Hence, a sender in the extension initializes as a receiver in the base OT.

    /// Starts the initialization.
    ///
    /// In this case, it initializes and runs **as a receiver** the first phase
    /// of the base OT ([`KAPPA`] times).
    ///
    /// See [`OTReceiver`](super::base::OTReceiver) for an explanation of the outputs.
    #[must_use]
    pub fn init_phase1<C: DklsCurve>(
        session_id: &[u8],
    ) -> (OTReceiver, Vec<bool>, Vec<C::Scalar>, Vec<EncProof<C>>)
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        let ot_receiver = OTReceiver::init();

        // The choice bits are sampled randomly.
        let mut correlation: Vec<bool> = Vec::with_capacity(KAPPA as usize);
        for _ in 0..KAPPA {
            correlation.push(rng::get_rng().gen());
        }

        let (vec_r, enc_proofs) = ot_receiver.run_phase1_batch::<C>(session_id, &correlation);

        (ot_receiver, correlation, vec_r, enc_proofs)
    }

    /// Finishes the initialization.
    ///
    /// The inputs are the instance of [`OTReceiver`](super::base::OTReceiver) generated
    /// in the previous round and everything needed to finish the OT base protocol
    /// (see the description of the aforementioned struct).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the base OT fails (see the file above).
    pub fn init_phase2<C: DklsCurve>(
        ot_receiver: &OTReceiver,
        session_id: &[u8],
        correlation: Vec<bool>,
        vec_r: &[C::Scalar],
        dlog_proof: &DLogProof<C>,
    ) -> Result<OTESender, ErrorOT>
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // The outputs from the base OT become the sender's seeds.
        let seeds = ot_receiver.run_phase2_batch::<C>(session_id, vec_r, dlog_proof)?;

        Ok(OTESender { correlation, seeds })
    }

    // PROTOCOL
    // We now follow the main steps in Fig. 10 of KOS.
    // The suggestions given in the DKLs papers are also implemented.
    // See the description at the beginning of this file for more details.

    /// Runs the sender's protocol.
    ///
    /// Input: OT width (see the remark [here](super::extension)), correlations for
    /// the points and values transmitted by the receiver. In this case, a correlation
    /// vector contains [`BATCH_SIZE`] scalars and `input_correlations` contains `ot_width`
    /// correlation vectors.
    ///
    /// Output: Protocol's output and data to be sent to the receiver.
    /// The usual output would be just a vector of [`BATCH_SIZE`] scalars.
    /// However, we are executing the protocol `ot_width` times, so the result
    /// is a vector containing `ot_width` such vectors.
    ///
    /// # Errors
    ///
    /// Will return  `Err` if `input_correlations` does not have the correct length
    /// or if the consistency check using the receiver values fails.
    pub fn run<C: DklsCurve>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        input_correlations: &[Vec<C::Scalar>],
        data: &OTEDataToSender,
    ) -> Result<(Vec<Vec<C::Scalar>>, Vec<Vec<C::Scalar>>), ErrorOT>
    where
        C::Scalar: Reduce<U256>,
    {
        // The protocol will be executed ot_width times using different input correlations.
        if input_correlations.len() != ot_width as usize {
            return Err(ErrorOT::new(
                "The vector of input correlations does not have the expected size!",
            ));
        }

        // EXTEND

        // Step 1 - No action for the sender.

        // Step 2 - Extend the seed with the pseudorandom generator (PRG).
        // The PRG will be implemented via hash functions.
        let mut extended_seeds: Vec<PRGOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            let mut prg: Vec<u8> = Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize); //It may use more capacity.

            // The PRG will given by concatenating "chunks" of hash outputs.
            // The reason for this is that we need more than 256 bits.
            let mut count = 0u16;
            while prg.len() < (EXTENDED_BATCH_SIZE / 8) as usize {
                // To change the "random oracle", we include the index and a counter into the salt.
                let salt = [&i.to_be_bytes(), &count.to_be_bytes(), session_id].concat();
                count += 1;

                let chunk = hash(&self.seeds[i as usize], &salt);

                prg.extend_from_slice(&chunk);
            }

            // We remove extra bytes
            let mut prg_output = [0; (EXTENDED_BATCH_SIZE / 8) as usize];
            prg_output.clone_from_slice(&prg[0..(EXTENDED_BATCH_SIZE / 8) as usize]);

            extended_seeds.push(prg_output);
        }

        // Step 3 - No action for the sender.

        // Step 4 - Compute the q from Fig. 10 in KOS.
        // It is computed with the matrix u sent by the receiver.
        let mut q: Vec<PRGOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            let mut q_i = [0; (EXTENDED_BATCH_SIZE / 8) as usize];
            for j in 0..EXTENDED_BATCH_SIZE / 8 {
                q_i[j as usize] = (u8::from(self.correlation[i as usize])
                    * data.u[i as usize][j as usize])
                    ^ extended_seeds[i as usize][j as usize];
            }
            q.push(q_i);
        }

        // CONSISTENCY CHECK

        // Step 1 - At this point, the sender would sample some random values to the receiver.
        // In order to reduce the round count, we adopt DKLs23 suggestion on page 30 and
        // modify this step via the Fiat-Shamir heuristic. Hence, this random value will not
        // be random but it will come from the data that the receiver has to transmit to
        // to the sender. In this case, we will simply hash the matrix u.

        // The constant m in KOS Fig. 10 is BATCH_SIZE/OT_SECURITY = 2. Thus, we need two
        // pseudorandom numbers chi1 and chi2. They have OT_SECURITY = 208 bits.
        // We can generate them with a hash.

        // This time, we are hashing the same message twice, so we put the tags 1 and 2 in the salt.
        let salt1 = [&(1u8).to_be_bytes(), session_id].concat();
        let salt2 = [&(2u8).to_be_bytes(), session_id].concat();

        // We concatenate the rows of the matrix u.
        let msg = data.u.concat();

        // We apply the hash and remove extra bytes.
        let mut chi1 = [0u8; (OT_SECURITY / 8) as usize];
        let mut chi2 = [0u8; (OT_SECURITY / 8) as usize];
        chi1.clone_from_slice(&hash(&msg, &salt1)[0..(OT_SECURITY / 8) as usize]);
        chi2.clone_from_slice(&hash(&msg, &salt2)[0..(OT_SECURITY / 8) as usize]);

        // Step 2 - No action for the sender.

        // Step 3 - Verify the values sent by the receiver against our data.
        // We start by computing the verifying vector q (as in KOS, Fig. 10).
        let mut verify_q: Vec<FieldElement> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            // The summation sign on the protocol is just the sum of the following two terms:
            let prod_qi_1 = field_mul(&q[i as usize][0..(OT_SECURITY / 8) as usize], &chi1);
            let prod_qi_2 = field_mul(
                &q[i as usize][((OT_SECURITY / 8) as usize)..((2 * OT_SECURITY / 8) as usize)],
                &chi2,
            );

            //We sum the terms to get q_i.
            let mut verify_qi = [0u8; (OT_SECURITY / 8) as usize];
            for k in 0..OT_SECURITY / 8 {
                verify_qi[k as usize] = prod_qi_1[k as usize]
                    ^ prod_qi_2[k as usize]
                    ^ q[i as usize][((2 * OT_SECURITY / 8) + k) as usize];
            }

            verify_q.push(verify_qi);
        }

        // We compute the same thing with the receiver's information.
        let mut verify_sender: Vec<FieldElement> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            let mut verify_sender_i = [0u8; (OT_SECURITY / 8) as usize];
            for k in 0..OT_SECURITY / 8 {
                verify_sender_i[k as usize] = data.verify_t[i as usize][k as usize]
                    ^ (u8::from(self.correlation[i as usize]) * data.verify_x[k as usize]);
            }

            verify_sender.push(verify_sender_i);
        }

        // The two values must agree.
        if verify_q != verify_sender {
            return Err(ErrorOT::new(
                "Receiver cheated in OTE: Consistency check failed!",
            ));
        }

        // TRANSPOSE AND RANDOMIZE

        // Step 1 - We compute the transpose of q and take the first BATCH_SIZE rows.

        let transposed_q = cut_and_transpose(&q);

        // Step 2 - No action for the sender.

        // Step 3 - We compute the final messages. For the final part, it will be better
        // if we compute them in the form Scalar<Secp256k1>.

        // IMPORTANT: This step will generate the sender's output. In this implementation,
        // we are executing the protocol ot_width times and, ideally, each execution must
        // use a different random oracle. Thus, this last part of code will be repeatedly
        // executed and the number of each iteration must appear in the hash functions.
        // We could also execute the previous steps ot_width times, but the consistency
        // checks would fail if we changed the random oracle (essentially because the
        // receiver did his part only once and with a unique random oracle).

        // For convenience, we write the correlation in "compressed form" as an array of u8.
        // We interpreted the correlation as a little-endian representation of a number.
        let mut compressed_correlation: Vec<u8> = Vec::with_capacity((KAPPA / 8) as usize);
        for i in 0..KAPPA / 8 {
            compressed_correlation.push(
                u8::from(self.correlation[(i * 8) as usize])
                    | (u8::from(self.correlation[(i * 8 + 1) as usize]) << 1)
                    | (u8::from(self.correlation[(i * 8 + 2) as usize]) << 2)
                    | (u8::from(self.correlation[(i * 8 + 3) as usize]) << 3)
                    | (u8::from(self.correlation[(i * 8 + 4) as usize]) << 4)
                    | (u8::from(self.correlation[(i * 8 + 5) as usize]) << 5)
                    | (u8::from(self.correlation[(i * 8 + 6) as usize]) << 6)
                    | (u8::from(self.correlation[(i * 8 + 7) as usize]) << 7),
            );
        }

        let mut vector_of_v0: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        let mut vector_of_v1: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v0: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            let mut v1: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                // For v1, we compute transposed_q[j] ^ correlation.
                let mut transposed_qj_plus_correlation = [0u8; (KAPPA / 8) as usize];
                for i in 0..KAPPA / 8 {
                    transposed_qj_plus_correlation[i as usize] =
                        transposed_q[j as usize][i as usize] ^ compressed_correlation[i as usize];
                }

                // This salt must depend on iteration (otherwise, v0 and v1 would be always the same).
                let salt = [
                    &j.to_be_bytes(),
                    session_id,
                    "Iteration number:".as_bytes(),
                    &iteration.to_be_bytes(),
                ]
                .concat();

                v0.push(hash_as_scalar::<C>(&transposed_q[j as usize], &salt));
                v1.push(hash_as_scalar::<C>(&transposed_qj_plus_correlation, &salt));
            }

            vector_of_v0.push(v0);
            vector_of_v1.push(v1);
        }

        // TRANSFER
        // We finished implementing Fig. 10 in KOS for the sender, which gives us
        // a random OT protocol. Now, for our use in DKLs23, we implement the
        // "Transfer" phase in Protocol 9 of DKLs18 (https://eprint.iacr.org/2018/499.pdf).

        // As before, this part is executed ot_width times.

        // Step 1 - We compute t_A and tau, as in the paper.
        // Note that t_A is just the message v0 we computed above.
        let mut vector_of_tau: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            // Retrieving the current values.
            let v0 = &vector_of_v0[iteration as usize];
            let v1 = &vector_of_v1[iteration as usize];
            let input_correlation = &input_correlations[iteration as usize];

            let mut tau: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let tau_j = v1[j as usize] - v0[j as usize] + input_correlation[j as usize];
                tau.push(tau_j);
            }

            vector_of_tau.push(tau);
        }

        // Step 2 - No action for the sender.

        // Each v0 in vector_of_v0 is the output for the sender in each iteration.
        // vector_of_tau has to be sent to the receiver.
        Ok((vector_of_v0, vector_of_tau))
    }
}

impl OTEReceiver {
    // INITIALIZE

    // According to KOS (Fig. 10), the initialization is done by applying the OT protocol
    // KAPPA times and considering the outputs as "seeds".

    // Attention: The roles are reversed during this part!
    // Hence, a receiver in the extension initializes as a sender in the base OT.

    /// Starts the initialization.
    ///
    /// In this case, it initializes and runs **as a sender** the first phase
    /// of the base OT ([`KAPPA`] times).
    ///
    /// See [`OTSender`](super::base::OTSender) for an explanation of the outputs.
    #[must_use]
    pub fn init_phase1<C: DklsCurve>(
        session_id: &[u8],
    ) -> (OTSender<C>, DLogProof<C>)
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        let ot_sender = OTSender::<C>::init(session_id);

        let dlog_proof = ot_sender.run_phase1();

        (ot_sender, dlog_proof)
    }

    /// Finishes the initialization.
    ///
    /// The inputs are the instance of [`OTSender`](super::base::OTSender) generated
    /// in the previous round and everything needed to finish the OT base protocol
    /// (see the description of the aforementioned struct).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the base OT fails (see the file above).
    pub fn init_phase2<C: DklsCurve>(
        ot_sender: &OTSender<C>,
        session_id: &[u8],
        seed: &Seed,
        enc_proofs: &[EncProof<C>],
    ) -> Result<OTEReceiver, ErrorOT>
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // The outputs from the base OT become the receiver's seeds.
        let (seeds0, seeds1) = ot_sender.run_phase2_batch(session_id, seed, enc_proofs)?;

        Ok(OTEReceiver { seeds0, seeds1 })
    }

    // PROTOCOL
    // We now follow the main steps in Fig. 10 of KOS.

    /// Runs the first phase of the receiver's protocol.
    ///
    /// Note that it is the receiver who starts the OTE protocol.
    ///
    /// Input: [`BATCH_SIZE`] choice bits.
    ///
    /// Output: Extended seeds (used in the next phase) and data to be sent to the sender.
    #[must_use]
    pub fn run_phase1(
        &self,
        session_id: &[u8],
        choice_bits: &[bool],
    ) -> (Vec<PRGOutput>, OTEDataToSender) {
        // EXTEND

        // Step 1 - Extend the choice bits by adding random noise.
        let mut random_choice_bits: Vec<bool> = Vec::with_capacity(OT_SECURITY as usize);
        for _ in 0..OT_SECURITY {
            random_choice_bits.push(rng::get_rng().gen());
        }
        let extended_choice_bits = [choice_bits, &random_choice_bits].concat();

        // For convenience, we also keep the choice bits in "compressed form" as an array of u8.
        // We interpreted extended_choice_bits as a little-endian representation of a number.
        let mut compressed_extended_bits: Vec<u8> =
            Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize);
        for i in 0..EXTENDED_BATCH_SIZE / 8 {
            compressed_extended_bits.push(
                u8::from(extended_choice_bits[(i * 8) as usize])
                    | (u8::from(extended_choice_bits[(i * 8 + 1) as usize]) << 1)
                    | (u8::from(extended_choice_bits[(i * 8 + 2) as usize]) << 2)
                    | (u8::from(extended_choice_bits[(i * 8 + 3) as usize]) << 3)
                    | (u8::from(extended_choice_bits[(i * 8 + 4) as usize]) << 4)
                    | (u8::from(extended_choice_bits[(i * 8 + 5) as usize]) << 5)
                    | (u8::from(extended_choice_bits[(i * 8 + 6) as usize]) << 6)
                    | (u8::from(extended_choice_bits[(i * 8 + 7) as usize]) << 7),
            );
        }

        // Step 2 - Extend the seeds with the pseudorandom generator (PRG).
        // The PRG will be implemented via hash functions.
        let mut extended_seeds0: Vec<PRGOutput> = Vec::with_capacity(KAPPA as usize);
        let mut extended_seeds1: Vec<PRGOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            let mut prg0: Vec<u8> = Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize); //It may use more capacity.
            let mut prg1: Vec<u8> = Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize);

            // The PRG will given by concatenating "chunks" of hash outputs.
            // The reason for this is that we need more than 256 bits.
            let mut count = 0u16;
            while prg0.len() < (EXTENDED_BATCH_SIZE / 8) as usize {
                // To change the "random oracle", we include the index and a counter into the salt.
                let salt = [&i.to_be_bytes(), &count.to_be_bytes(), session_id].concat();
                count += 1;

                let chunk0 = hash(&self.seeds0[i as usize], &salt);
                let chunk1 = hash(&self.seeds1[i as usize], &salt);

                prg0.extend_from_slice(&chunk0);
                prg1.extend_from_slice(&chunk1);
            }

            // We remove extra bytes
            let mut prg0_output = [0; (EXTENDED_BATCH_SIZE / 8) as usize];
            let mut prg1_output = [0; (EXTENDED_BATCH_SIZE / 8) as usize];
            prg0_output.clone_from_slice(&prg0[0..(EXTENDED_BATCH_SIZE / 8) as usize]);
            prg1_output.clone_from_slice(&prg1[0..(EXTENDED_BATCH_SIZE / 8) as usize]);

            extended_seeds0.push(prg0_output);
            extended_seeds1.push(prg1_output);
        }

        // Step 3 - Compute the matrix u from Fig. 10 in KOS.
        // This matrix will be sent to the sender.
        let mut u: Vec<PRGOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            let mut u_i = [0; (EXTENDED_BATCH_SIZE / 8) as usize];
            for j in 0..EXTENDED_BATCH_SIZE / 8 {
                u_i[j as usize] = extended_seeds0[i as usize][j as usize]
                    ^ extended_seeds1[i as usize][j as usize]
                    ^ compressed_extended_bits[j as usize];
            }
            u.push(u_i);
        }

        // Step 4 - No action for the receiver.

        // CONSISTENCY CHECK

        // Step 1 - At this point, the sender would sample some random values to the receiver.
        // In order to reduce the round count, we adopt DKLs23 suggestion on page 30 and
        // modify this step via the Fiat-Shamir heuristic. Hence, this random value will not
        // be random but it will come from the data that the receiver has to transmit to
        // to the sender. In this case, we will simply hash the matrix u.

        // The constant m in KOS Fig. 10 is BATCH_SIZE/OT_SECURITY = 2. Thus, we need two
        // pseudorandom numbers chi1 and chi2. They have OT_SECURITY = 208 bits.
        // We can generate them with a hash.

        // This time, we are hashing the same message twice, so we put the tags 1 and 2 in the salt.
        let salt1 = [&(1u8).to_be_bytes(), session_id].concat();
        let salt2 = [&(2u8).to_be_bytes(), session_id].concat();

        // We concatenate the rows of the matrix u.
        let msg = u.concat();

        // We apply the hash and remove extra bytes.
        let mut chi1 = [0u8; (OT_SECURITY / 8) as usize];
        let mut chi2 = [0u8; (OT_SECURITY / 8) as usize];
        chi1.clone_from_slice(&hash(&msg, &salt1)[0..(OT_SECURITY / 8) as usize]);
        chi2.clone_from_slice(&hash(&msg, &salt2)[0..(OT_SECURITY / 8) as usize]);

        // Step 2 - We compute the verification values to the sender.

        // The summation sign on the protocol is just the sum of the following two terms:
        let prod_x_1 = field_mul(
            &compressed_extended_bits[0..(OT_SECURITY / 8) as usize],
            &chi1,
        );
        let prod_x_2 = field_mul(
            &compressed_extended_bits
                [((OT_SECURITY / 8) as usize)..((2 * OT_SECURITY / 8) as usize)],
            &chi2,
        );

        // We sum the terms to get x.
        let mut verify_x = [0u8; (OT_SECURITY / 8) as usize];
        for k in 0..OT_SECURITY / 8 {
            verify_x[k as usize] = prod_x_1[k as usize]
                ^ prod_x_2[k as usize]
                ^ compressed_extended_bits[((2 * OT_SECURITY / 8) + k) as usize];
        }

        let mut verify_t: Vec<FieldElement> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            // The summation sign on the protocol is just the sum of the following two terms:
            let prod_ti_1 = field_mul(
                &extended_seeds0[i as usize][0..(OT_SECURITY / 8) as usize],
                &chi1,
            );
            let prod_ti_2 = field_mul(
                &extended_seeds0[i as usize]
                    [((OT_SECURITY / 8) as usize)..((2 * OT_SECURITY / 8) as usize)],
                &chi2,
            );

            //We sum the terms to get t_i.
            let mut verify_ti = [0u8; (OT_SECURITY / 8) as usize];
            for k in 0..OT_SECURITY / 8 {
                verify_ti[k as usize] = prod_ti_1[k as usize]
                    ^ prod_ti_2[k as usize]
                    ^ extended_seeds0[i as usize][((2 * OT_SECURITY / 8) + k) as usize];
            }

            verify_t.push(verify_ti);
        }

        // Step 3 - No action for the receiver.

        // These values are transmitted to the sender.
        let data_to_sender = OTEDataToSender {
            u,
            verify_x,
            verify_t,
        };

        // extended_seeds0 has to be kept for the next phase.
        (extended_seeds0, data_to_sender)
    }

    /// Finishes the receiver's protocol and gives his output.
    ///
    /// Input: Previous inputs, the OT width (see the remark [here](super::extension)),
    /// the `extended_seeds` from the previous phase and the vector of values tau sent
    /// by the sender.
    ///
    /// Output: Protocol's output. The usual output would be just a vector of [`BATCH_SIZE`]
    /// scalars. However, we are executing the protocol `ot_width` times, so the result
    /// is a vector containing `ot_width` such vectors.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the length of `vector_of_tau` is not `ot_width`.
    pub fn run_phase2<C: DklsCurve>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        choice_bits: &[bool],
        extended_seeds: &[PRGOutput],
        vector_of_tau: &[Vec<C::Scalar>],
    ) -> Result<Vec<Vec<C::Scalar>>, ErrorOT>
    where
        C::Scalar: Reduce<U256>,
    {
        // IMPORTANT: Since the sender executed its part with our data ot_width times,
        // our final result will be ot_width times the usual result we would get.
        // But first, we check that the sender gave us a message with the correct length.
        if vector_of_tau.len() != ot_width as usize {
            return Err(ErrorOT::new(
                "The vector sent by the sender does not have the expected size!",
            ));
        }

        // TRANSPOSE AND RANDOMIZE

        // Step 1 - We compute the transpose of extended_seeds and take the first BATCH_SIZE rows.

        let transposed_t = cut_and_transpose(extended_seeds);

        // Step 2 - We compute the final message. For the final part, it will be better
        // if we compute it in the form Scalar<Secp256k1>.

        // As stated for the sender, we run this part ot_width times with varying salts.
        let mut vector_of_v: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let salt = [
                    &j.to_be_bytes(),
                    session_id,
                    "Iteration number:".as_bytes(),
                    &iteration.to_be_bytes(),
                ]
                .concat();
                v.push(hash_as_scalar::<C>(&transposed_t[j as usize], &salt));
            }

            vector_of_v.push(v);
        }

        // Step 3 - No action for the receiver.

        // TRANSFER
        // We finished implementing Fig. 10 in KOS for the receiver, which gives us
        // a random OT protocol. Now, for our use in DKLs23, we implement the
        // "Transfer" phase in Protocol 9 of DKLs18 (https://eprint.iacr.org/2018/499.pdf).

        // Step 1 - No action for the receiver.

        // Step 2 - We compute t_B as in the paper. We use the value tau sent by the sender.

        // Again, we repeat this step ot_width times.

        let mut vector_of_t_b: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            // Retrieving the current values.
            let v = &vector_of_v[iteration as usize];
            let tau = &vector_of_tau[iteration as usize];

            let mut t_b: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let mut t_b_j = -v[j as usize];
                if choice_bits[j as usize] {
                    t_b_j = tau[j as usize] + t_b_j;
                }
                t_b.push(t_b_j);
            }

            vector_of_t_b.push(t_b);
        }

        // Each t_b in vector_of_t_b is the output for the receiver in each iteration.
        Ok(vector_of_t_b)
    }
}

// EXTRA FUNCTIONS

/// Transposes a given matrix.
///
/// This function receives a [`KAPPA`] by [`EXTENDED_BATCH_SIZE`] matrix of booleans,
/// takes the first [`BATCH_SIZE`] columns and computes the transpose matrix, which
/// has [`BATCH_SIZE`] rows and [`KAPPA`] columns.
///
/// The only problem is that the rows in the input and output are grouped in
/// bytes, so we have to take some care. For this conversion, we think of
/// the rows as a little-endian representation of a number. For example, the row
/// \[1110000010100000\] corresponds to \[7, 5\] in bytes (and not \[224,160\]).
///
/// This code was essentially copied from the function `transposeBooleanMatrix` here:
/// <https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos.go>.
#[must_use]
pub fn cut_and_transpose(input: &[PRGOutput]) -> Vec<HashOutput> {
    // We initialize the output as a zero matrix.
    let mut output: Vec<HashOutput> = vec![[0u8; (KAPPA / 8) as usize]; BATCH_SIZE as usize];

    for row_byte in 0..KAPPA / 8 {
        for row_bit_within_byte in 0..8 {
            // The next loop should go up to EXTENDED_BATCH_SIZE/8 if we wanted
            // to compute the actual transpose, so it is here that we do the cut.
            for column_byte in 0..BATCH_SIZE / 8 {
                for column_bit_within_byte in 0..8 {
                    // If we see input as a matrix of booleans, we want to
                    // take the element input[row_bit][column_bit].
                    let row_bit = (row_byte << 3) + row_bit_within_byte;
                    let column_bit = (column_byte << 3) + column_bit_within_byte;

                    // In every row, the columns are packed in bytes.
                    // We access the row_bit-th row, then the column_byte-th byte,
                    // and then we extract the desired bit.
                    let entry = (input[row_bit as usize][column_byte as usize]
                        >> column_bit_within_byte)
                        & 0x01;

                    // If we see output as a matrix of booleans, we want to
                    // write output[column_bit][row_bit] = entry;
                    // However, each row of output is also packed in bytes.
                    // Hence, we access the column_bit-th row, then the row_byte-th byte,
                    // and finally we put our bit in the correct place.
                    let shifted_entry = entry << row_bit_within_byte;
                    output[column_bit as usize][row_byte as usize] |= shifted_entry;
                }
            }
        }
    }

    output
}

/// Multiplication in the finite field of order 2^[`OT_SECURITY`]].
///
/// We follow <https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos.go>.
///
/// It is based on Algorithm 2.34 ("Right-to-left comb method for polynomial multiplication")
/// and Figure 2.9 (for reduction modulo the irreducible polynomial) of the book
/// Guide to Elliptic Curve Cryptography by Hankerson, Menezes and Vanstone.
///
/// # Panics
///
/// Will panic if `left` or `right` doesn't have the correct size, that is [`OT_SECURITY`] = 208 bits.
#[must_use]
pub fn field_mul(left: &[u8], right: &[u8]) -> FieldElement {
    // Constants W and t from Section 2.3 in the book.
    const W: u8 = 64;
    const T: u8 = 4;

    assert!(
        (left.len() == (OT_SECURITY / 8) as usize) && (right.len() == (OT_SECURITY / 8) as usize),
        "Binary field multiplication: Entries don't have the correct length!"
    );

    let mut a = [0u64; T as usize];
    let mut b = [0u64; (T + 1) as usize]; //b has extra space because it will be shifted.
    let mut c = [0u64; (2 * T) as usize];

    // Conversion of [u8; 26] to [u64; 4].
    for i in 0..OT_SECURITY / 8 {
        a[(i >> 3) as usize] |= u64::from(left[i as usize]) << ((i & 0x07) << 3);
        b[(i >> 3) as usize] |= u64::from(right[i as usize]) << ((i & 0x07) << 3);
    }

    // Algorithm 2.34 (page 49)
    for k in 0..W {
        for j in 0..T {
            //If the k-th bit of a[j] is 1, we add b to c (with the correct shift).
            if (a[j as usize] >> k) % 2 == 1 {
                for i in 0..=T {
                    c[(j + i) as usize] ^= b[i as usize];
                }
            }
        }

        // We shift b one digit to the left (not necessary in the last iteration)
        if k != W - 1 {
            for i in (1..=T).rev() {
                b[i as usize] = b[i as usize] << 1 | b[(i - 1) as usize] >> 63;
            }
        }
        b[0] <<= 1;
    }

    // For the moment, c is just the usual product of the two polynomials.
    // We have to reduce it modulo the polynomial f(X) = X^208 + X^9 + X^3 + X + 1
    // (according to Table A.1 on page 259).

    // We adapt the idea presented on page 54.

    for i in (T..(2 * T)).rev() {
        let t = c[i as usize];

        // The current block is reduced. Note that 208 = 3*64 + 16.
        // Hence, we skip 3 blocks and in the fourth block we put 16
        // bits of t (this is the t << 48 part). The remaining digits
        // go to the third block (this is the t >> 16 part).
        // Actually, this happens for every monomial in f(X), except
        // for X^208. Note that the difference between consecutive
        // numbers below is the same as the differences in the sequence
        // (9,3,1,0), which are the exponents in the monomials.
        c[(i - 4) as usize] ^= (t << 57) ^ (t << 51) ^ (t << 49) ^ (t << 48);
        c[(i - 3) as usize] ^= (t >> 7) ^ (t >> 13) ^ (t >> 15) ^ (t >> 16);

        // Erase the block that was reduced.
        c[i as usize] = 0;
    }
    // The block c[T-1] doesn't need to be reduced in its entirety,
    // only its first 64 - 16 = 48 bits.
    let t = c[(T - 1) as usize] >> 16;
    c[0] ^= (t << 9) ^ (t << 3) ^ (t << 1) ^ t;

    // We save only the last 16 bits (note that 0xFFFF = 0b11...11 with 16 one's).
    c[(T - 1) as usize] &= 0xFFFF;

    // At this point, c is the product of a and b in the finite field.

    // We convert the result to the original format.
    let mut result = [0u8; (OT_SECURITY / 8) as usize];
    for i in 0..OT_SECURITY / 8 {
        result[i as usize] = u8::try_from((c[(i >> 3) as usize] >> ((i & 0x07) << 3)) & 0xFF)
            .expect("This value fits into an u8!");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::hashes::scalar_to_bytes;
    use elliptic_curve::CurveArithmetic;
    use elliptic_curve::Field;
    use rand::Rng;
    use std::collections::HashSet;

    // All tests use secp256k1 as the concrete curve, matching the original
    // hard-coded behaviour.
    type C = k256::Secp256k1;
    type Scalar = <C as CurveArithmetic>::Scalar;

    /// Tests if [`field_mul`] is correctly computing
    /// the multiplication in the finite field.
    ///
    /// It is based on the test found here:
    /// <https://github.com/coinbase/kryptology/blob/master/pkg/ot/extension/kos/kos_test.go>.
    #[test]
    fn test_field_mul() {
        for _ in 0..100 {
            let initial = rng::get_rng().gen::<FieldElement>();

            //Raising an element to the power 2^208 must not change it.
            let mut result = initial;
            for _ in 0..OT_SECURITY {
                result = field_mul(&result, &result);
            }

            assert_eq!(initial, result);
        }
    }

    /// Tests if the outputs for the OTE protocol
    /// satisfy the relations they are supposed to satisfy.
    #[test]
    fn test_ot_extension() {
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // INITIALIZATION

        // Phase 1 - Receiver
        let (ot_sender, dlog_proof) = OTEReceiver::init_phase1::<C>(&session_id);

        // Phase 1 - Sender
        let (ot_receiver, correlation, vec_r, enc_proofs) =
            OTESender::init_phase1::<C>(&session_id);

        // Communication round (Exchange the proofs and the seed)
        let seed = ot_receiver.seed;

        // Phase 2 - Receiver
        let result_receiver =
            OTEReceiver::init_phase2::<C>(&ot_sender, &session_id, &seed, &enc_proofs);
        let ote_receiver = match result_receiver {
            Ok(r) => r,
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            }
        };

        // Phase 2 - Sender
        let result_sender =
            OTESender::init_phase2::<C>(&ot_receiver, &session_id, correlation, &vec_r, &dlog_proof);
        let ote_sender = match result_sender {
            Ok(s) => s,
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            }
        };

        // PROTOCOL

        let ot_width = 4;

        // Sampling the choices.
        let mut sender_input_correlations: Vec<Vec<Scalar>> = Vec::with_capacity(ot_width as usize);
        for _ in 0..ot_width {
            let mut current_input_correlation: Vec<Scalar> =
                Vec::with_capacity(BATCH_SIZE as usize);
            for _ in 0..BATCH_SIZE {
                current_input_correlation.push(Scalar::random(rng::get_rng()));
            }
            sender_input_correlations.push(current_input_correlation);
        }

        let mut receiver_choice_bits: Vec<bool> = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            receiver_choice_bits.push(rng::get_rng().gen());
        }

        // Phase 1 - Receiver
        let (extended_seeds, data_to_sender) =
            ote_receiver.run_phase1(&session_id, &receiver_choice_bits);

        // Communication round 1
        // Receiver keeps extended_seeds and transmits data_to_sender.

        // Unique phase - Sender
        let sender_result = ote_sender.run::<C>(
            &session_id,
            ot_width,
            &sender_input_correlations,
            &data_to_sender,
        );

        let sender_outputs: Vec<Vec<Scalar>>;
        let vector_of_tau: Vec<Vec<Scalar>>;
        match sender_result {
            Ok((v0, t)) => {
                (sender_outputs, vector_of_tau) = (v0, t);
            }
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            }
        }

        // Communication round 2
        // Sender transmits tau.

        // Phase 2 - Receiver
        let receiver_result = ote_receiver.run_phase2::<C>(
            &session_id,
            ot_width,
            &receiver_choice_bits,
            &extended_seeds,
            &vector_of_tau,
        );

        let receiver_outputs = match receiver_result {
            Ok(t_b) => t_b,
            Err(error) => {
                panic!("OTE error: {:?}", error.description);
            }
        };

        // Verification that the protocol did what it should do.

        let mut sender_outputs_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(ot_width as usize);
        let mut receiver_outputs_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(ot_width as usize);

        for iteration in 0..ot_width {
            for i in 0..BATCH_SIZE {
                //Depending on the choice the receiver made, the sum of the outputs should
                //be equal to 0 or to the correlation the sender chose.
                let sum = sender_outputs[iteration as usize][i as usize]
                    + receiver_outputs[iteration as usize][i as usize];
                if receiver_choice_bits[i as usize] {
                    assert_eq!(
                        sum,
                        sender_input_correlations[iteration as usize][i as usize]
                    );
                } else {
                    assert_eq!(sum, Scalar::ZERO);
                }
            }

            // We save these outputs in bytes for the next verification.
            sender_outputs_as_bytes.push(
                sender_outputs[iteration as usize]
                    .clone()
                    .into_iter()
                    .map(|x| scalar_to_bytes::<C>(&x))
                    .collect::<Vec<Vec<u8>>>()
                    .concat(),
            );
            receiver_outputs_as_bytes.push(
                receiver_outputs[iteration as usize]
                    .clone()
                    .into_iter()
                    .map(|x| scalar_to_bytes::<C>(&x))
                    .collect::<Vec<Vec<u8>>>()
                    .concat(),
            );
        }

        // We confirm that there are not repeated outputs.
        let mut sender_without_repetitions: HashSet<Vec<u8>> =
            HashSet::with_capacity(ot_width as usize);
        if !sender_outputs_as_bytes
            .into_iter()
            .all(move |x| sender_without_repetitions.insert(x))
        {
            panic!("Very improbable/unexpected: The sender got two identic outputs!");
        }

        let mut receiver_without_repetitions: HashSet<Vec<u8>> =
            HashSet::with_capacity(ot_width as usize);
        if !receiver_outputs_as_bytes
            .into_iter()
            .all(move |x| receiver_without_repetitions.insert(x))
        {
            panic!("Very improbable/unexpected: The receiver got two identic outputs!");
        }

        //TODO - We included this last check because an old implementation was wrong
        //       and was generating repeated outputs for the sender. A more appropriate
        //       test would be to run this test many times and attest that there is no
        //       noticeable correlation between the outputs.
    }
}
