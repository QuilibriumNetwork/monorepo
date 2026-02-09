//! Random Vector OLE functionality from `DKLs23`.
//!
//! This file realizes Functionality 3.5 in `DKLs23` (<https://eprint.iacr.org/2023/765.pdf>).
//! It is based upon the OT extension protocol [here](super::ot::extension).
//!
//! As `DKLs23` suggested, we use Protocol 1 of `DKLs19` (<https://eprint.iacr.org/2019/523.pdf>).
//! The first paper also gives some orientations on how to implement the protocol
//! in only two-rounds (see page 8 and Section 5.1) which we adopt here.

use elliptic_curve::bigint::U256;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::Reduce;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::{Field, PrimeField};
use serde::{Deserialize, Serialize};

use crate::utilities::hashes::{hash, hash_as_scalar, scalar_to_bytes, HashOutput};
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::rng;
use crate::DklsCurve;

use super::ot::extension::{deserialize_vec_prg, serialize_vec_prg};
use crate::utilities::ot::base::{OTReceiver, OTSender, Seed};
use crate::utilities::ot::extension::{
    OTEDataToSender, OTEReceiver, OTESender, PRGOutput, BATCH_SIZE,
};
use crate::utilities::ot::ErrorOT;
use rand::Rng;

/// Constant `L` from Functionality 3.5 in `DKLs23` used for signing in Protocol 3.6.
pub const L: u8 = 2;

/// This represents the number of times the OT extension protocol will be
/// called using the same value chosen by the receiver.
pub const OT_WIDTH: u8 = 2 * L;

/// Sender's data and methods for the multiplication protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MulSender<C: CurveArithmetic> {
    pub public_gadget: Vec<C::Scalar>,
    pub ote_sender: OTESender,
}

/// Receiver's data and methods for the multiplication protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MulReceiver<C: CurveArithmetic> {
    pub public_gadget: Vec<C::Scalar>,
    pub ote_receiver: OTEReceiver,
}

/// Data transmitted by the sender to the receiver after his phase.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MulDataToReceiver<C: CurveArithmetic> {
    pub vector_of_tau: Vec<Vec<C::Scalar>>,
    pub verify_r: HashOutput,
    pub verify_u: Vec<C::Scalar>,
    pub gamma_sender: Vec<C::Scalar>,
}

/// Data kept by the receiver between phases.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MulDataToKeepReceiver<C: CurveArithmetic> {
    pub b: C::Scalar,
    pub choice_bits: Vec<bool>,
    #[serde(
        serialize_with = "serialize_vec_prg",
        deserialize_with = "deserialize_vec_prg"
    )]
    pub extended_seeds: Vec<PRGOutput>,
    pub chi_tilde: Vec<C::Scalar>,
    pub chi_hat: Vec<C::Scalar>,
}

/// Represents an error during the multiplication protocol.
pub struct ErrorMul {
    pub description: String,
}

impl ErrorMul {
    /// Creates an instance of `ErrorMul`.
    #[must_use]
    pub fn new(description: &str) -> ErrorMul {
        ErrorMul {
            description: String::from(description),
        }
    }
}

// We implement the protocol.
impl<C: DklsCurve> MulSender<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding,
{
    // INITIALIZE

    // As in DKLs19 (https://eprint.iacr.org/2019/523.pdf), the initialization of the
    // multiplication protocol is the same as for our OT extension protocol.
    // Thus, we repeat the phases from the file ot_extension.rs.
    // The only difference is that we include the sampling for the public gadget vector.

    /// Starts the initialization of the protocol.
    ///
    /// See [`OTESender`](super::ot::extension::OTESender) for explanation.
    #[must_use]
    pub fn init_phase1(session_id: &[u8]) -> (OTReceiver, Vec<bool>, Vec<C::Scalar>, Vec<EncProof<C>>) {
        OTESender::init_phase1::<C>(session_id)
    }

    /// Finishes the initialization of the protocol.
    ///
    /// The inputs here come from [`OTESender`](super::ot::extension::OTESender),
    /// except for `nonce`, which was sent by the receiver for the
    /// computation of the public gadget vector.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the initialization fails (see the file above).
    pub fn init_phase2(
        ot_receiver: &OTReceiver,
        session_id: &[u8],
        correlation: Vec<bool>,
        vec_r: &[C::Scalar],
        dlog_proof: &DLogProof<C>,
        nonce: &C::Scalar,
    ) -> Result<MulSender<C>, ErrorOT> {
        let ote_sender =
            OTESender::init_phase2::<C>(ot_receiver, session_id, correlation, vec_r, dlog_proof)?;

        // We compute the public gadget vector from the nonce, in the same way as in
        // https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        let mut public_gadget: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut counter = *nonce;
        for _ in 0..BATCH_SIZE {
            counter += C::Scalar::ONE;
            public_gadget.push(hash_as_scalar::<C>(&scalar_to_bytes::<C>(&counter), session_id));
        }

        let mul_sender = MulSender {
            public_gadget,
            ote_sender,
        };

        Ok(mul_sender)
    }

    // PROTOCOL
    // We now follow the steps of Protocol 1 in DKLs19, implementing
    // the suggestions of DKLs23 as well.

    // It is worth pointing out that the parameter l from DKLs19 is not
    // the same as the parameter l from DKLs23. To highlight the difference,
    // we will always denote the DKLs23 parameter by a capital L.

    /// Runs the sender's protocol.
    ///
    /// Input: [`L`] instances of `Scalar` and data coming from receiver.
    ///
    /// Output: Protocol's output and data to receiver.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the underlying OT extension fails (see [`OTESender`](super::ot::extension::OTESender)).
    pub fn run(
        &self,
        session_id: &[u8],
        input: &[C::Scalar],
        data: &OTEDataToSender,
    ) -> Result<(Vec<C::Scalar>, MulDataToReceiver<C>), ErrorMul> {
        // RANDOMIZED MULTIPLICATION

        // Step 1 - No action for the sender.

        // Step 2 - We sample the pads a_tilde and the check values a_hat.
        // We also set the correlation for the OT protocol.

        // There are L pads and L check_values.
        let mut a_tilde: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        let mut a_hat: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for _ in 0..L {
            a_tilde.push(C::Scalar::random(rng::get_rng()));
            a_hat.push(C::Scalar::random(rng::get_rng()));
        }

        // For the correlation, let us first explain the case L = 1.
        // In this case, there are actually two correlations: one is
        // made with BATCH_SIZE copies of a_tilde and the other with
        // BATCH_SIZE copies of a_hat. We use two correlations in order
        // to get two outputs, as in DKLs19. Both of them will be used
        // in the OT extension with the same choice bits from the receiver.
        //
        // Now, by DKLs23, we hardcoded l = 1 in DKLs19. At the same time,
        // DKLs23 has its parameter L. To adapt the old protocol, we repeat
        // Step 2 in DKLs19 L times, so in the end we get 2*L correlations.
        let mut correlation_tilde: Vec<Vec<C::Scalar>> = Vec::with_capacity(L as usize);
        let mut correlation_hat: Vec<Vec<C::Scalar>> = Vec::with_capacity(L as usize);
        for i in 0..L {
            let correlation_tilde_i = vec![a_tilde[i as usize]; BATCH_SIZE as usize];
            let correlation_hat_i = vec![a_hat[i as usize]; BATCH_SIZE as usize];

            correlation_tilde.push(correlation_tilde_i);
            correlation_hat.push(correlation_hat_i);
        }

        // We gather the correlations.
        let correlations = [correlation_tilde, correlation_hat].concat();

        // Step 3 - We execute the OT protocol.

        // It is here that we use the "forced-reuse" technique that
        // DKLs23 mentions on page 8. As they say: "Alice performs the
        // steps of the protocol for each input in her vector, but uses
        // a single batch of Bob's OT instances for all of them,
        // concatenating the corresponding OT payloads to form one batch
        // of payloads with lengths proportionate to her input vector length."
        //
        // Hence, the OT extension protocol will be executed 2*L times with
        // the 2*L correlations from the previous step. The implementation
        // in the file ot/extension.rs already deals with these repetitions,
        // we just have to specify this quantity (the "OT width").

        let ote_sid = ["OT Extension protocol".as_bytes(), session_id].concat();

        let result = self.ote_sender.run::<C>(&ote_sid, OT_WIDTH, &correlations, data);

        let ot_outputs: Vec<Vec<C::Scalar>>;
        let vector_of_tau: Vec<Vec<C::Scalar>>; // Used by the receiver to finish the OT protocol.
        match result {
            Ok((out, tau)) => {
                (ot_outputs, vector_of_tau) = (out, tau);
            }
            Err(error) => {
                return Err(ErrorMul::new(&format!(
                    "OTE error during multiplication: {:?}",
                    error.description
                )));
            }
        }

        // This is the sender's output from the OT protocol with the notation from DKLs19.
        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

        // Step 4 - We compute the shared random values.

        // We use data as a transcript from Step 3.
        let transcript = [
            data.u.concat(),
            data.verify_x.to_vec(),
            data.verify_t.concat(),
        ]
        .concat();

        // At this point, the constant L from DKLs23 behaves as the
        // constant l from DKLs19.
        let mut chi_tilde: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        let mut chi_hat: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            // We compute the salts according to i and the variable.
            let salt_tilde = [&(1u8).to_be_bytes(), &i.to_be_bytes(), session_id].concat();
            let salt_hat = [&(2u8).to_be_bytes(), &i.to_be_bytes(), session_id].concat();

            chi_tilde.push(hash_as_scalar::<C>(&transcript, &salt_tilde));
            chi_hat.push(hash_as_scalar::<C>(&transcript, &salt_hat));
        }

        // Step 5 - We compute the verification value.
        // We use Section 5.1 in DKLs23 for an optimization of the
        // protocol in DKLs19.

        // We have to compute a matrix r and a vector u.
        // Only a hash of r will be sent to the receiver,
        // so we'll compute r directly in bytes.
        // The variable below saves each row of r in bytes.
        let mut rows_r_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        let mut verify_u: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            // We compute the i-th row of the matrix r in bytes.
            let mut entries_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let entry = (chi_tilde[i as usize] * z_tilde[i as usize][j as usize])
                    + (chi_hat[i as usize] * z_hat[i as usize][j as usize]);
                let entry_as_bytes = scalar_to_bytes::<C>(&entry);
                entries_as_bytes.push(entry_as_bytes);
            }
            let row_i_as_bytes = entries_as_bytes.concat();
            rows_r_as_bytes.push(row_i_as_bytes);

            // We compute the i-th entry of the vector u.
            let entry = (chi_tilde[i as usize] * a_tilde[i as usize])
                + (chi_hat[i as usize] * a_hat[i as usize]);
            verify_u.push(entry);
        }
        let r_as_bytes = rows_r_as_bytes.concat();

        // We transform r into a hash.
        let verify_r: HashOutput = hash(&r_as_bytes, session_id);

        // Step 6 - No action for the sender.

        // INPUT AND ADJUSTMENT

        // Step 7 - We compute the difference gamma_A.

        let mut gamma: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            let difference = input[i as usize] - a_tilde[i as usize];
            gamma.push(difference);
        }

        // Step 8 - Finally, we compute the protocol's output.
        // Recall that we hardcoded gamma_B = 0.

        let mut output: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            let mut summation = C::Scalar::ZERO;
            for j in 0..BATCH_SIZE {
                summation += self.public_gadget[j as usize] * z_tilde[i as usize][j as usize];
            }
            output.push(summation);
        }

        // We now return all values.

        let data_to_receiver = MulDataToReceiver {
            vector_of_tau,
            verify_r,
            verify_u,
            gamma_sender: gamma,
        };

        Ok((output, data_to_receiver))
    }
}

impl<C: DklsCurve> MulReceiver<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding,
{
    // INITIALIZE

    // As in DKLs19 (https://eprint.iacr.org/2019/523.pdf), the initialization of the
    // multiplication protocol is the same as for our OT extension protocol.
    // Thus, we repeat the phases from the file ot_extension.rs.
    // The only difference is that we include the sampling for the public gadget vector.

    /// Starts the initialization of the protocol.
    ///
    /// See [`OTEReceiver`](super::ot::extension::OTEReceiver) for explanation.
    ///
    /// The `Scalar` does not come from the OT extension. It is just
    /// a nonce for the generation of the public gadget vector. It should
    /// be kept for the next phase and transmitted to the sender.
    #[must_use]
    pub fn init_phase1(session_id: &[u8]) -> (OTSender<C>, DLogProof<C>, C::Scalar) {
        let (ot_sender, proof) = OTEReceiver::init_phase1::<C>(session_id);

        // For the choice of the public gadget vector, we will use the same approach
        // as in https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        // We sample a nonce that will be used by both parties to compute a common vector.
        let nonce = C::Scalar::random(rng::get_rng());

        (ot_sender, proof, nonce)
    }

    /// Finishes the initialization of the protocol.
    ///
    /// The inputs here come from [`OTEReceiver`](super::ot::extension::OTEReceiver),
    /// except for `nonce`, which was generated during the previous phase.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the initialization fails (see the file above).
    pub fn init_phase2(
        ot_sender: &OTSender<C>,
        session_id: &[u8],
        seed: &Seed,
        enc_proofs: &[EncProof<C>],
        nonce: &C::Scalar,
    ) -> Result<MulReceiver<C>, ErrorOT> {
        let ote_receiver = OTEReceiver::init_phase2::<C>(ot_sender, session_id, seed, enc_proofs)?;

        // We compute the public gadget vector from the nonce, in the same way as in
        // https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/mul.rs.
        let mut public_gadget: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut counter = *nonce;
        for _ in 0..BATCH_SIZE {
            counter += C::Scalar::ONE;
            public_gadget.push(hash_as_scalar::<C>(&scalar_to_bytes::<C>(&counter), session_id));
        }

        let mul_receiver = MulReceiver {
            public_gadget,
            ote_receiver,
        };

        Ok(mul_receiver)
    }

    // PROTOCOL
    // We now follow the steps of Protocol 1 in DKLs19, implementing
    // the suggestions of DKLs23 as well.

    // It is worth pointing out that the parameter l from DKLs19 is not
    // the same as the parameter l from DKLs23. To highlight the difference,
    // we will always denote the DKLs23 parameter by a capital L.

    /// Runs the first phase of the receiver's protocol.
    ///
    /// Note that it is the receiver who starts the multiplication protocol.
    ///
    /// The random factor coming from the protocol is already returned here.
    /// There are two other outputs: one to be kept for the next phase
    /// and one to be sent to the sender (related to the OT extension).
    #[must_use]
    pub fn run_phase1(
        &self,
        session_id: &[u8],
    ) -> (C::Scalar, MulDataToKeepReceiver<C>, OTEDataToSender) {
        // RANDOMIZED MULTIPLICATION

        // Step 1 - We sample the choice bits and compute the pad b_tilde.

        // Since we are hardcoding gamma_B = 0, b_tilde will serve as the
        // number b that the receiver inputs into the protocol. Hence, we
        // will denote b_tilde simply as b.

        let mut choice_bits: Vec<bool> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut b = C::Scalar::ZERO;
        for i in 0..BATCH_SIZE {
            let current_bit: bool = rng::get_rng().gen();
            if current_bit {
                b += &self.public_gadget[i as usize];
            }
            choice_bits.push(current_bit);
        }

        // Step 2 - No action for the receiver.

        // Step 3 (Incomplete) - We start the OT extension protocol.

        // Note that this protocol has one more round, so the receiver
        // cannot get the output immediately. This will only be computed
        // at the beginning of the next phase for the receiver.

        let ote_sid = ["OT Extension protocol".as_bytes(), session_id].concat();

        let (extended_seeds, data_to_sender) = self.ote_receiver.run_phase1(&ote_sid, &choice_bits);

        // Step 4 - We compute the shared random values.

        // We use data_to_sender as a transcript from Step 3.
        let transcript = [
            data_to_sender.u.concat(),
            data_to_sender.verify_x.to_vec(),
            data_to_sender.verify_t.concat(),
        ]
        .concat();

        // At this point, the constant L from DKLs23 behaves as the
        // constant l from DKLs19.
        let mut chi_tilde: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        let mut chi_hat: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            // We compute the salts according to i and the variable.
            let salt_tilde = [&(1u8).to_be_bytes(), &i.to_be_bytes(), session_id].concat();
            let salt_hat = [&(2u8).to_be_bytes(), &i.to_be_bytes(), session_id].concat();

            chi_tilde.push(hash_as_scalar::<C>(&transcript, &salt_tilde));
            chi_hat.push(hash_as_scalar::<C>(&transcript, &salt_hat));
        }

        // Step 5 - No action for the receiver, but he will receive
        // some values for the next step, so we stop here.

        // We now return all values.

        let data_to_keep = MulDataToKeepReceiver {
            b,
            choice_bits,
            extended_seeds,
            chi_tilde,
            chi_hat,
        };

        (b, data_to_keep, data_to_sender)
    }

    /// Finishes the receiver's protocol and gives his output.
    ///
    /// The inputs are the data kept from the previous phase and
    /// the data transmitted by the sender.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the consistency check using the sender values fails
    /// or if the underlying OT extension fails (see [`OTEReceiver`](super::ot::extension::OTEReceiver)).
    pub fn run_phase2(
        &self,
        session_id: &[u8],
        data_kept: &MulDataToKeepReceiver<C>,
        data_received: &MulDataToReceiver<C>,
    ) -> Result<Vec<C::Scalar>, ErrorMul> {
        // Step 3 (Conclusion) - We conclude the OT protocol.

        // The sender applied the protocol 2*L times with our data,
        // so we will have 2*L outputs (we refer to this number as
        // the "OT width").

        let ote_sid = ["OT Extension protocol".as_bytes(), session_id].concat();

        let result = self.ote_receiver.run_phase2::<C>(
            &ote_sid,
            OT_WIDTH,
            &data_kept.choice_bits,
            &data_kept.extended_seeds,
            &data_received.vector_of_tau,
        );

        let ot_outputs: Vec<Vec<C::Scalar>> = match result {
            Ok(out) => out,
            Err(error) => {
                return Err(ErrorMul::new(&format!(
                    "OTE error during multiplication: {:?}",
                    error.description
                )));
            }
        };

        // This is the receiver's output from the OT protocol with the notation from DKLs19.
        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

        // Step 6 - We verify if the data sent by the sender is consistent.

        // We use Section 5.1 in DKLs23 for an optimization of the
        // protocol in DKLs19.

        // We have to compute a matrix r and a vector u.
        // Only a hash of r will be sent to us so we'll
        // reconstruct r directly in bytes.
        // The variable below saves each row of r in bytes.
        let mut rows_r_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        for i in 0..L {
            // We compute the i-th row of the matrix r in bytes.
            let mut entries_as_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                // The entry depends on the choice bits.
                let mut entry = (-(data_kept.chi_tilde[i as usize]
                    * z_tilde[i as usize][j as usize]))
                    - (data_kept.chi_hat[i as usize] * z_hat[i as usize][j as usize]);
                if data_kept.choice_bits[j as usize] {
                    entry += &data_received.verify_u[i as usize];
                }

                let entry_as_bytes = scalar_to_bytes::<C>(&entry);
                entries_as_bytes.push(entry_as_bytes);
            }
            let row_i_as_bytes = entries_as_bytes.concat();
            rows_r_as_bytes.push(row_i_as_bytes);
        }
        let r_as_bytes = rows_r_as_bytes.concat();

        // We transform r into a hash.
        let expected_verify_r: HashOutput = hash(&r_as_bytes, session_id);

        // We compare the values.
        if data_received.verify_r != expected_verify_r {
            return Err(ErrorMul::new(
                "Sender cheated in multiplication protocol: Consistency check failed!",
            ));
        }

        // INPUT AND ADJUSTMENT

        // Step 7 - No action for the receiver.
        // (Remember that we hardcoded gamma_B = 0.)

        // Step 8 - Finally, we compute the protocol's output.
        // Recall that we hardcoded gamma_B = 0.

        let mut output: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L {
            let mut summation = C::Scalar::ZERO;
            for j in 0..BATCH_SIZE {
                summation += self.public_gadget[j as usize] * z_tilde[i as usize][j as usize];
            }
            let final_sum = (data_kept.b * data_received.gamma_sender[i as usize]) + summation;
            output.push(final_sum);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    type C = k256::Secp256k1;

    /// Tests if the outputs for the multiplication protocol
    /// satisfy the relations they are supposed to satisfy.
    #[test]
    fn test_multiplication() {
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // INITIALIZATION

        // Phase 1 - Receiver
        let (ot_sender, dlog_proof, nonce) = MulReceiver::<C>::init_phase1(&session_id);

        // Phase 1 - Sender
        let (ot_receiver, correlation, vec_r, enc_proofs) = MulSender::<C>::init_phase1(&session_id);

        // Communication round
        // OT: Exchange the proofs and the seed.
        // Mul: Exchange the nonce.
        let seed = ot_receiver.seed;

        // Phase 2 - Receiver
        let result_receiver =
            MulReceiver::<C>::init_phase2(&ot_sender, &session_id, &seed, &enc_proofs, &nonce);
        let mul_receiver = match result_receiver {
            Ok(r) => r,
            Err(error) => {
                panic!("Two-party multiplication error: {:?}", error.description);
            }
        };

        // Phase 2 - Sender
        let result_sender = MulSender::<C>::init_phase2(
            &ot_receiver,
            &session_id,
            correlation,
            &vec_r,
            &dlog_proof,
            &nonce,
        );
        let mul_sender = match result_sender {
            Ok(s) => s,
            Err(error) => {
                panic!("Two-party multiplication error: {:?}", error.description);
            }
        };

        // PROTOCOL

        // Sampling the choices.
        let mut sender_input: Vec<<C as CurveArithmetic>::Scalar> = Vec::with_capacity(L as usize);
        for _ in 0..L {
            sender_input.push(<C as CurveArithmetic>::Scalar::random(rng::get_rng()));
        }

        // Phase 1 - Receiver
        let (receiver_random, data_to_keep, data_to_sender) = mul_receiver.run_phase1(&session_id);

        // Communication round 1
        // Receiver keeps receiver_random (part of the output)
        // and data_to_keep, and transmits data_to_sender.

        // Unique phase - Sender
        let sender_result = mul_sender.run(&session_id, &sender_input, &data_to_sender);

        let sender_output: Vec<<C as CurveArithmetic>::Scalar>;
        let data_to_receiver: MulDataToReceiver<C>;
        match sender_result {
            Ok((output, data)) => {
                sender_output = output;
                data_to_receiver = data;
            }
            Err(error) => {
                panic!("Two-party multiplication error: {:?}", error.description);
            }
        }

        // Communication round 2
        // Sender transmits data_to_receiver.

        // Phase 2 - Receiver
        let receiver_result =
            mul_receiver.run_phase2(&session_id, &data_to_keep, &data_to_receiver);

        let receiver_output = match receiver_result {
            Ok(output) => output,
            Err(error) => {
                panic!("Two-party multiplication error: {:?}", error.description);
            }
        };

        // Verification that the protocol did what it should do.
        for i in 0..L {
            // The sum of the outputs should be equal to the product of the
            // sender's chosen scalar and the receiver's random scalar.
            let sum = sender_output[i as usize] + receiver_output[i as usize];
            assert_eq!(sum, sender_input[i as usize] * receiver_random);
        }
    }
}
