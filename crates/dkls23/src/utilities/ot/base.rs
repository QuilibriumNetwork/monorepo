//! Base OT.
//!
//! This file implements an oblivious transfer (OT) which will serve as a base
//! for the OT extension protocol.
//!
//! As suggested in page 30 of `DKLs23` (<https://eprint.iacr.org/2023/765.pdf>),
//! we implement the endemic OT protocol of Zhou et al., which can be found on
//! Section 3 of <https://eprint.iacr.org/2022/1525.pdf>.
//!
//! There are two phases for each party and one communication round between
//! them. Both Phase 1 and Phase 2 can be done concurrently for the sender
//! and the receiver.
//
//! There is also an initialization function which should be executed during
//! Phase 1. It saves some values that can be reused if the protocol is applied
//! several times. As this will be our case for the OT extension, there are
//! "batch" variants for each of the phases.
//!
//! The receiver's point `h` is derived from its seed with a random oracle
//! into the group (hash-to-curve, see [`derive_h`]). Its discrete logarithm
//! must stay unknown: otherwise the receiver can compute both messages and
//! the sender can read the choice bit.

use elliptic_curve::bigint::U256;
use elliptic_curve::group::{Curve as _, GroupEncoding};
use elliptic_curve::ops::Reduce;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::{Field, PrimeField};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::utilities::hashes::{hash, hash_as_scalar, point_to_bytes, HashOutput};
use crate::utilities::ot::ErrorOT;
use crate::utilities::proofs::{DLogProof, EncProof};
use crate::utilities::rng;
use crate::DklsCurve;
use crate::SECURITY;

// SENDER DATA

/// Sender's data and methods for the base OT protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize, C::AffinePoint: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>, C::AffinePoint: Deserialize<'de>"
))]
pub struct OTSender<C: CurveArithmetic> {
    pub s: C::Scalar,
    pub proof: DLogProof<C>,
}

// RECEIVER DATA

/// Seed kept by the receiver.
pub type Seed = [u8; SECURITY as usize];

/// Receiver's data and methods for the base OT protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTReceiver {
    pub seed: Seed,
}

/// Domain separation tag for hashing the receiver's seed to `h`.
const H_DST: &[u8] = b"DKLs23-BaseOT-h-V01-XMD:SHA-256_SSWU_RO_";

/// Derives the receiver's point `h` from its seed and the session id.
///
/// The paper takes `h` from a random oracle into the group, so we hash to
/// the curve. Nobody, including the receiver who picks the seed, knows the
/// discrete logarithm of `h` with respect to the generator.
#[must_use]
pub fn derive_h<C: DklsCurve>(session_id: &[u8], seed: &Seed) -> C::AffinePoint {
    // The seed and the label have fixed lengths, so this encoding is
    // unambiguous.
    let msgs: [&[u8]; 3] = [seed, b"Receiver", session_id];
    C::hash_to_curve(&msgs, H_DST)
}

/// The point `h` as derived before hash-to-curve: the generator times a
/// hash of the seed. Its discrete logarithm is public, so it only serves to
/// recognise a counterparty that still runs the old derivation.
fn legacy_h<C: DklsCurve>(session_id: &[u8], seed: &Seed) -> C::AffinePoint
where
    C::Scalar: Reduce<U256>,
{
    let generator: C::AffinePoint = crate::generator::<C>();
    let msg_for_h = ["Receiver".as_bytes(), seed].concat();
    let log_h = hash_as_scalar::<C>(&msg_for_h, session_id);
    (C::ProjectivePoint::from(generator) * log_h).to_affine()
}

impl<C: DklsCurve> OTSender<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding,
{
    // According to first paragraph on page 18,
    // the sender can reuse the secret s and the proof of discrete
    // logarithm. Thus, we isolate this part from the rest for efficiency.

    /// Initializes the protocol for a given session id.
    #[must_use]
    pub fn init(session_id: &[u8]) -> OTSender<C> {
        // We sample a nonzero random scalar.
        let mut s = C::Scalar::ZERO;
        while s == C::Scalar::ZERO {
            s = C::Scalar::random(rng::get_rng());
        }

        // In the paper, different protocols use different random oracles.
        // Thus, we will add a unique string to the session id here.
        let current_sid = [session_id, "DLogProof".as_bytes()].concat();
        let proof = DLogProof::<C>::prove(&s, &current_sid);

        OTSender { s, proof }
    }

    // Phase 1 - The sender transmits z = s * generator and the proof
    // of discrete logarithm. Note that z is contained in the proof.

    /// Generates a proof to be sent to the receiver.
    #[must_use]
    pub fn run_phase1(&self) -> DLogProof<C> {
        self.proof.clone()
    }

    // Since the sender is recycling the proof, we don't need a batch version.

    // Communication round
    // The sender transmits the proof.
    // He receives the receiver's seed and encryption proof (which contains u and v).

    // Phase 2 - We verify the receiver's data and compute the output.

    /// Using the seed and the encryption proof transmitted by the receiver,
    /// the two output messages are computed.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the encryption proof fails.
    pub fn run_phase2(
        &self,
        session_id: &[u8],
        seed: &Seed,
        enc_proof: &EncProof<C>,
    ) -> Result<(HashOutput, HashOutput), ErrorOT> {
        // We reconstruct h from the seed (as in the paper).
        let h = derive_h::<C>(session_id, seed);

        // h is already in enc_proof, but we check if the values agree.
        if h != enc_proof.proof0.base_h {
            if enc_proof.proof0.base_h == legacy_h::<C>(session_id, seed) {
                return Err(ErrorOT::new(
                    "Receiver uses the legacy base OT derivation of h: every party must upgrade!",
                ));
            }
            return Err(ErrorOT::new(
                "Receiver cheated in OT: Encryption proof failed!",
            ));
        }

        // We verify the proof.
        let current_sid = [session_id, "EncProof".as_bytes()].concat();
        if !enc_proof.verify(&current_sid) {
            return Err(ErrorOT::new(
                "Receiver cheated in OT: Encryption proof failed!",
            ));
        }

        // We compute the messages.
        // As before, instead of an identifier for the sender,
        // we just take the word 'Sender' for simplicity.

        let (_, v) = enc_proof.get_u_and_v();

        let value_for_m0 = (C::ProjectivePoint::from(v) * self.s).to_affine();
        let value_for_m1 =
            ((C::ProjectivePoint::from(v) - C::ProjectivePoint::from(h)) * self.s).to_affine();

        let msg_for_m0 = ["Sender".as_bytes(), &point_to_bytes::<C>(&value_for_m0)].concat();
        let msg_for_m1 = ["Sender".as_bytes(), &point_to_bytes::<C>(&value_for_m1)].concat();

        let m0 = hash(&msg_for_m0, session_id);
        let m1 = hash(&msg_for_m1, session_id);

        Ok((m0, m1))
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase2` for each encryption proof in `enc_proofs`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if one of the executions fails.
    pub fn run_phase2_batch(
        &self,
        session_id: &[u8],
        seed: &Seed,
        enc_proofs: &[EncProof<C>],
    ) -> Result<(Vec<HashOutput>, Vec<HashOutput>), ErrorOT> {
        let batch_size =
            u16::try_from(enc_proofs.len()).expect("The batch sizes used always fit into an u16!");

        let mut vec_m0: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        let mut vec_m1: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (m0, m1) = self.run_phase2(&current_sid, seed, &enc_proofs[i as usize])?;

            vec_m0.push(m0);
            vec_m1.push(m1);
        }

        Ok((vec_m0, vec_m1))
    }
}

impl OTReceiver {
    // Initialization - According to first paragraph on page 18,
    // the sender can reuse the seed. Thus, we isolate this part
    // from the rest for efficiency.

    /// Initializes the protocol.
    #[must_use]
    pub fn init() -> OTReceiver {
        let seed = rng::get_rng().gen::<Seed>();

        OTReceiver { seed }
    }

    // Phase 1 - We sample the secret values and provide proof.

    /// Given a choice bit, returns a secret scalar (to be kept)
    /// and an encryption proof (to be sent to the sender).
    #[must_use]
    pub fn run_phase1<C: DklsCurve>(&self, session_id: &[u8], bit: bool) -> (C::Scalar, EncProof<C>)
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // We sample the secret scalar r.
        let r = C::Scalar::random(rng::get_rng());

        // We compute h as in the paper.
        let h = derive_h::<C>(session_id, &self.seed);

        // We prove our data.
        // In the paper, different protocols use different random oracles.
        // Thus, we will add a unique string to the session id here.
        let current_sid = [session_id, "EncProof".as_bytes()].concat();
        let proof = EncProof::<C>::prove(&current_sid, &h, &r, bit);

        // r should be kept and proof should be sent.
        (r, proof)
    }

    // Phase 1 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase1` for each choice bit in `bits`.
    #[must_use]
    pub fn run_phase1_batch<C: DklsCurve>(
        &self,
        session_id: &[u8],
        bits: &[bool],
    ) -> (Vec<C::Scalar>, Vec<EncProof<C>>)
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        let batch_size =
            u16::try_from(bits.len()).expect("The batch sizes used always fit into an u16!");

        let mut vec_r: Vec<C::Scalar> = Vec::with_capacity(batch_size as usize);
        let mut vec_proof: Vec<EncProof<C>> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let (r, proof) = self.run_phase1::<C>(&current_sid, bits[i as usize]);

            vec_r.push(r);
            vec_proof.push(proof);
        }

        (vec_r, vec_proof)
    }

    // Communication round
    // The receiver transmits his seed and the proof.
    // He receives the sender's seed and proof of discrete logarithm (which contains z).

    // Phase 2 - We verify the sender's data and compute the output.
    // For the batch version, we split the phase into two steps: the
    // first depends only on the initialization values and can be done
    // once, while the second is different for each iteration.

    /// Verifies the discrete logarithm proof sent by the sender
    /// and returns the point concerned in the proof.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the proof fails.
    pub fn run_phase2_step1<C: DklsCurve>(
        &self,
        session_id: &[u8],
        dlog_proof: &DLogProof<C>,
    ) -> Result<C::AffinePoint, ErrorOT>
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // Verification of the proof.
        let current_sid = [session_id, "DLogProof".as_bytes()].concat();
        let verification = DLogProof::<C>::verify(dlog_proof, &current_sid);

        if !verification {
            return Err(ErrorOT::new(
                "Sender cheated in OT: Proof of discrete logarithm failed!",
            ));
        }

        let z = dlog_proof.point;

        Ok(z)
    }

    /// With the secret value `r` from Phase 1 and with the point `z`
    /// from the previous step, the output message is computed.
    #[must_use]
    pub fn run_phase2_step2<C: DklsCurve>(
        &self,
        session_id: &[u8],
        r: &C::Scalar,
        z: &C::AffinePoint,
    ) -> HashOutput
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // We compute the message.
        // As before, instead of an identifier for the sender,
        // we just take the word 'Sender' for simplicity.

        let value_for_mb = (C::ProjectivePoint::from(*z) * r).to_affine();

        let msg_for_mb = ["Sender".as_bytes(), &point_to_bytes::<C>(&value_for_mb)].concat();

        // We could return the bit as in the paper, but the receiver has this information.
        hash(&msg_for_mb, session_id)
    }

    // Phase 2 batch version: used for multiple executions (e.g. OT extension).

    /// Executes `run_phase2_step1` once and `run_phase2_step2` for every
    /// secret scalar in `vec_r` from Phase 1.
    ///
    /// # Errors
    ///
    /// Will return `Err` if one of the executions fails.
    pub fn run_phase2_batch<C: DklsCurve>(
        &self,
        session_id: &[u8],
        vec_r: &[C::Scalar],
        dlog_proof: &DLogProof<C>,
    ) -> Result<Vec<HashOutput>, ErrorOT>
    where
        C::Scalar: Reduce<U256> + PrimeField,
        C::AffinePoint: GroupEncoding,
    {
        // Step 1
        let z = self.run_phase2_step1::<C>(session_id, dlog_proof)?;

        // Step 2
        let batch_size =
            u16::try_from(vec_r.len()).expect("The batch sizes used always fit into an u16!");

        let mut vec_mb: Vec<HashOutput> = Vec::with_capacity(batch_size as usize);
        for i in 0..batch_size {
            // We use different ids for different iterations.
            let current_sid = [&i.to_be_bytes(), session_id].concat();

            let mb = self.run_phase2_step2::<C>(&current_sid, &vec_r[i as usize], &z);

            vec_mb.push(mb);
        }

        Ok(vec_mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type C = k256::Secp256k1;
    type Scalar = <C as CurveArithmetic>::Scalar;
    type ProjectivePoint = <C as CurveArithmetic>::ProjectivePoint;

    /// Tests if the outputs for the OT base protocol
    /// satisfy the relations they are supposed to satisfy.
    #[test]
    fn test_ot_base() {
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // Initialization
        let sender = OTSender::<C>::init(&session_id);
        let receiver = OTReceiver::init();

        // Phase 1 - Sender
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let bit = rng::get_rng().gen();
        let (r, enc_proof) = receiver.run_phase1::<C>(&session_id, bit);

        // Communication round - The parties exchange the proofs.
        // The receiver also sends his seed.
        let seed = receiver.seed;

        // Phase 2 - Sender
        let result_sender = sender.run_phase2(&session_id, &seed, &enc_proof);

        if let Err(error) = result_sender {
            panic!("OT error: {:?}", error.description);
        }

        let (m0, m1) = result_sender.unwrap();

        // Phase 2 - Receiver
        let result_receiver = receiver.run_phase2_step1::<C>(&session_id, &dlog_proof);

        if let Err(error) = result_receiver {
            panic!("OT error: {:?}", error.description);
        }

        let z = result_receiver.unwrap();
        let mb = receiver.run_phase2_step2::<C>(&session_id, &r, &z);

        // Verification that the protocol did what it should do.
        // Depending on the choice the receiver made, he should receive one of the pads.
        if bit {
            assert_eq!(m1, mb);
        } else {
            assert_eq!(m0, mb);
        }
    }

    /// Batch version for [`test_ot_base`].
    #[test]
    fn test_ot_base_batch() {
        ot_base_batch_round_trip::<C>();
    }

    /// [`test_ot_base_batch`] on P-256.
    #[test]
    fn test_ot_base_batch_p256() {
        ot_base_batch_round_trip::<p256::NistP256>();
    }

    fn ot_base_batch_round_trip<Crv: DklsCurve>()
    where
        Crv::Scalar: Reduce<U256> + PrimeField,
        Crv::AffinePoint: GroupEncoding,
    {
        let session_id = rng::get_rng().gen::<[u8; 32]>();

        // Initialization (unique)
        let sender = OTSender::<Crv>::init(&session_id);
        let receiver = OTReceiver::init();

        let batch_size = 256;

        // Phase 1 - Sender (unique)
        let dlog_proof = sender.run_phase1();

        // Phase 1 - Receiver
        let mut bits: Vec<bool> = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            bits.push(rng::get_rng().gen());
        }

        let (vec_r, enc_proofs) = receiver.run_phase1_batch::<Crv>(&session_id, &bits);

        // Communication round - The parties exchange the proofs.
        // The receiver also sends his seed.
        let seed = receiver.seed;

        // Phase 2 - Sender
        let result_sender = sender.run_phase2_batch(&session_id, &seed, &enc_proofs);

        if let Err(error) = result_sender {
            panic!("OT error: {:?}", error.description);
        }

        let (vec_m0, vec_m1) = result_sender.unwrap();

        // Phase 2 - Receiver
        let result_receiver = receiver.run_phase2_batch::<Crv>(&session_id, &vec_r, &dlog_proof);

        if let Err(error) = result_receiver {
            panic!("OT error: {:?}", error.description);
        }

        let vec_mb = result_receiver.unwrap();

        // Verification that the protocol did what it should do.
        // Depending on the choice the receiver made, he should receive one of the pads.
        for i in 0..batch_size {
            if bits[i] {
                assert_eq!(vec_m1[i], vec_mb[i]);
            } else {
                assert_eq!(vec_m0[i], vec_mb[i]);
            }
        }
    }

    /// The discrete logarithm the receiver would know if `h` were the
    /// generator times a hash of its seed.
    fn hashed_log_h(session_id: &[u8], seed: &Seed) -> Scalar {
        let msg_for_h = ["Receiver".as_bytes(), seed].concat();
        hash_as_scalar::<C>(&msg_for_h, session_id)
    }

    /// The receiver's `h` must not be the generator times a hash of its
    /// seed: anybody could compute its discrete logarithm.
    #[test]
    fn test_ot_base_h_is_not_a_hashed_multiple_of_generator() {
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let receiver = OTReceiver::init();
        let (_, enc_proof) = receiver.run_phase1::<C>(&session_id, false);

        let log_h = hashed_log_h(&session_id, &receiver.seed);
        let multiple = (ProjectivePoint::from(crate::generator::<C>()) * log_h).to_affine();

        assert_ne!(enc_proof.proof0.base_h, multiple);
    }

    /// The receiver must not be able to compute the message it did not
    /// choose. With a known `t = log(h)`, it could: `m1 = H((r - t) * z)`
    /// for the bit 0 and `m0 = H((r + t) * z)` for the bit 1.
    #[test]
    fn test_ot_base_receiver_cannot_compute_other_message() {
        for bit in [false, true] {
            let session_id = rng::get_rng().gen::<[u8; 32]>();
            let sender = OTSender::<C>::init(&session_id);
            let receiver = OTReceiver::init();

            let dlog_proof = sender.run_phase1();
            let (r, enc_proof) = receiver.run_phase1::<C>(&session_id, bit);
            let (m0, m1) = sender
                .run_phase2(&session_id, &receiver.seed, &enc_proof)
                .unwrap();
            let z = receiver
                .run_phase2_step1::<C>(&session_id, &dlog_proof)
                .unwrap();

            let t = hashed_log_h(&session_id, &receiver.seed);
            let (r_other, m_other) = if bit { (r + t, m0) } else { (r - t, m1) };
            let guess = receiver.run_phase2_step2::<C>(&session_id, &r_other, &z);

            assert_ne!(guess, m_other);
        }
    }

    /// The sender must not learn the choice bit. With a known `t = log(h)`,
    /// it could: `u = r * h` gives `r * G = u / t`, and `v - r * G = bit * h`.
    #[test]
    fn test_ot_base_sender_cannot_read_choice_bit() {
        for bit in [false, true] {
            let session_id = rng::get_rng().gen::<[u8; 32]>();
            let receiver = OTReceiver::init();
            let (_, enc_proof) = receiver.run_phase1::<C>(&session_id, bit);

            let (u, v) = enc_proof.get_u_and_v();
            let v = ProjectivePoint::from(v);
            let h = ProjectivePoint::from(enc_proof.proof0.base_h);
            let t = hashed_log_h(&session_id, &receiver.seed);
            let r_g = ProjectivePoint::from(u) * t.invert().unwrap();

            assert_ne!(v, r_g);
            assert_ne!(v - h, r_g);
        }
    }

    /// A sender rejects a receiver that still derives `h` the old way, with
    /// an error that names the cause.
    #[test]
    fn test_ot_base_rejects_legacy_h() {
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let sender = OTSender::<C>::init(&session_id);
        let receiver = OTReceiver::init();

        let log_h = hashed_log_h(&session_id, &receiver.seed);
        let legacy = (ProjectivePoint::from(crate::generator::<C>()) * log_h).to_affine();
        let r = Scalar::random(rng::get_rng());
        let current_sid = [session_id.as_slice(), "EncProof".as_bytes()].concat();
        let enc_proof = EncProof::<C>::prove(&current_sid, &legacy, &r, false);

        let error = sender
            .run_phase2(&session_id, &receiver.seed, &enc_proof)
            .expect_err("a receiver on the old derivation of h must be rejected");
        assert!(error.description.contains("legacy"));
    }
}
