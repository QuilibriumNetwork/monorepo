//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use merlin::Transcript;

use crate::curve_adapter::{CompressedPoint, Scalar};
use crate::errors::ProofError;

pub trait TranscriptProtocol {
    /// Append a domain separator for an `n`-bit, `m`-party range proof.
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64);

    /// Append a domain separator for a length-`n` inner product proof.
    fn innerproduct_domain_sep(&mut self, n: u64);

    /// Append a domain separator for a constraint system.
    fn r1cs_domain_sep(&mut self);

    /// Commit a domain separator for a CS without randomized constraints.
    fn r1cs_1phase_domain_sep(&mut self);

    /// Commit a domain separator for a CS with randomized constraints.
    fn r1cs_2phase_domain_sep(&mut self);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &CompressedPoint);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedPoint,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64) {
        self.append_message(b"dom-sep", b"rangeproof v1");
        self.append_u64(b"n", n);
        self.append_u64(b"m", m);
    }

    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }

    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-2phase");
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, &scalar.to_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedPoint) {
        self.append_message(label, point.as_bytes());
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedPoint,
    ) -> Result<(), ProofError> {
        // Check if point is identity
        if let Some(decompressed) = point.decompress() {
            if decompressed == crate::curve_adapter::Point::identity() {
                return Err(ProofError::VerificationError);
            }
        } else {
            return Err(ProofError::VerificationError);
        }

        Ok(self.append_message(label, point.as_bytes()))
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 114 ];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(buf)
    }
}
