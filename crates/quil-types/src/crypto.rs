use crate::error::Result;

/// Key types supported by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    Ed448 = 0,
    X448 = 1,
    Bls48581G1 = 2,
    Bls48581G2 = 3,
    Decaf448 = 4,
    Secp256k1Sha256 = 5,
    Secp256k1Sha3 = 6,
    Ed25519 = 7,
}

/// A cryptographic signer that can produce signatures over messages.
pub trait Signer: Send + Sync {
    fn key_type(&self) -> KeyType;
    fn public_key(&self) -> &[u8];
    fn private_key(&self) -> &[u8];
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_with_domain(&self, message: &[u8], domain: &[u8]) -> Result<Vec<u8>>;
}

/// Output of BLS signature aggregation.
pub struct BlsAggregateOutput {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Constructor for BLS48-581 keys and signature operations.
pub trait BlsConstructor: Send + Sync {
    fn new_key(&self) -> Result<(Box<dyn Signer>, Vec<u8>)>;
    fn from_bytes(&self, private_key: &[u8], public_key: &[u8]) -> Result<Box<dyn Signer>>;
    fn verify_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> bool;
    fn verify_multi_message_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool;
    fn aggregate(
        &self,
        public_keys: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<BlsAggregateOutput>;
}

/// Multiproof output from inclusion proving.
pub trait Multiproof: Send + Sync {
    fn commitment(&self) -> &[u8];
    fn proof(&self) -> &[u8];
    fn evaluations(&self) -> Vec<Vec<u8>>;
}

/// KZG polynomial commitment-based inclusion prover.
pub trait InclusionProver: Send + Sync {
    fn commit_raw(&self, data: &[u8], poly_size: u64) -> Result<Vec<u8>>;
    fn prove_raw(&self, data: &[u8], index: u64, poly_size: u64) -> Result<Vec<u8>>;
    fn verify_raw(
        &self,
        data: &[u8],
        commit: &[u8],
        index: u64,
        proof: &[u8],
        poly_size: u64,
    ) -> Result<bool>;
    fn prove_multiple(
        &self,
        commitments: &[&[u8]],
        polys: &[&[u8]],
        indices: &[u64],
        poly_size: u64,
    ) -> Result<Box<dyn Multiproof>>;
    fn verify_multiple(
        &self,
        commitments: &[&[u8]],
        evaluations: &[&[u8]],
        indices: &[u64],
        poly_size: u64,
        multi_commitment: &[u8],
        proof: &[u8],
    ) -> bool;
}

/// No-op inclusion prover that returns zero commitments and always verifies
/// successfully. Used as a placeholder when no real KZG prover is available.
pub struct NoopInclusionProver;

impl InclusionProver for NoopInclusionProver {
    fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
    fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
    fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
        Err(crate::error::QuilError::Internal("batch multiproof generation not supported".into()))
    }
    fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
}

/// Key manager for multi-algorithm signature verification. Dispatches
/// based on `KeyType` to the appropriate verifier.
///
/// The execution layer's `Verify` methods on every prover op call
/// `key_manager.validate_signature(key_type, public_key, message,
/// signature, domain)`.
pub trait KeyManager: Send + Sync {
    /// Verify a signature over `message` using the key identified by
    /// `key_type` and `public_key`. The `domain` is a context separator
    /// that the signer used in `sign_with_domain`.
    ///
    /// Returns `Ok(true)` for valid, `Ok(false)` for invalid, and
    /// `Err` for an internal error (e.g. unknown key type or malformed
    /// key).
    fn validate_signature(
        &self,
        key_type: KeyType,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        domain: &[u8],
    ) -> Result<bool>;
}

/// VDF-based frame header prover.
pub trait FrameProver: Send + Sync {
    /// Build a new app-shard `FrameHeader` for `previous_frame_output`'s
    /// successor. The VDF challenge is `sha3(address || frame_number ||
    /// timestamp || difficulty || fee_multiplier_vote || parent ||
    /// requests_root || state_roots... || prover)` where `parent =
    /// poseidon(previous_frame_output[:516])`. Including timestamp +
    /// fee_multiplier ensures distinct ranks within the same frame
    /// produce distinct VDF outputs and therefore distinct identities.
    fn prove_frame_header(
        &self,
        previous_frame_output: &[u8],
        address: &[u8],
        requests_root: &[u8],
        state_roots: &[Vec<u8>],
        prover: &[u8],
        timestamp: i64,
        difficulty: u32,
        fee_multiplier_vote: u64,
        frame_number: u64,
    ) -> Result<crate::proto::global::FrameHeader>;

    fn verify_frame_header(
        &self,
        header: &crate::proto::global::FrameHeader,
    ) -> Result<Vec<u8>>;

    /// Build a new `GlobalFrameHeader` for `previous_frame.frame_number + 1`.
    /// Mirrors Go's `WesolowskiFrameProver.ProveGlobalFrameHeader` at
    /// `vdf/wesolowski_frame_prover.go:397-493` exactly:
    ///
    ///   parent     = poseidon(previous_frame.output[:516])
    ///   challenge  = sha3(frame#||timestamp||difficulty||parent||
    ///                     commitments...||prover_root||request_root)
    ///   output     = WesolowskiSolve(challenge, difficulty)
    ///   signature  = signer.SignWithDomain(challenge||output, "global")
    fn prove_global_frame_header(
        &self,
        previous_frame: &crate::proto::global::GlobalFrameHeader,
        commitments: &[Vec<u8>],
        prover_root: &[u8],
        request_root: &[u8],
        signer: &dyn Signer,
        timestamp: i64,
        difficulty: u32,
        prover_index: u8,
    ) -> Result<crate::proto::global::GlobalFrameHeader>;

    fn verify_global_frame_header(
        &self,
        header: &crate::proto::global::GlobalFrameHeader,
    ) -> Result<Vec<u8>>;

    fn calculate_multi_proof(
        &self,
        challenge: &[u8; 32],
        difficulty: u32,
        ids: &[&[u8]],
        index: u32,
    ) -> Result<Vec<u8>>;

    fn verify_multi_proof(
        &self,
        challenge: &[u8; 32],
        difficulty: u32,
        ids: &[&[u8]],
        alleged_solutions: &[&[u8]],
    ) -> Result<bool>;

    /// Verify the BLS aggregate signature carried by an app-shard frame
    /// header. Mirrors Go
    /// `WesolowskiFrameProver.VerifyFrameHeaderSignature` at
    /// `vdf/wesolowski_frame_prover.go:327-395`.
    ///
    /// Returns `Ok(true)` when the signature verifies against the
    /// signers' aggregated pubkey. If `ids` is `Some`, additionally
    /// verifies the multi-proof carried in the signature bytes past
    /// offset 74.
    ///
    /// Default implementation returns an error — callers should use a
    /// real `WesolowskiFrameProver` when BLS verify is required.
    fn verify_frame_header_signature(
        &self,
        _header: &crate::proto::global::FrameHeader,
        _bls: &dyn BlsConstructor,
        _ids: Option<&[&[u8]]>,
    ) -> Result<bool> {
        Err(crate::error::QuilError::Internal(
            "FrameProver::verify_frame_header_signature not implemented".into(),
        ))
    }

    /// Verify the BLS aggregate signature on a `GlobalFrameHeader`.
    /// Mirrors Go `WesolowskiFrameProver.VerifyGlobalHeaderSignature`
    /// at `vdf/wesolowski_frame_prover.go:565-640`.
    fn verify_global_header_signature(
        &self,
        _header: &crate::proto::global::GlobalFrameHeader,
        _bls: &dyn BlsConstructor,
    ) -> Result<bool> {
        Err(crate::error::QuilError::Internal(
            "FrameProver::verify_global_header_signature not implemented".into(),
        ))
    }
}

/// Result of a range proof generation.
pub struct RangeProofResult {
    pub proof: Vec<u8>,
    pub commitments: Vec<u8>,
}

/// Bulletproof-based range proof and confidential transaction
/// operations over the DECAF448 curve.
pub trait BulletproofProver: Send + Sync {
    /// Generate a range proof for 56-byte DECAF448 scalar values.
    fn generate_range_proof(
        &self,
        values: &[Vec<u8>],
        blinding: &[u8],
        bit_size: u64,
    ) -> Result<RangeProofResult>;

    /// Generate input commitments from 56-byte scalar values.
    fn generate_input_commitments(
        &self,
        values: &[Vec<u8>],
        blinding: &[u8],
    ) -> Vec<u8>;

    /// Verify a range proof against commitments.
    fn verify_range_proof(
        &self,
        proof: &[u8],
        commitment: &[u8],
        bit_size: u64,
    ) -> bool;

    /// Verify that inputs sum to outputs (+ fees).
    fn sum_check(
        &self,
        inputs: &[Vec<u8>],
        additional_inputs: &[Vec<u8>],
        outputs: &[Vec<u8>],
        additional_outputs: &[Vec<u8>],
    ) -> bool;

    /// Create a hidden signature (4 DECAF448 scalars: x, t, a, r).
    fn sign_hidden(
        &self,
        x: &[u8],
        t: &[u8],
        a: &[u8],
        r: &[u8],
    ) -> Vec<u8>;

    /// Verify a hidden signature.
    fn verify_hidden(
        &self,
        challenge: &[u8],
        ext_transcript: &[u8],
        s1: &[u8],
        s2: &[u8],
        s3: &[u8],
        point: &[u8],
        commitment: &[u8],
    ) -> bool;

    /// Simple Schnorr signature.
    fn simple_sign(&self, secret_key: &[u8], message: &[u8]) -> Vec<u8>;

    /// Verify a simple Schnorr signature.
    fn simple_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        point: &[u8],
    ) -> bool;
}

/// Decaf448 elliptic curve agreement.
pub trait DecafAgreement: Send + Sync {
    fn private_key(&self) -> &[u8];
    fn public_key(&self) -> &[u8];
    fn agree_with(&self, other_public: &[u8]) -> Result<Vec<u8>>;
    fn agree_with_and_hash_to_scalar(&self, other_public: &[u8]) -> Result<Vec<u8>>;
    fn inverse_scalar(&self) -> Result<Vec<u8>>;
    fn scalar_mult(&self, scalar: &[u8]) -> Result<Vec<u8>>;
    fn add(&self, other: &[u8]) -> Result<Vec<u8>>;
}

/// Constructor for Decaf448 keys.
pub trait DecafConstructor: Send + Sync {
    fn new_key(&self) -> Result<Box<dyn DecafAgreement>>;
    fn from_bytes(&self, private_key: &[u8]) -> Result<Box<dyn DecafAgreement>>;
    fn hash_to_scalar(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn new_from_scalar(&self, scalar: &[u8]) -> Result<Box<dyn DecafAgreement>>;
    fn alt_generator(&self) -> Vec<u8>;
}
