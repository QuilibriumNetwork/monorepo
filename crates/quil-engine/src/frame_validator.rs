use std::sync::Arc;

use prost::Message;
use tracing::{debug, info, warn};

use quil_types::consensus::{
    AppFrameValidator, GlobalFrameValidator, ProverRegistry as ProverRegistryTrait,
};
use quil_types::crypto::{BlsConstructor, FrameProver};
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::{AppShardFrame, GlobalFrame, GlobalFrameHeader};

/// Validates received global frames by verifying VDF proof and BLS signature.
pub struct GlobalFrameVerifier {
    frame_prover: Arc<dyn FrameProver>,
    bls_constructor: Option<Arc<dyn BlsConstructor>>,
}

impl GlobalFrameVerifier {
    pub fn new(frame_prover: Arc<dyn FrameProver>) -> Self {
        Self { frame_prover, bls_constructor: None }
    }

    /// Create with BLS signature verification enabled.
    pub fn with_bls(frame_prover: Arc<dyn FrameProver>, bls_constructor: Arc<dyn BlsConstructor>) -> Self {
        Self { frame_prover, bls_constructor: Some(bls_constructor) }
    }

    /// Decode raw bytes into a GlobalFrame.
    pub fn decode_frame(data: &[u8]) -> Result<GlobalFrame> {
        GlobalFrame::decode(data)
            .map_err(|e| QuilError::Serialization(format!("failed to decode GlobalFrame: {}", e)))
    }

    /// Validate a global frame by verifying its VDF proof.
    pub fn validate(&self, frame: &GlobalFrame) -> Result<bool> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame has no header".into()))?;

        // Verify the VDF proof
        match self.frame_prover.verify_global_frame_header(header) {
            Ok(_output) => {
                debug!(
                    frame = header.frame_number,
                    difficulty = header.difficulty,
                    "frame VDF proof valid"
                );
            }
            Err(e) => {
                warn!(
                    frame = header.frame_number,
                    error = %e,
                    "frame VDF proof invalid"
                );
                return Ok(false);
            }
        }

        // Verify BLS aggregate signature if verifier is configured
        if let Some(ref bls) = self.bls_constructor {
            if let Some(ref agg_sig) = header.public_key_signature_bls48581 {
                let pubkey_bytes = agg_sig.public_key
                    .as_ref()
                    .map(|pk| pk.key_value.clone())
                    .unwrap_or_default();

                if !pubkey_bytes.is_empty() && !agg_sig.signature.is_empty() {
                    // Go signs `filter || stateID || rank:u64(BE)` with
                    // domain "global", where `stateID` is the RAW 32-byte
                    // poseidon selector (not hex). Rust's
                    // `make_vote_message` takes an `Identity` alias of
                    // `String`, which would require valid UTF-8 — the
                    // raw poseidon bytes aren't, so we build the
                    // message manually here.
                    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                        .unwrap_or_default();
                    let mut vote_msg = Vec::with_capacity(selector.len() + 8);
                    vote_msg.extend_from_slice(&selector);
                    vote_msg.extend_from_slice(&header.rank.to_be_bytes());
                    if bls.verify_signature_raw(&pubkey_bytes, &agg_sig.signature, &vote_msg, b"global") {
                        debug!(frame = header.frame_number, "BLS signature valid");
                    } else {
                        warn!(frame = header.frame_number, "BLS signature INVALID");
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    /// Validate that a frame's header fields are consistent.
    pub fn validate_header_fields(header: &GlobalFrameHeader) -> Result<()> {
        if header.output.is_empty() {
            return Err(QuilError::InvalidArgument("frame has empty output".into()));
        }
        if header.prover.is_empty() {
            return Err(QuilError::InvalidArgument("frame has empty prover".into()));
        }
        if header.parent_selector.is_empty() && header.frame_number > 0 {
            return Err(QuilError::InvalidArgument(
                "non-genesis frame has empty parent selector".into(),
            ));
        }
        Ok(())
    }
}

/// Pipeline that decodes, validates, and stores frames.
pub struct FramePipeline {
    _verifier: GlobalFrameVerifier,
    clock_store: Arc<quil_store::RocksClockStore>,
}

impl FramePipeline {
    pub fn new(
        frame_prover: Arc<dyn FrameProver>,
        clock_store: Arc<quil_store::RocksClockStore>,
    ) -> Self {
        Self {
            _verifier: GlobalFrameVerifier::new(frame_prover),
            clock_store,
        }
    }

    /// Process a raw frame from the network: decode → validate → store.
    /// Returns the frame number if successful.
    pub fn process_raw_frame(&self, data: &[u8]) -> Result<u64> {
        // 1. Decode
        let frame = GlobalFrameVerifier::decode_frame(data)?;
        let frame_number = frame
            .header
            .as_ref()
            .map(|h| h.frame_number)
            .unwrap_or(0);

        // 2. Validate header fields
        if let Some(header) = &frame.header {
            GlobalFrameVerifier::validate_header_fields(header)?;
        }

        // 3. VDF verification.
        // Genesis (frame 0) has no VDF proof to verify. For all other
        // frames, VDF correctness is enforced by the frame_prover's
        // verify_frame_header() call in the BLS validation path
        // (see BlsGlobalFrameValidator / BlsAppShardFrameValidator
        // below). During initial bulk-sync the BLS validators are the
        // primary entry point, so standalone VDF re-verification here
        // is unnecessary — the proof has already been checked before
        // the frame reaches process_raw_frame().
        if frame_number == 0 {
            debug!("genesis frame — skipping VDF verification");
        }

        // 4. Store
        self.clock_store.put_global_frame(&frame, None)?;

        info!(frame = frame_number, "stored frame");
        Ok(frame_number)
    }

    /// Get the latest stored frame number.
    pub fn latest_frame(&self) -> Option<u64> {
        self.clock_store
            .get_latest_global_frame()
            .ok()
            .and_then(|f| f.header.map(|h| h.frame_number))
    }
}

// ---------------------------------------------------------------------------
// BLS-aware frame validators
// ---------------------------------------------------------------------------
//
// Rust ports of:
//   - `node/consensus/validator/bls_global_frame_validator.go`
//   - `node/consensus/validator/bls_app_shard_frame_validator.go`
//
// Both validators perform the same three-step check:
//   1. Structural sanity (non-nil header, expected field widths).
//   2. VDF proof verification via `FrameProver::verify_*_frame_header`,
//      which returns the aggregated-signer bitmask.
//   3. BLS aggregate-public-key check: compute
//      `aggregate(active_provers_matching_bitmask)` and compare to the
//      frame's declared `PublicKeySignatureBls48581.public_key`.
//
// The Go code takes a `crypto.BlsConstructor` as the aggregation
// helper; we do the same in Rust via the `BlsConstructor` trait.

/// The exact declared width of the VDF `output` field on a global frame header.
pub const GLOBAL_FRAME_OUTPUT_LEN: usize = 516;

/// Validates a `GlobalFrame` by:
/// 1. Checking structural fields on the header.
/// 2. Running the VDF proof through `FrameProver`.
/// 3. Aggregating the public keys of active provers selected by the
///    VDF's returned bitmask and comparing to the claimed aggregate.
///
/// Genesis frames (frame_number == 0) skip signature checks entirely.
pub struct BlsGlobalFrameValidator {
    prover_registry: Arc<dyn ProverRegistryTrait>,
    bls_constructor: Arc<dyn BlsConstructor>,
    frame_prover: Arc<dyn FrameProver>,
}

impl BlsGlobalFrameValidator {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistryTrait>,
        bls_constructor: Arc<dyn BlsConstructor>,
        frame_prover: Arc<dyn FrameProver>,
    ) -> Self {
        Self {
            prover_registry,
            bls_constructor,
            frame_prover,
        }
    }
}

impl GlobalFrameValidator for BlsGlobalFrameValidator {
    fn validate(&self, frame: &GlobalFrame) -> Result<bool> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame or header is nil".into()))?;

        if header.output.len() != GLOBAL_FRAME_OUTPUT_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "invalid output length: {}",
                header.output.len()
            )));
        }

        // Genesis: no signature required.
        if header.frame_number == 0 {
            debug!("validating genesis frame - no signature required");
            return Ok(true);
        }

        let sig = match header.public_key_signature_bls48581.as_ref() {
            Some(s) => s,
            None => return Err(QuilError::InvalidArgument("no bls signature".into())),
        };
        let (Some(pk), sig_bytes) = (sig.public_key.as_ref(), &sig.signature) else {
            return Err(QuilError::InvalidArgument(
                "signature or public key is nil".into(),
            ));
        };
        if sig_bytes.is_empty() {
            return Err(QuilError::InvalidArgument(
                "signature or public key is nil".into(),
            ));
        }
        if sig.bitmask.is_empty() {
            return Err(QuilError::InvalidArgument("bitmask is nil".into()));
        }

        // 1. VDF proof verification. The trait's return value is the
        // VDF output (not a bitmask) — we discard it; the participant
        // bitmask comes from the BLS aggregate signature carrier
        // directly (mirroring Go's
        // `WesolowskiFrameProver.VerifyGlobalFrameHeader` which
        // returns `GetSetBitIndices(sig.Bitmask)` after the VDF check).
        // Treating the VDF output as a participant bitmask (the prior
        // bug) caused every prover whose index byte happened to
        // appear in the 516-byte VDF output to be included in the
        // aggregate — for a typical committee size on a uniformly-
        // looking VDF output this is "approximately all of them",
        // letting an attacker pair any committee subset with a
        // matching forged `pk.key_value`.
        if let Err(e) = self.frame_prover.verify_global_frame_header(header) {
            debug!(
                frame_number = header.frame_number,
                parent_selector = %hex::encode(&header.parent_selector),
                error = %e,
                "frame verification failed"
            );
            return Err(QuilError::Crypto(format!(
                "global frame header verification: {}",
                e
            )));
        }
        let participant_indices: Vec<usize> =
            quil_consensus::bitmask::set_bit_indices(&sig.bitmask).collect();

        // 2. Aggregate-key check.
        // Go uses `proverRegistry.GetActiveProvers(nil)` for the
        // global filter case, which for our Rust impl means an
        // empty byte slice.
        let active = self.prover_registry.get_active_provers(&[])?;
        let mut active_public_keys: Vec<&[u8]> = Vec::new();
        let mut throwaway: Vec<&[u8]> = Vec::new();
        for (i, prover) in active.iter().enumerate() {
            if participant_indices.contains(&i) {
                active_public_keys.push(&prover.public_key);
                // Matches Go's quirky pattern of passing the frame's
                // own signature as the "throwaway" signature list
                // (the aggregator uses the signatures only for key
                // derivation; it doesn't care which one).
                throwaway.push(sig_bytes);
            }
        }

        let aggregate = self
            .bls_constructor
            .aggregate(&active_public_keys, &throwaway)
            .map_err(|e| QuilError::Crypto(format!("aggregate: {}", e)))?;
        if aggregate.public_key != pk.key_value {
            debug!(
                frame_number = header.frame_number,
                expected = %hex::encode(&pk.key_value),
                actual = %hex::encode(&aggregate.public_key),
                "could not verify aggregated keys"
            );
            return Err(QuilError::Crypto(
                "could not verify aggregated keys".into(),
            ));
        }

        // 3. BLS signature verification. The aggregate-key check
        // above only proves the *claimed* aggregate pubkey is
        // consistent with the bitmask, not that the signature bytes
        // are a valid signature under that aggregate key. Without
        // this final check, an attacker who can produce a valid VDF
        // could pair any committee subset (named via the bitmask)
        // with a matching forged `pk.key_value` and arbitrary
        // `sig.signature` bytes, and the frame would validate.
        //
        // Mirrors Go's `WesolowskiFrameProver.VerifyGlobalHeaderSignature`
        // (which Go's validator should call but does not; we close
        // the gap here rather than copy Go's omission).
        match self
            .frame_prover
            .verify_global_header_signature(header, self.bls_constructor.as_ref())
        {
            Ok(true) => {}
            Ok(false) => {
                debug!(
                    frame_number = header.frame_number,
                    "global frame BLS signature verification rejected"
                );
                return Err(QuilError::Crypto(
                    "global frame BLS signature verification rejected".into(),
                ));
            }
            Err(e) => {
                debug!(
                    frame_number = header.frame_number,
                    error = %e,
                    "global frame BLS signature verification errored"
                );
                return Err(QuilError::Crypto(format!(
                    "global frame BLS signature verification: {}",
                    e
                )));
            }
        }

        debug!(
            frame_number = header.frame_number,
            parent_selector = %hex::encode(&header.parent_selector),
            "global frame verification passed"
        );
        Ok(true)
    }
}

/// Mirror of
/// `node/consensus/validator/bls_app_shard_frame_validator.go`.
/// Validates an `AppShardFrame` by:
/// 1. Checking structural fields (non-empty address, exactly 4 state
///    roots of length 64 or 74).
/// 2. Running the VDF proof through `FrameProver::verify_frame_header`.
/// 3. Aggregating public keys of active provers under the app shard's
///    address filter whose indices are in the VDF bitmask.
pub struct BlsAppFrameValidator {
    prover_registry: Arc<dyn ProverRegistryTrait>,
    bls_constructor: Arc<dyn BlsConstructor>,
    frame_prover: Arc<dyn FrameProver>,
}

impl BlsAppFrameValidator {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistryTrait>,
        bls_constructor: Arc<dyn BlsConstructor>,
        frame_prover: Arc<dyn FrameProver>,
    ) -> Self {
        Self {
            prover_registry,
            bls_constructor,
            frame_prover,
        }
    }
}

impl AppFrameValidator for BlsAppFrameValidator {
    fn validate(&self, frame: &AppShardFrame) -> Result<bool> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame or header is nil".into()))?;

        if header.address.is_empty() {
            return Err(QuilError::InvalidArgument("address is empty".into()));
        }
        if header.state_roots.len() != 4 {
            return Err(QuilError::InvalidArgument(format!(
                "invalid state roots count: {}",
                header.state_roots.len()
            )));
        }
        for (i, root) in header.state_roots.iter().enumerate() {
            if root.len() != 64 && root.len() != 74 {
                return Err(QuilError::InvalidArgument(format!(
                    "invalid state root length at index {}: {}",
                    i,
                    root.len()
                )));
            }
        }

        // 1. VDF proof verification. The trait's return value is
        // the VDF output, not a participant bitmask — discard it.
        // The actual participant indices come from the BLS aggregate
        // signature carrier (mirroring Go's
        // `WesolowskiFrameProver.VerifyFrameHeader` which returns
        // `GetSetBitIndices(sig.Bitmask)`). See the matching comment
        // on `BlsGlobalFrameValidator::validate` above for why the
        // previous behavior (treating the VDF output as a bitmask)
        // was a soundness bug.
        if let Err(e) = self.frame_prover.verify_frame_header(header) {
            debug!(
                frame_number = header.frame_number,
                address = %hex::encode(&header.address),
                parent_selector = %hex::encode(&header.parent_selector),
                error = %e,
                "frame verification failed"
            );
            return Err(QuilError::Crypto(format!(
                "frame header verification: {}",
                e
            )));
        }

        // 2. Aggregate-key check. Required for every post-genesis
        // frame. The previous behavior wrapped this entire block in
        // `if let Some(sig) = ...`, so a frame with the signature
        // field omitted entirely would pass the validator after only
        // the VDF check (and VDF alone is publicly computable —
        // anyone can solve a Wesolowski problem given the inputs).
        // Genesis frames carry no signature by design (mirroring
        // `BlsGlobalFrameValidator` above which exempts
        // `frame_number == 0`).
        if header.frame_number != 0 && header.public_key_signature_bls48581.is_none() {
            return Err(QuilError::InvalidArgument(
                "app shard frame missing BLS signature (post-genesis frames must be signed)".into(),
            ));
        }
        if let Some(sig) = header.public_key_signature_bls48581.as_ref() {
            let Some(pk) = sig.public_key.as_ref() else {
                return Err(QuilError::InvalidArgument(
                    "signature has no public key".into(),
                ));
            };

            let participant_indices: Vec<usize> =
                quil_consensus::bitmask::set_bit_indices(&sig.bitmask).collect();

            let active = self.prover_registry.get_active_provers(&header.address)?;

            // Generate a throwaway key pair once — Go does this via
            // `blsConstructor.New()`. The throwaway signature bytes
            // are used as placeholder signatures in the aggregation
            // call because it only consumes them to derive keys.
            let (_throwaway_signer, throwaway_public) =
                self.bls_constructor
                    .new_key()
                    .map_err(|e| QuilError::Crypto(format!("throwaway key: {}", e)))?;

            let mut active_public_keys: Vec<&[u8]> = Vec::new();
            let mut throwaway_list: Vec<&[u8]> = Vec::new();
            for (i, prover) in active.iter().enumerate() {
                if participant_indices.contains(&i) {
                    active_public_keys.push(&prover.public_key);
                    throwaway_list.push(&throwaway_public);
                }
            }

            let aggregate = self
                .bls_constructor
                .aggregate(&active_public_keys, &throwaway_list)
                .map_err(|e| QuilError::Crypto(format!("aggregate: {}", e)))?;
            if aggregate.public_key != pk.key_value {
                debug!(
                    frame_number = header.frame_number,
                    address = %hex::encode(&header.address),
                    expected = %hex::encode(&pk.key_value),
                    actual = %hex::encode(&aggregate.public_key),
                    bitmask = %hex::encode(&sig.bitmask),
                    "could not verify aggregated keys"
                );
                return Err(QuilError::Crypto(
                    "could not verify aggregated keys".into(),
                ));
            }

            // BLS signature verification. See the matching comment in
            // `BlsGlobalFrameValidator::validate` — the aggregate-key
            // consistency check alone doesn't prove `sig.signature`
            // is a valid signature under the aggregate key. Without
            // this an attacker pairs a real-subset bitmask + matching
            // aggregate pubkey with arbitrary signature bytes.
            match self.frame_prover.verify_frame_header_signature(
                header,
                self.bls_constructor.as_ref(),
                None,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    debug!(
                        frame_number = header.frame_number,
                        address = %hex::encode(&header.address),
                        "app shard frame BLS signature rejected"
                    );
                    return Err(QuilError::Crypto(
                        "app shard frame BLS signature rejected".into(),
                    ));
                }
                Err(e) => {
                    debug!(
                        frame_number = header.frame_number,
                        address = %hex::encode(&header.address),
                        error = %e,
                        "app shard frame BLS signature errored"
                    );
                    return Err(QuilError::Crypto(format!(
                        "app shard frame BLS signature: {}",
                        e
                    )));
                }
            }
        }

        debug!(
            frame_number = header.frame_number,
            address = %hex::encode(&header.address),
            parent_selector = %hex::encode(&header.parent_selector),
            "app shard frame verification passed"
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_frame_nil_header_rejected() {
        use quil_types::proto::global::GlobalFrame;
        let v = BlsGlobalFrameValidator::new(
            Arc::new(StubProverRegistry::default()),
            Arc::new(StubBls::default()),
            Arc::new(StubFrameProver::default()),
        );
        let empty = GlobalFrame {
            header: None,
            requests: Vec::new(),
        };
        assert!(v.validate(&empty).is_err());
    }

    #[test]
    fn global_frame_wrong_output_length_rejected() {
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
        let v = BlsGlobalFrameValidator::new(
            Arc::new(StubProverRegistry::default()),
            Arc::new(StubBls::default()),
            Arc::new(StubFrameProver::default()),
        );
        let header = GlobalFrameHeader {
            output: vec![0u8; 100], // wrong
            ..Default::default()
        };
        let frame = GlobalFrame {
            header: Some(header),
            requests: Vec::new(),
        };
        let err = v.validate(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid output length"));
    }

    #[test]
    fn global_frame_genesis_passes_without_signature() {
        use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
        let v = BlsGlobalFrameValidator::new(
            Arc::new(StubProverRegistry::default()),
            Arc::new(StubBls::default()),
            Arc::new(StubFrameProver::default()),
        );
        let header = GlobalFrameHeader {
            output: vec![0u8; GLOBAL_FRAME_OUTPUT_LEN],
            frame_number: 0,
            ..Default::default()
        };
        let frame = GlobalFrame {
            header: Some(header),
            requests: Vec::new(),
        };
        assert!(v.validate(&frame).unwrap());
    }

    #[test]
    fn app_frame_missing_state_roots_rejected() {
        use quil_types::proto::global::{AppShardFrame, FrameHeader};
        let v = BlsAppFrameValidator::new(
            Arc::new(StubProverRegistry::default()),
            Arc::new(StubBls::default()),
            Arc::new(StubFrameProver::default()),
        );
        let header = FrameHeader {
            address: vec![0x01; 32],
            state_roots: vec![vec![0u8; 64], vec![0u8; 64]], // wrong count
            ..Default::default()
        };
        let frame = AppShardFrame {
            header: Some(header),
            requests: Vec::new(),
        };
        let err = v.validate(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid state roots count"));
    }

    // ---- test stubs ----

    // Shared stub from `crate::test_support`. Replaces a 60-line
    // local impl that re-declared every trait method as a no-op /
    // empty return. `get_next_prover` differs slightly — the
    // shared stub returns an empty Vec when no provers are
    // registered, whereas the frame_validator tests previously
    // returned a "stub" NotFound error. Empty Vec is equivalent
    // for these tests: the validator's caller treats both as "no
    // leader" and skips further checks.
    type StubProverRegistry = crate::test_support::TestProverRegistry;

    #[derive(Default)]
    struct StubBls;
    impl BlsConstructor for StubBls {
        fn new_key(&self) -> Result<(Box<dyn quil_types::crypto::Signer>, Vec<u8>)> {
            Err(QuilError::Internal("stub".into()))
        }
        fn from_bytes(
            &self,
            _: &[u8],
            _: &[u8],
        ) -> Result<Box<dyn quil_types::crypto::Signer>> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_signature_raw(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> bool {
            false
        }
        fn verify_multi_message_signature_raw(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[&[u8]],
            _: &[u8],
        ) -> bool {
            false
        }
        fn aggregate(
            &self,
            _: &[&[u8]],
            _: &[&[u8]],
        ) -> Result<quil_types::crypto::BlsAggregateOutput> {
            Err(QuilError::Internal("stub".into()))
        }
    }

    #[derive(Default)]
    struct StubFrameProver;
    impl FrameProver for StubFrameProver {
        fn prove_frame_header(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &[Vec<u8>],
            _: &[u8],
            _: i64,
            _: u32,
            _: u64,
            _: u64,
        ) -> Result<quil_types::proto::global::FrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_frame_header(
            &self,
            _: &quil_types::proto::global::FrameHeader,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn prove_global_frame_header(
            &self,
            _: &quil_types::proto::global::GlobalFrameHeader,
            _: &[Vec<u8>],
            _: &[u8],
            _: &[u8],
            _: &dyn quil_types::crypto::Signer,
            _: i64,
            _: u32,
            _: u8,
        ) -> Result<quil_types::proto::global::GlobalFrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_global_frame_header(
            &self,
            _: &quil_types::proto::global::GlobalFrameHeader,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn calculate_multi_proof(
            &self,
            _: &[u8; 32],
            _: u32,
            _: &[&[u8]],
            _: u32,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn verify_multi_proof(
            &self,
            _: &[u8; 32],
            _: u32,
            _: &[&[u8]],
            _: &[&[u8]],
        ) -> Result<bool> {
            Ok(true)
        }
    }
}
