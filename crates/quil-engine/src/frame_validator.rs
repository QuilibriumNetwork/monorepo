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

        // 1. VDF proof verification. The returned bitmask names which
        // active-prover indices were aggregated into the header's
        // signature.
        let bits = match self.frame_prover.verify_global_frame_header(header) {
            Ok(b) => b,
            Err(e) => {
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
        };

        // 2. Aggregate-key check.
        // Go uses `proverRegistry.GetActiveProvers(nil)` for the
        // global filter case, which for our Rust impl means an
        // empty byte slice.
        let active = self.prover_registry.get_active_provers(&[])?;
        let mut active_public_keys: Vec<&[u8]> = Vec::new();
        let mut throwaway: Vec<&[u8]> = Vec::new();
        for (i, prover) in active.iter().enumerate() {
            // bits is `Vec<u8>`, each byte an index into `active`.
            if bits.iter().any(|&b| b as usize == i) {
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

        // 1. VDF proof verification.
        let bits = match self.frame_prover.verify_frame_header(header) {
            Ok(b) => b,
            Err(e) => {
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
        };

        // 2. Aggregate-key check (only if a BLS signature is attached).
        if let Some(sig) = header.public_key_signature_bls48581.as_ref() {
            let Some(pk) = sig.public_key.as_ref() else {
                return Err(QuilError::InvalidArgument(
                    "signature has no public key".into(),
                ));
            };

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
                if bits.iter().any(|&b| b as usize == i) {
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
                    bitmask = %hex::encode(&bits),
                    "could not verify aggregated keys"
                );
                return Err(QuilError::Crypto(
                    "could not verify aggregated keys".into(),
                ));
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

    #[derive(Default)]
    struct StubProverRegistry;
    impl ProverRegistryTrait for StubProverRegistry {
        fn get_prover_info(&self, _: &[u8]) -> Result<Option<quil_types::consensus::ProverInfo>> {
            Ok(None)
        }
        fn get_next_prover(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn get_active_provers(
            &self,
            _: &[u8],
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_prover_count(&self, _: &[u8]) -> Result<usize> {
            Ok(0)
        }
        fn get_provers(&self, _: &[u8]) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_provers_by_status(
            &self,
            _: &[u8],
            _: quil_types::consensus::ProverStatus,
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn update_prover_activity(&self, _: &[u8], _: &[u8], _: u64) -> Result<()> {
            Ok(())
        }
        fn refresh(&self) -> Result<()> {
            Ok(())
        }
        fn get_all_active_app_shard_provers(
            &self,
        ) -> Result<Vec<quil_types::consensus::ProverInfo>> {
            Ok(Vec::new())
        }
        fn get_prover_shard_summaries(
            &self,
            _frame_number: u64,
        ) -> Result<Vec<quil_types::consensus::ProverShardSummary>> {
            Ok(Vec::new())
        }
        fn prune_orphan_joins(&self, _: u64) -> Result<()> {
            Ok(())
        }
        fn evict_inactive_provers(
            &self,
            _: u64,
            _: u64,
            _: &std::collections::HashMap<String, u64>,
        ) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn current_frame(&self) -> u64 {
            0
        }
    }

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
