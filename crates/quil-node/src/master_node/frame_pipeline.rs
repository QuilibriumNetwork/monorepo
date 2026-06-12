use std::sync::Arc;

use tracing::info;

pub(crate) struct FramePipeline {
    pub frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
    pub frame_validator: quil_engine::frame_validator::GlobalFrameVerifier,
    pub fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager>,
}

pub(crate) fn init() -> FramePipeline {
    // ---------------------------------------------------------------
    // 4. Create frame pipeline with VDF verification
    // ---------------------------------------------------------------
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let bls_for_verify: Arc<dyn quil_types::crypto::BlsConstructor> =
        Arc::new(quil_crypto::Bls48581KeyConstructor);
    let frame_validator = quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
        frame_prover.clone(),
        bls_for_verify,
    );

    let fee_manager: Arc<dyn quil_types::consensus::DynamicFeeManager> =
        Arc::new(quil_engine::InMemoryDynamicFeeManager::new(360));

    info!("VDF frame prover ready (Wesolowski, 2048-bit)");

    FramePipeline {
        frame_prover,
        frame_validator,
        fee_manager,
    }
}
