use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};
use quil_types::execution::{ProcessMessageResult, ShardExecutionEngine};
use quil_types::proto::node;

use crate::domains;
use crate::engines::*;

/// Manages multiple execution engines and routes messages to the
/// appropriate engine based on domain address.
pub struct ExecutionEngineManager {
    engines: RwLock<HashMap<String, Box<dyn ShardExecutionEngine>>>,
    /// Shared CRDT used by the global/token/hypergraph engines (when
    /// constructed with `new_with_crypto`). Held here so callers can
    /// trigger a frame-keyed `commit` after processing all bundles —
    /// this is what flushes the in-memory phase trees to the on-disk
    /// hypergraph store, making new vertices visible to
    /// `prover_registry::refresh_from_store` and to peer HyperSync.
    crdt: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
}

impl ExecutionEngineManager {
    /// Build a manager with all engines initialized.
    pub fn new(
        inclusion_prover: Arc<dyn InclusionProver>,
        include_global: bool,
    ) -> Self {
        let mut engines: HashMap<String, Box<dyn ShardExecutionEngine>> = HashMap::new();

        if include_global {
            engines.insert(
                "global".into(),
                Box::new(GlobalExecutionEngine::new(inclusion_prover.clone())),
            );
        }

        Self::build(engines, inclusion_prover, include_global, None)
    }

    /// Create with full dependencies for real signature verification
    /// and state materialization on all engines.
    pub fn new_with_crypto(
        inclusion_prover: Arc<dyn InclusionProver>,
        key_manager: Arc<dyn quil_types::crypto::KeyManager>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        include_global: bool,
    ) -> Self {
        let mut engines: HashMap<String, Box<dyn ShardExecutionEngine>> = HashMap::new();

        if include_global {
            engines.insert(
                "global".into(),
                Box::new(GlobalExecutionEngine::new_with_intrinsic(
                    inclusion_prover.clone(),
                    key_manager,
                    crdt.clone(),
                )),
            );
        }

        Self::build_with_crdt(engines, inclusion_prover, crdt, include_global)
    }

    fn build(
        mut engines: HashMap<String, Box<dyn ShardExecutionEngine>>,
        _inclusion_prover: Arc<dyn InclusionProver>,
        include_global: bool,
        crdt: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    ) -> Self {
        let mode = if include_global { ExecutionMode::Global } else { ExecutionMode::Application };

        engines.insert("token".into(), Box::new(TokenExecutionEngine::new(mode)));
        engines.insert("compute".into(), Box::new(ComputeExecutionEngine::new(mode)));
        engines.insert("hypergraph".into(), Box::new(HypergraphExecutionEngine::new(mode)));

        Self { engines: RwLock::new(engines), crdt }
    }

    fn build_with_crdt(
        mut engines: HashMap<String, Box<dyn ShardExecutionEngine>>,
        inclusion_prover: Arc<dyn InclusionProver>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        include_global: bool,
    ) -> Self {
        let mode = if include_global { ExecutionMode::Global } else { ExecutionMode::Application };

        engines.insert("token".into(), Box::new(TokenExecutionEngine::new_with_state(
            mode, inclusion_prover.clone(), crdt.clone(),
        )));
        engines.insert("compute".into(), Box::new(ComputeExecutionEngine::new(mode)));
        engines.insert("hypergraph".into(), Box::new(HypergraphExecutionEngine::new_with_state(
            mode, crdt.clone(),
        )));

        Self { engines: RwLock::new(engines), crdt: Some(crdt) }
    }

    /// Persist the in-memory hypergraph phase trees for the given
    /// frame to the underlying store. Mirrors Go's
    /// `frame_materializer.go:316` `hg.Commit(frame)` after the
    /// per-bundle `state.Commit()` calls. Without this flush, the
    /// `RocksHypergraphStore::load_tree_blob` reads the previous
    /// frame's trees, so new vertices stay invisible to the prover
    /// registry refresh and to peer HyperSync.
    pub fn commit_frame(&self, frame_number: u64) -> Result<()> {
        if let Some(ref crdt) = self.crdt {
            crdt.commit(frame_number)?;
        }
        Ok(())
    }

    /// Get an engine by name.
    pub fn get_engine(&self, name: &str) -> Option<String> {
        let engines = self.engines.read().unwrap();
        if engines.contains_key(name) {
            Some(name.to_string())
        } else {
            None
        }
    }

    /// Get all supported capabilities across all engines.
    pub fn get_supported_capabilities(&self) -> Vec<node::Capability> {
        let engines = self.engines.read().unwrap();
        engines
            .values()
            .flat_map(|e| e.get_capabilities())
            .collect()
    }

    /// Route a message to the appropriate engine and validate it.
    pub fn validate_message(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<()> {
        let engine_name = self.select_engine(address)?;
        let engines = self.engines.read().unwrap();
        if let Some(engine) = engines.get(&engine_name) {
            engine.validate_message(frame_number, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        }
    }

    /// Route a message to the appropriate engine and process it.
    pub fn process_message(
        &self,
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        let engine_name = self.select_engine(address)?;
        let engines = self.engines.read().unwrap();
        if let Some(engine) = engines.get(&engine_name) {
            engine.process_message(frame_number, fee_multiplier, address, message)
        } else {
            Err(QuilError::NotFound(format!(
                "engine '{}' not found",
                engine_name
            )))
        }
    }

    /// Get the cost of a message by routing to the appropriate engine.
    pub fn get_cost(&self, message: &[u8]) -> Result<BigInt> {
        // For global frames, all messages route to the global engine.
        let engines = self.engines.read().unwrap();
        if let Some(engine) = engines.get("global") {
            return engine.get_cost(message);
        }
        Ok(BigInt::from(0))
    }

    /// Select the engine for a given domain address.
    fn select_engine(&self, address: &[u8]) -> Result<String> {
        if address.len() < 32 {
            return Err(QuilError::InvalidArgument("address too short".into()));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&address[..32]);

        if addr == domains::GLOBAL {
            Ok("global".into())
        } else if addr == domains::COMPUTE {
            Ok("compute".into())
        } else if addr == domains::QUIL_TOKEN {
            Ok("token".into())
        } else {
            // Default to hypergraph for unknown domains
            Ok("hypergraph".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;

    fn build_manager(include_global: bool) -> ExecutionEngineManager {
        ExecutionEngineManager::new(Arc::new(NoopInclusionProver), include_global)
    }

    // =================================================================
    // Engine registry
    // =================================================================

    #[test]
    fn manager_with_global_registers_four_engines() {
        let m = build_manager(true);
        assert!(m.get_engine("global").is_some());
        assert!(m.get_engine("token").is_some());
        assert!(m.get_engine("compute").is_some());
        assert!(m.get_engine("hypergraph").is_some());
    }

    #[test]
    fn manager_without_global_registers_three_engines() {
        let m = build_manager(false);
        assert!(m.get_engine("global").is_none());
        assert!(m.get_engine("token").is_some());
        assert!(m.get_engine("compute").is_some());
        assert!(m.get_engine("hypergraph").is_some());
    }

    #[test]
    fn manager_get_engine_unknown_returns_none() {
        let m = build_manager(true);
        assert!(m.get_engine("nonexistent").is_none());
        assert!(m.get_engine("").is_none());
        // Case-sensitive lookup.
        assert!(m.get_engine("GLOBAL").is_none());
    }

    // =================================================================
    // Capabilities aggregation
    // =================================================================

    #[test]
    fn manager_with_global_advertises_all_engine_protocol_ids() {
        // Each engine now advertises multiple capabilities (including
        // common ones like Double/Triple Ratchet and Onion Routing).
        // The manager concatenates all of them.
        let m = build_manager(true);
        let caps = m.get_supported_capabilities();
        // global(4) + token(4) + compute(12) + hypergraph(4) = 24
        assert_eq!(caps.len(), 24);
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(ids.contains(&crate::capabilities::GLOBAL_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::TOKEN_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::COMPUTE_PROTOCOL_V1));
    }

    #[test]
    fn manager_without_global_advertises_engine_protocol_ids() {
        let m = build_manager(false);
        let caps = m.get_supported_capabilities();
        // token(4) + compute(12) + hypergraph(4) = 20
        assert_eq!(caps.len(), 20);
        let ids: Vec<u32> = caps.iter().map(|c| c.protocol_identifier).collect();
        assert!(!ids.contains(&crate::capabilities::GLOBAL_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::TOKEN_PROTOCOL_V1));
        assert!(ids.contains(&crate::capabilities::COMPUTE_PROTOCOL_V1));
    }

    // =================================================================
    // select_engine domain routing
    // =================================================================

    #[test]
    fn select_engine_routes_global_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::GLOBAL).unwrap(), "global");
    }

    #[test]
    fn select_engine_routes_compute_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::COMPUTE).unwrap(), "compute");
    }

    #[test]
    fn select_engine_routes_quil_token_domain() {
        let m = build_manager(true);
        assert_eq!(m.select_engine(&domains::QUIL_TOKEN).unwrap(), "token");
    }

    #[test]
    fn select_engine_routes_unknown_domain_to_hypergraph() {
        let m = build_manager(true);
        let random = [0x42u8; 32];
        assert_eq!(m.select_engine(&random).unwrap(), "hypergraph");
    }

    #[test]
    fn select_engine_rejects_short_address() {
        let m = build_manager(true);
        let err = m.select_engine(&[0xFFu8; 16]).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn select_engine_rejects_empty_address() {
        let m = build_manager(true);
        let err = m.select_engine(&[]).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn select_engine_accepts_address_longer_than_32_bytes() {
        let m = build_manager(true);
        let mut long = [0u8; 64];
        long[..32].copy_from_slice(&domains::GLOBAL);
        long[32..].copy_from_slice(&[0xDE; 32]);
        assert_eq!(m.select_engine(&long).unwrap(), "global");
    }

    #[test]
    fn select_engine_is_deterministic() {
        let m = build_manager(true);
        let a = m.select_engine(&domains::QUIL_TOKEN).unwrap();
        let b = m.select_engine(&domains::QUIL_TOKEN).unwrap();
        assert_eq!(a, b);
    }

    // =================================================================
    // validate_message / process_message routing
    // =================================================================

    #[test]
    fn validate_message_routes_global_domain_to_global_engine() {
        let m = build_manager(true);
        assert!(m.validate_message(0, &domains::GLOBAL, b"").is_ok());
    }

    #[test]
    fn validate_message_routes_token_domain_to_token_engine() {
        let m = build_manager(true);
        assert!(m.validate_message(0, &domains::QUIL_TOKEN, b"").is_ok());
    }

    #[test]
    fn validate_message_routes_unknown_to_hypergraph() {
        let m = build_manager(true);
        let random = [0x99u8; 32];
        // The hypergraph engine now validates the message (peeks at the
        // type prefix). An empty message is too short → rejected.
        assert!(m.validate_message(0, &random, b"").is_err());
    }

    #[test]
    fn validate_message_rejects_short_address() {
        let m = build_manager(true);
        let err = m.validate_message(0, &[0xFF; 8], b"").unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn process_message_routes_global_and_returns_empty_result() {
        let m = build_manager(true);
        let r = m
            .process_message(0, &BigInt::from(1), &domains::GLOBAL, b"")
            .unwrap();
        assert!(r.messages.is_empty());
        assert!(r.state.is_empty());
    }

    #[test]
    fn process_message_routes_token_domain() {
        let m = build_manager(true);
        let r = m
            .process_message(0, &BigInt::from(1), &domains::QUIL_TOKEN, b"")
            .unwrap();
        assert!(r.messages.is_empty());
    }

    #[test]
    fn process_message_missing_global_errors_with_not_found() {
        // Without the global engine registered, process_message for
        // the GLOBAL domain routes to "global" and then fails to look
        // it up, returning NotFound.
        let m = build_manager(false);
        let err = m
            .process_message(0, &BigInt::from(1), &domains::GLOBAL, b"")
            .unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
    }
}
