//! Rebuild engines without carrying message changesets or stateful providers
//! from the source manager. Cryptographic services and proof-worker admission
//! are deliberately shared; all execution state comes from the new context.

use super::*;
use crate::manager::ExecutionForkContext;

fn check_capture_state(
    state: &Option<Arc<crate::hypergraph_state::HypergraphState>>,
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
) -> Result<()> {
    let state = state.as_ref().ok_or_else(|| QuilError::ExecutionUnavailable("capture requires stateful engines".into()))?;
    if !Arc::ptr_eq(state.crdt(), crdt) || state.changeset_len() != 0 {
        return Err(QuilError::ExecutionUnavailable("capture engine state mismatch or unfinished message".into()));
    }
    Ok(())
}

/// A GLOBAL clock must share the branch's database, unless the caller declared
/// that store as a separate, read-only GLOBAL anchor (a thread worker's master).
fn check_capture_clock(
    clock: &dyn quil_types::store::ClockStore,
    identity: &quil_types::store::BackingStoreIdentity,
    anchor: Option<&quil_types::store::BackingStoreIdentity>,
) -> Result<()> {
    let actual = clock.backing_store_identity();
    if actual.as_ref() != Some(identity) && (anchor.is_none() || actual.as_ref() != anchor) {
        return Err(QuilError::ExecutionUnavailable(
            "capture requires GLOBAL anchors from the same store; separate GLOBAL stores require a captured anchor context".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "engine_fork_tests.rs"]
mod tests;

fn fork_state(
    source: &Option<Arc<crate::hypergraph_state::HypergraphState>>,
    context: &ExecutionForkContext,
) -> Result<Option<Arc<crate::hypergraph_state::HypergraphState>>> {
    match source {
        None => Ok(None),
        Some(state) => {
            if state.changeset_len() != 0 {
                return Err(QuilError::ExecutionUnavailable(
                    "cannot fork an engine with an unfinished message changeset".into(),
                ));
            }
            Ok(Some(Arc::new(
                crate::hypergraph_state::HypergraphState::new(context.crdt.clone()),
            )))
        }
    }
}

impl GlobalExecutionEngine {
    pub(crate) fn check_execution_capture(&self, crdt: &Arc<quil_hypergraph::HypergraphCrdt>, identity: &quil_types::store::BackingStoreIdentity) -> Result<()> {
        check_capture_state(&self.state, crdt)?;
        if !self.crdt.as_ref().is_some_and(|source| Arc::ptr_eq(source, crdt)) {
            return Err(QuilError::ExecutionUnavailable("global capture CRDT mismatch".into()));
        }
        self.intrinsic.as_ref().ok_or_else(|| QuilError::ExecutionUnavailable("global capture requires intrinsic".into()))?
            .check_execution_capture(crdt, identity)
    }

    pub(crate) fn fork_with_context(&self, context: &ExecutionForkContext) -> Result<Self> {
        Ok(Self {
            inclusion_prover: self.inclusion_prover.clone(),
            intrinsic: self
                .intrinsic
                .as_ref()
                .map(|source| source.fork_with_context(context))
                .transpose()?,
            crdt: self.crdt.as_ref().map(|_| context.crdt.clone()),
            state: fork_state(&self.state, context)?,
        })
    }
}

impl TokenExecutionEngine {
    pub(crate) fn check_execution_capture(&self, crdt: &Arc<quil_hypergraph::HypergraphCrdt>, identity: &quil_types::store::BackingStoreIdentity, anchor: Option<&quil_types::store::BackingStoreIdentity>) -> Result<()> {
        check_capture_state(&self.state, crdt)?;
        check_capture_clock(self.clock_store.as_ref(), identity, anchor)
    }

    #[cfg(test)]
    pub(crate) fn global_clock_for_tests(&self) -> Arc<dyn quil_types::store::ClockStore> {
        self.clock_store.clone()
    }

    pub(crate) fn fork_with_context(&self, context: &ExecutionForkContext) -> Result<Self> {
        Ok(Self {
            mode: self.mode,
            #[cfg(feature = "native-proof")]
            token_policy: self.token_policy,
            #[cfg(feature = "native-proof")]
            token_execution: std::sync::Mutex::new(()),
            #[cfg(feature = "native-proof")]
            // Clone the existing lane/slots/host admission limits. Constructing
            // a worker or changing concurrency here would bypass those limits.
            token_worker: self.token_worker.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            state: fork_state(&self.state, context)?,
            key_manager: self.key_manager.clone(),
            clock_store: context.global_clock_store.clone(),
            config_resolver: self.config_resolver.for_execution_context(context.crdt.clone())?,
        })
    }
}

impl ComputeExecutionEngine {
    pub(crate) fn check_execution_capture(&self, crdt: &Arc<quil_hypergraph::HypergraphCrdt>, identity: &quil_types::store::BackingStoreIdentity, anchor: Option<&quil_types::store::BackingStoreIdentity>) -> Result<()> {
        check_capture_state(&self.state, crdt)?;
        if let Some(clock) = &self.global_clock { check_capture_clock(clock.as_ref(), identity, anchor)?; }
        Ok(())
    }

    pub(crate) fn fork_with_context(&self, context: &ExecutionForkContext) -> Result<Self> {
        Ok(Self {
            mode: self.mode,
            state: fork_state(&self.state, context)?,
            key_manager: self.key_manager.clone(),
            circuit_compiler: self.circuit_compiler.clone(),
            global_clock: self
                .global_clock
                .as_ref()
                .map(|_| context.global_clock_store.clone()),
        })
    }
}

impl HypergraphExecutionEngine {
    pub(crate) fn check_execution_capture(&self, crdt: &Arc<quil_hypergraph::HypergraphCrdt>, identity: &quil_types::store::BackingStoreIdentity, anchor: Option<&quil_types::store::BackingStoreIdentity>) -> Result<()> {
        check_capture_state(&self.state, crdt)?;
        if let Some(clock) = &self.global_clock { check_capture_clock(clock.as_ref(), identity, anchor)?; }
        Ok(())
    }

    pub(crate) fn fork_with_context(&self, context: &ExecutionForkContext) -> Result<Self> {
        Ok(Self {
            mode: self.mode,
            state: fork_state(&self.state, context)?,
            inclusion_prover: self.inclusion_prover.clone(),
            config_resolver: self
                .config_resolver
                .for_execution_context(context.crdt.clone())?,
            key_manager: self.key_manager.clone(),
            global_clock: self
                .global_clock
                .as_ref()
                .map(|_| context.global_clock_store.clone()),
        })
    }
}
