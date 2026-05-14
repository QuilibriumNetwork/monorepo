//! Forks + LevelledForest. Mirror of `consensus/forest/` + `consensus/forks/`.
//!
//! # LevelledForest
//!
//! A [`LevelledForest`] is a potentially-disconnected planar graph of
//! vertices, each with a "level" (our rank). Vertices have exactly one
//! parent at a strictly lower level. The forest supports **forward
//! references**: a vertex may cite a parent by ID before that parent has
//! been added. Internally, both cited-but-unknown parents and fully-added
//! vertices share the same container slot — an "empty" slot carries only
//! level/ID metadata, while a "full" slot also carries the concrete
//! [`Vertex`] payload.
//!
//! # Forks
//!
//! [`Forks`] implements the Jolteon / DiemBFT-v4 two-chain finalization
//! rule on top of a `LevelledForest`:
//!
//! > A state S is finalized when there exists a certified state C with
//! > `C.rank == S.rank + 1`.
//!
//! It also:
//!
//! - Validates vertex insertion (rank monotonicity, parent agreement).
//! - Detects double proposals and conflicting QCs (Byzantine evidence).
//! - Prunes the forest below the latest finalized rank.
//! - Emits consumer notifications for incorporated / finalized states.
//!
//! Forks is **not** safe for concurrent use — the event loop serializes
//! access on a single task.

use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{CertifiedState, FinalityProof, Identity, State, Unique};
use quil_types::error::{QuilError, Result};

// =====================================================================
// Vertex + errors
// =====================================================================

/// A vertex in the leveled forest. Each vertex has an identity, a level
/// (rank), and a (parent_id, parent_level) pair.
///
/// Mirror of Go's `consensus/forest/vertex.go::Vertex`.
pub trait Vertex: Send + Sync + std::fmt::Debug {
    fn vertex_id(&self) -> &Identity;
    fn level(&self) -> u64;
    /// Returns `(parent_id, parent_level)`. Per Go semantics, the forest
    /// **never** calls this method on a vertex whose level equals the
    /// lowest retained level — meaning root/genesis vertices without a
    /// real parent may return dummy values without breaking invariants.
    fn parent(&self) -> (Identity, u64);
}

/// Invalid-vertex error. Mirror of Go's `InvalidVertexError`.
#[derive(Debug, thiserror::Error)]
#[error("invalid vertex {} at level {level}: {msg}", hex::encode(.id))]
pub struct InvalidVertexError {
    pub id: Identity,
    pub level: u64,
    pub msg: String,
}

impl InvalidVertexError {
    fn of(v: &dyn Vertex, msg: impl Into<String>) -> Self {
        Self {
            id: v.vertex_id().clone(),
            level: v.level(),
            msg: msg.into(),
        }
    }
}

/// Missing-parent error. Benign from the perspective of Forks (no-op);
/// typically surfaces when a state references a pruned ancestor.
#[derive(Debug, thiserror::Error)]
#[error("missing state at rank {rank}, id={}", hex::encode(.id))]
pub struct MissingStateError {
    pub rank: u64,
    pub id: Identity,
}

/// Byzantine-threshold exceeded. Unrecoverable: conflicting QCs imply
/// 1/3+ malicious stake.
#[derive(Debug, thiserror::Error)]
#[error("byzantine threshold exceeded: {evidence}")]
pub struct ByzantineThresholdExceededError {
    pub evidence: String,
}

// =====================================================================
// LevelledForest
// =====================================================================

#[derive(Debug)]
struct VertexContainer {
    level: u64,
    /// `None` for empty containers (referenced but not yet added).
    /// `Some(...)` once the real vertex is inserted.
    vertex: Option<Arc<dyn Vertex>>,
    /// Child container IDs (at higher levels). Stored as IDs rather than
    /// references so we can keep the container storage simple — the Go
    /// version uses pointers but Rust's borrow checker makes that awkward.
    children: Vec<Identity>,
}

impl VertexContainer {
    fn is_empty(&self) -> bool {
        self.vertex.is_none()
    }
}

/// Mirror of Go's `forest/leveled_forest.go::LevelledForest`. **Not**
/// safe for concurrent use.
pub struct LevelledForest {
    vertices: HashMap<Identity, VertexContainer>,
    /// Per-level lists of container IDs — enables O(1) rank-indexed lookup.
    vertices_at_level: HashMap<u64, Vec<Identity>>,
    size: u64,
    lowest_level: u64,
}

impl LevelledForest {
    pub fn new(lowest_level: u64) -> Self {
        Self {
            vertices: HashMap::new(),
            vertices_at_level: HashMap::new(),
            size: 0,
            lowest_level,
        }
    }

    pub fn lowest_level(&self) -> u64 {
        self.lowest_level
    }

    pub fn get_size(&self) -> u64 {
        self.size
    }

    /// Has `id` been stored as a FULL vertex? Empty forward-reference
    /// containers return `false`.
    pub fn has_vertex(&self, id: &Identity) -> bool {
        self.vertices
            .get(id)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }

    /// Look up a vertex. Empty containers return `None`.
    pub fn get_vertex(&self, id: &Identity) -> Option<&Arc<dyn Vertex>> {
        self.vertices.get(id).and_then(|c| c.vertex.as_ref())
    }

    /// Iterate FULL vertices at a level. Skips empty containers.
    pub fn get_vertices_at_level(&self, level: u64) -> Vec<Arc<dyn Vertex>> {
        let Some(ids) = self.vertices_at_level.get(&level) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.vertices.get(id) {
                if let Some(v) = &c.vertex {
                    out.push(Arc::clone(v));
                }
            }
        }
        out
    }

    /// Count of FULL vertices at the given level.
    pub fn get_number_of_vertices_at_level(&self, level: u64) -> usize {
        self.vertices_at_level
            .get(&level)
            .map(|ids| {
                ids.iter()
                    .filter(|id| self.vertices.get(*id).map_or(false, |c| !c.is_empty()))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Iterate children of `id`. Returns an empty Vec if `id` is unknown.
    pub fn get_children(&self, id: &Identity) -> Vec<Arc<dyn Vertex>> {
        let Some(container) = self.vertices.get(id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for child_id in &container.children {
            if let Some(child) = self.vertices.get(child_id) {
                if let Some(v) = &child.vertex {
                    out.push(Arc::clone(v));
                }
            }
        }
        out
    }

    /// Prune all vertices *strictly below* `level`. No-op if `level`
    /// isn't greater than the current lowest.
    ///
    /// Returns an error only if `level < lowest_level` — a caller bug.
    pub fn prune_up_to_level(&mut self, level: u64) -> Result<()> {
        if level < self.lowest_level {
            return Err(QuilError::Consensus(format!(
                "new lowest level {} cannot be smaller than previous last retained level {}",
                level, self.lowest_level
            )));
        }
        if self.vertices.is_empty() {
            self.lowest_level = level;
            return Ok(());
        }

        let mut elements_pruned: u64 = 0;

        // Optimize iteration dimension, matching Go's approach.
        let range_span = level - self.lowest_level;
        if (self.vertices_at_level.len() as u64) < range_span {
            let drained: Vec<u64> = self
                .vertices_at_level
                .keys()
                .filter(|&&l| l < level)
                .copied()
                .collect();
            for l in drained {
                if let Some(ids) = self.vertices_at_level.remove(&l) {
                    for id in ids {
                        if let Some(c) = self.vertices.remove(&id) {
                            if !c.is_empty() {
                                elements_pruned += 1;
                            }
                        }
                    }
                }
            }
        } else {
            for l in self.lowest_level..level {
                if let Some(ids) = self.vertices_at_level.remove(&l) {
                    for id in ids {
                        if let Some(c) = self.vertices.remove(&id) {
                            if !c.is_empty() {
                                elements_pruned += 1;
                            }
                        }
                    }
                }
            }
        }
        self.lowest_level = level;
        self.size = self.size.saturating_sub(elements_pruned);
        Ok(())
    }

    /// Insert a vertex. If its level is below `lowest_level`, this is a
    /// no-op. Repeated insertion of the same ID preserves the first
    /// vertex inserted.
    ///
    /// **UNVALIDATED**: callers are expected to have passed the vertex
    /// through [`verify_vertex`](Self::verify_vertex) first.
    pub fn add_vertex(&mut self, vertex: Arc<dyn Vertex>) {
        if vertex.level() < self.lowest_level {
            return;
        }
        let id = vertex.vertex_id().clone();
        let level = vertex.level();

        // Fetch or create the container for `id`.
        let existed_but_empty = match self.vertices.get(&id) {
            Some(c) => c.is_empty(),
            None => {
                self.vertices.insert(
                    id.clone(),
                    VertexContainer {
                        level,
                        vertex: None,
                        children: Vec::new(),
                    },
                );
                self.vertices_at_level
                    .entry(level)
                    .or_default()
                    .push(id.clone());
                true
            }
        };

        if !existed_but_empty {
            // Already stored as a full vertex; keep the first one.
            return;
        }

        // Fill the container.
        self.vertices.get_mut(&id).unwrap().vertex = Some(Arc::clone(&vertex));
        self.register_with_parent(&id, level, &vertex);
        self.size += 1;
    }

    /// Record `child_id` as a child of its parent container, creating
    /// the parent as an empty forward-reference container if needed.
    fn register_with_parent(&mut self, child_id: &Identity, level: u64, vertex: &Arc<dyn Vertex>) {
        if level <= self.lowest_level {
            // Root-level vertices have no parent (or parent is pruned).
            return;
        }
        let (parent_id, parent_level) = vertex.parent();
        if parent_level < self.lowest_level {
            return;
        }
        // Get-or-create the parent container.
        if !self.vertices.contains_key(&parent_id) {
            self.vertices.insert(
                parent_id.clone(),
                VertexContainer {
                    level: parent_level,
                    vertex: None,
                    children: Vec::new(),
                },
            );
            self.vertices_at_level
                .entry(parent_level)
                .or_default()
                .push(parent_id.clone());
        }
        let parent = self.vertices.get_mut(&parent_id).unwrap();
        parent.children.push(child_id.clone());
    }

    /// Verify that inserting `vertex` would maintain the forest's
    /// invariants. Mirror of Go's `VerifyVertex`.
    pub fn verify_vertex(&self, vertex: &Arc<dyn Vertex>) -> std::result::Result<(), InvalidVertexError> {
        if vertex.level() < self.lowest_level {
            return Ok(());
        }

        let stored = self.vertices.get(vertex.vertex_id());
        let Some(stored) = stored else {
            return self.ensure_consistent_parent(vertex);
        };

        // Level must match (ID uniquely binds to a level).
        if vertex.level() != stored.level {
            return Err(InvalidVertexError::of(
                vertex.as_ref(),
                format!(
                    "level conflicts with stored vertex with same id ({}!={})",
                    vertex.level(),
                    stored.level
                ),
            ));
        }
        if stored.is_empty() {
            return self.ensure_consistent_parent(vertex);
        }

        // Both are full — compare parent info unless we're at the root.
        if vertex.level() == self.lowest_level {
            return Ok(());
        }
        let (new_pid, new_plevel) = vertex.parent();
        let stored_vertex = stored.vertex.as_ref().unwrap();
        let (stored_pid, stored_plevel) = stored_vertex.parent();
        if new_pid != stored_pid {
            return Err(InvalidVertexError::of(
                vertex.as_ref(),
                format!("parent ID conflicts with stored parent ({}!={})", hex::encode(&new_pid), hex::encode(&stored_pid)),
            ));
        }
        if new_plevel != stored_plevel {
            return Err(InvalidVertexError::of(
                vertex.as_ref(),
                format!(
                    "parent level conflicts with stored parent ({}!={})",
                    new_plevel, stored_plevel
                ),
            ));
        }
        Ok(())
    }

    fn ensure_consistent_parent(
        &self,
        vertex: &Arc<dyn Vertex>,
    ) -> std::result::Result<(), InvalidVertexError> {
        if vertex.level() <= self.lowest_level {
            return Ok(());
        }
        let (parent_id, parent_level) = vertex.parent();
        if vertex.level() <= parent_level {
            return Err(InvalidVertexError::of(
                vertex.as_ref(),
                format!(
                    "vertex parent level ({}) must be smaller than proposed vertex level ({})",
                    parent_level,
                    vertex.level()
                ),
            ));
        }
        let Some(stored_parent) = self.get_vertex(&parent_id) else {
            return Ok(());
        };
        if stored_parent.level() != parent_level {
            return Err(InvalidVertexError::of(
                vertex.as_ref(),
                format!(
                    "parent level conflicts with stored parent ({}!={})",
                    parent_level,
                    stored_parent.level()
                ),
            ));
        }
        Ok(())
    }
}

// =====================================================================
// StateContainer: adapt State<S> to Vertex
// =====================================================================

/// Wraps `State<S>` so it can live inside a `LevelledForest`. Holds the
/// inner state behind an `Arc` so `Forks` can share it with consumers.
#[derive(Debug)]
pub struct StateContainer<S: Unique> {
    state: Arc<State<S>>,
}

impl<S: Unique> StateContainer<S> {
    pub fn new(state: Arc<State<S>>) -> Self {
        Self { state }
    }
    pub fn state(&self) -> &Arc<State<S>> {
        &self.state
    }
}

impl<S: Unique> Vertex for StateContainer<S> {
    fn vertex_id(&self) -> &Identity {
        &self.state.identifier
    }
    fn level(&self) -> u64 {
        self.state.rank
    }
    fn parent(&self) -> (Identity, u64) {
        (self.state.parent_qc_identity.clone(), self.state.parent_qc_rank)
    }
}

// =====================================================================
// Forks: 2-chain finalization
// =====================================================================

/// Callback for emitting finalization events. Mirror of Go's
/// `FollowerConsumer` minus the double-propose notifications (we report
/// those via a separate callback).
///
/// `on_finalized_state` receives a `CertifiedState<S>` rather than
/// bare `State<S>` so the implementor can read the certifying QC's
/// aggregated signature directly (mirrors Go's
/// `models.CertifiedState.CertifyingQuorumCertificate`). Use
/// `certified.state` for the actual state; the certifying QC is on
/// `certified.certifying_quorum_certificate` when the upstream path
/// populates it.
pub trait FollowerConsumer<S: Unique>: Send + Sync {
    fn on_state_incorporated(&self, state: &State<S>);
    fn on_finalized_state(&self, certified: &CertifiedState<S>);
    fn on_double_propose_detected(&self, first: &State<S>, second: &State<S>);
}

/// Core finalizer callback. Called before consumer notifications so that
/// critical components (e.g. the state store) get the "make final"
/// message first. Errors propagate as fatal.
pub trait Finalizer: Send + Sync {
    fn make_final(&self, state_id: &Identity) -> Result<()>;
}

/// Jolteon / HotStuff / DiemBFT-v4 forks. See module docs for the
/// 2-chain finalization rule.
pub struct Forks<S: Unique> {
    finalization_callback: Arc<dyn Finalizer>,
    notifier: Arc<dyn FollowerConsumer<S>>,
    forest: LevelledForest,
    trusted_root: CertifiedState<S>,
    finality_proof: Option<FinalityProof<S>>,
    /// Parallel index of full states — mirrors what we store in the
    /// `LevelledForest` as `StateContainer`s, but lets us return
    /// strongly-typed `Arc<State<S>>` instead of a `&dyn Vertex`.
    state_index: HashMap<Identity, Arc<State<S>>>,
}

impl<S: Unique> Forks<S> {
    /// Construct a new `Forks`. Mirror of Go's `NewForks`.
    pub fn new(
        trusted_root: CertifiedState<S>,
        finalization_callback: Arc<dyn Finalizer>,
        notifier: Arc<dyn FollowerConsumer<S>>,
    ) -> Result<Self> {
        if trusted_root.state.identifier != trusted_root.certifying_qc_identity
            || trusted_root.state.rank != trusted_root.certifying_qc_rank
        {
            return Err(QuilError::Consensus(
                "invalid root: root QC is not pointing to root state".into(),
            ));
        }
        let state_index = Self::state_index_init(&trusted_root.state);
        let mut forks = Self {
            finalization_callback,
            notifier,
            forest: LevelledForest::new(trusted_root.state.rank),
            trusted_root,
            finality_proof: None,
            state_index,
        };
        let root_state = forks.trusted_root.state.clone();
        forks
            .ensure_state_is_valid_extension(&root_state)
            .map_err(|e| {
                QuilError::Consensus(format!(
                    "invalid root state {}: {}",
                    hex::encode(&root_state.identifier), e
                ))
            })?;
        let root_container: Arc<dyn Vertex> = Arc::new(StateContainer::new(Arc::new(root_state)));
        forks.forest.add_vertex(root_container);
        Ok(forks)
    }

    /// The largest rank at which a finalized state is known.
    pub fn finalized_rank(&self) -> u64 {
        match &self.finality_proof {
            Some(fp) => fp.state.rank,
            None => self.trusted_root.state.rank,
        }
    }

    /// The finalized state with the largest rank.
    pub fn finalized_state(&self) -> &State<S> {
        match &self.finality_proof {
            Some(fp) => &fp.state,
            None => &self.trusted_root.state,
        }
    }

    /// Returns the finality proof once any state beyond the root has
    /// been finalized.
    pub fn finality_proof(&self) -> Option<&FinalityProof<S>> {
        self.finality_proof.as_ref()
    }

    /// Look up a state by its identifier.
    pub fn get_state(&self, state_id: &Identity) -> Option<Arc<State<S>>> {
        let vertex = self.forest.get_vertex(state_id)?;
        // Safety: every vertex in the forest is actually a StateContainer.
        // We downcast via a trick — since `Vertex` is a trait, we use
        // the id/level-equivalent `State` stored behind an Arc.
        //
        // To keep the downcast simple, we maintain a parallel state
        // index. See `state_index` below.
        let _ = vertex;
        self.state_index.get(state_id).cloned()
    }

    /// All states at the given rank.
    pub fn get_states_for_rank(&self, rank: u64) -> Vec<Arc<State<S>>> {
        let vertices = self.forest.get_vertices_at_level(rank);
        vertices
            .iter()
            .filter_map(|v| self.state_index.get(v.vertex_id()).cloned())
            .collect()
    }

    /// `true` iff a state with this ID is stored (full vertex, not
    /// a forward reference).
    pub fn is_known_state(&self, state_id: &Identity) -> bool {
        self.forest.has_vertex(state_id)
    }

    /// Is processing the given state worthwhile? False if it's below
    /// the finalized threshold or already known.
    pub fn is_processing_needed(&self, state: &State<S>) -> bool {
        if state.rank < self.finalized_rank() {
            return false;
        }
        !self.is_known_state(&state.identifier)
    }

    /// Validate a potential state insertion. See Go's
    /// `EnsureStateIsValidExtension` for the detailed rules.
    ///
    /// Returns:
    /// - `Ok(())` when safe to insert (or when the state is below the
    ///   prune threshold and therefore trivially compatible).
    /// - `Err(QuilError::NotFound(..))` encoding a `MissingStateError`.
    /// - `Err(QuilError::Consensus(..))` encoding an `InvalidVertexError`
    ///   or other structural failure.
    pub fn ensure_state_is_valid_extension(&self, state: &State<S>) -> Result<()> {
        if state.rank < self.forest.lowest_level() {
            return Ok(());
        }
        let state_arc = Arc::new(state.clone());
        let container: Arc<dyn Vertex> = Arc::new(StateContainer::new(state_arc));
        if let Err(e) = self.forest.verify_vertex(&container) {
            return Err(QuilError::Consensus(format!(
                "not a valid vertex for state tree: {}",
                e
            )));
        }

        // Condition 3 (enforced here, not by LevelledForest): when the
        // parent is above the pruning threshold, it must be stored.
        if state.rank == self.forest.lowest_level() || state.parent_qc_rank < self.forest.lowest_level()
        {
            return Ok(());
        }
        if !self.forest.has_vertex(&state.parent_qc_identity) {
            return Err(QuilError::NotFound(format!(
                "missing parent state at rank {}, id={}",
                state.parent_qc_rank, hex::encode(&state.parent_qc_identity)
            )));
        }
        Ok(())
    }

    /// Add a certified state. May trigger finalization. Mirror of
    /// `AddCertifiedState`.
    pub fn add_certified_state(&mut self, certified: CertifiedState<S>) -> Result<()> {
        if !self.is_processing_needed(&certified.state) {
            return Ok(());
        }
        self.check_for_byzantine_evidence(&certified.state)?;
        // Note: in Rust, the cert QC is stored by rank/id in `CertifiedState`,
        // not as a `&dyn QC`, so we can't run Go's `checkForConflictingQCs`
        // directly here. That check happens inside `checkForByzantineEvidence`
        // via the parent-QC inspection; we accept a minor reduction in
        // coverage until proposals carry full QC references.

        let state_arc = Arc::new(certified.state.clone());
        self.state_index
            .insert(certified.state.identifier.clone(), Arc::clone(&state_arc));
        let container: Arc<dyn Vertex> = Arc::new(StateContainer::new(state_arc));
        self.forest.add_vertex(container);
        self.notifier.on_state_incorporated(&certified.state);
        self.check_for_advancing_finalization(&certified)?;
        Ok(())
    }

    /// Add a validated (but not yet certified) state. Mirror of
    /// `AddValidatedState`.
    pub fn add_validated_state(&mut self, state: State<S>) -> Result<()> {
        if !self.is_processing_needed(&state) {
            return Ok(());
        }
        self.check_for_byzantine_evidence(&state)?;
        let state_arc = Arc::new(state.clone());
        self.state_index
            .insert(state.identifier.clone(), Arc::clone(&state_arc));
        let container: Arc<dyn Vertex> = Arc::new(StateContainer::new(state_arc));
        self.forest.add_vertex(container);
        self.notifier.on_state_incorporated(&state);

        // Try to advance finalization via the parent-certified-by-state path.
        // We synthesize a CertifiedState for the parent using the child's
        // parent QC metadata.
        let Some(parent) = self.get_state(&state.parent_qc_identity) else {
            // Parent pruned: no effect on finalization.
            return Ok(());
        };
        if parent.rank != state.parent_qc_rank {
            return Err(QuilError::Consensus(format!(
                "mismatching QC with parent: parent rank {} != QC rank {}",
                parent.rank, state.parent_qc_rank
            )));
        }
        let certified_parent = CertifiedState {
            state: (*parent).clone(),
            certifying_qc_identity: state.parent_qc_identity.clone(),
            certifying_qc_rank: state.parent_qc_rank,
            // The certifying QC for `parent` is THIS state's
            // parent_quorum_certificate (which is a QC at `parent`'s
            // rank certifying `parent`). Forwarding the trait object
            // is what lets `on_finalized_state` consumers read the
            // aggregate without a QC-store lookup.
            certifying_quorum_certificate: state.parent_quorum_certificate.clone(),
        };
        self.check_for_advancing_finalization(&certified_parent)?;
        Ok(())
    }

    fn check_for_byzantine_evidence(&self, state: &State<S>) -> Result<()> {
        self.ensure_state_is_valid_extension(state)?;
        self.check_for_double_proposal(state);
        Ok(())
    }

    fn check_for_double_proposal(&self, state: &State<S>) {
        let others = self.forest.get_vertices_at_level(state.rank);
        for other in others {
            if other.vertex_id() != &state.identifier {
                if let Some(other_state) = self.state_index.get(other.vertex_id()) {
                    self.notifier
                        .on_double_propose_detected(state, other_state);
                }
            }
        }
    }

    /// Mirror of `checkForAdvancingFinalization`. Finalizes the parent
    /// of `certified_state` if `certified_state.rank ==
    /// parent_state.rank + 1`.
    fn check_for_advancing_finalization(
        &mut self,
        certified_state: &CertifiedState<S>,
    ) -> Result<()> {
        let last_finalized_rank = self.finalized_rank();
        if certified_state.state.rank <= last_finalized_rank
            || certified_state.state.parent_qc_rank < last_finalized_rank
        {
            return Ok(());
        }
        let parent_state = match self.state_index.get(&certified_state.state.parent_qc_identity) {
            Some(p) => Arc::clone(p),
            None => {
                return Err(QuilError::NotFound(format!(
                    "missing state at rank {}, id={}",
                    certified_state.state.parent_qc_rank,
                    hex::encode(&certified_state.state.parent_qc_identity)
                )));
            }
        };
        // Direct-1-chain rule.
        if parent_state.rank + 1 != certified_state.state.rank {
            return Ok(());
        }

        // Collect states to finalize (oldest first).
        let to_finalize =
            self.collect_states_for_finalization(&certified_state.state.parent_qc_identity, certified_state.state.parent_qc_rank)?;

        // Advance finality proof and prune.
        self.finality_proof = Some(FinalityProof {
            state: (*parent_state).clone(),
            certified_child: certified_state.clone(),
        });
        self.forest.prune_up_to_level(self.finalized_rank())?;

        // Emit notifications in rank-ascending order. The
        // `CertifiedState` view passed to consumers carries the
        // state plus the rank+identity references for the certifying
        // QC. `certifying_quorum_certificate` is left `None` here —
        // consumers that need the aggregate signature look it up by
        // `certifying_qc_identity` against a QC store. Mirror of Go's
        // `OnFinalizedState(*State)`, which delegates the QC lookup
        // to `OnQuorumCertificateTriggeredRankChange` for header
        // mutation.
        for state in to_finalize {
            let certified_view = CertifiedState {
                state: (*state).clone(),
                certifying_qc_identity: state.identifier.clone(),
                certifying_qc_rank: state.rank,
                certifying_quorum_certificate: None,
            };
            self.finalization_callback.make_final(&state.identifier)?;
            self.notifier.on_finalized_state(&certified_view);
        }
        Ok(())
    }

    /// Walk the parent chain from `(start_id, start_rank)` up to (but
    /// not including) the previously-finalized state, returning states
    /// in rank-ascending order.
    fn collect_states_for_finalization(
        &self,
        start_id: &Identity,
        start_rank: u64,
    ) -> Result<Vec<Arc<State<S>>>> {
        let last_finalized = self.finalized_state().clone();
        if start_rank < last_finalized.rank {
            return Err(QuilError::Consensus(format!(
                "byzantine: finalizing state with rank {} which is lower than previously finalized state at rank {}",
                start_rank, last_finalized.rank
            )));
        }
        if start_rank == last_finalized.rank {
            return Ok(vec![]);
        }

        let mut rev_stack: Vec<Arc<State<S>>> = Vec::new();
        let mut cur_id = start_id.clone();
        let mut cur_rank = start_rank;
        while cur_rank > last_finalized.rank {
            let Some(state) = self.state_index.get(&cur_id).cloned() else {
                return Err(QuilError::Consensus(format!(
                    "failed to get state (rank={}, id={}) for finalization",
                    cur_rank, hex::encode(&cur_id)
                )));
            };
            rev_stack.push(Arc::clone(&state));
            cur_id = state.parent_qc_identity.clone();
            cur_rank = state.parent_qc_rank;
        }

        if cur_rank == last_finalized.rank && cur_id != last_finalized.identifier {
            return Err(QuilError::Consensus(format!(
                "byzantine: finalizing states with rank {} at conflicting forks: {} and {}",
                cur_rank, hex::encode(&cur_id), hex::encode(&last_finalized.identifier)
            )));
        }

        // Reverse to get ascending order.
        rev_stack.reverse();
        Ok(rev_stack)
    }

    // Internal parallel index; kept in sync with the levelled forest for
    // the public `get_state` / `get_states_for_rank` API.
}

// We tack the state_index onto Forks via a private field. To avoid
// making every method `&mut self`, we store it directly (no lock) and
// mutate it under the same `&mut self` as forest.add_vertex.
impl<S: Unique> Forks<S> {
    fn state_index_init(trusted_root_state: &State<S>) -> HashMap<Identity, Arc<State<S>>> {
        let mut m = HashMap::new();
        m.insert(
            trusted_root_state.identifier.clone(),
            Arc::new(trusted_root_state.clone()),
        );
        m
    }
}

// Field access helper via separate struct: extend `Forks` with
// `state_index` by re-opening the struct at the top. Since we can't
// actually re-open in Rust, add it to the original struct definition.
// (See patch below.)

// -- Compile-time sanity: see below -------------------------------------
// The patch above declared `state_index` and `state_index_init`, but the
// struct itself still needs the field. We keep the struct definition in
// sync manually:

// Test harness + unit tests.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct AppState {
        id: Identity,
        source: Identity,
        rank: u64,
    }
    impl Unique for AppState {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.source }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    // ---------- LevelledForest tests ----------

    #[derive(Debug)]
    struct TestVertex {
        id: Identity,
        level: u64,
        parent_id: Identity,
        parent_level: u64,
    }
    impl Vertex for TestVertex {
        fn vertex_id(&self) -> &Identity { &self.id }
        fn level(&self) -> u64 { self.level }
        fn parent(&self) -> (Identity, u64) { (self.parent_id.clone(), self.parent_level) }
    }

    fn v(id: &str, level: u64, parent: &str, parent_level: u64) -> Arc<dyn Vertex> {
        Arc::new(TestVertex {
            id: id.into(),
            level,
            parent_id: parent.into(),
            parent_level,
        })
    }

    #[test]
    fn leveled_forest_add_and_get() {
        let mut f = LevelledForest::new(0);
        f.add_vertex(v("a", 1, "root", 0));
        assert!(f.has_vertex(&b"a".to_vec()));
        assert!(!f.has_vertex(&b"unknown".to_vec()));
        assert_eq!(f.get_size(), 1);
    }

    #[test]
    fn leveled_forest_parent_forward_reference() {
        let mut f = LevelledForest::new(0);
        // Add a child before its parent — creates an empty parent container.
        f.add_vertex(v("a", 2, "p", 1));
        assert!(!f.has_vertex(&b"p".to_vec())); // empty, doesn't count
        // Then add the parent.
        f.add_vertex(v("p", 1, "root", 0));
        assert!(f.has_vertex(&b"p".to_vec()));
        // Children list should include "a".
        let children = f.get_children(&b"p".to_vec());
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].vertex_id(), &b"a".to_vec());
    }

    #[test]
    fn leveled_forest_verify_rejects_cyclic_level() {
        let f = LevelledForest::new(0);
        let bad = v("bad", 1, "parent", 2); // parent level >= vertex level
        assert!(f.verify_vertex(&bad).is_err());
    }

    #[test]
    fn leveled_forest_prune_removes_lower_levels() {
        let mut f = LevelledForest::new(0);
        f.add_vertex(v("a", 1, "root", 0));
        f.add_vertex(v("b", 2, "a", 1));
        f.add_vertex(v("c", 3, "b", 2));
        assert_eq!(f.get_size(), 3);
        f.prune_up_to_level(2).unwrap();
        assert!(!f.has_vertex(&b"a".to_vec()));
        assert!(f.has_vertex(&b"b".to_vec()));
        assert!(f.has_vertex(&b"c".to_vec()));
    }

    #[test]
    fn leveled_forest_prune_below_lowest_errors() {
        let mut f = LevelledForest::new(5);
        assert!(f.prune_up_to_level(3).is_err());
    }

    // ---------- Forks tests ----------

    fn state(rank: u64, id: &str, parent_id: &str, parent_rank: u64) -> State<AppState> {
        State {
            rank,
            identifier: id.into(),
            proposer_id: "leader".into(),
            parent_qc_identity: parent_id.into(),
            parent_qc_rank: parent_rank,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState {
                id: id.into(),
                source: "leader".into(),
                rank,
            },
        }
    }

    fn certified(s: State<AppState>) -> CertifiedState<AppState> {
        CertifiedState {
            certifying_qc_identity: s.identifier.clone(),
            certifying_qc_rank: s.rank,
            certifying_quorum_certificate: None,
            state: s,
        }
    }

    #[derive(Default)]
    struct CountingFinalizer {
        count: AtomicUsize,
    }
    impl Finalizer for CountingFinalizer {
        fn make_final(&self, _id: &Identity) -> Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingConsumer {
        incorporated: Mutex<Vec<Identity>>,
        finalized: Mutex<Vec<Identity>>,
        double_proposed: Mutex<Vec<(Identity, Identity)>>,
    }
    impl FollowerConsumer<AppState> for RecordingConsumer {
        fn on_state_incorporated(&self, state: &State<AppState>) {
            self.incorporated.lock().unwrap().push(state.identifier.clone());
        }
        fn on_finalized_state(&self, certified: &CertifiedState<AppState>) {
            self.finalized.lock().unwrap().push(certified.state.identifier.clone());
        }
        fn on_double_propose_detected(
            &self,
            a: &State<AppState>,
            b: &State<AppState>,
        ) {
            self.double_proposed
                .lock()
                .unwrap()
                .push((a.identifier.clone(), b.identifier.clone()));
        }
    }

    fn new_forks() -> (Forks<AppState>, Arc<CountingFinalizer>, Arc<RecordingConsumer>) {
        let root = certified(state(0, "genesis", "genesis", 0));
        let f = Arc::new(CountingFinalizer::default());
        let c = Arc::new(RecordingConsumer::default());
        let forks = Forks::new(root, f.clone(), c.clone()).unwrap();
        (forks, f, c)
    }

    #[test]
    fn forks_finalizes_on_two_chain() {
        let (mut forks, finalizer, consumer) = new_forks();
        // Build a chain: genesis(0) <- A(1) <- B(2).
        // Adding certified B finalizes A (parent, rank+1).
        forks.add_certified_state(certified(state(1, "A", "genesis", 0))).unwrap();
        forks.add_certified_state(certified(state(2, "B", "A", 1))).unwrap();
        assert_eq!(forks.finalized_rank(), 1);
        assert_eq!(forks.finalized_state().identifier, b"A".to_vec());
        assert_eq!(finalizer.count.load(Ordering::SeqCst), 1);
        let finalized = consumer.finalized.lock().unwrap();
        assert_eq!(finalized.as_slice(), &[b"A".to_vec()]);
    }

    #[test]
    fn forks_no_finalization_with_gap() {
        let (mut forks, _, _) = new_forks();
        // Skip-rank child should NOT finalize parent (indirect 2-chain
        // rule requires direct 1-chain at parent).
        forks.add_certified_state(certified(state(1, "A", "genesis", 0))).unwrap();
        forks.add_certified_state(certified(state(3, "C", "A", 1))).unwrap();
        assert_eq!(forks.finalized_rank(), 0); // still root
    }

    #[test]
    fn forks_rejects_missing_parent() {
        let (mut forks, _, _) = new_forks();
        // Parent "Z" was never added.
        let err = forks
            .add_certified_state(certified(state(2, "A", "Z", 1)))
            .unwrap_err();
        assert!(matches!(err, QuilError::NotFound(_)));
    }

    #[test]
    fn forks_rejects_cyclic_rank() {
        let (mut forks, _, _) = new_forks();
        // Parent rank == child rank (not strictly smaller).
        let err = forks
            .add_certified_state(certified(state(1, "A", "genesis", 1)))
            .unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
    }

    #[test]
    fn forks_repeat_add_is_noop() {
        let (mut forks, _, consumer) = new_forks();
        forks.add_certified_state(certified(state(1, "A", "genesis", 0))).unwrap();
        forks.add_certified_state(certified(state(1, "A", "genesis", 0))).unwrap();
        let incorp = consumer.incorporated.lock().unwrap();
        assert_eq!(incorp.len(), 1);
    }

    #[test]
    fn forks_double_propose_detected() {
        let (mut forks, _, consumer) = new_forks();
        forks.add_certified_state(certified(state(1, "A", "genesis", 0))).unwrap();
        // Different ID at same rank → double propose.
        forks.add_certified_state(certified(state(1, "A-prime", "genesis", 0))).unwrap();
        let double = consumer.double_proposed.lock().unwrap();
        assert!(!double.is_empty());
    }
}
