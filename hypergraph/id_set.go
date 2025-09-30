package hypergraph

import (
	"math/big"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// IdSet represents a set of atom IDs with their associated atoms.
// It uses a lazy vector commitment tree for efficient storage and proofs.
type idSet struct {
	dirty     bool
	atomType  hypergraph.AtomType
	tree      *tries.LazyVectorCommitmentTree
	validator hypergraph.TreeValidator
}

// NewIdSet creates a new phase set for the specified atom and phase types.
// IdSets are CRDTs – combining two of them for add and remove phases creates a
// standard 2P set. These are combined for a 2P2P-Hypergraph CRDT.
func NewIdSet(
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	shardKey tries.ShardKey,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
	root tries.LazyVectorCommitmentNode,
	coveredPrefix []int,
) *idSet {
	return &idSet{
		dirty:    false,
		atomType: atomType,
		tree: &tries.LazyVectorCommitmentTree{
			SetType:         string(atomType),
			PhaseType:       string(phaseType),
			ShardKey:        shardKey,
			Store:           store,
			InclusionProver: prover,
			Root:            root,
			CoveredPrefix:   coveredPrefix,
		},
	}
}

// AttachValidator attaches a validation function to this ID set. The validator
// will be called when validating trees during sync operations.
func (set *idSet) AttachValidator(validator hypergraph.TreeValidator) {
	set.validator = validator
}

// GetTree returns the underlying tree. Be cautious when using this.
func (set *idSet) GetTree() *tries.LazyVectorCommitmentTree {
	return set.tree
}

// ValidateTree validates a vector commitment tree using the attached validator.
// If no validator is attached, returns nil. This is used to validate data
// trees associated with atoms in the set.
func (set *idSet) ValidateTree(
	key, value []byte,
	tree *tries.VectorCommitmentTree,
) error {
	if set.validator != nil {
		return set.validator(key, value, tree)
	} else {
		return nil
	}
}

// IsDirty returns true if the set has been modified since last commit. A dirty
// set indicates uncommitted changes that need to be persisted.
func (set *idSet) IsDirty() bool {
	return set.dirty
}

// Add inserts an atom into the ID set. The atom must match the set's atom type
// or ErrInvalidAtomType is returned. The atom is added to both the in-memory
// map and the backing tree store.
func (set *idSet) Add(
	txn tries.TreeBackingStoreTransaction,
	atom hypergraph.Atom,
) error {
	if atom.GetAtomType() != set.atomType {
		return hypergraph.ErrInvalidAtomType
	}

	id := atom.GetID()
	set.dirty = true
	return set.tree.Insert(
		txn,
		id[:],
		atom.ToBytes(),
		atom.Commit(set.tree.InclusionProver),
		atom.GetSize(),
	)
}

// Delete removes an atom from the ID set. The atom must match the set's atom
// type or ErrInvalidAtomType is returned. The atom is removed from the backing
// tree store.
func (set *idSet) Delete(
	txn tries.TreeBackingStoreTransaction,
	atom hypergraph.Atom,
) error {
	if atom.GetAtomType() != set.atomType {
		return hypergraph.ErrInvalidAtomType
	}

	id := atom.GetID()
	set.dirty = true
	return set.tree.Delete(txn, id[:])
}

// GetSize returns the total size of all atoms in the set.  Returns 0 if the
// tree has no size information.
func (set *idSet) GetSize() *big.Int {
	size := set.tree.GetSize()
	if size == nil {
		size = big.NewInt(0)
	}
	return size
}

// Has checks if an atom with the given ID exists in the set. Returns true if
// the atom is present, false otherwise.
func (set *idSet) Has(key [64]byte) bool {
	_, err := set.tree.Store.GetNodeByKey(
		set.tree.SetType,
		set.tree.PhaseType,
		set.tree.ShardKey,
		key[:],
	)
	return err == nil
}

func (hg *HypergraphCRDT) getCoveredPrefix() []int {
	return slices.Clone(hg.coveredPrefix)
}

func (hg *HypergraphCRDT) SetCoveredPrefix(prefix []int) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	hg.coveredPrefix = slices.Clone(prefix)

	for _, s := range hg.hyperedgeAdds {
		s.GetTree().CoveredPrefix = prefix
	}

	for _, s := range hg.hyperedgeRemoves {
		s.GetTree().CoveredPrefix = prefix
	}

	for _, s := range hg.vertexAdds {
		s.GetTree().CoveredPrefix = prefix
	}

	for _, s := range hg.vertexRemoves {
		s.GetTree().CoveredPrefix = prefix
	}

	return hg.store.SetCoveredPrefix(prefix)
}

// GetVertexAddsSet returns a specific vertex addition set by shard key.
// Note: This function is exposed for tests only – do not use directly unless
// verifying underlying state
func (
	hg *HypergraphCRDT,
) GetVertexAddsSet(shardKey tries.ShardKey) hypergraph.IdSet {
	return hg.getVertexAddsSet(shardKey)
}

func (
	hg *HypergraphCRDT,
) getVertexAddsSet(shardKey tries.ShardKey) hypergraph.IdSet {
	coveredPrefix := []int{}
	if shardKey.L1 != [3]byte{0, 0, 0} {
		coveredPrefix = hg.getCoveredPrefix()
	}
	adds, _ := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		coveredPrefix,
	)
	return adds
}

// GetVertexRemovesSet returns a specific vertex removal set by shard key.
// Note: This function is exposed for tests only – do not use directly unless
// verifying underlying state
func (
	hg *HypergraphCRDT,
) GetVertexRemovesSet(shardKey tries.ShardKey) hypergraph.IdSet {
	return hg.getVertexRemovesSet(shardKey)
}

func (
	hg *HypergraphCRDT,
) getVertexRemovesSet(shardKey tries.ShardKey) hypergraph.IdSet {
	coveredPrefix := []int{}
	if shardKey.L1 != [3]byte{0, 0, 0} {
		coveredPrefix = hg.getCoveredPrefix()
	}
	_, removes := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		coveredPrefix,
	)
	return removes
}

// GetHyperedgeAddsSet returns a specific hyperedge addition set by shard key.
// Note: This function is exposed for tests only – do not use directly unless
// verifying underlying state
func (
	hg *HypergraphCRDT,
) GetHyperedgeAddsSet(shardKey tries.ShardKey) hypergraph.IdSet {
	return hg.getHyperedgeAddsSet(shardKey)
}

func (
	hg *HypergraphCRDT,
) getHyperedgeAddsSet(shardKey tries.ShardKey) hypergraph.IdSet {
	coveredPrefix := []int{}
	if shardKey.L1 != [3]byte{0, 0, 0} {
		coveredPrefix = hg.getCoveredPrefix()
	}
	adds, _ := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.VertexAtomType,
		coveredPrefix,
	)
	return adds
}

// GetHyperedgeRemovesSet returns a specific hyperedge removal set by shard key.
// Note: This function is exposed for tests only – do not use directly unless
// verifying underlying state
func (
	hg *HypergraphCRDT,
) GetHyperedgeRemovesSet(shardKey tries.ShardKey) hypergraph.IdSet {
	return hg.getHyperedgeRemovesSet(shardKey)
}

func (
	hg *HypergraphCRDT,
) getHyperedgeRemovesSet(shardKey tries.ShardKey) hypergraph.IdSet {
	coveredPrefix := []int{}
	if shardKey.L1 != [3]byte{0, 0, 0} {
		coveredPrefix = hg.getCoveredPrefix()
	}
	_, removes := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.VertexAtomType,
		coveredPrefix,
	)
	return removes
}

// getOrCreateIdSet returns the add and remove sets for the given shard. If the
// sets don't exist, they are created with the appropriate parameters.
func (hg *HypergraphCRDT) getOrCreateIdSet(
	shardAddr tries.ShardKey,
	addMap map[tries.ShardKey]hypergraph.IdSet,
	removeMap map[tries.ShardKey]hypergraph.IdSet,
	atomType hypergraph.AtomType,
	coveredPrefix []int,
) (hypergraph.IdSet, hypergraph.IdSet) {
	if _, ok := addMap[shardAddr]; !ok {
		addMap[shardAddr] = NewIdSet(
			atomType,
			hypergraph.AddsPhaseType,
			shardAddr,
			hg.store,
			hg.prover,
			nil,
			coveredPrefix,
		)
	}
	if _, ok := removeMap[shardAddr]; !ok {
		removeMap[shardAddr] = NewIdSet(
			atomType,
			hypergraph.RemovesPhaseType,
			shardAddr,
			hg.store,
			hg.prover,
			nil,
			coveredPrefix,
		)
	}
	return addMap[shardAddr], removeMap[shardAddr]
}
