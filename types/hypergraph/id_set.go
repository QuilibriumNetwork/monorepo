package hypergraph

import (
	"math/big"

	tcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// TreeValidator is a function type for validating tree entries.
type TreeValidator func(
	key, value []byte,
	tree *tries.VectorCommitmentTree,
) error

// IdSet represents a set of atom IDs with their associated atoms.
// It uses a lazy vector commitment tree for efficient storage and proofs.
type IdSet struct {
	dirty     bool
	atomType  AtomType
	tree      *tries.LazyVectorCommitmentTree
	validator TreeValidator
}

// NewIdSet creates a new phase set for the specified atom and phase types.
// IdSets are CRDTs – combining two of them for add and remove phases creates a
// standard 2P set. These are combined for a 2P2P-Hypergraph CRDT.
func NewIdSet(
	atomType AtomType,
	phaseType PhaseType,
	shardKey tries.ShardKey,
	store tries.TreeBackingStore,
	prover tcrypto.InclusionProver,
	root tries.LazyVectorCommitmentNode,
) *IdSet {
	return &IdSet{
		dirty:    false,
		atomType: atomType,
		tree: &tries.LazyVectorCommitmentTree{
			SetType:         string(atomType),
			PhaseType:       string(phaseType),
			ShardKey:        shardKey,
			Store:           store,
			InclusionProver: prover,
			Root:            root,
		},
	}
}

// AttachValidator attaches a validation function to this ID set. The validator
// will be called when validating trees during sync operations.
func (set *IdSet) AttachValidator(validator TreeValidator) {
	set.validator = validator
}

// GetTree returns the underlying tree. Be cautious when using this.
func (set *IdSet) GetTree() *tries.LazyVectorCommitmentTree {
	return set.tree
}

// ValidateTree validates a vector commitment tree using the attached validator.
// If no validator is attached, returns nil. This is used to validate data
// trees associated with atoms in the set.
func (set *IdSet) ValidateTree(
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
func (set *IdSet) IsDirty() bool {
	return set.dirty
}

// Add inserts an atom into the ID set. The atom must match the set's atom type
// or ErrInvalidAtomType is returned. The atom is added to both the in-memory
// map and the backing tree store.
func (set *IdSet) Add(
	txn tries.TreeBackingStoreTransaction,
	atom Atom,
) error {
	if atom.GetAtomType() != set.atomType {
		return ErrInvalidAtomType
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
func (set *IdSet) Delete(
	txn tries.TreeBackingStoreTransaction,
	atom Atom,
) error {
	if atom.GetAtomType() != set.atomType {
		return ErrInvalidAtomType
	}

	id := atom.GetID()
	set.dirty = true
	return set.tree.Delete(txn, id[:])
}

// GetSize returns the total size of all atoms in the set.  Returns 0 if the
// tree has no size information.
func (set *IdSet) GetSize() *big.Int {
	size := set.tree.GetSize()
	if size == nil {
		size = big.NewInt(0)
	}
	return size
}

// Has checks if an atom with the given ID exists in the set. Returns true if
// the atom is present, false otherwise.
func (set *IdSet) Has(key [64]byte) bool {
	_, err := set.tree.Store.GetNodeByKey(
		set.tree.SetType,
		set.tree.PhaseType,
		set.tree.ShardKey,
		key[:],
	)
	return err == nil
}
