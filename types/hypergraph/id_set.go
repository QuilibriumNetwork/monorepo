package hypergraph

import (
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// TreeValidator is a function type for validating tree entries.
type TreeValidator func(
	key, value []byte,
	tree *tries.VectorCommitmentTree,
) error

type IdSet interface {
	// AttachValidator attaches a validation function to this ID set. The
	// validator will be called when validating trees during sync operations.
	AttachValidator(validator TreeValidator)

	// GetTree returns the underlying tree. Be cautious when using this.
	GetTree() *tries.LazyVectorCommitmentTree

	// ValidateTree validates a vector commitment tree using the attached
	// validator. If no validator is attached, returns nil. This is used to
	// validate data trees associated with atoms in the set.
	ValidateTree(
		key, value []byte,
		tree *tries.VectorCommitmentTree,
	) error

	// IsDirty returns true if the set has been modified since last commit. A
	// dirty set indicates uncommitted changes that need to be persisted.
	IsDirty() bool

	// Add inserts an atom into the ID set. The atom must match the set's atom
	// type or ErrInvalidAtomType is returned. The atom is added to both the
	// in-memory map and the backing tree store.
	Add(
		txn tries.TreeBackingStoreTransaction,
		atom Atom,
	) error

	// Delete removes an atom from the ID set. The atom must match the set's atom
	// type or ErrInvalidAtomType is returned. The atom is removed from the
	// backing tree store.
	Delete(
		txn tries.TreeBackingStoreTransaction,
		atom Atom,
	) error

	// GetSize returns the total size of all atoms in the set.  Returns 0 if the
	// tree has no size information.
	GetSize() *big.Int

	// Has checks if an atom with the given ID exists in the set. Returns true if
	// the atom is present, false otherwise.
	Has(key [64]byte) bool
}
