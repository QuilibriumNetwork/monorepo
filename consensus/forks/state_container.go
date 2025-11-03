package forks

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/forest"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StateContainer wraps a state proposal to implement forest.Vertex
// so the proposal can be stored in forest.LevelledForest
type StateContainer[StateT models.Unique] models.State[StateT]

var _ forest.Vertex = (*StateContainer[*nilUnique])(nil)

func ToStateContainer2[StateT models.Unique](
	state *models.State[StateT],
) *StateContainer[StateT] {
	return (*StateContainer[StateT])(state)
}

func (b *StateContainer[StateT]) GetState() *models.State[StateT] {
	return (*models.State[StateT])(b)
}

// Functions implementing forest.Vertex
func (b *StateContainer[StateT]) VertexID() models.Identity {
	return b.Identifier
}

func (b *StateContainer[StateT]) Level() uint64 {
	return b.Rank
}

func (b *StateContainer[StateT]) Parent() (models.Identity, uint64) {
	// Caution: not all states have a QC for the parent, such as the spork root
	// states.  Per API contract, we are obliged to return a value to prevent
	// panics during logging. (see vertex `forest.VertexToString` method).
	if b.ParentQuorumCertificate == nil {
		return "", 0
	}
	return b.ParentQuorumCertificate.Identity(),
		b.ParentQuorumCertificate.GetRank()
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
