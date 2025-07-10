package hypergraph

import (
	"math/big"

	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// HypergraphCRDT implements a CRDT-based 2P2P-Hypergraph. It maintains separate
// sets for additions and removals of vertices and hyperedges, allowing for
// conflict-free merging in distributed systems.
type HypergraphCRDT struct {
	// size tracks the total size of the hypergraph (adds - removes)
	size *big.Int
	// vertexAdds maps shard keys to sets of added vertices
	vertexAdds map[tries.ShardKey]*hypergraph.IdSet
	// vertexRemoves maps shard keys to sets of removed vertices
	vertexRemoves map[tries.ShardKey]*hypergraph.IdSet
	// hyperedgeAdds maps shard keys to sets of added hyperedges
	hyperedgeAdds map[tries.ShardKey]*hypergraph.IdSet
	// hyperedgeRemoves maps shard keys to sets of removed hyperedges
	hyperedgeRemoves map[tries.ShardKey]*hypergraph.IdSet
	// store provides persistence for the hypergraph data
	store tries.TreeBackingStore
	// prover generates cryptographic inclusion proofs
	prover crypto.InclusionProver
}

var _ hypergraph.Hypergraph = (*HypergraphCRDT)(nil)

// NewHypergraph creates a new CRDT-based hypergraph. The store provides
// persistence and the prover operates over the underlying vector commitment
// trees backing the sets.
func NewHypergraph(
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) *HypergraphCRDT {
	return &HypergraphCRDT{
		size:             big.NewInt(0),
		vertexAdds:       make(map[tries.ShardKey]*hypergraph.IdSet),
		vertexRemoves:    make(map[tries.ShardKey]*hypergraph.IdSet),
		hyperedgeAdds:    make(map[tries.ShardKey]*hypergraph.IdSet),
		hyperedgeRemoves: make(map[tries.ShardKey]*hypergraph.IdSet),
		store:            store,
		prover:           prover,
	}
}

// NewTransaction creates a new transaction for atomic operations.
func (hg *HypergraphCRDT) NewTransaction(indexed bool) (
	tries.TreeBackingStoreTransaction,
	error,
) {
	timer := prometheus.NewTimer(
		TransactionDuration.WithLabelValues(boolToString(indexed)),
	)
	defer timer.ObserveDuration()

	txn, err := hg.store.NewTransaction(indexed)
	if err != nil {
		TransactionTotal.WithLabelValues(boolToString(indexed), "error").Inc()
		return nil, err
	}

	TransactionTotal.WithLabelValues(boolToString(indexed), "success").Inc()
	return txn, nil
}

// GetProver returns the inclusion prover used by this hypergraph.
func (hg *HypergraphCRDT) GetProver() crypto.InclusionProver {
	return hg.prover
}

// ImportTree imports an existing commitment tree into the hypergraph. This is
// used to load pre-existing hypergraph data from persistent storage. The
// atomType and phaseType determine which set the tree is imported into.
func (hg *HypergraphCRDT) ImportTree(
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	shardKey tries.ShardKey,
	root tries.LazyVectorCommitmentNode,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) error {
	timer := prometheus.NewTimer(ImportTreeDuration)
	defer timer.ObserveDuration()

	set := hypergraph.NewIdSet(
		atomType,
		phaseType,
		shardKey,
		store,
		prover,
		root,
	)

	treeSize := set.GetSize()
	size, _ := treeSize.Float64()
	ImportTreeSize.Observe(size)

	switch atomType {
	case hypergraph.VertexAtomType:
		switch phaseType {
		case hypergraph.AddsPhaseType:
			hg.size.Add(hg.size, treeSize)
			hg.vertexAdds[shardKey] = set
		case hypergraph.RemovesPhaseType:
			hg.size.Sub(hg.size, treeSize)
			hg.vertexRemoves[shardKey] = set
		}
	case hypergraph.HyperedgeAtomType:
		switch phaseType {
		case hypergraph.AddsPhaseType:
			hg.size.Add(hg.size, treeSize)
			hg.hyperedgeAdds[shardKey] = set
		case hypergraph.RemovesPhaseType:
			hg.size.Sub(hg.size, treeSize)
			hg.hyperedgeRemoves[shardKey] = set
		}
	}

	ImportTreeTotal.WithLabelValues(
		string(atomType),
		string(phaseType),
		"success",
	).Inc()
	return nil
}

// GetSize returns the current total size of the hypergraph. The size is
// calculated as the sum of all added atoms' data minus removed atoms.
func (hg *HypergraphCRDT) GetSize() *big.Int {
	return hg.size
}

// boolToString converts a boolean to string for Prometheus labels.
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
